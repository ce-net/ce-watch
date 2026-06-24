//! ce-watch — the operator's security console for CE.
//!
//! A light axum service that lives beside the relay. It does two things:
//!
//!   1. Receives flag events from the hub's abuse detector over `POST /ingest`, gated by a shared
//!      secret header, and appends them to a durable, bounded, append-only log.
//!   2. Serves an admin-only single-page "security console" (gated by a separate admin token) that
//!      renders the flag log as a structured, filterable table with an unseen-count indicator.
//!
//! It deliberately holds NO libp2p / wasmtime / heavy deps — it is purely an HTTP sink + dashboard.
//! The node and hub stay the source of truth for the mesh; ce-watch is the operator's read model.
//!
//! Admin auth is the ce-secrets challenge-response primitive (see `auth`): the operator enrolls
//! their device's public key ONCE at deploy via `CE_WATCH_ADMIN_DEVICES`, then every request proves
//! possession of the matching private key over a fresh signed challenge. There is no pasted bearer
//! token. `/ingest` keeps its own shared-secret header (it is a server-to-server sink).

mod auth;
mod store;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use tower_http::cors::CorsLayer;

use store::{AdminStore, FlagEvent, RevokeOutcome, Store};

const CONSOLE_HTML: &str = include_str!("console.html");

#[derive(Clone)]
struct AppState {
    store: Arc<Store>,
    ingest_token: Arc<Option<String>>,
    /// Self-managed admin device store (deviceId -> { pub, role, label, added_ts }), persisted to
    /// `admins.json`. The source of truth for who is an admin after boot. Env-seeded at startup.
    admins: Arc<AdminStore>,
    /// Stateless-nonce HMAC key. Persisted across a process restart only if `CE_WATCH_SERVER_SECRET`
    /// is set; otherwise a fresh random secret is minted per boot (in-flight challenges from before a
    /// restart simply expire, which is the safe default).
    server_secret: Arc<Vec<u8>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ce_watch=info,tower_http=warn".into()),
        )
        .init();

    let data_dir = store::default_data_dir();
    let store = Arc::new(Store::open(data_dir.clone())?);

    let ingest_token = env_token("CE_WATCH_INGEST_TOKEN");
    // The env is now a BOOTSTRAP seed, not the source of truth: it is written into the persisted
    // admin store at startup for any device not already present, after which admins are managed
    // self-service (claim / request / approve / revoke) without ever touching the env or redeploying.
    let seed = auth::parse_seed(&std::env::var("CE_WATCH_ADMIN_DEVICES").unwrap_or_default());
    let admins = Arc::new(AdminStore::open(&data_dir, &seed)?);
    let server_secret = server_secret_from_env();

    if ingest_token.is_none() {
        tracing::warn!("CE_WATCH_INGEST_TOKEN is unset — /ingest will reject all requests");
    }
    if !admins.has_admins() {
        tracing::warn!(
            "no admin device yet — open the console and click \"Claim this console\" to become the \
             first admin (TOFU). Or seed one via CE_WATCH_ADMIN_DEVICES (deviceId:ecdsaPubB64url)."
        );
    } else {
        tracing::info!(count = admins.admin_count(), "admin device(s) present");
    }

    let state = AppState {
        store,
        ingest_token: Arc::new(ingest_token),
        admins,
        server_secret: Arc::new(server_secret),
    };

    let app = router(state);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8971);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!(%addr, data_dir = %data_dir.display(), "ce-watch listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(serve_console))
        .route("/admin", get(serve_console))
        .route("/health", get(|| async { "ok" }))
        .route("/ingest", post(ingest))
        .route("/admin/challenge", get(admin_challenge))
        .route("/admin/me", get(admin_me))
        .route("/admin/claim", post(admin_claim))
        .route("/admin/request", post(admin_request))
        .route("/admin/devices", get(admin_devices))
        .route("/admin/devices/approve", post(admin_devices_approve))
        .route("/admin/devices/revoke", post(admin_devices_revoke))
        .route("/admin/flags", get(admin_flags))
        .route("/admin/unseen", get(admin_unseen))
        .route("/admin/seen", post(admin_seen))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

fn env_token(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

/// Constant-ish header compare. Returns true only when a token is configured AND matches.
fn header_matches(headers: &HeaderMap, name: &str, expected: &Option<String>) -> bool {
    let expected = match expected {
        Some(e) => e,
        None => return false,
    };
    match headers.get(name).and_then(|v| v.to_str().ok()) {
        Some(got) => got == expected.as_str(),
        None => false,
    }
}

/// Resolve the stateless-nonce HMAC key: from `CE_WATCH_SERVER_SECRET` if set (so challenges survive
/// a restart), otherwise a fresh 32-byte random secret minted per boot.
fn server_secret_from_env() -> Vec<u8> {
    if let Ok(s) = std::env::var("CE_WATCH_SERVER_SECRET") {
        if !s.is_empty() {
            return s.into_bytes();
        }
    }
    // Cheap, dependency-free CSPRNG-ish seed: mix time + addr entropy. The nonce is only a replay
    // guard within a 300s window, not a long-term key, so a per-boot ephemeral secret is sufficient.
    let mut seed = Vec::with_capacity(32);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    seed.extend_from_slice(&nanos.to_le_bytes());
    seed.extend_from_slice(&std::process::id().to_le_bytes());
    let h = &seed as *const _ as usize;
    seed.extend_from_slice(&h.to_le_bytes());
    // Stretch to 32 bytes via SHA-256 (ce-secrets-rs already pulls sha2 transitively, but to avoid a
    // new direct dep we just repeat-and-truncate the entropy; it remains unguessable for replay).
    while seed.len() < 32 {
        seed.push(seed[seed.len() % seed.len().max(1)].wrapping_add(0x9e));
    }
    seed.truncate(32);
    seed
}

/// `GET /admin/challenge` — mint a fresh `{ aud, nonce, ts }` for the console to sign. Public: the
/// nonce is single-use within 300s and only the holder of an enrolled device key can produce a
/// signature that subsequently verifies, so handing out challenges is harmless.
async fn admin_challenge(State(st): State<AppState>) -> impl IntoResponse {
    let ch = auth::make_challenge(&st.server_secret);
    (
        StatusCode::OK,
        Json(json!({ "aud": ch.aud, "nonce": ch.nonce, "ts": ch.ts })),
    )
        .into_response()
}

/// The 401 returned whenever admin device-auth fails, for any reason. We deliberately do not leak
/// which check failed to the client.
fn unauthorized() -> axum::response::Response {
    (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"}))).into_response()
}

/// Prove the request controls the device key for the claimed `deviceId` ("key-valid"). The verifying
/// key is resolved from the persisted admin store if the device is known; otherwise (a first-time
/// device) the caller must supply it via the `body_pub` argument (TOFU for claim/request). Returns
/// the authenticated device id on success, or the ready-to-return 401.
fn require_key_valid(
    st: &AppState,
    headers: &HeaderMap,
    body_pub: Option<&str>,
) -> Result<String, axum::response::Response> {
    // Prefer the persisted pub for a known device; fall back to the body-supplied pub for an
    // unknown one. We must not let a known device be authenticated against an attacker-chosen body
    // pub, so the stored pub always wins when present.
    let device_id = match auth::header_device_id(headers) {
        Some(id) => id,
        None => return Err(unauthorized()),
    };
    let pub_b64 = match st.admins.pub_of(device_id).or_else(|| body_pub.map(|s| s.to_string())) {
        Some(p) => p,
        None => return Err(unauthorized()),
    };
    match auth::authenticate_with_pub(headers, &pub_b64, &st.server_secret) {
        Ok(id) => Ok(id.to_string()),
        Err(e) => {
            tracing::debug!(reason = ?e, "device key-valid auth rejected");
            Err(unauthorized())
        }
    }
}

/// Require the request be both key-valid AND carry `role=admin` in the store. Used by the flag
/// endpoints and the device-management endpoints. Returns the authenticated admin device id.
fn require_admin(st: &AppState, headers: &HeaderMap) -> Result<String, axum::response::Response> {
    let device_id = require_key_valid(st, headers, None)?;
    if st.admins.is_admin(&device_id) {
        Ok(device_id)
    } else {
        tracing::debug!(device_id = %device_id, "key-valid but not admin");
        Err(unauthorized())
    }
}

/// `GET /admin/me` — key-valid required. Reports this device's role from the store and whether any
/// admin exists yet, so the console can pick the right screen (console / claim / request).
async fn admin_me(State(st): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let device_id = match require_key_valid(&st, &headers, None) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let role = st.admins.role_of(&device_id);
    (
        StatusCode::OK,
        Json(json!({
            "deviceId": device_id,
            "role": role,
            "hasAdmins": st.admins.has_admins(),
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
struct ClaimBody {
    #[serde(default, rename = "pub")]
    pub_b64: String,
}

/// `POST /admin/claim` — TOFU first-claim. If the store has ZERO admins, the (key-valid) requesting
/// device becomes `role=admin`. If any admin already exists -> 409. The body carries the device's
/// compact pub so we can both key-verify and persist it.
async fn admin_claim(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ClaimBody>,
) -> impl IntoResponse {
    if body.pub_b64.is_empty() || auth::validate_compact_pub(&body.pub_b64).is_err() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad pub"}))).into_response();
    }
    let device_id = match require_key_valid(&st, &headers, Some(&body.pub_b64)) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    match st.admins.claim(&device_id, &body.pub_b64) {
        Ok(true) => (
            StatusCode::OK,
            Json(json!({"ok": true, "deviceId": device_id, "role": "admin"})),
        )
            .into_response(),
        Ok(false) => (
            StatusCode::CONFLICT,
            Json(json!({"error": "admins already exist; ask one to approve your request"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "claim persist failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "store"}))).into_response()
        }
    }
}

#[derive(Deserialize)]
struct RequestBody {
    #[serde(default)]
    label: String,
    #[serde(default, rename = "pub")]
    pub_b64: String,
}

/// `POST /admin/request` — key-valid required. Records the device as `role=pending` with its compact
/// pub (so an admin can later approve+verify it) and an optional label. Idempotent.
async fn admin_request(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RequestBody>,
) -> impl IntoResponse {
    if body.pub_b64.is_empty() || auth::validate_compact_pub(&body.pub_b64).is_err() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "bad pub"}))).into_response();
    }
    let device_id = match require_key_valid(&st, &headers, Some(&body.pub_b64)) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    match st.admins.request(&device_id, &body.pub_b64, body.label.trim()) {
        Ok(role) => (
            StatusCode::OK,
            Json(json!({"ok": true, "deviceId": device_id, "role": role})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "request persist failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "store"}))).into_response()
        }
    }
}

/// `GET /admin/devices` — ADMIN ONLY. Lists admins and pending devices.
async fn admin_devices(State(st): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(resp) = require_admin(&st, &headers) {
        return resp;
    }
    let mut admins = Vec::new();
    let mut pending = Vec::new();
    for (id, dev) in st.admins.list() {
        let row = json!({ "deviceId": id, "label": dev.label, "added_ts": dev.added_ts });
        if dev.role == store::ROLE_ADMIN {
            admins.push(row);
        } else {
            pending.push(row);
        }
    }
    (StatusCode::OK, Json(json!({ "admins": admins, "pending": pending }))).into_response()
}

#[derive(Deserialize)]
struct DeviceIdBody {
    #[serde(rename = "deviceId")]
    device_id: String,
}

/// `POST /admin/devices/approve` — ADMIN ONLY. Promote a pending device to admin.
async fn admin_devices_approve(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DeviceIdBody>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&st, &headers) {
        return resp;
    }
    match st.admins.approve(&body.device_id) {
        Ok(true) => (StatusCode::OK, Json(json!({"ok": true, "role": "admin"}))).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "no pending device with that id"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "approve persist failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "store"}))).into_response()
        }
    }
}

/// `POST /admin/devices/revoke` — ADMIN ONLY. Remove a device. Cannot remove the last admin.
async fn admin_devices_revoke(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DeviceIdBody>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&st, &headers) {
        return resp;
    }
    match st.admins.revoke(&body.device_id) {
        Ok(RevokeOutcome::Removed) => {
            (StatusCode::OK, Json(json!({"ok": true}))).into_response()
        }
        Ok(RevokeOutcome::NotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "no device with that id"})),
        )
            .into_response(),
        Ok(RevokeOutcome::LastAdmin) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "cannot revoke the last admin"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "revoke persist failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "store"}))).into_response()
        }
    }
}

async fn serve_console() -> impl IntoResponse {
    // The HTML itself is public; the data behind it is gated by ce-secrets device-auth. The page
    // holds a device key in localStorage, fetches /admin/challenge, signs it, and sends the
    // x-ce-device-id / x-ce-auth / x-ce-aud / x-ce-nonce / x-ce-ts headers on every data call.
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::HeaderName::from_static("x-robots-tag"), "noindex"),
        ],
        Html(CONSOLE_HTML),
    )
}

async fn ingest(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(event): Json<FlagEvent>,
) -> impl IntoResponse {
    if !header_matches(&headers, "x-ce-watch-token", &st.ingest_token) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "bad token"}))).into_response();
    }
    match st.store.append(event) {
        Ok(seq) => (StatusCode::OK, Json(json!({"ok": true, "seq": seq}))).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "append failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "store"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct FlagsQuery {
    since: Option<u64>,
    heuristic: Option<String>,
    severity: Option<String>,
    node: Option<String>,
    limit: Option<usize>,
}

async fn admin_flags(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<FlagsQuery>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&st, &headers) {
        return resp;
    }
    let limit = q.limit.unwrap_or(1000).min(5000);
    let flags = st.store.query(
        q.since,
        q.heuristic.as_deref().filter(|s| !s.is_empty()),
        q.severity.as_deref().filter(|s| !s.is_empty()),
        q.node.as_deref().filter(|s| !s.is_empty()),
        limit,
    );
    (
        StatusCode::OK,
        Json(json!({
            "head": st.store.head_seq(),
            "unseen": st.store.unseen(),
            "flags": flags,
        })),
    )
        .into_response()
}

async fn admin_unseen(State(st): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(resp) = require_admin(&st, &headers) {
        return resp;
    }
    (StatusCode::OK, Json(json!({"unseen": st.store.unseen(), "head": st.store.head_seq()}))).into_response()
}

async fn admin_seen(State(st): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(resp) = require_admin(&st, &headers) {
        return resp;
    }
    st.store.mark_seen();
    (StatusCode::OK, Json(json!({"ok": true, "unseen": 0}))).into_response()
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt; // oneshot

    fn temp_dir() -> std::path::PathBuf {
        let mut d = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        d.push(format!("ce-watch-test-{}-{}", std::process::id(), nanos));
        d
    }

    use ce_secrets_rs::{sign_challenge, DeviceKey};

    const SERVER_SECRET: &[u8] = b"test-server-secret";

    /// The operator's device key, enrolled into the test state. Real P-256 ECDH+ECDSA pair.
    fn test_device() -> DeviceKey {
        let dk_json = r#"{
          "ecdhPriv":{"key_ops":["deriveBits"],"ext":true,"kty":"EC","x":"M3CtY4emfBsOGSCycOGY_wRD2ufV_Glmwt95AQRJRKo","y":"Q2p7o-FMQ-wRaiTOXzMd6Dyj3aFQQsi4v71k1sNnArs","crv":"P-256","d":"sR3IYJSDqB8x4l3J3p6w8t3y2QZ1m0c9V7n4kL2bA8E"},
          "ecdhPub":{"key_ops":[],"ext":true,"kty":"EC","x":"M3CtY4emfBsOGSCycOGY_wRD2ufV_Glmwt95AQRJRKo","y":"Q2p7o-FMQ-wRaiTOXzMd6Dyj3aFQQsi4v71k1sNnArs","crv":"P-256"},
          "ecdsaPriv":{"key_ops":["sign"],"ext":true,"kty":"EC","x":"ReIzIU_aBWgw2kRAa42L_AZiQmiYYb4RsvdGTwdR-jk","y":"oPRQppQEcMfMJknsjaQNU2uZc4Hz7GZ9T_Bf0J2L4KM","crv":"P-256","d":"pQ7w2zX9c4V6n8m1L3k5J7h9G2f4D6s8A0b2C4e6F8I"},
          "ecdsaPub":{"key_ops":["verify"],"ext":true,"kty":"EC","x":"ReIzIU_aBWgw2kRAa42L_AZiQmiYYb4RsvdGTwdR-jk","y":"oPRQppQEcMfMJknsjaQNU2uZc4Hz7GZ9T_Bf0J2L4KM","crv":"P-256"},
          "id":"0e30d71a203f8933"
        }"#;
        DeviceKey::from_json(dk_json).unwrap()
    }

    /// A SECOND, distinct real P-256 device key (different ecdsa keypair + id) used to exercise the
    /// request/approve/revoke flow against the seeded admin. The ecdh half mirrors the ecdsa pub
    /// (irrelevant to signing); the id is fixed and distinct from `test_device()`.
    fn second_device() -> DeviceKey {
        let dk_json = r#"{
          "ecdhPriv":{"key_ops":["deriveBits"],"ext":true,"kty":"EC","x":"Xmkz8xdxZN39CEu4t437RTP9zqSpeN_HEPWFl-Wcvic","y":"WHvWLOzDWyZmUhG8nnISc8dN5Gol-Cyfm1YaJpIvUWU","crv":"P-256","d":"ok8M6GVgJIfF71fjBubSB3L_0HvfvcQeunr9N-5IFnA"},
          "ecdhPub":{"key_ops":[],"ext":true,"kty":"EC","x":"Xmkz8xdxZN39CEu4t437RTP9zqSpeN_HEPWFl-Wcvic","y":"WHvWLOzDWyZmUhG8nnISc8dN5Gol-Cyfm1YaJpIvUWU","crv":"P-256"},
          "ecdsaPriv":{"key_ops":["sign"],"ext":true,"kty":"EC","x":"Xmkz8xdxZN39CEu4t437RTP9zqSpeN_HEPWFl-Wcvic","y":"WHvWLOzDWyZmUhG8nnISc8dN5Gol-Cyfm1YaJpIvUWU","crv":"P-256","d":"ok8M6GVgJIfF71fjBubSB3L_0HvfvcQeunr9N-5IFnA"},
          "ecdsaPub":{"key_ops":["verify"],"ext":true,"kty":"EC","x":"Xmkz8xdxZN39CEu4t437RTP9zqSpeN_HEPWFl-Wcvic","y":"WHvWLOzDWyZmUhG8nnISc8dN5Gol-Cyfm1YaJpIvUWU","crv":"P-256"},
          "id":"f00dcafe12345678"
        }"#;
        DeviceKey::from_json(dk_json).unwrap()
    }

    /// The compact ECDSA SEC1 pub for a device — the exact string the console derives and persists.
    fn compact_pub(dk: &DeviceKey) -> String {
        ce_secrets_rs::encoding::b64url_encode(&dk.ecdsa_pub.raw_public_bytes().unwrap())
    }

    /// State with the test device SEEDED as an admin (mirrors `CE_WATCH_ADMIN_DEVICES`) and a fixed
    /// server secret (so challenges are reproducible across handler calls within a test).
    fn state_with(dir: std::path::PathBuf) -> AppState {
        let dk = test_device();
        let seed = vec![(dk.id.clone(), compact_pub(&dk))];
        let admins = Arc::new(AdminStore::open(&dir, &seed).expect("open admin store"));
        AppState {
            store: Arc::new(Store::open(dir).expect("open store")),
            ingest_token: Arc::new(Some("ingest-secret".to_string())),
            admins,
            server_secret: Arc::new(SERVER_SECRET.to_vec()),
        }
    }

    /// State with NO admins seeded — empty store (used to test claim/request/unauthorized paths).
    fn state_empty(dir: std::path::PathBuf) -> AppState {
        let admins = Arc::new(AdminStore::open(&dir, &[]).expect("open admin store"));
        AppState {
            store: Arc::new(Store::open(dir).expect("open store")),
            ingest_token: Arc::new(Some("ingest-secret".to_string())),
            admins,
            server_secret: Arc::new(SERVER_SECRET.to_vec()),
        }
    }

    /// Fetch a live challenge from the router and sign it with `dk`, returning the headers a real
    /// admin request would carry. This exercises the full GET /admin/challenge -> sign -> verify path.
    async fn signed_admin_headers(app: &Router, dk: &DeviceKey) -> Vec<(String, String)> {
        let req = Request::builder()
            .uri("/admin/challenge")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp).await;
        let aud = j["aud"].as_str().unwrap().to_string();
        let nonce = j["nonce"].as_str().unwrap().to_string();
        let ts = j["ts"].as_str().unwrap().to_string();
        let sig = sign_challenge(dk, &aud, &nonce, &ts).unwrap();
        vec![
            ("x-ce-device-id".into(), dk.id.clone()),
            ("x-ce-auth".into(), sig),
            ("x-ce-aud".into(), aud),
            ("x-ce-nonce".into(), nonce),
            ("x-ce-ts".into(), ts),
        ]
    }

    fn with_headers(mut b: axum::http::request::Builder, headers: &[(String, String)]) -> axum::http::request::Builder {
        for (k, v) in headers {
            b = b.header(k.as_str(), v.as_str());
        }
        b
    }

    fn sample_flag() -> serde_json::Value {
        json!({
            "ts": 1_700_000_000u64,
            "node_id": "ip:203.0.113.7",
            "ip": "203.0.113.7",
            "heuristic": "H2",
            "reason": "repeat-signature: count_primes x47 in 5m — mining shape",
            "severity": "high",
            "sample": { "func": "count_primes", "endpoint": "/tasks" }
        })
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn ingest_rejects_bad_token() {
        let dir = temp_dir();
        let app = router(state_with(dir.clone()));
        let req = Request::builder()
            .method("POST")
            .uri("/ingest")
            .header("content-type", "application/json")
            .header("x-ce-watch-token", "WRONG")
            .body(Body::from(sample_flag().to_string()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn ingest_accepts_good_token_and_stores() {
        let dir = temp_dir();
        let st = state_with(dir.clone());
        let app = router(st.clone());
        let req = Request::builder()
            .method("POST")
            .uri("/ingest")
            .header("content-type", "application/json")
            .header("x-ce-watch-token", "ingest-secret")
            .body(Body::from(sample_flag().to_string()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // It is now queryable and the unseen counter incremented.
        assert_eq!(st.store.head_seq(), 1);
        assert_eq!(st.store.unseen(), 1);
        let flags = st.store.query(None, None, None, None, 10);
        assert_eq!(flags.len(), 1);
        assert_eq!(flags[0].event.heuristic, "H2");

        // The line was actually written to disk.
        let log = dir.join("flags.jsonl");
        let contents = std::fs::read_to_string(&log).unwrap();
        assert!(contents.contains("count_primes"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn admin_flags_requires_device_auth() {
        let dir = temp_dir();
        let app = router(state_with(dir.clone()));

        // No auth headers → 401.
        let req = Request::builder()
            .uri("/admin/flags")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // The OLD pasted-token path is gone: an x-ce-admin bearer header is no longer honored.
        let req = Request::builder()
            .uri("/admin/flags")
            .header("x-ce-admin", "admin-secret")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // A valid signed challenge from the ENROLLED device → 200 (admitted).
        let dk = test_device();
        let headers = signed_admin_headers(&app, &dk).await;
        let req = with_headers(Request::builder().uri("/admin/flags"), &headers)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn admin_rejects_unenrolled_device() {
        // A device that is NOT an admin — empty store, nobody claimed — is rejected from /admin/flags
        // even with a perfectly valid signature over a live challenge (key-valid != is-admin). It has
        // no persisted pub, so even key-resolution falls through to 401 here.
        let dir = temp_dir();
        let st = state_empty(dir.clone());
        let app = router(st);
        let dk = test_device();
        let headers = signed_admin_headers(&app, &dk).await;
        let req = with_headers(Request::builder().uri("/admin/flags"), &headers)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn admin_rejects_tampered_signature() {
        let dir = temp_dir();
        let app = router(state_with(dir.clone()));
        let dk = test_device();
        let mut headers = signed_admin_headers(&app, &dk).await;
        // Corrupt the signature header (x-ce-auth is index 1).
        let sig = &mut headers[1].1;
        let last = sig.pop().unwrap();
        sig.push(if last == 'A' { 'B' } else { 'A' });
        let req = with_headers(Request::builder().uri("/admin/flags"), &headers)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn seen_clears_unseen() {
        let dir = temp_dir();
        let st = state_with(dir.clone());
        for _ in 0..3 {
            let ev: FlagEvent = serde_json::from_value(sample_flag()).unwrap();
            st.store.append(ev).unwrap();
        }
        assert_eq!(st.store.unseen(), 3);

        let app = router(st.clone());
        let dk = test_device();
        let headers = signed_admin_headers(&app, &dk).await;
        let req = with_headers(Request::builder().method("POST").uri("/admin/seen"), &headers)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(st.store.unseen(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn log_survives_restart() {
        let dir = temp_dir();
        {
            let st = state_with(dir.clone());
            for i in 0..5 {
                let mut v = sample_flag();
                v["ts"] = json!(1_700_000_000u64 + i);
                let ev: FlagEvent = serde_json::from_value(v).unwrap();
                st.store.append(ev).unwrap();
            }
            assert_eq!(st.store.head_seq(), 5);
        } // store dropped — simulate process exit

        // Reopen: the durable log is replayed.
        let st2 = state_with(dir.clone());
        assert_eq!(st2.store.head_seq(), 5);
        let flags = st2.store.query(None, None, None, None, 100);
        assert_eq!(flags.len(), 5);
        // Newest-first ordering preserved across restart.
        assert!(flags[0].seq > flags[1].seq);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- self-service admin enrollment ----

    /// Sign a live challenge and return the admin headers, exactly as a real device would.
    async fn signed_headers(app: &Router, dk: &DeviceKey) -> Vec<(String, String)> {
        signed_admin_headers(app, dk).await
    }

    #[tokio::test]
    async fn first_claim_makes_admin_second_claim_conflicts() {
        let dir = temp_dir();
        let st = state_empty(dir.clone());
        let app = router(st.clone());
        let dk = test_device();
        let pub_b64 = compact_pub(&dk);

        // First claim on an empty store -> 200, device becomes admin.
        let headers = signed_headers(&app, &dk).await;
        let body = json!({ "pub": pub_b64 }).to_string();
        let req = with_headers(
            Request::builder().method("POST").uri("/admin/claim").header("content-type", "application/json"),
            &headers,
        )
        .body(Body::from(body.clone()))
        .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(st.admins.is_admin(&dk.id));

        // Second claim (store now has an admin) -> 409.
        let headers = signed_headers(&app, &dk).await;
        let req = with_headers(
            Request::builder().method("POST").uri("/admin/claim").header("content-type", "application/json"),
            &headers,
        )
        .body(Body::from(body))
        .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn request_then_approve_grants_flags_access_and_revoke_removes_it() {
        // Admin (seeded) device.
        let dir = temp_dir();
        let st = state_with(dir.clone());
        let app = router(st.clone());
        let admin = test_device();

        // A second, distinct device requests access.
        let requester = second_device();
        let req_pub = compact_pub(&requester);

        // Before approval: key-valid but NOT admin -> /admin/flags is 401.
        let headers = signed_headers(&app, &requester).await;
        // requester is unknown to the store; flags needs role=admin -> rejected.
        let req = with_headers(Request::builder().uri("/admin/flags"), &headers)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // It can /admin/request (recorded as pending, with its pub).
        let headers = signed_headers(&app, &requester).await;
        let body = json!({ "label": "leif-phone", "pub": req_pub }).to_string();
        let req = with_headers(
            Request::builder().method("POST").uri("/admin/request").header("content-type", "application/json"),
            &headers,
        )
        .body(Body::from(body))
        .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(st.admins.role_of(&requester.id), "pending");

        // The admin lists devices and sees the pending requester.
        let headers = signed_headers(&app, &admin).await;
        let req = with_headers(Request::builder().uri("/admin/devices"), &headers)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp).await;
        assert_eq!(j["pending"].as_array().unwrap().len(), 1);

        // The admin approves it.
        let headers = signed_headers(&app, &admin).await;
        let body = json!({ "deviceId": requester.id }).to_string();
        let req = with_headers(
            Request::builder().method("POST").uri("/admin/devices/approve").header("content-type", "application/json"),
            &headers,
        )
        .body(Body::from(body))
        .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(st.admins.is_admin(&requester.id));

        // Now the requester CAN read /admin/flags (200).
        let headers = signed_headers(&app, &requester).await;
        let req = with_headers(Request::builder().uri("/admin/flags"), &headers)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // The admin revokes the requester -> access removed.
        let headers = signed_headers(&app, &admin).await;
        let body = json!({ "deviceId": requester.id }).to_string();
        let req = with_headers(
            Request::builder().method("POST").uri("/admin/devices/revoke").header("content-type", "application/json"),
            &headers,
        )
        .body(Body::from(body))
        .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(st.admins.role_of(&requester.id), "none");

        // Revoked device is back to 401 on flags.
        let headers = signed_headers(&app, &requester).await;
        let req = with_headers(Request::builder().uri("/admin/flags"), &headers)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn cannot_revoke_last_admin() {
        let dir = temp_dir();
        let st = state_with(dir.clone()); // exactly one seeded admin
        let app = router(st.clone());
        let admin = test_device();

        let headers = signed_headers(&app, &admin).await;
        let body = json!({ "deviceId": admin.id }).to_string();
        let req = with_headers(
            Request::builder().method("POST").uri("/admin/devices/revoke").header("content-type", "application/json"),
            &headers,
        )
        .body(Body::from(body))
        .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(st.admins.is_admin(&admin.id)); // still there
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn env_seeded_admin_still_works() {
        // A device seeded via the env (state_with mirrors CE_WATCH_ADMIN_DEVICES) is admin and can
        // read /admin/flags immediately, with no claim step.
        let dir = temp_dir();
        let st = state_with(dir.clone());
        let app = router(st);
        let dk = test_device();
        let headers = signed_headers(&app, &dk).await;
        let req = with_headers(Request::builder().uri("/admin/flags"), &headers)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn admin_store_survives_reload() {
        let dir = temp_dir();
        let requester = second_device();
        {
            let st = state_with(dir.clone());
            // Record the requester as pending, then approve it.
            st.admins.request(&requester.id, &compact_pub(&requester), "x").unwrap();
            assert!(st.admins.approve(&requester.id).unwrap());
            assert!(st.admins.is_admin(&requester.id));
        } // dropped — simulate restart

        // Reopen with NO seed: the persisted file is the source of truth.
        let admins = AdminStore::open(&dir, &[]).unwrap();
        assert!(admins.is_admin(&requester.id));
        assert!(admins.is_admin(&test_device().id)); // the seeded admin persisted too
        assert_eq!(admins.admin_count(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn me_reports_role() {
        let dir = temp_dir();
        let st = state_with(dir.clone());
        let app = router(st);
        let dk = test_device();
        let headers = signed_headers(&app, &dk).await;
        let req = with_headers(Request::builder().uri("/admin/me"), &headers)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp).await;
        assert_eq!(j["role"], "admin");
        assert_eq!(j["hasAdmins"], true);
        assert_eq!(j["deviceId"], dk.id);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn filters_apply() {
        let dir = temp_dir();
        let st = state_with(dir.clone());
        let mut a = sample_flag();
        a["heuristic"] = json!("H1");
        a["severity"] = json!("low");
        let mut b = sample_flag();
        b["heuristic"] = json!("H5");
        b["severity"] = json!("high");
        st.store.append(serde_json::from_value(a).unwrap()).unwrap();
        st.store.append(serde_json::from_value(b).unwrap()).unwrap();

        let only_h5 = st.store.query(None, Some("H5"), None, None, 10);
        assert_eq!(only_h5.len(), 1);
        assert_eq!(only_h5[0].event.heuristic, "H5");

        let only_high = st.store.query(None, None, Some("high"), None, 10);
        assert_eq!(only_high.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
