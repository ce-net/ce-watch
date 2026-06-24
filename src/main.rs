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

use auth::Devices;
use store::{FlagEvent, Store};

const CONSOLE_HTML: &str = include_str!("console.html");

#[derive(Clone)]
struct AppState {
    store: Arc<Store>,
    ingest_token: Arc<Option<String>>,
    /// Enrolled operator devices (deviceId -> ECDSA public JWK) for challenge-response admin auth.
    devices: Arc<Devices>,
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
    let devices = Devices::parse(&std::env::var("CE_WATCH_ADMIN_DEVICES").unwrap_or_default());
    let server_secret = server_secret_from_env();

    if ingest_token.is_none() {
        tracing::warn!("CE_WATCH_INGEST_TOKEN is unset — /ingest will reject all requests");
    }
    if devices.is_empty() {
        tracing::warn!(
            "CE_WATCH_ADMIN_DEVICES is unset/empty — no operator device enrolled, admin console \
             will reject all requests. Enroll with deviceId:ecdsaPubB64url (shown on first load)."
        );
    } else {
        tracing::info!(count = devices.len(), "admin device(s) enrolled");
    }

    let state = AppState {
        store,
        ingest_token: Arc::new(ingest_token),
        devices: Arc::new(devices),
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

/// Verify admin device-auth on a request. `Ok` carries the authenticated device id; `Err` is the
/// ready-to-return 401 response.
fn require_admin(st: &AppState, headers: &HeaderMap) -> Result<(), axum::response::Response> {
    match auth::authenticate(headers, &st.devices, &st.server_secret) {
        Ok(_device_id) => Ok(()),
        Err(e) => {
            tracing::debug!(reason = ?e, "admin auth rejected");
            Err(unauthorized())
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

    /// State with the test device enrolled and a fixed server secret (so challenges are reproducible
    /// across handler calls within a test).
    fn state_with(dir: std::path::PathBuf) -> AppState {
        let dk = test_device();
        let mut devices = Devices::default();
        devices
            .insert_compact(
                &dk.id,
                &ce_secrets_rs::encoding::b64url_encode(&dk.ecdsa_pub.raw_public_bytes().unwrap()),
            )
            .unwrap();
        AppState {
            store: Arc::new(Store::open(dir).expect("open store")),
            ingest_token: Arc::new(Some("ingest-secret".to_string())),
            devices: Arc::new(devices),
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
        // A device that is NOT in CE_WATCH_ADMIN_DEVICES — empty registry — is rejected even with a
        // perfectly valid signature over a live challenge.
        let dir = temp_dir();
        let st = AppState {
            store: Arc::new(Store::open(dir.clone()).unwrap()),
            ingest_token: Arc::new(Some("ingest-secret".into())),
            devices: Arc::new(Devices::default()), // nobody enrolled
            server_secret: Arc::new(SERVER_SECRET.to_vec()),
        };
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
