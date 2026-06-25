//! ce-monitor — the operator's security console for CE.
//!
//! A light axum service that lives beside the relay. It does two things:
//!
//!   1. Receives flag events from the hub's abuse detector **over the CE mesh** (a directed
//!      `send_message` on topic `ce-monitor/flag`, authenticated by the libp2p sender NodeId) and
//!      appends them to a durable, bounded, append-only log. There is NO HTTP and NO shared token
//!      between the hub and ce-monitor — see [`mesh`]. (The old `POST /ingest` + `x-ce-monitor-token`
//!      cheat is gone.)
//!   2. Serves an admin-only single-page "security console" that renders the flag log as a
//!      structured, filterable table with an unseen-count indicator.
//!
//! ce-monitor holds NO device registry and NO in-process crypto. It is a thin **relying party** of
//! **ce-auth**, reached over the CE MESH (not HTTP): every admin request carries the operator's
//! device-signed headers, which ce-monitor forwards to ce-auth's `verify` verb (located via
//! [`ce_rs::locate`], sent via [`ce_rs::CeClient::request`] on topic `ce-auth/rpc`); it admits iff
//! `{ok:true}`. Device enrollment, claim, request, approve and revoke all live in ce-auth. If no live
//! ce-auth instance can be reached, ce-monitor fails CLOSED (503).
//!
//! `GET /admin/challenge` runs ce-auth's `challenge` verb over the mesh and relays the
//! `{ aud, nonce, ts }` so the browser console never needs to know how to reach ce-auth. That HTTP
//! edge is the only HTTP in ce-monitor's auth path, and it terminates at this process; the hop to
//! ce-auth is pure mesh.

mod auth;
mod mesh;
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

use auth::{DynVerifier, MeshVerifier, VerifyError};
use mesh::MeshIngest;
use store::Store;

const CONSOLE_HTML: &str = include_str!("console.html");

#[derive(Clone)]
struct AppState {
    store: Arc<Store>,
    /// The relying-party verifier: runs ce-auth's `challenge` / `verify` verbs over the mesh.
    /// Injectable so tests can supply a mock instead of a live ce-auth + node.
    verifier: Arc<dyn DynVerifier>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ce_monitor=info,tower_http=warn".into()),
        )
        .init();

    let data_dir = store::default_data_dir();
    let store = Arc::new(Store::open(data_dir.clone())?);

    // Attach to the co-located ce node ONCE; the same client drives both the flag receiver and the
    // mesh relying-party verifier (locate + request ce-auth). No HTTP hop to ce-auth.
    let node_url = mesh::ce_node_url();
    let ce = ce_rs::CeClient::new(node_url.clone());
    tracing::info!(node_url = %node_url, service = auth::CE_AUTH_SERVICE, "delegating admin device-auth to ce-auth over the mesh");

    let verifier: Arc<dyn DynVerifier> = Arc::new(MeshVerifier::new(ce.clone()));

    // Flag ingest is a MESH receiver: drain the node's app-message stream, admitting only flags from
    // the hub's NodeId on topic `ce-monitor/flag`. No HTTP, no token.
    let hub_node = mesh::hub_node();
    if hub_node.is_empty() {
        tracing::warn!(
            "CE_MONITOR_HUB_NODE is unset — every mesh flag will be rejected (no authorized hub)"
        );
    } else {
        tracing::info!(hub_node = %hub_node, node_url = %node_url, "ce-monitor mesh flag ingest armed");
    }
    let ingest = Arc::new(MeshIngest::new(store.clone(), hub_node));
    tokio::spawn(mesh::run(ce.clone(), ingest));

    let state = AppState { store, verifier };

    let app = router(state);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8971);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!(%addr, data_dir = %data_dir.display(), "ce-monitor listening");

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
        .route("/admin/challenge", get(admin_challenge))
        .route("/admin/flags", get(admin_flags))
        .route("/admin/unseen", get(admin_unseen))
        .route("/admin/seen", post(admin_seen))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

/// `GET /admin/challenge` — run ce-auth's `challenge` verb for `aud=ce-monitor` over the mesh and relay
/// the `{ aud, nonce, ts }` to the browser console. The console signs it with its device key; only a
/// device enrolled in ce-auth can produce a signature that ce-auth's `verify` will later accept, so
/// handing out challenges is harmless. If no live ce-auth instance can be reached we fail closed
/// (503). This is the one HTTP edge (console -> ce-monitor); the hop to ce-auth is pure mesh.
async fn admin_challenge(State(st): State<AppState>) -> impl IntoResponse {
    match st.verifier.challenge_dyn().await {
        Ok(ch) => (StatusCode::OK, Json(ch)).into_response(),
        Err(VerifyError::Unreachable(reason)) => {
            tracing::warn!(reason = %reason, "ce-auth challenge unreachable — failing closed (503)");
            ce_auth_down()
        }
        // challenge() only ever returns Unreachable on failure; any other variant is still fail-safe.
        Err(_) => ce_auth_down(),
    }
}

/// The 401 returned whenever admin device-auth is denied by ce-auth (bad sig, expired nonce, not an
/// admin) or when the device-signed headers are absent. We do not leak which check failed.
fn unauthorized() -> axum::response::Response {
    (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"}))).into_response()
}

/// The 503 returned whenever ce-auth cannot be reached. Fail-closed: an auth outage NEVER admits.
fn ce_auth_down() -> axum::response::Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"error": "auth service unavailable"})),
    )
        .into_response()
}

/// Gate an admin request through ce-auth over the mesh. Returns the authenticated admin device id,
/// or the ready response: 401 on missing headers / denied, 503 on ce-auth unreachable (fail-closed —
/// an auth outage NEVER admits).
async fn require_admin_async(
    st: &AppState,
    headers: &HeaderMap,
) -> Result<String, axum::response::Response> {
    let res = auth::require_admin(st.verifier.as_ref(), headers).await;
    match res {
        Ok(id) => Ok(id),
        Err(VerifyError::MissingHeaders) => Err(unauthorized()),
        Err(VerifyError::Denied(v)) => {
            tracing::debug!(role = %v.role, device_id = %v.device_id, "ce-auth denied admin");
            Err(unauthorized())
        }
        Err(VerifyError::Unreachable(reason)) => {
            tracing::warn!(reason = %reason, "ce-auth unreachable — failing closed (503)");
            Err(ce_auth_down())
        }
    }
}

async fn serve_console() -> impl IntoResponse {
    // The HTML is public; the data behind it is gated by ce-auth device-auth. The page holds a
    // device key in localStorage, fetches /admin/challenge (proxied to ce-auth), signs it, and sends
    // the x-ce-device-id / x-ce-auth / x-ce-aud / x-ce-nonce / x-ce-ts headers on every data call.
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::HeaderName::from_static("x-robots-tag"), "noindex"),
        ],
        Html(CONSOLE_HTML),
    )
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
    if let Err(resp) = require_admin_async(&st, &headers).await {
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
    if let Err(resp) = require_admin_async(&st, &headers).await {
        return resp;
    }
    (StatusCode::OK, Json(json!({"unseen": st.store.unseen(), "head": st.store.head_seq()}))).into_response()
}

async fn admin_seen(State(st): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(resp) = require_admin_async(&st, &headers).await {
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
    use auth::{Challenge, SignedHeaders, Verifier, VerifyResponse};
    use axum::body::Body;
    use axum::http::Request;
    use std::sync::Mutex;
    use store::FlagEvent;
    use tower::ServiceExt; // oneshot

    fn temp_dir() -> std::path::PathBuf {
        let mut d = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        d.push(format!("ce-monitor-test-{}-{}", std::process::id(), nanos));
        d
    }

    /// A mock [`Verifier`] standing in for ce-auth's mesh `verify` / `challenge` verbs. Configured to
    /// admit, deny, or be unreachable, and records the headers it was asked to verify so tests can
    /// assert the forward. No live node or HTTP involved — it injects exactly what the mesh path
    /// would return.
    struct MockVerifier {
        outcome: MockOutcome,
        seen: Mutex<Option<SignedHeaders>>,
    }
    #[derive(Clone)]
    enum MockOutcome {
        /// `{ok:true}` — admit, with this device id / role echoed back.
        Ok { device_id: String, role: String },
        /// `{ok:false}` — ce-auth denied.
        Deny,
        /// No live ce-auth instance / mesh transport failed.
        Down,
    }
    impl MockVerifier {
        fn new(outcome: MockOutcome) -> Self {
            Self { outcome, seen: Mutex::new(None) }
        }
    }
    impl Verifier for MockVerifier {
        async fn verify(&self, headers: &SignedHeaders) -> Result<VerifyResponse, VerifyError> {
            *self.seen.lock().unwrap() = Some(headers.clone());
            match &self.outcome {
                MockOutcome::Ok { device_id, role } => Ok(VerifyResponse {
                    ok: true,
                    role: role.clone(),
                    device_id: device_id.clone(),
                }),
                MockOutcome::Deny => Err(VerifyError::Denied(VerifyResponse {
                    ok: false,
                    role: "none".into(),
                    device_id: String::new(),
                })),
                MockOutcome::Down => Err(VerifyError::Unreachable("mock down".into())),
            }
        }

        async fn challenge(&self) -> Result<Challenge, VerifyError> {
            match &self.outcome {
                // A reachable ce-auth (Ok or Deny outcome) mints a challenge; an unreachable one
                // fails closed exactly like the mesh path.
                MockOutcome::Down => Err(VerifyError::Unreachable("mock down".into())),
                _ => Ok(Challenge {
                    aud: auth::AUD.to_string(),
                    nonce: "abcd1234".to_string(),
                    ts: "2026-06-24T00:00:00.000Z".to_string(),
                }),
            }
        }
    }

    fn state_with(dir: std::path::PathBuf, outcome: MockOutcome) -> AppState {
        AppState {
            store: Arc::new(Store::open(dir).expect("open store")),
            verifier: Arc::new(MockVerifier::new(outcome)),
        }
    }

    /// The five device-signed headers a real console sends; values are arbitrary because the mock
    /// verifier decides the verdict, not their content.
    fn signed_headers() -> Vec<(String, String)> {
        vec![
            ("x-ce-device-id".into(), "dev-abc".into()),
            ("x-ce-auth".into(), "sig-xyz".into()),
            ("x-ce-aud".into(), "ce-monitor".into()),
            ("x-ce-nonce".into(), "nonce-1".into()),
            ("x-ce-ts".into(), "2026-06-24T00:00:00.000Z".into()),
        ]
    }

    fn with_headers(
        mut b: axum::http::request::Builder,
        headers: &[(String, String)],
    ) -> axum::http::request::Builder {
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

    // ---- relying-party admin auth (delegates to ce-auth /verify) ----

    #[tokio::test]
    async fn admin_flags_missing_headers_is_401() {
        let dir = temp_dir();
        let app = router(state_with(
            dir.clone(),
            MockOutcome::Ok { device_id: "d".into(), role: "admin".into() },
        ));
        // No device-signed headers → 401 before ce-auth is even consulted.
        let req = Request::builder().uri("/admin/flags").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn admin_flags_ce_auth_ok_admits() {
        let dir = temp_dir();
        let app = router(state_with(
            dir.clone(),
            MockOutcome::Ok { device_id: "dev-abc".into(), role: "admin".into() },
        ));
        let req = with_headers(Request::builder().uri("/admin/flags"), &signed_headers())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn admin_flags_ce_auth_deny_is_401() {
        let dir = temp_dir();
        let app = router(state_with(dir.clone(), MockOutcome::Deny));
        let req = with_headers(Request::builder().uri("/admin/flags"), &signed_headers())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn admin_flags_ce_auth_down_is_503() {
        let dir = temp_dir();
        let app = router(state_with(dir.clone(), MockOutcome::Down));
        let req = with_headers(Request::builder().uri("/admin/flags"), &signed_headers())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn verifier_receives_forwarded_signed_headers() {
        // The handler must forward the device-signed headers off the request to the verifier
        // verbatim, so ce-auth can re-derive the nonce and check the signature. We hold a typed
        // handle to the mock so we can read exactly what it was asked to verify.
        let dir = temp_dir();
        let mock = Arc::new(MockVerifier::new(MockOutcome::Ok {
            device_id: "dev-abc".into(),
            role: "admin".into(),
        }));
        let st = AppState {
            store: Arc::new(Store::open(dir.clone()).expect("open store")),
            verifier: mock.clone(),
        };
        let app = router(st);
        let req = with_headers(Request::builder().uri("/admin/unseen"), &signed_headers())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let seen = mock.seen.lock().unwrap().clone().expect("verifier was called");
        assert_eq!(seen.device_id, "dev-abc");
        assert_eq!(seen.sig, "sig-xyz");
        assert_eq!(seen.aud, "ce-monitor");
        assert_eq!(seen.nonce, "nonce-1");
        assert_eq!(seen.ts, "2026-06-24T00:00:00.000Z");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn seen_clears_unseen_when_admitted() {
        let dir = temp_dir();
        let st = state_with(
            dir.clone(),
            MockOutcome::Ok { device_id: "dev-abc".into(), role: "admin".into() },
        );
        for _ in 0..3 {
            let ev: FlagEvent = serde_json::from_value(sample_flag()).unwrap();
            st.store.append(ev).unwrap();
        }
        assert_eq!(st.store.unseen(), 3);

        let app = router(st.clone());
        let req = with_headers(
            Request::builder().method("POST").uri("/admin/seen"),
            &signed_headers(),
        )
        .body(Body::empty())
        .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(st.store.unseen(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn seen_denied_does_not_clear_unseen() {
        // A denied admin must NOT be able to clear the unseen counter.
        let dir = temp_dir();
        let st = state_with(dir.clone(), MockOutcome::Deny);
        let ev: FlagEvent = serde_json::from_value(sample_flag()).unwrap();
        st.store.append(ev).unwrap();
        assert_eq!(st.store.unseen(), 1);

        let app = router(st.clone());
        let req = with_headers(
            Request::builder().method("POST").uri("/admin/seen"),
            &signed_headers(),
        )
        .body(Body::empty())
        .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(st.store.unseen(), 1); // unchanged
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn admin_challenge_relays_ce_auth_mesh_challenge() {
        // A reachable ce-auth (mock) mints a challenge over the mesh; /admin/challenge relays the
        // { aud, nonce, ts } to the console verbatim.
        let dir = temp_dir();
        let st = state_with(
            dir.clone(),
            MockOutcome::Ok { device_id: "d".into(), role: "admin".into() },
        );
        let app = router(st);

        let req = Request::builder().uri("/admin/challenge").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp).await;
        assert_eq!(j["aud"], "ce-monitor");
        assert_eq!(j["nonce"], "abcd1234");
        assert_eq!(j["ts"], "2026-06-24T00:00:00.000Z");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn admin_challenge_ce_auth_down_is_503() {
        // No live ce-auth instance over the mesh → challenge fails → fail closed (503).
        let dir = temp_dir();
        let st = state_with(dir.clone(), MockOutcome::Down);
        let app = router(st);
        let req = Request::builder().uri("/admin/challenge").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn log_survives_restart() {
        let dir = temp_dir();
        {
            let st = state_with(dir.clone(), MockOutcome::Deny);
            for i in 0..5 {
                let mut v = sample_flag();
                v["ts"] = json!(1_700_000_000u64 + i);
                let ev: FlagEvent = serde_json::from_value(v).unwrap();
                st.store.append(ev).unwrap();
            }
            assert_eq!(st.store.head_seq(), 5);
        }

        let st2 = state_with(dir.clone(), MockOutcome::Deny);
        assert_eq!(st2.store.head_seq(), 5);
        let flags = st2.store.query(None, None, None, None, 100);
        assert_eq!(flags.len(), 5);
        assert!(flags[0].seq > flags[1].seq);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn filters_apply() {
        let dir = temp_dir();
        let st = state_with(dir.clone(), MockOutcome::Deny);
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
