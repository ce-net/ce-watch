//! ce-watch — the operator's security console for CE.
//!
//! A light axum service that lives beside the relay. It does two things:
//!
//!   1. Receives flag events from the hub's abuse detector **over the CE mesh** (a directed
//!      `send_message` on topic `ce-watch/flag`, authenticated by the libp2p sender NodeId) and
//!      appends them to a durable, bounded, append-only log. There is NO HTTP and NO shared token
//!      between the hub and ce-watch — see [`mesh`]. (The old `POST /ingest` + `x-ce-watch-token`
//!      cheat is gone.)
//!   2. Serves an admin-only single-page "security console" that renders the flag log as a
//!      structured, filterable table with an unseen-count indicator.
//!
//! ce-watch holds NO device registry and NO in-process crypto. It is a thin **relying party** of
//! **ce-auth**: every admin request carries the operator's device-signed headers, which ce-watch
//! forwards to ce-auth's `POST /verify`; it admits iff `{ok:true}`. Device enrollment, claim,
//! request, approve and revoke all live in ce-auth (`auth.ce-net.com`). If ce-auth is unreachable,
//! ce-watch fails CLOSED (503).
//!
//! `GET /admin/challenge` proxies ce-auth's `GET /challenge?aud=ce-watch` verbatim so the console
//! never needs to know ce-auth's address.

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

use auth::{HttpVerifier, Verifier, VerifyError};
use mesh::MeshIngest;
use store::Store;

const CONSOLE_HTML: &str = include_str!("console.html");

#[derive(Clone)]
struct AppState {
    store: Arc<Store>,
    /// Base URL of ce-auth (e.g. `http://127.0.0.1:8972`), used to proxy `/challenge` and to fetch
    /// the (lazily-built) [`Verifier`]'s endpoint. Slash-trimmed.
    ce_auth_url: Arc<String>,
    /// The relying-party verifier: forwards device-signed headers to ce-auth's `/verify`. Injectable
    /// so tests can supply a mock instead of a live ce-auth.
    verifier: Arc<dyn Verifier>,
    /// HTTP client used to proxy `GET /admin/challenge` -> ce-auth `GET /challenge?aud=ce-watch`.
    http: reqwest::Client,
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

    let ce_auth_url = auth::ce_auth_url();
    tracing::info!(ce_auth_url = %ce_auth_url, "delegating admin device-auth to ce-auth");

    let verifier: Arc<dyn Verifier> = Arc::new(HttpVerifier::new(ce_auth_url.clone()));

    // Flag ingest is a MESH receiver: attach to the co-located ce node and drain its app-message
    // stream, admitting only flags from the hub's NodeId on topic `ce-watch/flag`. No HTTP, no token.
    let node_url = mesh::ce_node_url();
    let hub_node = mesh::hub_node();
    if hub_node.is_empty() {
        tracing::warn!(
            "CE_WATCH_HUB_NODE is unset — every mesh flag will be rejected (no authorized hub)"
        );
    } else {
        tracing::info!(hub_node = %hub_node, node_url = %node_url, "ce-watch mesh flag ingest armed");
    }
    let ingest = Arc::new(MeshIngest::new(store.clone(), hub_node));
    tokio::spawn(mesh::run(node_url, ingest));

    let state = AppState {
        store,
        ce_auth_url: Arc::new(ce_auth_url),
        verifier,
        http: reqwest::Client::new(),
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
        .route("/admin/challenge", get(admin_challenge))
        .route("/admin/flags", get(admin_flags))
        .route("/admin/unseen", get(admin_unseen))
        .route("/admin/seen", post(admin_seen))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

/// `GET /admin/challenge` — proxy ce-auth's `GET /challenge?aud=ce-watch` verbatim. The console
/// signs the returned `{ aud, nonce, ts }` with its device key; only a device enrolled in ce-auth
/// can produce a signature that ce-auth will later accept, so handing out challenges is harmless.
/// If ce-auth is unreachable we fail closed (503).
async fn admin_challenge(State(st): State<AppState>) -> impl IntoResponse {
    let url = format!("{}/challenge?aud={}", st.ce_auth_url, auth::AUD);
    match st.http.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => match resp.bytes().await {
            Ok(body) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response(),
            Err(e) => {
                tracing::warn!(error = %e, "reading ce-auth /challenge body failed");
                ce_auth_down()
            }
        },
        Ok(resp) => {
            tracing::warn!(status = %resp.status(), "ce-auth /challenge returned non-2xx");
            ce_auth_down()
        }
        Err(e) => {
            tracing::warn!(error = %e, "ce-auth /challenge unreachable");
            ce_auth_down()
        }
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

/// Gate an admin request through ce-auth, running the (blocking) verify off the async executor.
/// Returns the authenticated admin device id, or the ready response: 401 on missing headers /
/// denied, 503 on ce-auth unreachable (fail-closed — an auth outage NEVER admits).
async fn require_admin_async(
    st: &AppState,
    headers: &HeaderMap,
) -> Result<String, axum::response::Response> {
    let verifier = st.verifier.clone();
    let headers = headers.clone();
    let res = tokio::task::spawn_blocking(move || auth::require_admin(verifier.as_ref(), &headers))
        .await
        .unwrap_or_else(|_| Err(VerifyError::Unreachable("verify task panicked".into())));
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
    use auth::{SignedHeaders, VerifyResponse};
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
        d.push(format!("ce-watch-test-{}-{}", std::process::id(), nanos));
        d
    }

    /// A mock [`Verifier`] standing in for ce-auth's `/verify`. Configured to admit, deny, or be
    /// unreachable, and records the headers it was asked to verify so tests can assert the forward.
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
        /// ce-auth could not be reached.
        Down,
    }
    impl MockVerifier {
        fn new(outcome: MockOutcome) -> Self {
            Self { outcome, seen: Mutex::new(None) }
        }
    }
    impl Verifier for MockVerifier {
        fn verify(&self, headers: &SignedHeaders) -> Result<VerifyResponse, VerifyError> {
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
    }

    fn state_with(dir: std::path::PathBuf, outcome: MockOutcome) -> AppState {
        AppState {
            store: Arc::new(Store::open(dir).expect("open store")),
            ce_auth_url: Arc::new("http://127.0.0.1:0".to_string()),
            verifier: Arc::new(MockVerifier::new(outcome)),
            http: reqwest::Client::new(),
        }
    }

    /// The five device-signed headers a real console sends; values are arbitrary because the mock
    /// verifier decides the verdict, not their content.
    fn signed_headers() -> Vec<(String, String)> {
        vec![
            ("x-ce-device-id".into(), "dev-abc".into()),
            ("x-ce-auth".into(), "sig-xyz".into()),
            ("x-ce-aud".into(), "ce-watch".into()),
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
            ce_auth_url: Arc::new("http://127.0.0.1:0".to_string()),
            verifier: mock.clone(),
            http: reqwest::Client::new(),
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
        assert_eq!(seen.aud, "ce-watch");
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
    async fn admin_challenge_proxies_ce_auth() {
        // Stand up a tiny stub ce-auth that serves GET /challenge?aud=ce-watch, point ce-watch at it,
        // and assert /admin/challenge returns the stub's body verbatim.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stub_addr = listener.local_addr().unwrap();
        let stub = Router::new().route(
            "/challenge",
            get(|Query(q): Query<std::collections::HashMap<String, String>>| async move {
                assert_eq!(q.get("aud").map(String::as_str), Some("ce-watch"));
                Json(json!({
                    "aud": "ce-watch",
                    "nonce": "abcd1234",
                    "ts": "2026-06-24T00:00:00.000Z"
                }))
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, stub).await.unwrap();
        });

        let dir = temp_dir();
        let mut st = state_with(dir.clone(), MockOutcome::Deny);
        st.ce_auth_url = Arc::new(format!("http://{}", stub_addr));
        let app = router(st);

        let req = Request::builder().uri("/admin/challenge").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp).await;
        assert_eq!(j["aud"], "ce-watch");
        assert_eq!(j["nonce"], "abcd1234");
        assert_eq!(j["ts"], "2026-06-24T00:00:00.000Z");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn admin_challenge_ce_auth_down_is_503() {
        // Point at a closed port → proxy fails → fail closed (503).
        let dir = temp_dir();
        let mut st = state_with(dir.clone(), MockOutcome::Deny);
        st.ce_auth_url = Arc::new("http://127.0.0.1:1".to_string());
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
