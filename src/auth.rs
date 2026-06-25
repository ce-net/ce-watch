//! ce-monitor as a thin RELYING PARTY of ce-auth — over the CE MESH, not HTTP.
//!
//! ce-monitor no longer manages devices, holds no admin store, and runs no in-process crypto. It
//! delegates every admin decision to **ce-auth** (the operator's SSO surface), reached as a
//! mesh-native service: ce-auth advertises the pinned name `ce-auth` and answers verbs on the topic
//! `ce-auth/rpc` over libp2p ([`ce_rs::serve`]). ce-monitor [`ce_rs::locate`]s a live instance and
//! sends it requests via [`ce_rs::CeClient::request`]. There is NO HTTP hop to ce-auth and no shared
//! secret. The contract every relying party uses:
//!
//!   - verb `challenge` `{ aud }` -> `{ aud, nonce, ts }`. We surface this through our own
//!     `GET /admin/challenge` so the browser console never needs to know how to reach ce-auth.
//!   - verb `verify` `{ aud, deviceId, sig, nonce, ts }` -> `{ ok, role, deviceId, .. }`. We forward
//!     the device-signed values off an incoming admin request and admit iff `ok == true`.
//!
//! A device enrolled in ce-auth == the operator == trusted by ce-monitor. Device enrollment, claim,
//! request, approve and revoke all live in ce-auth now; this file holds only the relying-party glue.
//!
//! The [`Verifier`] trait abstracts the mesh round-trips to ce-auth so handlers (and tests) can
//! inject a mock instead of standing up a real ce-auth + node. [`MeshVerifier`] is the production
//! implementation; it is fail-closed — any locate/transport/decode failure maps to
//! [`VerifyError::Unreachable`] (-> 503), never to an admit.

use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// The audience ce-monitor binds challenges to. ce-auth derives + TTL-checks the stateless nonce
/// against this exact string, so a signature minted for a different `aud` will not verify.
pub const AUD: &str = "ce-monitor";

/// The pinned mesh service name ce-auth advertises and relying parties `locate`. Mirrors
/// `ce_auth::service::SERVICE_NAME`.
pub const CE_AUTH_SERVICE: &str = "ce-auth";

/// The mesh request/reply topic for ce-auth verbs. Mirrors `ce_auth::service::TOPIC`.
pub const CE_AUTH_TOPIC: &str = "ce-auth/rpc";

/// Per-request mesh timeout for a ce-auth round-trip (locate + request). Generous enough for a DHT
/// lookup + one mesh hop, short enough that an auth outage fails closed promptly.
pub const MESH_TIMEOUT_MS: u64 = 5_000;

/// The five device-signed headers a console request carries, lifted off an incoming request. These
/// are exactly the fields ce-auth's `verify` verb needs to re-derive the nonce and check the
/// signature against the device's enrolled ECDSA pub.
#[derive(Debug, Clone)]
pub struct SignedHeaders {
    pub device_id: String,
    pub sig: String,
    /// The `x-ce-aud` the request claimed. Captured for logging/assertions; ce-monitor always sends
    /// its own pinned [`AUD`] to ce-auth's `verify`, so a token minted for a different app can never
    /// be replayed here even if the header claims otherwise.
    #[cfg_attr(not(test), allow(dead_code))]
    pub aud: String,
    pub nonce: String,
    pub ts: String,
}

impl SignedHeaders {
    /// Extract the `x-ce-device-id` / `x-ce-auth` / `x-ce-aud` / `x-ce-nonce` / `x-ce-ts` headers.
    /// Returns `None` if any are missing — the caller maps that to an unauthorized response.
    pub fn from_headers(headers: &HeaderMap) -> Option<Self> {
        let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_string);
        Some(SignedHeaders {
            device_id: get("x-ce-device-id")?,
            sig: get("x-ce-auth")?,
            aud: get("x-ce-aud")?,
            nonce: get("x-ce-nonce")?,
            ts: get("x-ce-ts")?,
        })
    }
}

/// The body ce-monitor sends to ce-auth's `verify` verb. `aud` is always pinned to ce-monitor's own
/// audience regardless of what the request claimed, so a device cannot get admitted here with a
/// token minted for a different app.
#[derive(Debug, Serialize)]
pub struct VerifyRequest<'a> {
    pub verb: &'a str,
    pub aud: &'a str,
    #[serde(rename = "deviceId")]
    pub device_id: &'a str,
    pub sig: &'a str,
    pub nonce: &'a str,
    pub ts: &'a str,
}

/// ce-auth's `verify` reply. We admit iff `ok == true`; `role`/`deviceId` are surfaced for logs.
/// ce-auth also returns `nodeId`/`cap`/`capRoot` on success, which ce-monitor ignores (it only needs
/// the boolean admit decision; the bridged cap is for apps that verify caps offline).
#[derive(Debug, Clone, Deserialize)]
pub struct VerifyResponse {
    pub ok: bool,
    #[serde(default)]
    pub role: String,
    #[serde(default, rename = "deviceId")]
    pub device_id: String,
}

/// A fresh challenge `{ aud, nonce, ts }` minted by ce-auth's `challenge` verb. ce-monitor relays this
/// verbatim to the browser console, which signs it with its device key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub aud: String,
    pub nonce: String,
    pub ts: String,
}

/// Why a verify attempt did not admit. `Unreachable` is fail-closed -> 503; everything else -> 401.
#[derive(Debug)]
pub enum VerifyError {
    /// Required device-signed headers were absent from the request.
    MissingHeaders,
    /// ce-auth answered, but `ok == false` (bad signature, expired nonce, or not an admin).
    Denied(VerifyResponse),
    /// ce-auth could not be reached over the mesh (no live instance, transport error, or an
    /// undecodable reply). Fail closed.
    Unreachable(String),
}

/// Abstracts the mesh round-trips to ce-auth, so handlers can be tested against a mock verifier
/// without a live ce-auth + node. Implementors run the `challenge` and `verify` verbs.
///
/// Async because the production path is a mesh request (locate + request) over `ce-rs`.
pub trait Verifier: Send + Sync {
    /// Run ce-auth's `verify` verb for the request's device-signed values. The `aud` sent is always
    /// [`AUD`]; the device id / sig / nonce / ts come from the headers.
    fn verify(
        &self,
        headers: &SignedHeaders,
    ) -> impl std::future::Future<Output = Result<VerifyResponse, VerifyError>> + Send;

    /// Run ce-auth's `challenge` verb for [`AUD`], returning a fresh `{ aud, nonce, ts }` to relay to
    /// the console. A locate/transport/decode failure is fail-closed [`VerifyError::Unreachable`].
    fn challenge(
        &self,
    ) -> impl std::future::Future<Output = Result<Challenge, VerifyError>> + Send;
}

/// Production [`Verifier`]: locates a live `ce-auth` instance over the mesh and sends it verb
/// requests on [`CE_AUTH_TOPIC`] via [`ce_rs::CeClient::request`]. Any failure to locate, send, or
/// decode is [`VerifyError::Unreachable`] (fail-closed) so a ce-auth outage can never silently admit.
///
/// It reuses the SAME [`ce_rs::CeClient`] the flag receiver attaches to (the co-located ce node), so
/// there is exactly one node attachment for the whole console.
pub struct MeshVerifier {
    ce: ce_rs::CeClient,
}

impl MeshVerifier {
    /// Build a `MeshVerifier` driving the given (already-attached) ce node client.
    pub fn new(ce: ce_rs::CeClient) -> Self {
        Self { ce }
    }

    /// Locate a live ce-auth instance and send it one verb envelope, returning the decoded JSON
    /// reply. All failure modes collapse to [`VerifyError::Unreachable`] (fail-closed).
    async fn call(&self, payload: &[u8]) -> Result<Value, VerifyError> {
        let reply = ce_rs::locate::call(
            &self.ce,
            CE_AUTH_SERVICE,
            CE_AUTH_TOPIC,
            payload,
            &ce_rs::locate::LocateOpts::default(),
            MESH_TIMEOUT_MS,
        )
        .await
        .map_err(|e| VerifyError::Unreachable(format!("ce-auth mesh request: {e}")))?;
        serde_json::from_slice(&reply)
            .map_err(|e| VerifyError::Unreachable(format!("decode ce-auth reply: {e}")))
    }
}

impl Verifier for MeshVerifier {
    async fn verify(&self, headers: &SignedHeaders) -> Result<VerifyResponse, VerifyError> {
        let body = VerifyRequest {
            verb: "verify",
            aud: AUD,
            device_id: &headers.device_id,
            sig: &headers.sig,
            nonce: &headers.nonce,
            ts: &headers.ts,
        };
        let payload = serde_json::to_vec(&body)
            .map_err(|e| VerifyError::Unreachable(format!("encode verify request: {e}")))?;
        let v = self.call(&payload).await?;
        // ce-auth never returns a transport error in-band; a `{ "error": .. }` reply (e.g. a bad
        // envelope) is treated as a denial, not an admit.
        let resp = VerifyResponse {
            ok: v.get("ok").and_then(Value::as_bool).unwrap_or(false),
            role: v.get("role").and_then(Value::as_str).unwrap_or_default().to_string(),
            device_id: v
                .get("deviceId")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        };
        if resp.ok {
            Ok(resp)
        } else {
            Err(VerifyError::Denied(resp))
        }
    }

    async fn challenge(&self) -> Result<Challenge, VerifyError> {
        let payload = serde_json::to_vec(&json!({ "verb": "challenge", "aud": AUD }))
            .map_err(|e| VerifyError::Unreachable(format!("encode challenge request: {e}")))?;
        let v = self.call(&payload).await?;
        let ch = Challenge {
            aud: v.get("aud").and_then(Value::as_str).unwrap_or(AUD).to_string(),
            nonce: v.get("nonce").and_then(Value::as_str).unwrap_or_default().to_string(),
            ts: v.get("ts").and_then(Value::as_str).unwrap_or_default().to_string(),
        };
        // A challenge with no nonce is a malformed reply (ce-auth could not mint one); fail closed
        // rather than hand the console a useless challenge it cannot sign.
        if ch.nonce.is_empty() || ch.ts.is_empty() {
            return Err(VerifyError::Unreachable("ce-auth challenge missing nonce/ts".into()));
        }
        Ok(ch)
    }
}

/// Run the full relying-party check for an incoming admin request: lift the device-signed headers,
/// then ask the [`Verifier`] over the mesh. Returns the authenticated admin device id on `{ok:true}`.
pub async fn require_admin(
    verifier: &dyn DynVerifier,
    headers: &HeaderMap,
) -> Result<String, VerifyError> {
    let signed = SignedHeaders::from_headers(headers).ok_or(VerifyError::MissingHeaders)?;
    let v = verifier.verify_dyn(&signed).await?;
    Ok(v.device_id)
}

/// Object-safe shim over [`Verifier`] so `AppState` can hold an `Arc<dyn DynVerifier>` (a trait with
/// native `async fn` is not object-safe). Auto-implemented for every [`Verifier`].
pub trait DynVerifier: Send + Sync {
    fn verify_dyn<'a>(
        &'a self,
        headers: &'a SignedHeaders,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<VerifyResponse, VerifyError>> + Send + 'a>>;

    fn challenge_dyn<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Challenge, VerifyError>> + Send + 'a>>;
}

impl<T: Verifier> DynVerifier for T {
    fn verify_dyn<'a>(
        &'a self,
        headers: &'a SignedHeaders,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<VerifyResponse, VerifyError>> + Send + 'a>>
    {
        Box::pin(self.verify(headers))
    }

    fn challenge_dyn<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Challenge, VerifyError>> + Send + 'a>>
    {
        Box::pin(self.challenge())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderName, HeaderValue};

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn signed_headers_round_trip() {
        let h = headers(&[
            ("x-ce-device-id", "dev1"),
            ("x-ce-auth", "sigA"),
            ("x-ce-aud", "ce-monitor"),
            ("x-ce-nonce", "nnn"),
            ("x-ce-ts", "2026-06-24T00:00:00.000Z"),
        ]);
        let s = SignedHeaders::from_headers(&h).expect("all present");
        assert_eq!(s.device_id, "dev1");
        assert_eq!(s.sig, "sigA");
        assert_eq!(s.aud, "ce-monitor");
        assert_eq!(s.nonce, "nnn");
    }

    #[test]
    fn signed_headers_missing_one_is_none() {
        let h = headers(&[
            ("x-ce-device-id", "dev1"),
            ("x-ce-auth", "sigA"),
            ("x-ce-aud", "ce-monitor"),
            ("x-ce-nonce", "nnn"),
            // x-ce-ts missing
        ]);
        assert!(SignedHeaders::from_headers(&h).is_none());
    }

    #[test]
    fn verify_request_serializes_with_verb_and_pinned_aud() {
        // The wire envelope must carry verb=verify and ce-monitor's own AUD, never the request's claim.
        let body = VerifyRequest {
            verb: "verify",
            aud: AUD,
            device_id: "dev1",
            sig: "sigA",
            nonce: "nnn",
            ts: "2026-06-24T00:00:00.000Z",
        };
        let v: Value = serde_json::to_value(&body).unwrap();
        assert_eq!(v["verb"], "verify");
        assert_eq!(v["aud"], "ce-monitor");
        assert_eq!(v["deviceId"], "dev1");
        assert_eq!(v["sig"], "sigA");
        assert_eq!(v["nonce"], "nnn");
        assert_eq!(v["ts"], "2026-06-24T00:00:00.000Z");
    }
}
