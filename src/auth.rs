//! ce-watch as a thin RELYING PARTY of ce-auth.
//!
//! ce-watch no longer manages devices, holds no admin store, and runs no in-process crypto. It
//! delegates every admin decision to **ce-auth** (the operator's SSO surface), reached over HTTP at
//! `CE_AUTH_URL` (default `http://127.0.0.1:8972`). The contract every app relies on:
//!
//!   - `GET  {ce-auth}/challenge?aud=ce-watch` -> `{ aud, nonce, ts }`. We proxy this verbatim from
//!     our own `GET /admin/challenge` so the console never needs to know ce-auth's address.
//!   - `POST {ce-auth}/verify { aud, deviceId, sig, nonce, ts }` -> `{ ok, role, deviceId }`. We
//!     forward the device-signed headers off an incoming admin request and admit iff `ok == true`.
//!
//! A device enrolled in ce-auth == the operator == trusted by ce-watch. Device enrollment, claim,
//! request, approve and revoke all live in ce-auth now; this file holds only the relying-party glue.
//!
//! The [`Verifier`] trait abstracts the call to ce-auth so handlers (and tests) can inject a mock
//! verifier instead of standing up a real ce-auth. [`HttpVerifier`] is the production implementation.

use std::time::Duration;

use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};

/// The audience ce-watch binds challenges to. ce-auth derives + TTL-checks the stateless nonce
/// against this exact string, so a signature minted for a different `aud` will not verify.
pub const AUD: &str = "ce-watch";

/// Default ce-auth base URL when `CE_AUTH_URL` is unset — the deployed local ce-auth sidecar.
pub const DEFAULT_CE_AUTH_URL: &str = "http://127.0.0.1:8972";

/// Resolve the ce-auth base URL from `CE_AUTH_URL`, falling back to [`DEFAULT_CE_AUTH_URL`].
/// Any trailing slash is trimmed so we can join paths with a single `/`.
pub fn ce_auth_url() -> String {
    let raw = std::env::var("CE_AUTH_URL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_CE_AUTH_URL.to_string());
    raw.trim_end_matches('/').to_string()
}

/// The five device-signed headers a console request carries, lifted off an incoming request. These
/// are exactly the fields ce-auth's `/verify` needs to re-derive the nonce and check the signature
/// against the device's enrolled ECDSA pub.
#[derive(Debug, Clone)]
pub struct SignedHeaders {
    pub device_id: String,
    pub sig: String,
    /// The `x-ce-aud` the request claimed. Captured for logging/assertions; ce-watch always sends
    /// its own pinned [`AUD`] to ce-auth's `/verify`, so a token minted for a different app can never
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

/// The body ce-watch POSTs to `{ce-auth}/verify`. `aud` is always pinned to ce-watch's own audience
/// regardless of what the request claimed, so a device cannot get admitted here with a token minted
/// for a different app.
#[derive(Debug, Serialize)]
pub struct VerifyRequest<'a> {
    pub aud: &'a str,
    #[serde(rename = "deviceId")]
    pub device_id: &'a str,
    pub sig: &'a str,
    pub nonce: &'a str,
    pub ts: &'a str,
}

/// ce-auth's `/verify` response. We admit iff `ok == true`; `role`/`deviceId` are surfaced for logs.
#[derive(Debug, Clone, Deserialize)]
pub struct VerifyResponse {
    pub ok: bool,
    #[serde(default)]
    pub role: String,
    #[serde(default, rename = "deviceId")]
    pub device_id: String,
}

/// Why a verify attempt did not admit. `Unreachable` is fail-closed -> 503; everything else -> 401.
#[derive(Debug)]
pub enum VerifyError {
    /// Required device-signed headers were absent from the request.
    MissingHeaders,
    /// ce-auth answered, but `ok == false` (bad signature, expired nonce, or not an admin).
    Denied(VerifyResponse),
    /// ce-auth could not be reached (or returned a transport/5xx error). Fail closed.
    Unreachable(String),
}

/// Abstracts the call to ce-auth's `/verify`, so handlers can be tested against a mock verifier
/// without a live ce-auth. Implementors take the device-signed headers and return ce-auth's verdict.
pub trait Verifier: Send + Sync {
    /// Verify the request's device-signed headers against ce-auth. The `aud` sent to ce-auth is
    /// always [`AUD`]; the device id / sig / nonce / ts come from the headers.
    fn verify(&self, headers: &SignedHeaders) -> Result<VerifyResponse, VerifyError>;
}

/// Production [`Verifier`]: POSTs to `{ce-auth}/verify` with a short timeout and admits on
/// `{ok:true}`. A transport error, timeout, or non-2xx status is treated as [`VerifyError::Unreachable`]
/// (fail-closed) so a ce-auth outage can never silently admit a request.
pub struct HttpVerifier {
    base_url: String,
    client: reqwest::blocking::Client,
}

impl HttpVerifier {
    /// Build an `HttpVerifier` against `base_url` (already slash-trimmed) with a 5s request timeout.
    pub fn new(base_url: String) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());
        Self { base_url, client }
    }
}

impl Verifier for HttpVerifier {
    fn verify(&self, headers: &SignedHeaders) -> Result<VerifyResponse, VerifyError> {
        let body = VerifyRequest {
            aud: AUD,
            device_id: &headers.device_id,
            sig: &headers.sig,
            nonce: &headers.nonce,
            ts: &headers.ts,
        };
        let url = format!("{}/verify", self.base_url);
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .map_err(|e| VerifyError::Unreachable(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(VerifyError::Unreachable(format!(
                "ce-auth /verify status {}",
                resp.status()
            )));
        }
        let v: VerifyResponse = resp
            .json()
            .map_err(|e| VerifyError::Unreachable(format!("decode ce-auth /verify: {e}")))?;
        if v.ok {
            Ok(v)
        } else {
            Err(VerifyError::Denied(v))
        }
    }
}

/// Run the full relying-party check for an incoming admin request: lift the device-signed headers,
/// then ask the [`Verifier`]. Returns the authenticated admin device id on `{ok:true}`.
pub fn require_admin(
    verifier: &dyn Verifier,
    headers: &HeaderMap,
) -> Result<String, VerifyError> {
    let signed = SignedHeaders::from_headers(headers).ok_or(VerifyError::MissingHeaders)?;
    let v = verifier.verify(&signed)?;
    Ok(v.device_id)
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
    fn ce_auth_url_defaults_and_trims() {
        // Default when unset.
        unsafe { std::env::remove_var("CE_AUTH_URL") };
        assert_eq!(ce_auth_url(), DEFAULT_CE_AUTH_URL);
        // Trailing slash trimmed.
        unsafe { std::env::set_var("CE_AUTH_URL", "http://example:9000/") };
        assert_eq!(ce_auth_url(), "http://example:9000");
        unsafe { std::env::remove_var("CE_AUTH_URL") };
    }

    #[test]
    fn signed_headers_round_trip() {
        let h = headers(&[
            ("x-ce-device-id", "dev1"),
            ("x-ce-auth", "sigA"),
            ("x-ce-aud", "ce-watch"),
            ("x-ce-nonce", "nnn"),
            ("x-ce-ts", "2026-06-24T00:00:00.000Z"),
        ]);
        let s = SignedHeaders::from_headers(&h).expect("all present");
        assert_eq!(s.device_id, "dev1");
        assert_eq!(s.sig, "sigA");
        assert_eq!(s.aud, "ce-watch");
        assert_eq!(s.nonce, "nnn");
    }

    #[test]
    fn signed_headers_missing_one_is_none() {
        let h = headers(&[
            ("x-ce-device-id", "dev1"),
            ("x-ce-auth", "sigA"),
            ("x-ce-aud", "ce-watch"),
            ("x-ce-nonce", "nnn"),
            // x-ce-ts missing
        ]);
        assert!(SignedHeaders::from_headers(&h).is_none());
    }
}
