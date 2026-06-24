//! Device-auth for the admin console — ce-secrets challenge-response, no pasted bearer token.
//!
//! The operator enrolls their device's ECDSA public key ONCE at deploy (via the
//! `CE_WATCH_ADMIN_DEVICES` env), not on every visit. Thereafter the console proves possession of
//! the matching private key per request:
//!
//!   1. `GET /admin/challenge` -> `{ aud: "ce-watch", nonce, ts }`. The nonce is the stateless
//!      `HMAC-SHA256(server_secret, ts)` from the ce-secrets auth primitive; nothing is stored.
//!   2. The console signs the flat canonical body `{ aud, deviceId, nonce, ts }` with its device
//!      ECDSA key (raw-P1363, base64url, no-pad) and sends `x-ce-device-id`, `x-ce-auth` (the sig),
//!      plus the challenge fields `x-ce-aud` / `x-ce-nonce` / `x-ce-ts`.
//!   3. We re-derive + TTL-check the nonce, confirm the device id is enrolled, and verify the
//!      signature against that device's enrolled ECDSA public key via `ce_secrets::verify_auth`.
//!
//! This is the whole login: "enrolled here" == "is the operator." All five ce-secrets interop traps
//! (HKDF empty salt, AES-GCM 12-byte nonce, raw-P1363-not-DER, base64url-no-pad, top-level-sorted
//! canonical JSON) are honored by the SDK we call.

use std::collections::HashMap;

use axum::http::HeaderMap;
use ce_secrets_rs::device::Jwk;
use ce_secrets_rs::encoding::{b64url_decode, b64url_encode};
use ce_secrets_rs::{check_nonce, make_nonce, now_unix_ms, verify_auth, AUTH_TTL_SECS};

/// The audience this console binds challenges to. A signature for a different `aud` will not verify.
pub const AUD: &str = "ce-watch";

/// The registry of enrolled operator devices: `deviceId -> enrolled ECDSA public JWK`.
///
/// Built once at boot from `CE_WATCH_ADMIN_DEVICES`. An empty registry means no device can
/// authenticate (admin endpoints reject everything), which is the safe default for a security
/// console with no operator enrolled yet.
#[derive(Clone, Default)]
pub struct Devices {
    by_id: HashMap<String, Jwk>,
}

impl Devices {
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Look up the enrolled ECDSA public key for a device id.
    pub fn get(&self, device_id: &str) -> Option<&Jwk> {
        self.by_id.get(device_id)
    }

    /// Enroll one device from its id and compact public form. Used by the parser and by tests.
    pub fn insert_compact(&mut self, device_id: &str, ecdsa_pub_b64url: &str) -> anyhow::Result<()> {
        let jwk = ecdsa_pub_from_compact(ecdsa_pub_b64url)?;
        self.by_id.insert(device_id.to_string(), jwk);
        Ok(())
    }

    /// Parse the `CE_WATCH_ADMIN_DEVICES` env value: comma-separated `deviceId:ecdsaPubB64url`
    /// entries, where `ecdsaPubB64url` is base64url(no-pad) of the 65-byte uncompressed SEC1 point
    /// (`04 || x || y`). Whitespace and empty entries are ignored. A malformed entry is skipped with
    /// a warning rather than failing boot, so one bad paste cannot lock out a valid co-enrolled
    /// device.
    pub fn parse(env: &str) -> Self {
        let mut devices = Devices::default();
        for entry in env.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            // deviceId is 16 hex chars; the pub may itself contain no ':', so split once on the
            // FIRST colon.
            let Some((id, pub_b64)) = entry.split_once(':') else {
                tracing::warn!(entry, "CE_WATCH_ADMIN_DEVICES entry missing ':' — skipped");
                continue;
            };
            let id = id.trim();
            let pub_b64 = pub_b64.trim();
            match devices.insert_compact(id, pub_b64) {
                Ok(()) => tracing::info!(device_id = id, "enrolled admin device"),
                Err(e) => tracing::warn!(device_id = id, error = %e, "bad admin device pub — skipped"),
            }
        }
        devices
    }
}

/// Reconstruct an ECDSA P-256 public JWK from the compact wire form: base64url(no-pad) of the
/// 65-byte uncompressed SEC1 point `04 || x(32) || y(32)`. This is the exact bytes the console
/// derives from its WebCrypto key, so the operator pastes one short string at deploy.
pub fn ecdsa_pub_from_compact(b64url: &str) -> anyhow::Result<Jwk> {
    let raw = b64url_decode(b64url)?;
    if raw.len() != 65 || raw[0] != 0x04 {
        anyhow::bail!(
            "expected 65-byte uncompressed SEC1 point (04||x||y), got {} bytes",
            raw.len()
        );
    }
    let x = b64url_encode(&raw[1..33]);
    let y = b64url_encode(&raw[33..65]);
    Ok(Jwk {
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        x,
        y,
        d: None,
        ext: None,
        key_ops: Vec::new(),
    })
}

/// A freshly minted challenge handed to the console. `aud` is fixed; `ts` is the current ISO-8601
/// instant; `nonce` is the stateless HMAC over `ts`.
pub struct Challenge {
    pub aud: &'static str,
    pub nonce: String,
    pub ts: String,
}

/// Mint a challenge: `ts = now (ISO-8601, ms)`, `nonce = HMAC-SHA256(server_secret, ts)` hex.
pub fn make_challenge(server_secret: &[u8]) -> Challenge {
    let ts = iso8601_now_ms();
    let nonce = make_nonce(server_secret, &ts);
    Challenge { aud: AUD, nonce, ts }
}

/// Why an auth attempt was rejected — surfaced for logs/tests, never leaked to the client beyond a
/// flat 401.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    MissingHeaders,
    AudMismatch,
    BadOrExpiredNonce,
    NotEnrolled,
    BadSignature,
}

/// Full relying-party check, mirroring `verifyAuthFull` in `auth.mjs`:
/// audience binding, nonce re-derivation + TTL, enrollment lookup, then the pure signature verify.
/// Returns the authenticated device id on success.
pub fn authenticate<'a>(
    headers: &'a HeaderMap,
    devices: &Devices,
    server_secret: &[u8],
) -> Result<&'a str, AuthError> {
    let device_id = header(headers, "x-ce-device-id").ok_or(AuthError::MissingHeaders)?;
    let sig = header(headers, "x-ce-auth").ok_or(AuthError::MissingHeaders)?;
    let aud = header(headers, "x-ce-aud").ok_or(AuthError::MissingHeaders)?;
    let nonce = header(headers, "x-ce-nonce").ok_or(AuthError::MissingHeaders)?;
    let ts = header(headers, "x-ce-ts").ok_or(AuthError::MissingHeaders)?;

    if aud != AUD {
        return Err(AuthError::AudMismatch);
    }
    // Re-derive the nonce from our own secret + the supplied ts, and enforce the 300s TTL. A
    // tampered or replayed-after-expiry challenge fails here without any server-side nonce store.
    if !check_nonce(server_secret, ts, nonce, now_unix_ms(), AUTH_TTL_SECS) {
        return Err(AuthError::BadOrExpiredNonce);
    }
    let enrolled = devices.get(device_id).ok_or(AuthError::NotEnrolled)?;
    match verify_auth(enrolled, aud, device_id, nonce, ts, sig) {
        Ok(true) => Ok(device_id),
        _ => Err(AuthError::BadSignature),
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Current time as a strict `YYYY-MM-DDTHH:MM:SS.mmmZ` UTC string — the exact shape JS
/// `Date.toISOString()` emits and the shape `parse_iso_ms` in the SDK expects.
fn iso8601_now_ms() -> String {
    let ms = now_unix_ms().max(0);
    let secs = ms / 1000;
    let millis = ms % 1000;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (h, mi, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
}

/// Inverse of Howard Hinnant's `days_from_civil` — unix days back to a (year, month, day) civil
/// date, matching the SDK's `parse_iso_ms` round-trip exactly.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ce_secrets_rs::{parse_iso_ms, sign_challenge, DeviceKey};

    fn header_map(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                axum::http::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    // A real device key (P-256 ECDH + ECDSA) the test both signs and enrolls with.
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

    /// The compact deploy string for a device: `b64url(04 || ecdsaPub.x || ecdsaPub.y)`.
    fn compact_pub(dk: &DeviceKey) -> String {
        b64url_encode(&dk.ecdsa_pub.raw_public_bytes().unwrap())
    }

    #[test]
    fn iso_now_roundtrips_through_parse() {
        // The challenge ts must parse back to a value within a second of now via the SDK parser.
        let ts = iso8601_now_ms();
        let parsed = parse_iso_ms(&ts).expect("SDK must parse our ISO string");
        assert!((now_unix_ms() - parsed).abs() < 2000, "ts={ts} parsed={parsed}");
    }

    #[test]
    fn compact_pub_reconstructs_enrolled_jwk() {
        let dk = test_device();
        let jwk = ecdsa_pub_from_compact(&compact_pub(&dk)).unwrap();
        // Same point the device advertised.
        assert_eq!(jwk.x, dk.ecdsa_pub.x);
        assert_eq!(jwk.y, dk.ecdsa_pub.y);
    }

    #[test]
    fn parse_env_enrolls_devices() {
        let dk = test_device();
        let env = format!("{}:{}", dk.id, compact_pub(&dk));
        let devices = Devices::parse(&env);
        assert_eq!(devices.len(), 1);
        assert!(devices.get(&dk.id).is_some());
    }

    #[test]
    fn enrolled_device_with_valid_challenge_is_admitted() {
        let dk = test_device();
        let secret = b"server-secret";
        let mut devices = Devices::default();
        devices.insert_compact(&dk.id, &compact_pub(&dk)).unwrap();

        let ch = make_challenge(secret);
        let sig = sign_challenge(&dk, ch.aud, &ch.nonce, &ch.ts).unwrap();
        let headers = header_map(&[
            ("x-ce-device-id", &dk.id),
            ("x-ce-auth", &sig),
            ("x-ce-aud", ch.aud),
            ("x-ce-nonce", &ch.nonce),
            ("x-ce-ts", &ch.ts),
        ]);
        assert_eq!(authenticate(&headers, &devices, secret), Ok(dk.id.as_str()));
    }

    #[test]
    fn unenrolled_device_is_rejected() {
        let dk = test_device();
        let secret = b"server-secret";
        // Empty registry — this device is not enrolled.
        let devices = Devices::default();
        let ch = make_challenge(secret);
        let sig = sign_challenge(&dk, ch.aud, &ch.nonce, &ch.ts).unwrap();
        let headers = header_map(&[
            ("x-ce-device-id", &dk.id),
            ("x-ce-auth", &sig),
            ("x-ce-aud", ch.aud),
            ("x-ce-nonce", &ch.nonce),
            ("x-ce-ts", &ch.ts),
        ]);
        assert_eq!(
            authenticate(&headers, &devices, secret),
            Err(AuthError::NotEnrolled)
        );
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let dk = test_device();
        let secret = b"server-secret";
        let mut devices = Devices::default();
        devices.insert_compact(&dk.id, &compact_pub(&dk)).unwrap();

        let ch = make_challenge(secret);
        let mut sig = sign_challenge(&dk, ch.aud, &ch.nonce, &ch.ts).unwrap();
        // Flip a character in the base64url signature.
        let last = sig.pop().unwrap();
        sig.push(if last == 'A' { 'B' } else { 'A' });
        let headers = header_map(&[
            ("x-ce-device-id", &dk.id),
            ("x-ce-auth", &sig),
            ("x-ce-aud", ch.aud),
            ("x-ce-nonce", &ch.nonce),
            ("x-ce-ts", &ch.ts),
        ]);
        assert_eq!(
            authenticate(&headers, &devices, secret),
            Err(AuthError::BadSignature)
        );
    }

    #[test]
    fn expired_challenge_is_rejected() {
        let dk = test_device();
        let secret = b"server-secret";
        let mut devices = Devices::default();
        devices.insert_compact(&dk.id, &compact_pub(&dk)).unwrap();

        // A ts 10 minutes in the past — past the 300s TTL. The nonce is correctly derived for that
        // ts (so the only thing failing is freshness), and the signature is valid over it.
        let old_ms = now_unix_ms() - 600_000;
        let old_secs = old_ms / 1000;
        let old_ts = {
            let days = old_secs.div_euclid(86_400);
            let tod = old_secs.rem_euclid(86_400);
            let (y, mo, d) = civil_from_days(days);
            format!(
                "{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}.000Z",
                tod / 3600,
                (tod % 3600) / 60,
                tod % 60
            )
        };
        let nonce = make_nonce(secret, &old_ts);
        let sig = sign_challenge(&dk, AUD, &nonce, &old_ts).unwrap();
        let headers = header_map(&[
            ("x-ce-device-id", &dk.id),
            ("x-ce-auth", &sig),
            ("x-ce-aud", AUD),
            ("x-ce-nonce", &nonce),
            ("x-ce-ts", &old_ts),
        ]);
        assert_eq!(
            authenticate(&headers, &devices, secret),
            Err(AuthError::BadOrExpiredNonce)
        );
    }

    #[test]
    fn tampered_nonce_is_rejected() {
        let dk = test_device();
        let secret = b"server-secret";
        let mut devices = Devices::default();
        devices.insert_compact(&dk.id, &compact_pub(&dk)).unwrap();

        let ch = make_challenge(secret);
        // Forge a nonce the server did not issue (not HMAC(secret, ts)).
        let forged_nonce = "deadbeef".repeat(8);
        let sig = sign_challenge(&dk, ch.aud, &forged_nonce, &ch.ts).unwrap();
        let headers = header_map(&[
            ("x-ce-device-id", &dk.id),
            ("x-ce-auth", &sig),
            ("x-ce-aud", ch.aud),
            ("x-ce-nonce", &forged_nonce),
            ("x-ce-ts", &ch.ts),
        ]);
        assert_eq!(
            authenticate(&headers, &devices, secret),
            Err(AuthError::BadOrExpiredNonce)
        );
    }

    #[test]
    fn missing_headers_rejected() {
        let devices = Devices::default();
        let headers = header_map(&[]);
        assert_eq!(
            authenticate(&headers, &devices, b"s"),
            Err(AuthError::MissingHeaders)
        );
    }
}
