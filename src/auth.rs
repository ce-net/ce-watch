//! Device-auth for the admin console — ce-secrets challenge-response, no pasted bearer token.
//!
//! A device proves possession of its ECDSA private key per request:
//!
//!   1. `GET /admin/challenge` -> `{ aud: "ce-watch", nonce, ts }`. The nonce is the stateless
//!      `HMAC-SHA256(server_secret, ts)` from the ce-secrets auth primitive; nothing is stored.
//!   2. The console signs the flat canonical body `{ aud, deviceId, nonce, ts }` with its device
//!      ECDSA key (raw-P1363, base64url, no-pad) and sends `x-ce-device-id`, `x-ce-auth` (the sig),
//!      plus the challenge fields `x-ce-aud` / `x-ce-nonce` / `x-ce-ts`.
//!   3. We re-derive + TTL-check the nonce, then verify the signature against the device's ECDSA
//!      public key via `ce_secrets::verify_auth` ([`authenticate_with_pub`]).
//!
//! "Key-valid" (the signature verifies for the claimed deviceId) is distinct from "is-admin" (that
//! deviceId has `role=admin` in the persisted admin store, see `store::AdminStore`). The store, not
//! a static env registry, is the source of truth for membership: enrollment is self-service
//! (claim / request / approve / revoke). The env `CE_WATCH_ADMIN_DEVICES` is only a one-time
//! bootstrap seed. All five ce-secrets interop traps (HKDF empty salt, AES-GCM 12-byte nonce,
//! raw-P1363-not-DER, base64url-no-pad, top-level-sorted canonical JSON) are honored by the SDK.

use axum::http::HeaderMap;
use ce_secrets_rs::device::Jwk;
use ce_secrets_rs::encoding::{b64url_decode, b64url_encode};
use ce_secrets_rs::{check_nonce, make_nonce, now_unix_ms, verify_auth, AUTH_TTL_SECS};

/// The audience this console binds challenges to. A signature for a different `aud` will not verify.
pub const AUD: &str = "ce-watch";

/// Parse the `CE_WATCH_ADMIN_DEVICES` env value into `(deviceId, compactPub)` seed pairs for the
/// persisted admin store. Wire format: comma-separated `deviceId:ecdsaPubB64url`, where the pub is
/// base64url(no-pad) of the 65-byte uncompressed SEC1 point (`04 || x || y`). We validate the pub is
/// a well-formed SEC1 point and
/// keep the original compact string (so the store persists the exact bytes the console derives). A
/// malformed entry is skipped with a warning rather than failing boot.
pub fn parse_seed(env: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in env.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((id, pub_b64)) = entry.split_once(':') else {
            tracing::warn!(entry, "CE_WATCH_ADMIN_DEVICES entry missing ':' — skipped");
            continue;
        };
        let id = id.trim().to_string();
        let pub_b64 = pub_b64.trim().to_string();
        // Validate it reconstructs to a P-256 point; keep the original compact string regardless.
        match ecdsa_pub_from_compact(&pub_b64) {
            Ok(_) => out.push((id, pub_b64)),
            Err(e) => tracing::warn!(device_id = %id, error = %e, "bad seed admin pub — skipped"),
        }
    }
    out
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
    BadSignature,
}

/// The "key-valid" check used by the self-service store: prove possession of the ECDSA private key
/// matching `pub_b64` (the compact SEC1 form) over a fresh challenge. The caller resolves `pub_b64`
/// either from the persisted admin store (for known devices) or from the request body (TOFU, for a
/// first `claim`/`request`). Returns the authenticated device id.
///
/// "Key-valid" is distinct from "is-admin": this proves the device controls the key for the claimed
/// `deviceId`; the store decides whether that device has `role=admin`.
pub fn authenticate_with_pub<'a>(
    headers: &'a HeaderMap,
    pub_b64: &str,
    server_secret: &[u8],
) -> Result<&'a str, AuthError> {
    let (device_id, sig, aud, nonce, ts) = challenge_fields(headers)?;
    verify_challenge(server_secret, aud, nonce, ts)?;
    let jwk = ecdsa_pub_from_compact(pub_b64).map_err(|_| AuthError::BadSignature)?;
    match verify_auth(&jwk, aud, device_id, nonce, ts, sig) {
        Ok(true) => Ok(device_id),
        _ => Err(AuthError::BadSignature),
    }
}

/// Extract the five challenge headers, or `MissingHeaders`.
fn challenge_fields<'a>(
    headers: &'a HeaderMap,
) -> Result<(&'a str, &'a str, &'a str, &'a str, &'a str), AuthError> {
    let device_id = header(headers, "x-ce-device-id").ok_or(AuthError::MissingHeaders)?;
    let sig = header(headers, "x-ce-auth").ok_or(AuthError::MissingHeaders)?;
    let aud = header(headers, "x-ce-aud").ok_or(AuthError::MissingHeaders)?;
    let nonce = header(headers, "x-ce-nonce").ok_or(AuthError::MissingHeaders)?;
    let ts = header(headers, "x-ce-ts").ok_or(AuthError::MissingHeaders)?;
    Ok((device_id, sig, aud, nonce, ts))
}

/// Audience binding + nonce re-derivation + 300s TTL. Stateless: no server-side nonce store.
fn verify_challenge(
    server_secret: &[u8],
    aud: &str,
    nonce: &str,
    ts: &str,
) -> Result<(), AuthError> {
    if aud != AUD {
        return Err(AuthError::AudMismatch);
    }
    if !check_nonce(server_secret, ts, nonce, now_unix_ms(), AUTH_TTL_SECS) {
        return Err(AuthError::BadOrExpiredNonce);
    }
    Ok(())
}

/// The claimed device id from the `x-ce-device-id` header (unverified — only proves which key the
/// caller asks us to check against; the signature check is what actually authenticates).
pub fn header_device_id(headers: &HeaderMap) -> Option<&str> {
    header(headers, "x-ce-device-id")
}

/// Validate a compact ECDSA SEC1 pub string (used to vet request bodies before persisting).
pub fn validate_compact_pub(b64url: &str) -> anyhow::Result<()> {
    ecdsa_pub_from_compact(b64url).map(|_| ())
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
    fn parse_seed_yields_id_pub_pairs() {
        let dk = test_device();
        let env = format!("  {}:{} , , bad-entry-no-colon ", dk.id, compact_pub(&dk));
        let seed = parse_seed(&env);
        // The valid entry is kept; the empty + colon-less entries are skipped.
        assert_eq!(seed.len(), 1);
        assert_eq!(seed[0].0, dk.id);
        assert_eq!(seed[0].1, compact_pub(&dk));
    }

    #[test]
    fn valid_challenge_is_admitted_against_pub() {
        let dk = test_device();
        let secret = b"server-secret";
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
            authenticate_with_pub(&headers, &compact_pub(&dk), secret),
            Ok(dk.id.as_str())
        );
    }

    #[test]
    fn wrong_pub_is_rejected() {
        // A valid signature, but verified against a DIFFERENT device's pub -> BadSignature. (This is
        // the "key-valid" failure: you do not control the key for that pub.)
        let dk = test_device();
        let secret = b"server-secret";
        // A different, valid P-256 SEC1 point.
        let other_pub = "BF5pM_MXcWTd_QhLuLeN-0Uz_c6kqXjfxxD1hZflnL4nWHvWLOzDWyZmUhG8nnISc8dN5Gol-Cyfm1YaJpIvUWU";
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
            authenticate_with_pub(&headers, other_pub, secret),
            Err(AuthError::BadSignature)
        );
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let dk = test_device();
        let secret = b"server-secret";
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
            authenticate_with_pub(&headers, &compact_pub(&dk), secret),
            Err(AuthError::BadSignature)
        );
    }

    #[test]
    fn expired_challenge_is_rejected() {
        let dk = test_device();
        let secret = b"server-secret";

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
            authenticate_with_pub(&headers, &compact_pub(&dk), secret),
            Err(AuthError::BadOrExpiredNonce)
        );
    }

    #[test]
    fn tampered_nonce_is_rejected() {
        let dk = test_device();
        let secret = b"server-secret";

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
            authenticate_with_pub(&headers, &compact_pub(&dk), secret),
            Err(AuthError::BadOrExpiredNonce)
        );
    }

    #[test]
    fn missing_headers_rejected() {
        let dk = test_device();
        let headers = header_map(&[]);
        assert_eq!(
            authenticate_with_pub(&headers, &compact_pub(&dk), b"s"),
            Err(AuthError::MissingHeaders)
        );
    }
}
