// Copyright (c) 2026 anti-rainer
// SPDX-License-Identifier: MIT

//! The AirSIM client's request authentication.
//!
//! The client signs every control request with a shared 32-byte secret:
//!
//! ```text
//! canonical = METHOD\npath\nsha256hex(body)\ntimestamp\nnonce
//! signature = base64url(HMAC-SHA256(secret, canonical))
//! ```
//!
//! and sends the three parts back as `x-airsim-vowlan-signature`,
//! `x-airsim-vowlan-timestamp` and `x-airsim-vowlan-nonce`.
//!
//! Two details matter more than the formula. The timestamp window is what stops
//! a captured request from being replayed forever, and the nonce is what stops
//! one from being replayed inside that window - so a nonce is remembered until
//! its timestamp would be rejected anyway, and not a moment longer.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// How far a request's timestamp may be from our clock.
///
/// The client re-signs once on a 401 because the first probe after a network
/// wake can land outside this window, so a generous window costs one replay
/// guard and saves a failed pairing.
pub const CLOCK_WINDOW: Duration = Duration::from_secs(30);

/// The three headers the client sends.
pub const HEADER_SIGNATURE: &str = "x-airsim-vowlan-signature";
pub const HEADER_TIMESTAMP: &str = "x-airsim-vowlan-timestamp";
pub const HEADER_NONCE: &str = "x-airsim-vowlan-nonce";

pub enum AuthError {
    MissingHeader(&'static str),
    BadTimestamp,
    OutsideWindow,
    Replayed,
    SignatureMismatch,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingHeader(name) => write!(formatter, "缺少请求头 {name}"),
            Self::BadTimestamp => formatter.write_str("时间戳格式错误"),
            Self::OutsideWindow => formatter.write_str("时间戳超出允许窗口"),
            Self::Replayed => formatter.write_str("nonce 已被使用"),
            Self::SignatureMismatch => formatter.write_str("签名不匹配"),
        }
    }
}

/// Verifies requests and remembers the nonces it has accepted.
///
/// One verifier per agent: the nonce memo is scoped to the key that accepted it,
/// and two agents never share a secret.
pub struct Verifier {
    key: Vec<u8>,
    /// Accepted nonces, each with the instant it stops being interesting.
    seen: Mutex<HashMap<String, SystemTime>>,
}

impl Verifier {
    pub fn new(key: Vec<u8>) -> Self {
        Self {
            key,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Verify one request.
    ///
    /// `body` is the raw request body: the digest covers what was sent, not what
    /// it parsed to, so a client cannot sign one payload and send another.
    pub fn verify(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        headers: &HashMap<String, String>,
        now: SystemTime,
    ) -> Result<(), AuthError> {
        let signature = header(headers, HEADER_SIGNATURE)?;
        let timestamp = header(headers, HEADER_TIMESTAMP)?;
        let nonce = header(headers, HEADER_NONCE)?;
        let timestamp: i64 = timestamp.parse().map_err(|_| AuthError::BadTimestamp)?;
        let now_seconds = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AuthError::BadTimestamp)?
            .as_secs() as i64;
        let skew = (now_seconds - timestamp).unsigned_abs();
        if skew > CLOCK_WINDOW.as_secs() {
            return Err(AuthError::OutsideWindow);
        }
        let canonical = canonical(method, path, body, timestamp, nonce);
        let expected = sign(&self.key, canonical.as_bytes());
        let supplied =
            crate::config::base64_url_decode(signature).ok_or(AuthError::SignatureMismatch)?;
        // Constant time: a length leak here would let an attacker learn the MAC
        // one byte at a time.
        if expected.ct_eq(&supplied).unwrap_u8() != 1 {
            return Err(AuthError::SignatureMismatch);
        }
        // Only remember a nonce after its signature checked out, otherwise an
        // unauthenticated request could burn a legitimate client's nonce.
        self.remember(nonce, now)?;
        Ok(())
    }

    fn remember(&self, nonce: &str, now: SystemTime) -> Result<(), AuthError> {
        let mut seen = self.seen.lock().map_err(|_| AuthError::Replayed)?;
        // Anything older than the window would already fail the timestamp check,
        // so its nonce no longer needs remembering.
        seen.retain(|_, expires| *expires > now);
        if seen.contains_key(nonce) {
            return Err(AuthError::Replayed);
        }
        seen.insert(
            nonce.to_owned(),
            now.checked_add(CLOCK_WINDOW)
                .unwrap_or(now + Duration::from_secs(30)),
        );
        Ok(())
    }

    /// The proof this plugin returns so the client can confirm it reached the
    /// agent it thinks it reached, not something replaying that agent's port.
    pub fn health_proof(&self, nonce: &str, agent_id: &str) -> String {
        let message = format!("AIRSIM-HEALTH1\n{nonce}\n{agent_id}");
        crate::config::base64_url_encode(&sign(&self.key, message.as_bytes()))
    }
}

fn header<'a>(
    headers: &'a HashMap<String, String>,
    name: &'static str,
) -> Result<&'a str, AuthError> {
    headers
        .get(name)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(AuthError::MissingHeader(name))
}

pub fn canonical(method: &str, path: &str, body: &[u8], timestamp: i64, nonce: &str) -> String {
    let digest: [u8; 32] = Sha256::digest(body).into();
    format!(
        "{}\n{}\n{}\n{}\n{}",
        method.to_uppercase(),
        path,
        hex_lower(&digest),
        timestamp,
        nonce
    )
}

fn sign(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x2a; 32];

    fn headers(signature: &str, timestamp: i64, nonce: &str) -> HashMap<String, String> {
        HashMap::from([
            (HEADER_SIGNATURE.to_owned(), signature.to_owned()),
            (HEADER_TIMESTAMP.to_owned(), timestamp.to_string()),
            (HEADER_NONCE.to_owned(), nonce.to_owned()),
        ])
    }

    fn signed(
        key: &[u8],
        method: &str,
        path: &str,
        body: &[u8],
        timestamp: i64,
        nonce: &str,
    ) -> String {
        let canonical = canonical(method, path, body, timestamp, nonce);
        crate::config::base64_url_encode(&sign(key, canonical.as_bytes()))
    }

    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_800_000_000)
    }

    /// The canonical string is the contract with the client. If this drifts the
    /// phone stops authenticating, so it is pinned literally.
    #[test]
    fn the_canonical_string_matches_the_clients_layout() {
        let digest = hex_lower(&Sha256::digest(b""));
        let expected = format!("GET\n/v1/health\n{digest}\n1800000000\nnonce-1");
        assert_eq!(
            canonical("get", "/v1/health", b"", 1_800_000_000, "nonce-1"),
            expected
        );
    }

    #[test]
    fn a_correctly_signed_request_is_accepted() {
        let verifier = Verifier::new(KEY.to_vec());
        let timestamp = 1_800_000_000;
        let signature = signed(&KEY, "GET", "/v1/health", b"", timestamp, "n1");
        assert!(
            verifier
                .verify(
                    "GET",
                    "/v1/health",
                    b"",
                    &headers(&signature, timestamp, "n1"),
                    now()
                )
                .is_ok()
        );
    }

    /// Replaying the exact same request must fail: the signature is still
    /// valid, so only the nonce memo stands between an eavesdropper and a
    /// second dial.
    #[test]
    fn a_replayed_request_is_refused_by_its_nonce() {
        let verifier = Verifier::new(KEY.to_vec());
        let timestamp = 1_800_000_000;
        let signature = signed(&KEY, "GET", "/v1/health", b"", timestamp, "n1");
        let headers = headers(&signature, timestamp, "n1");
        assert!(
            verifier
                .verify("GET", "/v1/health", b"", &headers, now())
                .is_ok()
        );
        assert!(matches!(
            verifier.verify("GET", "/v1/health", b"", &headers, now()),
            Err(AuthError::Replayed)
        ));
    }

    /// A signature made over a different body must not authorize the body that
    /// arrives, or an attacker could swap the payload of a signed dial.
    #[test]
    fn a_signature_over_another_body_does_not_authorize_this_one() {
        let verifier = Verifier::new(KEY.to_vec());
        let timestamp = 1_800_000_000;
        let signature = signed(
            &KEY,
            "POST",
            "/v2/calls/x/actions",
            b"{\"a\":1}",
            timestamp,
            "n1",
        );
        assert!(matches!(
            verifier.verify(
                "POST",
                "/v2/calls/x/actions",
                b"{\"a\":2}",
                &headers(&signature, timestamp, "n1"),
                now()
            ),
            Err(AuthError::SignatureMismatch)
        ));
    }

    /// The same signature must not authorize a different path or method.
    #[test]
    fn a_signature_is_bound_to_its_path_and_method() {
        let verifier = Verifier::new(KEY.to_vec());
        let timestamp = 1_800_000_000;
        let signature = signed(&KEY, "GET", "/v1/health", b"", timestamp, "n1");
        assert!(matches!(
            verifier.verify(
                "GET",
                "/v1/status",
                b"",
                &headers(&signature, timestamp, "n1"),
                now()
            ),
            Err(AuthError::SignatureMismatch)
        ));
        assert!(matches!(
            verifier.verify(
                "POST",
                "/v1/health",
                b"",
                &headers(&signature, timestamp, "n1"),
                now()
            ),
            Err(AuthError::SignatureMismatch)
        ));
    }

    /// A stale capture has to expire on its own, or a leaked request would stay
    /// usable as long as its nonce went unremembered.
    #[test]
    fn a_timestamp_outside_the_window_is_refused() {
        let verifier = Verifier::new(KEY.to_vec());
        let stale = 1_800_000_000 - CLOCK_WINDOW.as_secs() as i64 - 1;
        let signature = signed(&KEY, "GET", "/v1/health", b"", stale, "n1");
        assert!(matches!(
            verifier.verify(
                "GET",
                "/v1/health",
                b"",
                &headers(&signature, stale, "n1"),
                now()
            ),
            Err(AuthError::OutsideWindow)
        ));
    }

    /// A rejected signature must not burn the nonce: otherwise anyone who can
    /// reach the port could pre-empt a legitimate client's next request.
    #[test]
    fn a_failed_signature_does_not_burn_the_nonce() {
        let verifier = Verifier::new(KEY.to_vec());
        let timestamp = 1_800_000_000;
        let wrong = signed(
            b"not-the-key-not-the-key-not-the-k!",
            "GET",
            "/v1/health",
            b"",
            timestamp,
            "n1",
        );
        assert!(
            verifier
                .verify(
                    "GET",
                    "/v1/health",
                    b"",
                    &headers(&wrong, timestamp, "n1"),
                    now()
                )
                .is_err()
        );
        let correct = signed(&KEY, "GET", "/v1/health", b"", timestamp, "n1");
        assert!(
            verifier
                .verify(
                    "GET",
                    "/v1/health",
                    b"",
                    &headers(&correct, timestamp, "n1"),
                    now()
                )
                .is_ok(),
            "the legitimate client must still be able to use its nonce"
        );
    }

    /// The health proof is what convinces the phone it reached the right agent.
    #[test]
    fn the_health_proof_is_bound_to_the_nonce_and_agent() {
        let verifier = Verifier::new(KEY.to_vec());
        let proof = verifier.health_proof("nonce-1", "celmux");
        assert_eq!(proof, verifier.health_proof("nonce-1", "celmux"));
        assert_ne!(proof, verifier.health_proof("nonce-2", "celmux"));
        assert_ne!(proof, verifier.health_proof("nonce-1", "other"));
    }
}
