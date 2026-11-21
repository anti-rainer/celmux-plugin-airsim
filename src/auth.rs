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

#[derive(Debug)]
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
    /// Every key this agent accepts, keyed by the device it belongs to.
    ///
    /// One per paired phone: each phone generates its own secret at pairing and
    /// keeps it in its own keychain, so the agent has to hold all of them for
    /// the phones to work at the same time. A single key would mean the phone
    /// that paired most recently is the only one that can make a request.
    keys: HashMap<String, Vec<u8>>,
    /// Accepted nonces, each with the instant it stops being interesting.
    seen: Mutex<HashMap<String, SystemTime>>,
}

impl Verifier {
    /// A verifier that accepts several phones at once.
    pub fn with_keys(keys: HashMap<String, Vec<u8>>) -> Self {
        Self {
            keys,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Verify one request, and say which phone signed it.
    ///
    /// Every key is tried, because the request carries no device name: the
    /// phone signs its own request with its own secret and sends nothing that
    /// identifies which phone it is. The first key that matches is the answer,
    /// and a MAC match is proof enough to trust it - guessing a 32-byte HMAC
    /// is not something a wrong key does by accident.
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
    ) -> Result<String, AuthError> {
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
        let supplied =
            crate::config::base64_url_decode(signature).ok_or(AuthError::SignatureMismatch)?;
        let mut matched: Option<String> = None;
        for (device, key) in &self.keys {
            let expected = sign(key, canonical.as_bytes());
            // Constant time per key: a length leak here would let an attacker
            // learn the MAC one byte at a time.
            if expected.ct_eq(&supplied).unwrap_u8() == 1 {
                matched = Some(device.clone());
                break;
            }
        }
        let Some(device) = matched else {
            // Neither the keys nor the secret are printed: knowing either is
            // enough to sign as this line. The count is what tells "no phone has
            // paired" from "a phone signed with a key this agent never got".
            crate::log_warn!(
                "celmux-plugin-airsim: 签名不符（已配对密钥 {} 把）canonical={:?} 收到={}",
                self.keys.len(),
                canonical,
                crate::config::base64_url_encode(&supplied)
            );
            return Err(AuthError::SignatureMismatch);
        };
        // Only remember a nonce after its signature checked out, otherwise an
        // unauthenticated request could burn a legitimate client's nonce.
        self.remember(nonce, now)?;
        Ok(device)
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

    /// The key one device signs with, or any key when the caller has no device.
    ///
    /// A proof has to be signed with the key of the phone that will check it:
    /// each phone holds its own secret, so a proof signed with another phone's
    /// key fails to verify on the one that asked. `device` is what `verify`
    /// returned for the request being answered.
    fn signing_key(&self, device: Option<&str>) -> Option<&Vec<u8>> {
        match device {
            Some(device) => self.keys.get(device),
            None => self.keys.values().next(),
        }
    }

    /// The proof this plugin returns so the client can confirm it reached the
    /// agent it thinks it reached, not something replaying that agent's port.
    pub fn health_proof(&self, nonce: &str, agent_id: &str, device: Option<&str>) -> String {
        let message = format!("AIRSIM-HEALTH1\n{nonce}\n{agent_id}");
        self.signing_key(device)
            .map(|key| crate::config::base64_url_encode(&sign(key, message.as_bytes())))
            .unwrap_or_default()
    }

    /// Sign one canonical message with the key of the device being answered.
    ///
    /// Every proof the client checks is an HMAC over a string it builds itself -
    /// the health proof, the dial receipt - so the signing is one operation and
    /// only the message differs. The device matters because the client verifying
    /// the proof uses its own key.
    pub fn proof(&self, message: &str, device: Option<&str>) -> String {
        self.signing_key(device)
            .map(|key| crate::config::base64_url_encode(&sign(key, message.as_bytes())))
            .unwrap_or_default()
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

/// Check one signature against a secret, for a caller that has the pieces
/// separately rather than in headers.
///
/// The PCM handshake arrives as a line of text rather than as headers, so it
/// cannot go through [`Verifier::verify`]; the MAC and the comparison are the
/// same ones, which is what keeps one definition of a valid signature.
pub fn signature_matches(
    secret: &[u8],
    method: &str,
    path: &str,
    body: &[u8],
    timestamp: &str,
    nonce: &str,
    signature: &str,
) -> bool {
    let Ok(timestamp) = timestamp.parse::<i64>() else {
        return false;
    };
    let canonical = canonical(method, path, body, timestamp, nonce);
    let expected = sign(secret, canonical.as_bytes());
    // Constant time, like the header path: a length leak here would let an
    // attacker learn the MAC one byte at a time.
    crate::config::base64_url_decode(signature)
        .map(|supplied| expected.ct_eq(&supplied).unwrap_u8() == 1)
        .unwrap_or(false)
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

    /// A verifier holding one key, under the empty device name.
    ///
    /// The production constructors take a map because an agent holds one key per
    /// phone; the tests that are about verification rather than about device
    /// selection only need one.
    /// Two phones, two keys, both accepted - the whole point of the map.
    ///
    /// With one key per agent, the phone that paired last would be the only one
    /// that could make a request: the other's signature would be checked against
    /// a key that is not its own. Each request names its signer so the proofs
    /// returned for it can be signed with the key that phone will verify with.
    #[test]
    fn two_phones_each_sign_with_their_own_key() {
        let mut keys = HashMap::new();
        keys.insert("phone-a".to_owned(), KEY.to_vec());
        keys.insert("phone-b".to_owned(), OTHER.to_vec());
        let verifier = Verifier::with_keys(keys);
        let timestamp = 1_800_000_000;

        for (device, key, nonce) in [("phone-a", KEY, "nonce-a"), ("phone-b", OTHER, "nonce-b")] {
            let signature = signed(&key, "GET", "/v1/health", b"", timestamp, nonce);
            let request_headers = headers(&signature, timestamp, nonce);
            let matched = verifier
                .verify("GET", "/v1/health", b"", &request_headers, now())
                .expect("each paired phone verifies with its own key");
            assert_eq!(matched, device, "the signer is named");
        }

        // A phone whose key this agent never got is refused, not silently
        // treated as one of the others.
        let stranger_signature = signed(&STRANGER, "GET", "/v1/health", b"", timestamp, "nonce-c");
        let stranger_headers = headers(&stranger_signature, timestamp, "nonce-c");
        assert!(
            verifier
                .verify("GET", "/v1/health", b"", &stranger_headers, now())
                .is_err()
        );

        // A replay is refused even though the key is right: one memo covers
        // every device, so a nonce cannot be spent twice by any of them.
        let replay_signature = signed(&KEY, "GET", "/v1/health", b"", timestamp, "nonce-a");
        let replay_headers = headers(&replay_signature, timestamp, "nonce-a");
        assert!(matches!(
            verifier.verify("GET", "/v1/health", b"", &replay_headers, now()),
            Err(AuthError::Replayed)
        ));
    }

    /// The proof a phone checks is signed with that phone's key.
    ///
    /// Each phone verifies with its own secret, so answering one with another's
    /// key fails the check it is entitled to pass - which on the phone looks like
    /// a gateway that is not the one it paired with.
    #[test]
    fn a_proof_is_signed_with_the_key_of_the_phone_that_asked() {
        let mut keys = HashMap::new();
        keys.insert("phone-a".to_owned(), KEY.to_vec());
        keys.insert("phone-b".to_owned(), OTHER.to_vec());
        let verifier = Verifier::with_keys(keys);

        let for_a = verifier.proof("receipt", Some("phone-a"));
        let for_b = verifier.proof("receipt", Some("phone-b"));
        assert_ne!(for_a, for_b, "each phone gets its own signature");
        // Verify the way the phone does: recompute with its own key.
        let expected_a = crate::config::base64_url_encode(&sign(&KEY, b"receipt"));
        assert_eq!(for_a, expected_a);
        // An unknown device gets nothing rather than somebody else's proof.
        assert_eq!(verifier.proof("receipt", Some("phone-c")), "");
    }

    fn single(key: [u8; 32]) -> Verifier {
        let mut keys = HashMap::new();
        keys.insert(String::new(), key.to_vec());
        Verifier::with_keys(keys)
    }

    const KEY: [u8; 32] = [0x2a; 32];
    /// A second phone's key, distinct from the first's.
    const OTHER: [u8; 32] = [0x5c; 32];
    /// A key this agent never received.
    const STRANGER: [u8; 32] = [0xff; 32];

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
        let verifier = single(KEY);
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
        let verifier = single(KEY);
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
        let verifier = single(KEY);
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
        let verifier = single(KEY);
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
        let verifier = single(KEY);
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
        let verifier = single(KEY);
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
        let verifier = single(KEY);
        let proof = verifier.health_proof("nonce-1", "celmux", None);
        assert_eq!(proof, verifier.health_proof("nonce-1", "celmux", None));
        assert_ne!(proof, verifier.health_proof("nonce-2", "celmux", None));
        assert_ne!(proof, verifier.health_proof("nonce-1", "other", None));
    }
}
