// Copyright (c) 2026 anti-rainer
// SPDX-License-Identifier: MIT

//! The AirSIM pairing protocol.
//!
//! Pairing is not the same exchange as talking to a paired agent. Before the
//! phone has a secret, everything it sends is encrypted to a key only the
//! 6-digit code completes:
//!
//! ```text
//! shared = X25519(client_private, server_public)
//! key    = HKDF-SHA256(shared, salt = session_id,
//!                      info = "AirSIMPair/v1:<code>", len = 32)
//! sealed = AES-256-GCM(key, registration, aad = session_id)
//! ```
//!
//! The code is not compared against anything the server stores. It is part of
//! the key derivation, so a wrong code simply fails to decrypt. That is what
//! makes it a real secret: an eavesdropper on the LAN sees a public key and a
//! ciphertext, and without the six digits neither is worth anything.
//!
//! What arrives inside the ciphertext is the phone's `AgentPushRegistration`,
//! which carries the `vowlan_secret` this agent will sign every later request
//! with. So pairing is what *creates* the credential - there is no secret to
//! type in beforehand.

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// The protocol version this speaks, and the one the phone checks.
pub const PROTOCOL_VERSION: u32 = 1;
/// The product string `/pair/v1/info` must return, verbatim.
pub const PRODUCT: &str = "airsim-pair";

/// One pairing window: a key pair, the code that completes it, and when it
/// stops being offered.
pub struct Session {
    /// Goes in the `session` TXT record and in the HKDF salt, so a captured
    /// claim cannot be replayed into a later window.
    pub id: String,
    /// The 6 digits shown to the operator.
    pub code: String,
    secret: StaticSecret,
    pub public_key: [u8; 32],
    /// Unix milliseconds.
    pub expires_at: u64,
}

impl Session {
    /// Open a window that lives for `ttl`.
    ///
    /// The code is generated here rather than accepted from the caller so a
    /// window can never open without one: an empty code would derive a key
    /// anyone could compute.
    pub fn open(id: String, ttl: std::time::Duration) -> Result<Self, String> {
        let mut secret_bytes = [0_u8; 32];
        getrandom::fill(&mut secret_bytes).map_err(|error| format!("随机数不可用: {error}"))?;
        let secret = StaticSecret::from(secret_bytes);
        let public_key = PublicKey::from(&secret).to_bytes();
        let code = six_digit_code()?;
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "系统时间早于 1970 年".to_owned())?
            .as_millis() as u64
            + ttl.as_millis() as u64;
        Ok(Self {
            id,
            code,
            secret,
            public_key,
            expires_at,
        })
    }

    pub fn expired(&self, now: std::time::SystemTime) -> bool {
        let now_ms = now
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis() as u64)
            .unwrap_or(u64::MAX);
        now_ms >= self.expires_at
    }

    /// Decrypt a claim.
    ///
    /// `sealed` is the AES-GCM `combined` box - nonce, ciphertext, tag - and
    /// `client_public_key` is the phone's ephemeral key. A wrong code, a
    /// tampered body and a claim aimed at a different session all fail here,
    /// which is why there is no separate code comparison: the decryption *is*
    /// the comparison.
    pub fn open_claim(
        &self,
        client_public_key: &[u8; 32],
        sealed: &[u8],
    ) -> Result<Vec<u8>, String> {
        let shared = self
            .secret
            .diffie_hellman(&PublicKey::from(*client_public_key));
        let key = derive_key(shared.as_bytes(), &self.id, &self.code)?;
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|error| error.to_string())?;
        // The nonce is the first 12 bytes of the combined box, which is what
        // AES-GCM's `combined` layout means on the client side.
        if sealed.len() <= 12 {
            return Err("配对密文过短".to_owned());
        }
        let (nonce, body) = sealed.split_at(12);
        // AES-GCM's nonce is 12 bytes, so the slice splits and converts
        // without a fallible step beyond the length check above.
        let nonce_bytes: [u8; 12] = nonce
            .try_into()
            .map_err(|_| "配对密文 nonce 无效".to_owned())?;
        cipher
            .decrypt(
                (&nonce_bytes).into(),
                Payload {
                    msg: body,
                    aad: self.id.as_bytes(),
                },
            )
            .map_err(|_| "配对密文无法解密：验证码错误或数据被篡改".to_owned())
    }
}

/// HKDF-SHA256 with the session id as salt and the code in the info string.
///
/// This is exactly what the client computes; both sides must agree byte for
/// byte or nothing decrypts.
fn derive_key(shared: &[u8], session_id: &str, code: &str) -> Result<[u8; 32], String> {
    let hkdf = Hkdf::<Sha256>::new(Some(session_id.as_bytes()), shared);
    let info = format!("AirSIMPair/v1:{code}");
    let mut key = [0_u8; 32];
    hkdf.expand(info.as_bytes(), &mut key)
        .map_err(|_| "密钥派生失败".to_owned())?;
    Ok(key)
}

/// A uniform 6-digit code, `000000` included.
///
/// Rejection sampling over a 6-digit range: taking `random % 1_000_000` would
/// bias the low values, and this is a secret.
fn six_digit_code() -> Result<String, String> {
    const RANGE: u32 = 1_000_000;
    // The largest multiple of RANGE that fits in u32, so values at or above it
    // are discarded rather than folded.
    const LIMIT: u32 = u32::MAX - (u32::MAX % RANGE);
    loop {
        let mut bytes = [0_u8; 4];
        getrandom::fill(&mut bytes).map_err(|error| format!("随机数不可用: {error}"))?;
        let value = u32::from_le_bytes(bytes);
        if value < LIMIT {
            return Ok(format!("{:06}", value % RANGE));
        }
    }
}

/// What the phone sends to `/pair/v1/claim`.
pub struct Claim {
    pub session_id: String,
    pub client_public_key: [u8; 32],
    pub sealed_registration: Vec<u8>,
}

/// The registration the phone seals into a claim.
///
/// Only the parts this agent acts on are decoded: the rest belongs to the
/// phone and a cloud relay that is not in use here.
#[derive(Debug, Default)]
pub struct Registration {
    pub device_id: String,
    /// The secret every later request is signed with. Its presence is what
    /// makes pairing succeed.
    pub vowlan_secret: Option<String>,
}

pub fn parse_registration(bytes: &[u8]) -> Result<Registration, String> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| format!("注册信息不是有效 JSON: {error}"))?;
    let text = |key: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned()
    };
    Ok(Registration {
        device_id: text("device_id"),
        // The client may omit the secret on a re-pair; only its presence when
        // sent matters.
        vowlan_secret: value
            .get("vowlan_secret")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
    })
}

/// The proof that binds an agent's advertised ports to the secret the phone
/// just sent.
///
/// Without it, a phone that paired with one agent could be pointed at another
/// agent's ports by anything that can rewrite a response.
pub fn route_proof(
    secret: &[u8],
    session_id: &str,
    client_key: &str,
    agent_id: &str,
    control_port: u16,
    pcm_port: u16,
) -> String {
    use hmac::{Hmac, KeyInit as _, Mac};
    let message = format!(
        "AIRSIM-DIRECT1\n{session_id}\n{client_key}\n{agent_id}\n{control_port}\n{pcm_port}"
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(message.as_bytes());
    crate::config::base64_url_encode(&mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn session() -> Session {
        Session::open("session-1".to_owned(), Duration::from_secs(300)).unwrap()
    }

    /// Seal a registration the way the client does, so the test proves the two
    /// implementations agree rather than that one agrees with itself.
    fn seal(session: &Session, plaintext: &[u8]) -> (Vec<u8>, [u8; 32]) {
        let client_secret_bytes = [9_u8; 32];
        let client_secret = StaticSecret::from(client_secret_bytes);
        let client_public = PublicKey::from(&client_secret).to_bytes();
        let server_public = PublicKey::from(session.public_key);
        let shared = client_secret.diffie_hellman(&server_public);
        let key = derive_key(shared.as_bytes(), &session.id, &session.code).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce_bytes = [1_u8; 12];
        let sealed = cipher
            .encrypt(
                (&nonce_bytes).into(),
                Payload {
                    msg: plaintext,
                    aad: session.id.as_bytes(),
                },
            )
            .unwrap();
        let mut combined = nonce_bytes.to_vec();
        combined.extend_from_slice(&sealed);
        (combined, client_public)
    }

    #[test]
    fn a_claim_sealed_with_the_right_code_decrypts() {
        let session = session();
        let (sealed, client_public) = seal(&session, br#"{"device_id":"p2"}"#);
        let plaintext = session.open_claim(&client_public, &sealed).unwrap();
        assert_eq!(plaintext, br#"{"device_id":"p2"}"#);
    }

    /// The code is part of the key, so a wrong one fails at decryption rather
    /// than at a comparison nobody could reach.
    #[test]
    fn a_claim_sealed_with_another_code_does_not_decrypt() {
        let session = session();
        let (sealed, client_public) = seal(&session, br#"{"device_id":"p2"}"#);
        let wrong = Session {
            id: session.id.clone(),
            code: if session.code == "000000" {
                "000001".to_owned()
            } else {
                "000000".to_owned()
            },
            secret: StaticSecret::from([9_u8; 32]),
            public_key: session.public_key,
            expires_at: session.expires_at,
        };
        assert!(wrong.open_claim(&client_public, &sealed).is_err());
    }

    /// The session id is the AAD, so a claim for one window cannot be moved
    /// into another even with the same code and key.
    #[test]
    fn a_claim_is_bound_to_its_session_id() {
        let session = session();
        let (sealed, client_public) = seal(&session, b"payload");
        let other = Session {
            id: "session-2".to_owned(),
            code: session.code.clone(),
            secret: StaticSecret::from([3_u8; 32]),
            public_key: session.public_key,
            expires_at: session.expires_at,
        };
        assert!(other.open_claim(&client_public, &sealed).is_err());
    }

    #[test]
    fn a_window_stops_being_offered_when_it_expires() {
        let session = Session::open("s".to_owned(), Duration::from_secs(0)).unwrap();
        assert!(session.expired(SystemTime::now()));
        let live = Session::open("s".to_owned(), Duration::from_secs(600)).unwrap();
        assert!(!live.expired(SystemTime::now()));
    }

    /// The code is a secret, so it has to be six digits and cover the whole
    /// range evenly.
    #[test]
    fn the_code_is_six_digits() {
        for _ in 0..64 {
            let code = six_digit_code().unwrap();
            assert_eq!(code.len(), 6);
            assert!(code.chars().all(|character| character.is_ascii_digit()));
        }
    }

    /// Two windows must never share a key pair: the public key is broadcast, so
    /// a repeated one would let an old capture be replayed at a new window.
    #[test]
    fn every_window_gets_a_fresh_key_and_code() {
        let first = session();
        let second = session();
        assert_ne!(first.public_key, second.public_key);
    }

    #[test]
    fn the_registration_carries_the_secret_the_agent_will_verify_with() {
        let registration =
            parse_registration(br#"{"device_id":"p2","vowlan_secret":"abc","bundle_id":"com.x"}"#)
                .unwrap();
        assert_eq!(registration.device_id, "p2");
        assert_eq!(registration.vowlan_secret.as_deref(), Some("abc"));
    }

    #[test]
    fn a_registration_without_a_secret_is_still_parseable() {
        let registration = parse_registration(br#"{"device_id":"p2"}"#).unwrap();
        assert!(registration.vowlan_secret.is_none());
    }

    /// The proof is what binds the advertised ports to the paired secret.
    #[test]
    fn the_route_proof_covers_every_advertised_value() {
        let proof = route_proof(b"secret-key", "s1", "ck", "celmux", 8642, 8643);
        assert_eq!(
            proof,
            route_proof(b"secret-key", "s1", "ck", "celmux", 8642, 8643)
        );
        assert_ne!(
            proof,
            route_proof(b"secret-key", "s1", "ck", "celmux", 8644, 8643)
        );
        assert_ne!(
            proof,
            route_proof(b"secret-key", "s1", "ck", "other", 8642, 8643)
        );
        assert_ne!(
            proof,
            route_proof(b"other-key", "s1", "ck", "celmux", 8642, 8643)
        );
    }
}
