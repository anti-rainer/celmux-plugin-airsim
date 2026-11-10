// Copyright (c) 2026 anti-rainer
// SPDX-License-Identifier: MIT

//! Sending pushes to the phone through Apple.
//!
//! The cloud path's whole point is that the phone does not have to be reachable -
//! it is asleep, or on a different network - so the only way to tell it about a
//! call is a push. That means talking to APNs: HTTP/2, TLS, and a JWT signed with
//! an ES256 key the operator generates in their Apple developer account.
//!
//! Nothing here invents credentials. A p8 belongs to one Apple developer team, and
//! only that team can push to a token minted by an app signed with its profile. An
//! operator who signs their build with somebody else's certificate gets a working
//! control plane and no pushes, and [`Status::reason`] is how they find that out
//! instead of watching a phone that never rings.
//!
//! The three things APNs checks, in order of how often they are wrong:
//!
//! - `apns-topic` must be the bundle id the token belongs to (`.voip` appended for
//!   a PushKit token). A mismatch is `TopicDisallowed` or `DeviceTokenNotForTopic`.
//! - the JWT's `iss` is the team id and `kid` is the key id, not the other way
//!   round.
//! - a token minted by a development build only works against the sandbox host.

use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use serde_json::{Value, json};

/// Where a production build's tokens live.
const HOST_PRODUCTION: &str = "api.push.apple.com";
/// Where a development build's tokens live. Sending to the wrong one is answered
/// `BadDeviceToken` even though the token itself is fine.
const HOST_SANDBOX: &str = "api.sandbox.push.apple.com";

/// How long a signed JWT is reused.
///
/// Apple rejects a token older than an hour and asks for no more than one
/// generation per 20 minutes. 50 minutes sits between the two: fresh enough to be
/// accepted, slow enough that a busy gateway is not signing per request.
const TOKEN_LIFETIME: Duration = Duration::from_secs(50 * 60);

/// Why pushes are not going out. Reported verbatim to the operator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// A p8 and both identifiers are configured.
    Ready,
    /// No key: the operator has not set one up, or cannot.
    NoKey,
    /// A key is present but the identifiers that pair with it are not.
    Incomplete(String),
    /// The stored key is not a private key APNs can use.
    UnreadableKey(String),
}

impl Status {
    /// Whether a push can be attempted at all.
    pub fn ready(&self) -> bool {
        matches!(self, Self::Ready)
    }

    /// The sentence shown to the operator, or `None` when all is well.
    pub fn reason(&self) -> Option<String> {
        match self {
            Self::Ready => None,
            Self::NoKey => Some(
                "未配置 APNs 密钥：锁屏与后台推送不可用，手机需保持连接。\
                 需要自有 Apple 开发者账号生成的 p8（他人签名的 App 无法推送到）。"
                    .to_owned(),
            ),
            Self::Incomplete(what) => Some(format!("APNs 配置不完整：{what}")),
            Self::UnreadableKey(error) => Some(format!("APNs 密钥无法解析：{error}")),
        }
    }
}

/// What one push attempt ended as.
#[derive(Clone, Debug)]
pub struct Outcome {
    /// The HTTP status APNs answered with, or `None` if it could not be reached.
    pub status: Option<u16>,
    /// The `reason` field of APNs' error body, when it sent one.
    pub reason: String,
    /// The `apns-id` APNs assigned, for correlating with a support case.
    pub apns_id: String,
}

impl Outcome {
    /// A push APNs accepted.
    pub fn accepted(status: u16) -> bool {
        status == 200
    }

    /// A one-line account for the log.
    pub fn describe(&self) -> String {
        match self.status {
            Some(status) if Self::accepted(status) => format!("已受理 apns-id={}", self.apns_id),
            Some(status) => format!(
                "被拒绝 HTTP {status}{}{}",
                if self.reason.is_empty() { "" } else { " " },
                self.reason
            ),
            None => format!("无法连接 APNs {}", self.reason),
        }
    }
}

/// The push sender: credentials, the cached JWT, and the bundle to address.
pub struct Pusher {
    team_id: String,
    key_id: String,
    bundle_id: String,
    sandbox: bool,
    /// The p8 in PEM form, as the operator pasted it.
    key_pem: String,
    status: Status,
    /// The last signed JWT and when it was made. Signing is not free and APNs
    /// allows reuse, so it is minted on demand and kept until it nears expiry.
    token: Mutex<Option<(String, SystemTime)>>,
}

impl Pusher {
    /// Build a sender from configuration, validating the key up front.
    ///
    /// Validation happens here rather than at first push because the operator
    /// needs to know at startup: a key that cannot be parsed would otherwise only
    /// surface as a call that never rings.
    pub fn new(key_pem: &str, key_id: &str, team_id: &str, bundle_id: &str, sandbox: bool) -> Self {
        let (status, canonical_key) = if key_pem.trim().is_empty() {
            (Status::NoKey, String::new())
        } else if key_id.trim().is_empty() || team_id.trim().is_empty() {
            let missing = [
                if key_id.trim().is_empty() {
                    "Key ID"
                } else {
                    ""
                },
                if team_id.trim().is_empty() {
                    "Team ID"
                } else {
                    ""
                },
            ]
            .into_iter()
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join(" 与 ");
            (Status::Incomplete(missing), String::new())
        } else {
            match canonical_pem(key_pem) {
                Ok(pem) => (Status::Ready, pem),
                Err(error) => (Status::UnreadableKey(error), String::new()),
            }
        };
        Self {
            team_id: team_id.trim().to_owned(),
            key_id: key_id.trim().to_owned(),
            bundle_id: bundle_id.trim().to_owned(),
            sandbox,
            key_pem: canonical_key,
            status,
            token: Mutex::new(None),
        }
    }

    /// Whether this sender can push at all.
    pub fn status(&self) -> &Status {
        &self.status
    }

    /// The host pushes go to.
    pub fn host(&self) -> &'static str {
        if self.sandbox {
            HOST_SANDBOX
        } else {
            HOST_PRODUCTION
        }
    }

    /// The `apns-topic` a PushKit token needs.
    ///
    /// A VoIP token is addressed to `<bundle>.voip`. Sending to the bare bundle
    /// id is answered `TopicDisallowed`, which looks like a credentials problem
    /// and is not.
    pub fn voip_topic(&self) -> String {
        format!("{}.voip", self.bundle_id)
    }

    /// Send one VoIP push carrying `payload`.
    ///
    /// The payload is the whole notification: APNs adds the `aps` envelope itself
    /// for a PushKit push, so the fields here are exactly what the app reads out
    /// of `payload.dictionaryPayload`.
    pub fn push_voip(
        &self,
        device_token: &str,
        payload: &Value,
        collapse_id: &str,
        expires_at: u64,
    ) -> Outcome {
        if !self.status.ready() {
            return Outcome {
                status: None,
                reason: self
                    .status
                    .reason()
                    .unwrap_or_else(|| "APNs 未就绪".to_owned()),
                apns_id: String::new(),
            };
        }
        let token = match self.jwt() {
            Ok(token) => token,
            Err(error) => {
                return Outcome {
                    status: None,
                    reason: format!("无法签发 APNs JWT: {error}"),
                    apns_id: String::new(),
                };
            }
        };
        let body = serde_json::to_vec(payload).unwrap_or_default();
        let headers = [
            ("authorization", format!("bearer {token}")),
            ("apns-topic", self.voip_topic()),
            ("apns-push-type", "voip".to_owned()),
            // A ringing call is only worth interrupting someone for right now:
            // priority 10 is immediate delivery, not a batched one.
            ("apns-priority", "10".to_owned()),
            // The call's own expiry, not "0". APNs drops a push it cannot deliver
            // by then, which is what stops a call that has already been abandoned
            // from arriving minutes later.
            ("apns-expiration", expires_at.to_string()),
            // Two pushes for one call must replace each other rather than ring
            // twice; CallKit keys the second on the same UUID and would report a
            // duplicate.
            ("apns-collapse-id", collapse_id.to_owned()),
            ("content-type", "application/json".to_owned()),
        ];
        let path = format!("/3/device/{device_token}");
        let header_refs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        match crate::apns_http::post(self.host(), &path, &header_refs, &body) {
            Ok(response) => {
                let reason = if Outcome::accepted(response.status) {
                    String::new()
                } else {
                    serde_json::from_slice::<Value>(&response.body)
                        .ok()
                        .and_then(|value| {
                            value
                                .get("reason")
                                .and_then(Value::as_str)
                                .map(str::to_owned)
                        })
                        .unwrap_or_default()
                };
                Outcome {
                    status: Some(response.status),
                    reason,
                    apns_id: response.apns_id,
                }
            }
            Err(error) => Outcome {
                status: None,
                reason: error,
                apns_id: String::new(),
            },
        }
    }

    /// Send one ordinary (alert) push.
    ///
    /// Addressed to the bare bundle id: a VoIP token needs `.voip`, an alert token
    /// must not have it. `collapse-id` is the delivery id, so a message pushed
    /// twice replaces itself instead of showing twice.
    pub fn push_alert(&self, device_token: &str, payload: &Value, collapse_id: &str) -> Outcome {
        if !self.status.ready() {
            return Outcome {
                status: None,
                reason: self
                    .status
                    .reason()
                    .unwrap_or_else(|| "APNs 未就绪".to_owned()),
                apns_id: String::new(),
            };
        }
        let token = match self.jwt() {
            Ok(token) => token,
            Err(error) => {
                return Outcome {
                    status: None,
                    reason: format!("无法签发 APNs JWT: {error}"),
                    apns_id: String::new(),
                };
            }
        };
        let body = serde_json::to_vec(payload).unwrap_or_default();
        let headers = [
            ("authorization", format!("bearer {token}")),
            ("apns-topic", self.bundle_id.clone()),
            ("apns-push-type", "alert".to_owned()),
            // A message notification is worth delivering soon, but not at the cost
            // of waking a sleeping radio ahead of a voice call.
            ("apns-priority", "5".to_owned()),
            // Stored by APNs for a while, unlike a call: a message that arrived
            // while the phone was off is still worth seeing.
            ("apns-expiration", "0".to_owned()),
            ("apns-collapse-id", collapse_id.to_owned()),
            ("content-type", "application/json".to_owned()),
        ];
        let path = format!("/3/device/{device_token}");
        let header_refs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        match crate::apns_http::post(self.host(), &path, &header_refs, &body) {
            Ok(response) => {
                let reason = if Outcome::accepted(response.status) {
                    String::new()
                } else {
                    serde_json::from_slice::<Value>(&response.body)
                        .ok()
                        .and_then(|value| {
                            value
                                .get("reason")
                                .and_then(Value::as_str)
                                .map(str::to_owned)
                        })
                        .unwrap_or_default()
                };
                Outcome {
                    status: Some(response.status),
                    reason,
                    apns_id: response.apns_id,
                }
            }
            Err(error) => Outcome {
                status: None,
                reason: error,
                apns_id: String::new(),
            },
        }
    }

    /// The JWT for this team, signing a new one when the cached one is old.
    fn jwt(&self) -> Result<String, String> {
        if let Ok(token) = self.token.lock() {
            if let Some((value, at)) = token.as_ref() {
                if at.elapsed().unwrap_or(TOKEN_LIFETIME) < TOKEN_LIFETIME {
                    return Ok(value.clone());
                }
            }
        }
        let value = sign_jwt(&self.team_id, &self.key_id, &self.key_pem)?;
        if let Ok(mut token) = self.token.lock() {
            *token = Some((value.clone(), SystemTime::now()));
        }
        Ok(value)
    }
}

/// Build the ES256 JWT APNs expects.
///
/// `iss` is the team, `kid` is the key id, and the only claim is `iat`. Apple is
/// specific that the header carries `kid` and the payload carries `iss`; swapping
/// them is answered `InvalidProviderToken`.
fn sign_jwt(team_id: &str, key_id: &str, key_pem: &str) -> Result<String, String> {
    let issued = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    let header = json!({"alg": "ES256", "kid": key_id});
    let claims = json!({"iss": team_id, "iat": issued});
    let signing_input = format!(
        "{}.{}",
        crate::config::base64_url_encode(&serde_json::to_vec(&header).map_err(|e| e.to_string())?),
        crate::config::base64_url_encode(&serde_json::to_vec(&claims).map_err(|e| e.to_string())?)
    );
    let signature = crate::apns_http::es256_sign(key_pem, signing_input.as_bytes())?;
    Ok(format!(
        "{signing_input}.{}",
        crate::config::base64_url_encode(&signature)
    ))
}

/// Accept a p8 pasted with or without the PEM armour, and return full PEM.
///
/// Operators paste the file contents, and the file is 200 bytes of base64 between
/// two marker lines. Accepting a bare body costs nothing and saves a support
/// round-trip over a key that is otherwise perfectly good.
fn canonical_pem(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    let bare = trimmed
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    if bare.is_empty() {
        return Err("内容为空".to_owned());
    }
    // The body must decode as a private key before we promise anything: a
    // truncated paste is the mistake this catches.
    let der = crate::config::base64_url_decode_standard(&bare)
        .ok_or_else(|| "不是有效的 base64".to_owned())?;
    if der.len() < 64 {
        return Err(format!("密钥长度可疑（{} 字节）", der.len()));
    }
    Ok(format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        bare.as_bytes()
            .chunks(64)
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect::<Vec<_>>()
            .join("\n")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A p8 the operator has not set up is reported as such, not as a failure to
    /// send: the phone has to know it must keep its own connection open.
    #[test]
    fn a_missing_key_is_reported_as_missing_not_broken() {
        let pusher = Pusher::new("", "KEYID12345", "TEAMID1234", "com.example.app", false);
        assert_eq!(pusher.status(), &Status::NoKey);
        assert!(pusher.status().reason().is_some());
        let outcome = pusher.push_voip("deadbeef", &json!({}), "collapse", 0);
        assert!(outcome.status.is_none());
        assert!(outcome.reason.contains("未配置"));
    }

    /// A key without the identifiers it pairs with is refused at startup rather
    /// than at the first call, and both missing pieces are named.
    #[test]
    fn a_key_without_identifiers_names_what_is_missing() {
        let pusher = Pusher::new(
            "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
            "",
            "",
            "com.example.app",
            false,
        );
        match pusher.status() {
            Status::Incomplete(what) => {
                assert!(what.contains("Key ID"));
                assert!(what.contains("Team ID"));
            }
            other => panic!("应报告配置不完整，实际 {other:?}"),
        }
    }

    /// Garbage in the key field is caught before a call needs it.
    #[test]
    fn an_unreadable_key_is_rejected_up_front() {
        let pusher = Pusher::new(
            "not a key at all!!",
            "KEYID12345",
            "TEAMID1234",
            "com.example.app",
            false,
        );
        assert!(matches!(pusher.status(), Status::UnreadableKey(_)));
    }

    /// A VoIP token is addressed to `<bundle>.voip`. Using the bare bundle id is
    /// the mistake that looks like a credentials problem.
    #[test]
    fn the_voip_topic_carries_the_voip_suffix() {
        let pusher = Pusher::new("", "K", "T", "com.eric3u.airsim", false);
        assert_eq!(pusher.voip_topic(), "com.eric3u.airsim.voip");
        assert_eq!(pusher.host(), HOST_PRODUCTION);
        let sandbox = Pusher::new("", "K", "T", "com.eric3u.airsim", true);
        assert_eq!(sandbox.host(), HOST_SANDBOX);
    }

    /// The JWT APNs is given must be a real ES256 signature over the right claims.
    ///
    /// Apple's two silent rejections live here: `iss` and `kid` swapped, and a DER
    /// signature instead of the fixed 64-byte form JWS requires. Both are checked
    /// by verifying the signature the way APNs would rather than by reading the
    /// fields back.
    #[test]
    fn the_jwt_is_a_valid_es256_signature_with_the_right_claims() {
        use p256::ecdsa::signature::Verifier;
        use p256::ecdsa::{Signature, VerifyingKey};
        use p256::pkcs8::EncodePrivateKey;

        // A fixed scalar: the point of this test is the encoding APNs receives,
        // not the randomness of the key.
        let mut scalar = [7_u8; 32];
        scalar[0] = 1;
        let signing_key = p256::ecdsa::SigningKey::from_slice(&scalar).unwrap();
        let pem = signing_key
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string();
        let token = sign_jwt("TEAMID1234", "KEYID56789", &pem).expect("应能签发");

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT 必须是三段");

        let header: Value =
            serde_json::from_slice(&crate::config::base64_url_decode(parts[0]).unwrap()).unwrap();
        let claims: Value =
            serde_json::from_slice(&crate::config::base64_url_decode(parts[1]).unwrap()).unwrap();
        // `kid` in the header, `iss` in the claims. Swapping them is the mistake.
        assert_eq!(header["alg"], json!("ES256"));
        assert_eq!(header["kid"], json!("KEYID56789"));
        assert_eq!(claims["iss"], json!("TEAMID1234"));
        assert!(claims["iat"].as_u64().unwrap() > 1_600_000_000);

        // The signature verifies as raw r||s over `header.claims`, which is what
        // APNs does; a DER signature would fail this same check.
        let signature = crate::config::base64_url_decode(parts[2]).unwrap();
        assert_eq!(signature.len(), 64, "ES256 签名必须是固定的 64 字节");
        VerifyingKey::from(&signing_key)
            .verify(
                format!("{}.{}", parts[0], parts[1]).as_bytes(),
                &Signature::from_slice(&signature).unwrap(),
            )
            .expect("签名应能被验证");
    }

    /// Armour is optional, and whitespace inside the body is not part of the key.
    #[test]
    fn a_pasted_key_is_normalised_to_full_pem() {
        // 64 bytes of base64-decodable content, enough for the length check.
        let body = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2\
                    OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r\
                    1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G";
        let canonical = canonical_pem(body).expect("裸 base64 应被接受");
        assert!(canonical.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(canonical.trim_end().ends_with("-----END PRIVATE KEY-----"));
        // Already-armoured input is accepted too, and produces the same body.
        let armoured = format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n");
        assert_eq!(canonical_pem(&armoured).unwrap(), canonical);
        // A truncated paste is not.
        assert!(canonical_pem("MIGHAgEAMBMG").is_err());
    }
}
