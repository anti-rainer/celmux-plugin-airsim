// Copyright (c) 2026 anti-rainer
// SPDX-License-Identifier: MIT

//! The pairing endpoints.
//!
//! Two routes, both unauthenticated by design - a phone that has not paired has
//! no credential to present. What protects them is the pairing window: it only
//! exists while the operator has one open, it expires, and it refuses a claim
//! that does not decrypt under its 6-digit code.
//!
//! ```text
//! GET  /pair/v1/info    what the window is, and the key to seal a claim to
//! POST /pair/v1/claim   the sealed registration, in exchange for a route proof
//! ```

use std::sync::Arc;

use serde_json::{Value, json};

use crate::agents::Agent;
use crate::http::{Request, Response};
use crate::pairing::{self, Claim};

/// Handle a pairing request. `None` means the path is not a pairing route.
pub fn handle(agent: &Arc<Agent>, request: &Request) -> Option<Response> {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/pair/v1/info") => Some(info(agent)),
        ("POST", "/pair/v1/claim") => Some(claim(agent, request)),
        _ => None,
    }
}

/// What the phone needs to build a claim.
///
/// `server_time` is not decoration: the phone uses it to work out how far its
/// clock is from this host, because the two are rarely in sync and every later
/// request is timestamped.
fn info(agent: &Arc<Agent>) -> Response {
    match agent.with_pairing(|session| {
        (
            session.id.clone(),
            crate::config::base64_url_encode(&session.public_key),
            session.expires_at,
        )
    }) {
        Some((session_id, server_public_key, expires_at)) => {
            let server_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_millis() as u64)
                .unwrap_or_default();
            Response::ok(json!({
                "product": pairing::PRODUCT,
                "version": pairing::PROTOCOL_VERSION,
                "session_id": session_id,
                "server_public_key": server_public_key,
                "expires_at": expires_at,
                "server_time": server_time,
                "agent_id": agent.id(),
            }))
        }
        // No window open, or the one that was open has expired. The phone reads
        // this as "nothing to pair with here", which is the honest answer.
        None => Response::error(
            404,
            "Not Found",
            "no_pairing_window",
            "没有打开的配对窗口，请在 Celmux 插件设置中开始配对",
        ),
    }
}

/// Exchange a sealed registration for a route proof.
fn claim(agent: &Arc<Agent>, request: &Request) -> Response {
    let payload: Value = match serde_json::from_slice(&request.body) {
        Ok(value) => value,
        Err(error) => {
            return Response::error(400, "Bad Request", "bad_request", &error.to_string());
        }
    };
    let session_id = payload
        .get("session_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let client_key_text = payload
        .get("client_public_key")
        .and_then(Value::as_str)
        .unwrap_or("");
    let sealed_text = payload
        .get("sealed_registration")
        .and_then(Value::as_str)
        .unwrap_or("");
    // `want_direct_route` is read but not acted on: a direct route is the only
    // kind this agent has, so there is nothing to choose between. Reading it
    // keeps a payload missing the field from being a parse error.
    let _want_direct_route = payload
        .get("want_direct_route")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if session_id.is_empty() || client_key_text.is_empty() || sealed_text.is_empty() {
        return Response::error(
            400,
            "Bad Request",
            "bad_request",
            "缺少 session_id、client_public_key 或 sealed_registration",
        );
    }
    let Some(client_key) = crate::config::base64_url_decode(client_key_text)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
    else {
        return Response::error(
            400,
            "Bad Request",
            "bad_request",
            "client_public_key 必须是 32 字节的 base64url",
        );
    };
    let Some(sealed) = crate::config::base64_url_decode(sealed_text) else {
        return Response::error(
            400,
            "Bad Request",
            "bad_request",
            "sealed_registration 不是有效的 base64url",
        );
    };
    let claim = Claim {
        session_id: session_id.to_owned(),
        client_public_key: client_key,
        sealed_registration: sealed,
    };
    // The window is consumed under its own lock: two claims must not both
    // succeed against one window, or a second phone could pair with a code that
    // was only ever shown once.
    let plaintext = agent.with_pairing(|session| {
        if session.id != claim.session_id {
            return Err("配对会话不匹配".to_owned());
        }
        session.open_claim(&claim.client_public_key, &claim.sealed_registration)
    });
    let Some(plaintext) = plaintext else {
        return Response::error(
            404,
            "Not Found",
            "no_pairing_window",
            "没有打开的配对窗口或已过期",
        );
    };
    let plaintext = match plaintext {
        Ok(plaintext) => plaintext,
        Err(error) => {
            return Response::error(403, "Forbidden", "invalid_code", &error);
        }
    };
    let registration = match pairing::parse_registration(&plaintext) {
        Ok(registration) => registration,
        Err(error) => {
            return Response::error(400, "Bad Request", "bad_registration", &error);
        }
    };
    let Some(encoded_secret) = registration.vowlan_secret.clone() else {
        return Response::error(
            400,
            "Bad Request",
            "missing_secret",
            "注册信息里没有 vowlan_secret，无法建立签名凭据",
        );
    };
    let Some(secret) = crate::config::base64_url_decode(&encoded_secret) else {
        return Response::error(
            400,
            "Bad Request",
            "bad_secret",
            "vowlan_secret 不是有效的 base64url",
        );
    };
    if secret.len() < 32 {
        return Response::error(
            400,
            "Bad Request",
            "bad_secret",
            "vowlan_secret 至少需要 32 字节",
        );
    }
    // Store the secret before answering: a proof the phone accepts while the
    // agent cannot verify its next request would drop the very first call. It
    // is also written to disk, because a restart that forgot the pairing would
    // make the operator walk to the web UI and read six new digits every time.
    agent.set_secret(secret.clone());
    // Written through the agent, which knows where it lives: a restart that
    // forgot the pairing would make the operator read six new digits every
    // time the plugin restarts, which is every config save and every upgrade.
    agent.persist_secret();
    agent.close_pairing();
    let proof = pairing::route_proof(
        &secret,
        session_id,
        client_key_text,
        &agent.id(),
        agent.config.control_port,
        agent.config.pcm_port,
    );
    crate::log_info!(
        "celmux-plugin-airsim: agent {} 配对成功 device={}",
        agent.id(),
        if registration.device_id.is_empty() {
            "?"
        } else {
            &registration.device_id
        }
    );
    Response::ok(json!({
        "configured": true,
        "agent_id": agent.id(),
        "control_port": agent.config.control_port,
        "pcm_port": agent.config.pcm_port,
        "route_proof": proof,
        "device_id_hint": short_hint(&registration.device_id),
    }))
}

/// The last few characters of a device id, which is all the phone shows.
fn short_hint(device_id: &str) -> String {
    if device_id.is_empty() {
        return String::new();
    }
    let visible: String = device_id
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    visible
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::AgentConfig;

    fn agent() -> Arc<Agent> {
        Arc::new(Agent::new(
            AgentConfig {
                line_id: "dji1".to_owned(),
                name: String::new(),
                control_port: 8642,
                pcm_port: 8643,
            },
            None,
        ))
    }

    fn request(method: &str, path: &str, body: &str) -> Request {
        Request {
            method: method.to_owned(),
            path: path.to_owned(),
            query: String::new(),
            headers: std::collections::HashMap::new(),
            body: body.as_bytes().to_vec(),
        }
    }

    /// With no window open there is nothing to pair against, and the answer says
    /// so instead of handing out a key nobody can use.
    #[test]
    fn info_without_a_window_reports_nothing_to_pair_with() {
        let response = handle(&agent(), &request("GET", "/pair/v1/info", "")).unwrap();
        assert_eq!(response.status, 404);
    }

    /// The info payload carries every field the client validates before it will
    /// build a claim.
    #[test]
    fn info_reports_the_product_version_and_key() {
        let agent = agent();
        agent
            .open_pairing(std::time::Duration::from_secs(300), "s1".to_owned())
            .unwrap();
        let response = handle(&agent, &request("GET", "/pair/v1/info", "")).unwrap();
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["product"], "airsim-pair");
        assert_eq!(body["version"], 1);
        assert_eq!(body["session_id"], "s1");
        // The client rejects a key that is not 32 bytes.
        let key = crate::config::base64_url_decode(body["server_public_key"].as_str().unwrap());
        assert_eq!(key.map(|bytes| bytes.len()), Some(32));
        assert!(body["expires_at"].as_u64().unwrap() > 0);
        assert!(body["server_time"].as_u64().unwrap() > 0);
    }

    /// A claim against a closed window is refused rather than evaluated. The
    /// body is well formed on purpose: the point is that a valid-looking claim
    /// finds no window to be checked against.
    #[test]
    fn a_claim_without_a_window_is_refused() {
        let body = format!(
            r#"{{"session_id":"s1","client_public_key":"{}","sealed_registration":"{}"}}"#,
            crate::config::base64_url_encode(&[1_u8; 32]),
            crate::config::base64_url_encode(&[2_u8; 40])
        );
        let response = handle(&agent(), &request("POST", "/pair/v1/claim", &body)).unwrap();
        assert_eq!(response.status, 404);
    }

    /// A malformed claim is a bad request, not a crash.
    #[test]
    fn a_malformed_claim_is_rejected() {
        let response = handle(&agent(), &request("POST", "/pair/v1/claim", "{}")).unwrap();
        assert_eq!(response.status, 400);
    }

    /// A well-formed claim with the wrong code must not pair: this is the only
    /// thing standing between a LAN eavesdropper and a signing secret.
    #[test]
    fn a_claim_that_does_not_decrypt_never_pairs() {
        let agent = agent();
        agent
            .open_pairing(std::time::Duration::from_secs(300), "s1".to_owned())
            .unwrap();
        let body = format!(
            r#"{{"session_id":"s1","client_public_key":"{}","sealed_registration":"{}"}}"#,
            crate::config::base64_url_encode(&[1_u8; 32]),
            crate::config::base64_url_encode(&[2_u8; 40])
        );
        let response = handle(&agent, &request("POST", "/pair/v1/claim", &body)).unwrap();
        assert_eq!(response.status, 403);
        assert!(!agent.paired());
    }

    /// A session id that does not match the open window is refused before any
    /// decryption is attempted.
    #[test]
    fn a_claim_for_another_session_is_refused() {
        let agent = agent();
        agent
            .open_pairing(std::time::Duration::from_secs(300), "s1".to_owned())
            .unwrap();
        let body = format!(
            r#"{{"session_id":"other","client_public_key":"{}","sealed_registration":"{}"}}"#,
            crate::config::base64_url_encode(&[1_u8; 32]),
            crate::config::base64_url_encode(&[2_u8; 40])
        );
        let response = handle(&agent, &request("POST", "/pair/v1/claim", &body)).unwrap();
        assert_eq!(response.status, 403);
    }

    #[test]
    fn a_non_pairing_path_is_left_to_the_caller() {
        assert!(handle(&agent(), &request("GET", "/v1/health", "")).is_none());
    }

    /// The hint is only the tail of a device id, which is all the phone shows.
    #[test]
    fn the_device_hint_is_short() {
        assert_eq!(short_hint("ABCDEFGH1234"), "1234");
        assert_eq!(short_hint(""), "");
    }
}
