// Copyright (c) 2026 anti-rainer
// SPDX-License-Identifier: MIT

//! A client that pairs the way the iPhone app does, then exercises the control
//! plane with the secret pairing produced.
//!
//! This exists because "the gateway answered 200" is not evidence that the app
//! works. The app's proof check is a separate step that fails silently, and the
//! only honest way to test it is to complete the same exchange the app
//! completes. Run it against a live agent while a pairing window is open:
//!
//! ```text
//! celmux-plugin-airsim pair-probe --port 8642 --code 123456
//! ```
//!
//! Every assertion here maps to something the app checks, not to something that
//! happens to be easy to assert.

use std::io::{Read, Write};
use std::net::TcpStream;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::config::{base64_url_decode, base64_url_encode};

pub fn main(args: Vec<String>) -> i32 {
    let mut port = 8642_u16;
    let mut host = String::from("127.0.0.1");
    let mut code = String::new();
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--port" => {
                port = iter
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(port);
            }
            "--host" => host = iter.next().unwrap_or(host),
            "--code" => code = iter.next().unwrap_or_default(),
            other => {
                eprintln!("未知参数: {other}");
                return 2;
            }
        }
    }
    if code.is_empty() {
        eprintln!("用法: pair-probe --port 8642 --code <六位验证码> [--host 127.0.0.1]");
        return 2;
    }
    match run(&format!("{host}:{port}"), &code) {
        Ok(()) => {
            println!("\n全部通过");
            0
        }
        Err(error) => {
            eprintln!("\n失败: {error}");
            1
        }
    }
}

fn run(base: &str, code: &str) -> Result<(), String> {
    // 1. The pairing window's id salts the key derivation, and its public key
    //    is half of the exchange.
    let info = get(&format!("http://{base}/pair/v1/info"))?;
    let value: serde_json::Value =
        serde_json::from_str(&info).map_err(|error| format!("info 不是 JSON: {error}"))?;
    let session_id = value
        .get("session_id")
        .and_then(|value| value.as_str())
        .ok_or("info 缺少 session_id")?
        .to_owned();
    let server_key: [u8; 32] = base64_url_decode(
        value
            .get("server_public_key")
            .and_then(|value| value.as_str())
            .ok_or("info 缺少 server_public_key")?,
    )
    .ok_or("server_public_key 不是有效 base64url")?
    .try_into()
    .map_err(|_: Vec<u8>| "server_public_key 不是 32 字节")?;
    println!("配对窗口 {session_id}");

    // 2. The phone's ephemeral key, and the secret it wants this agent to sign
    //    with afterwards. Pairing is what creates the credential.
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed).map_err(|error| format!("随机数不可用: {error}"))?;
    let client_secret = StaticSecret::from(seed);
    let client_public = PublicKey::from(&client_secret).to_bytes();
    let vowlan_secret_bytes = {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|error| format!("随机数不可用: {error}"))?;
        bytes
    };
    let vowlan_secret = base64_url_encode(&vowlan_secret_bytes);

    // 3. Seal the registration to a key only the six digits complete.
    let shared = client_secret.diffie_hellman(&PublicKey::from(server_key));
    let hkdf = Hkdf::<Sha256>::new(Some(session_id.as_bytes()), shared.as_bytes());
    let mut key = [0_u8; 32];
    hkdf.expand(format!("AirSIMPair/v1:{code}").as_bytes(), &mut key)
        .map_err(|_| "密钥派生失败")?;
    let registration = serde_json::json!({
        "device_id": "celmux-pair-probe",
        "vowlan_secret": vowlan_secret,
        "agent_kind": "standalone",
        "device_name": "Celmux 验证客户端",
    })
    .to_string();
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|error| error.to_string())?;
    let mut nonce = [0_u8; 12];
    getrandom::fill(&mut nonce).map_err(|error| format!("随机数不可用: {error}"))?;
    let sealed = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: registration.as_bytes(),
                aad: session_id.as_bytes(),
            },
        )
        .map_err(|_| "加密注册信息失败")?;
    let mut boxed = nonce.to_vec();
    boxed.extend_from_slice(&sealed);

    // 4. Claim it.
    let body = serde_json::json!({
        "session_id": session_id,
        "client_public_key": base64_url_encode(&client_public),
        "sealed_registration": base64_url_encode(&boxed),
        "want_direct_route": true,
    })
    .to_string();
    let claimed = post(&format!("http://{base}/pair/v1/claim"), &body)?;
    let claimed: serde_json::Value = serde_json::from_str(&claimed)
        .map_err(|error| format!("claim 不是 JSON: {claimed} ({error})"))?;
    let agent_id = claimed
        .get("agent_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| format!("claim 缺少 agent_id: {claimed}"))?
        .to_owned();
    println!("配对成功，agent {agent_id}");
    println!("配对密钥 {vowlan_secret}");
    println!();

    // 5. Talk to it exactly as the app does, and check what the app checks.
    let mut failures = Vec::new();
    let (status, body, nonce) = signed_get(base, &vowlan_secret_bytes, "/v1/health")?;
    println!("/v1/health -> {status}");
    let health: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    match health
        .get("identity_proof")
        .and_then(|value| value.as_str())
    {
        // The proof must be a MAC this same key can reproduce, over the nonce of
        // this request: a proof of the wrong shape passes JSON decoding and then
        // fails the app's check, which is the failure mode this guards.
        Some(proof) => {
            let expected = hmac_base64_url(
                &vowlan_secret_bytes,
                &format!("AIRSIM-HEALTH1\n{nonce}\n{agent_id}"),
            );
            if proof == expected {
                println!("  identity_proof 校验通过");
            } else {
                failures.push("identity_proof 与本端计算的 MAC 不一致".to_owned());
            }
        }
        None => failures.push("/v1/health 缺少 identity_proof".to_owned()),
    }
    for field in [
        "agent_id",
        "agent_kind",
        "device_name",
        "canonical_call_ids",
    ] {
        if health.get(field).is_none() {
            failures.push(format!("/v1/health 缺少 {field}"));
        }
    }

    for path in [
        "/api/health",
        "/api/status",
        "/api/calls/status",
        "/api/calls/events",
        "/api/events",
        "/api/sim/identity",
        "/api/sms",
        "/api/sms/status",
    ] {
        match signed_get(base, &vowlan_secret_bytes, path) {
            Ok((status, body, _)) => {
                println!("{path} -> {status}");
                if status != 200 {
                    failures.push(format!("{path} 返回 {status}: {body}"));
                    continue;
                }
                match serde_json::from_str::<serde_json::Value>(&body) {
                    Ok(json) => {
                        if path == "/api/health" && !json["version"].is_string() {
                            failures.push("/api/health 的 version 不是字符串".to_owned());
                        }
                        if path == "/api/events" && !json["call"].is_object() {
                            failures.push("/api/events 缺少嵌套的 call".to_owned());
                        }
                        if path == "/api/calls/status" && !json["polling"].is_boolean() {
                            failures.push("/api/calls/status 缺少 polling".to_owned());
                        }
                    }
                    Err(error) => failures.push(format!("{path} 的响应不是 JSON: {error}")),
                }
            }
            Err(error) => failures.push(format!("{path}: {error}")),
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n  "))
    }
}

fn signed_get(base: &str, secret: &[u8], path: &str) -> Result<(u16, String, String), String> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0);
    let mut nonce_bytes = [0_u8; 16];
    getrandom::fill(&mut nonce_bytes).map_err(|error| format!("随机数不可用: {error}"))?;
    let nonce = base64_url_encode(&nonce_bytes);
    let canonical = format!("GET\n{path}\n{}\n{timestamp}\n{nonce}", sha256_hex(b""));
    let signature = hmac_base64_url(secret, &canonical);
    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: {base}\r\nX-AirSIM-VoWLAN-Version: 1\r\nX-AirSIM-VoWLAN-Timestamp: {timestamp}\r\nX-AirSIM-VoWLAN-Nonce: {nonce}\r\nX-AirSIM-VoWLAN-Signature: {signature}\r\nConnection: close\r\n\r\n"
    );
    let (status, body) = exchange(base, &mut request)?;
    Ok((status, body, nonce))
}

fn get(url: &str) -> Result<String, String> {
    let base = url
        .strip_prefix("http://")
        .and_then(|rest| rest.split('/').next())
        .ok_or("bad url")?;
    let path = &url[url.find(base).unwrap() + base.len()..];
    let mut request = format!("GET {path} HTTP/1.1\r\nHost: {base}\r\nConnection: close\r\n\r\n");
    exchange(base, &mut request).map(|(_, body)| body)
}

fn post(url: &str, body: &str) -> Result<String, String> {
    let base = url
        .strip_prefix("http://")
        .and_then(|rest| rest.split('/').next())
        .ok_or("bad url")?;
    let path = &url[url.find(base).unwrap() + base.len()..];
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: {base}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    exchange(base, &mut request).map(|(_, body)| body)
}

fn exchange(host_port: &str, request: &mut String) -> Result<(u16, String), String> {
    let mut stream =
        TcpStream::connect(host_port).map_err(|error| format!("连接 {host_port}: {error}"))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(15)))
        .ok();
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("发送: {error}"))?;
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|error| format!("读取: {error}"))?;
    let text = String::from_utf8_lossy(&raw).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    Ok((status, body))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn hmac_base64_url(secret: &[u8], message: &str) -> String {
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(message.as_bytes());
    base64_url_encode(&mac.finalize().into_bytes())
}
