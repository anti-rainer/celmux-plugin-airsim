// Copyright (c) 2026 anti-rainer
// SPDX-License-Identifier: MIT

//! The two things talking to APNs needs and std does not have: an HTTP/2 client
//! over TLS, and an ES256 signature.
//!
//! Both are deliberately small. The plugin is otherwise synchronous - every other
//! socket in it is a blocking `TcpStream` - so rather than turn the whole process
//! async, each push spins up a single-threaded runtime, does its one request, and
//! lets the runtime die. A push happens when a call arrives, not in a loop, so the
//! cost of standing a runtime up is paid a few times an hour at most and buys a
//! much smaller surface than threading async through the rest of the plugin.
//!
//! HTTP/2 is not a choice here: Apple answers HTTP/1.1 with a protocol error, so
//! `h2` and its runtime are the price of the feature.

use std::sync::Arc;

use serde_json::Value;

use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use p256::pkcs8::DecodePrivateKey;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;

/// What APNs answered.
pub struct Response {
    pub status: u16,
    /// The response body, which for a rejection is `{"reason": "..."}`.
    pub body: Vec<u8>,
    /// The `apns-id` header, for correlating with Apple's own logs.
    pub apns_id: String,
}

/// Send one request to an APNs host.
///
/// Blocking by design: the caller is a thread that wants an answer before it
/// returns, and there is no other work for it to do meanwhile.
pub fn post(
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<Response, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("无法创建运行时: {error}"))?;
    runtime.block_on(post_async(host, path, headers, body))
}

async fn post_async(
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<Response, String> {
    let tls = Arc::new(tls_config()?);
    let server_name =
        ServerName::try_from(host.to_owned()).map_err(|error| format!("主机名无效: {error}"))?;
    let tcp = tokio::net::TcpStream::connect((host, 443))
        .await
        .map_err(|error| format!("无法连接 {host}: {error}"))?;
    // Nagle would add up to 40 ms to a push whose whole point is arriving now.
    let _ = tcp.set_nodelay(true);
    let connector = tokio_rustls::TlsConnector::from(tls);
    let stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|error| format!("TLS 握手失败: {error}"))?;

    // `h2` wants an `AsyncRead + AsyncWrite` that it owns; the connection future
    // must be driven concurrently with the request, so it is spawned.
    let (mut client, connection) = h2::client::handshake(stream)
        .await
        .map_err(|error| format!("HTTP/2 握手失败: {error}"))?;
    tokio::spawn(async move {
        // The error is not actionable here: every request reports its own failure,
        // and the connection dying only means the next push dials again.
        let _ = connection.await;
    });

    let mut request = http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("https://{host}{path}"))
        .body(())
        .map_err(|error| format!("无法构造请求: {error}"))?;
    for (name, value) in headers {
        request.headers_mut().insert(
            http::header::HeaderName::try_from(*name)
                .map_err(|error| format!("请求头名无效 {name}: {error}"))?,
            http::header::HeaderValue::try_from(*value)
                .map_err(|error| format!("请求头值无效: {error}"))?,
        );
    }
    let (response, mut send) = client
        .send_request(request, false)
        .map_err(|error| format!("无法发送请求: {error}"))?;
    send.send_data(bytes::Bytes::copy_from_slice(body), true)
        .map_err(|error| format!("无法发送正文: {error}"))?;

    let response = response
        .await
        .map_err(|error| format!("未收到响应: {error}"))?;
    let status = response.status().as_u16();
    let apns_id = response
        .headers()
        .get("apns-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let mut body_stream = response.into_body();
    let mut collected = Vec::new();
    while let Some(chunk) = body_stream.data().await {
        let chunk = chunk.map_err(|error| format!("读取响应失败: {error}"))?;
        collected.extend_from_slice(&chunk);
        let _ = body_stream.flow_control().release_capacity(chunk.len());
    }
    Ok(Response {
        status,
        body: collected,
        apns_id,
    })
}

/// Post JSON to an arbitrary URL over HTTP/1.1.
///
/// Separate from [`post`], which is HTTP/2 because APNs requires it. A relay may
/// be either an ordinary HTTPS endpoint or a plain-HTTP loopback port, and
/// standing a TLS stack up to talk to this process's own listener would be work
/// for nothing - so that case does not use a socket at all.
pub fn post_json(url: &str, body: &Value) -> Result<crate::relay_agent::Reply, String> {
    // HTTPS only, with no exception for loopback. The body carries the phone's
    // `device_secret`, and a plaintext path would exist only so this process could
    // talk to itself - which it does not do: when the relay is this plugin's own,
    // the event is dispatched in-process and never becomes a socket.
    if !url.starts_with("https://") {
        return Err(format!("relay 地址必须是 https://: {url}"));
    }
    let payload = serde_json::to_vec(body).map_err(|error| error.to_string())?;
    let text = post_https_1(url, &payload)?;
    let body = if text.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).unwrap_or(Value::String(text))
    };
    Ok(crate::relay_agent::Reply { status: 200, body })
}

/// An HTTPS POST over HTTP/1.1, for an external relay.
fn post_https_1(url: &str, payload: &[u8]) -> Result<String, String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| "不是 https 地址".to_owned())?;
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_owned()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (
            host.to_owned(),
            port.parse::<u16>().map_err(|_| "端口无效".to_owned())?,
        ),
        None => (authority.to_owned(), 443),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("无法创建运行时: {error}"))?;
    runtime.block_on(async move {
        let tls = Arc::new(tls_config()?);
        let server_name =
            ServerName::try_from(host.clone()).map_err(|error| format!("主机名无效: {error}"))?;
        let tcp = tokio::net::TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|error| format!("无法连接 relay: {error}"))?;
        let _ = tcp.set_nodelay(true);
        let stream = tokio_rustls::TlsConnector::from(tls)
            .connect(server_name, tcp)
            .await
            .map_err(|error| format!("TLS 握手失败: {error}"))?;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = stream;
        let head = format!(
            "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            payload.len()
        );
        stream
            .write_all(head.as_bytes())
            .await
            .map_err(|error| format!("发送事件失败: {error}"))?;
        stream
            .write_all(payload)
            .await
            .map_err(|error| format!("发送事件失败: {error}"))?;
        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .await
            .map_err(|error| format!("读取 relay 响应失败: {error}"))?;
        let text = String::from_utf8_lossy(&raw);
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(0);
        if !(200..300).contains(&status) {
            return Err(format!("relay 拒绝事件: HTTP {status}"));
        }
        Ok(text
            .split_once("\r\n\r\n")
            .map(|(_, body)| body.to_owned())
            .unwrap_or_default())
    })
}

/// A TLS configuration trusting the public roots.
///
/// Apple's hosts are ordinary public certificates; there is nothing to pin and no
/// private CA to trust, so the bundled webpki roots are the whole story and the
/// plugin needs no filesystem CA store.
fn tls_config() -> Result<ClientConfig, String> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    Ok(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|error| format!("TLS 版本配置失败: {error}"))?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Sign `input` with the operator's ES256 key.
///
/// The signature is the fixed 64-byte `r || s` form JWS requires, not the DER
/// encoding `p256` produces by default: Apple rejects DER with a decode error that
/// says nothing useful about the cause.
pub fn es256_sign(key_pem: &str, input: &[u8]) -> Result<Vec<u8>, String> {
    let key = SigningKey::from_pkcs8_pem(key_pem)
        .map_err(|error| format!("p8 不是有效的 EC 私钥: {error}"))?;
    let signature: Signature = key.sign(input);
    Ok(signature.to_bytes().to_vec())
}
