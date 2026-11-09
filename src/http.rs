// Copyright (c) 2026 anti-rainer
// SPDX-License-Identifier: MIT

//! A deliberately small HTTP/1.1 server.
//!
//! The control API is a handful of JSON endpoints a phone calls on a LAN, so
//! pulling in a full framework would cost more in binary size and build time
//! than it saves. What this has to get right is request framing: read the head,
//! read exactly `Content-Length` bytes, answer, and close. No keep-alive, no
//! chunked encoding, no pipelining - none of which the client uses.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

/// The largest body this accepts. The control API takes small JSON documents;
/// anything larger is a mistake or an attempt to exhaust memory.
const MAX_BODY: usize = 256 * 1024;

pub struct Request {
    pub method: String,
    /// Path without the query string.
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

pub struct Response {
    pub status: u16,
    pub reason: &'static str,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl Response {
    pub fn json(status: u16, reason: &'static str, body: serde_json::Value) -> Self {
        Self {
            status,
            reason,
            content_type: "application/json",
            body: body.to_string().into_bytes(),
        }
    }

    pub fn ok(body: serde_json::Value) -> Self {
        Self::json(200, "OK", body)
    }

    pub fn error(status: u16, reason: &'static str, code: &str, message: &str) -> Self {
        Self::json(
            status,
            reason,
            serde_json::json!({"ok": false, "code": code, "message": message}),
        )
    }
}

#[derive(Debug)]
pub enum ReadError {
    Io,
    Malformed,
    TooLarge,
}

/// Accept connections until the listener is closed.
pub fn serve(listener: TcpListener, handler: Arc<dyn Fn(Request) -> Response + Send + Sync>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let handler = Arc::clone(&handler);
        // One thread per connection: a phone makes one call at a time, and a
        // hung client must not block the listener.
        std::thread::spawn(move || {
            let _ = handle_connection(stream, handler);
        });
    }
}

fn handle_connection(
    stream: TcpStream,
    handler: Arc<dyn Fn(Request) -> Response + Send + Sync>,
) -> std::io::Result<()> {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(15)));
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(15)));
    let mut writer = stream.try_clone()?;
    let response = match read_request(stream) {
        Ok(request) => handler(request),
        Err(ReadError::TooLarge) => {
            Response::error(413, "Payload Too Large", "too_large", "请求体过大")
        }
        Err(_) => Response::error(400, "Bad Request", "malformed", "请求格式错误"),
    };
    write_response(&mut writer, response)
}

pub fn read_request(stream: TcpStream) -> Result<Request, ReadError> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader
        .read_line(&mut request_line)
        .map_err(|_| ReadError::Io)?
        == 0
    {
        return Err(ReadError::Io);
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or(ReadError::Malformed)?.to_owned();
    let target = parts.next().ok_or(ReadError::Malformed)?.to_owned();
    // The query string is dropped: no route this serves reads one, and a caller
    // that appended one would only be matching against a path it did not mean.
    let path = target
        .split_once('?')
        .map_or(target.clone(), |(path, _)| path.to_owned());
    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).map_err(|_| ReadError::Io)? == 0 {
            return Err(ReadError::Malformed);
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        // A header count bound: a client sending thousands of headers is not
        // the AirSIM app.
        if headers.len() > 64 {
            return Err(ReadError::TooLarge);
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let length: usize = headers
        .get("content-length")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    if length > MAX_BODY {
        return Err(ReadError::TooLarge);
    }
    let mut body = vec![0_u8; length];
    if length > 0 {
        reader.read_exact(&mut body).map_err(|_| ReadError::Io)?;
    }
    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

fn write_response(stream: &mut TcpStream, response: Response) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        response.reason,
        response.content_type,
        response.body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&response.body)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// Feed a raw request through the real parser over a socket, because the
    /// interesting failures are in framing rather than in the parsing helpers.
    fn parse(raw: &[u8]) -> Result<Request, ReadError> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|_| ReadError::Io)?;
        let address = listener.local_addr().map_err(|_| ReadError::Io)?;
        let payload = raw.to_vec();
        let writer = std::thread::spawn(move || {
            let mut client = TcpStream::connect(address).expect("connect");
            let _ = client.write_all(&payload);
        });
        let (stream, _) = listener.accept().map_err(|_| ReadError::Io)?;
        let result = read_request(stream);
        let _ = writer.join();
        result
    }

    /// A query string is dropped rather than matched against: no route this
    /// serves reads one.
    #[test]
    fn a_request_drops_its_query_from_the_path() {
        let request = parse(b"GET /v1/health?x=1 HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/v1/health");
        assert!(request.body.is_empty());
    }

    #[test]
    fn header_names_are_case_insensitive() {
        let request =
            parse(b"GET /v1/health HTTP/1.1\r\nX-AirSim-VoWLAN-Nonce: abc\r\n\r\n").unwrap();
        assert_eq!(
            request
                .headers
                .get("x-airsim-vowlan-nonce")
                .map(String::as_str),
            Some("abc")
        );
    }

    /// The body must be exactly Content-Length bytes: a short body would leave
    /// the digest covering less than the client signed.
    #[test]
    fn the_body_is_read_to_its_declared_length() {
        let request =
            parse(b"POST /v2/commands/enqueue HTTP/1.1\r\nContent-Length: 7\r\n\r\n{\"a\":1}")
                .unwrap();
        assert_eq!(request.body, b"{\"a\":1}");
    }

    #[test]
    fn a_body_over_the_cap_is_refused_before_it_is_read() {
        let raw = format!(
            "POST /v2/commands/enqueue HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        assert!(matches!(parse(raw.as_bytes()), Err(ReadError::TooLarge)));
    }

    #[test]
    fn a_request_line_without_a_target_is_malformed() {
        assert!(matches!(parse(b"GET\r\n\r\n"), Err(ReadError::Malformed)));
    }
}
