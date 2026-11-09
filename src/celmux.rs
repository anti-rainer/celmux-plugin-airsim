// Copyright (c) 2026 anti-rainer
// SPDX-License-Identifier: MIT

//! The Celmux side of the bridge.
//!
//! This plugin holds no card state. Every question about lines, calls and
//! messages is answered by Celmux, which is the only process that knows how a
//! subscriber is currently reachable. The token it authenticates with was
//! minted at install time and is presented as `Authorization: Bearer` on the
//! plugin-scoped routes - the plugin has no password and never logs in.

use serde::Deserialize;
use serde_json::Value;

pub struct Client {
    base: String,
    token: String,
    plugin_id: String,
}

/// One line as Celmux reports it.
///
/// The AirSIM client thinks in "devices"; Celmux thinks in lines, because one
/// device can carry several subscribers under N-standby. A line is what the
/// phone actually dials, so a line is what gets advertised.
#[derive(Debug, Clone, Deserialize)]
pub struct Line {
    pub line_id: String,
    /// Which module carries this line. The card joins it to the device row to
    /// show which module and SIM are behind the line.
    #[serde(default)]
    pub device_id: String,
    pub device_name: String,
    #[serde(default)]
    pub profile_name: String,
    /// Who operates the line; what the phone shows under the device name.
    #[serde(default)]
    pub operator_name: String,
    #[serde(default)]
    pub local_phone: String,
    #[serde(default)]
    pub voice_route: String,
    #[serde(default)]
    pub online: bool,
    #[serde(default)]
    pub n_standby: bool,
}

impl Line {
    /// Whether this line can carry a call or a message at all.
    ///
    /// A module in N-standby still reports its own bare line alongside the
    /// Profile lines, but that bare line has no card of its own to use: the
    /// cards belong to the Profiles. Offering it would put an entry in the
    /// phone's list that can never place a call.
    /// A bare module line is the fallback Celmux reports for the module itself,
    /// as opposed to a line backed by one Profile card.
    pub fn is_bare(&self) -> bool {
        self.profile_name.is_empty() && !self.line_id.contains('#')
    }

    /// Whether this line can carry a call or a message right now.
    ///
    /// Two things disqualify a line and they are independent. A bare line on a
    /// module that also reports Profiles cannot select a card. And any line
    /// whose voice route Celmux reports as unavailable has nothing to dial
    /// through - that is what the module in N-standby shows for its own bare
    /// line, because the voice route belongs to the Profiles.
    pub fn usable(&self) -> bool {
        self.voice_route != "unavailable"
    }

    /// What the phone shows for this line: device, operator and number.
    ///
    /// One shape for every line, whether or not the module is in N-standby:
    /// the phone lists these side by side, and two naming schemes would look
    /// like two different kinds of thing. An absent part is left out rather than
    /// shown as an empty separator.
    pub fn card_name(&self) -> String {
        let operator = if self.operator_name.is_empty() {
            self.profile_name.as_str()
        } else {
            self.operator_name.as_str()
        };
        [self.device_name.as_str(), operator, self.local_phone.as_str()]
            .into_iter()
            .filter(|part| !part.trim().is_empty())
            .collect::<Vec<&str>>()
            .join(" · ")
    }
}

/// One module as Celmux reports it, reduced to what a line card shows.
#[derive(Debug, Clone, Deserialize)]
pub struct Device {
    pub id: String,
    /// Whether the module answers on its control channel.
    #[serde(default)]
    pub running: bool,
    /// `vocall`, `qmi_voice` or `unavailable`.
    #[serde(default)]
    pub voice_route: String,
    /// Why the route is what it is, in Celmux's own words.
    #[serde(default)]
    pub voice_route_reason: String,
    #[serde(default)]
    pub vowifi_n_standby_active: bool,
    #[serde(default)]
    pub vowifi_n_standby_online: usize,
    #[serde(default)]
    pub vowifi_n_standby_total: usize,
    #[serde(default)]
    pub vowifi_active: bool,
    #[serde(default)]
    pub network_enabled: bool,
    /// The module's own voice-over-USB stack rather than a SIP call.
    #[serde(default)]
    pub at_module_ims: bool,
    #[serde(default)]
    pub modem: Option<Modem>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Modem {
    #[serde(default)]
    pub iccid: Option<String>,
    #[serde(default)]
    pub imsi: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub registration_state_text: Option<String>,
    #[serde(default)]
    pub signal_dbm: Option<i32>,
}

#[derive(Debug)]
pub enum Error {
    Transport(String),
    Status { status: u16, body: String },
    Decode(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(reason) => write!(formatter, "无法连接 Celmux: {reason}"),
            Self::Status { status, body } => {
                write!(formatter, "Celmux 返回 {status}: {body}")
            }
            Self::Decode(reason) => write!(formatter, "无法解析 Celmux 响应: {reason}"),
        }
    }
}

impl Client {
    pub fn new(base: String, token: String, plugin_id: String) -> Self {
        Self {
            base,
            token,
            plugin_id,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/api/plugin-api/{}{}", self.base, self.plugin_id, path)
    }

    fn request(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value, Error> {
        let url = self.url(path);
        let parsed = split_url(&url)?;
        let payload = body
            .map(|value| value.to_string().into_bytes())
            .unwrap_or_default();
        let head = format!(
            "{method} {target} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\n\
             Content-Type: application/json\r\nContent-Length: {length}\r\n\
             Connection: close\r\n\r\n",
            target = parsed.target,
            host = parsed.host,
            token = self.token,
            length = payload.len()
        );
        let mut stream = std::net::TcpStream::connect((parsed.host.as_str(), parsed.port))
            .map_err(|error| Error::Transport(error.to_string()))?;
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(20)));
        let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(20)));
        {
            use std::io::Write;
            stream
                .write_all(head.as_bytes())
                .and_then(|()| stream.write_all(&payload))
                .map_err(|error| Error::Transport(error.to_string()))?;
            stream.flush().ok();
        }
        let (status, raw) = read_http(&mut stream)?;
        let value: Value =
            serde_json::from_slice(&raw).map_err(|error| Error::Decode(error.to_string()))?;
        if !(200..300).contains(&status) {
            return Err(Error::Status {
                status,
                body: value
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
            });
        }
        Ok(value)
    }

    pub fn lines(&self) -> Result<Vec<Line>, Error> {
        let value = self.request("GET", "/lines", None)?;
        let lines = value
            .get("lines")
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new()));
        serde_json::from_value(lines).map_err(|error| Error::Decode(error.to_string()))
    }

    /// Read the configuration Celmux resolved for this plugin. Used at startup
    /// to confirm the token works before advertising anything.
    pub fn config(&self) -> Result<Value, Error> {
        self.request("GET", "/config", None)
    }

    pub fn dial(&self, line_id: &str, number: &str) -> Result<Value, Error> {
        self.request(
            "POST",
            "/dial",
            Some(serde_json::json!({"line_id": line_id, "number": number})),
        )
    }

    pub fn call_action(&self, action: &str, call_id: &str) -> Result<Value, Error> {
        self.request(
            "POST",
            &format!("/{action}"),
            Some(serde_json::json!({"call_id": call_id})),
        )
    }

    pub fn calls(&self) -> Result<Value, Error> {
        self.request("GET", "/calls", None)
    }

    /// Subscribe to the events Celmux pushes.
    ///    /// One connection, held open, one JSON object per line. Celmux owns this
    /// direction: an incoming call or a received message happens while the phone
    /// is not asking, so the plugin has to be told rather than ask.
    ///
    /// The response is `Transfer-Encoding: chunked` and never ends, so the body
    /// has to be decoded chunk by chunk: reading it line by line would hand the
    /// JSON parser the chunk-size line instead of the frame.
    pub fn subscribe<F>(&self, mut on_event: F) -> Result<(), Error>
    where
        F: FnMut(&Value),
    {
        let url = self.url("/events");
        let parsed = split_url(&url)?;
        let head = format!(
            "GET {target} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\n\
             Accept: application/x-ndjson\r\nConnection: keep-alive\r\n\r\n",
            target = parsed.target,
            host = parsed.host,
            token = self.token,
        );
        let mut stream = std::net::TcpStream::connect((parsed.host.as_str(), parsed.port))
            .map_err(|error| Error::Transport(error.to_string()))?;
        // No read timeout: this connection is supposed to sit idle for long
        // stretches, and a timeout would look like a disconnect whenever nothing
        // happened.
        let _ = stream.set_read_timeout(None);
        {
            use std::io::Write;
            stream
                .write_all(head.as_bytes())
                .map_err(|error| Error::Transport(error.to_string()))?;
            stream.flush().ok();
        }
        use std::io::BufRead;
        let mut reader = std::io::BufReader::new(stream);
        // The status line is checked before anything else: a refused stream would
        // otherwise look like an endless run of unparseable frames.
        let mut status_line = String::new();
        if reader
            .read_line(&mut status_line)
            .map_err(|error| Error::Transport(error.to_string()))?
            == 0
        {
            return Err(Error::Transport("事件流没有响应".to_owned()));
        }
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        if !(200..300).contains(&status) {
            return Err(Error::Transport(format!(
                "事件流被拒绝: {}",
                status_line.trim()
            )));
        }
        let mut chunked = false;
        loop {
            let mut line = String::new();
            if reader
                .read_line(&mut line)
                .map_err(|error| Error::Transport(error.to_string()))?
                == 0
            {
                return Err(Error::Transport("事件流响应头不完整".to_owned()));
            }
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                break;
            }
            if let Some((name, value)) = trimmed.split_once(':')
                && name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
        }
        // Frames accumulate here and are dispatched on whole lines: a chunk may
        // split a JSON object in the middle, and a frame may span two chunks.
        let mut pending = Vec::new();
        loop {
            if chunked && !read_chunk(&mut reader, &mut pending)? {
                return Ok(());
            }
            if !chunked {
                // No chunking: the body is the frames, read as it arrives.
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => return Ok(()),
                    Ok(_) => pending.extend_from_slice(line.as_bytes()),
                    Err(error) => return Err(Error::Transport(error.to_string())),
                }
            }
            while let Some(index) = pending.iter().position(|byte| *byte == b'\n') {
                let line: Vec<u8> = pending.drain(..=index).collect();
                let text = String::from_utf8_lossy(&line);
                let trimmed = text.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
                    on_event(&value);
                }
            }
        }
    }

    /// The state a plugin that just (re)connected has missed.
    ///
    /// The push stream only carries what happens while it is open, so a plugin
    /// that started a moment ago would otherwise wait for the next call before
    /// knowing one is already ringing.
    pub fn events_snapshot(&self) -> Result<Value, Error> {
        self.request("GET", "/events/once", None)
    }

    /// Recent messages for one line, newest first.
    ///
    /// Celmux holds every line's messages; this asks for its own. The phone is
    /// that line's phone, so a conversation it cannot answer from here is not
    /// its business - and handing it another line's messages would attribute
    /// that number to this device.
    pub fn messages(&self, line_id: &str) -> Result<Value, Error> {
        // The line is named the way Celmux names lines everywhere: `module` for
        // a device's own line, `module#iccid` for one Profile on it. Celmux
        // resolves the card from that label itself, so nothing is guessed here.
        let encoded = percent_encode(line_id);
        self.request("GET", &format!("/sms?line={encoded}"), None)
    }


    /// Send one message on one line.
    pub fn send_sms(&self, line_id: &str, to: &str, text: &str) -> Result<Value, Error> {
        // Celmux's names, not the phone's: it wants `number` and `content` for a
        // message, where the app says `phone` and `message`. Sending the app's
        // words through unchanged is rejected with a missing-field error that
        // names neither the field nor the caller.
        self.request(
            "POST",
            "/sms",
            Some(serde_json::json!({
                "line_id": line_id,
                "number": to,
                "content": text,
            })),
        )
    }

    /// What the phone's line card shows about the module and the card.
    ///
    /// Read from Celmux's device list, which is the only place that knows a
    /// module's registration state and a card's operator at the same time.
    pub fn devices(&self) -> Result<Vec<Device>, Error> {
        let value = self.request("GET", "/devices", None)?;
        let devices = value
            .get("devices")
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new()));
        serde_json::from_value(devices).map_err(|error| Error::Decode(error.to_string()))
    }

    /// Pull the carrier's next block: signed 16-bit LE mono, base64 encoded.
    ///
    /// An empty `samples` is not an error - the carrier produces audio on its
    /// own clock, so "nothing yet" is the normal answer for a poll that comes
    /// between two blocks.
    pub fn pull_audio(&self, call_id: u64) -> Result<Option<Vec<u8>>, Error> {
        let value = self.request("GET", &format!("/audio?call_id={call_id}"), None)?;
        let encoded = value.get("samples").and_then(Value::as_str).unwrap_or("");
        if encoded.is_empty() {
            return Ok(None);
        }
        crate::config::base64_url_decode(encoded)
            .map(Some)
            .ok_or_else(|| Error::Decode("音频帧不是有效的 base64".to_owned()))
    }

    /// Send captured audio to the caller. Celmux resamples to the carrier's own
    /// clock, so 8 kHz mono is accepted for every carrier codec.
    pub fn push_audio(&self, call_id: u64, samples: &[u8]) -> Result<(), Error> {
        self.request(
            "POST",
            &format!("/audio?call_id={call_id}"),
            Some(serde_json::json!({
                "samples": crate::config::base64_url_encode(samples),
                "sample_rate": crate::pcm::SAMPLE_RATE,
            })),
        )
        .map(|_| ())
    }

    /// The call the bridge is currently carrying, if any.
    ///
    /// The PCM gateway is opened by the phone separately from the control
    /// request that answered a call, so it has to learn which call it belongs
    /// to. Calling the call list is enough: a plugin carries one call at a time
    /// and the active one is the only call in a talking state.
    pub fn active_call_id(&self, line_id: &str) -> Option<u64> {
        let value = self.calls().ok()?;
        value
            .get("calls")
            .and_then(Value::as_array)?
            .iter()
            .find_map(|call| {
                // Scoped to this agent's line: two agents bridge two calls at
                // once, and each has to pick its own.
                if call.get("line_id").and_then(Value::as_str) != Some(line_id) {
                    return None;
                }
                let state = call.get("state").and_then(Value::as_str)?;
                if !matches!(state, "active" | "connected" | "talking") {
                    return None;
                }
                call.get("call_id").and_then(Value::as_u64).or_else(|| {
                    call.get("call_id")
                        .and_then(Value::as_str)
                        .and_then(|text| text.parse().ok())
                })
            })
    }

    /// Whether `call_id` is still the active call.
    ///
    /// Passing `None` asks "is there any active call", which is what the gateway
    /// needs before it knows its own id.
    pub fn call_still_active(&self, line_id: &str, call_id: Option<u64>) -> bool {
        match (self.active_call_id(line_id), call_id) {
            (Some(active), Some(expected)) => active == expected,
            (Some(_), None) => true,
            (None, _) => false,
        }
    }
}

#[derive(Debug)]
pub struct ParsedUrl {
    pub host: String,
    pub port: u16,
    pub target: String,
}

/// Split an absolute URL into host, port, request target and scheme.
fn split_url(url: &str) -> Result<ParsedUrl, Error> {
    // Plain HTTP: this talks to Celmux over loopback, which is a host-local
    // hop, not a network one. Celmux's listener accepts both plaintext and TLS
    // on the same port, and the plugin-scoped API is reached the direct way
    // rather than through the browser's TLS path.
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| Error::Transport(format!("只支持 http:// 地址: {url}")))?;
    let (authority, target) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (
            host.to_owned(),
            port.parse()
                .map_err(|_| Error::Transport(format!("端口无效: {authority}")))?,
        ),
        None => (authority.to_owned(), 80),
    };
    if host.is_empty() {
        return Err(Error::Transport(format!("地址缺少主机名: {url}")));
    }
    Ok(ParsedUrl {
        host,
        port,
        target: target.to_owned(),
    })
}

/// Read one HTTP response with `Connection: close` semantics.
/// Read one `Transfer-Encoding: chunked` chunk into `out`.
///
/// Returns `false` at the terminating zero-length chunk. The sizes are hex, and a
/// chunk's trailing CRLF is part of the framing rather than the payload, so it is
/// consumed here and never reaches the JSON parser.
fn read_chunk(
    reader: &mut impl std::io::BufRead,
    out: &mut Vec<u8>,
) -> Result<bool, Error> {
    let mut size_line = String::new();
    if reader
        .read_line(&mut size_line)
        .map_err(|error| Error::Transport(error.to_string()))?
        == 0
    {
        return Ok(false);
    }
    // A chunk size may carry an extension after a semicolon; it is not part of
    // the length.
    let size_text = size_line.trim().split(';').next().unwrap_or("").trim();
    if size_text.is_empty() {
        // A blank line between chunks is framing noise, not the end of the body.
        return Ok(true);
    }
    let size = usize::from_str_radix(size_text, 16)
        .map_err(|_| Error::Transport(format!("分块长度无效: {size_text}")))?;
    if size == 0 {
        // Consume the trailer and the blank line that follows it.
        loop {
            let mut trailer = String::new();
            if reader
                .read_line(&mut trailer)
                .map_err(|error| Error::Transport(error.to_string()))?
                == 0
            {
                return Ok(false);
            }
            if trailer.trim().is_empty() {
                return Ok(false);
            }
        }
    }
    let mut chunk = vec![0_u8; size];
    reader
        .read_exact(&mut chunk)
        .map_err(|error| Error::Transport(error.to_string()))?;
    out.extend_from_slice(&chunk);
    // The CRLF after the payload.
    let mut crlf = String::new();
    let _ = reader.read_line(&mut crlf);
    Ok(true)
}

/// Percent-encode a value for a query string.
///
/// A line label can carry `#` (a Profile line is `module#iccid`), and an
/// unencoded `#` would truncate the query at the fragment, silently asking
/// Celmux for the module's line instead of the Profile's.
fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(char::from(*byte));
            }
            other => encoded.push_str(&format!("%{other:02X}")),
        }
    }
    encoded
}

fn read_http(stream: &mut dyn std::io::Read) -> Result<(u16, Vec<u8>), Error> {
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|error| Error::Transport(error.to_string()))?;
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| Error::Decode("响应没有头部结束标记".to_owned()))?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| Error::Decode("响应没有状态码".to_owned()))?;
    Ok((status, raw[split + 4..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Celmux answers a stream with `Transfer-Encoding: chunked`, so the frames
    /// arrive wrapped in hex sizes. Reading them as plain lines hands the JSON
    /// parser the size line instead of the frame - which is a silent stall, not a
    /// visible error.
    #[test]
    fn a_chunked_stream_is_decoded_into_frames() {
        let first = "{\"event\":\"call\",\"payload\":1}\n";
        let second = "{\"event\":\"sms\",\"payload\":22}\n";
        // The sizes are computed rather than written out, so the fixture cannot
        // drift from what it claims to contain.
        let input = format!(
            "{:x}\r\n{first}\r\n{:x}\r\n{second}\r\n0\r\n\r\n",
            first.len(),
            second.len()
        );
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        while read_chunk(&mut reader, &mut out).unwrap() {}
        let text = String::from_utf8(out).unwrap();
        let frames: Vec<&str> = text.lines().filter(|line| !line.is_empty()).collect();
        assert_eq!(frames.len(), 2);
        assert!(frames[0].contains("\"call\""));
        assert!(frames[1].contains("\"sms\""));
    }

    /// A frame split across two chunks must still come out whole: the network
    /// chooses where a chunk ends, not the writer.
    #[test]
    fn a_frame_split_across_chunks_is_reassembled() {
        let first = "{\"event\":\"ca";
        let second = "ll\"}\n";
        let input = format!(
            "{:x}\r\n{first}\r\n{:x}\r\n{second}\r\n0\r\n\r\n",
            first.len(),
            second.len()
        );
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        while read_chunk(&mut reader, &mut out).unwrap() {}
        assert_eq!(String::from_utf8(out).unwrap(), "{\"event\":\"call\"}\n");
    }

    #[test]
    fn a_url_splits_into_host_port_and_target() {
        let url = split_url("http://127.0.0.1:8080/api/plugin-api/airsim/lines").unwrap();
        assert_eq!(url.host, "127.0.0.1");
        assert_eq!(url.port, 8080);
        assert_eq!(url.target, "/api/plugin-api/airsim/lines");
    }

    #[test]
    fn a_url_without_a_port_uses_eighty() {
        let url = split_url("http://celmux.local/api/x").unwrap();
        assert_eq!(url.host, "celmux.local");
        assert_eq!(url.port, 80);
        assert_eq!(url.target, "/api/x");
    }

    /// The plugin reaches Celmux over loopback on a plain socket: Celmux's
    /// listener accepts both plaintext and TLS on the same port, and the
    /// plugin-scoped API is not the browser's TLS path.
    #[test]
    fn an_https_url_is_refused_with_a_reason() {
        let error = split_url("https://127.0.0.1/api/x").unwrap_err();
        assert!(error.to_string().contains("http://"));
    }

    #[test]
    fn a_url_without_a_scheme_is_refused_with_a_reason() {
        let error = split_url("ftp://127.0.0.1/x").unwrap_err();
        assert!(error.to_string().contains("http"));
    }

    /// The line shape is the contract with Celmux's `/lines` route. A row with
    /// only the required fields has to decode, because Celmux omits empty ones.
    #[test]
    fn a_line_row_decodes_with_only_its_required_fields() {
        let line: Line =
            serde_json::from_str(r#"{"line_id":"d1","device_id":"d1","device_name":"读卡器1"}"#)
                .unwrap();
        assert_eq!(line.line_id, "d1");
        assert_eq!(line.operator_name, "");
        assert!(!line.online);
    }

    #[test]
    fn a_full_line_row_decodes_its_profile_fields() {
        let line: Line = serde_json::from_str(
            r#"{"line_id":"d1#89049","device_id":"d1","device_name":"dji1",
                "iccid":"89049","profile_name":"Globe","operator_name":"Globe",
                "local_phone":"+63917","voice_route":"vocall","online":true,
                "n_standby":true}"#,
        )
        .unwrap();
        assert_eq!(line.operator_name, "Globe");
        assert!(line.online);
        assert!(line.n_standby);
    }
}
