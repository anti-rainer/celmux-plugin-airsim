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
