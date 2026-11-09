// Copyright (c) 2026 anti-rainer
// SPDX-License-Identifier: MIT

//! The control API the AirSIM client speaks.
//!
//! Every route except `/healthz` is signed. `/healthz` exists unsigned for
//! reachability probes only and discloses nothing.
//!
//! The shape here follows the client's expectations, not Celmux's: the phone
//! asks about devices and calls, so lines are projected into that vocabulary
//! rather than the phone being taught about N-standby Profiles.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::agents::Agent;
use crate::celmux::{Client, Line};
use crate::http::{Request, Response};

pub struct Control {
    pub client: Arc<Client>,
    pub agent: Arc<Agent>,
    /// What a long poll compares against: bumped whenever anything the phone
    /// cares about changes.
    pub revision: Arc<crate::revision::Revision>,
}

/// One device as the phone understands it: a thing with a name that can place
/// and receive calls.
///
/// Celmux's lines collapse into this: a device's own line is the device, and an
/// N-standby Profile is a device of its own, because that is what the phone
/// needs in order to dial one subscriber rather than another.
struct DeviceView {
    id: String,
    name: String,
    line: Line,
}

fn devices(lines: Vec<Line>) -> Vec<DeviceView> {
    lines
        .into_iter()
        .map(|line| {
            let id = line.line_id.clone();
            let name = if line.n_standby {
                // A Profile line is distinguished by its subscription, not by
                // the device it shares with its siblings.
                let operator = if line.operator_name.is_empty() {
                    line.profile_name.clone()
                } else {
                    line.operator_name.clone()
                };
                format!("{} · {}", line.device_name, operator)
            } else {
                line.device_name.clone()
            };
            DeviceView { id, name, line }
        })
        .collect()
}

/// One numeric query parameter, or `None`.
///
/// The plugin's own HTTP reader drops the query string, so long-poll parameters
/// have to be read from the raw path here.
fn query_number(query: &str, key: &str) -> Option<u64> {
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        if name == key { value.parse().ok() } else { None }
    })
}

/// The call the phone should show as active, if there is one.
///
/// Celmux reports its calls as rows; the app wants one `active` record or null.
/// An empty `active` is the normal state and must be null, not an empty object:
/// the client decodes it as an optional record and an object missing its
/// required fields fails the whole status.
fn active_call(value: &Value) -> Option<Value> {
    // Celmux answers a bare array of live calls; older shapes nested them. Both
    // are read here so a call in progress is never reported as idle.
    let calls = match value {
        Value::Array(rows) => rows,
        other => other
            .get("calls")
            .or_else(|| other.get("active"))
            .and_then(Value::as_array)?,
    };
    let row = calls.first()?;
    let number = row
        .get("number")
        .or_else(|| row.get("remote_number"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let state = row.get("state").and_then(Value::as_str).unwrap_or("active");
    let direction = row
        .get("direction")
        .and_then(Value::as_str)
        .unwrap_or("incoming");
    let started_at = row
        .get("started_at")
        .or_else(|| row.get("created_at"))
        .and_then(Value::as_str)
        .unwrap_or("1970-01-01T00:00:00Z");
    Some(super::control_api::call_record(
        number, state, direction, started_at,
    ))
}

impl Control {
    /// Route one request. `Ok` carries the response; `Err` is a request that
    /// failed authentication, which is always a 401 with no detail beyond that.
    pub fn handle(self: &Arc<Self>, request: Request) -> Response {
        // An unsigned liveness probe: the phone and any operator tooling use it
        // to tell "port closed" from "auth wrong", and it says nothing.
        if request.path == "/healthz" {
            return Response::ok(json!({"ok": true}));
        }
        // Before this agent has paired there is no secret, so nothing can be
        // verified and the only thing worth answering is the pairing exchange.
        // Read through the agent rather than a field set at startup: pairing
        // happens while this listener is already running, and a verifier fixed
        // at startup would keep the agent refusing the secret pairing just gave
        // it.
        let Some(verifier) = self.agent.verifier() else {
            if let Some(response) = crate::pair_endpoint::handle(&self.agent, &request) {
                return response;
            }
            return Response::error(
                503,
                "Service Unavailable",
                "not_paired",
                "该 agent 尚未配对，请先在 Celmux 插件设置中开始配对",
            );
        };
        let now = std::time::SystemTime::now();
        // The canonical string uses the request target as sent, query string
        // included: the app signs `api/events?after=…&timeout_ms=…` whole, so
        // verifying against the path alone rejects every parameterised request.
        let target = if request.query.is_empty() {
            request.path.clone()
        } else {
            format!("{}?{}", request.path, request.query)
        };
        if let Err(error) = verifier.verify(
            &request.method,
            &target,
            &request.body,
            &request.headers,
            now,
        ) {
            return Response::error(401, "Unauthorized", "unauthorized", &error.to_string());
        }
        match (request.method.as_str(), request.path.as_str()) {
            // iOS uses two names for the same probe. `/v1/health` is the
            // VoWLAN gateway's own identity answer; `/api/health` is the
            // agent's, and the app asks for both depending on which layer it is
            // talking to.
            // The VoWLAN identity answer and the agent's own health answer are
            // different models with different shapes: one carries
            // `identity_proof` for the route proof, the other `version` as a
            // string for the status screen. Answering both with one payload
            // makes one of the two fail to decode.
            ("GET", "/v1/health") => self.health(&request),
            ("GET", "/api/health") => self.agent_health(),
            ("GET", "/v1/devices/status") => self.device_status(),
            ("GET", "/api/status") => self.device_status(),
            ("GET", "/api/calls/status") => self.call_status(),
            ("GET", "/api/calls/events") => self.call_status(),
            ("GET", "/api/events") => self.events(&request),
            ("GET", "/api/sim/identity") => self.sim_identity(),
            ("GET", "/api/sms") => self.messages(),
            ("GET", "/api/sms/status") => self.sms_status(),
            ("POST", "/api/sms/send") => self.send_sms(&request),
            ("POST", "/api/sms/ack") => Response::ok(json!({"ok": true, "acked": 0})),
            // The app records hangs up and history locally first, then tells the
            // agent; a 404 makes it stop asking on every later launch.
            ("POST", "/api/calls/history/ack") => Response::ok(json!({"ok": true})),
            ("POST", "/api/sms/clear-module") => Response::ok(json!({"ok": true})),
            ("PATCH", "/api/sms/settings") => Response::ok(json!({"ok": true})),
            ("GET", "/api/feedback") => Response::ok(json!({"ok": true})),
            ("GET", "/api/debug") => Response::ok(json!({"ok": true, "events": []})),
            ("POST", "/api/debug/clear") => Response::ok(json!({"ok": true})),
            ("POST", "/api/sms/refresh") => self.messages(),
            ("POST", "/api/calls/dial") => self.dial(&request),
            ("POST", "/api/calls/answer") => self.call_action("answer", &request),
            ("POST", "/api/calls/reject") => self.call_action("reject", &request),
            ("POST", "/api/calls/hangup") => self.call_action("hangup", &request),
            ("POST", "/api/calls/dtmf") => self.call_action("dtmf", &request),
            ("POST", "/api/calls/audio/mute") => Response::ok(json!({"ok": true})),
            // The app reads this before opening the PCM socket. Answering 404
            // makes it treat audio as unsupported and fall back to signalling
            // only, which is a call with no sound.
            ("GET", "/api/calls/audio/host/config") => self.audio_host_config(),
            ("POST", "/v2/commands/enqueue") => self.enqueue(&request),
            (method, path) if method == "POST" && path.starts_with("/v2/calls/") => {
                self.call_action(path, &request)
            }
            _ => Response::error(404, "Not Found", "not_found", "接口不存在"),
        }
    }

    /// `GET /v1/health` — proof that this is the agent the phone paired with.
    fn health(&self, request: &Request) -> Response {
        let nonce = request
            .headers
            .get(crate::auth::HEADER_NONCE)
            .cloned()
            .unwrap_or_default();
        let agent_id = self.agent.id();
        let proof = self
            .agent
            .verifier()
            .map(|verifier| verifier.health_proof(&nonce, &agent_id))
            .unwrap_or_default();
        // The field names here are the iOS client's, not ours: it decodes
        // `identity_proof` and refuses the route without it, which is why a
        // pairing that otherwise succeeded reported an unreachable gateway.
        Response::ok(json!({
            "ok": true,
            "transport": "vowlan",
            "version": 1,
            "agent_id": agent_id,
            "identity_proof": proof,
            "agent_kind": "standalone",
            "device_name": self.agent.name(),
            "manufacturer": "Celmux",
            "model": "Celmux VoWiFi Gateway",
            // The subscriber this agent's line answers on. The phone shows it
            // under the device name and uses it to tell two lines on the same
            // module apart, so omitting it leaves the card with no number at
            // all even though pairing succeeded.
            "phone_number": self.line_phone(),
            "canonical_call_ids": true,
            "control_port": self.agent.config.control_port,
            "pcm_port": self.agent.config.pcm_port,
        }))
    }

    /// The number this agent's line answers on, empty when Celmux has not
    /// learned it yet.
    fn line_phone(&self) -> String {
        self.client
            .lines()
            .ok()
            .and_then(|lines| {
                lines
                    .into_iter()
                    .find(|line| line.line_id == self.agent.config.line_id)
            })
            .map(|line| line.local_phone)
            .unwrap_or_default()
    }

    /// `GET /api/health` — the agent's own health, which is a different model
    /// from the VoWLAN identity answer above.
    fn agent_health(&self) -> Response {
        let (state, registration) = self.cellular_state();
        Response::ok(super::control_api::agent_health(
            env!("CARGO_PKG_VERSION"),
            &state,
            &registration,
        ))
    }

    /// The module's registration state, as far as Celmux will say.
    ///
    /// Absence is reported as empty strings rather than guesses: the app shows
    /// these two verbatim, and inventing "registered" would tell the operator a
    /// line can call when it cannot.
    fn cellular_state(&self) -> (String, String) {
        let Ok(devices) = self.client.devices() else {
            return (String::new(), String::new());
        };
        let Some(device) = devices
            .iter()
            .find(|device| device.id == self.agent.config.line_id || device.id == self.agent.config.line_id.split('#').next().unwrap_or(""))
        else {
            return (String::new(), String::new());
        };
        let state = if device.running { "registered" } else { "unregistered" };
        let registration = if device.vowifi_n_standby_active || device.running {
            "home"
        } else {
            ""
        };
        (state.to_owned(), registration.to_owned())
    }

    /// `GET /v1/devices/status` — what the phone lists.
    fn device_status(&self) -> Response {
        let lines = match self.client.lines() {
            Ok(lines) => lines,
            Err(error) => {
                return Response::error(
                    502,
                    "Bad Gateway",
                    "celmux_unavailable",
                    &error.to_string(),
                );
            }
        };
        // Only this agent's line: AirSIM's model is one card per agent, and a
        // second entry would be a device the phone could dial but whose
        // identity it could never ask about.
        let devices: Vec<Value> = devices(lines)
            .into_iter()
            .filter(|device| device.line.line_id == self.agent.config.line_id)
            .map(|device| {
                json!({
                    "id": device.id,
                    "name": device.name,
                    "number": device.line.local_phone,
                    "operator": device.line.operator_name,
                    "online": device.line.online,
                    // The phone only offers a device for calling when its IMS
                    // registration is up; saying so here keeps it from dialling
                    // into a line that cannot answer.
                    "callable": device.line.online && device.line.voice_route != "unavailable",
                })
            })
            .collect();
        Response::ok(json!({"ok": true, "devices": devices}))
    }

    /// `GET /api/calls/status` and `api/calls/events`.
    ///
    /// Both answer with the same shape: the app polls one and long-polls the
    /// other, and either may be the one it asks first depending on the version
    /// it decided we are.
    fn call_status(&self) -> Response {
        let active = match self.client.calls() {
            Ok(value) => active_call(&value),
            Err(error) => {
                return Response::error(
                    502,
                    "Bad Gateway",
                    "celmux_unavailable",
                    &error.to_string(),
                );
            }
        };
        Response::ok(super::control_api::call_status(active, Vec::new()))
    }

    /// Hold Celmux's event stream open and wake the phone's poll when it fires.
    ///
    /// Celmux is the source: it pushes an incoming call or a received message,
    /// and this turns that push into a revision change so the phone's long poll
    /// answers at once instead of on its next timeout. Reconnecting is this
    /// thread's job, because the stream ending is normal - Celmux restarting, a
    /// config save, an upgrade.
    pub fn follow_celmux(self: Arc<Self>) {
        std::thread::spawn(move || {
            crate::log_info!("celmux-plugin-airsim: 开始订阅 Celmux 事件流");
            // Catch up on what happened while this process was not running, so a
            // call already ringing is not invisible until it ends.
            match self.client.events_snapshot() {
                Ok(_) => self.revision.bump(),
                Err(error) => {
                    crate::log_warn!("celmux-plugin-airsim: 读取事件快照失败: {error}")
                }
            }
            loop {
                let fired = self.client.subscribe(|frame| {
                    let event = frame.get("event").and_then(Value::as_str).unwrap_or("");
                    match event {
                        // `ready` is the stream's greeting, not a change.
                        "ready" => {}
                        _ => self.revision.bump(),
                    }
                });
                if let Err(error) = fired {
                    // Celmux is down or restarting. Back off so a plugin does not
                    // spin against a closed port.
                    crate::log_warn!("celmux-plugin-airsim: 事件流中断: {error}");
                    std::thread::sleep(std::time::Duration::from_secs(2));
                }
            }
        });
    }

    /// `GET /api/events` — the combined call/SMS long poll.
    ///
    /// Held until something changes or the caller's timeout expires, because the
    /// app uses this as its only poll loop: answering instantly would make it
    /// poll as fast as the network allows, which on a phone is a battery cost for
    /// no information.
    fn events(&self, request: &Request) -> Response {
        let after = query_number(&request.query, "after").unwrap_or(0);
        let timeout = query_number(&request.query, "timeout_ms")
            .map(|millis| std::time::Duration::from_millis(millis.min(30_000)))
            .unwrap_or(std::time::Duration::from_secs(15));
        let revision = self.revision.wait_past(after, timeout);
        let active = self.client.calls().ok().and_then(|value| active_call(&value));
        let slots = self
            .client
            .lines()
            .map(|lines| lines.iter().map(super::control_api::sim_slot).collect())
            .unwrap_or_default();
        let messages = self.sms_count();
        let status = super::control_api::call_status(active, Vec::new());
        Response::ok(super::control_api::agent_event_status(
            revision,
            status,
            messages,
            slots,
        ))
    }

    fn sms_count(&self) -> usize {
        self.client
            .messages()
            .ok()
            .and_then(|value| {
                value
                    .get("messages")
                    .or_else(|| value.get("items"))
                    .and_then(serde_json::Value::as_array)
                    .map(Vec::len)
            })
            .unwrap_or(0)
    }

    /// `GET /api/sim/identity`
    fn sim_identity(&self) -> Response {
        let number = self
            .client
            .lines()
            .ok()
            .and_then(|lines| {
                lines
                    .into_iter()
                    .find(|line| line.line_id == self.agent.config.line_id)
            })
            .map(|line| line.local_phone)
            .unwrap_or_default();
        Response::ok(super::control_api::sim_identity(&number))
    }

    /// `GET /api/sms`
    ///
    /// Celmux's row shape is not the app's: the app keys history on
    /// `delivery_id`, needs a `direction` of its own, and treats `sender` as the
    /// other party. Sending its rows through unchanged would show every message
    /// as incoming from the phone's own number.
    fn messages(&self) -> Response {
        match self.client.messages() {
            Ok(value) => {
                let messages = super::control_api::sms_messages(&value);
                Response::ok(json!({"ok": true, "messages": messages}))
            }
            Err(error) => Response::error(
                502,
                "Bad Gateway",
                "celmux_unavailable",
                &error.to_string(),
            ),
        }
    }

    /// `GET /api/sms/status`
    fn sms_status(&self) -> Response {
        Response::ok(super::control_api::sms_status(self.sms_count(), ""))
    }

    /// `POST /api/calls/dial` — the app's own dial route.
    ///
    /// The body is `number` plus an `operation_id` the app uses to match the
    /// receipt to its request, and optionally `sim_account` for which line to
    /// call from. A missing line is this agent's own.
    fn dial(&self, request: &Request) -> Response {
        let payload: Value = match serde_json::from_slice(&request.body) {
            Ok(value) => value,
            Err(error) => {
                return Response::error(400, "Bad Request", "bad_request", &error.to_string());
            }
        };
        let number = payload
            .get("number")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_owned();
        if number.is_empty() {
            return Response::error(400, "Bad Request", "bad_request", "缺少被叫号码");
        }
        let line_id = payload
            .get("sim_account")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or(&self.agent.config.line_id)
            .to_owned();
        let operation_id = payload
            .get("operation_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        match self.client.dial(&line_id, &number) {
            Ok(value) => {
                // A dial that the app is not told about is a call it cannot show
                // until its next poll, so the poll is released now.
                self.revision.bump();
                Response::ok(json!({
                    "ok": true,
                    "operation_id": operation_id,
                    "line_id": line_id,
                    "number": number,
                    "call": value,
                }))
            }
            Err(error) => Response::error(
                502,
                "Bad Gateway",
                "celmux_unavailable",
                &error.to_string(),
            ),
        }
    }

    /// `GET /api/calls/audio/host/config` — audio route diagnostics.
    ///
    /// The app reads this to show statistics about the Android USB audio bridge.
    /// There is no such bridge here: audio travels over the PCM gateway instead,
    /// so this answers with what is true - a route that is ready because the
    /// gateway is listening - rather than with invented USB identifiers.
    fn audio_host_config(&self) -> Response {
        Response::ok(json!({
            "vendor_id": 0,
            "product_id": 0,
            "location_id": 0,
            "route_ready": true,
            "route_session_ready": true,
            "route_running": true,
            "pcm_port": self.agent.config.pcm_port,
            "diagnostic_log": "音频由 PCM 网关承载",
            "log_tail": [],
        }))
    }

    /// `POST /api/sms/send`
    fn send_sms(&self, request: &Request) -> Response {
        let payload: Value = match serde_json::from_slice(&request.body) {
            Ok(value) => value,
            Err(error) => {
                return Response::error(400, "Bad Request", "bad_request", &error.to_string());
            }
        };
        // The app's own field names: `phone` and `message`, plus `sim_account`
        // for which line to send from. A missing line is this agent's own line,
        // because the phone chose this gateway for the line behind it.
        let field = |names: &[&str]| {
            names
                .iter()
                .find_map(|name| payload.get(*name).and_then(Value::as_str))
                .unwrap_or("")
                .to_owned()
        };
        let to = field(&["phone", "to", "recipient"]);
        let text = field(&["message", "content", "text", "body"]);
        let line_id = {
            let requested = field(&["sim_account", "line_id"]);
            if requested.is_empty() {
                self.agent.config.line_id.clone()
            } else {
                requested
            }
        };
        if to.is_empty() || text.is_empty() {
            return Response::error(
                400,
                "Bad Request",
                "bad_request",
                "缺少收件人或内容",
            );
        }
        match self.client.send_sms(&line_id, &to, &text) {
            Ok(_) => {
                // The app's inbox is keyed on the delivery queue, and a send it
                // is not told about is a message the operator sees nowhere until
                // the next full refresh.
                self.revision.bump();
                Response::ok(json!({"sent": true, "segments": 1}))
            }
            Err(error) => Response::error(
                502,
                "Bad Gateway",
                "celmux_unavailable",
                &error.to_string(),
            ),
        }
    }

    /// `POST /v2/commands/enqueue` — the phone's way to start a dial.
    fn enqueue(&self, request: &Request) -> Response {
        let payload: Value = match serde_json::from_slice(&request.body) {
            Ok(value) => value,
            Err(error) => {
                return Response::error(400, "Bad Request", "bad_request", &error.to_string());
            }
        };
        let command = payload.get("command").and_then(Value::as_str).unwrap_or("");
        let device_id = payload
            .get("device_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        let number = payload.get("number").and_then(Value::as_str).unwrap_or("");
        if command != "dial" {
            return Response::error(
                400,
                "Bad Request",
                "unsupported_command",
                "目前只支持 dial 命令",
            );
        }
        if device_id.is_empty() || number.is_empty() {
            return Response::error(
                400,
                "Bad Request",
                "bad_request",
                "缺少 device_id 或 number",
            );
        }
        match self.client.dial(device_id, number) {
            Ok(result) => {
                let call_id = result
                    .get("call_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                Response::ok(json!({"ok": true, "call_id": call_id}))
            }
            Err(error) => Response::error(502, "Bad Gateway", "dial_failed", &error.to_string()),
        }
    }

    /// `POST /v2/calls/{uuid}/actions` — answer, reject, hang up, DTMF.
    fn call_action(&self, path: &str, request: &Request) -> Response {
        let Some(call_id) = path
            .strip_prefix("/v2/calls/")
            .and_then(|suffix| suffix.strip_suffix("/actions"))
        else {
            return Response::error(404, "Not Found", "not_found", "接口不存在");
        };
        let payload: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
        let action = payload.get("action").and_then(Value::as_str).unwrap_or("");
        let forwarded = match action {
            "answer" => "answer",
            "reject" | "decline" => "reject",
            "hangup" | "end" => "hangup",
            "dtmf" => "dtmf",
            _ => {
                return Response::error(
                    400,
                    "Bad Request",
                    "unsupported_action",
                    "不支持的通话动作",
                );
            }
        };
        match self.client.call_action(forwarded, call_id) {
            Ok(_) => Response::ok(json!({"ok": true})),
            Err(error) => Response::error(502, "Bad Gateway", "action_failed", &error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(id: &str, device: &str, operator: &str, profile: &str, n_standby: bool) -> Line {
        Line {
            line_id: id.to_owned(),
            device_id: device.to_owned(),
            device_name: device.to_owned(),
            profile_name: profile.to_owned(),
            operator_name: operator.to_owned(),
            local_phone: "+100".to_owned(),
            voice_route: "vocall".to_owned(),
            online: true,
            n_standby,
        }
    }

    fn test_agent() -> Arc<Agent> {
        Arc::new(Agent::new(
            crate::agents::AgentConfig {
                line_id: "读卡器1".to_owned(),
                name: "读卡器1".to_owned(),
                control_port: 18642,
                pcm_port: 18643,
            },
            // A fixed secret: the test signs with the same bytes the verifier
            // holds, so it exercises the real authentication path.
            Some(vec![7_u8; 32]),
        ))
    }

    /// Sign one request the way the phone does: the canonical string is
    /// `METHOD\npath\nsha256(body)\ntimestamp\nnonce`, MAC'd with the paired
    /// secret.
    fn signed_request_with(method: &str, path: &str, secret: &[u8]) -> Request {
        use hmac::digest::KeyInit as _;
        use hmac::{Hmac, Mac};
        use sha2::{Digest, Sha256};
        // Near the current clock: the verifier rejects a timestamp outside its
        // skew window, so a fixed literal would fail authentication rather than
        // test what this test is about.
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() as i64)
            .unwrap_or(0);
        let nonce = "nonce-fixed";
        let digest: String = Sha256::digest(b"")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let canonical = format!("{method}\n{path}\n{digest}\n{timestamp}\n{nonce}");
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(canonical.as_bytes());
        let signature = crate::config::base64_url_encode(&mac.finalize().into_bytes());
        let mut headers = std::collections::HashMap::new();
        headers.insert("x-airsim-vowlan-version".to_owned(), "1".to_owned());
        headers.insert("x-airsim-vowlan-timestamp".to_owned(), timestamp.to_string());
        headers.insert("x-airsim-vowlan-nonce".to_owned(), nonce.to_owned());
        headers.insert("x-airsim-vowlan-signature".to_owned(), signature);
        Request {
            method: method.to_owned(),
            path: path.to_owned(),
            query: String::new(),
            headers,
            body: Vec::new(),
        }
    }

    fn signed_request(method: &str, path: &str) -> Request {
        signed_request_with(method, path, &[7_u8; 32])
    }

    fn control() -> Arc<Control> {
        Arc::new(Control {
            // A port nothing listens on: routes that reach Celmux fail closed,
            // which is what these assertions rely on.
            client: Arc::new(Client::new(
                "http://127.0.0.1:1".to_owned(),
                "unused".to_owned(),
                "airsim".to_owned(),
            )),
            agent: test_agent(),
            revision: Arc::new(crate::revision::Revision::default()),
        })
    }

    /// The client decodes `identity_proof`. A payload that calls it `proof`
    /// verifies as a request and still reads as an unreachable gateway, which is
    /// exactly the bug this test exists for.
    #[test]
    fn the_health_route_answers_the_field_the_client_decodes() {
        let response = control().handle(signed_request("GET", "/v1/health"));
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert!(body.get("identity_proof").is_some(), "body: {body}");
        assert_eq!(body["ok"], true);
        assert_eq!(body["canonical_call_ids"], true);
        assert!(body.get("agent_kind").is_some());
        assert!(body.get("device_name").is_some());
    }

    /// `AgentHealth.version` is a String on the client; an integer there fails
    /// decoding and the status screen goes blank.
    #[test]
    fn the_agent_health_route_reports_a_string_version() {
        let response = control().handle(signed_request("GET", "/api/health"));
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert!(body["version"].is_string(), "body: {body}");
        assert_eq!(body["ok"], true);
    }

    /// The app long-polls this and reads the call status nested inside it.
    #[test]
    fn the_event_route_nests_the_call_status() {
        let response = control().handle(signed_request("GET", "/api/events"));
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert!(body["call"].is_object(), "body: {body}");
        assert!(body["revision"].is_number());
        assert_eq!(body["call"]["polling"], true);
        assert!(body["sim_slots"].is_array());
    }

    /// The app signs the request target *with* its query string, so verifying a
    /// parameterised request against the bare path rejects it. Every long poll
    /// carries `after` and `timeout_ms`, which makes this the difference between
    /// an event stream that works and one that always answers 401.
    #[test]
    fn a_signed_request_with_a_query_string_verifies() {
        let path = "/api/events";
        let query = "after=0&timeout_ms=1000";
        let target = format!("{path}?{query}");
        use hmac::digest::KeyInit as _;
        use hmac::{Hmac, Mac};
        use sha2::{Digest, Sha256};
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() as i64)
            .unwrap_or(0);
        let digest: String = Sha256::digest(b"")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let canonical = format!("GET\n{target}\n{digest}\n{timestamp}\nnonce-q");
        let mut mac = Hmac::<Sha256>::new_from_slice(&[7_u8; 32]).unwrap();
        mac.update(canonical.as_bytes());
        let signature = crate::config::base64_url_encode(&mac.finalize().into_bytes());
        let mut headers = std::collections::HashMap::new();
        headers.insert("x-airsim-vowlan-version".to_owned(), "1".to_owned());
        headers.insert("x-airsim-vowlan-timestamp".to_owned(), timestamp.to_string());
        headers.insert("x-airsim-vowlan-nonce".to_owned(), "nonce-q".to_owned());
        headers.insert("x-airsim-vowlan-signature".to_owned(), signature);
        let response = control().handle(Request {
            method: "GET".to_owned(),
            path: path.to_owned(),
            query: query.to_owned(),
            headers,
            body: Vec::new(),
        });
        assert_eq!(response.status, 200, "a signed long poll must verify");
    }

    /// Every route the phone calls must exist, even when it fails closed: a 404
    /// makes the app record the route as unsupported and stop asking.
    #[test]
    fn every_route_the_phone_calls_is_answered() {
        let control = control();
        for path in [
            "/v1/health",
            "/api/health",
            "/api/status",
            "/api/calls/status",
            "/api/calls/events",
            "/api/events",
            "/api/sim/identity",
            "/api/sms",
            "/api/sms/status",
            "/api/calls/audio/host/config",
            "/api/feedback",
            "/api/debug",
        ] {
            let response = control.handle(signed_request("GET", path));
            assert_ne!(response.status, 404, "{path} is missing");
        }
    }

    /// A wrong secret is a refusal, not an answer.
    #[test]
    fn a_request_signed_with_the_wrong_secret_is_refused() {
        let response = control().handle(signed_request_with("GET", "/v1/health", &[9_u8; 32]));
        assert_eq!(response.status, 401);
    }

    /// A device's own line keeps the device name, because that is what the
    /// operator calls it.
    #[test]
    fn a_device_line_is_named_after_its_device() {
        let views = devices(vec![line("d1", "读卡器1", "Globe", "", false)]);
        assert_eq!(views[0].name, "读卡器1");
        assert_eq!(views[0].id, "d1");
    }

    /// Under N-standby several lines share one device, so the device name alone
    /// would give the phone two indistinguishable entries.
    #[test]
    fn n_standby_lines_are_distinguished_by_their_subscription() {
        let views = devices(vec![
            line("d1#890", "dji1", "Globe", "Globe", true),
            line("d1#891", "dji1", "Smart", "Smart", true),
        ]);
        assert_eq!(views[0].name, "dji1 · Globe");
        assert_eq!(views[1].name, "dji1 · Smart");
        assert_ne!(views[0].name, views[1].name);
    }

    /// A Profile with no resolved operator still needs a distinct name, so the
    /// Profile name stands in.
    #[test]
    fn a_profile_line_falls_back_to_its_profile_name() {
        let views = devices(vec![line("d1#890", "dji1", "", "旅行卡", true)]);
        assert_eq!(views[0].name, "dji1 · 旅行卡");
    }
}
