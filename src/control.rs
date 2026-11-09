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

use crate::auth::Verifier;
use crate::celmux::{Client, Line};
use crate::http::{Request, Response};

pub struct Control {
    pub client: Client,
    pub verifier: Verifier,
    pub agent_id: String,
    /// The host and ports this bridge advertised, so the phone can be told what
    /// to dial for media.
    pub host: String,
    pub control_port: u16,
    pub pcm_port: u16,
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

impl Control {
    /// Route one request. `Ok` carries the response; `Err` is a request that
    /// failed authentication, which is always a 401 with no detail beyond that.
    pub fn handle(self: &Arc<Self>, request: Request) -> Response {
        // An unsigned liveness probe: the phone and any operator tooling use it
        // to tell "port closed" from "auth wrong", and it says nothing.
        if request.path == "/healthz" {
            return Response::ok(json!({"ok": true}));
        }
        let now = std::time::SystemTime::now();
        if let Err(error) = self.verifier.verify(
            &request.method,
            &request.path,
            &request.body,
            &request.headers,
            now,
        ) {
            return Response::error(401, "Unauthorized", "unauthorized", &error.to_string());
        }
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/v1/health") => self.health(&request),
            ("GET", "/v1/devices/status") => self.device_status(),
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
        Response::ok(json!({
            "ok": true,
            "agent_id": self.agent_id,
            "proof": self.verifier.health_proof(&nonce, &self.agent_id),
            "control_port": self.control_port,
            "pcm_port": self.pcm_port,
        }))
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
        let devices: Vec<Value> = devices(lines)
            .into_iter()
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
            iccid: String::new(),
            profile_name: profile.to_owned(),
            operator_name: operator.to_owned(),
            local_phone: "+100".to_owned(),
            voice_route: "vocall".to_owned(),
            online: true,
            n_standby,
        }
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
