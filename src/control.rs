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
    /// The ports every line shares. Reported in health so the phone knows where
    /// to open audio, and the same two numbers for every line.
    pub ports: Ports,
}

/// The installation-wide pair of ports the phone talks to.
#[derive(Clone, Copy, Debug)]
pub struct Ports {
    pub control: u16,
    pub pcm: u16,
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
    // A module that reports Profile lines also reports a bare line of its own,
    // left over from before the Profiles existed. It cannot select a card, so it
    // stays out of the phone's list; a module with no Profiles keeps its bare
    // line, because that is its only one.
    let modules_with_profiles: std::collections::BTreeSet<String> = lines
        .iter()
        .filter(|line| !line.is_bare())
        .map(|line| line.device_id.clone())
        .collect();
    lines
        .into_iter()
        .filter(|line| {
            let keep = line.usable();
            if !keep {
                // Only a dropped line is worth a line of log: it explains a
                // number the operator expected to see and did not.
                crate::log_info!(
                    "celmux-plugin-airsim: 线路 {} 语音路由不可用（{}），不暴露给手机",
                    line.line_id,
                    line.voice_route
                );
            }
            keep
        })
        .filter(|line| !(line.is_bare() && modules_with_profiles.contains(&line.device_id)))
        .map(|line| {
            let id = line.line_id.clone();
            let name = line.card_name();
            DeviceView { id, name, line }
        })
        .collect()
}

/// The name this agent's line should be shown under.
///
/// Computed from the line as Celmux reports it now, not from the name stored
/// when the operator exposed the line: a line's card, operator and number all
/// change while the exposure stays, and a stale snapshot would keep showing the
/// old ones. Falls back to the stored name when Celmux cannot be reached, so a
/// network blip does not rename the device to nothing.
pub fn line_display_name(agent: &crate::agents::Agent) -> String {
    // One device carrying several cards is named by the device, not by one of
    // its cards: the phone shows one entry per agent, and naming it after a slot
    // would rename the device whenever the first slot changed.
    agent.name()
}

/// The call id Celmux assigned, as text.
///
/// Celmux nests the call row under `call.call`; the id is a number there and the
/// client wants it as an opaque string.
fn call_id_text(value: &Value) -> Option<String> {
    let id = value
        .get("call")
        .and_then(|call| call.get("call"))
        .and_then(|call| call.get("id"))
        .or_else(|| value.get("call").and_then(|call| call.get("id")))
        .or_else(|| value.get("id"))?;
    match id {
        Value::Number(number) => Some(number.to_string()),
        Value::String(text) => Some(text.clone()),
        _ => None,
    }
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
    // Which exposed line this call is on. The phone shows one active call at a
    // time and uses this to say which card is ringing - without it, a call on
    // the second card looks like a call on the first.
    let line = row
        .get("line_id")
        .or_else(|| row.get("device_id"))
        .and_then(Value::as_str)
        .unwrap_or("");
    Some(super::control_api::call_record(
        number,
        state,
        direction,
        started_at,
        line,
    ))
}

/// Route one request on the shared control port.
///
/// Every line listens on this one port, and the request itself names its line:
/// it is signed with that line's secret, so verifying against each known secret
/// identifies the line. That is how the reference agent works too - it scans its
/// paired records and takes the one whose secret verifies. Without a line there
/// is nothing to answer, so an unverifiable request is a 401 and an unpaired
/// installation answers only the pairing exchange.
pub fn handle_shared(
    fleet: &Arc<crate::agents::Fleet>,
    client: &Arc<Client>,
    ports: &Ports,
    request: Request,
) -> Response {
    // An unsigned liveness probe says nothing and needs no line.
    if request.path == "/healthz" {
        return Response::ok(json!({"ok": true}));
    }
    // Every request on this port is logged with the headers that decide
    // authorship. When a phone reports the gateway unreachable, this is the only
    // way to tell "the request never arrived" from "it arrived and was
    // refused" - and if it was refused, which line it should have matched.
    crate::log_info!(
        "celmux-plugin-airsim: 收到 {} {} 时间戳={:?} nonce={:?} 签名={}",
        request.method,
        request.path,
        request.headers.get(crate::auth::HEADER_TIMESTAMP),
        request.headers.get(crate::auth::HEADER_NONCE),
        request
            .headers
            .get(crate::auth::HEADER_SIGNATURE)
            .map(|value| value.chars().take(8).collect::<String>())
            .unwrap_or_default()
    );
    let now = std::time::SystemTime::now();
    let target = if request.query.is_empty() {
        request.path.clone()
    } else {
        format!("{}?{}", request.path, request.query)
    };
    for agent in fleet.list() {
        let Some(verifier) = agent.verifier() else {
            continue;
        };
        if verifier
            .verify(
                &request.method,
                &target,
                &request.body,
                &request.headers,
                now,
            )
            .is_ok()
        {
            // The revision is the line's, not a fresh one: the phone's long
            // poll compares against it, and the thread following Celmux bumps
            // it. A revision created per request would never change, so every
            // poll would wait out its full timeout and a call would look like
            // it never arrived.
            let control = Control {
                client: Arc::clone(client),
                revision: agent.revision(),
                agent,
                ports: *ports,
            };
            return control.handle_verified(request);
        }
    }
    // No line's secret verified it. Say why per line, because "签名不匹配" alone
    // cannot distinguish a stale secret on the phone from a clock skew from a
    // path mismatch - and each of those has a different fix.
    for agent in fleet.list() {
        match agent.verifier() {
            Some(verifier) => {
                if let Err(error) = verifier.verify(
                    &request.method,
                    &target,
                    &request.body,
                    &request.headers,
                    now,
                ) {
                    crate::log_warn!(
                        "celmux-plugin-airsim: {} 校验失败: {error:?}",
                        agent.id()
                    );
                }
            }
            None => crate::log_warn!("celmux-plugin-airsim: {} 没有配对密钥", agent.id()),
        }
    }
    // Before any line has paired, the only thing worth answering is the pairing
    // exchange itself, which is what a phone that is about to pair asks for.
    for agent in fleet.list() {
        if agent.paired() {
            continue;
        }
        if let Some(response) = crate::pair_endpoint::handle(&agent, ports, &request) {
            return response;
        }
    }
    if fleet.list().iter().all(|agent| !agent.paired()) {
        return Response::error(
            503,
            "Service Unavailable",
            "not_paired",
            "尚未配对，请先在 Celmux 插件设置中开始配对",
        );
    }
    Response::error(401, "Unauthorized", "unauthorized", "签名不匹配")
}

impl Control {
    /// Route one request that has already been attributed to this line.
    ///
    /// Authentication happens in [`handle_shared`], which has to look at every
    /// line's secret to know which line the request belongs to. Repeating it
    /// here would verify the same signature twice for no information.
    pub fn handle_verified(&self, request: Request) -> Response {
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
            // The app polls this one, and it decodes the same fields as /v1:
            // `identity_proof` in particular, without which it refuses the
            // gateway outright. Two health routes with different bodies is how
            // the app came to report 「VoWLAN 鉴权失败」 while curl saw 200.
            ("GET", "/api/health") => self.health(&request),
            ("GET", "/v1/devices/status") => self.device_status(),
            ("GET", "/api/status") => self.device_status(),
            ("GET", "/api/calls/status") => self.call_status(),
            ("GET", "/api/calls/events") => self.call_status(),
            ("GET", "/api/events") => self.events(&request),
            ("GET", "/api/sim/identity") => self.sim_identity(),
            ("GET", "/api/sms") => self.messages(),
            ("GET", "/api/sms/status") => self.sms_status(),
            // Routes the app calls that carry no Celmux-side meaning yet. Each
            // one answers in the shape the app decodes rather than 404: a 404 is
            // read as "this gateway is not an agent", and the app then stops
            // probing an otherwise healthy line.
            ("GET", "/api/push/status") => self.push_status(),
            ("POST", "/api/push/register") => self.push_register(&request),
            ("POST", "/api/push/mode") => Response::ok(self.push_status_body()),
            ("GET", "/api/local-mode") => Response::ok(json!({"local_mode": true})),
            ("POST", "/api/local-mode") => Response::ok(json!({"local_mode": true})),
            ("GET", "/api/android/status") => self.device_status(),
            ("GET", "/api/calls/early-media") => {
                Response::error(404, "Not Found", "not_found", "早期媒体未启用")
            }
            ("POST", "/api/calls/audio/host/warmup") => Response::ok(json!({"ok": true})),
            ("POST", "/api/calls/audio/host/register") => Response::ok(json!({"ok": true})),
            ("POST", "/api/calls/resolve") => self.device_status(),
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
            // A String on the client: an integer here fails decoding and the
            // app's status screen goes blank.
            "version": "0.2.0",
            "agent_id": agent_id,
            "identity_proof": proof,
            "agent_kind": "standalone",
            "device_name": self.line_name(),
            "manufacturer": "Celmux",
            "model": "Celmux VoWiFi Gateway",
            // The subscriber this agent's line answers on. The phone shows it
            // under the device name and uses it to tell two lines on the same
            // module apart, so omitting it leaves the card with no number at
            // all even though pairing succeeded.
            "phone_number": self.line_phone(),
            "canonical_call_ids": true,
            "control_port": self.ports.control,
            "pcm_port": self.ports.pcm,
        }))
    }

    /// The number this agent's line answers on, empty when Celmux has not
    /// learned it yet.
    fn line_phone(&self) -> String {
        // The first exposed line's number, for the routes that predate
        // `sim_slots` and expect a single number.
        self.client
            .lines()
            .ok()
            .and_then(|lines| {
                lines
                    .into_iter()
                    .find(|line| Some(&line.line_id) == self.agent.config.lines.first())
            })
            .map(|line| line.local_phone)
            .unwrap_or_default()
    }

    /// `GET /v1/devices/status` and `api/status` — what the phone lists.
    ///
    /// One device entry per exposed line, which is how the phone models several
    /// cards behind one gateway: it shows them as a list and names the one it
    /// wants in `sim_account` when it dials or sends.
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
        // Every exposed line, in the order the operator put them: the phone
        // lists these as the cards it can call from.
        let devices: Vec<Value> = devices(lines)
            .into_iter()
            .filter(|device| {
                self.agent.config.lines.contains(&device.line.line_id)
            })
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
        self.all_messages().len()
    }

    /// Every exposed line's messages, as the app's model.
    ///
    /// The app keeps one history for the device and tells the cards apart by
    /// each message's `sim_slot`, so the union is what it expects - not the
    /// messages of whichever line happens to be first.
    fn all_messages(&self) -> Vec<Value> {
        let mut messages: Vec<Value> = self
            .agent
            .config
            .lines
            .iter()
            .filter_map(|line_id| self.client.messages(line_id).ok())
            .flat_map(|value| super::control_api::sms_messages(&value))
            .collect();
        // Newest first, which is the order the phone renders and the order
        // Celmux uses. Sorting here rather than per line keeps two cards'
        // messages interleaved by time instead of grouped by card.
        messages.sort_by(|left, right| {
            let key = |value: &Value| {
                value
                    .get("timestamp")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned()
            };
            key(right).cmp(&key(left))
        });
        messages
    }

    /// `GET /api/sim/identity`
    fn sim_identity(&self) -> Response {
        // The default slot's number. The app reads this before it has a slot
        // list and falls back to `sim_slots` for the rest, so answering with the
        // first exposed line is the useful answer rather than none.
        let number = self
            .client
            .lines()
            .ok()
            .and_then(|lines| {
                lines
                    .into_iter()
                    .find(|line| Some(&line.line_id) == self.agent.config.lines.first())
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
        match self.client.lines() {
            Ok(_) => {
                // A bare array, because the app decodes `[SMSMessage]` from this
                // route. Wrapping it in an object makes the decode fail and the
                // list silently keep whatever it had before - a refresh button
                // that appears to do nothing.
                Response::ok(Value::Array(self.all_messages()))
            }
            Err(error) => Response::error(
                502,
                "Bad Gateway",
                "celmux_unavailable",
                &error.to_string(),
            ),
        }
    }

    /// What this agent's line is called right now.
    fn line_name(&self) -> String {
        line_display_name(&self.agent)
    }

    /// The push status document.
    ///
    /// The app reads this to decide whether a cloud path is configured, and it
    /// is where `local_mode` comes from. This gateway is local-only, so the
    /// honest answer is "configured, cloud off": reporting a cloud path it does
    /// not have would send the app down a relay that never answers.
    fn push_status(&self) -> Response {
        Response::ok(self.push_status_body())
    }

    fn push_status_body(&self) -> serde_json::Value {
        json!({
            "local_mode": true,
            "cloud_enabled": false,
            "configured": true,
            "call_push_ready": false,
            "message_push_ready": false,
            "last_error": "",
            "wan_interface": "celmux",
        })
    }

    /// `POST /api/push/register`
    ///
    /// The app registers its APNs tokens here when a cloud path is in use. This
    /// gateway has none, so nothing is stored and the reply says so instead of
    /// pretending the registration took.
    fn push_register(&self, _request: &Request) -> Response {
        Response::ok(json!({
            "registered": false,
            "local_mode": true,
            "reason": "celmux 直连网关不使用云端推送",
        }))
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
        // The slot the phone chose. Falling back to the first exposed line keeps
        // a client that predates the slot list working, and a slot that is not
        // exposed is refused below rather than silently dialling from another
        // card - dialling from the wrong number is worse than not dialling.
        let line_id = payload
            .get("sim_account")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| self.agent.config.primary_line().to_owned());
        if !self.agent.config.lines.contains(&line_id) {
            return Response::error(
                409,
                "Conflict",
                "unknown_slot",
                "该线路未暴露给 AirSIM",
            );
        }
        let operation_id = payload
            .get("operation_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        match self.client.dial(&line_id, &number) {
            Ok(value) => {
                // The app does not treat a 200 as "the call started". It decodes
                // a receipt binding this request to one call, and without the
                // fields below it concludes the peer is unsupported and never
                // asks for audio at all - which is exactly what "stuck
                // establishing the voice link" looks like from the phone.
                self.revision.bump();
                let android_id = call_id_text(&value).unwrap_or_default();
                // The nonce of this very request is what the receipt is signed
                // over, so the proof cannot be replayed onto another dial.
                let nonce = request
                    .headers
                    .get(crate::auth::HEADER_NONCE)
                    .cloned()
                    .unwrap_or_default();
                let backend_id = format!("celmux:{line_id}");
                let operation_proof = self.agent.proof(&format!(
                    "AIRSIM-DIAL1\n{nonce}\n{operation_id}\n{android_id}\n{backend_id}"
                ));
                Response::ok(json!({
                    "ok": true,
                    "version": 1,
                    "operation_id": operation_id,
                    "android_id": android_id,
                    "backend_id": backend_id,
                    "operation_proof": operation_proof,
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
            "pcm_port": self.ports.pcm,
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
                self.agent.config.primary_line().to_owned()
            } else {
                requested
            }
        };
        // Sending from a card the operator did not expose would put the message
        // on a number the phone never offered.
        if !self.agent.config.lines.contains(&line_id) {
            return Response::error(409, "Conflict", "unknown_slot", "该线路未暴露给 AirSIM");
        }
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
                lines: vec!["读卡器1".to_owned()],
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

    const TEST_PORTS: crate::control::Ports = crate::control::Ports {
        control: 18642,
        pcm: 18643,
    };

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
            ports: TEST_PORTS,
        })
    }

    /// The client decodes `identity_proof`. A payload that calls it `proof`
    /// verifies as a request and still reads as an unreachable gateway, which is
    /// exactly the bug this test exists for.
    #[test]
    fn the_health_route_answers_the_field_the_client_decodes() {
        let response = control().handle_verified(signed_request("GET", "/v1/health"));
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert!(body.get("identity_proof").is_some(), "body: {body}");
        assert_eq!(body["ok"], true);
        assert_eq!(body["canonical_call_ids"], true);
        assert!(body.get("agent_kind").is_some());
        assert!(body.get("device_name").is_some());
    }

    /// Both health routes answer the same document.
    ///
    /// The app polls `/api/health`; `/v1/health` is the older sibling. When the
    /// two differed, the app decoded `identity_proof` from a body that did not
    /// carry it and reported 「VoWLAN 鉴权失败」 while curl saw a healthy 200.
    /// `version` is a String on the client, so an integer there blanks the
    /// status screen.
    #[test]
    fn both_health_routes_answer_the_same_document() {
        for path in ["/api/health", "/v1/health"] {
            let response = control().handle_verified(signed_request("GET", path));
            assert_eq!(response.status, 200, "{path}");
            let body: Value = serde_json::from_slice(&response.body).unwrap();
            assert!(body["version"].is_string(), "{path}: {body}");
            assert_eq!(body["ok"], true, "{path}");
            assert!(body.get("identity_proof").is_some(), "{path}: {body}");
            assert!(body.get("agent_id").is_some(), "{path}: {body}");
            assert!(body.get("phone_number").is_some(), "{path}: {body}");
        }
    }

    /// The app long-polls this and reads the call status nested inside it.
    #[test]
    fn the_event_route_nests_the_call_status() {
        let response = control().handle_verified(signed_request("GET", "/api/events"));
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
        let response = control().handle_verified(Request {
            method: "GET".to_owned(),
            path: path.to_owned(),
            query: query.to_owned(),
            headers,
            body: Vec::new(),
        });
        assert_eq!(response.status, 200, "a signed long poll must verify");
    }

    /// The app decodes `[SMSMessage]` from `/api/sms`. Answering an object makes
    /// the decode fail, and the app keeps the list it already has - a refresh
    /// that appears to do nothing rather than an error anyone can see.
    #[test]
    fn the_sms_route_answers_a_bare_array() {
        let response = control().handle_verified(signed_request("GET", "/api/sms"));
        // The client is unreachable in this test, so the shape is what can be
        // asserted: never an object with a `messages` key.
        let body = String::from_utf8_lossy(&response.body);
        assert!(
            !body.contains("\"messages\""),
            "must not wrap the list: {body}"
        );
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
            let response = control.handle_verified(signed_request("GET", path));
            assert_ne!(response.status, 404, "{path} is missing");
        }
    }

    /// A wrong secret is a refusal, not an answer.
    #[test]
    fn a_request_signed_with_the_wrong_secret_is_refused() {
        // Through the shared port, because that is where the signature decides
        // which line - and whether any line - the request belongs to.
        // A fleet in a scratch directory: reconcile creates the agents, and the
        // secret is handed to each the way pairing would.
        let root = std::env::temp_dir().join("celmux-plugin-shared-route-test");
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::create_dir_all(&root);
        let fleet = Arc::new(crate::agents::Fleet::new(&root));
        fleet
            .reconcile(vec![crate::agents::AgentConfig {
                lines: vec!["读卡器1".to_owned()],
            }])
            .unwrap();
        for agent in fleet.list() {
            agent.set_secret(vec![7_u8; 32]);
        }
        let client = Arc::new(Client::new(
            "http://127.0.0.1:1".to_owned(),
            "unused".to_owned(),
            "airsim".to_owned(),
        ));
        let wrong = self::handle_shared(
            &fleet,
            &client,
            &TEST_PORTS,
            signed_request_with("GET", "/v1/health", &[9_u8; 32]),
        );
        assert_eq!(wrong.status, 401, "签错密钥必须被拒绝");
        let right = self::handle_shared(
            &fleet,
            &client,
            &TEST_PORTS,
            signed_request_with("GET", "/v1/health", &[7_u8; 32]),
        );
        assert_eq!(right.status, 200, "签对密钥应被接受");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Every line is named the same way: device, operator, number. The phone
    /// lists them side by side, and a module with an extra naming scheme would
    /// read as a different kind of thing.
    #[test]
    fn a_line_is_named_by_device_operator_and_number() {
        let views = devices(vec![line("d1", "读卡器1", "Globe", "", false)]);
        assert_eq!(views[0].name, "读卡器1 · Globe · +100");
        assert_eq!(views[0].id, "d1");
    }

    /// Under N-standby several lines share one device, so the number is what
    /// keeps the entries apart.
    #[test]
    fn n_standby_lines_are_distinguished_by_their_number() {
        let views = devices(vec![
            line("d1#890", "dji1", "Globe", "Globe", true),
            line("d1#891", "dji1", "Smart", "Smart", true),
        ]);
        assert_eq!(views[0].name, "dji1 · Globe · +100");
        assert_ne!(views[0].name, views[1].name);
    }

    /// A Profile with no resolved operator still needs a distinct name, so the
    /// Profile name stands in.
    #[test]
    fn a_profile_line_falls_back_to_its_profile_name() {
        let views = devices(vec![line("d1#890", "dji1", "", "旅行卡", true)]);
        assert_eq!(views[0].name, "dji1 · 旅行卡 · +100");
    }

    /// A module that reports Profiles also reports a bare line of its own, left
    /// over from before the Profiles existed. It cannot select a card, so it
    /// must not reach the phone - while a module with no Profiles keeps its
    /// bare line, because that is its only one.
    #[test]
    fn a_bare_line_is_dropped_only_when_its_module_has_profiles() {
        let views = devices(vec![
            line("读卡器2", "读卡器2", "", "", false),
            line("读卡器2#890", "读卡器2", "Vodafone", "Vodafone UK", true),
            line("读卡器1", "读卡器1", "Globe", "", false),
        ]);
        let ids: Vec<&str> = views.iter().map(|view| view.id.as_str()).collect();
        assert_eq!(ids, vec!["读卡器2#890", "读卡器1"], "裸线路只在该模组有 Profile 时丢弃");
    }
    /// The app's `AgentPushStatus` has four required fields. A 404 here is read
    /// as "not an agent" and the app stops probing a healthy line, so this route
    /// has to answer - with the local truth, which is that there is no cloud
    /// path to register against.
    #[test]
    fn the_push_status_route_answers_the_shape_the_app_decodes() {
        let response = control().handle_verified(signed_request("GET", "/api/push/status"));
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        for key in [
            "local_mode",
            "cloud_enabled",
            "configured",
            "call_push_ready",
            "message_push_ready",
        ] {
            assert!(body.get(key).is_some(), "缺少 {key}: {body}");
        }
        assert_eq!(body["local_mode"], true);
        assert_eq!(body["cloud_enabled"], false);
        assert_eq!(body["configured"], true);
    }

    /// Every route the app is allowed to call must answer rather than 404.
    #[test]
    fn every_route_the_app_calls_is_answered() {
        let control = control();
        for path in [
            "/v1/health",
            "/api/health",
            "/api/status",
            "/api/debug",
            "/api/push/status",
            "/api/calls/status",
            "/api/calls/events",
            "/api/sms",
            "/api/sms/status",
            "/api/feedback",
            "/api/calls/audio/host/config",
            "/api/local-mode",
        ] {
            let response = control.handle_verified(signed_request("GET", path));
            assert_ne!(response.status, 404, "{path} 返回 404");
        }
    }
}
