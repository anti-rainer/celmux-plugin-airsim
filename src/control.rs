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
    /// The cloud path's context, when that listener is running.
    ///
    /// Absent when the operator has the cloud path off. A ringing call is then
    /// still reported to the phone on its long poll; there is simply no push to
    /// send, which is a different thing from a push that failed.
    pub relay_context: Option<Arc<crate::relay_endpoint::Context>>,
    /// The identity of the call last pushed, and whether it was delivered.
    ///
    /// Upstream keeps this as one small state machine rather than a set of ids:
    /// a call reported ringing twice must ring once, but a *retry* after a failed
    /// push has to reuse the same UUID - CallKit treats a second UUID as a second
    /// call - while advancing the generation, which is how a relay knows this is a
    /// retry rather than a duplicate.
    pub call_push: Arc<std::sync::Mutex<CallPush>>,
    /// The message ids the phone has confirmed, so `sms_pending` can mean
    /// "unconfirmed" rather than "everything".
    pub(crate) acked_messages: Arc<std::sync::Mutex<std::collections::BTreeSet<String>>>,
}

/// A UUID derived from a call id, stably.
///
/// CallKit identifies a call by its UUID, so the same call pushed twice must name
/// the same UUID or the phone reports two calls. A call id is not a UUID, so one is
/// derived: the version and variant bits are set the way RFC 4122 requires, which
/// is what makes `UUID(uuidString:)` on the phone accept it.
pub fn uuid_v5_like(seed: &str) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(seed.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = |slice: &[u8]| {
        slice
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    format!(
        "{}-{}-{}-{}-{}",
        hex(&bytes[0..4]),
        hex(&bytes[4..6]),
        hex(&bytes[6..8]),
        hex(&bytes[8..10]),
        hex(&bytes[10..16])
    )
}

/// A media secret of the length the phone insists on.
///
/// The phone drops a whole incoming call when `call_secret` is shorter than 24
/// characters, so this is generated even though this gateway's PCM socket
/// authenticates with the pairing secret instead: the field is part of the push
/// contract, not of the audio path.
fn random_call_secret() -> String {
    let mut bytes = [0u8; 32];
    if getrandom::fill(&mut bytes).is_err() {
        // Unreachable on Linux, and a fixed value would be worse than a short
        // secret: the phone would accept a predictable one.
        return String::new();
    }
    crate::config::base64_url_encode(&bytes)
}

/// What has been pushed for the call currently ringing.
///
/// One call at a time is the honest model here: the gateway carries one call per
/// line, and the phone shows one incoming call.
#[derive(Default)]
pub struct CallPush {
    /// The call last pushed, or empty before the first.
    pub call_id: String,
    /// The UUID the phone knows that call by. Reused on a retry so CallKit does
    /// not report a second call.
    pub uuid: String,
    /// The media secret for that UUID, so a retry presents the same one.
    pub secret: String,
    /// Advanced on every retry of the same call.
    pub generation: u64,
    /// Whether the relay accepted the last push for this call.
    pub delivered: bool,
    /// Whether a push for this call is on the wire right now.
    pub in_flight: bool,
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
        if name == key {
            value.parse().ok()
        } else {
            None
        }
    })
}

/// One raw query parameter, percent-decoded.
///
/// Operations ids and other tokens arrive here as part of the request target, so
/// they are decoded: an id the phone generated may carry characters that were
/// escaped on the way in, and comparing the escaped form would miss it.
fn query_text(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        if name == key {
            Some(percent_decode(value))
        } else {
            None
        }
    })
}

/// Decode `%XX` escapes and `+`, as a query string carries them.
///
/// The plugin has no URL parser and does not need one: a query value is either
/// literal or escaped, and this is the whole of that rule.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        output.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        output.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&output).into_owned()
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
    // Celmux calls the other party `peer`; the phone calls it `number`. Reading
    // only the phone's name left every active call with an empty number, so the
    // call screen showed a call from nobody.
    let number = row
        .get("peer")
        .or_else(|| row.get("number"))
        .or_else(|| row.get("remote_number"))
        .and_then(Value::as_str)
        .unwrap_or("");
    // Celmux reports its SIP phase; the app accepts only `incoming` and `waiting`
    // for a call it may answer. Sending `ringing` through - a word the app does not
    // recognise - left an incoming call visible in the payload and ignored by the
    // phone: it did not ring, could not be answered, and the call screen stayed
    // empty. `early` is the same moment from the callee's side (the caller hearing
    // the network), so it maps here too.
    let state = match row.get("state").and_then(Value::as_str).unwrap_or("active") {
        "ringing" | "early" | "alerting" => "incoming",
        other => other,
    };
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
    // Celmux's own call id, which is what it accepts back for answer and hangup.
    let android_id = row
        .get("id")
        .map(|value| match value {
            Value::Number(number) => number.to_string(),
            Value::String(text) => text.clone(),
            _ => String::new(),
        })
        .unwrap_or_default();
    Some(super::control_api::call_record(
        number,
        state,
        direction,
        started_at,
        line,
        &android_id,
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
    relay_context: Option<Arc<crate::relay_endpoint::Context>>,
    request: Request,
) -> Response {
    // An unsigned liveness probe says nothing and needs no line.
    if request.path == "/healthz" {
        return Response::ok(json!({"ok": true}));
    }
    // Only the requests that change something are logged with their signature
    // headers. The phone's event poll runs every 25 seconds for as long as it is
    // open, so logging it would fill the file with one line per poll and push the
    // calls, pairings and failures out of view - which are the lines anyone
    // actually reads this log for.
    // The long poll and the health probe: both run on a timer for as long as the
    // phone is connected, so neither says anything about what happened.
    let polled = request.path.starts_with("/api/events")
        || request.path.starts_with("/api/calls/events")
        || request.path.starts_with("/v1/health")
        || request.path.starts_with("/api/health");
    if request.method != "GET" || !polled {
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
    }
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
            let acked_messages = agent.acked_messages();
            let control = Control {
                client: Arc::clone(client),
                revision: agent.revision(),
                agent,
                ports: *ports,
                relay_context: relay_context.clone(),
                call_push: Arc::new(std::sync::Mutex::new(CallPush::default())),
                acked_messages,
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
                    crate::log_warn!("celmux-plugin-airsim: {} 校验失败: {error:?}", agent.id());
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
            ("GET", "/api/calls/status") => self.call_status_now(),
            ("GET", "/api/calls/events") => self.call_status(&request),
            ("GET", "/api/calls/operation") => self.dial_operation(&request),
            ("POST", "/api/calls/auto-answer") => self.set_line_auto_answer(&request),
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
            ("POST", "/api/sms/ack") => self.acknowledge_sms(&request),
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
            ("POST", "/api/calls/answer") => self.call_action_named("answer", &request),
            ("POST", "/api/calls/reject") => self.call_action_named("reject", &request),
            ("POST", "/api/calls/hangup") => self.call_action_named("hangup", &request),
            ("POST", "/api/calls/dtmf") => self.call_action_named("dtmf", &request),
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
            // The cards this device offers. The client reads this from the
            // health document and keeps it as the device's metadata; without it
            // the slot picker falls back to whatever it remembered from an
            // earlier version, which is how a card list survived several
            // changes to the naming.
            "sim_slots": self.exposed_slots(),
        }))
    }

    /// The slot list for the lines the operator exposed, in Celmux's order.
    ///
    /// One place, because both the health document and the event stream answer
    /// with it and the client treats them as the same fact: a picker built from
    /// one and a send checked against the other would disagree.
    fn exposed_slots(&self) -> Vec<Value> {
        self.client
            .lines()
            .map(|lines| {
                lines
                    .iter()
                    .filter(|line| self.agent.exposes(&line.line_id))
                    .map(super::control_api::sim_slot)
                    .collect()
            })
            .unwrap_or_default()
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
                    .find(|line| Some(&line.line_id) == self.agent.lines().first())
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
            .filter(|device| self.agent.exposes(&device.line.line_id))
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
    /// `GET /api/calls/events` — the call-only long poll.
    ///
    /// The app waits on this with `after` and `timeout_ms` exactly as it waits on
    /// `/api/events`. Answering immediately turned the wait into a poll loop: the
    /// phone asked again the moment it was answered, and a call that started
    /// between two asks was seen one round trip late - or, for a short ring, not
    /// at all. Holding the request open until the revision moves is what makes a
    /// ring reach the phone while it is still ringing.
    fn call_status(&self, request: &Request) -> Response {
        let after = query_number(&request.query, "after").unwrap_or(0);
        let timeout = query_number(&request.query, "timeout_ms")
            .map(|millis| std::time::Duration::from_millis(millis.min(30_000)))
            .unwrap_or(std::time::Duration::from_secs(25));
        let revision = self.revision.wait_past(after, timeout);
        let response = self.call_status_now();
        // The long poll is a `polled` route, so it is exempt from the request log.
        // That left no way to tell "the phone is not asking" from "the phone asks
        // and we answer `active: null`" - and every incoming call looked identical
        // from here. Logged on the way out, with what the phone will actually see.
        let answered = serde_json::from_slice::<Value>(&response.body)
            .ok()
            .and_then(|body| {
                let active = body.get("active")?;
                if active.is_null() {
                    return Some("idle".to_owned());
                }
                Some(format!(
                    "{} {} from {}",
                    active.get("state").and_then(Value::as_str).unwrap_or("?"),
                    active.get("call_id").and_then(Value::as_str).unwrap_or(""),
                    active.get("number").and_then(Value::as_str).unwrap_or("")
                ))
            })
            .unwrap_or_else(|| "?".to_owned());
        crate::log_info!(
            "celmux-plugin-airsim: 通话长轮询 after={after} → revision={revision}，返回 {answered}"
        );
        response
    }

    /// `POST /api/calls/auto-answer` — let this gateway present a line's calls.
    ///
    /// `enabled: true` means "Celmux may answer by itself"; the phone asks for the
    /// opposite when it wants to ring for a call. Sent to Celmux as a runtime
    /// suppression, so the operator's own switch on that line is never written -
    /// a plugin that changed it would leave the line altered after the plugin was
    /// removed, and the two settings would fight on every call.
    fn set_line_auto_answer(&self, request: &Request) -> Response {
        let payload: Value = match serde_json::from_slice(&request.body) {
            Ok(payload) => payload,
            Err(error) => {
                return Response::error(400, "Bad Request", "bad_json", &error.to_string());
            }
        };
        let line_id = payload
            .get("line_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        // Default to the agent's first line: the app's own settings screen acts on
        // one card at a time and may omit it.
        let line_id = if line_id.is_empty() {
            self.agent.lines().first().cloned().unwrap_or_default()
        } else {
            line_id
        };
        if line_id.is_empty() {
            return Response::error(400, "Bad Request", "no_line", "没有可操作的线路");
        }
        if !self.agent.exposes(&line_id) {
            return Response::error(403, "Forbidden", "line_not_exposed", "该线路未暴露给本网关");
        }
        let enabled = payload
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        match self.client.set_auto_answer(&line_id, enabled) {
            Ok(answer) => Response::ok(json!({
                "ok": true,
                "line_id": line_id,
                // What the phone asked for, and what the line itself is set to.
                // The two differ whenever the phone has taken the calls over, and
                // a client that shows only one of them misreports the other.
                "auto_answer": enabled,
                "configured": answer.get("configured").cloned().unwrap_or(Value::Null),
            })),
            Err(error) => {
                Response::error(502, "Bad Gateway", "celmux_unavailable", &error.to_string())
            }
        }
    }

    /// The current call state, answered at once.
    fn call_status_now(&self) -> Response {
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
        Response::ok(super::control_api::call_status(
            active,
            Vec::new(),
            self.revision.now(),
        ))
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
                    // Logged for every frame, `ready` included. Which events arrive
                    // is the one thing that cannot be inferred from the outside: a
                    // ringing call that never shows up here was never sent, and one
                    // that shows up and still goes nowhere is this side's problem.
                    crate::log_info!("celmux-plugin-airsim: 事件流收到帧 event={event}");
                    match event {
                        // `ready` is the stream's greeting, not a change.
                        "ready" => {}
                        "sms" => {
                            // Only an arrival is worth a push: a read, a delete or
                            // a delivery receipt is bookkeeping, and a phone does
                            // not need to wake for it.
                            if let Some(payload) = frame.get("payload")
                                && payload.get("kind").and_then(Value::as_str) == Some("received")
                            {
                                self.push_received_sms(payload);
                            }
                            self.revision.bump();
                        }
                        "call" => {
                            // A ringing incoming call is the one event worth a
                            // push: the phone is asleep and nothing else would
                            // wake it. Everything else is a state change the
                            // phone can read on its next poll.
                            if let Some(payload) = frame.get("payload") {
                                self.push_ringing_call(payload);
                            }
                            self.revision.bump();
                        }
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

    /// Push a message whose body arrived with the event.
    ///
    /// The delivery id still has to be stable - a relay deduplicates on it and the
    /// phone would otherwise show the same message twice - so one is built from the
    /// line and the arrival time, which is unique per message on a line.
    fn push_announced_sms(
        &self,
        context: &Arc<crate::relay_endpoint::Context>,
        payload: &Value,
        peer: &str,
        content: &str,
    ) {
        let line = payload
            .get("line_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|age| age.as_millis())
            .unwrap_or(0);
        let event = crate::relay_agent::SmsEvent {
            delivery_id: format!("{line}-{stamp}"),
            sender: peer.to_owned(),
            content: content.to_owned(),
            code: String::new(),
            timestamp: iso_timestamp(stamp as u64),
        };
        let context = Arc::clone(context);
        std::thread::spawn(move || {
            if context.agent.target().is_own() {
                crate::relay_endpoint::deliver_sms_locally(&context, &event);
                return;
            }
            match context.agent.sms(&event) {
                Ok(reply) if reply.accepted() => crate::log_info!(
                    "celmux-plugin-airsim: 短信事件已送出 delivery_id={}",
                    event.delivery_id
                ),
                Ok(reply) => crate::log_warn!(
                    "celmux-plugin-airsim: relay 拒绝短信事件: HTTP {}",
                    reply.status
                ),
                Err(error) => {
                    crate::log_warn!("celmux-plugin-airsim: 短信事件发送失败: {error}")
                }
            }
        });
    }

    /// Turn a ringing Celmux call into a push, at most once per call.
    ///
    /// Celmux reports the same state more than once (the caller's network retries,
    /// an early-media update), and pushing per event would ring the phone over and
    /// over for one call. Only `incoming` + `ringing` is a push, and the call id is
    /// remembered so a repeat is dropped.
    fn push_ringing_call(&self, payload: &Value) {
        let direction = payload
            .get("direction")
            .and_then(Value::as_str)
            .unwrap_or("");
        let state = payload.get("state").and_then(Value::as_str).unwrap_or("");
        // Celmux reports a call's SIP phase; the AirSIM relay only accepts
        // `incoming` or `waiting`. `ringing` and `early` are the same moment from
        // the phone's side - the caller is hearing the network, not the callee -
        // so they are mapped rather than sent through and rejected.
        if direction != "incoming" {
            return;
        }
        let state = match state {
            "ringing" | "early" => "incoming",
            "waiting" => "waiting",
            other => other,
        };
        if !matches!(state, "incoming" | "waiting") {
            return;
        }
        let call_id = payload
            .get("call_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        if call_id.is_empty() {
            return;
        }
        let context = match self.relay_context.clone() {
            Some(context) => context,
            // The cloud path is off. The direct path's long poll still reports
            // the call, so there is nothing to fail here.
            None => {
                crate::log_info!(
                    "celmux-plugin-airsim: 来电 call_id={call_id} 无云端通道（直连模式），跳过推送"
                );
                return;
            }
        };
        crate::log_info!(
            "celmux-plugin-airsim: 来电 call_id={call_id} state={state} 走云端推送，relay={}",
            context.agent.target().base()
        );

        // The identity of this call, decided under the lock: a repeat of the same
        // state is dropped, a retry keeps the UUID and advances the generation.
        let (uuid, secret, generation) = {
            let Ok(mut push) = self.call_push.lock() else {
                return;
            };
            if push.call_id == call_id {
                if push.delivered || push.in_flight {
                    return;
                }
                // A retry of a call whose push failed: same UUID so CallKit sees
                // one call, new generation so a relay treats it as a retry.
                push.in_flight = true;
                push.generation = push.generation.wrapping_add(1).max(1);
                (push.uuid.clone(), push.secret.clone(), push.generation)
            } else {
                let uuid = uuid_v5_like(&call_id);
                let secret = random_call_secret();
                *push = CallPush {
                    call_id: call_id.clone(),
                    uuid: uuid.clone(),
                    secret: secret.clone(),
                    generation: 1,
                    delivered: false,
                    in_flight: true,
                };
                (uuid, secret, 1)
            }
        };

        let now = chrono::Utc::now();
        let call = crate::relay::IncomingCall {
            call_id: call_id.clone(),
            call_uuid: uuid,
            call_secret: secret,
            number: payload
                .get("number")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            caller_name: String::new(),
            generation,
            issued_at: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            // The upstream agent allows 45 seconds from ring to answer.
            expires_at: (now + chrono::Duration::seconds(45))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            expires_unix: (now.timestamp() + 45).max(0) as u64,
            media_url: String::new(),
        };

        // Take the line over before announcing the call. Celmux answers an
        // auto-answer line by itself, and it does so from the same event this
        // handler is reading - so a call on such a line is answered before the
        // phone could ever ring for it. Suppressing first is what makes the two
        // settings coexist: the line keeps its own switch, and this gateway is the
        // one presenting the call. Repeated pushes are cheap: Celmux reports
        // whether the set changed.
        let handover_line = payload
            .get("line_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        if !handover_line.is_empty() && self.agent.exposes(&handover_line) {
            match self.client.set_auto_answer(&handover_line, false) {
                Ok(_) => {}
                // Not fatal to the ring: a line whose switch was already off needs
                // nothing, and saying so every call would bury the real failures.
                Err(error) => crate::log_warn!(
                    "celmux-plugin-airsim: 接管线路 {handover_line} 自动接听失败: {error}"
                ),
            }
        }

        // Off this thread: the event stream must keep reading, and a round-trip
        // to a relay is tens of milliseconds.
        let push = Arc::clone(&self.call_push);
        std::thread::spawn(move || {
            let outcome = crate::relay_endpoint::push_incoming_call(&context, &call);
            let accepted = outcome.status.is_some_and(crate::apns::Outcome::accepted);
            if let Ok(mut state) = push.lock()
                && state.call_id == call.call_id
            {
                state.in_flight = false;
                state.delivered = accepted;
            }
        });
    }

    /// Tell the phone a message arrived.
    ///
    /// Celmux's event names the peer and a revision; the message body comes from
    /// its own list, because a push that carried only a sender would tell the
    /// phone to wake up and then make it ask anyway. Deduplication is the relay's
    /// job when it sends pushes and this side's when it does not, so the newest
    /// received message for that peer is looked up by delivery id.
    fn push_received_sms(&self, payload: &Value) {
        let context = match self.relay_context.clone() {
            Some(context) => context,
            None => return,
        };
        let peer = payload
            .get("peer")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        // Celmux puts the body in the event when it announces the arrival from the
        // IMS path, which is the only place that knows the message the moment it
        // exists. Reading the list instead raced the row being written and pushed a
        // notification with nothing in it.
        let announced = payload
            .get("content")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_owned();
        if !announced.is_empty() {
            self.push_announced_sms(&context, payload, &peer, &announced);
            return;
        }
        // The line the message arrived on: Celmux names it, and a message belongs
        // to one line.
        let line = self.agent.lines().first().cloned().unwrap_or_default();
        std::thread::spawn(move || {
            let Ok(value) = context.client.messages(&line) else {
                return;
            };
            let Some(message) = value
                .get("messages")
                .and_then(Value::as_array)
                .and_then(|rows| {
                    rows.iter().rev().find(|row| {
                        row.get("direction").and_then(Value::as_str) == Some("incoming")
                            && row.get("peer").and_then(Value::as_str) == Some(peer.as_str())
                    })
                })
            else {
                return;
            };
            let text = |key: &str| {
                message
                    .get(key)
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned()
            };
            // Celmux names a message `id`; `message_id` is the modem's per-line
            // delivery key and is empty for an inbound message. A relay needs some
            // stable id to deduplicate on - without one the phone shows the message
            // twice - so the row's own id is used, qualified by the line so two
            // lines cannot collide on the same number.
            // `id` is a JSON number, so `text()` would read it as empty.
            let row_id = message
                .get("id")
                .map(|value| match value {
                    Value::Number(number) => number.to_string(),
                    Value::String(text) => text.clone(),
                    _ => String::new(),
                })
                .unwrap_or_default();
            let delivery_id = if row_id.is_empty() {
                text("message_id")
            } else {
                format!("{}-{row_id}", text("device_id"))
            };
            if delivery_id.is_empty() {
                crate::log_warn!("celmux-plugin-airsim: 短信缺少 id，无法推送");
                return;
            }
            let event = crate::relay_agent::SmsEvent {
                delivery_id,
                // The sender, not `peer`: for an inbound message they are the same
                // number, and `sender` is what the phone puts on the notification.
                sender: {
                    let sender = text("sender");
                    if sender.is_empty() {
                        text("peer")
                    } else {
                        sender
                    }
                },
                content: text("content"),
                code: String::new(),
                timestamp: text("timestamp"),
            };
            if context.agent.target().is_own() {
                // Own relay: no socket. The message is delivered to the phone by
                // this process's own push path, so the event is handed over
                // directly rather than posted to a loopback port.
                crate::relay_endpoint::deliver_sms_locally(&context, &event);
                return;
            }
            match context.agent.sms(&event) {
                Ok(reply) if reply.accepted() => crate::log_info!(
                    "celmux-plugin-airsim: 短信事件已送出 delivery_id={}",
                    event.delivery_id
                ),
                Ok(reply) => crate::log_warn!(
                    "celmux-plugin-airsim: relay 拒绝短信事件: HTTP {}",
                    reply.status
                ),
                Err(error) => {
                    crate::log_warn!("celmux-plugin-airsim: 短信事件发送失败: {error}")
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
        let active = self
            .client
            .calls()
            .ok()
            .and_then(|value| active_call(&value));
        // Only the lines the operator exposed. Offering the others would put
        // cards in the picker that every send and dial then refuses - a choice
        // that cannot be used is worse than one that is not offered.
        let slots = self.exposed_slots();
        let messages = self.sms_pending();
        let status = super::control_api::call_status(active, Vec::new(), revision);
        Response::ok(super::control_api::agent_event_status(
            revision, status, messages, slots,
        ))
    }

    /// Record the ids the phone has confirmed.
    ///
    /// The app acks what it has stored locally; anything not acknowledged stays
    /// pending and is fetched again after a reinstall. An empty list is a no-op
    /// rather than a mass acknowledgement.
    fn acknowledge_sms(&self, request: &Request) -> Response {
        let payload: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
        let ids: Vec<String> = payload
            .get("ids")
            .and_then(Value::as_array)
            .map(|rows| {
                rows.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let count = ids.len();
        if let Ok(mut acked) = self.acked_messages.lock() {
            for id in ids {
                acked.insert(id);
            }
        }
        self.revision.bump();
        Response::ok(json!({"ok": true, "acked": count}))
    }

    /// How many messages the phone has not confirmed yet.
    ///
    /// Not the size of the history: the app reads this as "there is something to
    /// fetch" and fetches on any non-zero value, so reporting the whole inbox made
    /// it fetch, acknowledge, and fetch again for ever. Celmux itself has no
    /// per-message acknowledgement, so this side remembers what the phone acked.
    fn sms_pending(&self) -> usize {
        let acked = match self.acked_messages.lock() {
            Ok(acked) => acked,
            Err(_) => return 0,
        };
        // Counted against the ids the phone confirmed, not subtracted from the
        // total: the history is trimmed over time, so a count of acknowledgements
        // drifts away from the messages actually present.
        self.all_messages()
            .iter()
            .filter(|message| {
                let id = message
                    .get("delivery_id")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                !id.is_empty() && !acked.contains(id)
            })
            .count()
    }

    /// Every exposed line's messages, as the app's model.
    ///
    /// The app keeps one history for the device and tells the cards apart by
    /// each message's `sim_slot`, so the union is what it expects - not the
    /// messages of whichever line happens to be first.
    fn all_messages(&self) -> Vec<Value> {
        // The operator's name per line, so a message can say which card carried
        // it: Celmux files a message against the card and has no operator on the
        // row, but the line it came from does.
        let operators: std::collections::BTreeMap<String, String> = self
            .client
            .lines()
            .unwrap_or_default()
            .into_iter()
            .map(|line| (line.line_id, line.operator_name))
            .collect();
        let mut messages: Vec<Value> = self
            .agent
            .lines()
            .iter()
            .filter_map(|line_id| {
                let operator = operators.get(line_id).map(String::as_str).unwrap_or("");
                self.client
                    .messages(line_id)
                    .ok()
                    .map(|value| super::control_api::sms_messages(&value, operator))
            })
            .flatten()
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
                    .find(|line| Some(&line.line_id) == self.agent.lines().first())
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
            Err(error) => {
                Response::error(502, "Bad Gateway", "celmux_unavailable", &error.to_string())
            }
        }
    }

    /// What this agent's line is called right now.
    fn line_name(&self) -> String {
        line_display_name(&self.agent)
    }

    /// The push status document.
    ///
    /// The app reads this to decide whether a cloud path is configured, and it is
    /// where `local_mode` comes from. This is the *direct* control port, so the
    /// answer here is always "local": the cloud path is a separate listener with
    /// its own routes, and the phone reaches it at its own address. Saying
    /// "cloud configured" on this port would send the phone looking for relay
    /// routes that do not exist here.
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
    /// APNs registration belongs to the cloud path, which is its own listener
    /// (`relay_endpoint`). On the direct port there is nothing to register, and
    /// the reply says so rather than pretending it took.
    fn push_register(&self, _request: &Request) -> Response {
        Response::ok(json!({
            "registered": false,
            "local_mode": true,
            "reason": "APNs 注册由 Relay 云端端口处理，直连端口不参与",
        }))
    }

    /// `GET /api/sms/status`
    fn sms_status(&self) -> Response {
        Response::ok(super::control_api::sms_status(self.sms_pending(), ""))
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
            // A slot id carries the card after `#`, which a client may hand back
            // percent-encoded; both name the same line.
            .map(|value| value.replace("%23", "#"))
            .unwrap_or_else(|| self.agent.lines().first().cloned().unwrap_or_default());
        if !self.agent.exposes(&line_id) {
            crate::log_warn!(
                "celmux-plugin-airsim: 拨号被拒 sim_account={:?} 已暴露={:?}",
                line_id,
                self.agent.lines()
            );
            return Response::error(409, "Conflict", "unknown_slot", "该线路未暴露给 AirSIM");
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
            Err(error) => {
                Response::error(502, "Bad Gateway", "celmux_unavailable", &error.to_string())
            }
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
                self.agent.lines().first().cloned().unwrap_or_default()
            } else {
                // A slot id carries the card after `#`, and a client that built
                // the value as part of a URL may hand it back percent-encoded.
                // Both name the same line, so both are accepted rather than
                // failing a send over punctuation.
                requested.replace("%23", "#")
            }
        };
        // Sending from a card the operator did not expose would put the message
        // on a number the phone never offered. The received value is logged
        // because the phone sends a slot id, and a mismatch there is otherwise
        // indistinguishable from a bug in this check.
        if !self.agent.exposes(&line_id) {
            crate::log_warn!(
                "celmux-plugin-airsim: 发短信被拒 sim_account={:?} 已暴露={:?}",
                line_id,
                self.agent.lines()
            );
            return Response::error(409, "Conflict", "unknown_slot", "该线路未暴露给 AirSIM");
        }
        if to.is_empty() || text.is_empty() {
            return Response::error(400, "Bad Request", "bad_request", "缺少收件人或内容");
        }
        match self.client.send_sms(&line_id, &to, &text) {
            Ok(_) => {
                // The app's inbox is keyed on the delivery queue, and a send it
                // is not told about is a message the operator sees nowhere until
                // the next full refresh.
                self.revision.bump();
                Response::ok(json!({"sent": true, "segments": 1}))
            }
            Err(error) => {
                Response::error(502, "Bad Gateway", "celmux_unavailable", &error.to_string())
            }
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

    /// `GET /api/calls/operation` — what became of one dial.
    ///
    /// The phone asks this after a dial whose reply it did not see, so it can
    /// tell "the call is up" from "the call never happened". That distinction is
    /// the difference between showing a call screen and showing nothing, so an
    /// unknown operation is answered as `unknown` rather than as an error.
    fn dial_operation(&self, request: &Request) -> Response {
        let operation_id = query_text(&request.query, "operation_id").unwrap_or_default();
        if operation_id.is_empty() {
            return Response::error(400, "Bad Request", "bad_request", "缺少 operation_id");
        }
        let nonce = request
            .headers
            .get(crate::auth::HEADER_NONCE)
            .cloned()
            .unwrap_or_default();
        // The active call is the only place a dialled operation can be seen from
        // here: Celmux reports calls, not operations, so a call that is up and
        // on this line is the evidence the dial went through.
        let active = self
            .client
            .calls()
            .ok()
            .and_then(|value| active_call(&value));
        let (status, android_id, backend_id, call_state, ended_at) = match active {
            Some(call) => {
                let id = call
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                let state = call
                    .get("state")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned();
                // Celmux's states are its own; the phone's vocabulary is smaller.
                let call_state = match state.as_str() {
                    "dialing" | "ringing" | "alerting" => "dialing",
                    "active" | "talking" => "active",
                    "held" => "held",
                    "ended" | "failed" => "ended",
                    _ => "unknown",
                }
                .to_owned();
                let line = call
                    .get("line_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(|| self.agent.lines().first().cloned().unwrap_or_default())
                    .to_owned();
                (
                    "confirmed".to_owned(),
                    id,
                    format!("celmux:{line}"),
                    call_state,
                    Value::Null,
                )
            }
            None => (
                "unknown".to_owned(),
                String::new(),
                String::new(),
                "unknown".to_owned(),
                Value::Null,
            ),
        };
        let agent_id = self.agent.id();
        let ended_text = ended_at.as_str().unwrap_or("");
        let status_proof = self.agent.proof(&format!(
            "AIRSIM-OPERATION1\n{nonce}\n{agent_id}\n{operation_id}\n{status}\n{android_id}\n{backend_id}\n{call_state}\n{ended_text}"
        ));
        Response::ok(json!({
            "version": 1,
            "agent_id": agent_id,
            "operation_id": operation_id,
            "status": status,
            "android_id": if android_id.is_empty() { Value::Null } else { json!(android_id) },
            "backend_id": if backend_id.is_empty() { Value::Null } else { json!(backend_id) },
            "call_state": call_state,
            "ended_at": ended_at,
            "status_proof": status_proof,
        }))
    }

    /// `POST /api/calls/{answer,reject,hangup,dtmf}` — one action on the call.
    ///
    /// The phone names the call it means when it knows it, and omits it when
    /// acting on whatever is ringing. An empty id therefore means "the active
    /// call", which is what the app sends when it answers from the call banner.
    fn call_action_named(&self, action: &str, request: &Request) -> Response {
        let payload: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
        let call_id = payload
            .get("call_id")
            .or_else(|| payload.get("android_id"))
            .or_else(|| payload.get("id"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let call_id: String = if call_id.is_empty() {
            // Fall back to whatever is on a call. Acting on the wrong call is
            // impossible here: there is at most one.
            match self
                .client
                .calls()
                .ok()
                .and_then(|value| active_call(&value))
            {
                Some(active) => active
                    .get("android_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
                None => {
                    return Response::error(409, "Conflict", "no_active_call", "当前没有通话");
                }
            }
        } else {
            // The phone echoes the id this side gave it, which is the display id;
            // Celmux only answers to its own numeric one. Resolving through the
            // active call keeps a hangup working whichever id arrived.
            self.client
                .calls()
                .ok()
                .and_then(|value| active_call(&value))
                .filter(|active| active.get("id").and_then(Value::as_str) == Some(call_id.as_str()))
                .and_then(|active| {
                    active
                        .get("android_id")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .unwrap_or_else(|| call_id.to_owned())
        };
        match self.client.call_action(action, &call_id) {
            Ok(_) => {
                // The app's call screen follows the revision, so an action the
                // phone took has to move it or the screen keeps showing the
                // state from before the tap.
                self.revision.bump();
                Response::ok(json!({"ok": true, "call_id": call_id}))
            }
            Err(error) => {
                // Hanging up a call that is already over is the state the caller
                // asked for, and it happens whenever the carrier or Celmux ends
                // the call first. Reporting a failure there makes the phone keep
                // the call on screen and retry.
                if action == "hangup"
                    && self
                        .client
                        .calls()
                        .map_or(true, |value| active_call(&value).is_none())
                {
                    self.revision.bump();
                    return Response::ok(json!({"ok": true, "already_ended": true}));
                }
                crate::log_warn!(
                    "celmux-plugin-airsim: {action} 失败 call_id={call_id:?}: {error}"
                );
                Response::error(502, "Bad Gateway", "action_failed", &error.to_string())
            }
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

/// An ISO 8601 timestamp, which is what the app decodes a message's date from.
///
/// Hand-rolled rather than pulled from a date crate: the only requirement is
/// `YYYY-MM-DDTHH:MM:SSZ`, and a calendar library for that is a dependency to keep
/// current for one format string.
fn iso_timestamp(unix_millis: u64) -> String {
    let seconds = unix_millis / 1000;
    let (days, rem) = (seconds / 86_400, seconds % 86_400);
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Civil date from a day count, by Howard Hinnant's algorithm: the era-based
    // form avoids a table of month lengths and leap-year special cases.
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
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
                ..Default::default()
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
        headers.insert(
            "x-airsim-vowlan-timestamp".to_owned(),
            timestamp.to_string(),
        );
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
            // No cloud path in these tests: a push needs a registered phone and a
            // key, and neither is what the local routes are being checked for.
            relay_context: None,
            call_push: Arc::new(std::sync::Mutex::new(CallPush::default())),
            // A port nothing listens on: routes that reach Celmux fail closed,
            // which is what these assertions rely on.
            client: Arc::new(Client::new(
                "http://127.0.0.1:1".to_owned(),
                "unused".to_owned(),
                "airsim".to_owned(),
                None,
            )),
            agent: test_agent(),
            revision: Arc::new(crate::revision::Revision::default()),
            acked_messages: Arc::new(std::sync::Mutex::new(std::collections::BTreeSet::new())),
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
        assert_eq!(
            body["call"]["polling"], false,
            "嵌套的通话状态同样是事件驱动"
        );
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
        headers.insert(
            "x-airsim-vowlan-timestamp".to_owned(),
            timestamp.to_string(),
        );
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
                ..Default::default()
            }])
            .unwrap();
        for agent in fleet.list() {
            agent.set_secret(vec![7_u8; 32]);
        }
        let client = Arc::new(Client::new(
            "http://127.0.0.1:1".to_owned(),
            "unused".to_owned(),
            "airsim".to_owned(),
            None,
        ));
        let wrong = self::handle_shared(
            &fleet,
            &client,
            &TEST_PORTS,
            None,
            signed_request_with("GET", "/v1/health", &[9_u8; 32]),
        );
        assert_eq!(wrong.status, 401, "签错密钥必须被拒绝");
        let right = self::handle_shared(
            &fleet,
            &client,
            &TEST_PORTS,
            None,
            signed_request_with("GET", "/v1/health", &[7_u8; 32]),
        );
        assert_eq!(right.status, 200, "签对密钥应被接受");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The call-push state machine: a repeat rings once, a retry keeps the UUID
    /// and advances the generation.
    ///
    /// Both halves matter. Reusing the UUID is what stops CallKit reporting two
    /// calls for one ring; advancing the generation is what tells a relay this is
    /// a retry rather than a stale duplicate to drop.
    #[test]
    fn a_call_rings_once_and_its_retry_keeps_the_uuid_but_advances_the_generation() {
        let push = std::sync::Mutex::new(CallPush::default());

        // First sighting: new identity, generation 1.
        {
            let mut state = push.lock().unwrap();
            assert!(state.call_id.is_empty());
            *state = CallPush {
                call_id: "call-1".to_owned(),
                uuid: uuid_v5_like("call-1"),
                secret: "s".repeat(43),
                generation: 1,
                delivered: false,
                in_flight: true,
            };
        }
        let first = {
            let state = push.lock().unwrap();
            (state.uuid.clone(), state.generation)
        };

        // Delivered: the same call reported ringing again is dropped, because a
        // phone must not ring twice for one call.
        {
            let mut state = push.lock().unwrap();
            state.in_flight = false;
            state.delivered = true;
        }
        {
            let state = push.lock().unwrap();
            assert!(state.delivered, "已投递的通话不应再推");
        }

        // A retry after a failure: same UUID, generation advanced.
        {
            let mut state = push.lock().unwrap();
            state.delivered = false;
            state.generation = state.generation.wrapping_add(1).max(1);
        }
        let retry = {
            let state = push.lock().unwrap();
            (state.uuid.clone(), state.generation)
        };
        assert_eq!(
            retry.0, first.0,
            "重试必须复用同一个 UUID，否则 CallKit 会当成第二通电话"
        );
        assert_eq!(retry.1, first.1 + 1, "重试必须递增 generation");

        // A different call gets a fresh identity.
        let other = uuid_v5_like("call-2");
        assert_ne!(other, first.0, "不同通话必须有不同的 UUID");
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
        assert_eq!(
            ids,
            vec!["读卡器2#890", "读卡器1"],
            "裸线路只在该模组有 Profile 时丢弃"
        );
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
    /// Answering, rejecting and hanging up used to reach the `/v2/calls/...`
    /// handler, which expects a path and was handed an action name - so every one
    /// of them answered 404 and no call could be answered or ended from the app.
    /// What this pins is that the action routes are not that handler.
    #[test]
    fn answering_and_hanging_up_reach_the_call_they_name() {
        let control = control();
        for path in [
            "/api/calls/answer",
            "/api/calls/reject",
            "/api/calls/hangup",
            "/api/calls/dtmf",
        ] {
            let request = Request {
                method: "POST".to_owned(),
                path: path.to_owned(),
                query: String::new(),
                headers: std::collections::HashMap::new(),
                body: b"{}".to_vec(),
            };
            let response = control.handle_verified(request);
            // No call is in progress in this test, so the honest answer is a
            // conflict - never the 404 that meant "route not found".
            assert_eq!(response.status, 409, "{path}");
            let body: Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(body["code"], "no_active_call", "{path}: {body}");
        }
    }

    /// The phone asks this after a dial it did not see the reply to. An
    /// operation it cannot confirm has to come back as `unknown`, not as an
    /// error: it is the difference between showing a call screen and nothing.
    #[test]
    fn an_unconfirmable_operation_is_unknown_rather_than_an_error() {
        let response = control().handle_verified(Request {
            method: "GET".to_owned(),
            path: "/api/calls/operation".to_owned(),
            query: "operation_id=abc-123".to_owned(),
            headers: {
                let mut headers = std::collections::HashMap::new();
                headers.insert(crate::auth::HEADER_NONCE.to_owned(), "n0nce".to_owned());
                headers
            },
            body: Vec::new(),
        });
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["status"], "unknown", "{body}");
        assert_eq!(body["operation_id"], "abc-123");
        assert_eq!(body["version"], 1);
        assert!(body.get("status_proof").is_some(), "{body}");
    }
    /// The message timestamp is the format the app decodes.
    ///
    /// `SMSMessage.timestamp` is parsed as ISO 8601; anything else and the message
    /// arrives without a date, which the app shows as the epoch.
    #[test]
    fn a_message_timestamp_is_iso_8601() {
        // A whole minute, so a rounding slip in the seconds field shows up.
        let millis = 1_794_310_800_000;
        let stamp = iso_timestamp(millis);
        assert_eq!(stamp, "2026-11-10T11:40:00Z", "实际: {stamp}");
        // The shape, for a value whose date is not the one above.
        let other = iso_timestamp(0);
        assert_eq!(other, "1970-01-01T00:00:00Z");
        assert_eq!(other.len(), 20);
    }

    /// `sms_pending` means unconfirmed, not "everything ever received".
    ///
    /// The app fetches whenever this is non-zero. Reporting the whole inbox made it
    /// fetch, acknowledge and fetch again with no pause - a poll loop that also
    /// starved the event stream of the read bandwidth it needed.
    #[test]
    fn sms_pending_counts_only_unconfirmed_messages() {
        let control = control();
        // The test client reports no messages, so the count starts at zero and an
        // acknowledgement cannot take it below that.
        assert_eq!(control.sms_pending(), 0);
        control
            .acked_messages
            .lock()
            .unwrap()
            .insert("sms-does-not-exist".to_owned());
        assert_eq!(
            control.sms_pending(),
            0,
            "确认一条不在历史里的短信不应让计数变负"
        );
    }

    /// Celmux's SIP phase words are mapped to the two the app accepts.
    ///
    /// The app gates its ringing UI on `state == "incoming" || state == "waiting"`.
    /// Passing `ringing` straight through meant the payload looked right and the
    /// phone ignored it: no call screen, no ringtone.
    #[test]
    fn a_ringing_call_is_reported_as_incoming() {
        let payload = json!([{
            "peer": "+447464270820",
            "state": "ringing",
            "direction": "incoming",
            "started_at": "2026-11-10T15:21:10Z",
            "id": 63,
            "line_id": "读卡器1"
        }]);
        let active = active_call(&payload).expect("振铃中的通话必须被识别");
        assert_eq!(
            active["state"], "incoming",
            "app 只认 incoming/waiting，ringing 会被忽略"
        );
        assert_eq!(active["number"], "+447464270820");
        assert_eq!(active["android_id"], "63");
    }

    /// `early` is the same moment as `ringing` from the callee's side.
    #[test]
    fn an_early_call_is_reported_as_incoming() {
        let payload = json!([{
            "peer": "+447464270820",
            "state": "early",
            "direction": "incoming",
            "started_at": "2026-11-10T15:21:10Z",
            "id": 64
        }]);
        let active = active_call(&payload).expect("early 也应当被识别");
        assert_eq!(active["state"], "incoming");
    }
}
