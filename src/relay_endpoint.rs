// Copyright (c) 2026 anti-rainer
// SPDX-License-Identifier: MIT

//! The relay routes AirSIM's cloud path expects, served by this plugin.
//!
//! See [`crate::relay`] for why this process is the relay. This module is the
//! HTTP shape of it: five routes, each of which the phone calls with a body it
//! builds itself, and each of which answers with a document the phone decodes
//! strictly.
//!
//! Nothing here carries audio. A cloud call's media goes through the same PCM
//! gateway a direct call uses; the cloud path only decides how the phone reaches
//! the control plane. That is why the enqueue answer hands back a `media_url`
//! pointing at the PCM port - the phone then opens the same socket it would have
//! opened over the LAN.
//!
//! The routes are mounted on the settings listener, which is the one an operator
//! can put behind a reverse proxy: the phone requires `https`, and a proxy that
//! terminates TLS in front of this port is the smallest way to give it that.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::agents::Fleet;
use crate::http::{Request, Response};
use crate::relay::{AgentReport, SERVICE, State, VERSION};

/// What the relay needs to answer truthfully about the agent it fronts.
/// The settings a running process can adopt without being restarted.
#[derive(Clone, Default)]
pub struct LiveConfig {
    /// The id the phone binds its pairing to.
    pub agent_id: String,
    /// The PCM port a cloud call is handed; the same socket a direct call uses.
    pub pcm_port: u16,
    /// The line a command dials from when the phone does not name one.
    pub default_line: String,
    /// The push sender. Rebuilt when the APNs key or its identifiers change, so a
    /// key pasted into the settings page takes effect on the next push.
    pub pusher: Option<Arc<crate::apns::Pusher>>,
}

pub struct Context {
    pub state: Arc<State>,
    /// Celmux, for the line details the phone shows.
    pub client: Arc<crate::celmux::Client>,
    /// The values a settings change can replace while this process runs.
    ///
    /// Everything here used to be a plain field read straight off the config at
    /// startup, which made a settings page edit mean a restart. A restart drops
    /// the phone's registration and every open stream, so the values live behind a
    /// lock and the readers take a copy of the current one instead.
    pub live: Arc<std::sync::RwLock<LiveConfig>>,
    pub plugin_version: String,
    /// The agent half: where this plugin sends its events.
    ///
    /// Either this process's own relay or somebody else's, decided by
    /// `relay_target`. A single code path either way: the difference is only
    /// which side holds the APNs key.
    pub agent: Arc<crate::relay_agent::Agent>,
}

impl Context {
    /// The live settings, copied.
    fn live(&self) -> LiveConfig {
        self.live
            .read()
            .map(|live| live.clone())
            .unwrap_or_default()
    }

    fn agent_id(&self) -> String {
        self.live().agent_id
    }

    fn pcm_port(&self) -> u16 {
        self.live().pcm_port
    }

    fn default_line(&self) -> String {
        self.live().default_line
    }

    /// The push sender, or a stub that says why it cannot push.
    fn pusher(&self) -> Arc<crate::apns::Pusher> {
        self.live()
            .pusher
            .unwrap_or_else(|| Arc::new(crate::apns::Pusher::new("", "", "", "", false)))
    }

    /// The address the phone should post call-control requests to.
    ///
    /// Upstream puts its own origin in the dial response so a phone pointed at one
    /// relay never sends a control request to another. An externally configured
    /// relay is that origin; a self-hosted one has no configured address to offer,
    /// so the field is left out rather than invented - the phone then keeps using
    /// the address it was given.
    fn public_relay_url(&self) -> String {
        if self.agent.target().is_own() {
            String::new()
        } else {
            self.agent.target().base()
        }
    }
}

/// Answer one relay route, or `None` if this path is not one of them.
pub fn handle(context: &Context, fleet: &Arc<Fleet>, request: &Request) -> Option<Response> {
    let path = request
        .path
        .split('?')
        .next()
        .unwrap_or(request.path.as_str());
    let path = path.trim_start_matches('/');
    let route = [
        "healthz",
        "v1/devices/register",
        "v1/devices/status",
        "v1/events/heartbeat",
        "v2/commands/enqueue",
        "v2/calls/",
        "v2/commands/result",
        "v1/events/call",
        "v2/commands/pull",
        "v2/commands/complete",
        "api/push/status",
        "api/push/mode",
        "api/push/register",
    ]
    .into_iter()
    // A route ending in `/` is a prefix: the call-action paths carry the call's
    // UUID, so they cannot be enumerated as literals.
    .find(|route| path == *route || (route.ends_with('/') && path.starts_with(route)))?;
    match (request.method.as_str(), route) {
        ("GET", "healthz") => Some(health()),
        ("POST", "v1/devices/register") => Some(register(context, request)),
        ("POST", "v1/devices/status") => Some(status(context, fleet, request)),
        ("POST", "v1/events/heartbeat") => Some(heartbeat_route(context, fleet, request)),
        ("POST", "v2/commands/enqueue") => Some(enqueue(context, fleet, request)),
        // Call control: `POST /v2/calls/{uuid}/actions` and
        // `GET /v2/calls/{uuid}/actions/{command_id}`. The phone answers, rejects
        // and hangs up through these, and without them a call cannot be ended from
        // the handset at all - it stayed ringing until the operator gave up.
        _ if path.starts_with("v2/calls/") => Some(call_control(context, fleet, path, request)),
        ("POST", "v2/commands/result") => Some(result(context, request)),
        // The agent-side routes, for when this process is its own relay. They
        // exist so the agent half has exactly one destination shape whether the
        // relay is local or remote.
        ("POST", "v1/events/call") => Some(receive_call(context, request)),
        ("POST", "v2/commands/pull") => Some(pull_commands()),
        ("POST", "v2/commands/complete") => Some(complete_command(request)),
        ("GET", "api/push/status") => Some(push_status(context)),
        ("POST", "api/push/mode") => Some(push_mode(context, request)),
        ("POST", "api/push/register") => Some(push_register(context, request)),
        _ => Some(Response::error(
            405,
            "Method Not Allowed",
            "method_not_allowed",
            "该 Relay 路由不支持此方法",
        )),
    }
}
/// `GET healthz`
///
/// The phone checks three things before it will talk to a relay at all: `ok`,
/// the service name, and that a version string is present. A relay that answers
/// anything else is treated as the wrong server rather than a broken one.
fn health() -> Response {
    Response::ok(json!({
        "ok": true,
        "service": SERVICE,
        "version": VERSION,
    }))
}

/// `POST v1/devices/register`
///
/// The phone generates `device_id` and `device_secret` itself and registers them
/// here, so this stores credentials rather than issuing them. It answers
/// `{"registered": true}` and nothing else - the phone decodes exactly that.
fn register(context: &Context, request: &Request) -> Response {
    let body = match body_of(request) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let (device, first) = context.state.register(&body);
    if device.device_id.is_empty() || device.device_secret.is_empty() {
        // Two ways to land here: an empty credential, or an identity that is not
        // the one this gateway is bound to. The second is the case that matters -
        // a stranger who reached the port tried to enrol - so it is a refusal
        // with an explicit reason rather than an empty-field complaint.
        return Response::error(
            403,
            "Forbidden",
            "registration_refused",
            "注册被拒绝：本网关已绑定其他设备，或凭据为空",
        );
    }
    // The push tokens and bundle are recorded but never used: this relay sends no
    // pushes, because a plugin has no APNs credentials. They are kept and reported
    // so an operator can see the phone did register for them, and so a future push
    // path does not need a second registration format.
    crate::log_info!(
        "celmux-plugin-airsim: Relay 设备已注册 device_id={} bundle={} env={} voip_token={} relay_url={} first={first} at={:?}",
        device.device_id,
        device.bundle_id,
        device.environment,
        if device.voip_token.is_empty() {
            "无"
        } else {
            "有"
        },
        device.relay_url,
        device.registered_at
    );
    Response::ok(json!({"registered": true}))
}

/// `GET api/push/status`
///
/// The phone reads this before it writes APNs credentials anywhere. Answering
/// `local_mode: true` means "this gateway keeps its pairing locally", and the
/// phone then skips the write - which is what this relay wants, since it sends no
/// pushes and has nowhere to put a token.
fn push_status(context: &Context) -> Response {
    let ready = context.pusher().status().ready();
    Response::ok(json!({
        // `local_mode` is what decides whether the phone hands its APNs token
        // over. It stays true until a key exists: a phone that gave up its token
        // to a gateway which cannot push would stop keeping its own connection
        // open and then never hear about a call at all.
        "local_mode": !ready,
        "cloud_enabled": true,
        "configured": true,
        // A call push needs a key that APNs will accept. Saying `true` without one
        // would make the phone stop keeping its own connection open and wait for
        // pushes that never come.
        "call_push_ready": ready,
        "message_push_ready": false,
        "environment": if context.pusher().host().contains("sandbox") { "sandbox" } else { "production" },
        "relay_url": "",
        "last_error": context.pusher().status().reason().unwrap_or_default(),
    }))
}

/// `POST v1/events/call` — the agent side handing this relay a ringing call.
///
/// This is where the APNs key is used when this process is its own relay. The
/// event arrives authenticated as the phone, because the phone's record is what
/// carries the push token - the same rule an external relay applies, so the agent
/// half does not need to know which kind of relay it is talking to.
fn receive_call(context: &Context, request: &Request) -> Response {
    let body = match body_of(request) {
        Ok(body) => body,
        Err(response) => return response,
    };
    if !authenticated(context, &body) {
        return Response::error(401, "Unauthorized", "unauthorized", "device 凭据无效");
    }
    let text = |key: &str| {
        body.get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned()
    };
    let expires_at = text("expires_at");
    let call = crate::relay::IncomingCall {
        call_id: text("call_id"),
        call_uuid: text("call_uuid"),
        call_secret: text("call_secret"),
        number: text("number"),
        caller_name: text("caller_name"),
        generation: body.get("generation").and_then(Value::as_u64).unwrap_or(1),
        issued_at: text("issued_at"),
        expires_at: expires_at.clone(),
        expires_unix: expires_seconds(&expires_at),
        media_url: text("media_url"),
    };
    if call.call_id.is_empty() || call.call_uuid.is_empty() {
        return Response::error(
            400,
            "Bad Request",
            "invalid_call",
            "call_id 与 call_uuid 不能为空",
        );
    }
    // The push itself. Everything above decided whether to send it; this is the
    // only place in the plugin that uses the APNs key, which is what makes the
    // key unnecessary when the relay is somebody else's.
    let token = match context.state.voip_token() {
        Some(token) if !token.is_empty() => token,
        _ => {
            return Response::error(409, "Conflict", "no_token", "手机尚未注册推送 token");
        }
    };
    let mut payload = json!({
        "aps": {"content-available": 1},
        "event": "incoming_call",
        "agent_id": context.agent_id(),
        "call_id": call.call_id,
        "call_uuid": call.call_uuid,
        "generation": call.generation,
        "number": call.number,
        "caller_name": call.caller_name,
        "issued_at": call.issued_at,
        "expires_at": call.expires_at,
        "call_secret": call.call_secret,
        "media_transport": "legacy_pcm",
    });
    if !call.media_url.is_empty() {
        payload["media_url"] = json!(call.media_url);
    }
    let outcome = context
        .pusher()
        .push_voip(&token, &payload, &call.call_uuid, call.expires_unix);
    if !outcome.status.is_some_and(crate::apns::Outcome::accepted) {
        crate::log_warn!(
            "celmux-plugin-airsim: APNs 推送未受理 call_id={} {}",
            call.call_id,
            outcome.describe()
        );
        return Response::error(502, "Bad Gateway", "push_failed", &outcome.describe());
    }
    Response::ok(json!({"accepted": true, "call_id": call.call_id}))
}

/// Run one command a relay handed us, and report how it ended.
///
/// The relay is a queue, not an actor: it holds what the phone enqueued and waits
/// for this side to say what happened. Reporting the outcome is not optional -
/// a relay that never hears back keeps the command open, and the phone polls it
/// until it times out.
fn dispatch_pulled(context: &Arc<Context>, command: &Value) {
    let text = |key: &str| {
        command
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned()
    };
    let command_id = text("command_id");
    let kind = text("type");
    let number = text("number");
    let message = text("message");
    let line = match context.default_line().is_empty() {
        true => text("sim_account"),
        false => context.default_line().clone(),
    };
    let outcome = match kind.as_str() {
        "dial" => context.client.dial(&line, &number).map(|_| ()),
        "hangup" => context
            .client
            .call_action("hangup", &text("call_id"))
            .map(|_| ()),
        "answer" => context
            .client
            .call_action("answer", &text("call_id"))
            .map(|_| ()),
        // Upstream's name for it: the phone sends `send_sms`.
        "send_sms" | "sms" => context
            .client
            .send_sms(&line, &number, &message)
            .map(|_| ()),
        other => Err(crate::celmux::Error::Transport(format!(
            "不支持的命令类型: {other}"
        ))),
    };
    match outcome {
        Ok(()) => {
            crate::log_info!("celmux-plugin-airsim: 云端命令执行完成 {kind} {command_id}");
            let _ = context.agent.complete(&command_id, true, "");
        }
        Err(error) => {
            crate::log_warn!("celmux-plugin-airsim: 云端命令执行失败 {kind} {command_id}: {error}");
            let _ = context
                .agent
                .complete(&command_id, false, &error.to_string());
        }
    }
}

/// What the agent side signs an event with.
///
/// Three sources, in order of authority:
///
/// * the phone's own relay credential, captured at pairing - the only one that
///   can be right when the relay is somebody else's, because the phone generated
///   it and registered it there;
/// * the registered device, when this process is the relay and registered the
///   phone itself;
/// * an explicitly configured pair, for a phone paired before the claim's
///   credential was kept.
fn signing_credentials(context: &Arc<Context>) -> Option<crate::relay_agent::Credentials> {
    if let Some(relay) = context.state.phone_relay() {
        return Some(crate::relay_agent::Credentials {
            device_id: relay.device_id,
            device_secret: relay.device_secret,
        });
    }
    context.state.credentials().map(
        |(device_id, device_secret)| crate::relay_agent::Credentials {
            device_id,
            device_secret,
        },
    )
}

/// Deliver a received message to the phone, from this process's own relay.
///
/// The APNs side of an SMS event, kept next to the call path so both use the one
/// key. Only reached when this plugin is its own relay: an external relay does
/// this with its own key, and posting the event to ourselves over loopback would
/// be the plaintext path that does not exist here.
pub fn deliver_sms_locally(context: &Arc<Context>, event: &crate::relay_agent::SmsEvent) {
    let token = match context.state.alert_token() {
        Some(token) if !token.is_empty() => token,
        // Without an alert token there is no push channel for a message. The
        // phone still gets it on its next poll, so this is not an error.
        _ => return,
    };
    let payload = json!({
        "aps": {
            "alert": {"title": event.sender, "body": event.content},
            "sound": "default",
        },
        "event": "incoming_sms",
        "sender": event.sender,
        "content": event.content,
        "delivery_id": event.delivery_id,
        "timestamp": event.timestamp,
    });
    // An alert push is addressed to the bare bundle id, not `<bundle>.voip`: it is
    // an ordinary notification, and the wrong topic is answered `TopicDisallowed`.
    let outcome = context
        .pusher()
        .push_alert(&token, &payload, &event.delivery_id);
    crate::log_info!(
        "celmux-plugin-airsim: 短信推送 delivery_id={} {}",
        event.delivery_id,
        outcome.describe()
    );
}

/// `POST /v2/calls/{uuid}/actions` and its result route.
///
/// How the phone answers, rejects and hangs up. Without these a call placed through
/// the cloud path could not be ended from the handset: the phone had no route to
/// ask for it, so it rang until the operator gave up, and the next dial was refused
/// because the line was still busy.
fn call_control(context: &Context, fleet: &Arc<Fleet>, path: &str, request: &Request) -> Response {
    let rest = match path.strip_prefix("v2/calls/") {
        Some(rest) => rest,
        None => return Response::error(404, "Not Found", "not_found", "Relay 路由不存在"),
    };
    let mut segments = rest.split('/');
    let call_uuid = segments.next().unwrap_or("");
    let (second, third) = (segments.next(), segments.next());
    // Only `actions` and `actions/{command_id}` exist under this prefix.
    if second != Some("actions") {
        return Response::error(404, "Not Found", "not_found", "Relay 路由不存在");
    }
    // The UUID is in the path, so a malformed one cannot address a call.
    if !is_uuid(call_uuid) {
        return Response::error(400, "Bad Request", "invalid_call_uuid", "call UUID 无效");
    }

    if request.method == "GET" {
        // The phone polls this for the outcome. This agent runs the action inline, so
        // by the time it asks the answer is already known.
        let _ = third;
        return Response::ok(json!({
            "status": "done",
            "call_uuid": call_uuid,
        }));
    }

    let body = match body_of(request) {
        Ok(body) => body,
        Err(response) => return response,
    };
    if !authenticated(context, &body) {
        return Response::error(401, "Unauthorized", "unauthorized", "device 凭据无效");
    }
    let device_id = body.get("device_id").and_then(Value::as_str).unwrap_or("");
    let paired = fleet
        .list()
        .iter()
        .filter_map(|agent| agent.paired_device_id())
        .any(|id| id == device_id);
    if !paired {
        return Response::error(
            403,
            "Forbidden",
            "not_paired",
            "该设备未与本网关配对，不能控制通话",
        );
    }
    // Upstream's vocabulary, not SIP's: the phone sends these three.
    let action = body.get("action").and_then(Value::as_str).unwrap_or("");
    let command_id = body.get("command_id").and_then(Value::as_str).unwrap_or("");
    // Celmux numbers its calls itself and knows nothing of `outgoing-<uuid>`, so the
    // id the phone echoes back has to be resolved against the live call. Sending it
    // through was answered `call_id 无效`, which is why hanging up never worked.
    let requested = body.get("call_id").and_then(Value::as_str).unwrap_or("");
    let call_id = context
        .client
        .calls()
        .ok()
        .and_then(|value| live_call_id(&value, call_uuid))
        .or_else(|| Some(requested.to_owned()).filter(|id| !id.is_empty()))
        .unwrap_or_default();
    if call_id.is_empty() {
        return Response::error(404, "Not Found", "call_not_found", "没有正在进行的通话");
    }
    let verb = match action {
        "answer" => "answer",
        // A rejected incoming call and an ended one are the same act on the line.
        "reject" | "end" => "hangup",
        other => {
            return Response::error(
                400,
                "Bad Request",
                "invalid_action",
                &format!("不支持的通话动作: {other}"),
            );
        }
    };
    match context.client.call_action(verb, &call_id) {
        Ok(_) => {
            crate::log_info!(
                "celmux-plugin-airsim: 通话动作 {action} call_uuid={call_uuid} call_id={call_id} command_id={command_id}"
            );
            Response::ok(json!({
                "status": "accepted",
                "action": action,
                "call_id": call_id,
                "call_uuid": call_uuid,
                "command_id": command_id,
            }))
        }
        Err(error) => {
            crate::log_warn!("celmux-plugin-airsim: 通话动作失败 {action}: {error}");
            Response::error(502, "Bad Gateway", "call_action_failed", &error.to_string())
        }
    }
}

/// The id Celmux uses for the call the phone is acting on.
///
/// One call at a time per line, so the live entry is the answer; the phone's own id
/// is only a hint for choosing between several.
fn live_call_id(calls: &Value, call_uuid: &str) -> Option<String> {
    let rows = calls.as_array()?;
    let active = rows.iter().find(|call| {
        matches!(
            call.get("state").and_then(Value::as_str),
            Some("active") | Some("dialing") | Some("ringing") | Some("early")
        )
    })?;
    let _ = call_uuid;
    let id = active.get("id")?;
    Some(match id {
        Value::Number(number) => number.to_string(),
        Value::String(text) => text.clone(),
        _ => return None,
    })
}

/// Whether `value` is a hyphenated UUID, which is what the phone round-trips
/// through `UUID(uuidString:)`.
fn is_uuid(value: &str) -> bool {
    let groups: Vec<&str> = value.split('-').collect();
    groups.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(groups.iter())
            .all(|(length, group)| {
                group.len() == *length && group.chars().all(|c| c.is_ascii_hexdigit())
            })
}

/// `POST v2/commands/pull` — what the phone queued for this agent.
///
/// Nothing is queued here: this plugin's commands arrive over its own control
/// port from the phone directly, not through the relay's queue. Answering an
/// empty list rather than 404 keeps the agent half's loop uniform.
fn pull_commands() -> Response {
    Response::ok(json!({"commands": []}))
}

/// `POST v2/commands/complete` — how a pulled command ended.
fn complete_command(request: &Request) -> Response {
    match body_of(request) {
        Ok(body) => {
            let command_id = body.get("command_id").and_then(Value::as_str).unwrap_or("");
            Response::ok(json!({"ok": true, "command_id": command_id}))
        }
        Err(response) => response,
    }
}

/// `expires_at` as seconds since the epoch, for `apns-expiration`.
fn expires_seconds(text: &str) -> u64 {
    chrono::DateTime::parse_from_rfc3339(text)
        .map(|at| at.timestamp().max(0) as u64)
        // No usable expiry means the push is not stored at all, which is the safe
        // reading: a call that has already ended must not ring late.
        .unwrap_or(0)
}

/// `POST api/push/mode`
///
/// Enabling or disabling the cloud path. The mode is the operator's choice at the
/// phone, so this records nothing and confirms: the phone drives every cloud
/// request itself, and this relay has no schedule of its own to start.
fn push_mode(context: &Context, request: &Request) -> Response {
    let body = match body_of(request) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let enabled = body.get("enabled").and_then(Value::as_bool).unwrap_or(true);
    crate::log_info!(
        "celmux-plugin-airsim: Relay 云端模式 {}",
        if enabled { "开启" } else { "关闭" }
    );
    if enabled {
        // A heartbeat right away, so the directory the phone is about to read
        // already has this agent online instead of waiting a full interval.
        context.state.heartbeat(&json!({}));
    }
    Response::ok(json!({"ok": true, "enabled": enabled}))
}

/// `POST api/push/register`
///
/// APNs token registration. This relay sends no pushes - a plugin has no APNs
/// credentials - so nothing is stored and the answer says so. Reporting success
/// would make the phone wait for pushes that never arrive.
fn push_register(context: &Context, request: &Request) -> Response {
    let body = match body_of(request) {
        Ok(body) => body,
        Err(response) => return response,
    };
    // A registration carries the same device credentials every other route uses,
    // so it is authenticated the same way rather than accepted anonymously.
    if body.get("device_id").is_some() && !authenticated(context, &body) {
        return Response::error(401, "Unauthorized", "unauthorized", "device 凭据无效");
    }
    // The token is kept whatever the key situation: an operator who adds a p8
    // tomorrow should not have to make the phone register again.
    let stored = context.state.store_push_tokens(&body);
    let ready = context.pusher().status().ready();
    Response::ok(json!({
        "registered": stored && ready,
        "local_mode": !ready,
        "reason": context.pusher().status().reason().unwrap_or_default(),
    }))
}

/// Tell one phone that a call is coming in.
///
/// The payload is read field by field out of `payload.dictionaryPayload` by the
/// app, so these names are the contract, not a preference: `event` must be
/// `incoming_call`, `call_uuid` must parse as a UUID, and `expires_at` is compared
/// against the phone's clock - an expired push is dropped silently, which is what
/// keeps a late push from ringing a phone after the caller gave up.
pub fn push_incoming_call(
    context: &Arc<Context>,
    call: &crate::relay::IncomingCall,
) -> crate::apns::Outcome {
    // A self-hosted relay already knows the phone it registered, so the agent can
    // sign as it without being configured. An explicitly configured pair is not
    // overwritten: an external relay needs the registration it holds itself.
    if let Some(credentials) = signing_credentials(context) {
        context.agent.adopt(credentials);
    }
    // Own relay: the push happens here, with this process's key, without an event
    // becoming a socket. This is why no plaintext HTTP path exists.
    if context.agent.target().is_own() {
        let body = json!({
            "device_id": context.agent.credentials().device_id,
            "device_secret": context.agent.credentials().device_secret,
            "call_id": call.call_id,
            "call_uuid": call.call_uuid,
            "call_secret": call.call_secret,
            "number": call.number,
            "caller_name": call.caller_name,
            "generation": call.generation,
            "issued_at": call.issued_at,
            "expires_at": call.expires_at,
            "media_url": call.media_url,
        });
        let request = Request {
            method: "POST".to_owned(),
            path: "/v1/events/call".to_owned(),
            query: String::new(),
            headers: std::collections::HashMap::new(),
            body: serde_json::to_vec(&body).unwrap_or_default(),
        };
        let response = receive_call(context, &request);
        let accepted = response.status == 200;
        crate::log_info!(
            "celmux-plugin-airsim: 来电事件本地派发 call_id={} status={}",
            call.call_id,
            response.status
        );
        return crate::apns::Outcome {
            status: Some(if accepted { 200 } else { response.status }),
            reason: if accepted {
                String::new()
            } else {
                String::from_utf8_lossy(&response.body).into_owned()
            },
            apns_id: String::new(),
        };
    }
    // Somebody else's relay: the event travels there over HTTPS and their key
    // does the push. This installation needs no APNs key in that case.
    if let Err(error) = context.agent.call(call) {
        crate::log_warn!(
            "celmux-plugin-airsim: 来电事件发送失败 call_id={}: {error}",
            call.call_id
        );
        return crate::apns::Outcome {
            status: None,
            reason: error,
            apns_id: String::new(),
        };
    }
    crate::log_info!(
        "celmux-plugin-airsim: 来电事件已送往外接 relay call_id={} relay={}",
        call.call_id,
        context.agent.target().base()
    );
    crate::apns::Outcome {
        status: Some(202),
        reason: String::new(),
        apns_id: String::new(),
    }
}

/// `POST v1/events/heartbeat`
///
/// The upstream agent sends this every 120 s and the phone counts an agent online
/// for 150 s after the last one, which is why this route exists at all: without it
/// every other route answers correctly and the self-test still fails on "Agent
/// 心跳".
/// Keep this agent's own heartbeat fresh.
///
/// This process is both the agent and the relay, so no outside party would ever
/// report in on its behalf. Without this timer the directory answers every request
/// correctly and still says "心跳过期", because the last heartbeat was whenever the
/// phone last happened to touch it - and the phone's self-test reads exactly that.
pub fn spawn_heartbeat(context: Arc<Context>) {
    // The command poller runs on its own thread: a pull that blocks for a relay's
    // timeout must not delay the heartbeat, which is what the phone reads to
    // decide whether this gateway is alive.
    if !context.agent.target().is_own() {
        let polling = Arc::clone(&context);
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
                if let Some(credentials) = signing_credentials(&polling) {
                    polling.agent.adopt(credentials);
                }
                if !polling.agent.ready() {
                    continue;
                }
                match polling.agent.pull() {
                    Ok(reply) if reply.accepted() => {
                        let commands = reply
                            .body
                            .get("commands")
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_default();
                        for command in commands {
                            dispatch_pulled(&polling, &command);
                        }
                    }
                    Ok(reply) => crate::log_warn!(
                        "celmux-plugin-airsim: relay 拒绝命令拉取: HTTP {}",
                        reply.status
                    ),
                    // A relay that is temporarily unreachable is not an error worth
                    // a line every five seconds.
                    Err(_) => {}
                }
            }
        });
    }
    std::thread::spawn(move || {
        loop {
            let report = crate::relay::self_report();
            // The same check a relay applies. Failing here would mean this side is
            // about to have every heartbeat rejected, which is worth knowing from
            // its own log rather than from the relay's.
            let state = report
                .get("cellular_state")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !crate::relay::valid_cellular_state(state) {
                crate::log_warn!(
                    "celmux-plugin-airsim: 心跳 cellular_state 不合法（{state}），relay 会拒绝"
                );
            }
            // Local state first: the directory this process serves must be right
            // even when the configured relay is far away or down.
            context.state.heartbeat(&report);
            // Then the relay, when it is somebody else's. Our own was recorded by
            // the line above: there is nothing to send and no socket to open.
            if !context.agent.target().is_own() {
                if let Some(credentials) = signing_credentials(&context) {
                    context.agent.adopt(credentials);
                }
                match context.agent.heartbeat(&report) {
                    Ok(reply) if reply.accepted() => {}
                    Ok(reply) => crate::log_warn!(
                        "celmux-plugin-airsim: 外部 relay 拒绝心跳: HTTP {}",
                        reply.status
                    ),
                    Err(error) => {
                        crate::log_warn!("celmux-plugin-airsim: 心跳发送失败: {error}")
                    }
                }
            }
            std::thread::sleep(crate::relay::HEARTBEAT_INTERVAL);
        }
    });
}

fn heartbeat_route(context: &Context, fleet: &Arc<Fleet>, request: &Request) -> Response {
    let body = match body_of(request) {
        Ok(body) => body,
        Err(response) => return response,
    };
    if !authenticated(context, &body) {
        return Response::error(401, "Unauthorized", "unauthorized", "device 凭据无效");
    }
    // Only the paired phone reports for this gateway. A stranger's heartbeat would
    // move the operator's agent in and out of the window the phone reads, which is
    // the one thing this route is trusted for.
    let device_id = body.get("device_id").and_then(Value::as_str).unwrap_or("");
    let paired = fleet
        .list()
        .iter()
        .filter_map(|agent| agent.paired_device_id())
        .any(|id| id == device_id);
    if !paired {
        return Response::error(
            403,
            "Forbidden",
            "not_paired",
            "该设备未与本网关配对，不能上报心跳",
        );
    }
    context.state.heartbeat(&body);
    Response::ok(json!({"ok": true}))
}

/// `POST v1/devices/status`
///
/// The directory the phone's self-test reads, and the only place it learns
/// whether this agent is online. Online means a heartbeat inside the window the
/// phone counts, not merely that the process is up: reporting this plugin online
/// without a heartbeat would make the phone's check meaningless.
fn status(context: &Context, fleet: &Arc<Fleet>, request: &Request) -> Response {
    let body = match body_of(request) {
        Ok(body) => body,
        Err(response) => return response,
    };
    // The directory names the operator's number and carrier. Only the paired phone
    // has any business reading it: a device that merely registered is a stranger,
    // and this route used to hand it the number anyway.
    let device_id = body.get("device_id").and_then(Value::as_str).unwrap_or("");
    let paired = fleet
        .list()
        .iter()
        .filter_map(|agent| agent.paired_device_id())
        .any(|id| id == device_id);
    if !paired {
        if !authenticated(context, &body) {
            return Response::error(401, "Unauthorized", "unauthorized", "device 凭据无效");
        }
        // A registered device gets a truthful, empty answer rather than a refusal:
        // the phone's own self-test asks this route, and telling it "no such route"
        // would read as a relay fault.
        return Response::ok(json!({
            "ok": true,
            "cloud_online": false,
            "agents": [],
            "at_ok": false,
        }));
    }
    if !authenticated(context, &body) {
        return Response::error(401, "Unauthorized", "unauthorized", "device 凭据无效");
    }
    Response::ok(context.state.status(&report(context, fleet)))
}

/// The UUID a call is known by.
///
/// Derived from the command id so a retried enqueue names the same call instead of
/// minting a second identity the phone would treat as a different call.
fn call_uuid_for(command_id: &str) -> String {
    crate::control::uuid_v5_like(command_id)
}

/// `POST v2/commands/enqueue`
///
/// The phone asks this agent to dial, send, or act on a call. The answer has to
/// carry the call identity the phone will use for media, and it is decoded
/// strictly: a missing `call` or `media_url` makes the phone treat the command as
/// unsupported and never place the call.
///
/// `media_url` points at the PCM port, so the phone opens the same audio socket
/// it would have opened over the LAN - the cloud path differs only in which
/// address the control plane is reached at.
fn enqueue(context: &Context, fleet: &Arc<Fleet>, request: &Request) -> Response {
    let body = match body_of(request) {
        Ok(body) => body,
        Err(response) => return response,
    };
    if !authenticated(context, &body) {
        return Response::error(401, "Unauthorized", "unauthorized", "device 凭据无效");
    }
    // Registering proves only that the caller knows the secret it invented. Acting
    // on the operator's SIM is reserved for the phone that paired: otherwise any
    // stranger who registers can dial out and send messages on these lines.
    let device_id = body.get("device_id").and_then(Value::as_str).unwrap_or("");
    let paired = fleet
        .list()
        .iter()
        .filter_map(|agent| agent.paired_device_id())
        .any(|id| id == device_id);
    if !paired {
        crate::log_warn!(
            "celmux-plugin-airsim: Relay 拒绝命令：device_id={device_id} 不是已配对的手机"
        );
        return Response::error(
            403,
            "Forbidden",
            "not_paired",
            "该设备未与本网关配对，不能控制线路",
        );
    }
    let command = context.state.enqueue(&body);
    if command.command_id.is_empty() {
        return Response::error(400, "Bad Request", "bad_command", "command_id 不能为空");
    }
    let agent = report(context, fleet);
    crate::log_info!(
        "celmux-plugin-airsim: Relay 命令 {} command_id={} number={}",
        command.kind,
        command.command_id,
        command.number
    );
    // The call identity is derived from the command so a retried enqueue for the
    // same command names the same call, which is what the phone's dial receipt
    // expects.
    // The command runs here rather than being handed back to the phone: the phone
    // enqueued it precisely so this agent would act. It is dispatched after the
    // answer is composed, because a dial can take a second and the phone's
    // enqueue timeout is short.
    let dispatch = Dispatch {
        state: Arc::clone(&context.state),
        client: Arc::clone(&context.client),
        command: command.clone(),
        line: context.default_line().clone(),
        agent_id: context.agent_id().clone(),
    };
    std::thread::spawn(move || dispatch.run());
    let call_id = format!("outgoing-{}", command.command_id);
    // The call identity the phone will use for every later control request. It has
    // to be a real UUID: the phone's control client does
    // `UUID(uuidString: envelope.callUUID)` and silently drops the call when that
    // fails, which is the "missing call_uuid" the operator sees.
    let call_uuid = call_uuid_for(&command.command_id);
    Response::ok(json!({
        "accepted": true,
        "command_id": command.command_id,
        "status": "accepted",
        // The phone will not place the call unless the agent it enqueued on is
        // the one answering, so this is the gateway's own liveness.
        "agent_connected": true,
        "call": {
            "agent_id": agent.id,
            "call_id": call_id.clone(),
            "call_uuid": call_uuid.clone(),
            "generation": 1,
            "direction": "outgoing",
            // Where the phone sends `POST /v2/calls/{uuid}/actions`. Upstream
            // carries its own origin here so a phone pointed at one relay never
            // posts a control request to another.
            "relay_url": context.public_relay_url(),
            // The phone signs its media handshake with this; the PCM gateway
            // already authenticates with the pairing secret, so it is the same
            // credential the direct path uses rather than a second one.
            "call_secret": "",
            "media_url": format!("tcp://{}:{}", agent.name, context.pcm_port()),
            "media_transport": "legacy_pcm",
        },
    }))
}

/// `POST v2/commands/result`
///
/// How a command ended. The phone polls this after enqueuing; `completed` and
/// `failed` are the two states it stops on.
fn result(context: &Context, request: &Request) -> Response {
    let body = match body_of(request) {
        Ok(body) => body,
        Err(response) => return response,
    };
    if !authenticated(context, &body) {
        return Response::error(401, "Unauthorized", "unauthorized", "device 凭据无效");
    }
    let command_id = body
        .get("command_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_owned();
    let Some(command) = context.state.command(&command_id) else {
        return Response::ok(json!({
            "command_id": command_id,
            "status": "failed",
            "error": "未知命令",
        }));
    };
    Response::ok(json!({
        "command_id": command.command_id,
        "status": command.status,
        "result": if command.status == "completed" {
            json!({"dialing": command.kind == "dial", "sent": command.kind == "send_sms"})
        } else {
            Value::Null
        },
        "error": if command.error.is_empty() { Value::Null } else { json!(command.error) },
    }))
}

/// One enqueued command, on its way to Celmux.
///
/// It runs on its own thread: the phone waits a short time for the enqueue answer
/// and a dial takes longer than that, so the answer goes out first and the outcome
/// is left for the phone to poll.
struct Dispatch {
    state: Arc<State>,
    client: Arc<crate::celmux::Client>,
    command: crate::relay::Command,
    line: String,
    agent_id: String,
}

impl Dispatch {
    /// Whether the command was addressed to this agent.
    fn target_matches(&self) -> bool {
        // An empty target predates per-agent routing; this gateway only ever had
        // one agent, so it is its own.
        self.command.target_agent_id.is_empty() || self.command.target_agent_id == self.agent_id
    }

    fn run(self) {
        // A command that named another agent is not this agent's to run. Refusing
        // it is the difference between "the phone asked the wrong device" and a
        // command silently executing here.
        if !self.target_matches() {
            self.state
                .complete(&self.command.command_id, "failed", "命令目标不是本 Agent");
            return;
        }
        // The phone names the slot it wants when it has several, which is how one
        // gateway serves more than one card. An unnamed slot is this agent's own.
        let line = if self.command.sim_account.is_empty() {
            self.line.clone()
        } else {
            self.command.sim_account.replace("%23", "#")
        };
        let outcome = match self.command.kind.as_str() {
            "dial" => self.client.dial(&line, &self.command.number).map(|_| ()),
            "send_sms" => self
                .client
                .send_sms(&line, &self.command.number, &self.command.message)
                .map(|_| ()),
            // Call actions name the call the phone is already on, which this side
            // resolves from the live registry rather than from the command.
            action @ ("answer" | "hangup" | "reject" | "dtmf") => {
                let call_id = self
                    .client
                    .calls()
                    .ok()
                    .and_then(|value| command_call_id(&value))
                    .unwrap_or_default();
                self.client.call_action(action, &call_id).map(|_| ())
            }
            other => {
                self.state.complete(
                    &self.command.command_id,
                    "failed",
                    &format!("不支持的命令: {other}"),
                );
                return;
            }
        };
        match outcome {
            Ok(()) => self
                .state
                .complete(&self.command.command_id, "completed", ""),
            Err(error) => {
                self.state
                    .complete(&self.command.command_id, "failed", &error.to_string())
            }
        }
    }
}

/// The call a command action applies to: the one currently up.
fn command_call_id(value: &Value) -> Option<String> {
    let rows = value
        .as_array()
        .or_else(|| value.get("calls").and_then(Value::as_array))?;
    rows.iter().find_map(|row| {
        let state = row.get("state").and_then(Value::as_str)?;
        if !matches!(state, "active" | "ringing" | "dialing") {
            return None;
        }
        row.get("id").and_then(|value| match value {
            Value::Number(number) => Some(number.to_string()),
            Value::String(text) => Some(text.clone()),
            _ => None,
        })
    })
}

/// What this relay reports about the agent it fronts.
///
/// The name comes from the exposed line, because that is what the phone shows and
/// which card a call would go out on. It is computed per request rather than
/// cached: exposing a different line or changing a card renames the agent, and a
/// stale name is what makes an operator look at the wrong device.
fn report(context: &Context, fleet: &Arc<Fleet>) -> AgentReport {
    let agent = fleet.list().first().cloned();
    let name = agent.as_ref().map(|agent| agent.name()).unwrap_or_default();
    // The number comes from the line the agent carries, which only Celmux knows.
    // An unreachable Celmux leaves it empty rather than failing the directory: a
    // phone that cannot see its device number is better off than one that cannot
    // see the device at all.
    let number = context
        .client
        .lines()
        .ok()
        .and_then(|lines| {
            lines.into_iter().find(|line| {
                agent.as_ref().is_some_and(|a| {
                    a.lines()
                        .first()
                        .is_some_and(|first| *first == line.line_id)
                })
            })
        })
        .map(|line| line.local_phone)
        .unwrap_or_default();
    AgentReport {
        id: context.agent_id().clone(),
        name,
        model: "celmux".to_owned(),
        number,
        version: context.plugin_version.clone(),
        at_ok: true,
    }
}

fn authenticated(context: &Context, body: &Value) -> bool {
    let device_id = body.get("device_id").and_then(Value::as_str).unwrap_or("");
    let secret = body
        .get("device_secret")
        .and_then(Value::as_str)
        .unwrap_or("");
    context.state.authenticates(device_id, secret)
}

fn body_of(request: &Request) -> Result<Value, Response> {
    serde_json::from_slice(&request.body).map_err(|error| {
        Response::error(
            400,
            "Bad Request",
            "bad_request",
            &format!("请求格式错误: {error}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(method: &str, path: &str, body: Value) -> Request {
        Request {
            method: method.to_owned(),
            path: path.to_owned(),
            query: String::new(),
            headers: std::collections::HashMap::new(),
            body: body.to_string().into_bytes(),
        }
    }

    /// A fleet with one agent, paired as `device_id`.
    ///
    /// The relay routes now distinguish the paired phone from a device that merely
    /// registered, so a test about the paired phone's own behaviour needs one.
    fn paired_fleet(device_id: &str) -> Arc<Fleet> {
        let fleet = Arc::new(Fleet::default());
        fleet
            .reconcile(vec![crate::agents::AgentConfig {
                lines: vec!["line-1".to_owned()],
                expose_all_lines: false,
                name: "Celmux".to_owned(),
                id: "celmux".to_owned(),
            }])
            .expect("fleet");
        for agent in fleet.list() {
            agent.set_relay_credentials(
                device_id.to_owned(),
                "paired-secret".to_owned(),
                String::new(),
            );
        }
        fleet
    }

    fn context() -> Context {
        Context {
            // A relay of its own on a port nothing listens on: the routes under
            // test answer locally and never reach the agent side.
            agent: Arc::new(crate::relay_agent::Agent::new(
                crate::relay_agent::Target::from_mode("", "", 1),
                crate::relay_agent::Credentials::default(),
                "celmux",
            )),
            // No key in these tests: the routes under test do not push, and the
            // ones that report push readiness are asserting the no-key answer.
            live: Arc::new(std::sync::RwLock::new(LiveConfig {
                agent_id: "celmux".to_owned(),
                pcm_port: 8643,
                default_line: "读卡器1".to_owned(),
                pusher: Some(Arc::new(crate::apns::Pusher::new(
                    "",
                    "",
                    "",
                    "com.test.app",
                    false,
                ))),
            })),
            state: Arc::new(State::default()),
            client: Arc::new(crate::celmux::Client::new(
                "http://127.0.0.1:1".to_owned(),
                "unused".to_owned(),
                "airsim".to_owned(),
                None,
            )),
            plugin_version: "0.2.0".to_owned(),
        }
    }

    fn body_of_response(response: &Response) -> Value {
        serde_json::from_slice(&response.body).unwrap()
    }

    /// `healthz` is checked verbatim by the phone: a wrong service name makes it
    /// treat this relay as the wrong server rather than a broken one.
    #[test]
    fn healthz_answers_the_service_name_the_phone_requires() {
        let context = context();
        let fleet = Arc::new(Fleet::default());
        let response = handle(&context, &fleet, &request("GET", "/healthz", json!({}))).unwrap();
        let body = body_of_response(&response);
        assert_eq!(body["ok"], json!(true));
        assert_eq!(body["service"], json!(SERVICE));
        assert!(!body["version"].as_str().unwrap_or("").is_empty());
    }

    /// Registration stores the credentials the phone generated, and a status
    /// query without them is refused rather than answered with a directory.
    #[test]
    fn the_directory_is_refused_without_the_registered_credentials() {
        let context = context();
        let fleet = paired_fleet("d1");

        let registered = handle(
            &context,
            &fleet,
            &request(
                "POST",
                "/v1/devices/register",
                json!({"device_id": "d1", "device_secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "voip_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}),
            ),
        )
        .unwrap();
        assert_eq!(body_of_response(&registered)["registered"], json!(true));

        let anonymous = handle(
            &context,
            &fleet,
            &request("POST", "/v1/devices/status", json!({"device_id": "d1", "device_secret": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "voip_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})),
        )
        .unwrap();
        assert_eq!(anonymous.status, 401);

        let directory = handle(
            &context,
            &fleet,
            &request("POST", "/v1/devices/status", json!({"device_id": "d1", "device_secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "voip_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})),
        )
        .unwrap();
        let body = body_of_response(&directory);
        assert_eq!(body["agents"][0]["agent_id"], json!("celmux"));
        assert_eq!(body["capabilities"]["agent_command_routing"], json!(1));
    }

    /// A heartbeat is what makes the agent online; the phone reports an agent
    /// whose heartbeat is stale as offline, so this is the one state the
    /// directory must not guess.
    #[test]
    fn a_heartbeat_is_what_makes_the_agent_online() {
        let context = context();
        let fleet = paired_fleet("d1");
        context
            .state
            .register(&json!({"device_id": "d1", "device_secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "voip_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}));
        let credentials = json!({"device_id": "d1", "device_secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "voip_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"});

        let before = body_of_response(
            &handle(
                &context,
                &fleet,
                &request("POST", "/v1/devices/status", credentials.clone()),
            )
            .unwrap(),
        );
        assert_eq!(before["cloud_online"], json!(false));

        let beat = handle(
            &context,
            &fleet,
            &request(
                "POST",
                "/v1/events/heartbeat",
                json!({"device_id": "d1", "device_secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "at_ok": true}),
            ),
        )
        .unwrap();
        assert_eq!(beat.status, 200);

        let after = body_of_response(
            &handle(
                &context,
                &fleet,
                &request("POST", "/v1/devices/status", credentials),
            )
            .unwrap(),
        );
        assert_eq!(after["cloud_online"], json!(true));
        assert_eq!(after["agents"][0]["cloud_online"], json!(true));
    }

    /// A registration is trusted by its credential, not by a shared path.
    ///
    /// The phone derives `device_id` from SHA-256 over its `device_secret`, so an
    /// id is not a name it picks: re-presenting a known id has to present the same
    /// secret. That is the upstream relay's rule, and it replaced a shared path
    /// segment - which defended the port but could not tell a second legitimate
    /// device from an intruder - and a first-registration lock, which shut the
    /// port behind the first phone.
    #[test]
    fn a_known_device_must_present_its_own_secret_and_a_new_one_is_let_in() {
        let context = context();
        let fleet = Arc::new(Fleet::default());
        let register = |body: serde_json::Value| {
            handle(
                &context,
                &fleet,
                &request("POST", "v1/devices/register", body),
            )
        };

        let accepted = register(json!({
            "device_id": "d1",
            "device_secret": "0123456789abcdef0123",
            "voip_token": "a".repeat(64),
        }))
        .expect("route exists");
        assert_eq!(body_of_response(&accepted)["registered"], json!(true));

        // The same id with a different secret is an impostor.
        let impostor = register(json!({
            "device_id": "d1",
            "device_secret": "ffffffffffffffffffff",
            "voip_token": "b".repeat(64),
        }))
        .expect("route exists");
        assert_eq!(impostor.status, 403);

        // A different phone is a different id with its own credential, and the
        // port is not closed to it: two devices may share one relay.
        let second = register(json!({
            "device_id": "d2",
            "device_secret": "abcdef0123456789abcd",
            "voip_token": "c".repeat(64),
        }))
        .expect("route exists");
        assert_eq!(body_of_response(&second)["registered"], json!(true));
    }

    /// The phone only writes APNs credentials when a gateway says it does not
    /// keep its pairing locally. Saying so here is what stops that write; the
    /// relay has nowhere to put a token and sends no pushes.
    #[test]
    fn push_status_tells_the_phone_to_keep_its_pairing_local() {
        let context = context();
        let fleet = Arc::new(Fleet::default());
        let status = handle(
            &context,
            &fleet,
            &request("GET", "api/push/status", json!({})),
        )
        .unwrap();
        let body = body_of_response(&status);
        assert_eq!(body["local_mode"], json!(true));
        // No ready push channel, and no relay address for the phone to call back:
        // both are part of how the phone decides the pairing stays local.
        assert_eq!(body["call_push_ready"], json!(false));
        assert_eq!(body["message_push_ready"], json!(false));
        assert_eq!(body["relay_url"], json!(""));

        // A push registration is accepted and honestly ignored.
        let registered = handle(
            &context,
            &fleet,
            &request("POST", "api/push/register", json!({"voip_token": "abc"})),
        )
        .unwrap();
        assert_eq!(body_of_response(&registered)["registered"], json!(false));
    }

    /// Turning the cloud path on makes the agent online at once, so the
    /// directory the phone reads next is not empty for a full heartbeat interval.
    #[test]
    fn enabling_cloud_mode_reports_this_agent_online_immediately() {
        let context = context();
        let fleet = Arc::new(Fleet::default());
        assert!(!context.state.online());
        let response = handle(
            &context,
            &fleet,
            &request("POST", "api/push/mode", json!({"enabled": true})),
        )
        .unwrap();
        assert_eq!(response.status, 200);
        assert!(context.state.online());
    }

    /// A route this relay does not serve is not its business: the settings
    /// listener still has to answer its own paths.
    #[test]
    fn another_path_is_left_to_the_next_handler() {
        let context = context();
        let fleet = Arc::new(Fleet::default());
        assert!(handle(&context, &fleet, &request("GET", "/api/status", json!({}))).is_none());
        // The right path with the wrong method is an error, not a fall-through.
        let wrong = handle(
            &context,
            &fleet,
            &request("GET", "/v1/devices/status", json!({})),
        )
        .unwrap();
        assert_eq!(wrong.status, 405);
    }
    /// A registered stranger may not act on the lines.
    ///
    /// This is the gap that open registration leaves: any id that registers knows
    /// its own secret, so a credential check passes for it. What it cannot have is
    /// the identity the operator paired - that one was read off a screen. Without
    /// this check a stranger dials out on the operator's SIM.
    #[test]
    fn a_stranger_who_registered_cannot_dial() {
        let context = context();
        // One agent, paired as "paired-phone" - the identity an operator read off
        // a screen.
        let fleet = Arc::new(Fleet::default());
        fleet
            .reconcile(vec![crate::agents::AgentConfig {
                lines: vec!["line-1".to_owned()],
                expose_all_lines: false,
                name: "Celmux".to_owned(),
                id: "celmux".to_owned(),
            }])
            .expect("fleet");
        for agent in fleet.list() {
            agent.set_relay_credentials(
                "paired-phone".to_owned(),
                "paired-secret".to_owned(),
                String::new(),
            );
        }

        // The stranger registers: that succeeds, and it is not the problem.
        let stranger = "stranger";
        let registered = handle(
            &context,
            &fleet,
            &request(
                "POST",
                "v1/devices/register",
                json!({
                    "device_id": stranger,
                    "device_secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "voip_token": "a".repeat(64),
                }),
            ),
        )
        .expect("route exists");
        assert_eq!(body_of_response(&registered)["registered"], json!(true));

        // Acting on a line is refused, with a reason the operator can act on.
        let refused = handle(
            &context,
            &fleet,
            &request(
                "POST",
                "v2/commands/enqueue",
                json!({
                    "device_id": stranger,
                    "device_secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "command_id": "probe",
                    "type": "dial",
                    "number": "+447469192531",
                }),
            ),
        )
        .expect("route exists");
        assert_eq!(refused.status, 403);
        assert_eq!(
            body_of_response(&refused)["code"],
            json!("not_paired"),
            "拒绝原因必须说明是未配对，而不是凭据错误"
        );
    }

    /// A registered stranger learns nothing about the operator's line.
    ///
    /// The directory names the number and the carrier, and the heartbeat is what
    /// the phone trusts to know whether this agent is alive. Neither belongs to a
    /// device that only registered - registration is open by design, so a device
    /// that passed it has proved nothing beyond knowing its own secret.
    #[test]
    fn a_stranger_reads_no_directory_and_cannot_report_a_heartbeat() {
        let context = context();
        let fleet = paired_fleet("paired-phone");
        let stranger = "intruder";
        let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let credentials = json!({"device_id": stranger, "device_secret": secret});

        // Registration itself succeeds: that is how a second device joins.
        let registered = handle(
            &context,
            &fleet,
            &request(
                "POST",
                "v1/devices/register",
                json!({
                    "device_id": stranger,
                    "device_secret": secret,
                    "voip_token": "d".repeat(64),
                }),
            ),
        )
        .expect("route exists");
        assert_eq!(body_of_response(&registered)["registered"], json!(true));

        // The directory answers, but with nothing in it - no number, no carrier.
        let directory = handle(
            &context,
            &fleet,
            &request("POST", "v1/devices/status", credentials.clone()),
        )
        .expect("route exists");
        let body = body_of_response(&directory);
        assert_eq!(body["agents"], json!([]), "陌生人不应看到任何 agent");
        assert_eq!(body["cloud_online"], json!(false));

        // A heartbeat is refused, so a stranger cannot make this agent look alive
        // or dead to the phone that actually paired.
        let beat = handle(
            &context,
            &fleet,
            &request("POST", "v1/events/heartbeat", credentials),
        )
        .expect("route exists");
        assert_eq!(beat.status, 403);
    }

    /// The dial response carries what the phone's control client requires.
    ///
    /// `call_uuid` has to parse as a UUID: the client does
    /// `UUID(uuidString: envelope.callUUID)` and drops the call when that fails,
    /// which surfaces as "missing call_uuid". The same identity has to come back
    /// for a retried enqueue, or the phone treats the retry as a second call.
    #[test]
    fn a_dial_returns_a_usable_call_identity() {
        let uuid = call_uuid_for("6f1e2d3c-1111-2222-3333-444455556666");
        assert!(is_uuid(&uuid), "call_uuid 必须是合法 UUID: {uuid}");
        assert_eq!(
            uuid,
            call_uuid_for("6f1e2d3c-1111-2222-3333-444455556666"),
            "同一 command 重试必须复用同一个 call_uuid"
        );
        assert_ne!(
            uuid,
            call_uuid_for("00000000-0000-0000-0000-000000000000"),
            "不同 command 必须得到不同 call_uuid"
        );

        // The format check the phone applies.
        assert!(is_uuid("a064765c-d0d9-4e8d-96e3-636ba9137f44"));
        assert!(!is_uuid("probe-2093624"), "非 UUID 必须被拒绝");
        assert!(!is_uuid("a064765cd0d94e8d96e3636ba9137f44"));
    }
    /// The push sender can be replaced while the process runs.
    ///
    /// A key pasted into the settings page used to need a restart, and a restart
    /// drops the phone's registration - so the operator saw "saved" and nothing
    /// rang. The sender lives behind the same lock as the rest of the live
    /// configuration, and readers take the current one.
    #[test]
    fn the_pusher_can_be_replaced_at_runtime() {
        let context = context();
        let before = context.pusher().host().to_owned();
        assert!(
            context.pusher().status().reason().is_some(),
            "没有密钥时应当说明为什么不能推送"
        );

        if let Ok(mut live) = context.live.write() {
            live.pusher = Some(Arc::new(crate::apns::Pusher::new(
                "not-a-real-key",
                "KEYID12345",
                "TEAMID1234",
                "com.test.app",
                true,
            )));
        }

        assert_ne!(
            context.pusher().host(),
            before.as_str(),
            "换到沙盒后主机名应当改变"
        );
        assert!(
            context.pusher().host().contains("sandbox"),
            "沙盒环境的推送主机名带 sandbox"
        );
    }
}
