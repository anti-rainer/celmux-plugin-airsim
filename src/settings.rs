// Copyright (c) 2026 anti-rainer
// SPDX-License-Identifier: MIT

//! The plugin's own settings surface: its page, its pairing window, and the
//! line assignment that decides which agents exist.
//!
//! Celmux serves this plugin's page from `ui/` inside the plugin directory; this
//! module answers the same origin the page runs on, so the page can call these
//! endpoints directly. It is the only listener the operator configures, and the
//! only one with a stable port: agent ports move with the assignment.

use std::sync::{Arc, OnceLock};
use std::time::Instant;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::agents::{AgentConfig, Fleet};
use crate::celmux::Client;
use crate::config;
use crate::http::{Request, Response};

/// How long a pairing window stays open.
///
/// Long enough to walk to the phone, short enough that a code left on screen
/// stops being useful. Six digits is a million guesses, and a window closes
/// itself whether or not anyone is watching.
const PAIRING_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// The key the assignment is stored under in Celmux's plugin configuration.
const ASSIGNMENT_KEY: &str = "agents";
/// Expose every line Celmux has, instead of the stored list.
const EXPOSE_ALL_KEY: &str = "expose_all_lines";
/// What the settings page shows in place of a secret it may not read back.
const MASKED_SECRET: &str = "********";
/// The display name, stored apart from the line list.
const AGENT_NAME_KEY: &str = "agent_name";
/// The credential id, stored apart from the line list.
const AGENT_ID_KEY: &str = "agent_id";

/// One line the operator assigned to an agent.
#[derive(Debug, Clone, Deserialize)]
struct AssignedLine {
    /// The Celmux line label.
    line_id: String,
    /// Kept so a stored assignment written by an older page still parses; the
    /// slot is named from the line itself, so this is not read.
    #[serde(default, rename = "name")]
    _name: String,
    // Ports in a stored assignment are ignored: they are one installation-wide
    // pair now, not a per-line choice. Reading them would let an old saved value
    // silently override what the ports page shows.
}

/// Read the assignment from Celmux's plugin configuration.
///
/// The value is stored as JSON in one config field, so the settings page can
/// save it with the same call it uses for every other field and Celmux does not
/// need a schema for a plugin's own structure.
pub fn load_assignment(client: &Client) -> Result<Vec<AgentConfig>, String> {
    let value = client.config().map_err(|error| error.to_string())?;
    let config = value.get("config");
    let read = |key: &str| -> String {
        config
            .and_then(|config| config.get(key))
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_owned()
    };
    // The identity is its own configuration, not part of the line list: the list
    // is the operator's ordering of lines, and folding a name into it would make
    // renaming the agent rewrite every row.
    // The switch is read from the same place the list is, because they answer the
    // same question: which lines this gateway offers.
    let expose_all = config
        .and_then(|config| config.get(EXPOSE_ALL_KEY))
        .and_then(Value::as_str)
        .map(|value| matches!(value.trim(), "true" | "1" | "on" | "yes"))
        .unwrap_or(false);
    let identity = (read(AGENT_NAME_KEY), read(AGENT_ID_KEY), expose_all);
    let raw = config
        .and_then(|config| config.get(ASSIGNMENT_KEY))
        .and_then(Value::as_str)
        .unwrap_or("");
    parse_assignment(raw, identity)
}

/// Parse the stored assignment, tolerating an empty value.
fn parse_assignment(
    raw: &str,
    identity: (String, String, bool),
) -> Result<Vec<AgentConfig>, String> {
    let (_, _, expose_all_lines) = identity.clone();
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        // An empty list is still a gateway when every line is exposed: there is
        // nothing to curate, and demanding a list first would make the switch
        // impossible to use on a fresh installation.
        if expose_all_lines {
            let (name, id, expose_all_lines) = identity;
            return Ok(vec![AgentConfig {
                lines: Vec::new(),
                expose_all_lines,
                name,
                id,
            }]);
        }
        return Ok(Vec::new());
    }
    let lines: Vec<AssignedLine> =
        serde_json::from_str(trimmed).map_err(|error| format!("线路分配不是有效 JSON: {error}"))?;
    // One agent carrying every assigned line. The stored form stays a list
    // because the operator's order is what the phone shows.
    let lines: Vec<String> = lines
        .into_iter()
        .map(|line| line.line_id.trim().to_owned())
        .filter(|line_id| !line_id.is_empty())
        .collect();
    let (name, id, _) = identity;
    if lines.is_empty() && !expose_all_lines {
        // No lines is no agent, but the operator may still have set a name before
        // assigning any: keeping it means the page shows what they typed.
        return Ok(Vec::new());
    }
    Ok(vec![AgentConfig {
        lines,
        expose_all_lines,
        name,
        id,
    }])
}

/// Parse an assignment the way the settings page does, for tests.
#[cfg(test)]
pub(crate) fn parse_assignment_for_tests(
    raw: &str,
    identity: (String, String, bool),
) -> Vec<AgentConfig> {
    parse_assignment(raw, identity).unwrap_or_default()
}

/// Route one request on the settings listener.
pub fn handle(
    fleet: &Arc<Fleet>,
    client: &Arc<Client>,
    advertisements: &Arc<
        std::sync::Mutex<std::collections::BTreeMap<String, crate::discovery::Advertisement>>,
    >,
    host: &str,
    ports: &crate::control::Ports,
    relay: &Arc<crate::relay_endpoint::Context>,
    request: Request,
) -> Response {
    let relay_state = &relay.state;
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/api/status") => status(fleet, client, host, ports, relay_state),
        ("POST", "/api/pair") => open_pairing(fleet, advertisements, &request),
        ("POST", "/api/unpair") => unpair(fleet, &request),
        ("GET", "/api/lines") => lines(fleet, client),
        ("GET", "/api/logs") => logs(&request),
        ("GET", "/api/config") => config_read(client),
        ("POST", "/api/config") => config_write(fleet, client, relay, &request),
        ("GET", "/api/relay/devices") => relay_devices(relay_state),
        ("GET", "/api/info") => info_page(),
        _ => Response::error(404, "Not Found", "not_found", "接口不存在"),
    }
}

/// What the page shows: every agent, whether it is paired, and where it listens.
fn status(
    fleet: &Arc<Fleet>,
    client: &Arc<Client>,
    host: &str,
    ports: &crate::control::Ports,
    relay_state: &Arc<crate::relay::State>,
) -> Response {
    let agents: Vec<Value> = fleet
        .list()
        .into_iter()
        .map(|agent| {
            json!({
                "agent_id": agent.id(),
                // The line as it is now, not the name stored at exposure time.
                "name": crate::control::line_display_name(&agent),
                "lines": agent.lines(),
                // Every line answers on the same pair; repeating the numbers
                // per line would suggest they can differ.
                "control_port": ports.control,
                "pcm_port": ports.pcm,
                "paired": agent.paired(),
                "pairing_open": agent.with_pairing(|_| ()).is_some(),
            })
        })
        .collect();
    Response::ok(json!({
        "ok": true,
        "host": host,
        // Whether the phone's own relay credential was captured at pairing. The
        // external mode cannot sign an event without it, and the operator cannot
        // supply it, so the page has to say whether it is there.
        "relay_credential": relay_state.phone_relay().map(|relay| json!({
            "device_id": relay.device_id,
            "relay_url": relay.relay_url,
            "present": true,
        })).unwrap_or_else(|| json!({"present": false})),
        "plugin_port": crate::config::DEFAULT_PORT,
        "agents": agents,
        // What the home page counts. Built here rather than from three requests
        // in the page, so the numbers describe one moment instead of three.
        "totals": totals(fleet, client),
    }))
}

/// The counts the home page shows.
///
/// Every line the operator exposed is asked for its messages, and the calls come
/// from Celmux's one call list. A line that cannot be reached is left out of the
/// count rather than failing the whole document: the page is a status view, and
/// one unreachable reader should not blank it.
fn totals(fleet: &Arc<Fleet>, client: &Arc<Client>) -> Value {
    // Only the lines the operator exposed: the page describes what the phone can
    // reach, not everything the readers happen to hold. Asked through `exposes`,
    // which is the same question the phone's own list answers - a count built from
    // the stored assignment would ignore the expose-all switch and disagree with
    // the slot picker.
    let agents = fleet.list();
    let lines: Vec<crate::celmux::Line> = client
        .lines()
        .unwrap_or_default()
        .into_iter()
        .filter(|line| agents.iter().any(|agent| agent.exposes(&line.line_id)))
        .collect();
    let mut sent = 0_u64;
    let mut received = 0_u64;
    for line in &lines {
        let Ok(value) = client.messages(&line.line_id) else {
            continue;
        };
        for message in value
            .get("messages")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            match message.get("direction").and_then(Value::as_str) {
                Some("outgoing") => sent += 1,
                Some("incoming") => received += 1,
                _ => {}
            }
        }
    }
    let calls = client.calls().unwrap_or(Value::Null);
    let rows: Vec<&Value> = calls
        .get("calls")
        .and_then(Value::as_array)
        .map(|rows| rows.iter().collect())
        .unwrap_or_default();
    let outgoing_calls = rows
        .iter()
        .filter(|row| row.get("direction").and_then(Value::as_str) == Some("outgoing"))
        .count();
    let incoming_calls = rows
        .iter()
        .filter(|row| row.get("direction").and_then(Value::as_str) == Some("incoming"))
        .count();
    // Everything the readers hold, not just what was exposed: the home page
    // separates "lines this gateway knows about" from "lines the phone can use".
    let known = client.lines().map(|rows| rows.len()).unwrap_or(0);
    json!({
        "lines": known,
        "lines_callable": lines.iter().filter(|line| line.usable()).count(),
        "lines_exposed": lines.len(),
        "sms_sent": sent,
        "sms_received": received,
        "calls_outgoing": outgoing_calls,
        "calls_incoming": incoming_calls,
        "uptime_seconds": uptime_seconds(),
        "memory_kb": memory_kb(),
        "threads": threads(),
    })
}

/// How long this process has been running, in seconds.
fn uptime_seconds() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_secs()
}

/// Resident memory in kilobytes, read from the process itself.
///
/// `/proc/self/status` is the only source that needs no dependency and no
/// syscall wrapper, and this runs on Linux only.
fn memory_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("VmRSS:"))
                .and_then(|line| {
                    line.split_whitespace()
                        .nth(1)
                        .and_then(|value| value.parse().ok())
                })
        })
        .unwrap_or(0)
}

/// How many threads this process has.
fn threads() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("Threads:"))
                .and_then(|line| {
                    line.split_whitespace()
                        .nth(1)
                        .and_then(|value| value.parse().ok())
                })
        })
        .unwrap_or(0)
}

#[derive(Deserialize)]
struct PairRequest {
    agent_id: String,
}

/// Open a pairing window for one agent and hand back its 6-digit code.
///
/// The code is returned once, here, and never stored anywhere readable: it is
/// only ever a component of the key derived from it.
fn open_pairing(
    fleet: &Arc<Fleet>,
    advertisements: &Arc<
        std::sync::Mutex<std::collections::BTreeMap<String, crate::discovery::Advertisement>>,
    >,
    request: &Request,
) -> Response {
    let payload: PairRequest = match serde_json::from_slice(&request.body) {
        Ok(payload) => payload,
        Err(error) => {
            return Response::error(400, "Bad Request", "bad_request", &error.to_string());
        }
    };
    let Some(agent) = fleet.by_id(&payload.agent_id) else {
        return Response::error(404, "Not Found", "unknown_agent", "该 agent 不存在");
    };
    let session_id = match random_session_id() {
        Ok(id) => id,
        Err(error) => return Response::error(500, "Internal Server Error", "random", &error),
    };
    match agent.open_pairing(PAIRING_TTL, session_id) {
        Ok((code, expires_at)) => {
            // Advertise the window so the phone finds it by browsing. Without
            // this only manual addressing works, and the window would be
            // invisible to an operator who never configured an address.
            let agent_id = agent.id();
            if let Ok(mut advertisements) = advertisements.lock()
                && let Some(advertisement) = advertisements.get_mut(&agent_id)
            {
                let public_key = agent
                    .with_pairing(|session| session.public_key)
                    .unwrap_or_default();
                if let Err(error) = advertisement.add_pairing_window(
                    &agent_id,
                    &agent
                        .with_pairing(|session| session.id.clone())
                        .unwrap_or_default(),
                    &public_key,
                    expires_at,
                ) {
                    crate::log_warn!("celmux-plugin-airsim: 配对广播失败: {error}");
                }
            }
            Response::ok(json!({
                "ok": true,
                "code": code,
                "expires_at": expires_at,
                "agent_id": agent_id,
                "ttl_seconds": PAIRING_TTL.as_secs(),
            }))
        }
        Err(error) => Response::error(500, "Internal Server Error", "pairing", &error),
    }
}

#[derive(Deserialize)]
struct UnpairRequest {
    agent_id: String,
}

/// Forget an agent's secret, so its phone has to pair again.
fn unpair(fleet: &Arc<Fleet>, request: &Request) -> Response {
    let payload: UnpairRequest = match serde_json::from_slice(&request.body) {
        Ok(payload) => payload,
        Err(error) => {
            return Response::error(400, "Bad Request", "bad_request", &error.to_string());
        }
    };
    let Some(agent) = fleet.by_id(&payload.agent_id) else {
        return Response::error(404, "Not Found", "unknown_agent", "该 agent 不存在");
    };
    agent.clear_secret();
    // Also from disk: clearing only memory would leave the old secret to be
    // read back at the next restart, and an "unpaired" agent would start
    // accepting requests from the phone it was just detached from.
    agent.forget_secret();
    agent.close_pairing();
    Response::ok(json!({"ok": true, "agent_id": agent.id()}))
}

/// The lines this installation can offer, read from Celmux.
/// Every line, joined with what the card's own module and SIM look like.
///
/// A line alone says which subscriber it is; an operator choosing which lines
/// to expose needs to know which module carries it and whether its voice route
/// is actually up. Celmux keeps those two facts in two routes, so they are
/// joined here rather than by the page.
fn lines(fleet: &Arc<Fleet>, client: &Arc<Client>) -> Response {
    let lines = match client.lines() {
        Ok(lines) => lines,
        Err(error) => {
            return Response::error(502, "Bad Gateway", "celmux_unavailable", &error.to_string());
        }
    };
    let devices = client.devices().unwrap_or_default();
    let by_id: std::collections::BTreeMap<&str, &crate::celmux::Device> = devices
        .iter()
        .map(|device| (device.id.as_str(), device))
        .collect();
    let agents = fleet.list();
    let rows: Vec<Value> = lines
        .into_iter()
        .map(|line| {
            let device = line.device_id.as_str();
            let module = by_id.get(device);
            // Whether the operator exposed this line. There is one agent, so
            // the question is membership rather than which agent.
            // Whether this line is exposed at all. Pairing and the ports belong
            // to the installation, so they are reported once at the top of the
            // page rather than repeated on every card.
            let exposed = agents
                .iter()
                .any(|agent| agent.exposes(&line.line_id));
            json!({
                "line_id": line.line_id,
                "device_id": device,
                "device_name": line.device_name,
                "operator_name": line.operator_name,
                "local_phone": line.local_phone,
                "n_standby": line.n_standby,
                "online": line.online,
                "profile_name": line.profile_name,
                // The route this line's voice takes: the module's own VoLTE,
                // this host's VoWiFi, or an N-standby Profile's VoWiFi.
                "voice_route": module.map(|device| device.voice_route.clone()).unwrap_or_default(),
                "voice_route_reason": module.map(|device| device.voice_route_reason.clone()).unwrap_or_default(),
                "vowifi_active": module.map(|device| device.vowifi_active).unwrap_or(false),
                "n_standby_active": module.map(|device| device.vowifi_n_standby_active).unwrap_or(false),
                "registration": module
                    .and_then(|device| device.modem.as_ref())
                    .and_then(|modem| modem.registration_state_text.clone())
                    .unwrap_or_default(),
                // What the module is doing right now, which is what tells an
                // operator why a line is not callable.
                "module_running": module.map(|device| device.running).unwrap_or(false),
                "network_enabled": module.map(|device| device.network_enabled).unwrap_or(false),
                "module_ims": module.map(|device| device.at_module_ims).unwrap_or(false),
                "n_standby_online": module.map(|device| device.vowifi_n_standby_online).unwrap_or(0),
                "n_standby_total": module.map(|device| device.vowifi_n_standby_total).unwrap_or(0),
                "signal_dbm": module
                    .and_then(|device| device.modem.as_ref())
                    .and_then(|modem| modem.signal_dbm),
                "iccid": module
                    .and_then(|device| device.modem.as_ref())
                    .and_then(|modem| modem.iccid.clone())
                    .unwrap_or_default(),
                "imsi": module
                    .and_then(|device| device.modem.as_ref())
                    .and_then(|modem| modem.imsi.clone())
                    .unwrap_or_default(),
                "module_model": module
                    .and_then(|device| device.modem.as_ref())
                    .and_then(|modem| modem.model.clone())
                    .unwrap_or_default(),
                "exposed": exposed,
            })
        })
        .collect();
    Response::ok(json!({"ok": true, "lines": rows}))
}

/// The plugin's own configuration, as Celmux holds it.
///
/// Read through the plugin token rather than from the environment: the page has
/// to show what the operator saved, and the environment the process started with
/// may predate the last save.
/// Which devices this relay knows, and which one it signs as.
///
/// Read-only: registration is open to any phone whose credential it can present,
/// exactly as the upstream relay works, so there is no list to edit. Saying so on
/// the page is more honest than offering an approval switch that no longer gates
/// anything.
fn relay_devices(state: &Arc<crate::relay::State>) -> Response {
    Response::ok(json!({
        "ok": true,
        "devices": state.devices(),
        "acting": state.credentials().map(|(id, _)| id).unwrap_or_default(),
        "push": state.voip_token().is_some(),
    }))
}

fn config_read(client: &Arc<Client>) -> Response {
    match client.config() {
        Ok(value) => Response::ok(json!({
            "ok": true,
            "config": value.get("config").cloned().unwrap_or_else(|| json!({})),
        })),
        Err(error) => Response::error(502, "Bad Gateway", "celmux_unavailable", &error.to_string()),
    }
}

/// `POST /api/config` — apply a settings change now, persist it behind the page.
///
/// Memory is the truth while the process runs; the stored configuration is what
/// the next start reads. A change is applied here, answered here, and written
/// through Celmux on a thread.
///
/// Deliberately no reload: re-reading the stored configuration on a timer meant
/// the two could disagree for as long as the save took, and the poll would then
/// put the stale value back over a change the operator had just made and seen. One
/// writer, one reader, no reconciliation.
fn config_write(
    fleet: &Arc<Fleet>,
    client: &Arc<Client>,
    relay: &Arc<crate::relay_endpoint::Context>,
    request: &Request,
) -> Response {
    let payload: Value = match serde_json::from_slice(&request.body) {
        Ok(payload) => payload,
        Err(error) => {
            return Response::error(400, "Bad Request", "bad_json", &error.to_string());
        }
    };
    let Some(values) = payload.get("values").and_then(Value::as_object) else {
        return Response::error(400, "Bad Request", "no_values", "缺少 values");
    };
    // Only the assignment is applied here. Every other key is read from Celmux by
    // the code that uses it, so persisting them is the whole job for those.
    // The two values that change what this gateway offers are applied here. Every
    // other key is read from Celmux by the code that uses it, so persisting it is
    // the whole job for those.
    let running = fleet.list().first().cloned();
    let current = running
        .as_ref()
        .map(|agent| agent.config())
        .unwrap_or_default();
    // The identity the running agent answers to, not the raw config value: an
    // unset `agent_id` in the configuration is the default, and passing the empty
    // string through would build a config whose id matches no running agent - the
    // change would be stored and silently not applied.
    let identity = running
        .as_ref()
        .map(|agent| (agent.name(), agent.id()))
        .unwrap_or_else(|| (current.name.clone(), current.id.clone()));
    let expose_all = values
        .get(EXPOSE_ALL_KEY)
        .and_then(Value::as_str)
        .map(|value| matches!(value.trim(), "true" | "1" | "on" | "yes"))
        .unwrap_or(current.expose_all_lines);
    let assignment = values
        .get(ASSIGNMENT_KEY)
        .and_then(Value::as_str)
        .unwrap_or("");
    if !assignment.is_empty() || values.contains_key(EXPOSE_ALL_KEY) {
        // An absent assignment keeps the one in effect, so flipping the switch
        // does not have to send the line list with it.
        let raw = if assignment.is_empty() {
            serde_json::to_string(
                &current
                    .lines
                    .iter()
                    .map(|line| json!({ "line_id": line }))
                    .collect::<Vec<_>>(),
            )
            .unwrap_or_else(|_| "[]".to_owned())
        } else {
            assignment.to_owned()
        };
        match parse_assignment(&raw, (identity.0, identity.1, expose_all)) {
            Ok(configs) => {
                let changed = fleet.apply_configs(configs);
                crate::log_info!(
                    "celmux-plugin-airsim: 配置已应用 expose_all={expose_all} lines={} changed={changed}",
                    current.lines.len()
                );
            }
            Err(error) => {
                return Response::error(400, "Bad Request", "bad_assignment", &error);
            }
        }
    }

    // The push sender is built from the key and its identifiers, so it has to be
    // rebuilt when any of them arrives - otherwise pasting a key into the settings
    // page would still need a restart before a call could ring.
    const APNS_KEYS: [&str; 5] = [
        "apns_p8",
        "apns_key_id",
        "apns_team_id",
        "apns_bundle_id",
        "apns_sandbox",
    ];
    if APNS_KEYS.iter().any(|key| values.contains_key(*key)) {
        let read = |key: &str| -> String {
            values
                .get(key)
                .and_then(Value::as_str)
                .map(|value| value.trim().to_owned())
                .unwrap_or_default()
        };
        let p8 = read("apns_p8");
        // An empty key in a save is "leave it alone", not "clear it": the page
        // shows secrets masked, and a form that round-trips the mask would
        // otherwise wipe the key every time an unrelated field was saved.
        if !p8.is_empty() && p8 != MASKED_SECRET {
            let sandbox = read("apns_sandbox");
            let pusher = crate::apns::Pusher::new(
                &p8,
                &read("apns_key_id"),
                &read("apns_team_id"),
                &read("apns_bundle_id"),
                sandbox == "true" || sandbox == "1",
            );
            if let Ok(mut live) = relay.live.write() {
                live.pusher = Some(Arc::new(pusher));
            }
            crate::log_info!("celmux-plugin-airsim: APNs 凭据已更新，无需重启");
        }
    }

    // Persist off this thread: the page has its answer, and a slow or unavailable
    // Celmux must not turn a click into a spinner.
    let client = Arc::clone(client);
    let values: std::collections::BTreeMap<String, String> = values
        .iter()
        .filter_map(|(key, value)| value.as_str().map(|text| (key.clone(), text.to_owned())))
        .collect();
    std::thread::spawn(move || {
        if let Err(error) = persist_config(&client, values) {
            crate::log_warn!("celmux-plugin-airsim: 配置未能写入 Celmux: {error}");
        }
    });

    Response::ok(json!({"ok": true}))
}

/// Write settings back through Celmux.
fn persist_config(
    client: &Arc<Client>,
    values: std::collections::BTreeMap<String, String>,
) -> Result<(), String> {
    client
        .set_config(&values)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// The tail of this plugin's own log.
fn logs(request: &Request) -> Response {
    let lines: usize = request
        .path
        .split_once('?')
        .and_then(|(_, query)| {
            query
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .find(|(key, _)| *key == "lines")
                .and_then(|(_, value)| value.parse().ok())
        })
        .unwrap_or(300)
        .clamp(20, 2000);
    Response::ok(json!({
        "ok": true,
        "level": crate::logging::level().as_str(),
        "lines": crate::logging::tail(lines),
    }))
}

/// What the plugin is, for its own information tab.
fn info_page() -> Response {
    Response::ok(json!({
        "ok": true,
        "id": config::PLUGIN_ID,
        "version": env!("CARGO_PKG_VERSION"),
        "repository": env!("CARGO_PKG_REPOSITORY"),
        "log_level": crate::logging::level().as_str(),
        "protocol": {
            "pairing": crate::pairing::PROTOCOL_VERSION,
            "product": crate::pairing::PRODUCT,
            "pcm_sample_rate": crate::pcm::SAMPLE_RATE,
            "pcm_frame_bytes": crate::pcm::FRAME_BYTES,
        },
    }))
}

fn random_session_id() -> Result<String, String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| format!("随机数不可用: {error}"))?;
    Ok(config::base64_url_encode(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An empty assignment is not an error: a freshly installed plugin has no
    /// agents yet, and the operator picks lines in the page.
    #[test]
    fn an_empty_assignment_yields_no_agents() {
        assert!(parse_assignment("", Default::default()).unwrap().is_empty());
        assert!(
            parse_assignment("   ", Default::default())
                .unwrap()
                .is_empty()
        );
    }

    /// The assignment is one JSON field in Celmux's config, so it has to parse
    /// from the exact text a page would save. Every assigned line becomes a slot
    /// on the one agent, in the order the operator put them.
    #[test]
    fn an_assignment_parses_into_one_agent_with_a_slot_per_line() {
        let agents = parse_assignment(
            r#"[{"line_id":"dji1","control_port":8642,"pcm_port":8643},
                {"line_id":"读卡器1#8904","name":"Globe","control_port":8652,"pcm_port":8653}]"#,
            Default::default(),
        )
        .unwrap();
        assert_eq!(agents.len(), 1, "只有一个 agent");
        assert_eq!(
            agents[0].lines,
            vec!["dji1".to_owned(), "读卡器1#8904".to_owned()]
        );
    }

    /// A row with no line names no agent, so it must not create a ghost.
    #[test]
    fn a_row_without_a_line_is_skipped() {
        let agents = parse_assignment(
            r#"[{"line_id":"","control_port":8642,"pcm_port":8643},
                {"line_id":"dji1","control_port":8644,"pcm_port":8645}]"#,
            Default::default(),
        )
        .unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].lines, vec!["dji1".to_owned()], "空行不产生槽位");
    }

    #[test]
    fn a_malformed_assignment_names_the_problem() {
        let error = parse_assignment("not json", Default::default()).unwrap_err();
        assert!(error.contains("JSON"));
    }

    /// A window is what makes pairing possible at all; it has to last long
    /// enough to walk to the phone and short enough to stop being useful.
    #[test]
    fn the_pairing_window_is_minutes_not_hours() {
        assert_eq!(PAIRING_TTL.as_secs(), 300);
    }
    fn assignment(lines: &[&str]) -> String {
        let rows: Vec<String> = lines
            .iter()
            .map(|line| format!("{{\"line_id\":\"{line}\"}}"))
            .collect();
        format!("[{}]", rows.join(","))
    }

    fn identity(expose_all: bool) -> (String, String, bool) {
        ("Celmux".to_owned(), "celmux".to_owned(), expose_all)
    }

    /// The switch survives parsing, and the curated list survives with it.
    ///
    /// Both have to be readable afterwards: with the switch on the list is not
    /// consulted, and an operator who turns the switch back off expects the lines
    /// they assigned to still be there.
    #[test]
    fn the_expose_all_switch_is_parsed_alongside_the_assignment() {
        let raw = assignment(&["读卡器1", "dji1"]);

        let off = parse_assignment(&raw, identity(false)).expect("parse");
        assert_eq!(off.len(), 1);
        assert!(!off[0].expose_all_lines);
        assert_eq!(off[0].lines, vec!["读卡器1".to_owned(), "dji1".to_owned()]);

        let on = parse_assignment(&raw, identity(true)).expect("parse");
        assert_eq!(on.len(), 1);
        assert!(on[0].expose_all_lines);
        assert_eq!(
            on[0].lines,
            vec!["读卡器1".to_owned(), "dji1".to_owned()],
            "打开开关不清空手动分配的线路"
        );
    }

    /// With no assignment at all, the switch alone still yields a gateway.
    ///
    /// Otherwise the switch would be unusable on a fresh installation: there is
    /// nothing to curate yet, and every line is supposed to appear.
    #[test]
    fn the_switch_alone_yields_a_gateway_with_no_assignment() {
        let on = parse_assignment("", identity(true)).expect("parse");
        assert_eq!(on.len(), 1, "开关打开时没有线路也要有 agent");
        assert!(on[0].expose_all_lines);
        assert!(on[0].lines.is_empty());

        let off = parse_assignment("", identity(false)).expect("parse");
        assert!(off.is_empty(), "开关关闭且没有线路时没有 agent");
    }
}
