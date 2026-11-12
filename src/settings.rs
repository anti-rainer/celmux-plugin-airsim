// Copyright (c) 2026 anti-rainer
// SPDX-License-Identifier: MIT

//! The plugin's own settings surface: its page, its pairing window, and the
//! line assignment that decides which agents exist.
//!
//! Celmux serves this plugin's page from `ui/` inside the plugin directory; this
//! module answers the same origin the page runs on, so the page can call these
//! endpoints directly. It is the only listener the operator configures, and the
//! only one with a stable port: agent ports move with the assignment.
//!
//! The assignment itself is the plugin's own state, on this plugin's own disk
//! ([`crate::assignment`]). It is not a provider setting: adding a line is a
//! decision the operator makes on this page, not a value Celmux resolves and
//! hands down, and routing it through the host made a click into a configuration
//! write that the plugin could not verify and a schema it did not own could
//! refuse. Celmux's configuration still answers for the ports, the credentials
//! and the log level - one place per fact.

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

/// Read the assignment this installation has.
///
/// The plugin's own file is the truth. Celmux's plugin configuration is read once
/// as a **seed**: an installation that had lines before this moved has them in a
/// host config field, and silently dropping them on upgrade would make every line
/// disappear and look like the bridge had lost its settings. After the first
/// read with no file present, the file is written and the host value is never
/// consulted again - which is what makes this plugin's state its own.
pub fn load_assignment(
    client: &Client,
    store: &crate::assignment::Store,
) -> Result<Vec<AgentConfig>, String> {
    let identity = host_identity(client);
    let document = match store.load() {
        document if store.path().exists() => document,
        _ => {
            let seeded = seed_from_host(client, &identity);
            if seeded.lines.is_empty() && !seeded.expose_all {
                seeded
            } else {
                crate::log_info!(
                    "celmux-plugin-airsim: 从 Celmux 配置迁移 {} 条线路到 {}",
                    seeded.lines.len(),
                    store.path().display()
                );
                let _ = store.save(&seeded);
                seeded
            }
        }
    };
    Ok(configs_from_document(&document, &identity))
}

/// The agent name and id, which stay in the host configuration: they are
/// provider settings the operator edits on Celmux's page, not this plugin's own
/// state.
fn host_identity(client: &Client) -> (String, String) {
    let Ok(value) = client.config() else {
        return (String::new(), String::new());
    };
    let config = value.get("config");
    let read = |key: &str| -> String {
        config
            .and_then(|config| config.get(key))
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_owned()
    };
    (read(AGENT_NAME_KEY), read(AGENT_ID_KEY))
}

/// A one-time read of an assignment stored in Celmux's configuration.
fn seed_from_host(client: &Client, _identity: &(String, String)) -> crate::assignment::Document {
    let Ok(value) = client.config() else {
        return crate::assignment::Document::default();
    };
    let config = value.get("config");
    let expose_all = config
        .and_then(|config| config.get(EXPOSE_ALL_KEY))
        .and_then(Value::as_str)
        .map(|value| matches!(value.trim(), "true" | "1" | "on" | "yes"))
        .unwrap_or(false);
    let raw = config
        .and_then(|config| config.get(ASSIGNMENT_KEY))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_owned();
    if raw.is_empty() {
        return crate::assignment::from_lines(Vec::<String>::new(), expose_all);
    }
    let Ok(lines) = serde_json::from_str::<Vec<AssignedLine>>(&raw) else {
        crate::log_warn!("celmux-plugin-airsim: Celmux 里的线路分配不是有效 JSON，按未加入处理");
        return crate::assignment::from_lines(Vec::<String>::new(), expose_all);
    };
    crate::assignment::from_lines(lines.into_iter().map(|line| line.line_id), expose_all)
}

/// Project a stored assignment onto the agents this gateway runs.
///
/// One agent carrying every assigned line. The stored form stays a list because
/// the operator's order is what the phone shows.
fn configs_from_document(
    document: &crate::assignment::Document,
    identity: &(String, String),
) -> Vec<AgentConfig> {
    let (name, id) = identity.clone();
    if document.lines.is_empty() && !document.expose_all {
        // No lines is no agent, but the operator may still have set a name
        // before assigning any: keeping it means the page shows what they typed.
        return Vec::new();
    }
    vec![AgentConfig {
        lines: document.lines.clone(),
        expose_all_lines: document.expose_all,
        name,
        id,
    }]
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
        ("GET", "/api/config") => config_read(fleet, client),
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

/// `GET /api/config` — the provider settings, plus the assignment this plugin
/// owns.
///
/// The two travel together because they are one form to the operator, but they
/// are answered from different places on purpose: the provider settings come
/// from Celmux, which resolves them, and the assignment comes from this plugin's
/// own disk, which is where a click is saved. Serving the assignment from the
/// host's copy is what made the page load a list the plugin had already replaced.
fn config_read(fleet: &Arc<Fleet>, client: &Arc<Client>) -> Response {
    let assignment = fleet.assignment_store().load();
    let mut config = match client.config() {
        Ok(value) => value
            .get("config")
            .cloned()
            .unwrap_or_else(|| json!({}))
            .as_object()
            .cloned()
            .unwrap_or_default(),
        // Celmux being unreachable must not hide the line list: the operator can
        // still see and edit what this plugin offers.
        Err(_) => serde_json::Map::new(),
    };
    config.insert(
        ASSIGNMENT_KEY.to_owned(),
        Value::String(
            serde_json::to_string(
                &assignment
                    .lines
                    .iter()
                    .map(|line| json!({ "line_id": line }))
                    .collect::<Vec<_>>(),
            )
            .unwrap_or_else(|_| "[]".to_owned()),
        ),
    );
    config.insert(
        EXPOSE_ALL_KEY.to_owned(),
        Value::String(
            if assignment.expose_all {
                "true"
            } else {
                "false"
            }
            .to_owned(),
        ),
    );
    Response::ok(json!({ "ok": true, "config": config }))
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
    // The assignment first, and it is the only key this route persists itself.
    //
    // Every other key is a provider setting: Celmux resolves it, hands it down at
    // launch, and reading it from there is the whole job. The line assignment is
    // a decision made on this page, so it is written to this plugin's own disk -
    // and written *before* the fleet is told about it, because a click the
    // operator has already seen must not be one that failed to save. The previous
    // order reported success and wrote behind the answer, so a refused write came
    // back to the page as a line that quietly rejoined the list it had just left.
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
    let assignment = values.get(ASSIGNMENT_KEY).and_then(Value::as_str);
    let expose_all_sent = values.contains_key(EXPOSE_ALL_KEY);
    if assignment.is_some() || expose_all_sent {
        let store = fleet.assignment_store();
        // An absent assignment keeps the one in effect, so flipping the switch
        // does not have to send the line list with it.
        let document = match assignment {
            Some(raw) if !raw.trim().is_empty() => {
                match serde_json::from_str::<Vec<AssignedLine>>(raw.trim()) {
                    Ok(lines) => crate::assignment::from_lines(
                        lines.into_iter().map(|line| line.line_id),
                        expose_all,
                    ),
                    Err(error) => {
                        return Response::error(
                            400,
                            "Bad Request",
                            "bad_assignment",
                            &format!("线路分配不是有效 JSON: {error}"),
                        );
                    }
                }
            }
            _ => crate::assignment::from_lines(current.lines.iter(), expose_all),
        };
        if let Err(error) = store.save(&document) {
            crate::log_warn!("celmux-plugin-airsim: 线路分配未能保存: {error}");
            return Response::error(500, "Internal Server Error", "assignment_not_saved", &error);
        }
        // Persisted, so the fleet can be told. One call adds, updates and
        // removes: the first line on a fresh installation builds the agent, and
        // removing the last one takes it away.
        let changed = fleet.apply_configs(configs_from_document(&document, &identity));
        crate::log_info!(
            "celmux-plugin-airsim: 线路分配已保存 {} expose_all={expose_all} lines={} agents={} changed={changed}",
            store.path().display(),
            document.lines.len(),
            fleet.list().len()
        );
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

    // The remaining keys are provider settings Celmux owns, so they are written
    // back for the next launch. The assignment is not among them any more: it is
    // this plugin's own state and it was already saved above, synchronously,
    // where a failure could still be reported to the page.
    //
    // Persisted off this thread: the page has its answer, and a slow or
    // unavailable Celmux must not turn a click into a spinner.
    let client = Arc::clone(client);
    let values: std::collections::BTreeMap<String, String> = values
        .iter()
        .filter(|(key, _)| !is_own_state(key))
        .filter_map(|(key, value)| value.as_str().map(|text| (key.clone(), text.to_owned())))
        .collect();
    if !values.is_empty() {
        std::thread::spawn(move || {
            if let Err(error) = persist_config(&client, values) {
                crate::log_warn!("celmux-plugin-airsim: 配置未能写入 Celmux: {error}");
            }
        });
    }

    Response::ok(json!({"ok": true}))
}

/// Keys this plugin owns rather than the host.
///
/// Sending them back to Celmux would recreate the shadow copy that made an
/// "add this line" click into a configuration write: two places to be wrong, and
/// a host refusal that looked like a success on the page.
fn is_own_state(key: &str) -> bool {
    matches!(key, ASSIGNMENT_KEY | EXPOSE_ALL_KEY)
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

    fn identity() -> (String, String) {
        ("Celmux".to_owned(), "celmux".to_owned())
    }

    /// A line list becomes one agent carrying every line, in the operator's
    /// order: the phone shows the slots in that order.
    #[test]
    fn an_assignment_becomes_one_agent_with_a_slot_per_line() {
        let document = crate::assignment::from_lines(["dji1", "读卡器1#8904"], false);
        let agents = configs_from_document(&document, &identity());
        assert_eq!(agents.len(), 1, "one agent, not one per line");
        assert_eq!(
            agents[0].lines,
            vec!["dji1".to_owned(), "读卡器1#8904".to_owned()]
        );
        assert!(!agents[0].expose_all_lines);
        assert_eq!(agents[0].name, "Celmux");
    }

    /// Nothing offered is no agent at all: a gateway with no slots would still
    /// answer the phone and offer it nothing to call.
    #[test]
    fn nothing_offered_is_no_agent() {
        let document = crate::assignment::from_lines(Vec::<String>::new(), false);
        assert!(configs_from_document(&document, &identity()).is_empty());
    }

    /// The "expose everything" switch is a gateway even with an empty list: the
    /// list is a snapshot and Celmux is not, so the switch is what a fresh
    /// installation uses before it has curated anything.
    #[test]
    fn exposing_everything_needs_no_stored_lines() {
        let document = crate::assignment::from_lines(Vec::<String>::new(), true);
        let agents = configs_from_document(&document, &identity());
        assert_eq!(agents.len(), 1);
        assert!(agents[0].expose_all_lines);
        assert!(agents[0].lines.is_empty());
    }
}
