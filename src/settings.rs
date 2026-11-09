// Copyright (c) 2026 anti-rainer
// SPDX-License-Identifier: MIT

//! The plugin's own settings surface: its page, its pairing window, and the
//! line assignment that decides which agents exist.
//!
//! Celmux serves this plugin's page from `ui/` inside the plugin directory; this
//! module answers the same origin the page runs on, so the page can call these
//! endpoints directly. It is the only listener the operator configures, and the
//! only one with a stable port: agent ports move with the assignment.

use std::sync::Arc;

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

/// One line the operator assigned to an agent.
#[derive(Debug, Clone, Deserialize)]
struct AssignedLine {
    /// The Celmux line label.
    line_id: String,
    #[serde(default)]
    name: String,
    control_port: u16,
    pcm_port: u16,
}

/// Read the assignment from Celmux's plugin configuration.
///
/// The value is stored as JSON in one config field, so the settings page can
/// save it with the same call it uses for every other field and Celmux does not
/// need a schema for a plugin's own structure.
pub fn load_assignment(client: &Client) -> Result<Vec<AgentConfig>, String> {
    let value = client.config().map_err(|error| error.to_string())?;
    let raw = value
        .get("config")
        .and_then(|config| config.get(ASSIGNMENT_KEY))
        .and_then(Value::as_str)
        .unwrap_or("");
    parse_assignment(raw)
}

/// Parse the stored assignment, tolerating an empty value.
fn parse_assignment(raw: &str) -> Result<Vec<AgentConfig>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let lines: Vec<AssignedLine> =
        serde_json::from_str(trimmed).map_err(|error| format!("线路分配不是有效 JSON: {error}"))?;
    Ok(lines
        .into_iter()
        .filter(|line| !line.line_id.trim().is_empty())
        .map(|line| AgentConfig {
            line_id: line.line_id.trim().to_owned(),
            name: line.name.trim().to_owned(),
            control_port: line.control_port,
            pcm_port: line.pcm_port,
        })
        .collect())
}

/// Route one request on the settings listener.
pub fn handle(
    fleet: &Arc<Fleet>,
    client: &Arc<Client>,
    advertisements: &Arc<
        std::sync::Mutex<std::collections::BTreeMap<String, crate::discovery::Advertisement>>,
    >,
    host: &str,
    request: Request,
) -> Response {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/api/status") => status(fleet, host),
        ("POST", "/api/pair") => open_pairing(fleet, advertisements, &request),
        ("POST", "/api/unpair") => unpair(fleet, &request),
        ("GET", "/api/lines") => lines(fleet, client),
        ("GET", "/api/logs") => logs(&request),
        ("GET", "/api/config") => config_read(client),
        ("GET", "/api/info") => info_page(),
        _ => Response::error(404, "Not Found", "not_found", "接口不存在"),
    }
}

/// What the page shows: every agent, whether it is paired, and where it listens.
fn status(fleet: &Arc<Fleet>, host: &str) -> Response {
    let agents: Vec<Value> = fleet
        .list()
        .into_iter()
        .map(|agent| {
            json!({
                "agent_id": agent.id(),
                "name": agent.name(),
                "line_id": agent.config.line_id,
                "control_port": agent.config.control_port,
                "pcm_port": agent.config.pcm_port,
                "paired": agent.paired(),
                "pairing_open": agent.with_pairing(|_| ()).is_some(),
            })
        })
        .collect();
    Response::ok(json!({
        "ok": true,
        "host": host,
        "plugin_port": config::DEFAULT_PORT,
        "agents": agents,
    }))
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
            // Which agent carries this line, if the operator exposed it.
            let agent = agents
                .iter()
                .find(|agent| agent.config.line_id == line.line_id)
                .map(|agent| {
                    json!({
                        "agent_id": agent.id(),
                        "name": agent.name(),
                        "control_port": agent.config.control_port,
                        "pcm_port": agent.config.pcm_port,
                        "paired": agent.paired(),
                    })
                });
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
                "agent": agent,
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
fn config_read(client: &Arc<Client>) -> Response {
    match client.config() {
        Ok(value) => Response::ok(json!({
            "ok": true,
            "config": value.get("config").cloned().unwrap_or_else(|| json!({})),
        })),
        Err(error) => Response::error(502, "Bad Gateway", "celmux_unavailable", &error.to_string()),
    }
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
        assert!(parse_assignment("").unwrap().is_empty());
        assert!(parse_assignment("   ").unwrap().is_empty());
    }

    /// The assignment is one JSON field in Celmux's config, so it has to parse
    /// from the exact text a page would save.
    #[test]
    fn an_assignment_parses_into_agents() {
        let agents = parse_assignment(
            r#"[{"line_id":"dji1","control_port":8642,"pcm_port":8643},
                {"line_id":"读卡器1#8904","name":"Globe","control_port":8652,"pcm_port":8653}]"#,
        )
        .unwrap();
        assert_eq!(agents.len(), 2);
        assert_eq!(agents[0].line_id, "dji1");
        assert_eq!(agents[0].name, "");
        assert_eq!(agents[1].name, "Globe");
        assert_eq!(agents[1].control_port, 8652);
    }

    /// A row with no line names no agent, so it must not create a ghost.
    #[test]
    fn a_row_without_a_line_is_skipped() {
        let agents = parse_assignment(
            r#"[{"line_id":"","control_port":8642,"pcm_port":8643},
                {"line_id":"dji1","control_port":8644,"pcm_port":8645}]"#,
        )
        .unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].line_id, "dji1");
    }

    #[test]
    fn a_malformed_assignment_names_the_problem() {
        let error = parse_assignment("not json").unwrap_err();
        assert!(error.contains("JSON"));
    }

    /// A window is what makes pairing possible at all; it has to last long
    /// enough to walk to the phone and short enough to stop being useful.
    #[test]
    fn the_pairing_window_is_minutes_not_hours() {
        assert_eq!(PAIRING_TTL.as_secs(), 300);
    }
}
