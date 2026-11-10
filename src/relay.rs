// Copyright (c) 2026 anti-rainer
// SPDX-License-Identifier: MIT

//! The Relay side of the AirSIM bridge, served by this process.
//!
//! AirSIM's cloud path expects a relay it can register with, poll for agent
//! status, and enqueue commands on. Upstream that relay is a public service
//! (`airsim-push.remotepilot.site`); here it is this plugin, which already owns
//! the control plane, the audio bridge and the Celmux link. Serving the relay
//! contract ourselves means the phone's cloud path and its direct path end at the
//! same code, and nothing about the calls depends on an outside service being up.
//!
//! The contract is small - five routes - and it is fixed by the phone, not by us:
//!
//! ```text
//! GET  healthz                 {"ok":true,"service":"airsim-push-relay","version":"…"}
//! POST v1/devices/register     {"registered":true}
//! POST v1/devices/status       the agent directory
//! POST v2/commands/enqueue     accept a command, answer with the call identity
//! POST v2/commands/result      how that command ended
//! ```
//!
//! Two things about it are worth knowing before reading the handlers. The phone
//! generates `device_id`/`device_secret` itself and registers them here, so this
//! side stores credentials rather than issuing them. And the audio for a cloud
//! call is carried on the same PCM gateway the direct path uses, so a cloud call
//! and a direct call differ only in how the phone reaches this plugin.

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde_json::{Value, json};

/// What the phone is told the relay is. `healthz` is checked verbatim: a relay
/// that answers with any other service name is treated as the wrong server.
pub const SERVICE: &str = "airsim-push-relay";
/// The relay contract this implements.
pub const VERSION: &str = "celmux-1.0.0";
/// How long a heartbeat keeps an agent counted as online.
///
/// The phone's self-test reports "心跳过期" past this window, and the upstream
/// agent heartbeats every 120 s to stay inside it.
pub const ONLINE_WINDOW: std::time::Duration = std::time::Duration::from_secs(150);

/// How often this agent reports in.
///
/// The phone counts an agent online for 150 s after its last heartbeat, and the
/// upstream agent uses 120 s to stay inside that without chattering on a weak
/// link. This process is both the agent and the relay, so nothing external would
/// ever send a heartbeat: without this timer the directory would say "心跳过期"
/// about a gateway that is answering every other request correctly.
pub const HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// One phone that registered for the cloud path.
///
/// The phone is the party that generates these, so they are stored, not issued.
#[derive(Clone, Debug, Default)]
pub struct Device {
    pub device_id: String,
    pub device_secret: String,
    /// Push tokens the phone reported. This relay sends no pushes - the plugin has
    /// no APNs credentials - but they are kept so a future push path does not
    /// need a second registration format.
    pub voip_token: String,
    pub alert_token: String,
    pub environment: String,
    pub bundle_id: String,
    pub relay_url: String,
    pub registered_at: Option<std::time::SystemTime>,
}

/// A call that just started ringing, as a push describes it.
///
/// The same shape the phone reads out of a push payload, kept apart from the push
/// itself so it can be built and tested without a key.
#[derive(Clone, Debug, Default)]
pub struct IncomingCall {
    pub call_id: String,
    /// A fresh UUID per call, not derived from the call id.
    ///
    /// The phone hands this straight to CallKit, and CallKit treats a repeated
    /// UUID as the same call. A retried push therefore reuses it (see
    /// `Control::push_ringing_call`), but a different call must never share one.
    pub call_uuid: String,
    /// The secret the phone signs its media handshake with.
    ///
    /// Short of 24 characters the phone discards the whole notification - it
    /// validates this before it even looks at the number - so this is not
    /// optional decoration.
    pub call_secret: String,
    pub number: String,
    pub caller_name: String,
    pub generation: u64,
    /// When the call started ringing, as an ISO 8601 timestamp.
    pub issued_at: String,
    /// When this push stops being worth delivering.
    ///
    /// The phone drops a push whose expiry has passed, so a call that has already
    /// been abandoned cannot ring a phone minutes later.
    pub expires_at: String,
    /// The same instant as `expires_at`, in the seconds-since-epoch form APNs
    /// wants for `apns-expiration`.
    pub expires_unix: u64,
    /// Where the phone opens media for this call.
    pub media_url: String,
}

/// A command the phone asked this agent to run.
#[derive(Clone, Debug)]
pub struct Command {
    pub command_id: String,
    pub kind: String,
    pub number: String,
    pub message: String,
    pub sim_account: String,
    pub target_agent_id: String,
    /// `completed` or `failed` once it has run; `accepted` while pending.
    pub status: String,
    pub error: String,
    pub enqueued_at: std::time::SystemTime,
}

/// The relay's own state: registered phones, their commands, and when this
/// agent was last heard from.
pub struct State {
    inner: Mutex<Inner>,
    /// The registered id this gateway signs as, when more than one registered.
    preferred: Mutex<String>,
    /// The credential the phone itself registered with a relay under.
    ///
    /// Sent only inside the pairing claim, and kept apart from the devices this
    /// state registered: those are phones that registered *here*, this is the one
    /// the phone registered elsewhere. With an external relay it is the only
    /// credential an event can be signed with.
    phone_relay: Mutex<Option<crate::agents::RelayCredentials>>,
    /// Where the registered device is remembered, so a restart does not reopen
    /// registration to the world. `None` keeps it in memory only, which is what
    /// the tests use.
    store: Option<std::path::PathBuf>,
}

/// Whether a registration body is shaped like a device identity.
///
/// The same floor the upstream relay enforces, so a phone that works against
/// theirs works here and one that fails there does not appear to work here. The
/// bundle id is not compared against a fixed value: this gateway serves one app,
/// which the operator configures, so the check belongs to the push path.
fn validate_registration(body: &Value) -> Result<(), String> {
    let text = |key: &str| {
        body.get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_owned()
    };
    let device_id = text("device_id");
    let device_secret = text("device_secret");
    if device_id.is_empty() || device_id.len() > 128 {
        return Err("device_id 无效".to_owned());
    }
    // The secret is a base64url random value the phone generates; the floor keeps
    // an empty or placeholder one from becoming a device here.
    if device_secret.len() < 16 || device_secret.len() > 512 {
        return Err("device_secret 长度无效".to_owned());
    }
    let has_token = [
        "voip_token",
        "alert_token",
        "watch_voip_token",
        "live_activity_push_to_start_token",
    ]
    .iter()
    .any(|key| !text(key).is_empty());
    if !has_token {
        return Err("至少需要一个 APNs token".to_owned());
    }
    Ok(())
}

impl Default for State {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            preferred: Mutex::new(String::new()),
            phone_relay: Mutex::new(None),
            store: None,
        }
    }
}

impl State {
    /// A state that remembers its registered device across restarts.
    ///
    /// Registration binds this relay to one phone, so forgetting the binding on
    /// every restart would mean a window after each restart in which a stranger
    /// could claim the gateway. The file sits beside the pairing secrets and is
    /// created `0600` for the same reason.
    pub fn persistent(root: &std::path::Path) -> Self {
        let path = root.join("relay-device");
        let mut inner = Inner::default();
        let mut preferred_id = String::new();
        let mut phone_relay: Option<crate::agents::RelayCredentials> = None;
        if let Ok(file) = std::fs::read_to_string(&path) {
            for text in file.lines() {
                // Four fields: id, secret, VoIP token, alert token. An older file has
                // only the first two, so the tokens are read as optional rather than
                // making the whole registration unreadable.
                let line = text.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                // `^ id` names the device this gateway signs as when several have.
                if let Some(preferred) = line.strip_prefix("^ ") {
                    preferred_id = preferred.trim().to_owned();
                    continue;
                }
                // `= id secret relay` is the phone's own relay credential.
                if let Some(rest) = line.strip_prefix("= ") {
                    let mut fields = rest.splitn(3, ' ');
                    let device_id = fields.next().unwrap_or("").to_owned();
                    let device_secret = fields.next().unwrap_or("").to_owned();
                    let relay_url = fields.next().unwrap_or("").to_owned();
                    if !device_id.is_empty() && !device_secret.is_empty() {
                        phone_relay = Some(crate::agents::RelayCredentials {
                            device_id,
                            device_secret,
                            relay_url,
                        });
                    }
                    continue;
                }
                let mut fields = line.split_whitespace();
                let id = fields.next().unwrap_or("");
                let secret = fields.next().unwrap_or("");
                let voip_token = fields.next().unwrap_or("");
                let alert_token = fields.next().unwrap_or("");
                // A trailing empty field is lost to `split_whitespace`; that is fine,
                // an absent token and an empty one mean the same thing here.
                if !id.is_empty() && !secret.is_empty() {
                    inner.devices.insert(
                        id.to_owned(),
                        Device {
                            device_id: id.to_owned(),
                            device_secret: secret.to_owned(),
                            voip_token: voip_token.to_owned(),
                            alert_token: alert_token.to_owned(),
                            registered_at: Some(std::time::SystemTime::now()),
                            ..Device::default()
                        },
                    );
                }
            }
        }
        Self {
            inner: Mutex::new(inner),
            preferred: Mutex::new(preferred_id),
            phone_relay: Mutex::new(phone_relay),
            store: Some(path),
        }
    }

    /// Write the owning device out, so the binding survives a restart.
    ///
    /// Four space-separated fields: id, secret, VoIP token, alert token. The last
    /// two may be empty, which is why they are positional rather than named - the
    /// file is read by this process alone.
    fn persist(&self) {
        let Some(path) = self.store.as_ref() else {
            return;
        };
        // One line per device: `id secret voip alert`, and a leading `+` marks an
        // id approved but not yet registered. One file because the registry is one
        // thing: a second file would let the two drift apart after a crash between
        // writes.
        let mut lines: Vec<String> = Vec::new();
        if let Ok(preferred) = self.preferred.lock()
            && !preferred.is_empty()
        {
            lines.push(format!("^ {preferred}"));
        }
        if let Some(relay) = self.phone_relay() {
            lines.push(format!(
                "= {} {} {}",
                relay.device_id, relay.device_secret, relay.relay_url
            ));
        }
        if let Ok(inner) = self.inner.lock() {
            for device in inner.devices.values() {
                lines.push(format!(
                    "{} {} {} {}",
                    device.device_id, device.device_secret, device.voip_token, device.alert_token
                ));
            }
        }
        let text = format!("{}\n", lines.join("\n"));
        let temporary = path.with_extension("tmp");
        let written = std::fs::File::create(&temporary).and_then(|mut file| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
            }
            use std::io::Write;
            file.write_all(text.as_bytes())
        });
        if written.is_ok() {
            let _ = std::fs::rename(&temporary, path);
        }
    }
}

#[derive(Default)]
struct Inner {
    devices: BTreeMap<String, Device>,
    commands: BTreeMap<String, Command>,
    /// When the agent last reported in. `None` until the first heartbeat.
    last_heartbeat: Option<std::time::SystemTime>,
    /// The most recent heartbeat's own fields, echoed back in the directory so a
    /// phone sees what the agent said about itself rather than a guess.
    heartbeat: BTreeMap<String, Value>,
}

impl State {
    /// Record a registration, keeping any push tokens the phone already sent.
    ///
    /// Returns the stored device and whether this was the first registration of
    /// it, which is what tells "the phone came back" from "the phone is retrying
    /// because it never succeeded".
    pub fn register(&self, body: &Value) -> (Device, bool) {
        if let Err(reason) = validate_registration(body) {
            crate::log_warn!("celmux-plugin-airsim: Relay 拒绝注册：{reason}");
            return (
                Device {
                    device_id: String::new(),
                    ..Device::default()
                },
                false,
            );
        }
        let device_id = text(body, "device_id");
        let mut device = Device {
            device_id: device_id.clone(),
            device_secret: text(body, "device_secret"),
            voip_token: text(body, "voip_token"),
            alert_token: text(body, "alert_token"),
            environment: text(body, "environment"),
            bundle_id: text(body, "bundle_id"),
            relay_url: text(body, "relay_url"),
            registered_at: Some(std::time::SystemTime::now()),
        };
        let Ok(mut inner) = self.inner.lock() else {
            return (device, false);
        };
        // Registration is open to a new device and closed to an impostor, the way
        // the upstream relay does it: the phone's `device_id` is the first 16 bytes
        // of SHA-256 over its `device_secret`, so an id is not a name somebody
        // picks - it is derived from the credential. Re-presenting a known id
        // therefore has to present the same secret, and a new id is a different
        // phone with its own credential.
        //
        // This replaces the pairing-path secret and the first-registration lock:
        // both defended against a stranger registering, but neither could tell a
        // second legitimate device from an intruder, and the path was a shared
        // secret the operator had to distribute.
        if let Some(previous) = inner.devices.get(&device_id)
            && !constant_time_eq(&previous.device_secret, &device.device_secret)
        {
            crate::log_warn!(
                "celmux-plugin-airsim: Relay 拒绝注册：device_id={device_id} 的密钥与已登记的不一致"
            );
            return (
                Device {
                    device_id: String::new(),
                    ..Device::default()
                },
                false,
            );
        }
        // A re-registration that omits a token must not erase the one already
        // stored: the phone only sends them when APNs hands it a new one.
        let first = !inner.devices.contains_key(&device_id);
        if let Some(previous) = inner.devices.get(&device_id) {
            if device.voip_token.is_empty() {
                device.voip_token = previous.voip_token.clone();
            }
            if device.alert_token.is_empty() {
                device.alert_token = previous.alert_token.clone();
            }
        }
        inner.devices.insert(device_id, device.clone());
        drop(inner);
        // Only after the binding is in memory, and only for a registration that
        // was accepted: a refused one has already returned above.
        self.persist();
        (device, first)
    }

    /// Remember the push tokens the phone reported.
    ///
    /// Returns whether anything was stored. The tokens persist across a restart
    /// through the same one-line file as the device credential, because a phone
    /// only re-registers when APNs hands it a new token - a restart must not lose
    /// the ability to ring it.
    pub fn store_push_tokens(&self, body: &Value) -> bool {
        let voip = text(body, "voip_token");
        let alert = text(body, "alert_token");
        if voip.is_empty() && alert.is_empty() {
            return false;
        }
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        // Which device the tokens belong to. The phone names itself; falling back
        // to "the only one" would hand an Android agent's token to the celmux
        // phone when both use this relay.
        let named = text(body, "device_id");
        let target = if !named.is_empty() {
            if inner.devices.contains_key(&named) {
                Some(named)
            } else {
                return false;
            }
        } else if inner.devices.len() == 1 {
            inner.devices.keys().next().cloned()
        } else {
            // Ambiguous: more than one device registered and the request did not
            // say which. Guessing would deliver a call to the wrong phone.
            return false;
        };
        let Some(device) = target.and_then(|id| inner.devices.get_mut(&id)) else {
            // A token for a device that never registered is not usable: the
            // registration is what binds the token to this gateway.
            return false;
        };
        if !voip.is_empty() {
            device.voip_token = voip.clone();
        }
        if !alert.is_empty() {
            device.alert_token = alert.clone();
        }
        drop(inner);
        self.persist();
        true
    }

    /// The registered phone's credentials, for signing events.
    ///
    /// This process is the party that registered the phone, so when it is also
    /// its own relay it can sign as that phone without being told anything. That
    /// is what makes the agent half work with no extra configuration.
    pub fn credentials(&self) -> Option<(String, String)> {
        self.owner()
            .map(|device| (device.device_id, device.device_secret))
    }

    /// The device this gateway acts for.
    ///
    /// Several may register - an operator running celmux beside an upstream
    /// Android agent has two - and the events this process generates are its own
    /// phone's. `preferred` names that id when the operator set it; otherwise the
    /// first registration is the one, which is the celmux phone in the ordinary
    /// case because celmux installs and starts this plugin.
    /// The VoIP token of the device this gateway acts for.
    ///
    /// A call is pushed to this one: a VoIP token only accepts `voip` pushes, and
    /// sending a call to an alert token is answered as an invalid topic.
    pub fn voip_token(&self) -> Option<String> {
        self.owner().map(|device| device.voip_token)
    }

    /// The alert token, for an ordinary notification such as a received message.
    pub fn alert_token(&self) -> Option<String> {
        self.owner()
            .map(|device| device.alert_token)
            .filter(|token| !token.is_empty())
    }

    fn owner(&self) -> Option<Device> {
        let inner = self.inner.lock().ok()?;
        // The earliest registration, not the smallest id: `devices` is keyed by id,
        // so iteration order is alphabetical and would quietly pick `android-agent`
        // over `celmux-phone` for a reason nobody chose.
        inner
            .devices
            .values()
            .min_by_key(|device| device.registered_at)
            .cloned()
    }

    /// Keep the credential the phone registered with a relay under.
    ///
    /// Test-only: production learns the paired identity from the agent's pairing
    /// record, and a setter reachable from a registration is exactly how a stranger
    /// took this over before.
    #[cfg(test)]
    pub fn set_phone_relay(&self, relay: crate::agents::RelayCredentials) {
        if let Ok(mut slot) = self.phone_relay.lock() {
            *slot = Some(relay);
        }
        self.persist();
    }

    /// The devices registered here, for the operator to see who is connected.
    pub fn devices(&self) -> Vec<Value> {
        let Ok(inner) = self.inner.lock() else {
            return Vec::new();
        };
        inner
            .devices
            .values()
            .map(|device| {
                json!({
                    "device_id": device.device_id,
                    // Never the secret: the page only needs to know a device is
                    // there, and a secret on a page is a secret in a screenshot.
                    "has_push": !device.voip_token.is_empty(),
                    "registered_at": device.registered_at
                        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|age| age.as_secs()),
                })
            })
            .collect()
    }

    /// The credential the phone registered with a relay under, if it reported one.
    pub fn phone_relay(&self) -> Option<crate::agents::RelayCredentials> {
        self.phone_relay.lock().ok().and_then(|slot| slot.clone())
    }

    /// Whether `secret` is the credential of `device_id`.
    pub fn authenticates(&self, device_id: &str, secret: &str) -> bool {
        if device_id.is_empty() || secret.is_empty() {
            return false;
        }
        self.inner.lock().is_ok_and(|inner| {
            inner
                .devices
                .get(device_id)
                .is_some_and(|device| constant_time_eq(&device.device_secret, secret))
        })
    }

    /// Note that the agent reported in, and what it said.
    pub fn heartbeat(&self, body: &Value) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.last_heartbeat = Some(std::time::SystemTime::now());
            inner.heartbeat = body
                .as_object()
                .map(|fields| {
                    fields
                        .iter()
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect()
                })
                .unwrap_or_default();
        }
    }

    /// Seconds since the agent last reported in, or `None` if it never has.
    fn silence(&self) -> Option<u64> {
        self.inner.lock().ok().and_then(|inner| {
            inner.last_heartbeat.and_then(|at| {
                std::time::SystemTime::now()
                    .duration_since(at)
                    .ok()
                    .map(|age| age.as_secs())
            })
        })
    }

    /// Whether the agent is inside the window the phone counts as online.
    pub fn online(&self) -> bool {
        self.silence()
            .is_some_and(|age| age < ONLINE_WINDOW.as_secs())
    }

    /// Record a command the phone enqueued, returning the stored copy.
    pub fn enqueue(&self, body: &Value) -> Command {
        let command = Command {
            command_id: text(body, "command_id"),
            kind: text(body, "type"),
            number: text(body, "number"),
            message: text(body, "message"),
            sim_account: text(body, "sim_account"),
            target_agent_id: text(body, "target_agent_id"),
            status: "accepted".to_owned(),
            error: String::new(),
            enqueued_at: std::time::SystemTime::now(),
        };
        if let Ok(mut inner) = self.inner.lock() {
            // Commands are short-lived and few; keeping an unbounded map of them
            // would only be a way to leak memory on a long-running gateway.
            inner.commands.retain(|_, existing| {
                elapsed_seconds(existing.enqueued_at) < COMMAND_RETENTION.as_secs()
            });
            inner
                .commands
                .insert(command.command_id.clone(), command.clone());
        }
        command
    }

    /// Store the outcome of a command that has run.
    pub fn complete(&self, command_id: &str, status: &str, error: &str) {
        if let Ok(mut inner) = self.inner.lock()
            && let Some(command) = inner.commands.get_mut(command_id)
        {
            command.status = status.to_owned();
            command.error = error.to_owned();
        }
    }

    /// One command, for the phone to poll.
    pub fn command(&self, command_id: &str) -> Option<Command> {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| inner.commands.get(command_id).cloned())
    }

    /// The agent directory document.
    ///
    /// Built from what this plugin actually knows about itself: one agent, this
    /// one, whose online state is whether its heartbeat is recent. `agents` is
    /// always non-empty while the gateway is alive, because a relay that reports
    /// no agents is what makes the phone's self-test fail at the first step.
    pub fn status(&self, agent: &AgentReport) -> Value {
        let online = self.online();
        let heartbeat = self
            .inner
            .lock()
            .map(|inner| inner.heartbeat.clone())
            .unwrap_or_default();
        let silence = self.silence();
        let cellular_state = heartbeat
            .get("cellular_state")
            .cloned()
            .unwrap_or_else(|| json!(if online { "registered" } else { "unknown" }));
        json!({
            "cloud_online": online,
            "agent_version": agent.version,
            "at_ok": agent.at_ok,
            "cellular_state": cellular_state,
            "cellular_registration": heartbeat
                .get("cellular_registration")
                .cloned()
                .unwrap_or_else(|| json!("celmux")),
            "cellular_recovery": heartbeat
                .get("cellular_recovery")
                .cloned()
                .unwrap_or_else(|| json!("not_required")),
            "signal_dbm": heartbeat.get("signal_dbm").cloned(),
            "active_agent_id": agent.id,
            "capabilities": {"agent_command_routing": 1},
            "agents": [{
                "agent_id": agent.id,
                "agent_kind": "celmux",
                "device_name": agent.name,
                "manufacturer": "celmux",
                "model": agent.model,
                "phone_number": agent.number,
                "agent_version": agent.version,
                "cloud_online": online,
                "command_routing_version": 1,
                "battery": {"level": Value::Null, "charging": Value::Null},
            }],
            // Not part of the phone's model, but the only place an operator can
            // see how stale the heartbeat is without reading this process's log.
            "heartbeat_age_seconds": silence,
        })
    }
}

/// What this agent says about itself in its own heartbeat.
///
/// The directory echoes these fields back to the phone, so they are the ones the
/// phone shows: which service this is, that its AT layer is up, and what it is
/// calling itself. Values that would be guesses are left out rather than invented.
pub fn self_report() -> Value {
    json!({
        "event": "agent_heartbeat",
        "agent_version": VERSION,
        "agent_kind": "celmux",
        // A relay validates this against a four-value vocabulary and rejects
        // anything else outright, so the value is chosen from that set rather
        // than described freely.
        "cellular_state": "registered",
        "cellular_registration": "celmux",
        "cellular_recovery": "not_required",
        "ecm_carrier": "celmux",
        "at_ok": true,
        "command_routing_version": 1,
        // Nullable readings this gateway does not measure. Present and null
        // rather than absent, so a relay's schema sees the field it expects.
        "signal_dbm": Value::Null,
        "battery": {"level": Value::Null, "charging": Value::Null},
    })
}

/// The cellular states a relay accepts.
///
/// Upstream refuses a heartbeat whose state is anything outside this set, so the
/// vocabulary lives here rather than being spelled out at each call site.
pub const CELLULAR_STATES: [&str; 4] = ["registered", "searching", "denied", "unregistered"];

/// Whether a heartbeat's cellular state is one a relay will accept.
pub fn valid_cellular_state(state: &str) -> bool {
    CELLULAR_STATES.contains(&state)
}

/// How long a finished command is kept for the phone to poll.
const COMMAND_RETENTION: std::time::Duration = std::time::Duration::from_secs(300);

/// What this relay says about the agent it fronts.
///
/// Owned rather than borrowed: the name is computed from the live line list, so
/// it changes while the gateway runs and cannot be a reference to anything
/// stable.
pub struct AgentReport {
    pub id: String,
    pub name: String,
    pub model: String,
    pub number: String,
    pub version: String,
    pub at_ok: bool,
}

fn elapsed_seconds(at: std::time::SystemTime) -> u64 {
    std::time::SystemTime::now()
        .duration_since(at)
        .map(|age| age.as_secs())
        .unwrap_or(0)
}

fn text(body: &Value, key: &str) -> String {
    body.get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_owned()
}

/// Compare without leaking how much of a secret matched.
fn constant_time_eq(left: &str, right: &str) -> bool {
    let (left, right) = (left.as_bytes(), right.as_bytes());
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> AgentReport {
        AgentReport {
            id: "celmux".to_owned(),
            name: "celmux".to_owned(),
            model: "MU300".to_owned(),
            number: "+447".to_owned(),
            version: "0.2.0".to_owned(),
            at_ok: true,
        }
    }

    /// A phone registers the credentials it generated; only those come back in.
    #[test]
    fn a_registered_device_authenticates_with_its_own_secret() {
        let state = State::default();
        let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        state.register(&json!({"device_id": "d1", "device_secret": secret, "voip_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}));
        assert!(state.authenticates("d1", secret));
        assert!(!state.authenticates("d1", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"));
        assert!(!state.authenticates("d2", secret));
        assert!(!state.authenticates("d1", ""));
    }

    /// The directory names this agent before any heartbeat arrives, because a
    /// relay that answers with no agents fails the phone's first step.
    #[test]
    fn the_directory_always_lists_this_agent_and_ages_its_heartbeat() {
        let state = State::default();
        let before = state.status(&report());
        assert_eq!(before["agents"].as_array().map(Vec::len), Some(1));
        assert_eq!(before["agents"][0]["agent_id"], json!("celmux"));
        // No heartbeat yet: present, but not online.
        assert_eq!(before["cloud_online"], json!(false));
        assert_eq!(before["heartbeat_age_seconds"], Value::Null);

        state.heartbeat(&json!({"cellular_state": "registered", "at_ok": true}));
        let after = state.status(&report());
        assert_eq!(after["cloud_online"], json!(true));
        assert_eq!(after["agents"][0]["cloud_online"], json!(true));
        assert_eq!(after["cellular_state"], json!("registered"));
        // The routing version the phone reads comes from capabilities.
        assert_eq!(after["capabilities"]["agent_command_routing"], json!(1));
    }

    /// A command is accepted, then carries whatever outcome it ended with.
    #[test]
    fn a_command_keeps_its_outcome_for_the_phone_to_poll() {
        let state = State::default();
        let command = state.enqueue(&json!({
            "command_id": "c1", "type": "dial", "number": "0800",
            "target_agent_id": "celmux",
        }));
        assert_eq!(command.status, "accepted");
        assert_eq!(command.kind, "dial");

        state.complete("c1", "completed", "");
        let stored = state.command("c1").unwrap();
        assert_eq!(stored.status, "completed");
        assert_eq!(stored.number, "0800");
        assert!(state.command("missing").is_none());
    }

    /// The agent's own report is what the phone reads as "this device is alive".
    ///
    /// It has to say enough for the directory to answer, and it must not claim a
    /// version or a service different from what `healthz` reports.
    #[test]
    fn the_self_report_names_this_service_and_its_version() {
        let report = self_report();
        assert_eq!(report["event"], json!("agent_heartbeat"));
        assert_eq!(report["agent_version"], json!(VERSION));
        assert_eq!(report["at_ok"], json!(true));

        // Feeding it back is what the heartbeat timer does, and it must put the
        // directory into the online state the phone's self-test looks for.
        let state = State::default();
        assert!(!state.online());
        state.heartbeat(&report);
        assert!(state.online());
        assert_eq!(state.status(&tests::report())["cloud_online"], json!(true));
    }

    /// Secrets compared in constant time still compare correctly.
    #[test]
    fn secret_comparison_is_exact() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
        assert!(constant_time_eq("", ""));
    }
    /// Two devices, one relay: an upstream agent beside celmux.
    ///
    /// Either may register, the way the upstream relay allows it: an id is derived
    /// from the phone's secret, so a second phone is a second id rather than an
    /// intruder. What must not happen is one device's token being used for the
    /// other - a call pushed to the wrong handset.
    #[test]
    fn a_second_device_registers_and_each_keeps_its_own_tokens() {
        let state = State::default();
        let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let celmux = serde_json::json!({
            "device_id": "celmux-phone",
            "device_secret": secret,
            "voip_token": "voip-a",
            "alert_token": "alert-a",
        });
        let (accepted, first) = state.register(&celmux);
        assert!(
            first && accepted.device_id == "celmux-phone",
            "第一台设备应当直接注册成功"
        );

        // A second phone: its own id and its own credential.
        let android = serde_json::json!({
            "device_id": "android-agent",
            "device_secret": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            "voip_token": "voip-b",
        });
        assert!(
            state.register(&android).0.device_id == "android-agent",
            "第二台设备用自己凭据应当能注册"
        );

        // Each keeps its own push token: sharing one would send a celmux call to
        // the Android handset.
        assert_eq!(
            state.voip_token().as_deref(),
            Some("voip-a"),
            "本网关推的是最先登记的那台手机"
        );
        let android_token = state
            .devices()
            .into_iter()
            .find(|device| device["device_id"] == json!("android-agent"))
            .map(|device| device["has_push"].clone());
        assert_eq!(
            android_token,
            Some(json!(true)),
            "第二台设备的推送凭据应当独立保存"
        );

        // A known id with the wrong secret is refused: a reinstall returns with
        // the same secret, an impostor does not.
        let impostor = serde_json::json!({
            "device_id": "celmux-phone",
            "device_secret": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            "voip_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        });
        assert!(
            state.register(&impostor).0.device_id.is_empty(),
            "已登记设备的错误密钥必须被拒绝"
        );
    }

    /// The registration and the acting device survive a restart.
    ///
    /// A phone only re-registers when APNs hands it a new token, so a restart that
    /// forgot the binding would leave this gateway unable to ring it until the
    /// phone happened to refresh.
    #[test]
    fn the_registration_and_the_acting_device_survive_a_restart() {
        let root = std::env::temp_dir().join(format!("celmux-relay-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::create_dir_all(&root);
        {
            let state = State::persistent(&root);
            state.register(&serde_json::json!({
                "device_id": "celmux-phone",
                "device_secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "voip_token": "voip-a",
            }));
        }
        let reloaded = State::persistent(&root);
        assert_eq!(
            reloaded.voip_token().as_deref(),
            Some("voip-a"),
            "重启后仍应能推出自己那台手机"
        );
        assert!(
            reloaded.authenticates(
                "celmux-phone",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            ),
            "重启后凭据仍应能通过校验"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Registering must not touch the paired identity.
    ///
    /// It did: `register` recorded the caller's credential as the phone's relay
    /// credential, so whoever registered last became the identity this gateway
    /// signs as. A stranger who reached the port could take it over without ever
    /// pairing, and then receive the pushes meant for the operator's phone.
    #[test]
    fn registering_never_replaces_the_paired_identity() {
        let state = State::default();
        state.set_phone_relay(crate::agents::RelayCredentials {
            device_id: "paired-phone".to_owned(),
            device_secret: "paired-secret".to_owned(),
            relay_url: "https://relay.example.com".to_owned(),
        });
        assert_eq!(
            state.phone_relay().map(|relay| relay.device_id),
            Some("paired-phone".to_owned())
        );

        // A stranger registers with a credential of their own.
        let (device, _) = state.register(&serde_json::json!({
            "device_id": "intruder",
            "device_secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "voip_token": "a".repeat(64),
        }));
        assert_eq!(device.device_id, "intruder", "注册本身应当成功");

        // The identity this gateway signs as is still the paired phone's.
        assert_eq!(
            state.phone_relay().map(|relay| relay.device_id),
            Some("paired-phone".to_owned()),
            "注册不得改写已配对身份"
        );
    }
}
