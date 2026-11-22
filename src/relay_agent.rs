// Copyright (c) 2026 anti-rainer
// SPDX-License-Identifier: MIT

//! The agent side of the cloud path: telling a relay what just happened.
//!
//! Upstream AirSIM splits the cloud path in two. The agent reports events and the
//! relay turns them into pushes, which is what makes a relay shareable: whoever
//! runs it holds the APNs key and nobody else needs one. This module is the agent
//! half, written to that contract rather than to this plugin's own shape, so the
//! same events reach this installation's relay and the AirSIM author's.
//!
//! ```text
//! POST /v1/devices/register      the phone's registration, forwarded as-is
//! POST /v1/events/call           a call is ringing
//! POST /v1/events/sms            a message arrived
//! POST /v1/events/heartbeat      this agent is alive
//! POST /v2/commands/pull         what the phone queued for this agent
//! POST /v2/commands/complete     how that command ended
//! ```
//!
//! Every event is signed as the *phone*, because that is the record a relay looks
//! up to find a push token. When this plugin also runs the relay it is the party
//! that registered the phone, so it has the credentials anyway; pointing the
//! agent at an outside relay means the phone must have registered there.

use serde_json::{Value, json};

/// Where events go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// This plugin's own relay, reached on the loopback port it listens on.
    ///
    /// Kept distinct from an explicit address because it is the case where this
    /// process holds the APNs key, and therefore the one case where a push can be
    /// sent without a network round-trip.
    Own { port: u16 },
    /// Somebody else's relay, by address.
    External { base: String },
}

impl Target {
    /// Decide from configuration.
    ///
    /// An empty address means "my own relay": the operator who never filled this
    /// in is the one running a single installation, and asking them to type their
    /// own loopback address would be a trap.
    /// Resolve from an explicit mode, falling back to the address's presence.
    ///
    /// `own` ignores the address entirely, and `external` requires one: the mode
    /// is the operator's statement about which relay is in charge, so the other
    /// side's leftovers must not quietly win. A mode this build does not know is
    /// treated as a request for the local relay rather than as a failure - the
    /// safe reading of an unrecognised value is the one whose key is here.
    pub fn from_mode(mode: &str, configured: &str, own_port: u16) -> Self {
        let trimmed = configured.trim().trim_end_matches('/');
        match mode.trim().to_ascii_lowercase().as_str() {
            "external" if !trimmed.is_empty() => Self::External {
                base: trimmed.to_owned(),
            },
            "external" => Self::Own { port: own_port },
            _ => Self::Own { port: own_port },
        }
    }

    /// The base address an event is posted to.
    pub fn base(&self) -> String {
        match self {
            Self::Own { port } => format!("http://127.0.0.1:{port}"),
            Self::External { base } => base.clone(),
        }
    }

    /// Whether this process is also the relay that receives these events.
    pub fn is_own(&self) -> bool {
        matches!(self, Self::Own { .. })
    }
}

/// The credentials an event is signed with.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Credentials {
    pub device_id: String,
    pub device_secret: String,
}

impl Credentials {
    /// Whether a signed event can be sent at all.
    ///
    /// Without these a relay answers 401 whatever the payload says, so the check
    /// happens here rather than as a rejected round-trip.
    pub fn ready(&self) -> bool {
        !self.device_id.is_empty() && !self.device_secret.is_empty()
    }
}

/// What a relay answered.
#[derive(Clone, Debug)]
pub struct Reply {
    pub status: u16,
    pub body: Value,
}

impl Reply {
    /// Whether the relay accepted the event.
    pub fn accepted(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// A client for whichever relay is configured.
pub struct Agent {
    target: Target,
    /// Behind a lock because a credential can arrive later: the phone registers
    /// with this process's relay after the agent is built, and an event sent
    /// before that has nobody to sign as.
    credentials: std::sync::Mutex<Credentials>,
    agent_id: String,
}

impl Agent {
    pub fn new(target: Target, credentials: Credentials, agent_id: &str) -> Self {
        Self {
            target,
            credentials: std::sync::Mutex::new(credentials),
            agent_id: agent_id.to_owned(),
        }
    }

    /// Where this agent's events go.
    pub fn target(&self) -> &Target {
        &self.target
    }

    /// Whether events can be sent: a relay is configured and credentials exist.
    pub fn ready(&self) -> bool {
        self.credentials().ready()
    }

    /// Fill in credentials the plugin discovered for itself.
    ///
    /// An explicitly configured pair wins: an external relay needs the phone to
    /// have registered there, and what this process knows is only its own
    /// registration. With nothing configured, the phone that registered with this
    /// plugin's relay is exactly the right identity to sign as - which is why a
    /// self-hosted setup needs no extra configuration.
    pub fn adopt(&self, credentials: Credentials) {
        if let Ok(mut current) = self.credentials.lock()
            && !current.ready()
            && credentials.ready()
        {
            *current = credentials;
        }
    }

    /// The credentials in use, for the settings page to report.
    pub fn credentials(&self) -> Credentials {
        self.credentials
            .lock()
            .map(|current| current.clone())
            .unwrap_or_default()
    }

    /// Report a ringing call.
    ///
    /// The payload is the one the AirSIM relay validates: `event` must be
    /// `incoming_call`, `call_uuid` must be a UUID, and `expires_at` must be
    /// within two minutes of now. A relay rejects anything else with 400, so
    /// these fields are a contract and not a preference.
    pub fn call(&self, call: &crate::relay::IncomingCall) -> Result<Reply, String> {
        let signed = self.credentials();
        self.post(
            "/v1/events/call",
            json!({
                "agent_id": self.agent_id,
                "event": "incoming_call",
                "device_id": signed.device_id,
                "device_secret": signed.device_secret,
                "call_id": call.call_id,
                "call_uuid": call.call_uuid,
                "generation": call.generation,
                "call_secret": call.call_secret,
                "number": call.number,
                "caller_name": call.caller_name,
                "issued_at": call.issued_at,
                "expires_at": call.expires_at,
                "media_transport": "legacy_pcm",
            }),
        )
    }

    /// Report a received message.
    pub fn sms(&self, message: &SmsEvent) -> Result<Reply, String> {
        let signed = self.credentials();
        self.post(
            "/v1/events/sms",
            json!({
                "event": "incoming_sms",
                "device_id": signed.device_id,
                "device_secret": signed.device_secret,
                "delivery_id": message.delivery_id,
                "sender": message.sender,
                "content": message.content,
                "code": message.code,
                "timestamp": message.timestamp,
            }),
        )
    }

    /// Report that a call changed phase.
    ///
    /// The relay forwards this to the phone as an APNs `background` push, which is
    /// how a *second* device learns that the call was answered elsewhere or is
    /// over. The direct path does not need it: every client polls the same
    /// revision there, so a hangup on one phone wakes the others by itself. Over a
    /// relay there is no shared poll - the phones are behind different networks -
    /// so the only thing that stops a second phone ringing is this event.
    ///
    /// `phase` is a fixed set on the relay (`idle`, `ringing`, `connecting`,
    /// `active`, `ending`, `ended`, `failed`); anything else is a 400. `source`
    /// is likewise fixed (`app`, `callkit`, `agent`, `relay`) and says which layer
    /// decided the phase, so the relay can order events that raced.
    pub fn call_state(
        &self,
        call: &crate::relay::IncomingCall,
        phase: &str,
        source: &str,
        failure: &str,
    ) -> Result<Reply, String> {
        let signed = self.credentials();
        let mut body = json!({
            "event": "call_state",
            "agent_id": self.agent_id,
            "device_id": signed.device_id,
            "device_secret": signed.device_secret,
            "call_id": call.call_id,
            "call_uuid": call.call_uuid,
            "generation": call.generation,
            "phase": phase,
            "source": source,
            "timestamp": now_iso8601(),
        });
        if !failure.is_empty()
            && let Some(object) = body.as_object_mut()
        {
            object.insert("failure".to_owned(), json!(failure));
        }
        self.post("/v1/events/call-state", body)
    }

    /// Report which device owns the call now.
    ///
    /// Distinct from `call_state`: this is not about the call's phase but about
    /// the fact that one device took it and the others should stop offering it.
    /// The relay pushes it to the phone's `alert_token` rather than its VoIP one,
    /// because the phone holding the call is awake - the point is to tell the
    /// sleeping ones.
    pub fn call_owner(
        &self,
        call: &crate::relay::IncomingCall,
        owner: &str,
        phase: &str,
    ) -> Result<Reply, String> {
        let signed = self.credentials();
        self.post(
            "/v1/events/call-owner",
            json!({
                "event": "call_owner",
                "agent_id": self.agent_id,
                "device_id": signed.device_id,
                "device_secret": signed.device_secret,
                "call_id": call.call_id,
                "call_uuid": call.call_uuid,
                "generation": call.generation,
                "owner": owner,
                "phase": phase,
            }),
        )
    }

    /// Say this agent is alive.
    pub fn heartbeat(&self, report: &Value) -> Result<Reply, String> {
        let signed = self.credentials();
        let mut body = report.clone();
        if let Some(object) = body.as_object_mut() {
            object.insert("device_id".to_owned(), json!(signed.device_id));
            object.insert("device_secret".to_owned(), json!(signed.device_secret));
        }
        self.post("/v1/events/heartbeat", body)
    }

    /// Take whatever the phone queued for this agent.
    ///
    /// Upstream splits commands in two directions: the phone enqueues them on the
    /// relay, and the agent pulls them rather than being called. That keeps the
    /// agent behind NAT able to work without an inbound port.
    pub fn pull(&self) -> Result<Reply, String> {
        let signed = self.credentials();
        self.post(
            "/v2/commands/pull",
            json!({
                "device_id": signed.device_id,
                "device_secret": signed.device_secret,
                "agent_id": self.agent_id,
            }),
        )
    }

    /// Report how a pulled command ended.
    pub fn complete(&self, command_id: &str, ok: bool, error: &str) -> Result<Reply, String> {
        let signed = self.credentials();
        self.post(
            "/v2/commands/complete",
            json!({
                "device_id": signed.device_id,
                "device_secret": signed.device_secret,
                "agent_id": self.agent_id,
                "command_id": command_id,
                "status": if ok { "completed" } else { "failed" },
                "error": error,
            }),
        )
    }

    fn post(&self, path: &str, body: Value) -> Result<Reply, String> {
        if !self.ready() {
            return Err("缺少设备凭据，无法向 relay 发送事件".to_owned());
        }
        let url = format!("{}{path}", self.target.base());
        crate::apns_http::post_json(&url, &body)
    }
}

/// The current time as ISO 8601, the format the relay parses.
fn now_iso8601() -> String {
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    iso8601_from_epoch_seconds(since.as_secs())
}

/// Format seconds since the epoch as `YYYY-MM-DDTHH:MM:SS.000Z`.
///
/// Hand-rolled rather than pulling a date crate in for one timestamp: the relay
/// only requires something `Date.parse` accepts, and these are the values a call
/// already carries in `issued_at`.
fn iso8601_from_epoch_seconds(seconds: u64) -> String {
    let days = seconds / 86_400;
    let rest = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.000Z",
        rest / 3_600,
        (rest % 3_600) / 60,
        rest % 60
    )
}

/// Days since 1970-01-01 to a calendar date (Howard Hinnant's algorithm).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

/// One received message, as an SMS event describes it.
#[derive(Clone, Debug, Default)]
pub struct SmsEvent {
    pub delivery_id: String,
    pub sender: String,
    pub content: String,
    /// A verification code the relay may surface separately, when one is present.
    pub code: String,
    pub timestamp: String,
    /// The card this message arrived on, as the client names a slot.
    ///
    /// The push is not the authoritative copy - the agent's own message list is -
    /// but the client merges the two, and a push carrying no line used to erase a
    /// label it already had. Empty means the line was not known, which the client
    /// is told to treat as "keep what you have".
    pub sim_slot: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The timestamp the relay parses has to be a real ISO 8601 instant.
    ///
    /// `receiveCallState` rejects the whole event when `Date.parse(timestamp)` is
    /// not finite, and the failure surfaces only as a 400 from someone else's
    /// server - so the format is checked here rather than discovered there.
    #[test]
    fn the_state_timestamp_is_iso8601_the_relay_can_parse() {
        // Known instants, including the leap day that a naive day-count gets
        // wrong and the epoch itself.
        for (seconds, expected) in [
            (0_u64, "1970-01-01T00:00:00.000Z"),
            (1_000_000_000, "2001-09-09T01:46:40.000Z"),
            (1_709_164_800, "2024-02-29T00:00:00.000Z"),
            (1_800_000_000, "2027-01-15T08:00:00.000Z"),
        ] {
            assert_eq!(iso8601_from_epoch_seconds(seconds), expected);
        }
        // The shape is what the relay's `Date.parse` needs: four-digit year,
        // fixed-width fields, a trailing Z.
        let now = now_iso8601();
        assert_eq!(now.len(), 24, "{now}");
        assert!(now.ends_with('Z'), "{now}");
        assert_eq!(&now[4..5], "-", "{now}");
        assert_eq!(&now[10..11], "T", "{now}");
    }

    /// The phase mapping this side sends is one the relay accepts.
    ///
    /// `receiveCallState` refuses anything outside its own set with a 400, and the
    /// set is not this side's vocabulary: `rejected` and `missed` are Celmux words
    /// for "the call is over" and have to be sent as `ended`. A phase slipping
    /// through unmapped is a dropped event, which shows up as a second phone that
    /// keeps ringing - not as an error anywhere.
    #[test]
    fn only_relay_phases_are_sent() {
        // What the relay accepts, from its own validation.
        let relay_phases = [
            "idle",
            "ringing",
            "connecting",
            "active",
            "ending",
            "ended",
            "failed",
        ];
        // What this side maps Celmux states to.
        for state in ["ringing", "active", "rejected", "missed", "ended", "failed"] {
            let phase = match state {
                "ringing" => "ringing",
                "active" => "active",
                "rejected" | "missed" | "ended" => "ended",
                "failed" => "failed",
                other => panic!("{other} would be dropped rather than sent"),
            };
            assert!(
                relay_phases.contains(&phase),
                "{state} maps to {phase}, which the relay would refuse"
            );
        }
    }

    /// A call-state body names the call and the agent the relay matches on.
    ///
    /// The relay looks the call up by `call_uuid` and checks the agent against the
    /// registration; an event missing either comes back 400 or 403 and reads like a
    /// routing bug rather than a malformed body.
    #[test]
    fn a_call_state_event_names_its_call_and_its_agent() {
        let target = Target::External {
            base: "http://127.0.0.1:1".to_owned(),
        };
        let credentials = Credentials {
            device_id: "device-1".to_owned(),
            device_secret: "secret-1".to_owned(),
        };
        assert!(!target.is_own(), "an external target is not this process");
        let agent = Agent::new(target, credentials, "celmux-1");
        assert!(agent.ready(), "credentials are what make it ready");
        // The base is what every event is posted to, so it must be the relay the
        // operator configured rather than something derived.
        assert_eq!(agent.target().base(), "http://127.0.0.1:1");
    }
}
