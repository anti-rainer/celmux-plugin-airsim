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

    /// Say this agent is alive.
    pub fn heartbeat(&self, report: &Value) -> Result<Reply, String> {
        let signed = self.credentials();
        let mut body = report.clone();
        if let Some(object) = body.as_object_mut() {
            object.insert("device_id".to_owned(), json!(signed.device_id));
            object.insert(
                "device_secret".to_owned(),
                json!(signed.device_secret),
            );
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

/// One received message, as an SMS event describes it.
#[derive(Clone, Debug, Default)]
pub struct SmsEvent {
    pub delivery_id: String,
    pub sender: String,
    pub content: String,
    /// A verification code the relay may surface separately, when one is present.
    pub code: String,
    pub timestamp: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An empty address means this installation's own relay, and nothing else:
    /// asking an operator to type their own loopback address would be a trap.
    #[test]
    fn an_empty_address_means_this_plugins_own_relay() {
        let own = Target::from_mode("", "", 43770);
        assert!(own.is_own());
        assert_eq!(own.base(), "http://127.0.0.1:43770");

        // A trailing slash is not a different relay.
        let external = Target::from_mode("external", "https://relay.example.com/", 43770);
        assert!(!external.is_own());
        assert_eq!(external.base(), "https://relay.example.com");
    }

    /// The point of the split: the same event path serves a relay this process
    /// runs and one somebody else runs, and only the second needs a configured
    /// address.
    ///
    /// When this plugin is its own relay it already knows the phone it
    /// registered, so a credential it discovers later is adopted. When it is not,
    /// the operator's pair is kept - because only the phone's registration at
    /// *that* relay is the right identity there.
    #[test]
    fn discovered_credentials_fill_in_but_never_overwrite_configured_ones() {
        let own = Agent::new(
            Target::from_mode("", "", 43770),
            Credentials::default(),
            "celmux",
        );
        assert!(!own.ready());
        own.adopt(Credentials {
            device_id: "discovered".to_owned(),
            device_secret: "secret".to_owned(),
        });
        assert!(own.ready(), "自有 relay 应自动采用已注册手机的凭据");
        assert_eq!(own.credentials().device_id, "discovered");

        let external = Agent::new(
            Target::from_mode("external", "https://relay.example.com", 43770),
            Credentials {
                device_id: "configured".to_owned(),
                device_secret: "secret".to_owned(),
            },
            "celmux",
        );
        external.adopt(Credentials {
            device_id: "discovered".to_owned(),
            device_secret: "other".to_owned(),
        });
        assert_eq!(
            external.credentials().device_id,
            "configured",
            "外部 relay 必须使用本机配置的凭据，而不是本地注册的那份"
        );
        assert!(!external.target().is_own());
    }

    /// Events are signed as the phone, so credentials are what decides whether
    /// anything can be sent at all.
    #[test]
    fn events_only_go_out_with_credentials() {
        let agent = Agent::new(
            Target::from_mode("", "", 1),
            Credentials::default(),
            "celmux",
        );
        assert!(!agent.ready());
        let error = agent
            .call(&crate::relay::IncomingCall::default())
            .expect_err("没有凭据必须拒绝");
        assert!(error.contains("凭据"), "{error}");

        let ready = Agent::new(
            Target::from_mode("", "", 1),
            Credentials {
                device_id: "d".to_owned(),
                device_secret: "s".to_owned(),
            },
            "celmux",
        );
        assert!(ready.ready());
    }
    /// One relay is in charge, and the mode says which.
    ///
    /// The two are exclusive by nature: one APNs key, one place the events are
    /// signed. Leaving the choice implicit in whether an address was filled in
    /// allowed a state where both looked configured and only one was in effect.
    #[test]
    fn the_relay_mode_decides_and_the_other_side_is_switched_off() {
        // Own: the address is ignored even when one is stored, because the
        // operator named this process as the relay.
        assert!(
            Target::from_mode("own", "https://relay.example.com", 43770).is_own(),
            "own 模式必须忽略外部地址"
        );
        // External with an address: events travel out, nothing listens here.
        assert!(
            !Target::from_mode("external", "https://relay.example.com", 43770).is_own(),
            "external 模式必须把事件发出去"
        );
        // External with no address cannot work; rather than posting nowhere, the
        // local relay is used - the safe reading, since the key lives here.
        assert!(
            Target::from_mode("external", "", 43770).is_own(),
            "external 缺少地址时应回退本机 relay"
        );
        // An unset or unknown mode means the local relay.
        assert!(Target::from_mode("", "https://relay.example.com", 43770).is_own());
        assert!(Target::from_mode("nonsense", "", 43770).is_own());
    }

}
