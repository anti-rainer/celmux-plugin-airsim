// Copyright (c) 2026 anti-rainer
// SPDX-License-Identifier: MIT

//! One agent per line.
//!
//! AirSIM's model is one card per agent: `api/sim/identity` answers with a
//! single phone number and there is no list of cards anywhere in the client, so
//! an agent that carried several lines would have exactly one of them reachable
//! and no way to say which. Celmux, meanwhile, has lines - a device's own line,
//! and one per N-standby Profile.
//!
//! So a line maps to an agent. Each agent gets its own id, its own ports, its
//! own pairing window and its own secret, and the phone lists them as separate
//! devices that pair independently. That is the only mapping the client's model
//! can express, and it means the operator picks which lines are reachable by
//! choosing which agents exist.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::pairing::Session;

/// What the operator assigned to one line.
#[derive(Clone, Debug)]
pub struct AgentConfig {
    /// The line this agent carries, as a Celmux line label.
    pub line_id: String,
    /// What the phone lists. Falls back to the line label.
    pub name: String,
    /// Control port for this agent.
    pub control_port: u16,
    /// PCM port for this agent.
    pub pcm_port: u16,
}

impl AgentConfig {
    /// The id the phone stores a credential under, and the name in Bonjour.
    ///
    /// Derived from the line rather than configurable: an id that could be
    /// typed twice would let two agents claim the same credential slot, and the
    /// phone keeps exactly one secret per id.
    pub fn agent_id(&self) -> String {
        format!("celmux-{}", sanitize(&self.line_id))
    }

    fn display_name(&self) -> &str {
        if self.name.is_empty() {
            &self.line_id
        } else {
            &self.name
        }
    }
}

/// A running agent: its configuration, its signing secret, and the pairing
/// window currently open for it.
pub struct Agent {
    pub config: AgentConfig,
    /// The secret every request from this agent's phone is signed with.
    ///
    /// `None` until the phone pairs: pairing is what creates it, because the
    /// phone generates the secret and sends it inside the encrypted claim.
    secret: Mutex<Option<Vec<u8>>>,
    /// An open pairing window, if the operator started one.
    pairing: Mutex<Option<Session>>,
    /// The verifier for the current secret.
    ///
    /// Rebuilt when pairing replaces the secret: a verifier is bound to one key
    /// and to the nonces it has accepted, so reusing one across a re-pair would
    /// either refuse every request or accept nonces from the old secret.
    verifier: Mutex<Option<(Vec<u8>, std::sync::Arc<crate::auth::Verifier>)>>,
}

impl Agent {
    pub fn new(config: AgentConfig, secret: Option<Vec<u8>>) -> Self {
        Self {
            config,
            secret: Mutex::new(secret),
            pairing: Mutex::new(None),
            verifier: Mutex::new(None),
        }
    }

    pub fn id(&self) -> String {
        self.config.agent_id()
    }

    pub fn name(&self) -> String {
        self.config.display_name().to_owned()
    }

    /// The secret this agent's phone signs with, if it has paired.
    pub fn secret(&self) -> Option<Vec<u8>> {
        self.secret.lock().ok().and_then(|secret| secret.clone())
    }

    pub fn set_secret(&self, value: Vec<u8>) {
        if let Ok(mut secret) = self.secret.lock() {
            *secret = Some(value);
        }
    }

    /// The verifier for the current secret, built on first use and rebuilt
    /// whenever the secret changes.
    pub fn verifier(&self) -> Option<std::sync::Arc<crate::auth::Verifier>> {
        let secret = self.secret()?;
        let mut cached = self.verifier.lock().ok()?;
        if let Some((key, verifier)) = cached.as_ref()
            && *key == secret
        {
            return Some(std::sync::Arc::clone(verifier));
        }
        let verifier = std::sync::Arc::new(crate::auth::Verifier::new(secret.clone()));
        *cached = Some((secret, std::sync::Arc::clone(&verifier)));
        Some(verifier)
    }

    /// Forget the secret, so the phone has to pair again.
    pub fn clear_secret(&self) {
        if let Ok(mut secret) = self.secret.lock() {
            *secret = None;
        }
        // The verifier is bound to the old secret; keeping it would let a
        // forgotten credential keep working.
        if let Ok(mut cached) = self.verifier.lock() {
            *cached = None;
        }
    }

    pub fn paired(&self) -> bool {
        self.secret().is_some()
    }

    /// Open a pairing window, replacing any window already open.
    ///
    /// Replacing rather than refusing: an operator who lost the code before the
    /// phone used it needs a way to get a new one, and the old window carries no
    /// state worth preserving.
    pub fn open_pairing(
        &self,
        ttl: std::time::Duration,
        session_id: String,
    ) -> Result<(String, u64), String> {
        let session = Session::open(session_id, ttl)?;
        let code = session.code.clone();
        let expires_at = session.expires_at;
        if let Ok(mut pairing) = self.pairing.lock() {
            *pairing = Some(session);
            return Ok((code, expires_at));
        }
        Err("配对窗口不可用".to_owned())
    }

    pub fn close_pairing(&self) {
        if let Ok(mut pairing) = self.pairing.lock() {
            *pairing = None;
        }
    }

    /// Run `use_session` against the open window, if it is still live.
    pub fn with_pairing<T>(&self, use_session: impl FnOnce(&Session) -> T) -> Option<T> {
        let mut pairing = self.pairing.lock().ok()?;
        let session = pairing.as_ref()?;
        if session.expired(std::time::SystemTime::now()) {
            *pairing = None;
            return None;
        }
        Some(use_session(session))
    }
}

/// Every configured agent, keyed by line label.
///
/// Shared behind an `Arc` because the control listener, the PCM listener and the
/// settings page all reach it, and a pairing that starts in one must be visible
/// to the others immediately.
#[derive(Default)]
pub struct Fleet {
    agents: Mutex<BTreeMap<String, Arc<Agent>>>,
}

impl Fleet {
    /// Replace the fleet from configuration.
    ///
    /// A line that keeps its assignment keeps its agent, and therefore its
    /// secret and its pairing state: re-saving the settings page must not
    /// unpair a phone. Only lines that appear or disappear change.
    pub fn reconcile(&self, configs: Vec<AgentConfig>) -> Result<(), String> {
        let mut agents = self
            .agents
            .lock()
            .map_err(|_| "agent 表不可用".to_owned())?;
        let mut next: BTreeMap<String, Arc<Agent>> = BTreeMap::new();
        for config in configs {
            if let Some(existing) = agents.get(&config.line_id) {
                // Same line, possibly renamed ports: keep the secret, adopt the
                // new ports by rebuilding with the old secret.
                next.insert(
                    config.line_id.clone(),
                    Arc::new(Agent::new(config, existing.secret())),
                );
            } else {
                next.insert(config.line_id.clone(), Arc::new(Agent::new(config, None)));
            }
        }
        *agents = next;
        Ok(())
    }

    pub fn list(&self) -> Vec<Arc<Agent>> {
        self.agents
            .lock()
            .map(|agents| agents.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn by_id(&self, agent_id: &str) -> Option<Arc<Agent>> {
        self.agents
            .lock()
            .ok()?
            .values()
            .find(|agent| agent.id() == agent_id)
            .cloned()
    }

    /// The agent whose control listener is on `port`, for a pairing request.
    ///
    /// The phone pairs by dialling a host and port, so the port is the only
    /// identity it presents.
    pub fn by_port(&self, port: u16) -> Option<Arc<Agent>> {
        self.agents
            .lock()
            .ok()?
            .values()
            .find(|agent| agent.config.control_port == port)
            .cloned()
    }

    pub fn is_empty(&self) -> bool {
        self.agents
            .lock()
            .map(|agents| agents.is_empty())
            .unwrap_or(true)
    }
}

/// Turn a line label into something usable as an id and a Bonjour name.
///
/// A line label is `device` or `device#iccid`, and can carry a device name with
/// spaces or Chinese in it. The id has to survive being a Keychain account key
/// on the phone, so only what is unambiguous is kept.
fn sanitize(line_id: &str) -> String {
    let mut output = String::with_capacity(line_id.len());
    for character in line_id.chars() {
        if character.is_ascii_alphanumeric() {
            output.push(character.to_ascii_lowercase());
        } else if !output.ends_with('-') {
            output.push('-');
        }
    }
    let trimmed = output.trim_matches('-').to_owned();
    if trimmed.is_empty() {
        "line".to_owned()
    } else {
        trimmed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(line: &str, control: u16) -> AgentConfig {
        AgentConfig {
            line_id: line.to_owned(),
            name: String::new(),
            control_port: control,
            pcm_port: control + 1,
        }
    }

    /// A line label can carry a device name with spaces or Chinese; the agent id
    /// has to survive being a Keychain key on the phone.
    #[test]
    fn an_agent_id_survives_a_line_label_with_separators() {
        let id = config("读卡器1#89049032000000000001", 8642).agent_id();
        assert!(id.starts_with("celmux-"));
        assert!(
            id.chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '-')
        );
        assert!(!id.ends_with('-'));
    }

    /// Two different lines must never collapse to the same id, or the phone
    /// would store one credential for both.
    #[test]
    fn distinct_lines_keep_distinct_ids() {
        let dji1 = config("dji1", 8642).agent_id();
        let dji2 = config("dji2", 8644).agent_id();
        assert_ne!(dji1, dji2);
        assert_eq!(dji1, "celmux-dji1");
    }

    #[test]
    fn a_label_with_nothing_usable_still_yields_an_id() {
        assert_eq!(sanitize("###"), "line");
        assert_eq!(sanitize(""), "line");
    }

    /// AirSIM keeps one secret per agent id, so a line that keeps its
    /// assignment must keep its secret across a settings save.
    #[test]
    fn resaving_the_settings_keeps_a_paired_secret() {
        let fleet = Fleet::default();
        fleet.reconcile(vec![config("dji1", 8642)]).unwrap();
        let agent = fleet.list().into_iter().next().unwrap();
        agent.set_secret(vec![7; 32]);
        fleet.reconcile(vec![config("dji1", 8652)]).unwrap();
        let again = fleet.list().into_iter().next().unwrap();
        assert_eq!(again.secret(), Some(vec![7; 32]));
        // The new ports are adopted, the secret is not lost.
        assert_eq!(again.config.control_port, 8652);
    }

    /// Adding a line must not disturb the ones already paired.
    #[test]
    fn adding_a_line_leaves_the_others_paired() {
        let fleet = Fleet::default();
        fleet.reconcile(vec![config("dji1", 8642)]).unwrap();
        fleet.list()[0].set_secret(vec![1; 32]);
        fleet
            .reconcile(vec![config("dji1", 8642), config("dji2", 8644)])
            .unwrap();
        let agents = fleet.list();
        assert_eq!(agents.len(), 2);
        let first = agents
            .iter()
            .find(|agent| agent.config.line_id == "dji1")
            .unwrap();
        assert_eq!(first.secret(), Some(vec![1; 32]));
    }

    /// Removing a line drops its agent and therefore its secret: the line is no
    /// longer reachable, so keeping the credential would only leave the phone
    /// with an entry that always fails.
    #[test]
    fn removing_a_line_forgets_its_secret() {
        let fleet = Fleet::default();
        fleet
            .reconcile(vec![config("dji1", 8642), config("dji2", 8644)])
            .unwrap();
        fleet.list()[0].set_secret(vec![3; 32]);
        fleet.reconcile(vec![config("dji2", 8644)]).unwrap();
        assert_eq!(fleet.list().len(), 1);
        assert!(fleet.by_id("celmux-dji1").is_none());
    }

    /// The phone pairs by host and port, so the port is the only identity a
    /// pairing request carries.
    #[test]
    fn an_agent_is_reachable_by_its_control_port() {
        let fleet = Fleet::default();
        fleet.reconcile(vec![config("dji1", 8642)]).unwrap();
        assert!(fleet.by_port(8642).is_some());
        assert!(fleet.by_port(9999).is_none());
    }

    /// Once a window expires it stops answering, rather than accepting a claim
    /// against a stale key.
    #[test]
    fn an_expired_window_closes_itself() {
        let agent = Agent::new(config("dji1", 8642), None);
        agent
            .open_pairing(std::time::Duration::from_secs(0), "s".to_owned())
            .unwrap();
        assert!(agent.with_pairing(|_| ()).is_none());
    }

    /// An operator who lost the code needs a new one; opening a window replaces
    /// the previous session rather than refusing.
    #[test]
    fn opening_a_window_again_replaces_the_code() {
        let agent = Agent::new(config("dji1", 8642), None);
        let (first, _) = agent
            .open_pairing(std::time::Duration::from_secs(300), "s1".to_owned())
            .unwrap();
        let (second, _) = agent
            .open_pairing(std::time::Duration::from_secs(300), "s2".to_owned())
            .unwrap();
        assert_eq!(first.len(), 6);
        assert_eq!(second.len(), 6);
        let live_session = agent.with_pairing(|session| session.id.clone());
        assert_eq!(live_session.as_deref(), Some("s2"));
    }
}
