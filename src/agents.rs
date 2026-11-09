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
    /// Derived from the name rather than typed, so two agents cannot claim the
    /// same credential slot - the phone keeps exactly one secret per id.
    ///
    /// A line label is not usable as an id on its own: it can be `读卡器1`, and
    /// stripping the non-ASCII characters the phone's Keychain account key
    /// cannot carry leaves `1`, which two different devices would share. So the
    /// readable part is kept when it survives, and a digest of the whole label
    /// is appended whenever the readable part could be ambiguous.
    pub fn agent_id(&self) -> String {
        let label = if self.name.is_empty() {
            &self.line_id
        } else {
            &self.name
        };
        let readable = sanitize(label);
        if readable == "line" || !is_distinctive(&readable, label) {
            // Nothing usable survived, or what survived is a fragment: name the
            // agent by a digest instead of by a fragment that collides.
            format!("celmux-{}", short_digest(&self.line_id))
        } else {
            format!("celmux-{readable}")
        }
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
    /// Where this agent's secret is persisted, so a restart does not require
    /// pairing again.
    store: Option<crate::secrets::Store>,
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
            store: None,
            pairing: Mutex::new(None),
            verifier: Mutex::new(None),
        }
    }

    /// The same agent, but remembering its secret under `root`.
    pub fn with_store(mut self, root: &std::path::Path) -> Self {
        self.store = Some(crate::secrets::Store::new(root));
        self
    }

    /// Forget the persisted secret, so the next restart does not read it back.
    pub fn forget_secret(&self) {
        let Some(store) = self.store.as_ref() else {
            return;
        };
        if let Err(error) = store.forget(&self.id()) {
            crate::log_warn!("celmux-plugin-airsim: 无法清除配对密钥: {error}");
        }
    }

    /// Persist the current secret. Called by pairing, after it sets one.
    pub fn persist_secret(&self) {
        let Some(store) = self.store.as_ref() else {
            return;
        };
        let Some(secret) = self.secret() else {
            return;
        };
        if let Err(error) = store.save(&self.id(), &secret) {
            // Not fatal: this process still has the pairing, and the operator
            // learns on the next restart rather than losing it now.
            crate::log_warn!("celmux-plugin-airsim: 配对密钥未能保存: {error}");
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
pub struct Fleet {
    agents: Mutex<BTreeMap<String, Arc<Agent>>>,
    /// The plugin's own directory, where pairing secrets are kept.
    root: std::path::PathBuf,
}

impl Fleet {
    /// A fleet that remembers its pairings under `root`.
    pub fn new(root: &std::path::Path) -> Self {
        Self {
            agents: Mutex::new(BTreeMap::new()),
            root: root.to_path_buf(),
        }
    }
}

impl Default for Fleet {
    fn default() -> Self {
        // Tests and probes get a fleet that forgets when it is dropped: a
        // default that wrote to disk would let one test's pairing leak into
        // another through a file neither of them named.
        Self::new(std::path::Path::new("."))
    }
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
        // Secrets live on disk as well as in memory, so an agent rebuilt for a
        // renamed port - or one rebuilt after a restart - is still the agent the
        // phone paired with.
        let stored = crate::secrets::Store::new(&self.root).load();
        let mut next: BTreeMap<String, Arc<Agent>> = BTreeMap::new();
        for config in configs {
            let agent = Agent::new(config, None).with_store(&self.root);
            let in_memory = agents
                .get(&agent.config.line_id)
                .and_then(|existing| existing.secret());
            if let Some(secret) = in_memory.or_else(|| stored.get(&agent.id()).cloned()) {
                agent.set_secret(secret);
            }
            next.insert(agent.config.line_id.clone(), Arc::new(agent));
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
}

/// Whether the sanitised form still identifies the label it came from.
///
/// A label whose non-ASCII characters all vanished keeps only the digits and
/// ASCII that happened to sit beside them, so `读卡器1` and `读卡器2` become `1`
/// and `2` and `读卡器10` and `打印机10` would both become `10`. Treating a form
/// that carries less than half the label's bytes as a fragment keeps the
/// readable case readable and the ambiguous case unambiguous.
fn is_distinctive(sanitised: &str, label: &str) -> bool {
    let kept = sanitised
        .chars()
        .filter(|character| *character != '-')
        .count();
    let total = label.chars().count();
    total > 0 && kept * 2 >= total
}

/// A stable digest of a label, short enough to sit in an id.
fn short_digest(label: &str) -> String {
    use sha2::{Digest, Sha256};
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest: [u8; 32] = Sha256::digest(label.as_bytes()).into();
    let mut encoded = String::with_capacity(16);
    for byte in &digest[..8] {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
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

    /// The real labels on this installation are Chinese, and stripping the
    /// non-ASCII characters leaves only a digit - which two devices would
    /// share. A label whose readable part is a fragment has to be named by a
    /// digest instead.
    #[test]
    fn chinese_labels_do_not_collapse_to_a_shared_digit() {
        let first = config("读卡器1", 8642).agent_id();
        let second = config("读卡器2", 8644).agent_id();
        let tenth = config("打印机10", 8646).agent_id();
        assert_ne!(first, second);
        assert_ne!(first, tenth);
        assert_ne!(second, tenth);
        assert_ne!(first, "celmux-1");
        // Still an id the phone's Keychain can key on.
        for id in [&first, &second, &tenth] {
            assert!(
                id.chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-'),
                "{id} must be ascii"
            );
        }
    }

    /// A label that is mostly ASCII keeps its readable form.
    #[test]
    fn a_readable_label_keeps_its_readable_id() {
        assert_eq!(config("dji1", 8642).agent_id(), "celmux-dji1");
        assert_eq!(config("simreader2", 8642).agent_id(), "celmux-simreader2");
    }

    /// The same label always yields the same id, or a restart would orphan the
    /// phone's credential.
    #[test]
    fn an_agent_id_is_stable_across_calls() {
        let first = config("读卡器1", 8642).agent_id();
        let second = config("读卡器1", 9999).agent_id();
        assert_eq!(first, second);
    }

    #[test]
    fn a_label_with_nothing_usable_still_yields_an_id() {
        let id = config("###", 8642).agent_id();
        assert!(id.starts_with("celmux-"));
        assert!(id.len() > "celmux-".len());
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

    /// The whole reason secrets are written to disk: a new process - which is
    /// what a restart, a config save and an upgrade all produce - must find the
    /// pairing already there instead of asking the operator for six digits.
    #[test]
    fn a_restart_finds_the_pairing_on_disk() {
        let root = std::env::temp_dir().join("celmux-airsim-restart");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        {
            let fleet = Fleet::new(&root);
            fleet.reconcile(vec![config("dji1", 8642)]).unwrap();
            let agent = fleet.list().into_iter().next().unwrap();
            agent.set_secret(vec![5; 32]);
            agent.persist_secret();
        }
        // A fresh fleet over the same directory is what the next process has.
        let restarted = Fleet::new(&root);
        restarted.reconcile(vec![config("dji1", 8642)]).unwrap();
        let agent = restarted.list().into_iter().next().unwrap();
        assert_eq!(agent.secret(), Some(vec![5; 32]));
        assert!(agent.verifier().is_some(), "the pairing must be usable");
        let _ = std::fs::remove_dir_all(&root);
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

    /// The phone addresses an agent by its id, which is what it stores a
    /// credential under.
    #[test]
    fn an_agent_is_reachable_by_its_id() {
        let fleet = Fleet::default();
        fleet.reconcile(vec![config("dji1", 8642)]).unwrap();
        assert!(fleet.by_id("celmux-dji1").is_some());
        assert!(fleet.by_id("celmux-nothing").is_none());
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
