// Copyright (c) 2026 anti-rainer
// SPDX-License-Identifier: MIT

//! One agent, carrying every exposed line as a SIM slot.
//!
//! This is the shape the client already has: an agent reports `sim_slots`, the
//! phone shows a selector, and a call or a message names the slot it wants in
//! `sim_account`. That is how the reference agent exposes two SIMs from one
//! device - one pair of ports, one pairing, one credential, several cards.
//!
//! So the plugin is one device, not one device per line. A line maps to a slot,
//! and the operator picks which lines are reachable by choosing which slots
//! exist. The earlier one-agent-per-line arrangement made the phone pair once per
//! card to reach the same installation, which is not what the client is for.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::pairing::Session;

/// The id this gateway uses when the operator has not chosen one.
pub const DEFAULT_AGENT_ID: &str = "celmux";
/// The name it shows when the operator has not chosen one.
pub const DEFAULT_AGENT_NAME: &str = "Celmux";

/// What the operator exposed: the lines this installation offers, in order.
///
/// There is one agent, so this is the whole configuration. Each line becomes a
/// SIM slot the phone can choose between.
#[derive(Clone, Debug, Default)]
pub struct AgentConfig {
    /// The lines this agent carries, as Celmux line labels, in display order.
    ///
    /// Ignored when `expose_all_lines` is set, which exposes whatever Celmux has
    /// at the moment of the request.
    pub lines: Vec<String>,
    /// Expose every line Celmux currently has, instead of the list above.
    ///
    /// The list is a snapshot, and Celmux is not: a reader plugged in, a Profile
    /// switched in N-standby, or a VoWiFi tunnel coming up adds a line that no
    /// static list could have named. With this on, a line appears as soon as
    /// Celmux knows about it and disappears when it goes away, which is what an
    /// installation that treats the gateway as a bridge - rather than as a curated
    /// set of cards - wants.
    pub expose_all_lines: bool,
    /// The display name the phone shows. Operator-editable: it is a label, and
    /// renaming it changes nothing about the pairing.
    pub name: String,
    /// The id the phone stores its credential under. Operator-editable, but with
    /// a consequence the settings page warns about: changing it orphans the
    /// secret the phone filed under the old id, so the phone must pair again.
    pub id: String,
    // No ports here. One control port and one PCM port serve the installation;
    // the request names its line by the slot it asks for, so a port per line
    // would spend a port and a firewall rule on information the payload carries.
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
        // Typed by the operator, with a stable default.
        //
        // It must never derive from the exposed lines: the phone stores one
        // secret per id and looks it up by this same string, so adding or
        // removing a line would rename the device and the phone would look up a
        // secret that no longer has a matching id - a pairing that succeeded
        // failing its health check with 「VoWLAN 鉴权失败」. A value the operator
        // chooses avoids that, and the settings page says what changing it costs.
        if self.id.trim().is_empty() {
            DEFAULT_AGENT_ID.to_owned()
        } else {
            self.id.trim().to_owned()
        }
    }
}

/// A running agent: its configuration, its signing secret, and the pairing
/// window currently open for it.
pub struct Agent {
    /// Bumped when anything this line cares about changes: the phone's long
    /// poll compares against it, and the thread following Celmux bumps it.
    revision: Arc<crate::revision::Revision>,
    /// What the operator exposed, replaceable at runtime.
    ///
    /// Behind a lock rather than immutable because a settings change must take
    /// effect without restarting the process: restarting to read one boolean
    /// drops every open connection, the pairing handshake and the phone's event
    /// stream - for a value that is read on the next request anyway.
    config: std::sync::RwLock<AgentConfig>,
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
    /// What the phone registered with a relay under, learned at pairing.
    relay_credentials: Mutex<Option<RelayCredentials>>,
    acked_messages: Arc<std::sync::Mutex<std::collections::BTreeSet<String>>>,
}

/// The credential a phone registered with a relay under.
///
/// Generated by the phone, not by us, and sent only inside the pairing claim.
/// `relay_url` records which relay it belongs to, so a credential left over from
/// a previous relay is not presented to a new one.
#[derive(Clone, Debug, Default)]
pub struct RelayCredentials {
    pub device_id: String,
    pub device_secret: String,
    pub relay_url: String,
}

impl Agent {
    pub fn new(config: AgentConfig, secret: Option<Vec<u8>>) -> Self {
        Self {
            revision: Arc::new(crate::revision::Revision::default()),
            config: std::sync::RwLock::new(config),
            secret: Mutex::new(secret),
            store: None,
            pairing: Mutex::new(None),
            verifier: Mutex::new(None),
            relay_credentials: Mutex::new(None),
            acked_messages: Arc::new(std::sync::Mutex::new(std::collections::BTreeSet::new())),
        }
    }

    /// The message ids the phone has confirmed for this line.
    ///
    /// Shared with every request handler the way `revision` is, and per agent
    /// because an acknowledgement is about one line's inbox: a shared set would let
    /// confirming on one card silence another's pending count.
    pub fn acked_messages(&self) -> Arc<std::sync::Mutex<std::collections::BTreeSet<String>>> {
        Arc::clone(&self.acked_messages)
    }

    /// This line's revision, shared with every request handler for it.
    pub fn revision(&self) -> Arc<crate::revision::Revision> {
        Arc::clone(&self.revision)
    }

    /// The same agent, but remembering its secret under `root`.
    pub fn with_store(mut self, root: &std::path::Path) -> Self {
        let store = crate::secrets::Store::new(root);
        // Read back the credential pairing stored here, not in `new`: the store is
        // attached after construction, and a credential that vanished on restart
        // would leave an external-relay installation unable to sign its events
        // until the phone paired again.
        if let Some(relay) = store.load_relay(&self.id())
            && let Ok(mut slot) = self.relay_credentials.lock()
        {
            *slot = Some(relay);
        }
        self.store = Some(store);
        self
    }

    /// Sign one canonical message with this agent's secret.
    ///
    /// Empty when the agent has not paired, which makes a proof check fail
    /// rather than pass with nothing behind it.
    pub fn proof(&self, message: &str) -> String {
        self.verifier()
            .map(|verifier| verifier.proof(message))
            .unwrap_or_default()
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
    /// Write the phone's relay credential beside the pairing secret.
    ///
    /// Its own file rather than a field in `paired-secrets`: that file maps an
    /// agent to one key and is rewritten by pairing, while this credential belongs
    /// to the phone and to a particular relay. Folding them together would make
    /// re-pairing appear to invalidate a relay registration it does not touch.
    pub fn persist_relay_credentials(&self) {
        let Some(store) = self.store.as_ref() else {
            return;
        };
        let Some(relay) = self.relay_credentials() else {
            return;
        };
        if let Err(error) = store.save_relay(&self.id(), &relay) {
            crate::log_warn!("celmux-plugin-airsim: relay 凭据未能保存: {error}");
        }
    }

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
        self.config().agent_id()
    }

    /// What the phone lists this device as.
    ///
    /// The installation, not a card: the phone shows one entry per agent and
    /// picks cards inside it, so naming the device after its first line would
    /// rename it whenever the exposed set changed.
    pub fn name(&self) -> String {
        let config = self.config();
        if config.name.trim().is_empty() {
            DEFAULT_AGENT_NAME.to_owned()
        } else {
            config.name.trim().to_owned()
        }
    }

    /// The line currently on a call, with that call's id.
    ///
    /// A slot is chosen per call, so a PCM socket follows the call in progress
    /// rather than a fixed line. Returning both together keeps them from being
    /// paired up wrongly when two slots are busy.
    /// The lines this agent exposes, in the order they were configured.
    /// A copy of the configuration in effect right now.
    ///
    /// A copy, not a guard: callers hold it across work that must not keep the
    /// write side waiting, and a settings change landing mid-request should give
    /// that request one consistent view rather than a half-old one.
    pub fn config(&self) -> AgentConfig {
        self.config
            .read()
            .map(|config| config.clone())
            .unwrap_or_default()
    }

    /// Replace the configuration in place.
    ///
    /// Returns whether anything changed, so the reload thread can say so in the
    /// log instead of reporting a change every time it polls.
    pub fn replace_config(&self, next: AgentConfig) -> bool {
        let Ok(mut current) = self.config.write() else {
            return false;
        };
        let same = current.lines == next.lines
            && current.expose_all_lines == next.expose_all_lines
            && current.name == next.name
            && current.id == next.id;
        if same {
            return false;
        }
        *current = next;
        // The phone's long poll waits on this: a new line must show up without
        // waiting out its timeout.
        self.revision.bump();
        true
    }

    pub fn lines(&self) -> Vec<String> {
        self.config().lines.clone()
    }

    /// Whether Celmux's line is one this agent offers.
    ///
    /// One place, because the health document, the slot picker, the status list,
    /// SMS filtering and the PCM handshake all ask the same question. When they
    /// each carried their own `config.lines.contains(...)`, exposing every line
    /// would have meant finding every one of them - and missing one shows up as a
    /// line that lists but cannot be dialled.
    pub fn exposes(&self, line_id: &str) -> bool {
        let config = self.config();
        if config.expose_all_lines {
            return true;
        }
        config.lines.iter().any(|line| line == line_id)
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

    /// Remember the credential the phone registered with a relay under.
    ///
    /// Passed up at pairing and nowhere else: the phone generates it and sends it
    /// to whichever relay it was pointed at, so this process only ever sees it in
    /// that claim. With an external relay it is the only credential the events can
    /// be signed with.
    pub fn set_relay_credentials(
        &self,
        device_id: String,
        device_secret: String,
        relay_url: String,
    ) {
        if let Ok(mut relay) = self.relay_credentials.lock() {
            *relay = Some(RelayCredentials {
                device_id,
                device_secret,
                relay_url,
            });
        }
    }

    /// What the phone registered with a relay under, if it reported one.
    pub fn relay_credentials(&self) -> Option<RelayCredentials> {
        self.relay_credentials
            .lock()
            .ok()
            .and_then(|relay| relay.clone())
    }

    /// The id of the phone that paired with this gateway, if any.
    ///
    /// This is the identity the operator vouched for by reading six digits off a
    /// screen. It is what distinguishes the paired phone from a device that merely
    /// registered, and only the former may act on these lines.
    pub fn paired_device_id(&self) -> Option<String> {
        self.relay_credentials()
            .map(|relay| relay.device_id)
            .filter(|id| !id.is_empty())
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

/// The installation's single agent.
///
/// Named `Fleet` because every caller reaches it that way, but there is exactly
/// one: the client pairs with a device and chooses among its slots, so a second
/// agent would be a second device at the same address.
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

    /// The store the line assignment lives in: this plugin's own disk, beside
    /// the pairing secrets. Not Celmux's configuration - adding a line is the
    /// operator's decision on this page, not a value the host resolves.
    pub fn assignment_store(&self) -> crate::assignment::Store {
        crate::assignment::Store::new(&self.root)
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
    /// Make the running fleet match `configs`, without rebuilding what it can
    /// keep.
    ///
    /// This is the only way an assignment change reaches the running process, and
    /// it has to do all three things - add, update, remove - because the
    /// assignment is a complete statement of what this gateway offers:
    ///
    /// * A line the operator just added has no agent yet, so "update the agents
    ///   that exist" did nothing and still answered success. That was the click
    ///   that appeared to apply and then reverted.
    /// * Removing the last line has to take the agent away, or the page reports
    ///   nothing offered while the phone keeps dialling the line that is still
    ///   configured - "remove" that cannot remove is the same bug upside down.
    /// * An agent that keeps its place must not be rebuilt. Rebuilding drops its
    ///   pairing window, its call suppression and the revision the phone's long
    ///   poll is waiting on, so re-saving the page would unpair phones and stall
    ///   their event streams for a change that never touched them.
    ///
    /// Returns whether anything changed.
    pub fn apply_configs(&self, configs: Vec<AgentConfig>) -> bool {
        let Ok(mut agents) = self.agents.lock() else {
            return false;
        };
        let mut changed = false;
        let mut wanted: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let stored = crate::secrets::Store::new(&self.root).load();
        for config in configs {
            let id = config.agent_id();
            wanted.insert(id.clone());
            match agents.get(&id) {
                Some(agent) => changed |= agent.replace_config(config),
                None => {
                    // A new agent is the agent the phone already paired with, if
                    // it paired before: the secret lives on disk as well as in
                    // memory, and dropping it here would answer the phone's next
                    // request with a signature it cannot produce.
                    let agent = Agent::new(config, None).with_store(&self.root);
                    if let Some(secret) = stored.get(&id).cloned() {
                        agent.set_secret(secret);
                    }
                    agents.insert(id, Arc::new(agent));
                    changed = true;
                }
            }
        }
        let removed: Vec<String> = agents
            .keys()
            .filter(|id| !wanted.contains(*id))
            .cloned()
            .collect();
        for id in removed {
            agents.remove(&id);
            changed = true;
        }
        changed
    }

    /// Replace the whole fleet at startup.
    ///
    /// Startup-shaped on purpose: there is no running state to preserve, and a
    /// process that has just come up has no phone waiting on a revision yet.
    /// Settings changes go through `apply_configs`, which keeps the agents it
    /// can and still adds and removes the ones that changed.
    pub fn reconcile(&self, configs: Vec<AgentConfig>) -> Result<(), String> {
        let mut agents = self
            .agents
            .lock()
            .map_err(|_| "agent 表不可用".to_owned())?;
        // Secrets live on disk as well as in memory, so an agent rebuilt after a
        // config save - or after a restart - is still the agent the phone paired
        // with.
        let stored = crate::secrets::Store::new(&self.root).load();
        let mut next: BTreeMap<String, Arc<Agent>> = BTreeMap::new();
        for config in configs {
            let agent = Agent::new(config, None).with_store(&self.root);
            let in_memory = agents
                .get(&agent.id())
                .and_then(|existing| existing.secret());
            if let Some(secret) = in_memory.or_else(|| stored.get(&agent.id()).cloned()) {
                agent.set_secret(secret);
            }
            next.insert(agent.id(), Arc::new(agent));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn config(line: &str, _control: u16) -> AgentConfig {
        AgentConfig {
            lines: vec![line.to_owned()],
            expose_all_lines: false,
            // The defaults, so a test that wants a named agent says so explicitly.
            name: String::new(),
            id: String::new(),
        }
    }

    /// The identity is the operator's to choose, and it changes only when they
    /// change it - never because a line was added or removed.
    #[test]
    fn the_identity_comes_from_configuration_not_from_the_lines() {
        let named = AgentConfig {
            lines: vec!["读卡器1".to_owned()],
            expose_all_lines: false,
            name: "客厅网关".to_owned(),
            id: "living-room".to_owned(),
        };
        assert_eq!(named.agent_id(), "living-room");
        assert_eq!(Agent::new(named.clone(), None).name(), "客厅网关");

        // Adding a line must not rename the device: the phone looks its secret
        // up by this string, so a rename would orphan the pairing.
        let widened = AgentConfig {
            lines: vec!["读卡器1".to_owned(), "读卡器2".to_owned()],
            ..named
        };
        assert_eq!(widened.agent_id(), "living-room");

        // An empty identity falls back rather than producing an agent the phone
        // cannot address.
        let blank = AgentConfig {
            lines: vec!["dji1".to_owned()],
            expose_all_lines: false,
            name: String::new(),
            id: String::new(),
        };
        assert_eq!(blank.agent_id(), DEFAULT_AGENT_ID);
        assert_eq!(Agent::new(blank, None).name(), DEFAULT_AGENT_NAME);
    }

    /// The id is the installation's, not a line's.
    ///
    /// The phone stores one secret per id and looks it up by this same string,
    /// so an id derived from the exposed lines would rename the device whenever
    /// the operator added or removed one - and the phone would then look up a
    /// secret that no longer has a matching id.
    #[test]
    fn the_agent_id_does_not_change_when_the_lines_do() {
        let one = config("读卡器1", 8642).agent_id();
        let two = AgentConfig {
            lines: vec!["读卡器1".to_owned(), "dji1".to_owned()],
            ..Default::default()
        }
        .agent_id();
        let none = AgentConfig::default().agent_id();
        assert_eq!(one, two);
        assert_eq!(one, none);
        assert_eq!(one, "celmux");
    }

    /// The same label always yields the same id, or a restart would orphan the
    /// phone's credential.
    #[test]
    fn an_agent_id_is_stable_across_calls() {
        let first = config("读卡器1", 8642).agent_id();
        let second = config("读卡器1", 9999).agent_id();
        assert_eq!(first, second);
    }

    /// A line label with nothing usable in it is still a line: it becomes a
    /// slot, and the id does not depend on it.
    #[test]
    fn a_label_with_nothing_usable_still_exposes_a_slot() {
        let config = config("###", 8642);
        assert_eq!(config.agent_id(), "celmux");
        assert_eq!(config.lines, vec!["###".to_owned()]);
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
        // The line identity survives a reconcile; the ports are no longer part
        // of a line's configuration, so there is nothing to assert about them.
        assert_eq!(again.lines(), vec!["dji1".to_owned()]);
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

    /// The click that started this: a line added to a gateway that already had
    /// agents was never installed, because only existing agents were updated.
    #[test]
    fn adding_a_line_that_has_no_agent_yet_installs_one() {
        let root = std::env::temp_dir().join("celmux-airsim-add-line");
        let _ = std::fs::remove_dir_all(&root);
        let fleet = Fleet::new(&root);
        // A gateway with no lines has no agent at all.
        assert!(!fleet.apply_configs(Vec::new()));
        assert_eq!(fleet.list().len(), 0);

        let added = fleet.apply_configs(vec![AgentConfig {
            lines: vec!["读卡器1#890".to_owned()],
            ..Default::default()
        }]);
        assert!(added, "加入一条线路必须报告变化");
        let agents = fleet.list();
        assert_eq!(agents.len(), 1);
        assert!(agents[0].exposes("读卡器1#890"));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Removing the last line must take the agent with it. Leaving it behind
    /// reports nothing offered while the phone still dials the line.
    #[test]
    fn removing_the_last_line_takes_the_agent_away() {
        let root = std::env::temp_dir().join("celmux-airsim-remove-last");
        let _ = std::fs::remove_dir_all(&root);
        let fleet = Fleet::new(&root);
        fleet.apply_configs(vec![AgentConfig {
            lines: vec!["dji1".to_owned()],
            ..Default::default()
        }]);
        assert_eq!(fleet.list().len(), 1);

        assert!(
            fleet.apply_configs(Vec::new()),
            "移除最后一条线路必须报告变化"
        );
        assert_eq!(fleet.list().len(), 0, "没有线路就不该还有 agent");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// An agent that keeps its place must not be rebuilt by a settings save: a
    /// rebuild drops the revision the phone's long poll waits on.
    #[test]
    fn a_save_that_changes_nothing_leaves_the_agent_alone() {
        let root = std::env::temp_dir().join("celmux-airsim-noop-save");
        let _ = std::fs::remove_dir_all(&root);
        let fleet = Fleet::new(&root);
        let config = AgentConfig {
            lines: vec!["dji1".to_owned()],
            ..Default::default()
        };
        fleet.apply_configs(vec![config.clone()]);
        let before = fleet.list()[0].clone();
        before.set_secret(vec![9; 32]);

        assert!(!fleet.apply_configs(vec![config]), "没有变化就不该报告变化");
        let after = fleet.list()[0].clone();
        assert!(
            Arc::ptr_eq(&before, &after),
            "同一个 agent 必须还是同一个对象，否则长轮询会被打断"
        );
        assert_eq!(after.secret(), Some(vec![9; 32]));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A new agent for a line the phone already paired with must find that
    /// pairing on disk, or the phone's next request is signed with a key we have
    /// forgotten.
    #[test]
    fn a_new_agent_finds_the_pairing_a_previous_one_left() {
        let root = std::env::temp_dir().join("celmux-airsim-readd");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let config = AgentConfig {
            lines: vec!["读卡器1#890".to_owned()],
            ..Default::default()
        };
        {
            let fleet = Fleet::new(&root);
            fleet.apply_configs(vec![config.clone()]);
            let agent = fleet.list()[0].clone();
            agent.set_secret(vec![4; 32]);
            agent.persist_secret();
        }
        // A fresh process over the same directory, where the line is added
        // again rather than reconciled at startup.
        let fleet = Fleet::new(&root);
        fleet.apply_configs(vec![config]);
        assert_eq!(fleet.list()[0].secret(), Some(vec![4; 32]));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Adding a slot must not disturb the pairing: the device is the same
    /// device, and only what it carries changed.
    #[test]
    fn adding_a_slot_leaves_the_pairing_intact() {
        let fleet = Fleet::default();
        fleet.reconcile(vec![config("dji1", 8642)]).unwrap();
        fleet.list()[0].set_secret(vec![1; 32]);
        fleet
            .reconcile(vec![AgentConfig {
                lines: vec!["dji1".to_owned(), "dji2".to_owned()],
                ..Default::default()
            }])
            .unwrap();
        let agents = fleet.list();
        assert_eq!(agents.len(), 1, "仍是一个 agent");
        assert_eq!(agents[0].lines().len(), 2, "两个槽位");
        assert_eq!(agents[0].secret(), Some(vec![1; 32]), "密钥不受影响");
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

    /// The phone addresses the installation by its id, which is what it stores
    /// a credential under.
    #[test]
    fn the_installation_is_reachable_by_its_id() {
        let fleet = Fleet::default();
        fleet.reconcile(vec![config("dji1", 8642)]).unwrap();
        assert!(fleet.by_id("celmux").is_some());
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
    /// A line the operator never assigned is exposed when the switch is on.
    ///
    /// The list is a snapshot; Celmux is not. A reader plugged in afterwards, or
    /// an N-standby Profile switched in, adds a line no static list could name -
    /// and the point of the switch is that such a line appears without anyone
    /// editing a list.
    #[test]
    fn exposing_all_lines_includes_one_that_was_never_assigned() {
        let curated = AgentConfig {
            lines: vec!["读卡器1".to_owned()],
            expose_all_lines: false,
            name: "C".to_owned(),
            id: "celmux".to_owned(),
        };
        let agent = Agent::new(curated, None);
        assert!(agent.exposes("读卡器1"));
        assert!(!agent.exposes("读卡器3"), "未分配的线路默认不暴露");

        let everything = AgentConfig {
            lines: vec!["读卡器1".to_owned()],
            expose_all_lines: true,
            name: "C".to_owned(),
            id: "celmux".to_owned(),
        };
        let agent = Agent::new(everything, None);
        assert!(agent.exposes("读卡器1"));
        assert!(agent.exposes("读卡器3"), "打开开关后任何线路都暴露");
        assert!(
            agent.exposes("dji1@89860012345678901234"),
            "N 待 Profile 也暴露"
        );
    }

    /// A configuration change applies without rebuilding the agent.
    ///
    /// This is the whole point of the lock: restarting a plugin to read one
    /// boolean drops the pairing window, every open socket and the phone's event
    /// stream. Rebuilding the agent would do the same thing in-process.
    #[test]
    fn a_new_assignment_applies_to_the_running_agent() {
        let agent = Agent::new(
            AgentConfig {
                lines: vec!["读卡器1".to_owned()],
                expose_all_lines: false,
                name: "Celmux".to_owned(),
                id: "celmux".to_owned(),
            },
            None,
        );
        let revision_before = agent.revision().now();
        assert!(!agent.exposes("读卡器3"));

        let changed = agent.replace_config(AgentConfig {
            lines: vec!["读卡器1".to_owned(), "读卡器3".to_owned()],
            expose_all_lines: true,
            name: "Celmux".to_owned(),
            id: "celmux".to_owned(),
        });
        assert!(changed, "分配变化应当报告为改变");
        assert!(agent.exposes("读卡器3"), "新线路立即生效");
        assert!(
            agent.revision().now() != revision_before,
            "revision 要推进，否则手机的长轮询要等满超时"
        );

        // The same configuration again is not a change, or the reload thread
        // would log one every poll.
        let again = agent.replace_config(AgentConfig {
            lines: vec!["读卡器1".to_owned(), "读卡器3".to_owned()],
            expose_all_lines: true,
            name: "Celmux".to_owned(),
            id: "celmux".to_owned(),
        });
        assert!(!again, "相同配置不应报告为改变");
    }
}
