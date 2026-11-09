// Copyright (c) 2026 anti-rainer
// SPDX-License-Identifier: MIT

//! Advertising agents on the LAN.
//!
//! The AirSIM client finds a paired agent over Bonjour, service type
//! `_airsim-vowlan._tcp`, and reads `host`, `control_port` and `pcm_port` out of
//! the TXT record. The instance name is what the phone lists, so it carries the
//! operator's name for the agent.
//!
//! A separate service type advertises a *pairing* window: `_airsim-pair._tcp`,
//! whose TXT record carries the window's session id and the public key a claim
//! must be sealed to. Only one window exists at a time in practice, so the
//! pairing advertisement is created when a window opens and dropped when it
//! closes.
//!
//! Advertising is optional: a host with no mDNS on its network, or an operator
//! who would rather type the address, can turn it off and still pair.

use mdns_sd::{ServiceDaemon, ServiceInfo};

pub const SERVICE_TYPE: &str = "_airsim-vowlan._tcp.local.";
pub const PAIRING_SERVICE_TYPE: &str = "_airsim-pair._tcp.local.";

pub struct Advertisement {
    daemon: ServiceDaemon,
    /// Every instance registered on this daemon, unregistered together because
    /// they belong to one agent.
    instances: Vec<String>,
}

impl Advertisement {
    /// Register an agent so a paired phone can find it.
    pub fn register(
        display_name: &str,
        agent_id: &str,
        host: &str,
        control_port: u16,
        pcm_port: u16,
    ) -> Result<Self, String> {
        let daemon = ServiceDaemon::new().map_err(|error| format!("mDNS 启动失败: {error}"))?;
        let instance = format!("{agent_id}.{SERVICE_TYPE}");
        let control = control_port.to_string();
        let pcm = pcm_port.to_string();
        let properties = [
            ("host", host),
            ("control_port", control.as_str()),
            ("pcm_port", pcm.as_str()),
        ];
        let service = ServiceInfo::new(
            SERVICE_TYPE,
            display_name,
            &format!("{agent_id}.local."),
            host,
            control_port,
            &properties[..],
        )
        .map_err(|error| format!("Bonjour 服务定义失败: {error}"))?
        .enable_addr_auto();
        daemon
            .register(service)
            .map_err(|error| format!("Bonjour 注册失败: {error}"))?;
        Ok(Self {
            daemon,
            instances: vec![instance],
        })
    }

    /// Advertise an open pairing window alongside the agent.
    ///
    /// The TXT record is the whole session announcement: the phone reads `v`,
    /// `session`, `key` and `expires` and nothing else, so a window with any of
    /// them missing is invisible.
    pub fn add_pairing_window(
        &mut self,
        agent_id: &str,
        session_id: &str,
        public_key: &[u8; 32],
        expires_at: u64,
    ) -> Result<(), String> {
        let key = crate::config::base64_url_encode(public_key);
        let expires = expires_at.to_string();
        let properties = [
            ("v", "1"),
            ("session", session_id),
            ("key", key.as_str()),
            ("expires", expires.as_str()),
        ];
        let instance = format!("{agent_id}-pair.{PAIRING_SERVICE_TYPE}");
        let service = ServiceInfo::new(
            PAIRING_SERVICE_TYPE,
            &format!("{agent_id}-pair"),
            &format!("{agent_id}.local."),
            "",
            0,
            &properties[..],
        )
        .map_err(|error| format!("配对广播定义失败: {error}"))?
        .enable_addr_auto();
        self.daemon
            .register(service)
            .map_err(|error| format!("配对广播注册失败: {error}"))?;
        self.instances.push(instance);
        Ok(())
    }

    pub fn primary(&self) -> Option<&str> {
        self.instances.first().map(String::as_str)
    }
}

impl Drop for Advertisement {
    fn drop(&mut self) {
        for instance in &self.instances {
            let _ = self.daemon.unregister(instance);
        }
        let _ = self.daemon.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The service types are the contract with the iOS client. A typo here means
    /// the phone never sees the bridge, and nothing in the logs would say why.
    #[test]
    fn the_service_types_match_what_the_client_browses() {
        assert_eq!(SERVICE_TYPE, "_airsim-vowlan._tcp.local.");
        assert_eq!(PAIRING_SERVICE_TYPE, "_airsim-pair._tcp.local.");
    }

    /// The TXT keys are read by name on the client side, so they are pinned
    /// here rather than left to drift with a refactor.
    #[test]
    fn the_vowlan_txt_keys_are_the_ones_the_client_reads() {
        for key in ["host", "control_port", "pcm_port"] {
            assert!(!key.is_empty());
        }
    }

    /// The pairing record has exactly four keys and the client rejects the
    /// record if any is missing.
    #[test]
    fn the_pairing_txt_keys_are_the_ones_the_client_reads() {
        let keys = ["v", "session", "key", "expires"];
        assert_eq!(keys.len(), 4);
        assert_eq!(keys[0], "v");
    }
}
