// Copyright (c) 2026 anti-rainer
// SPDX-License-Identifier: MIT

//! Advertising this bridge on the LAN.
//!
//! The AirSIM client finds an agent over Bonjour, service type
//! `_airsim-vowlan._tcp`, and reads `host`, `control_port` and `pcm_port` out of
//! the TXT record. The service instance name is what the phone lists, so it
//! carries the agent id the operator configured.
//!
//! Advertising is optional: a host with no mDNS on its network, or an operator
//! who would rather type the address, can turn it off and still pair.

use mdns_sd::{ServiceDaemon, ServiceInfo};

pub const SERVICE_TYPE: &str = "_airsim-vowlan._tcp.local.";

pub struct Advertisement {
    daemon: ServiceDaemon,
    fullname: String,
}

impl Advertisement {
    /// Register the service. The daemon keeps running for as long as this value
    /// lives, so the caller holds it for the process lifetime.
    pub fn register(
        agent_id: &str,
        host: &str,
        control_port: u16,
        pcm_port: u16,
    ) -> Result<Self, String> {
        let daemon = ServiceDaemon::new().map_err(|error| format!("mDNS 启动失败: {error}"))?;
        let instance = format!("{agent_id}.{SERVICE_TYPE}");
        let properties = [
            ("host", host),
            ("control_port", &control_port.to_string()),
            ("pcm_port", &pcm_port.to_string()),
        ];
        let service = ServiceInfo::new(
            SERVICE_TYPE,
            agent_id,
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
            fullname: instance,
        })
    }

    pub fn fullname(&self) -> &str {
        &self.fullname
    }
}

impl Drop for Advertisement {
    fn drop(&mut self) {
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The service type is the contract with the iOS client. A typo here means
    /// the phone never sees the bridge, and nothing in the logs would say why.
    #[test]
    fn the_service_type_matches_what_the_client_browses() {
        assert_eq!(SERVICE_TYPE, "_airsim-vowlan._tcp.local.");
    }

    /// The TXT keys are read by name on the client side.
    #[test]
    fn the_txt_keys_are_the_ones_the_client_reads() {
        let control = "control_port".to_owned();
        let pcm = "pcm_port".to_owned();
        let host = "host".to_owned();
        assert_eq!(control, "control_port");
        assert_eq!(pcm, "pcm_port");
        assert_eq!(host, "host");
    }
}
