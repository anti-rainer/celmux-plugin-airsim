// Copyright (c) 2026 anti-rainer
// SPDX-License-Identifier: MIT

//! What this plugin needs to run, read from the environment Celmux passes when
//! it launches the process.
//!
//! Celmux owns the configuration: the operator edits it in the settings page,
//! and Celmux hands the resolved values down as environment variables. The
//! plugin never reads Celmux's database and never holds its own copy of the
//! operator's choices, so there is exactly one place where a value can be
//! wrong.

use std::collections::BTreeMap;

/// The plugin id. Celmux mints a token against this name, and every API call
/// this process makes carries it.
pub const PLUGIN_ID: &str = "airsim";

/// The port Celmux's plugin centre relays to: this plugin's own settings page
/// and its configuration API.
///
/// Separate from the phone's control port on purpose. The two callers
/// authenticate differently - the page with a token Celmux minted for the
/// operator who opened it, the phone by signing each request - and keeping them
/// on separate listeners means neither credential is ever accepted where the
/// other is expected.
pub const DEFAULT_PORT: u16 = 43769;

/// The port every line's control API answers on. Shared by all lines: the
/// request says which line it belongs to by the secret that signed it.
pub const DEFAULT_CONTROL_PORT: u16 = 8642;

/// The PCM port, shared by all lines for the same reason.
pub const DEFAULT_PCM_PORT: u16 = 8643;

#[derive(Debug, Clone)]
pub struct Config {
    /// Where Celmux's HTTP API listens. The plugin reaches it over loopback.
    pub celmux_url: String,
    /// The private token Celmux minted at install time.
    pub celmux_token: String,
    /// The AirSIM-facing port: the API the settings page drives, and the
    /// pairing endpoints.
    pub port: u16,
    /// The port every line's control API answers on. One port, not one per
    /// line: a request names its line by the secret that signed it, so a port
    /// per line would spend a port and a firewall rule on information the
    /// signature already carries.
    pub control_port: u16,
    /// The PCM port, shared by every line for the same reason.
    pub pcm_port: u16,
    /// Whether to advertise agents on Bonjour.
    pub advertise: bool,
}

const REQUIRED: [&str; 2] = ["celmux_url", "celmux_token"];

#[derive(Debug)]
pub enum ConfigError {
    Missing(&'static str),
    Invalid(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(key) => write!(
                formatter,
                "配置项 {key} 未设置，请在 Celmux 设置 → 插件中填写"
            ),
            Self::Invalid(reason) => formatter.write_str(reason),
        }
    }
}

impl Config {
    /// Read the configuration from `CELMUX_PLUGIN_<KEY>` variables.
    ///
    /// Celmux upper-cases the key and prefixes it, so `port` arrives as
    /// `CELMUX_PLUGIN_PORT`. A required value that is absent is a startup
    /// failure rather than a guess.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_map(|key| std::env::var(format!("CELMUX_PLUGIN_{}", key.to_uppercase())).ok())
    }

    fn from_map(read: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let values: BTreeMap<&str, String> = REQUIRED
            .iter()
            .filter_map(|key| read(key).map(|value| (*key, value)))
            .collect();
        for key in REQUIRED {
            if values
                .get(key)
                .map(String::as_str)
                .unwrap_or("")
                .trim()
                .is_empty()
            {
                return Err(ConfigError::Missing(key));
            }
        }
        let port = match read("port").map(|value| value.trim().to_owned()) {
            Some(value) if !value.is_empty() => value
                .parse()
                .map_err(|_| ConfigError::Invalid(format!("port 不是有效端口号: {value}")))?,
            _ => DEFAULT_PORT,
        };
        let control_port = read("control_port")
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .map(|value| {
                value.parse().map_err(|_| {
                    ConfigError::Invalid(format!("control_port 不是有效端口号: {value}"))
                })
            })
            .transpose()?
            .unwrap_or(DEFAULT_CONTROL_PORT);
        let pcm_port = read("pcm_port")
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .map(|value| {
                value.parse().map_err(|_| {
                    ConfigError::Invalid(format!("pcm_port 不是有效端口号: {value}"))
                })
            })
            .transpose()?
            .unwrap_or(DEFAULT_PCM_PORT);
        if control_port == pcm_port {
            return Err(ConfigError::Invalid(
                "control_port 与 pcm_port 不能相同".to_owned(),
            ));
        }
        Ok(Self {
            celmux_url: values["celmux_url"].trim().trim_end_matches('/').to_owned(),
            celmux_token: values["celmux_token"].trim().to_owned(),
            port,
            control_port,
            pcm_port,
            advertise: read("advertise")
                .map(|value| value.trim() != "false" && value.trim() != "0")
                .unwrap_or(true),
        })
    }
}

/// Decode base64url with or without padding.
///
/// The AirSIM client emits it unpadded, but an operator typing a value into the
/// settings form will paste whatever a generator produced, so both forms have
/// to work.
pub fn base64_url_decode(value: &str) -> Option<Vec<u8>> {
    let normalised: String = value
        .trim()
        .replace('-', "+")
        .replace('_', "/")
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    let trimmed = normalised.trim_end_matches('=');
    let padding = (4 - trimmed.len() % 4) % 4;
    let padded = format!("{trimmed}{}", "=".repeat(padding));
    base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        padded.as_bytes(),
    )
    .ok()
}

pub fn base64_url_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        Config::from_map(|key| {
            owned
                .iter()
                .find(|(candidate, _)| candidate == key)
                .map(|(_, value)| value.clone())
        })
    }

    #[test]
    fn a_missing_required_value_names_itself() {
        let error = config(&[("celmux_url", "http://127.0.0.1:8080")]).unwrap_err();
        assert!(matches!(error, ConfigError::Missing("celmux_token")));
        assert!(error.to_string().contains("celmux_token"));
    }

    #[test]
    fn a_blank_required_value_counts_as_missing() {
        let error = config(&[
            ("celmux_url", "http://127.0.0.1:8080"),
            ("celmux_token", "   "),
        ])
        .unwrap_err();
        assert!(matches!(error, ConfigError::Missing("celmux_token")));
    }

    /// The pairing secret is no longer a setting: pairing creates it, so the
    /// plugin has to start without one.
    #[test]
    fn the_plugin_starts_without_a_pairing_secret() {
        let config = config(&[
            ("celmux_url", "http://127.0.0.1:8080/"),
            ("celmux_token", "token"),
        ])
        .unwrap();
        // A trailing slash would double up when a path is appended.
        assert_eq!(config.celmux_url, "http://127.0.0.1:8080");
        assert_eq!(config.port, DEFAULT_PORT);
        assert!(config.advertise);
    }

    #[test]
    fn a_configured_port_replaces_the_default() {
        let config = config(&[
            ("celmux_url", "http://127.0.0.1:8080"),
            ("celmux_token", "token"),
            ("port", "8123"),
        ])
        .unwrap();
        assert_eq!(config.port, 8123);
    }

    #[test]
    fn an_unparseable_port_is_refused_by_name() {
        let error = config(&[
            ("celmux_url", "http://127.0.0.1:8080"),
            ("celmux_token", "token"),
            ("port", "not-a-port"),
        ])
        .unwrap_err();
        assert!(error.to_string().contains("port"));
    }

    /// Operators paste padded and unpadded values interchangeably, and pairing
    /// claims arrive in the same encoding.
    #[test]
    fn a_padded_value_decodes_the_same_as_an_unpadded_one() {
        let bytes = [3_u8; 32];
        let unpadded = base64_url_encode(&bytes);
        let padded = format!("{unpadded}==");
        assert_eq!(base64_url_decode(&unpadded).unwrap(), bytes.to_vec());
        assert_eq!(base64_url_decode(&padded).unwrap(), bytes.to_vec());
    }

    /// The default port is what the settings page tells the operator to point
    /// nginx at, so it is pinned rather than left to drift.
    #[test]
    fn the_default_port_is_the_documented_one() {
        assert_eq!(DEFAULT_PORT, 43769);
    }
}
