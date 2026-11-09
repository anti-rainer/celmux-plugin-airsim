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

#[derive(Debug, Clone)]
pub struct Config {
    /// Where Celmux's HTTP API listens. The plugin reaches it over loopback.
    pub celmux_url: String,
    /// The private token Celmux minted at install time.
    pub celmux_token: String,
    /// The name the AirSIM client shows for this device.
    pub agent_id: String,
    /// The 32-byte secret an AirSIM client pairs with, base64url encoded.
    ///
    /// This is separate from `celmux_token` on purpose: the Celmux token
    /// authenticates *this plugin* to Celmux, and the AirSIM secret
    /// authenticates *the phone* to this plugin. Sharing one value would mean a
    /// phone that can reach the bridge could also rewrite cards.
    pub pairing_secret: String,
    /// Port the AirSIM control API listens on.
    pub control_port: u16,
    /// Port the PCM gateway listens on.
    pub pcm_port: u16,
    /// Whether to advertise on Bonjour. Off means the phone must be given the
    /// address by hand, which is what a headless host wants.
    pub advertise: bool,
}

/// Every setting the manifest declares, so a missing value names itself.
const REQUIRED: [&str; 3] = ["celmux_url", "celmux_token", "pairing_secret"];

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
    /// Celmux upper-cases the key and prefixes it, so `control_port` arrives as
    /// `CELMUX_PLUGIN_CONTROL_PORT`. Defaults are the ones the manifest
    /// declares, and a required value that is absent is a startup failure
    /// rather than a guess.
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
        let pairing_secret = values
            .get("pairing_secret")
            .map(String::as_str)
            .unwrap_or_default()
            .trim()
            .to_owned();
        // The AirSIM client refuses a secret shorter than 32 bytes, and there is
        // no point accepting one here only to fail at pairing time.
        let decoded = base64_url_decode(&pairing_secret).ok_or_else(|| {
            ConfigError::Invalid("pairing_secret 不是有效的 base64url".to_owned())
        })?;
        if decoded.len() < 32 {
            return Err(ConfigError::Invalid(
                "pairing_secret 至少需要 32 字节".to_owned(),
            ));
        }
        Ok(Self {
            celmux_url: values["celmux_url"].trim().trim_end_matches('/').to_owned(),
            celmux_token: values["celmux_token"].trim().to_owned(),
            pairing_secret,
            agent_id: read("agent_id")
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "celmux".to_owned()),
            control_port: read("control_port")
                .and_then(|value| value.trim().parse().ok())
                .unwrap_or(8642),
            pcm_port: read("pcm_port")
                .and_then(|value| value.trim().parse().ok())
                .unwrap_or(8643),
            advertise: read("advertise")
                .map(|value| value.trim() != "false" && value.trim() != "0")
                .unwrap_or(true),
        })
    }

    /// The bytes the AirSIM client and this plugin both hold.
    pub fn pairing_key(&self) -> Vec<u8> {
        base64_url_decode(&self.pairing_secret).unwrap_or_default()
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

    fn secret() -> String {
        base64_url_encode(&[9_u8; 32])
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
            ("pairing_secret", &secret()),
        ])
        .unwrap_err();
        assert!(matches!(error, ConfigError::Missing("celmux_token")));
    }

    /// The AirSIM client rejects a short secret, so accepting one here would
    /// only move the failure to pairing time, where it is harder to explain.
    #[test]
    fn a_short_pairing_secret_is_refused_at_startup() {
        let error = config(&[
            ("celmux_url", "http://127.0.0.1:8080"),
            ("celmux_token", "token"),
            ("pairing_secret", &base64_url_encode(&[1_u8; 16])),
        ])
        .unwrap_err();
        assert!(error.to_string().contains("32"));
    }

    /// Operators paste padded and unpadded secrets interchangeably.
    #[test]
    fn a_padded_pairing_secret_decodes_the_same_as_an_unpadded_one() {
        let bytes = [3_u8; 32];
        let unpadded = base64_url_encode(&bytes);
        let padded = format!("{unpadded}==");
        assert_eq!(base64_url_decode(&unpadded).unwrap(), bytes.to_vec());
        assert_eq!(base64_url_decode(&padded).unwrap(), bytes.to_vec());
    }

    #[test]
    fn defaults_apply_when_optional_values_are_absent() {
        let config = config(&[
            ("celmux_url", "http://127.0.0.1:8080/"),
            ("celmux_token", "token"),
            ("pairing_secret", &secret()),
        ])
        .unwrap();
        // A trailing slash would double up when a path is appended.
        assert_eq!(config.celmux_url, "http://127.0.0.1:8080");
        assert_eq!(config.agent_id, "celmux");
        assert_eq!(config.control_port, 8642);
        assert_eq!(config.pcm_port, 8643);
        assert!(config.advertise);
    }
}
