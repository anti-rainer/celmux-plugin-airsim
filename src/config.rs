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

/// The port the AirSIM cloud path reaches this process on.
///
/// A listener of its own, not a route on the settings port, because the two have
/// opposite exposure: the cloud path has to be reachable from the internet
/// through a reverse proxy, and the settings page must not be. Sharing a port
/// would put pairing, log reading and configuration behind whatever proxy the
/// operator set up for the relay.
pub const DEFAULT_RELAY_PORT: u16 = 43770;

#[derive(Debug, Clone)]
pub struct Config {
    /// Where Celmux's HTTP API listens. The plugin reaches it over loopback.
    pub celmux_url: String,
    /// The private token Celmux minted at install time.
    pub celmux_token: String,
    /// Where call audio goes: Celmux's own audio wire, as
    /// `CELMUX_PLUGIN_AUDIO_URL` publishes it.
    ///
    /// Not a route on the HTTP API. A plugin carries one 20 ms block every
    /// 20 ms, and a block per request would make the caller hear the request
    /// path rather than the carrier.
    pub audio_url: Option<String>,
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
    /// Whether the AirSIM cloud path is served at all.
    ///
    /// Off by default. The cloud path is the one part of this plugin that is
    /// meant to be reachable from the internet, and an operator who only ever
    /// uses the phone on the same LAN should not have that listener open. Turning
    /// it on is a deliberate act, and it is the only thing that starts the relay
    /// listener, the heartbeat, and the APNs machinery.
    pub relay_enabled: bool,
    /// The port the AirSIM cloud path reaches this process on, behind a proxy
    /// that terminates TLS for it.
    pub relay_port: u16,
    /// Where the agent side sends its events.
    ///
    /// Empty means this plugin's own relay. An operator who runs somebody else's
    /// relay - the AirSIM author's, for instance - puts that address here and the
    /// events travel there instead. The difference is not cosmetic: the relay is
    /// what holds the APNs key, so pointing this elsewhere means this
    /// installation needs no key of its own.
    pub relay_target: String,

    /// Which relay this installation uses: `own` or `external`.
    ///
    /// The two are exclusive by nature - one APNs key, one place events are
    /// signed for - but the choice used to be implicit in whether an address was
    /// filled in. That left a state where both looked configured and only one was
    /// in effect. Naming the mode makes the choice visible and the other side
    /// switched off, not merely outvoted.
    pub relay_mode: String,
    /// The device credentials the events are signed with.
    ///
    /// A relay authenticates an event as the phone, because the phone's record is
    /// what carries the push token. When this plugin runs the relay it is also
    /// what registered the phone, so it already has these; an external relay
    /// requires the phone to have registered there.
    pub relay_device_id: String,
    pub relay_device_secret: String,
    /// The APNs signing key, as the full PEM an operator pastes in.
    ///
    /// Empty means this plugin sends no pushes. It then says so honestly on
    /// every route that could imply one, because a phone waiting for a push that
    /// never comes is worse than a phone that knows it has to stay connected.
    pub apns_p8: String,
    /// The 10-character Key ID Apple showed when the key was created.
    pub apns_key_id: String,
    /// The 10-character Team ID the key belongs to.
    pub apns_team_id: String,
    /// The bundle the pushes are addressed to. APNs rejects a push whose topic is
    /// not the app that owns the token, so this is not cosmetic.
    pub apns_bundle_id: String,
    /// Whether to address the sandbox APNs host instead of production.
    ///
    /// A development-signed build gets a sandbox token and a production host
    /// answers `BadDeviceToken`, so an operator debugging with Xcode needs this.
    pub apns_sandbox: bool,
    /// Whether to advertise agents on Bonjour.
    pub advertise: bool,
}

const REQUIRED: [&str; 2] = ["celmux_url", "celmux_token"];
/// Keys read for use but not required to be present.
///
/// `audio_url` is the audio wire Celmux publishes at plugin launch. It is
/// optional because a Celmux too old to publish it has no such wire, and the
/// plugin then has no audio path rather than refusing to start - the control
/// plane still works, so the operator can see why.
const OPTIONAL: [&str; 1] = ["audio_url"];

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
            .chain(OPTIONAL.iter())
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
                value
                    .parse()
                    .map_err(|_| ConfigError::Invalid(format!("pcm_port 不是有效端口号: {value}")))
            })
            .transpose()?
            .unwrap_or(DEFAULT_PCM_PORT);
        let relay_port = read("relay_port")
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .map(|value| {
                value.parse().map_err(|_| {
                    ConfigError::Invalid(format!("relay_port 不是有效端口号: {value}"))
                })
            })
            .transpose()?
            .unwrap_or(DEFAULT_RELAY_PORT);
        // Four listeners, all on the same host: two of them sharing a port is not
        // a preference, it is a plugin that cannot start.
        let ports = [
            ("port", port),
            ("control_port", control_port),
            ("pcm_port", pcm_port),
            ("relay_port", relay_port),
        ];
        for (index, (name, value)) in ports.iter().enumerate() {
            if ports[index + 1..].iter().any(|(_, other)| other == value) {
                return Err(ConfigError::Invalid(format!(
                    "{name} 与另一个端口重复: {value}"
                )));
            }
        }
        Ok(Self {
            celmux_url: values["celmux_url"].trim().trim_end_matches('/').to_owned(),
            celmux_token: values["celmux_token"].trim().to_owned(),
            audio_url: read("audio_url").map(|value| value.trim().to_owned()),
            port,
            control_port,
            pcm_port,
            relay_enabled: read("relay_enabled")
                .map(|value| !matches!(value.trim(), "false" | "0" | "off" | "no"))
                .unwrap_or(false),
            relay_port,
            relay_mode: read("relay_mode")
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase(),
            relay_target: read("relay_target")
                .map(|value| value.trim().trim_end_matches('/').to_owned())
                .unwrap_or_default(),
            relay_device_id: read("relay_device_id").unwrap_or_default(),
            relay_device_secret: read("relay_device_secret").unwrap_or_default(),
            apns_p8: read("apns_p8").unwrap_or_default(),
            apns_key_id: read("apns_key_id").unwrap_or_default(),
            apns_team_id: read("apns_team_id").unwrap_or_default(),
            apns_bundle_id: read("apns_bundle_id")
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "com.eric3u.airsim".to_owned()),
            apns_sandbox: read("apns_sandbox")
                .map(|value| matches!(value.trim(), "true" | "1" | "on" | "yes"))
                .unwrap_or(false),
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

/// Decode standard base64, as a `.p8` file body is written.
///
/// The same decoder serves both alphabets: [`base64_url_decode`] maps the URL
/// characters onto the standard ones before decoding, so a caller that knows it
/// has standard input can use this name and be understood.
pub fn base64_url_decode_standard(value: &str) -> Option<Vec<u8>> {
    base64_url_decode(value)
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
