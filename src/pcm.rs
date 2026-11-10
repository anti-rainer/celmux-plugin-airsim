// Copyright (c) 2026 anti-rainer
// SPDX-License-Identifier: MIT

//! The AirSIM PCM gateway.
//!
//! AirSIM carries call audio as a raw TCP stream of 8 kHz signed 16-bit mono
//! little-endian samples in 20 ms blocks - 160 samples, 320 bytes. It is not
//! WebRTC and has no negotiation, so the shape is fixed:
//!
//! ```text
//! client -> server  "AIRSIMPCM1\n"
//! server -> client  "AIRSIMREADY"
//! then both directions are bare 320-byte frames, forever
//! ```
//!
//! Two directions, two clocks. Audio from Celmux is pulled on one thread and
//! written to the socket; audio from the socket is read on another and pushed
//! into Celmux. They are separate threads on purpose: a blocking write to a
//! phone that stopped reading must not stop the plugin from accepting audio
//! from the carrier, or a paused app would deadlock the call.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use crate::agents::{Agent, Fleet};
use crate::celmux::Client;

/// The client's opening line, prefixed by the version tag.
///
/// AirSIM's iPhone app does not send a bare hello: it sends
/// `AIRSIMVWL1 <timestamp> <nonce> <signature>\n`, where the signature is the
/// same HMAC the control plane uses, over `PCM\n/v1/pcm\n<sha256(body)>\n
/// <timestamp>\n<nonce>`. Answering without checking it would let anything on
/// the network open a call's audio, so it is verified before a single frame is
/// accepted.
pub const CLIENT_HELLO_PREFIX: &str = "AIRSIMVWL1 ";
/// What the client waits for before it sends frames.
pub const SERVER_READY: &[u8] = b"AIRSIMREADY";

/// The longest handshake line accepted.
///
/// The reference form is `AIRSIMVWL1 <ts> <nonce> <signature>`, well under 200
/// bytes. A peer that sends more than this is not sending a handshake, and
/// reading until it stops would hold the connection open for it to say anything.
const MAX_HELLO_BYTES: usize = 1024;
/// 320 bytes: 160 samples at 8 kHz, 20 ms.
pub const FRAME_BYTES: usize = 320;
/// 20 ms, which is what paces both directions.
pub const FRAME_INTERVAL: Duration = Duration::from_millis(20);
/// The rate both ends speak. Celmux resamples to the carrier's own clock.
pub const SAMPLE_RATE: u32 = 8_000;
/// How long to keep retrying the audio wire while Celmux has no call to bind.
///
/// A dial takes a moment to become visible on Celmux's side, and the phone's
/// audio arrives before that. Long enough to cover the race, short enough that a
/// plugin with no call does not hold a thread for the length of a call.
const WIRE_BIND_TIMEOUT: Duration = Duration::from_secs(30);

/// Accept PCM connections until the listener closes.
///
/// One listener for every line. The handshake names its line: it is signed with
/// that line's secret, so trying each known secret in turn says which line the
/// audio belongs to - the same way the control port does it. A per-line port
/// would cost a port and a firewall rule for information the signature already
/// carries.
pub fn serve_shared(listener: TcpListener, client: Arc<Client>, fleet: Arc<Fleet>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            continue;
        };
        let client = Arc::clone(&client);
        let fleet = Arc::clone(&fleet);
        std::thread::spawn(move || {
            let _ = handle_shared(stream, client, fleet);
        });
    }
}

/// Serve one PCM connection, attributing it to the line whose secret signed the
/// handshake.
fn handle_shared(mut stream: TcpStream, client: Arc<Client>, fleet: Arc<Fleet>) -> std::io::Result<()> {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let peer = stream
        .peer_addr()
        .map(|address| address.to_string())
        .unwrap_or_else(|_| "?".to_owned());

    // Logged before the handshake: "no connection at all" and "a connection that
    // failed its handshake" are different problems, and from the phone both look
    // like audio that never starts.
    crate::log_info!("celmux-plugin-airsim: PCM 连接建立 {peer}，等待握手");
    let mut hello = String::new();
    {
        // Read exactly one line, one byte at a time. A buffered reader would also
        // pull in whatever arrived right behind the handshake, and those bytes -
        // the phone's first audio frames - have no way back into the socket.
        use std::io::Read as _;
        let mut byte = [0_u8; 1];
        loop {
            match stream.read(&mut byte) {
                Ok(0) => {
                    crate::log_warn!("celmux-plugin-airsim: PCM 对方关闭连接，未发送握手（{peer}）");
                    return Ok(());
                }
                Ok(_) => {
                    if byte[0] == b'\n' {
                        break;
                    }
                    hello.push(byte[0] as char);
                    if hello.len() > MAX_HELLO_BYTES {
                        crate::log_warn!("celmux-plugin-airsim: PCM 握手过长，已拒绝（{peer}）");
                        return Ok(());
                    }
                }
                Err(error) => {
                    crate::log_warn!("celmux-plugin-airsim: PCM 握手读取失败（{peer}）: {error}");
                    return Ok(());
                }
            }
        }
    }
    let Some(agent) = handshake_line(&fleet, hello.trim_end()) else {
        crate::log_warn!("celmux-plugin-airsim: PCM 握手无匹配线路，已拒绝（{peer}）");
        return Ok(());
    };
    crate::log_info!(
        "celmux-plugin-airsim: PCM 连接 {peer} 归属 {}",
        agent.id()
    );
    stream.write_all(SERVER_READY)?;
    stream.flush()?;
    // The handshake timeouts above exist for the handshake only. Leaving them on
    // the call would end the audio the first time either side went quiet for two
    // seconds - which a real conversation does constantly, and which reads as
    // Celmux hanging up on a call nobody dropped.
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    bridge(stream, client, agent)
}

/// Which line signed this handshake.
fn handshake_line(fleet: &Fleet, hello: &str) -> Option<Arc<Agent>> {
    fleet
        .list()
        .into_iter()
        .find(|agent| verify_handshake(agent, hello))
}

/// Carry audio between one phone and one line's call.
///
/// The call id is looked up from the line's own active call: the handshake
/// names the line, so which call the audio belongs to follows from it. A second
/// phone on the same port names a different line, and therefore a different
/// call - which is why the port can be shared at all.
fn bridge(stream: TcpStream, client: Arc<Client>, agent: Arc<Agent>) -> std::io::Result<()> {
    // The phone decides when to open audio, and it can only do that once, at the
    // moment the call needs sound. Turning it away because the call is not
    // visible yet leaves it retrying and the first seconds of speech with nowhere
    // to go - which is what a handshake that waits for `active` does. The wire to
    // Celmux is therefore opened here too, and Celmux names the call it bound.
    //
    // Audio is still per call: whichever exposed line is on a call carries this
    // socket, and the line the handshake named is the only one considered.
    let wire = match connect_wire(&client, &agent) {
        Ok(wire) => wire,
        Err(error) => {
            crate::log_warn!("celmux-plugin-airsim: PCM 音频通道不可用: {error}");
            return Ok(());
        }
    };
    let (upstream_reader, upstream_writer, call_id) = match wire.split() {
        Ok(parts) => parts,
        Err(error) => {
            crate::log_warn!("celmux-plugin-airsim: PCM 音频通道拆分失败: {error}");
            return Ok(());
        }
    };
    crate::log_info!("celmux-plugin-airsim: PCM 音频已对接通话 {call_id}");
    let phone_reader = stream.try_clone()?;
    // Either direction ending ends the bridge. Joining both would leave the other
    // blocked on a read that has nothing left to read, so the socket is shut down
    // once the first one returns - which is what makes the phone's own hang-up
    // and Celmux's end of the call both take effect immediately.
    let phone_writer = stream.try_clone()?;
    let upstream_shutdown = upstream_reader.try_clone();
    // Phone -> Celmux.
    let upload = std::thread::spawn(move || {
        copy_frames(phone_reader, upstream_writer);
        let _ = phone_writer.shutdown(std::net::Shutdown::Both);
    });
    // Celmux -> phone.
    let download = std::thread::spawn(move || {
        copy_frames(upstream_reader, stream);
        if let Ok(handle) = upstream_shutdown {
            let _ = handle.shutdown(std::net::Shutdown::Both);
        }
    });
    let _ = upload.join();
    let _ = download.join();
    Ok(())
}

/// Open the wire, retrying while Celmux has no call to bind yet.
///
/// A dial takes a moment to become visible on Celmux's side, and the phone's
/// audio arrives before that. Retrying is what keeps that race from costing the
/// greeting.
fn connect_wire(client: &Arc<Client>, agent: &Arc<Agent>) -> Result<crate::audio_wire::Wire, String> {
    let address = client.audio_wire_address()?;
    let plugin_id = client.plugin_id();
    let token = client.token();
    // Every line this agent exposes, tried in order: which of them is on a call
    // is Celmux's answer to give, not this side's to assume.
    let lines = agent.lines();
    if lines.is_empty() {
        return Err("插件没有配置任何线路".to_owned());
    }
    let deadline = std::time::Instant::now() + WIRE_BIND_TIMEOUT;
    loop {
        for line in &lines {
            match crate::audio_wire::Wire::connect(&address, plugin_id, token, line) {
                Ok(Some(wire)) => return Ok(wire),
                // Celmux is up and this line has no call to bind yet.
                Ok(None) => {}
                Err(crate::audio_wire::Error::Refused(detail)) => {
                    return Err(detail);
                }
                Err(error) => {
                    if std::time::Instant::now() >= deadline {
                        return Err(error.to_string());
                    }
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err("等待 Celmux 绑定通话超时".to_owned());
        }
        std::thread::sleep(FRAME_INTERVAL);
    }
}

/// Move whole 320-byte blocks from one socket to the other.
///
/// Both ends of this bridge speak the same framing, so no conversion belongs
/// here: a block read is a block written, and anything that re-frames it would be
/// the thing that makes the audio uneven.
fn copy_frames(mut from: TcpStream, mut to: TcpStream) {
    let mut frame = vec![0_u8; FRAME_BYTES];
    loop {
        if from.read_exact(&mut frame).is_err() {
            return;
        }
        if to.write_all(&frame).is_err() {
            return;
        }
        let _ = to.flush();
    }
}

/// Check the handshake's signature against the secret the phone paired with.
///
/// The canonical string is the control plane's, with `PCM` as the method and
/// `/v1/pcm` as the path, so the same key that signs a request signs the audio
/// stream. An agent that has not paired accepts nothing: without a secret there
/// is nothing to check against, and an unchecked stream would carry a stranger's
/// audio into a live call.
fn verify_handshake(agent: &Arc<Agent>, hello: &str) -> bool {
    let Some(secret) = agent.secret() else {
        return false;
    };
    let Some(rest) = hello.strip_prefix(CLIENT_HELLO_PREFIX) else {
        return false;
    };
    let mut parts = rest.split(' ');
    let (Some(timestamp), Some(nonce), Some(signature)) =
        (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    crate::auth::signature_matches(&secret, "PCM", "/v1/pcm", b"", timestamp, nonce, signature)
}

#[cfg(test)]
mod handshake_tests {
    use super::*;
    use crate::agents::{Agent, AgentConfig};

    fn agent(secret: Option<Vec<u8>>) -> Arc<Agent> {
        Arc::new(Agent::new(
            AgentConfig {
                lines: vec!["读卡器1".to_owned()],
                ..Default::default()
            },
            secret,
        ))
    }

    /// Sign a handshake the way the app does, so the test speaks the real
    /// protocol rather than a fixture that agrees with itself.
    fn handshake(secret: &[u8], timestamp: i64, nonce: &str) -> String {
        let canonical = crate::auth::canonical("PCM", "/v1/pcm", b"", timestamp, nonce);
        use hmac::digest::KeyInit as _;
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(canonical.as_bytes());
        let signature = crate::config::base64_url_encode(&mac.finalize().into_bytes());
        format!("AIRSIMVWL1 {timestamp} {nonce} {signature}")
    }

    /// The app's own handshake must be accepted, or no call has audio at all.
    #[test]
    fn a_signed_handshake_is_accepted() {
        let secret = vec![7_u8; 32];
        let line = handshake(&secret, 1_800_000_000, "nonce-pcm");
        assert!(verify_handshake(&agent(Some(secret)), &line));
    }

    /// A signature over different bytes must not open a call's audio.
    #[test]
    fn a_tampered_handshake_is_refused() {
        let secret = vec![7_u8; 32];
        let line = handshake(&[9_u8; 32], 1_800_000_000, "nonce-pcm");
        assert!(!verify_handshake(&agent(Some(secret)), &line));
    }

    /// An unpaired agent has no key to check against, so it accepts nothing: an
    /// unchecked stream would carry a stranger's audio into a live call.
    #[test]
    fn an_unpaired_agent_accepts_nothing() {
        let line = handshake(&[7_u8; 32], 1_800_000_000, "nonce-pcm");
        assert!(!verify_handshake(&agent(None), &line));
    }

    /// Anything that is not the handshake is not AirSIM.
    #[test]
    fn a_foreign_greeting_is_refused() {
        assert!(!verify_handshake(
            &agent(Some(vec![7_u8; 32])),
            "AIRSIMPCM1"
        ));
        assert!(!verify_handshake(&agent(Some(vec![7_u8; 32])), ""));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These are the whole protocol contract with the AirSIM client. A change to
    /// any of them is a change the phone would reject, so they are pinned
    /// literally.
    #[test]
    fn the_protocol_constants_match_what_the_client_expects() {
        // The client opens with a signed line, not a bare hello: `AIRSIMVWL1 `
        // is the tag its handshake carries.
        assert_eq!(CLIENT_HELLO_PREFIX, "AIRSIMVWL1 ");
        assert_eq!(SERVER_READY, b"AIRSIMREADY");
        assert_eq!(SERVER_READY.len(), 11);
    }

    /// 20 ms of 8 kHz mono, 16 bits per sample.
    #[test]
    fn a_frame_is_twenty_milliseconds_of_audio() {
        assert_eq!(FRAME_BYTES, 320);
        assert_eq!(FRAME_BYTES, SAMPLE_RATE as usize / 50 * 2);
    }
}
