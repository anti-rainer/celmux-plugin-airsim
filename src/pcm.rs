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
/// 320 bytes: 160 samples at 8 kHz, 20 ms.
pub const FRAME_BYTES: usize = 320;
/// 20 ms, which is what paces both directions.
pub const FRAME_INTERVAL: Duration = Duration::from_millis(20);
/// The rate both ends speak. Celmux resamples to the carrier's own clock.
pub const SAMPLE_RATE: u32 = 8_000;

/// Accept PCM connections until the listener closes.
///
/// One listener for every line. The handshake names its line: it is signed with
/// that line's secret, so trying each known secret in turn says which line the
/// audio belongs to - the same way the control port does it. A per-line port
/// would cost a port and a firewall rule for information the signature already
/// carries.
pub fn serve_shared(listener: TcpListener, client: Arc<Client>, fleet: Arc<Fleet>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
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

    let mut hello = String::new();
    {
        use std::io::BufRead;
        let mut reader = std::io::BufReader::new(&stream);
        if let Err(error) = reader.read_line(&mut hello) {
            crate::log_warn!("celmux-plugin-airsim: PCM 握手读取失败（{peer}）: {error}");
            return Ok(());
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
    // Audio is per call, not per device: two slots can be on two calls at once,
    // so this socket follows whichever exposed line is on a call, and gives up
    // when none is. The handshake identified the device; the call identifies the
    // card.
    let Some((line, call_id)) = agent.active_call(&client) else {
        crate::log_warn!(
            "celmux-plugin-airsim: agent {} 没有进行中的通话，PCM 连接结束",
            agent.id()
        );
        return Ok(());
    };

    let read_half = stream.try_clone()?;
    let reader = {
        let client = Arc::clone(&client);
        let line_id = line.clone();
        std::thread::spawn(move || read_loop(read_half, client, Some(call_id), line_id))
    };
    let writer = {
        let client = Arc::clone(&client);
        std::thread::spawn(move || write_loop(stream, client, Some(call_id), line))
    };
    // Either direction ending means the call is over for this client.
    let _ = reader.join();
    let _ = writer.join();
    Ok(())
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

/// Phone -> Celmux: 320-byte frames in, resampled by Celmux on the way out.
fn read_loop(mut stream: TcpStream, client: Arc<Client>, call_id: Option<u64>, line_id: String) {
    let mut frame = vec![0_u8; FRAME_BYTES];
    loop {
        match stream.read_exact(&mut frame) {
            Ok(()) => {}
            // A read timeout is not an error here: it is what lets the loop
            // notice a call that ended while the phone stayed connected.
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if !client.call_still_active(&line_id, call_id) {
                    return;
                }
                continue;
            }
            Err(_) => return,
        }
        let Some(call_id) = call_id else { continue };
        // One failed upload must not end the call: the carrier may be between
        // media states, and the next frame can succeed.
        let _ = client.push_audio(call_id, &frame);
    }
}

/// Celmux -> phone: pull a block, pace it to 20 ms, write it.
fn write_loop(mut stream: TcpStream, client: Arc<Client>, call_id: Option<u64>, line_id: String) {
    loop {
        let Some(call_id) = call_id else {
            std::thread::sleep(FRAME_INTERVAL);
            if !client.call_still_active(&line_id, None) {
                return;
            }
            continue;
        };
        match client.pull_audio(call_id) {
            Ok(Some(frame)) => {
                // The gateway frame is fixed at 320 bytes; a short block is
                // padded with silence so the client's framing never shifts.
                let mut out = vec![0_u8; FRAME_BYTES];
                let take = frame.len().min(FRAME_BYTES);
                out[..take].copy_from_slice(&frame[..take]);
                if stream.write_all(&out).is_err() {
                    return;
                }
                let _ = stream.flush();
            }
            // Nothing from the carrier yet. Sleeping one frame keeps this loop
            // from spinning against Celmux while an idle call holds the line.
            Ok(None) => std::thread::sleep(FRAME_INTERVAL),
            Err(_) => {
                if !client.call_still_active(&line_id, Some(call_id)) {
                    return;
                }
                std::thread::sleep(FRAME_INTERVAL);
            }
        }
    }
}

#[cfg(test)]
mod handshake_tests {
    use super::*;
    use crate::agents::{Agent, AgentConfig};

    fn agent(secret: Option<Vec<u8>>) -> Arc<Agent> {
        Arc::new(Agent::new(
            AgentConfig {
                lines: vec!["读卡器1".to_owned()],
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
