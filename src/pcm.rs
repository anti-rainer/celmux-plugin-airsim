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

use crate::agents::Agent;
use crate::celmux::Client;

/// The client's opening line.
pub const CLIENT_HELLO: &[u8] = b"AIRSIMPCM1\n";
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
/// One listener per agent: a PCM stream is a bare socket with a handshake and
/// no request framing, so it cannot carry an id that would let several agents
/// share a port.
pub fn serve(listener: TcpListener, client: Arc<Client>, agent: Arc<Agent>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let client = Arc::clone(&client);
        let agent = Arc::clone(&agent);
        std::thread::spawn(move || {
            let _ = handle(stream, client, agent);
        });
    }
}

fn handle(mut stream: TcpStream, client: Arc<Client>, agent: Arc<Agent>) -> std::io::Result<()> {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

    let mut hello = vec![0_u8; CLIENT_HELLO.len()];
    stream.read_exact(&mut hello)?;
    // A connection that does not open with the handshake is not AirSIM, and
    // guessing at what it wanted would only fill the log.
    if hello != CLIENT_HELLO {
        return Ok(());
    }
    stream.write_all(SERVER_READY)?;
    stream.flush()?;

    // The call id arrives in the query of the control request that asked for
    // audio, so the gateway learns it from the first frame's owner. Until then
    // it has nothing to bridge, which is the honest state right after the
    // handshake.
    // The gateway belongs to one agent, so it bridges that agent's line: a
    // second phone on the same port would otherwise be handed someone else's
    // audio.
    let line = agent.config.line_id.clone();
    let call_id = client.active_call_id(&line);

    let read_half = stream.try_clone()?;
    let reader = {
        let client = Arc::clone(&client);
        let line_id = line.clone();
        std::thread::spawn(move || read_loop(read_half, client, call_id, line_id))
    };
    let writer = {
        let client = Arc::clone(&client);
        std::thread::spawn(move || write_loop(stream, client, call_id, line))
    };
    // Either direction ending means the call is over for this client.
    let _ = reader.join();
    let _ = writer.join();
    Ok(())
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
mod tests {
    use super::*;

    /// These four constants are the whole protocol contract with the AirSIM
    /// client. A change to any of them is a change the phone would reject, so
    /// they are pinned literally.
    #[test]
    fn the_handshake_matches_what_the_client_opens_with() {
        assert_eq!(CLIENT_HELLO, b"AIRSIMPCM1\n");
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
