// Copyright (c) 2026 anti-rainer
// SPDX-License-Identifier: MIT

//! The audio wire between this plugin and Celmux.
//!
//! Speech has a clock: one 20 ms block every 20 ms. HTTP is the wrong shape for
//! that, and no amount of buffering fixes it - every block would cost its own
//! request, its own connection, its own signature, and the pacing the caller
//! hears would be the pacing of the request path. That is exactly what a choppy
//! call sounds like.
//!
//! So audio has its own socket:
//!
//! ```text
//! plugin -> celmux   "CELMUXAUDIO1 <plugin-id> <token> <line>\n"
//! celmux -> plugin   "CELMUXAUDIOOK <call-id>\n"      (or "CELMUXAUDIOERR <reason>\n")
//! then both directions are bare 320-byte frames, forever
//! ```
//!
//! The line is named here because it is this side's own setting: which lines to
//! expose lives in the plugin's configuration, not in Celmux. Celmux answers with
//! the call it found on that line, so this side never guesses which call the
//! socket belongs to and never has to ask again. The control plane keeps its
//! HTTP: it carries requests that happen once, not fifty times a second.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// The opening line this plugin sends.
pub const CLIENT_HELLO: &str = "CELMUXAUDIO1 ";
/// What Celmux answers when the socket is bound to a call.
pub const SERVER_READY: &str = "CELMUXAUDIOOK ";
/// What Celmux answers when it is not.
pub const SERVER_ERROR: &str = "CELMUXAUDIOERR ";

/// A handshake answer longer than this is not one.
const MAX_ANSWER_BYTES: usize = 512;

/// A connected audio wire.
pub struct Wire {
    stream: TcpStream,
    /// The call Celmux bound this socket to.
    pub call_id: u64,
}

impl Wire {
    /// Open the wire and learn which call it carries.
    ///
    /// `None` means Celmux is up but has no call to bind yet, which is normal
    /// while dialling: the phone opens audio the moment a call needs sound, and
    /// the call becomes visible to Celmux a moment later. Retrying is the
    /// caller's job, not an error to report.
    pub fn connect(
        address: &str,
        plugin_id: &str,
        token: &str,
        line: &str,
    ) -> Result<Option<Self>, Error> {
        let mut stream = TcpStream::connect(address).map_err(Error::Io)?;
        stream.set_nodelay(true).map_err(Error::Io)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(Error::Io)?;
        let hello = format!("{CLIENT_HELLO}{plugin_id} {token} {line}\n");
        stream.write_all(hello.as_bytes()).map_err(Error::Io)?;
        stream.flush().map_err(Error::Io)?;
        let answer = read_line(&mut stream)?;
        if let Some(detail) = answer.strip_prefix(SERVER_ERROR) {
            return match detail.trim() {
                // Not an error: there is simply nothing to carry yet.
                "no call" => Ok(None),
                other => Err(Error::Refused(other.to_owned())),
            };
        }
        let call_id = answer
            .strip_prefix(SERVER_READY)
            .and_then(|detail| detail.trim().parse().ok())
            .ok_or(Error::Refused(answer.clone()))?;
        stream.set_read_timeout(None).map_err(Error::Io)?;
        Ok(Some(Self { stream, call_id }))
    }

    /// Split the wire into its two directions.
    ///
    /// Both halves are the same socket: the framing is symmetric, so neither side
    /// has to ask the other for anything once the handshake is done.
    pub fn split(self) -> std::io::Result<(TcpStream, TcpStream, u64)> {
        let reader = self.stream.try_clone()?;
        Ok((reader, self.stream, self.call_id))
    }
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// Celmux refused the handshake or answered something this side cannot read.
    Refused(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Refused(detail) => write!(formatter, "celmux 拒绝音频通道: {detail}"),
        }
    }
}

impl std::error::Error for Error {}

/// Read one newline-terminated line without consuming what follows.
///
/// A buffered reader would take the first audio block with it, and the first
/// block of a call is the one that carries the greeting.
fn read_line(stream: &mut TcpStream) -> Result<String, Error> {
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                line.push(byte[0]);
                if line.len() > MAX_ANSWER_BYTES {
                    return Err(Error::Refused("answer too long".to_owned()));
                }
            }
            Err(error) => return Err(Error::Io(error)),
        }
    }
    String::from_utf8(line).map_err(|_| Error::Refused("answer not utf-8".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two handshakes are distinguishable, so a phone's hello is never taken
    /// for Celmux's answer.
    #[test]
    fn the_handshake_tags_do_not_overlap() {
        assert!(!SERVER_READY.starts_with(CLIENT_HELLO.trim_end()));
        assert!(!SERVER_ERROR.starts_with(CLIENT_HELLO.trim_end()));
        assert!(!CLIENT_HELLO.trim_end().starts_with(SERVER_READY.trim_end()));
    }
}
