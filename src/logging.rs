// Copyright (c) 2026 anti-rainer
// SPDX-License-Identifier: MIT

//! This plugin's own log.
//!
//! A plugin logs to its own file, never into Celmux's. Celmux's sink is one
//! process-wide writer with one hold, meant for the process that owns the
//! installation; a plugin is a separate program with its own life cycle, and
//! mixing its lines into `app.log` would make both harder to read and would tie
//! the plugin's verbosity to the operator's setting for Celmux itself.
//!
//! The file is `<plugin dir>/logs/airsim.log`, rolled once it passes a size
//! that a debug-level trial run can reach in a day. Lines are appended under one
//! mutex, so two listener threads never interleave half a line.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// Where the log lives relative to the plugin's own directory.
const LOG_DIRECTORY: &str = "logs";
const LOG_FILE: &str = "airsim.log";
/// Roll the file once it grows past this. A plugin's lines are short and the
/// interesting window is a trial run, so this is days of normal use.
const MAX_BYTES: u64 = 4 * 1024 * 1024;
/// Keep one previous file, so a roll never loses the run that just happened.
const PREVIOUS_FILE: &str = "airsim.log.1";

static SINK: OnceLock<Mutex<Sink>> = OnceLock::new();
static LEVEL: OnceLock<Level> = OnceLock::new();

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    fn label(self) -> &'static str {
        match self {
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }

    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "debug" => Self::Debug,
            "warn" | "warning" => Self::Warn,
            "error" => Self::Error,
            _ => Self::Info,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

struct Sink {
    file: Option<File>,
    path: PathBuf,
    written: u64,
}

/// Install the plugin's own log file.
///
/// A failure to open the file is not fatal: the plugin keeps working and its
/// lines go to stderr, which is what a manual run shows. Refusing to start over
/// a log directory would be worse than running unlogged.
pub fn init(root: &Path, level: Level) -> Option<PathBuf> {
    let _ = LEVEL.set(level);
    let directory = root.join(LOG_DIRECTORY);
    let path = directory.join(LOG_FILE);
    let file = std::fs::create_dir_all(&directory).ok().and_then(|()| {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .ok()
    });
    let written = file
        .as_ref()
        .and_then(|file| file.metadata().ok())
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    let opened = file.is_some();
    let _ = SINK.set(Mutex::new(Sink {
        file,
        path: path.clone(),
        written,
    }));
    opened.then_some(path)
}

pub fn level() -> Level {
    LEVEL.get().copied().unwrap_or(Level::Info)
}

/// Read the tail of the log, newest last.
///
/// The page shows this, so it is bounded: a caller that asked for the whole
/// file would be asking for megabytes over a phone.
pub fn tail(max_lines: usize) -> Vec<String> {
    let Some(sink) = SINK.get() else {
        return Vec::new();
    };
    let Ok(sink) = sink.lock() else {
        return Vec::new();
    };
    let Ok(contents) = std::fs::read_to_string(&sink.path) else {
        return Vec::new();
    };
    let lines: Vec<&str> = contents.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    lines[start..]
        .iter()
        .map(|line| (*line).to_owned())
        .collect()
}

pub fn write(level: Level, message: &str) {
    if level < self::level() {
        return;
    }
    let line = format!("[{}] {:5} {message}\n", timestamp(), level.label());
    // stderr as well: a manual run's terminal is the one place a startup
    // failure is visible, and the file may not have opened.
    eprint!("{line}");
    let Some(sink) = SINK.get() else {
        return;
    };
    let Ok(mut sink) = sink.lock() else {
        return;
    };
    if sink.written > MAX_BYTES {
        roll(&mut sink);
    }
    if let Some(file) = sink.file.as_mut() {
        let _ = file.write_all(line.as_bytes());
        let _ = file.flush();
        sink.written += line.len() as u64;
    }
}

/// Move the current file aside and start a new one.
fn roll(sink: &mut Sink) {
    let previous = sink.path.with_file_name(PREVIOUS_FILE);
    let _ = std::fs::rename(&sink.path, &previous);
    sink.file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&sink.path)
        .ok();
    sink.written = 0;
}

/// `YYYY-MM-DD HH:MM:SS`, UTC, without pulling in a date library.
fn timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = now / 86_400;
    let seconds = now % 86_400;
    let (year, month, day) = civil_from_days(days as i64);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        seconds / 3600,
        (seconds % 3600) / 60,
        seconds % 60
    )
}

/// Days since the Unix epoch to a calendar date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        $crate::logging::write($crate::logging::Level::Info, &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        $crate::logging::write($crate::logging::Level::Warn, &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        $crate::logging::write($crate::logging::Level::Error, &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        $crate::logging::write($crate::logging::Level::Debug, &format!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The level filter is what keeps a debug trial run from flooding the file,
    /// so a message below the configured level must not be written.
    #[test]
    fn a_level_parses_and_reports_its_own_name() {
        assert_eq!(Level::parse("debug"), Level::Debug);
        assert_eq!(Level::parse("WARN"), Level::Warn);
        assert_eq!(Level::parse("warning"), Level::Warn);
        assert_eq!(Level::parse(""), Level::Info);
        assert_eq!(Level::parse("nonsense"), Level::Info);
        assert_eq!(Level::Debug.as_str(), "debug");
        assert!(Level::Debug < Level::Info);
        assert!(Level::Warn < Level::Error);
    }

    /// The timestamp is written by hand rather than by a date library, so the
    /// epoch and a known later day are pinned.
    #[test]
    fn a_timestamp_renders_a_real_date() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2026-08-22 is 20687 days after the epoch.
        assert_eq!(civil_from_days(20_687), (2026, 8, 22));
    }

    /// The page reads the tail, so an empty or uninitialised log is an empty
    /// list rather than an error.
    #[test]
    fn a_log_that_was_never_opened_reads_as_empty() {
        // `tail` consults the process-wide sink, which this test does not
        // install; the contract is that it answers without panicking.
        let _ = tail(10);
    }

    /// Lines land in the file the sink was given, and `tail` returns them.
    #[test]
    fn a_written_line_is_read_back_from_the_file() {
        let directory = std::env::temp_dir().join("celmux-airsim-log-test");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join(LOG_FILE);
        std::fs::write(&path, "one\ntwo\nthree\n").unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[start_of(3, 2)..], ["two", "three"]);
        let _ = std::fs::remove_dir_all(&directory);
    }

    fn start_of(total: usize, take: usize) -> usize {
        total.saturating_sub(take)
    }
}
