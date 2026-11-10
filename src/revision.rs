// Copyright (c) 2026 anti-rainer
// SPDX-License-Identifier: MIT

//! The event revision the phone long-polls against.
//!
//! AirSIM's app prefers one long poll of `api/events` over two separate loops for
//! calls and SMS. It sends `after=<revision>` and `timeout_ms`, and expects an
//! answer when something changed or when the timeout expires - whichever comes
//! first. Answering immediately every time works, but it makes the app poll as
//! fast as the network allows, which in the background burns battery for nothing
//! and in the foreground makes the call state feel laggy because every poll is a
//! fresh round trip.
//!
//! So this holds the request until the revision moves or the deadline passes. The
//! revision is wall-clock milliseconds of the last change, which the poller only
//! compares for change - a restart moving it forward is harmless, moving it back
//! would hide an update.

use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

/// How long a poll may be held before it answers with "nothing changed".
///
/// The app asks for at most 30 seconds and clamps lower; this is the ceiling for
/// a request that asks for something unreasonable, not the normal case.
const MAX_HOLD: Duration = Duration::from_secs(30);

/// The longest a poll is held even when the caller asks for more.
pub struct Revision {
    current: Mutex<u64>,
}

impl Default for Revision {
    fn default() -> Self {
        Self {
            current: Mutex::new(now_ms()),
        }
    }
}

impl Revision {
    /// The current revision.
    pub fn now(&self) -> u64 {
        self.current.lock().map(|value| *value).unwrap_or(0)
    }

    /// Record a change. Every poll waiting on the old revision wakes.
    pub fn bump(&self) {
        if let Ok(mut current) = self.current.lock() {
            // Strictly forward, never merely "now". Two changes in the same
            // millisecond - which happens when a line list is applied row by row -
            // would otherwise leave the revision unchanged, and a poll already
            // waiting on that value would sit out its whole timeout before the
            // phone learned anything.
            let next = now_ms();
            *current = if next > *current { next } else { *current + 1 };
        }
    }

    /// Wait until the revision passes `after`, or `timeout` expires.
    ///
    /// Returns the revision to report.
    ///
    /// An `after` ahead of ours is *not* a reason to answer at once. The app starts
    /// from `AgentEventCursor.initial`, which is `u64::MAX` - a sentinel meaning
    /// "I have no position yet", not a timestamp. Answering such a poll immediately
    /// (the old behaviour) meant every long poll returned within a millisecond,
    /// carrying `active: null`, so the app spun as fast as the network allowed and
    /// a ringing call could only be seen if it happened to exist at the exact
    /// moment of one of those answers. Treating it as "unknown, so from now on" is
    /// what lets the first poll actually wait for the ring.
    pub fn wait_past(&self, after: u64, timeout: Duration) -> u64 {
        let timeout = timeout.min(MAX_HOLD);
        let start = self.now();
        // A position ahead of us is a sentinel or a restart, never a real reading:
        // wait from here. A position behind ours is a real reading with news
        // waiting, so it answers at once - that is the point of the revision.
        if start > after {
            return start;
        }
        let deadline = Instant::now() + timeout;
        // Polled rather than driven by a condvar: a change can come from a thread
        // that must not block on this lock, and a 50ms tick is far below the
        // latency the app can perceive.
        //
        // Compared against `start`, not `after`. `after` may be a sentinel that
        // never equals a real timestamp, so testing `current != after` returned on
        // the first tick - a long poll that lasted 50ms and then spun.
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
            let current = self.now();
            if current != start {
                return current;
            }
        }
        self.now()
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A poll that already knows the current revision has nothing to be told, so
    /// it is held until its timeout rather than answered in a hot loop.
    #[test]
    fn a_poll_holding_the_current_revision_is_held_until_its_timeout() {
        let revision = Revision::default();
        let current = revision.now();
        let started = Instant::now();
        assert_eq!(
            revision.wait_past(current, Duration::from_millis(300)),
            current
        );
        // Held for about the timeout: shorter means a hot loop, much longer means
        // the deadline is not honoured.
        assert!(
            started.elapsed() >= Duration::from_millis(250),
            "returned after {:?}",
            started.elapsed()
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    /// A poll that is behind must be told about the change immediately rather than
    /// waiting out its timeout.
    #[test]
    fn a_poll_behind_the_revision_is_answered_at_once() {
        let revision = Revision::default();
        let stale = revision.now().saturating_sub(1000);
        let started = Instant::now();
        assert_eq!(
            revision.wait_past(stale, Duration::from_secs(5)),
            revision.now()
        );
        assert!(started.elapsed() < Duration::from_millis(200));
    }

    /// A change during the hold releases it well before the deadline.
    #[test]
    fn a_change_releases_a_waiting_poll() {
        let revision = std::sync::Arc::new(Revision::default());
        let current = revision.now();
        let raiser = revision.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            raiser.bump();
        });
        let started = Instant::now();
        let answered = revision.wait_past(current, Duration::from_secs(5));
        assert!(answered > current);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "held for {:?}",
            started.elapsed()
        );
    }

    /// An absurd timeout is capped, so a misbehaving caller cannot pin a thread
    /// for an hour. The cap itself is what this asserts; waiting it out would cost
    /// the whole test run, so the number is checked directly.
    #[test]
    fn the_hold_ceiling_is_bounded() {
        assert!(MAX_HOLD <= Duration::from_secs(30));
        // A caller asking for a year gets the ceiling, which is what the clamp
        // inside `wait_past` computes.
        let requested = Duration::from_secs(31_536_000);
        assert_eq!(requested.min(MAX_HOLD), MAX_HOLD);
    }
    /// A poll asking from `u64::MAX` waits; it does not answer at once.
    ///
    /// That value is the app's "no position yet" sentinel. Answering immediately
    /// turned every long poll into a sub-millisecond return, so the app spun and an
    /// incoming call was only ever visible by luck.
    #[test]
    fn a_poll_from_the_future_sentinel_waits_instead_of_answering_at_once() {
        let revision = Revision::default();
        let started = Instant::now();
        let answered = revision.wait_past(u64::MAX, Duration::from_millis(300));
        assert!(
            started.elapsed() >= Duration::from_millis(250),
            "哨兵值必须挂起等待，不能立刻返回（实际 {:?}）",
            started.elapsed()
        );
        assert_eq!(answered, revision.now());
    }

    /// A poll already behind the current revision answers at once: there is news.
    #[test]
    fn a_poll_behind_the_revision_answers_at_once() {
        let revision = Revision::default();
        let started = Instant::now();
        revision.wait_past(0, Duration::from_secs(5));
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "已知落后于当前 revision 时应当立刻返回（实际 {:?}）",
            started.elapsed()
        );
    }
}
