// Copyright (c) 2026 anti-rainer
// SPDX-License-Identifier: MIT

//! Which lines this gateway offers, kept on disk beside the pairing secrets.
//!
//! This is not operator configuration. Configuration is what Celmux resolves for
//! a plugin and hands down at launch - ports, credentials, log level - and there
//! is exactly one place where a value can be wrong. The line assignment is not
//! that: it is a decision the operator makes by clicking a row on this plugin's
//! own page, possibly many times, and every one of those clicks is a fact about
//! this installation that must survive a restart.
//!
//! Keeping it here rather than in Celmux's plugin settings is what makes the
//! plugin independent of the host for its own state. The previous arrangement
//! stored the assignment as one JSON string in a host configuration field, so an
//! "add this line" click was really a configuration write: it had to be a valid
//! value for a schema the plugin did not own, it was masked wherever the host
//! showed secrets, and a host-side rejection was indistinguishable from a
//! successful write. The click looked applied - the page had already redrawn -
//! and the next poll put the row back where it was.
//!
//! The file is a small JSON document, written whole and replaced atomically. It
//! holds only line labels, which are public: no secret is ever here.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Where the assignment lives, relative to the plugin's own directory.
const FILE: &str = "line-assignment.json";

/// The stored form. Versions exist so a later shape can be read back rather than
/// guessed at; there is one today.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Document {
    #[serde(default)]
    version: u32,
    /// Whether every line Celmux has is offered, ignoring `lines`.
    #[serde(default)]
    pub expose_all: bool,
    /// The lines the operator added, in the order the page showed them.
    #[serde(default)]
    pub lines: Vec<String>,
}

impl Document {
    const VERSION: u32 = 1;
}

/// The assignment on disk.
pub struct Store {
    path: PathBuf,
}

impl Store {
    /// A store rooted at the plugin's own directory.
    pub fn new(root: &Path) -> Self {
        Self {
            path: root.join(FILE),
        }
    }

    /// Read what was stored, or an empty assignment.
    ///
    /// A missing file is an empty assignment, not an error: a fresh install has
    /// simply never added a line, and the page must open. A corrupt one is also
    /// empty, with a warning - refusing to start over a file the operator can
    /// recreate by clicking would take the whole bridge down.
    pub fn load(&self) -> Document {
        let raw = match std::fs::read_to_string(&self.path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Document::default();
            }
            Err(error) => {
                crate::log_warn!(
                    "celmux-plugin-airsim: 无法读取线路分配 {}: {error}",
                    self.path.display()
                );
                return Document::default();
            }
        };
        match serde_json::from_str::<Document>(&raw) {
            Ok(mut document) => {
                if document.version == 0 {
                    document.version = Document::VERSION;
                }
                // A duplicate label would show one row twice and expose one line
                // while the page claimed two.
                let mut seen = BTreeSet::new();
                document.lines.retain(|line| seen.insert(line.clone()));
                document
            }
            Err(error) => {
                crate::log_warn!(
                    "celmux-plugin-airsim: 线路分配文件无法解析，按未加入处理 {}: {error}",
                    self.path.display()
                );
                Document::default()
            }
        }
    }

    /// Replace the assignment.
    ///
    /// Written to a sibling and renamed, so a crash mid-write leaves the previous
    /// assignment intact rather than a truncated file. Returns the error instead
    /// of logging it: the caller answers the page, and a click that did not
    /// survive a restart is something the operator has to be told.
    pub fn save(&self, document: &Document) -> Result<(), String> {
        let mut document = document.clone();
        document.version = Document::VERSION;
        let body = serde_json::to_vec_pretty(&document)
            .map_err(|error| format!("线路分配无法序列化: {error}"))?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("无法创建插件目录 {}: {error}", parent.display()))?;
        }
        let staging = self.path.with_extension("json.tmp");
        {
            let mut file = std::fs::File::create(&staging)
                .map_err(|error| format!("无法写入线路分配 {}: {error}", staging.display()))?;
            file.write_all(&body)
                .map_err(|error| format!("无法写入线路分配: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("无法落盘线路分配: {error}"))?;
        }
        std::fs::rename(&staging, &self.path)
            .map_err(|error| format!("无法替换线路分配 {}: {error}", self.path.display()))
    }

    /// The path this store wrote to, for the log line that says where.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// The assignment a page submitted, in the order it sent them.
///
/// Empty labels are dropped rather than stored: a row with no line cannot be
/// matched against Celmux and would sit in the file forever.
pub fn from_lines<I, S>(lines: I, expose_all: bool) -> Document
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut seen = BTreeSet::new();
    let lines: Vec<String> = lines
        .into_iter()
        .map(|line| line.as_ref().trim().to_owned())
        .filter(|line| !line.is_empty() && seen.insert(line.clone()))
        .collect();
    Document {
        version: Document::VERSION,
        expose_all,
        lines,
    }
}

#[cfg(test)]
mod tests {
    use super::{Document, Store, from_lines};

    fn root(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("celmux-airsim-assignment-{name}"));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    /// The click that this module exists for: add a line, and it is still there
    /// when the process reads the file again. The previous arrangement stored
    /// this in a host configuration field, so the write could be refused by a
    /// schema this plugin did not own while the page had already redrawn.
    #[test]
    fn an_added_line_survives_a_reload() {
        let root = root("reload");
        let store = Store::new(&root);
        assert!(store.load().lines.is_empty(), "a fresh install has none");

        let document = from_lines(["读卡器1#89441000400316068339"], false);
        store.save(&document).expect("save");
        assert_eq!(store.load(), document);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Removing the last line is a real state, not "no file yet": the page must
    /// come back up showing nothing offered rather than everything.
    #[test]
    fn removing_every_line_is_remembered_as_a_decision() {
        let root = root("empty");
        let store = Store::new(&root);
        store
            .save(&from_lines(["读卡器1#89441000400316068339"], false))
            .expect("save");
        store
            .save(&from_lines(Vec::<String>::new(), false))
            .expect("save empty");
        let loaded = store.load();
        assert!(loaded.lines.is_empty());
        assert!(!loaded.expose_all);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A line named twice would render one row twice and count it twice.
    #[test]
    fn a_line_named_twice_is_stored_once() {
        let document = from_lines(["a#1", "a#1", "  ", "b#2"], false);
        assert_eq!(document.lines, vec!["a#1".to_owned(), "b#2".to_owned()]);
    }

    /// A corrupt file must not stop the plugin: the operator can rebuild the
    /// list by clicking, but cannot restart a process that refused to start.
    #[test]
    fn an_unreadable_file_reads_as_nothing_offered() {
        let root = root("corrupt");
        std::fs::create_dir_all(&root).expect("dir");
        std::fs::write(root.join("line-assignment.json"), b"{not json").expect("write");
        let loaded = Store::new(&root).load();
        assert_eq!(loaded, Document::default());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The write is staged and renamed, so an interrupted save leaves the
    /// previous assignment readable instead of a half-written file.
    #[test]
    fn a_save_replaces_the_previous_assignment_atomically() {
        let root = root("atomic");
        let store = Store::new(&root);
        store.save(&from_lines(["a#1"], false)).expect("first");
        store.save(&from_lines(["b#2"], false)).expect("second");
        assert_eq!(store.load().lines, vec!["b#2".to_owned()]);
        assert!(
            !root.join("line-assignment.json.tmp").exists(),
            "the staging file must not survive a completed save"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
