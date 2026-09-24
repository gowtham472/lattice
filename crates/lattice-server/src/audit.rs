//! A tamper-evident audit log of API use.
//!
//! Every API request except the public health check is recorded (allowed or refused) as one JSON
//! line in `<data-dir>/audit.jsonl`: time, principal, role, method, path, status and peer. Each
//! line carries a sequence number and the BLAKE3 of the line before it, so deleting, reordering or
//! editing any line breaks the chain at a point [`verify`] names. The server verifies the whole
//! log before it starts and refuses to run on a broken one; `lattice audit verify` checks a copy
//! offline. The chain proves integrity against edits, not against someone who truncates the file
//! and rewrites it wholesale: ship the log (or its latest hash) off the host for that.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

pub const FILE_NAME: &str = "audit.jsonl";
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// Entries kept in memory for `/api/audit`.
const RECENT: usize = 1000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Entry {
    pub seq: u64,
    pub time: String,
    /// The principal's name, or `-` when the caller did not authenticate.
    pub actor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    pub method: String,
    /// Path and query, truncated to 512 characters.
    pub path: String,
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    /// BLAKE3 of the previous line, or zeros for the first.
    pub prev: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit log line {line}: {reason}")]
    Broken { line: usize, reason: String },
    #[error("audit log: {0}")]
    Io(#[from] std::io::Error),
}

/// What a verified log contains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub entries: u64,
    /// Hex BLAKE3 of the last line: publish it to anchor the log.
    pub head: String,
}

/// Checks a whole log: every line parses, sequence numbers run 1, 2, 3, … and every `prev` is
/// the BLAKE3 of the line before it.
pub fn verify(bytes: &[u8]) -> Result<Verified, AuditError> {
    let mut head = GENESIS.to_owned();
    let mut entries = 0;
    if bytes.is_empty() {
        return Ok(Verified { entries, head });
    }
    if !bytes.ends_with(b"\n") {
        return Err(AuditError::Broken {
            line: bytes.split(|b| *b == b'\n').count(),
            reason: "the last line is incomplete".into(),
        });
    }
    for (index, line) in bytes[..bytes.len() - 1].split(|b| *b == b'\n').enumerate() {
        let number = index + 1;
        let broken = |reason: String| AuditError::Broken {
            line: number,
            reason,
        };
        let entry: Entry =
            serde_json::from_slice(line).map_err(|e| broken(format!("not an entry: {e}")))?;
        if entry.seq != entries + 1 {
            return Err(broken(format!(
                "sequence {} follows {entries}: lines were removed or reordered",
                entry.seq
            )));
        }
        if entry.prev != head {
            return Err(broken(
                "does not chain to the line before it: a line was altered or removed".into(),
            ));
        }
        head = blake3::hash(line).to_hex().to_string();
        entries = entry.seq;
    }
    Ok(Verified { entries, head })
}

struct Inner {
    file: Option<File>,
    seq: u64,
    head: String,
    recent: VecDeque<Entry>,
}

pub struct AuditLog {
    inner: Mutex<Inner>,
}

/// One request, as the guard saw it.
pub struct Event<'a> {
    pub actor: Option<(&'a str, &'a str)>,
    pub method: &'a str,
    pub path: &'a str,
    pub status: u16,
    pub peer: Option<String>,
}

impl AuditLog {
    /// Opens the log in `dir`, verifying what is already there, or keeps it in memory only.
    pub fn open(dir: Option<&Path>) -> Result<Self, AuditError> {
        let mut inner = Inner {
            file: None,
            seq: 0,
            head: GENESIS.to_owned(),
            recent: VecDeque::new(),
        };
        if let Some(dir) = dir {
            std::fs::create_dir_all(dir)?;
            let path = dir.join(FILE_NAME);
            let existing = match std::fs::read(&path) {
                Ok(bytes) => bytes,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                Err(e) => return Err(e.into()),
            };
            let verified = verify(&existing)?;
            inner.seq = verified.entries;
            inner.head = verified.head;
            for line in existing.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
                if let Ok(entry) = serde_json::from_slice::<Entry>(line) {
                    push_recent(&mut inner.recent, entry);
                }
            }
            inner.file = Some(OpenOptions::new().create(true).append(true).open(&path)?);
        }
        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    /// Appends one entry. A write failure is logged, never fatal to the request.
    pub fn record(&self, event: Event<'_>, time: String) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        let entry = Entry {
            seq: inner.seq + 1,
            time,
            actor: event
                .actor
                .map_or_else(|| "-".to_owned(), |(name, _)| name.to_owned()),
            role: event.actor.map(|(_, role)| role.to_owned()),
            method: event.method.to_owned(),
            path: event.path.chars().take(512).collect(),
            status: event.status,
            peer: event.peer,
            prev: inner.head.clone(),
        };
        let Ok(line) = serde_json::to_vec(&entry) else {
            return;
        };
        if let Some(file) = inner.file.as_mut() {
            let mut bytes = line.clone();
            bytes.push(b'\n');
            if let Err(error) = file.write_all(&bytes) {
                tracing::error!(%error, "could not append to the audit log");
                return;
            }
        }
        inner.seq = entry.seq;
        inner.head = blake3::hash(&line).to_hex().to_string();
        push_recent(&mut inner.recent, entry);
    }

    /// The newest entries, newest first.
    pub fn recent(&self, limit: usize) -> (Vec<Entry>, u64, String) {
        let Ok(inner) = self.inner.lock() else {
            return (Vec::new(), 0, String::new());
        };
        (
            inner.recent.iter().rev().take(limit).cloned().collect(),
            inner.seq,
            inner.head.clone(),
        )
    }
}

fn push_recent(recent: &mut VecDeque<Entry>, entry: Entry) {
    if recent.len() == RECENT {
        recent.pop_front();
    }
    recent.push_back(entry);
}
