//! Durable append-only flag store.
//!
//! Flags are persisted one-JSON-object-per-line to `flags.jsonl` in the data dir. The file is the
//! source of truth and survives restarts: on boot we replay it to rebuild the in-memory tail and
//! the running counters. The file is bounded by size-based rotation — when it grows past
//! `MAX_LOG_BYTES` it is moved aside to `flags.jsonl.1` (one generation kept) and a fresh file is
//! started, so disk usage stays bounded without losing recent history.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Rotate the active log once it passes this size (bytes). Keeps disk bounded.
const MAX_LOG_BYTES: u64 = 16 * 1024 * 1024;
/// How many flags to keep resident in memory for the admin feed.
const MEM_TAIL: usize = 5_000;

/// A single flag event. Mirrors the SHARED CONTRACT FlagEvent shape exactly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlagEvent {
    pub ts: u64,
    pub node_id: String,
    pub ip: String,
    pub heuristic: String,
    pub reason: String,
    pub severity: String,
    #[serde(default)]
    pub sample: serde_json::Value,
}

/// Internal record: a stored flag plus a monotonic sequence id used for `since` cursoring and
/// for the unseen watermark.
#[derive(Clone, Debug, Serialize)]
pub struct StoredFlag {
    pub seq: u64,
    #[serde(flatten)]
    pub event: FlagEvent,
}

struct Inner {
    data_dir: PathBuf,
    file: File,
    bytes: u64,
    next_seq: u64,
    /// Highest seq the operator has marked seen. unseen = next_seq-1 - seen_watermark.
    seen_watermark: u64,
    tail: VecDeque<StoredFlag>,
}

pub struct Store {
    inner: Mutex<Inner>,
}

impl Store {
    /// Open (creating if needed) the store rooted at `data_dir`, replaying any existing log.
    pub fn open(data_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&data_dir)
            .with_context(|| format!("create data dir {}", data_dir.display()))?;
        let log_path = data_dir.join("flags.jsonl");

        let mut next_seq: u64 = 1;
        let mut tail: VecDeque<StoredFlag> = VecDeque::new();

        if log_path.exists() {
            let f = File::open(&log_path)
                .with_context(|| format!("open {}", log_path.display()))?;
            for line in BufReader::new(f).lines() {
                let line = match line {
                    Ok(l) => l,
                    Err(_) => continue,
                };
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if let Ok(ev) = serde_json::from_str::<FlagEvent>(line) {
                    let stored = StoredFlag { seq: next_seq, event: ev };
                    next_seq += 1;
                    tail.push_back(stored);
                    if tail.len() > MEM_TAIL {
                        tail.pop_front();
                    }
                }
            }
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .with_context(|| format!("open append {}", log_path.display()))?;
        let bytes = file.metadata().map(|m| m.len()).unwrap_or(0);

        // On restart the operator starts with everything already-known marked seen would hide
        // history; instead we keep the unseen watermark at 0 so the dot reflects the full backlog
        // until the operator acknowledges. Persisted watermark would be nicer but the contract only
        // requires durability of the LOG; a restart simply re-surfaces the unseen backlog, which is
        // the safe default for a security console.
        let seen_watermark = 0;

        Ok(Self {
            inner: Mutex::new(Inner {
                data_dir,
                file,
                bytes,
                next_seq,
                seen_watermark,
                tail,
            }),
        })
    }

    /// Append a flag durably, then update in-memory tail + counters. Returns the assigned seq.
    pub fn append(&self, event: FlagEvent) -> Result<u64> {
        let mut g = self.inner.lock().map_err(|_| anyhow::anyhow!("store poisoned"))?;

        let line = serde_json::to_string(&event).context("serialize flag")?;
        let bytes = line.len() as u64 + 1;

        // Rotate before writing if this write would push us over the cap.
        if g.bytes + bytes > MAX_LOG_BYTES {
            rotate(&mut g)?;
        }

        g.file
            .write_all(line.as_bytes())
            .context("write flag line")?;
        g.file.write_all(b"\n").context("write newline")?;
        g.file.flush().context("flush flag")?;
        // Durability: fsync so the flag survives a hard crash, matching the test's restart guarantee.
        let _ = g.file.sync_all();
        g.bytes += bytes;

        let seq = g.next_seq;
        g.next_seq += 1;
        let stored = StoredFlag { seq, event };
        g.tail.push_back(stored);
        if g.tail.len() > MEM_TAIL {
            g.tail.pop_front();
        }
        Ok(seq)
    }

    /// Number of flags appended since the last `mark_seen`.
    pub fn unseen(&self) -> u64 {
        let g = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return 0,
        };
        (g.next_seq - 1).saturating_sub(g.seen_watermark)
    }

    /// Mark everything up to the current head as seen; clears the unseen dot.
    pub fn mark_seen(&self) {
        if let Ok(mut g) = self.inner.lock() {
            g.seen_watermark = g.next_seq - 1;
        }
    }

    /// Highest assigned seq (0 if empty).
    pub fn head_seq(&self) -> u64 {
        match self.inner.lock() {
            Ok(g) => g.next_seq - 1,
            Err(_) => 0,
        }
    }

    /// Return flags newest-first, with optional `since` (exclusive seq), heuristic and severity
    /// filters. `since` lets the UI poll for only-new rows.
    pub fn query(
        &self,
        since: Option<u64>,
        heuristic: Option<&str>,
        severity: Option<&str>,
        node: Option<&str>,
        limit: usize,
    ) -> Vec<StoredFlag> {
        let g = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let mut out: Vec<StoredFlag> = g
            .tail
            .iter()
            .filter(|s| since.map(|c| s.seq > c).unwrap_or(true))
            .filter(|s| heuristic.map(|h| s.event.heuristic == h).unwrap_or(true))
            .filter(|s| severity.map(|sv| s.event.severity == sv).unwrap_or(true))
            .filter(|s| node.map(|n| s.event.node_id == n).unwrap_or(true))
            .cloned()
            .collect();
        out.sort_by(|a, b| b.seq.cmp(&a.seq));
        out.truncate(limit);
        out
    }
}

/// Move the active log to `flags.jsonl.1` (overwriting any prior generation) and reopen a fresh,
/// empty active log. Caller holds the lock.
fn rotate(g: &mut Inner) -> Result<()> {
    let active = g.data_dir.join("flags.jsonl");
    let prev = g.data_dir.join("flags.jsonl.1");
    g.file.flush().ok();
    let _ = g.file.sync_all();
    if active.exists() {
        let _ = std::fs::remove_file(&prev);
        std::fs::rename(&active, &prev).context("rotate flag log")?;
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&active)
        .context("reopen flag log after rotate")?;
    g.file = file;
    g.bytes = 0;
    Ok(())
}

/// Resolve the data dir from env (`CE_WATCH_DATA_DIR`) or default to `./ce-watch-data`.
pub fn default_data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("CE_WATCH_DATA_DIR") {
        if !d.is_empty() {
            return PathBuf::from(d);
        }
    }
    Path::new("ce-watch-data").to_path_buf()
}
