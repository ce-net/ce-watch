//! Durable append-only flag store.
//!
//! Flags are persisted one-JSON-object-per-line to `flags.jsonl` in the data dir. The file is the
//! source of truth and survives restarts: on boot we replay it to rebuild the in-memory tail and
//! the running counters. The file is bounded by size-based rotation — when it grows past
//! `MAX_LOG_BYTES` it is moved aside to `flags.jsonl.1` (one generation kept) and a fresh file is
//! started, so disk usage stays bounded without losing recent history.

use std::collections::{BTreeMap, VecDeque};
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

/// The role a device holds in the admin store. `Admin` may use the flag console and manage other
/// devices; `Pending` is a device that has requested access but not yet been approved.
pub const ROLE_ADMIN: &str = "admin";
pub const ROLE_PENDING: &str = "pending";

/// A persisted admin/pending device record. `pub` is the compact ECDSA SEC1 form
/// (`base64url(04||x||y)`) the console derives from its WebCrypto key — the exact string accepted by
/// `auth::ecdsa_pub_from_compact`, so we can reconstruct the verifying key to authenticate the
/// device on every request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminDevice {
    /// Compact ECDSA SEC1 public point, base64url(no-pad) of `04 || x(32) || y(32)`.
    #[serde(rename = "pub")]
    pub pub_b64: String,
    /// `"admin"` or `"pending"`.
    pub role: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub added_ts: u64,
}

/// The persisted, self-managed admin device store (`admins.json` in the data dir). It is the source
/// of truth for "who is an admin" after boot. Env-seeded devices are written in as `role=admin` at
/// startup (a bootstrap) but never override a device already present in the file.
///
/// The map (`deviceId -> AdminDevice`) is held under a mutex and mirrored to disk atomically (write
/// to a temp file, fsync, rename) with mode 0600 on unix, so a crash mid-write cannot corrupt it.
pub struct AdminStore {
    path: PathBuf,
    inner: Mutex<BTreeMap<String, AdminDevice>>,
}

impl AdminStore {
    /// Open (creating if needed) the admin store at `data_dir/admins.json`, replaying any existing
    /// file, then seeding any `seed` entries (deviceId -> compact-pub) as `role=admin` for devices
    /// not already present. A change from seeding is persisted immediately.
    pub fn open(data_dir: &Path, seed: &[(String, String)]) -> Result<Self> {
        std::fs::create_dir_all(data_dir)
            .with_context(|| format!("create data dir {}", data_dir.display()))?;
        let path = data_dir.join("admins.json");

        let mut map: BTreeMap<String, AdminDevice> = BTreeMap::new();
        if path.exists() {
            let raw = std::fs::read_to_string(&path)
                .with_context(|| format!("read {}", path.display()))?;
            if !raw.trim().is_empty() {
                map = serde_json::from_str(&raw)
                    .with_context(|| format!("parse {}", path.display()))?;
            }
        }

        let store = Self { path, inner: Mutex::new(map) };

        // Seed env-provided devices as admins (bootstrap). The persisted file wins for any device
        // already present, so re-deploying with the same env never demotes/overwrites live state.
        let mut changed = false;
        {
            let mut g = store
                .inner
                .lock()
                .map_err(|_| anyhow::anyhow!("admin store poisoned"))?;
            for (id, pub_b64) in seed {
                if !g.contains_key(id) {
                    g.insert(
                        id.clone(),
                        AdminDevice {
                            pub_b64: pub_b64.clone(),
                            role: ROLE_ADMIN.to_string(),
                            label: "env-seed".to_string(),
                            added_ts: now_unix_secs(),
                        },
                    );
                    changed = true;
                }
            }
        }
        if changed {
            store.persist()?;
        }
        Ok(store)
    }

    /// Atomically write the current map to disk (temp file + fsync + rename), mode 0600 on unix.
    fn persist(&self) -> Result<()> {
        let g = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("admin store poisoned"))?;
        let json = serde_json::to_string_pretty(&*g).context("serialize admins")?;
        drop(g);

        let tmp = self.path.with_extension("json.tmp");
        {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)
                .with_context(|| format!("open temp {}", tmp.display()))?;
            f.write_all(json.as_bytes()).context("write admins temp")?;
            f.flush().ok();
            let _ = f.sync_all();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &self.path).context("rename admins into place")?;
        Ok(())
    }

    /// Number of devices with `role=admin`.
    pub fn admin_count(&self) -> usize {
        match self.inner.lock() {
            Ok(g) => g.values().filter(|d| d.role == ROLE_ADMIN).count(),
            Err(_) => 0,
        }
    }

    /// True when at least one admin exists.
    pub fn has_admins(&self) -> bool {
        self.admin_count() > 0
    }

    /// The role of a device id: `"admin"`, `"pending"`, or `"none"` (unknown).
    pub fn role_of(&self, device_id: &str) -> &'static str {
        match self.inner.lock() {
            Ok(g) => match g.get(device_id).map(|d| d.role.as_str()) {
                Some(ROLE_ADMIN) => ROLE_ADMIN,
                Some(ROLE_PENDING) => ROLE_PENDING,
                _ => "none",
            },
            Err(_) => "none",
        }
    }

    pub fn is_admin(&self, device_id: &str) -> bool {
        self.role_of(device_id) == ROLE_ADMIN
    }

    /// Snapshot the device map (id -> record) for listing.
    pub fn list(&self) -> Vec<(String, AdminDevice)> {
        match self.inner.lock() {
            Ok(g) => g.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// TOFU first claim: if there are ZERO admins, make `device_id` an admin (recording its `pub`).
    /// Returns `Ok(true)` on success, `Ok(false)` if an admin already exists (caller -> 409).
    pub fn claim(&self, device_id: &str, pub_b64: &str) -> Result<bool> {
        {
            let mut g = self
                .inner
                .lock()
                .map_err(|_| anyhow::anyhow!("admin store poisoned"))?;
            if g.values().any(|d| d.role == ROLE_ADMIN) {
                return Ok(false);
            }
            g.insert(
                device_id.to_string(),
                AdminDevice {
                    pub_b64: pub_b64.to_string(),
                    role: ROLE_ADMIN.to_string(),
                    label: "claimed".to_string(),
                    added_ts: now_unix_secs(),
                },
            );
        }
        self.persist()?;
        Ok(true)
    }

    /// Record a device as `role=pending` with its compact pub and optional label. Idempotent: a
    /// device already present (admin or pending) is left as-is except a pending device may refresh
    /// its label/pub. Returns the resulting role.
    pub fn request(&self, device_id: &str, pub_b64: &str, label: &str) -> Result<&'static str> {
        let role;
        {
            let mut g = self
                .inner
                .lock()
                .map_err(|_| anyhow::anyhow!("admin store poisoned"))?;
            match g.get_mut(device_id) {
                Some(d) if d.role == ROLE_ADMIN => {
                    role = ROLE_ADMIN;
                }
                Some(d) => {
                    // already pending — refresh its advertised pub/label
                    d.pub_b64 = pub_b64.to_string();
                    if !label.is_empty() {
                        d.label = label.to_string();
                    }
                    role = ROLE_PENDING;
                }
                None => {
                    g.insert(
                        device_id.to_string(),
                        AdminDevice {
                            pub_b64: pub_b64.to_string(),
                            role: ROLE_PENDING.to_string(),
                            label: label.to_string(),
                            added_ts: now_unix_secs(),
                        },
                    );
                    role = ROLE_PENDING;
                }
            }
        }
        self.persist()?;
        Ok(role)
    }

    /// Promote a pending device to admin. Returns `Ok(true)` if a pending device was promoted,
    /// `Ok(false)` if the device is unknown or already an admin.
    pub fn approve(&self, device_id: &str) -> Result<bool> {
        let mut promoted = false;
        {
            let mut g = self
                .inner
                .lock()
                .map_err(|_| anyhow::anyhow!("admin store poisoned"))?;
            if let Some(d) = g.get_mut(device_id) {
                if d.role == ROLE_PENDING {
                    d.role = ROLE_ADMIN.to_string();
                    promoted = true;
                }
            }
        }
        if promoted {
            self.persist()?;
        }
        Ok(promoted)
    }

    /// Remove a device entirely. Returns `Err` if removing it would drop the last admin (caller's
    /// `requester` is passed so we can phrase that as "cannot revoke your own last admin"); the
    /// guard is on the GLOBAL admin count, so the last admin cannot be removed by anyone.
    pub fn revoke(&self, device_id: &str) -> Result<RevokeOutcome> {
        let outcome;
        {
            let mut g = self
                .inner
                .lock()
                .map_err(|_| anyhow::anyhow!("admin store poisoned"))?;
            match g.get(device_id) {
                None => return Ok(RevokeOutcome::NotFound),
                Some(d) => {
                    let is_admin = d.role == ROLE_ADMIN;
                    let admin_count = g.values().filter(|x| x.role == ROLE_ADMIN).count();
                    if is_admin && admin_count <= 1 {
                        return Ok(RevokeOutcome::LastAdmin);
                    }
                }
            }
            g.remove(device_id);
            outcome = RevokeOutcome::Removed;
        }
        self.persist()?;
        Ok(outcome)
    }

    /// Look up a device's compact pub (for reconstructing its verifying key during auth).
    pub fn pub_of(&self, device_id: &str) -> Option<String> {
        match self.inner.lock() {
            Ok(g) => g.get(device_id).map(|d| d.pub_b64.clone()),
            Err(_) => None,
        }
    }
}

/// Outcome of a revoke attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum RevokeOutcome {
    Removed,
    NotFound,
    LastAdmin,
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
