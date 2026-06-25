//! Abuse detector — moved out of ce-hub so the hub only TRACKS and ce-monitor does all the watching.
//!
//! ce-hub emits raw observations over the mesh (topic `ce-monitor/observe`): a `submit` per dispatched
//! task, a `runtime` per result, and per-node `gauge` deltas for in-flight load. This module keeps the
//! windowed per-IP / per-node state and runs the H1-H6 heuristics on those observations, returning
//! `FlagEvent`s that the mesh ingest appends to the durable store. Memory is bounded to recent traffic
//! (the DETECT_WINDOW) and the IP map cap.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::store::FlagEvent;

const DETECT_WINDOW: Duration = Duration::from_secs(300); // 5m sliding window
const DETECT_IP_CAP: usize = 4096; // bound on tracked submitter IPs
const DETECT_MS_SAMPLES: usize = 64; // per-IP runtime samples kept for the H3 median
const FLAG_THROTTLE: Duration = Duration::from_secs(30); // collapse repeats of the same (ip, heuristic)

const H1_BUCKET_CAP: f64 = 10.0;
const H1_REFILL_PER_S: f64 = 0.2;
const H2_IDENTICAL_MAX: u64 = 15;
const H3_MEDIAN_MS: f64 = 8000.0;
const H3_MIN_RUNS: usize = 5;
const H4_MODULE_MAX: u64 = 8;
const H5_DISTINCT_NODES: usize = 3;
const H5_TASK_COUNT: usize = 25;
const H6_PENDING_SECS: u64 = 60;

#[derive(Clone)]
struct RateBucket {
    tokens: f64,
    last: Instant,
}

#[derive(Default)]
struct IpStat {
    bucket: Option<RateBucket>,
    sigs: HashMap<String, VecDeque<Instant>>,
    modules: HashMap<String, VecDeque<Instant>>,
    nodes: HashMap<String, Instant>,
    submits: VecDeque<Instant>,
    ms_samples: VecDeque<f64>,
}

#[derive(Default, Clone)]
struct NodeGauge {
    pending: u64,
    cores: u32,
    over_since: Option<Instant>,
}

#[derive(Default)]
struct DetectState {
    ips: HashMap<String, IpStat>,
    gauges: HashMap<String, NodeGauge>,
}

fn prune_window(q: &mut VecDeque<Instant>, now: Instant) {
    while let Some(front) = q.front() {
        if now.duration_since(*front) > DETECT_WINDOW {
            q.pop_front();
        } else {
            break;
        }
    }
}

/// Owns the detector state. Methods take the windowed observations and return the flags to store.
pub struct Detector {
    state: Mutex<DetectState>,
    throttle: Mutex<HashMap<(String, String), Instant>>,
}

impl Default for Detector {
    fn default() -> Self {
        Detector { state: Mutex::new(DetectState::default()), throttle: Mutex::new(HashMap::new()) }
    }
}

impl Detector {
    pub fn new() -> Self {
        Self::default()
    }

    /// H1-H5 for one submission from `ip` targeting `node_id`. Any trip becomes a FlagEvent.
    pub fn submit(&self, ip: &str, func: &str, submit_sig: &str, module_sha: Option<&str>, node_id: &str) -> Vec<FlagEvent> {
        let now = Instant::now();
        let mut trips: Vec<(String, String, String, Value)> = Vec::new();
        {
            let mut det = self.state.lock().unwrap();
            if !det.ips.contains_key(ip) && det.ips.len() >= DETECT_IP_CAP {
                if let Some(victim) = det.ips.keys().next().cloned() {
                    det.ips.remove(&victim);
                }
            }
            let stat = det.ips.entry(ip.to_string()).or_default();

            // H1 — per-IP submit token bucket.
            let b = stat.bucket.get_or_insert(RateBucket { tokens: H1_BUCKET_CAP, last: now });
            let dt = now.duration_since(b.last).as_secs_f64();
            b.last = now;
            b.tokens = (b.tokens + dt * H1_REFILL_PER_S).min(H1_BUCKET_CAP);
            if b.tokens >= 1.0 {
                b.tokens -= 1.0;
            } else {
                trips.push(("H1".into(), format!("submit-rate: ip exceeded {H1_BUCKET_CAP:.0}-burst @ {H1_REFILL_PER_S}/s token bucket"), "med".into(), json!({ "func": func })));
            }

            // H2 — repeated identical (func, sig) submissions per ip in the window.
            let q = stat.sigs.entry(submit_sig.to_string()).or_default();
            q.push_back(now);
            prune_window(q, now);
            let sig_count = q.len() as u64;
            if sig_count > H2_IDENTICAL_MAX {
                trips.push(("H2".into(), format!("repeat-signature: {func} x{sig_count} in 5m — mining shape (sig {})", &submit_sig[..submit_sig.len().min(8)]), "high".into(), json!({ "func": func, "count": sig_count, "sig": submit_sig })));
            }

            // H4 — same raw module sha256 submitted >N times per ip in the window.
            if let Some(msha) = module_sha {
                let mq = stat.modules.entry(msha.to_string()).or_default();
                mq.push_back(now);
                prune_window(mq, now);
                let mod_count = mq.len() as u64;
                if mod_count > H4_MODULE_MAX {
                    trips.push(("H4".into(), format!("module-fanout: same wasm module x{mod_count} in 5m (mod {})", &msha[..msha.len().min(8)]), "high".into(), json!({ "module_sha": msha, "count": mod_count })));
                }
            }

            // H5 — one ip touching >N distinct nodes AND >M tasks in the window.
            stat.nodes.insert(node_id.to_string(), now);
            stat.nodes.retain(|_, t| now.duration_since(*t) <= DETECT_WINDOW);
            stat.submits.push_back(now);
            prune_window(&mut stat.submits, now);
            let distinct_nodes = stat.nodes.len();
            let task_count = stat.submits.len();
            if distinct_nodes > H5_DISTINCT_NODES && task_count > H5_TASK_COUNT {
                trips.push(("H5".into(), format!("fan-out: ip hit {distinct_nodes} distinct nodes with {task_count} tasks in 5m"), "med".into(), json!({ "distinct_nodes": distinct_nodes, "tasks": task_count })));
            }
        }
        trips.into_iter().filter_map(|(h, reason, sev, sample)| self.raise(node_id, ip, &h, &reason, &sev, sample)).collect()
    }

    /// H3 rolling-median latency for one runtime sample.
    pub fn runtime(&self, ip: &str, node_id: &str, ms: f64) -> Vec<FlagEvent> {
        if !(ms.is_finite() && ms > 0.0) {
            return Vec::new();
        }
        let (median, runs) = {
            let mut det = self.state.lock().unwrap();
            let stat = det.ips.entry(ip.to_string()).or_default();
            stat.ms_samples.push_back(ms);
            while stat.ms_samples.len() > DETECT_MS_SAMPLES {
                stat.ms_samples.pop_front();
            }
            let runs = stat.submits.len().max(stat.ms_samples.len());
            let mut sorted: Vec<f64> = stat.ms_samples.iter().copied().collect();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let median = if sorted.is_empty() { 0.0 } else { sorted[sorted.len() / 2] };
            (median, runs)
        };
        if median > H3_MEDIAN_MS && runs > H3_MIN_RUNS {
            self.raise(node_id, ip, "H3", &format!("long-jobs: rolling median {median:.0}ms over {runs} runs/5m — sustained heavy compute"), "low", json!({ "median_ms": median, "runs": runs })).into_iter().collect()
        } else {
            Vec::new()
        }
    }

    /// Arm/disarm a node's H6 in-flight gauge when pending crosses its core count.
    pub fn gauge_inc(&self, node_id: &str, cores: u32) {
        let mut det = self.state.lock().unwrap();
        let g = det.gauges.entry(node_id.to_string()).or_default();
        g.cores = cores;
        g.pending = g.pending.saturating_add(1);
        if g.pending > g.cores as u64 {
            if g.over_since.is_none() {
                g.over_since = Some(Instant::now());
            }
        } else {
            g.over_since = None;
        }
    }

    pub fn gauge_dec(&self, node_id: &str) {
        let mut det = self.state.lock().unwrap();
        if let Some(g) = det.gauges.get_mut(node_id) {
            g.pending = g.pending.saturating_sub(1);
            if g.pending <= g.cores as u64 {
                g.over_since = None;
            }
        }
    }

    /// H6 sweep — flag nodes whose pending has exceeded cores for too long. Called on a timer.
    pub fn sweep_h6(&self) -> Vec<FlagEvent> {
        let now = Instant::now();
        let trips: Vec<(String, u64, u32, u64)> = {
            let det = self.state.lock().unwrap();
            det.gauges
                .iter()
                .filter_map(|(id, g)| {
                    g.over_since.and_then(|since| {
                        let over = now.duration_since(since).as_secs();
                        (over >= H6_PENDING_SECS).then(|| (id.clone(), g.pending, g.cores, over))
                    })
                })
                .collect()
        };
        trips
            .into_iter()
            .filter_map(|(id, pending, cores, over)| {
                self.raise(&id, "", "H6", &format!("overloaded-node: pending {pending} > {cores} cores for {over}s — saturated/stuck"), "med", json!({ "pending": pending, "cores": cores, "over_secs": over }))
            })
            .collect()
    }

    /// Build a FlagEvent unless this (ip, heuristic) was raised within FLAG_THROTTLE.
    fn raise(&self, node_id: &str, ip: &str, heuristic: &str, reason: &str, severity: &str, sample: Value) -> Option<FlagEvent> {
        {
            let mut thr = self.throttle.lock().unwrap();
            let now = Instant::now();
            thr.retain(|_, t| now.duration_since(*t) <= FLAG_THROTTLE * 4);
            let key = (ip.to_string(), heuristic.to_string());
            if let Some(last) = thr.get(&key) {
                if now.duration_since(*last) < FLAG_THROTTLE {
                    return None;
                }
            }
            thr.insert(key, now);
        }
        let resolved_node = if node_id.is_empty() { format!("ip:{ip}") } else { node_id.to_string() };
        Some(FlagEvent {
            ts: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
            node_id: resolved_node,
            ip: ip.to_string(),
            heuristic: heuristic.to_string(),
            reason: reason.to_string(),
            severity: severity.to_string(),
            sample,
        })
    }
}
