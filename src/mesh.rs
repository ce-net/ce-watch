//! Mesh flag ingest — the real CE mesh receiver that replaces the old `POST /ingest` HTTP cheat.
//!
//! ce-monitor attaches to its co-located `ce` node over `ce-rs` (`CeClient` at `CE_NODE_URL`, default
//! `http://127.0.0.1:8844`) and drains the node's inbound app-message stream
//! (`CeClient::messages_stream` -> `GET /mesh/messages/stream`). Each incoming [`ce_rs::AppMessage`]
//! arrives tagged with a **Noise-authenticated sender NodeId** (`msg.from`), which the local node
//! verified — that replaces the deleted `x-ce-monitor-token` shared secret entirely.
//!
//! Authorization is **by sender**: we accept a flag only when `msg.from == CE_MONITOR_HUB_NODE` (the
//! hub's NodeId) and `msg.topic == "ce-monitor/flag"`. Anything else — wrong sender, wrong topic, or
//! an undeserializable payload — is dropped. Admitted flags go straight to the existing [`Store`].
//!
//! The receive/authorize/store core ([`MeshIngest::handle`]) is split from the transport so it can
//! be unit-tested with an injected message source; the live loop ([`run`]) wires it to the node's
//! SSE stream and retries (it never crashes the console if the node is briefly unreachable).

use std::sync::Arc;
use std::time::Duration;

use crate::detect::Detector;
use crate::store::Store;

/// The topic the hub emits raw abuse-observations on. ce-monitor runs the detector on them (the hub no
/// longer detects — it only tracks). We filter our mesh inbox on this exact string.
pub const OBSERVE_TOPIC: &str = "ce-monitor/observe";

/// One raw observation from ce-hub: a dispatched task (`submit`), a result (`runtime`), or a per-node
/// in-flight gauge delta (`gauge_inc`/`gauge_dec`). The detector turns these into FlagEvents.
#[derive(serde::Deserialize)]
#[serde(tag = "kind")]
enum Observation {
    #[serde(rename = "submit")]
    Submit { ip: String, func: String, submit_sig: String, #[serde(default)] module_sha: Option<String>, node: String },
    #[serde(rename = "runtime")]
    Runtime { ip: String, node: String, ms: f64 },
    #[serde(rename = "gauge_inc")]
    GaugeInc { node: String, #[serde(default)] cores: u32 },
    #[serde(rename = "gauge_dec")]
    GaugeDec { node: String },
}

/// Default ce node API base URL when `CE_NODE_URL` is unset — the co-located local node.
pub const DEFAULT_CE_NODE_URL: &str = "http://127.0.0.1:8844";

/// A minimal view of an inbound mesh app-message: the authenticated sender NodeId, the topic, and
/// the raw payload bytes. Mirrors the load-bearing fields of [`ce_rs::AppMessage`] so the ingest
/// core can be unit-tested with synthetic messages (no live node, no SSE).
#[derive(Debug, Clone)]
pub struct InboundMessage {
    /// Authenticated sender NodeId (hex) — the local node verified the libp2p sender's signature.
    pub from: String,
    /// App-chosen topic namespace.
    pub topic: String,
    /// Raw payload bytes (the FlagEvent JSON).
    pub payload: Vec<u8>,
}

impl From<ce_rs::AppMessage> for InboundMessage {
    fn from(m: ce_rs::AppMessage) -> Self {
        // payload() hex-decodes; on a bad-hex node bug we fall back to empty bytes, which the ingest
        // core then rejects as an undeserializable payload (dropped, never stored).
        let payload = m.payload().unwrap_or_default();
        InboundMessage { from: m.from, topic: m.topic, payload }
    }
}

/// The verdict of attempting to ingest one inbound message — used by tests to assert the policy.
#[derive(Debug, PartialEq, Eq)]
pub enum Ingested {
    /// Authorized hub observation processed by the detector (any resulting flags were stored).
    Stored,
    /// Topic was not [`OBSERVE_TOPIC`] — ignored.
    WrongTopic,
    /// Sender NodeId was not the configured hub — rejected (unauthorized).
    Unauthorized,
    /// Payload was not a valid [`Observation`] JSON — dropped.
    BadPayload,
}

/// The receive/authorize/detect core. Holds the [`Store`], the [`Detector`], and the single authorized
/// sender (the hub's NodeId). Pure of any transport so it can be exercised with injected messages.
pub struct MeshIngest {
    store: Arc<Store>,
    detector: Arc<Detector>,
    /// The ONLY NodeId whose observations are accepted (the hub's). Empty => accept none (fail closed).
    hub_node: String,
}

impl MeshIngest {
    /// Build an ingest core that admits observations only from `hub_node` (the hub's NodeId hex).
    pub fn new(store: Arc<Store>, detector: Arc<Detector>, hub_node: String) -> Self {
        Self { store, detector, hub_node }
    }

    /// Receive one inbound message: filter topic, authorize by sender NodeId, deserialize the
    /// observation, run the detector, and append any resulting flags. Authorization is strict: an
    /// unset/empty `hub_node` accepts nothing (fail closed).
    pub fn handle(&self, msg: &InboundMessage) -> Ingested {
        if msg.topic != OBSERVE_TOPIC {
            return Ingested::WrongTopic;
        }
        if self.hub_node.is_empty() || msg.from != self.hub_node {
            tracing::warn!(from = %msg.from, "ce-monitor: dropping observation from unauthorized sender");
            return Ingested::Unauthorized;
        }
        let obs: Observation = match serde_json::from_slice(&msg.payload) {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(error = %e, "ce-monitor: dropping observation with undeserializable payload");
                return Ingested::BadPayload;
            }
        };
        let flags = match obs {
            Observation::Submit { ip, func, submit_sig, module_sha, node } => {
                self.detector.submit(&ip, &func, &submit_sig, module_sha.as_deref(), &node)
            }
            Observation::Runtime { ip, node, ms } => self.detector.runtime(&ip, &node, ms),
            Observation::GaugeInc { node, cores } => {
                self.detector.gauge_inc(&node, cores);
                Vec::new()
            }
            Observation::GaugeDec { node } => {
                self.detector.gauge_dec(&node);
                Vec::new()
            }
        };
        for ev in flags {
            if let Err(e) = self.store.append(ev) {
                tracing::error!(error = %e, "ce-monitor: store append failed for detector flag");
            }
        }
        Ingested::Stored
    }

    /// Run the H6 sweep (called on a timer) and store any flags it raises.
    pub fn sweep(&self) {
        for ev in self.detector.sweep_h6() {
            let _ = self.store.append(ev);
        }
    }
}

/// Resolve the ce node API base URL from `CE_NODE_URL`, falling back to [`DEFAULT_CE_NODE_URL`].
pub fn ce_node_url() -> String {
    std::env::var("CE_NODE_URL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_CE_NODE_URL.to_string())
}

/// Resolve the hub's authorized NodeId from `CE_MONITOR_HUB_NODE`. Empty (unset) => accept no flags.
pub fn hub_node() -> String {
    std::env::var("CE_MONITOR_HUB_NODE").unwrap_or_default()
}

/// Run the live mesh receiver forever: open the node's app-message SSE stream and feed every message
/// through `ingest`. Reconnects with a fixed backoff; if the local node is unreachable it logs a
/// warning and retries (it NEVER crashes the console). Spawn this as a background task at startup.
///
/// Takes the shared [`ce_rs::CeClient`] (the one attachment to the co-located node) so the flag
/// receiver and the ce-auth relying-party verifier ride the same node.
pub async fn run(ce: ce_rs::CeClient, ingest: Arc<MeshIngest>) {
    use futures_util::StreamExt as _;

    let mut backoff = Duration::from_millis(500);
    loop {
        match ce.messages_stream().await {
            Ok(stream) => {
                tracing::info!(node_url = %ce.base_url(), topic = OBSERVE_TOPIC, "ce-monitor mesh inbox up");
                backoff = Duration::from_millis(500);
                let mut stream = std::pin::pin!(stream);
                while let Some(item) = stream.next().await {
                    match item {
                        Ok(m) => {
                            let _ = ingest.handle(&InboundMessage::from(m));
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "ce-monitor mesh stream error; reconnecting");
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    node_url = %ce.base_url(),
                    "ce-monitor: local ce node unreachable; retrying mesh inbox"
                );
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> std::path::PathBuf {
        let mut d = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        d.push(format!("ce-monitor-mesh-test-{}-{}", std::process::id(), nanos));
        d
    }

    const HUB: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const OTHER: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    /// A `submit` observation re-using one wasm module hash — repeat it >8 times to trip H4.
    fn submit_obs(module: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "kind": "submit",
            "ip": "203.0.113.7",
            "func": "count_primes",
            "submit_sig": "deadbeefcafef00d",
            "module_sha": module,
            "node": "node-a",
        }))
        .unwrap()
    }

    fn ingest_for(store: &Arc<Store>, hub: &str) -> MeshIngest {
        MeshIngest::new(store.clone(), Arc::new(Detector::new()), hub.to_string())
    }

    fn msg(from: &str, topic: &str, payload: Vec<u8>) -> InboundMessage {
        InboundMessage { from: from.into(), topic: topic.into(), payload }
    }

    /// Authorized submit observations from the hub run the detector; repeated module fan-out trips H4
    /// and the resulting flag lands in the store.
    #[test]
    fn hub_observations_trip_h4_and_store() {
        let dir = temp_dir();
        let store = Arc::new(Store::open(dir.clone()).unwrap());
        let ingest = ingest_for(&store, HUB);

        for _ in 0..9 {
            assert_eq!(ingest.handle(&msg(HUB, OBSERVE_TOPIC, submit_obs("abcd1234"))), Ingested::Stored);
        }
        // H4 (module fan-out) tripped once; the throttle collapses repeats to a single flag.
        assert!(store.head_seq() >= 1, "module fan-out must raise at least one flag");
        let flags = store.query(None, None, None, None, 10);
        assert!(flags.iter().any(|f| f.event.heuristic == "H4"), "expected an H4 flag");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An observation from any sender that is NOT the configured hub is rejected and not processed.
    #[test]
    fn non_hub_sender_rejected() {
        let dir = temp_dir();
        let store = Arc::new(Store::open(dir.clone()).unwrap());
        let ingest = ingest_for(&store, HUB);

        assert_eq!(ingest.handle(&msg(OTHER, OBSERVE_TOPIC, submit_obs("abcd1234"))), Ingested::Unauthorized);
        assert_eq!(store.head_seq(), 0, "an unauthorized sender must not store anything");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With no configured hub node (empty), nothing is accepted (fail closed) even on the right topic.
    #[test]
    fn empty_hub_node_accepts_nothing() {
        let dir = temp_dir();
        let store = Arc::new(Store::open(dir.clone()).unwrap());
        let ingest = ingest_for(&store, "");

        assert_eq!(ingest.handle(&msg(HUB, OBSERVE_TOPIC, submit_obs("abcd1234"))), Ingested::Unauthorized);
        assert_eq!(store.head_seq(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A message on a different topic is ignored (even from the hub).
    #[test]
    fn wrong_topic_ignored() {
        let dir = temp_dir();
        let store = Arc::new(Store::open(dir.clone()).unwrap());
        let ingest = ingest_for(&store, HUB);

        assert_eq!(ingest.handle(&msg(HUB, "ce-monitor/other", submit_obs("abcd1234"))), Ingested::WrongTopic);
        assert_eq!(store.head_seq(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A hub message whose payload is not a valid Observation is dropped, not processed.
    #[test]
    fn bad_payload_dropped() {
        let dir = temp_dir();
        let store = Arc::new(Store::open(dir.clone()).unwrap());
        let ingest = ingest_for(&store, HUB);

        assert_eq!(ingest.handle(&msg(HUB, OBSERVE_TOPIC, b"not json".to_vec())), Ingested::BadPayload);
        assert_eq!(store.head_seq(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The `From<AppMessage>` bridge carries through `from`/`topic` and hex-decodes the payload.
    #[test]
    fn app_message_bridge_decodes() {
        let am: ce_rs::AppMessage = serde_json::from_value(serde_json::json!({
            "from": HUB,
            "topic": OBSERVE_TOPIC,
            "payload_hex": hex::encode(submit_obs("abcd1234")),
            "received_at": 1u64,
        }))
        .unwrap();
        let inbound = InboundMessage::from(am);
        assert_eq!(inbound.from, HUB);
        assert_eq!(inbound.topic, OBSERVE_TOPIC);
        assert!(!inbound.payload.is_empty());
    }
}
