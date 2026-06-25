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

use crate::store::{FlagEvent, Store};

/// The topic every flag is published on. The hub sends with this exact topic; we filter on it.
pub const FLAG_TOPIC: &str = "ce-monitor/flag";

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
    /// Authorized hub flag on the flag topic, deserialized and appended to the store.
    Stored,
    /// Topic was not [`FLAG_TOPIC`] — ignored.
    WrongTopic,
    /// Sender NodeId was not the configured hub — rejected (unauthorized).
    Unauthorized,
    /// Payload was not a valid [`FlagEvent`] JSON — dropped.
    BadPayload,
}

/// The receive/authorize/store core. Holds the [`Store`] and the single authorized sender (the
/// hub's NodeId). Pure of any transport so it can be exercised with injected messages.
pub struct MeshIngest {
    store: Arc<Store>,
    /// The ONLY NodeId whose flags are accepted (the hub's). Empty => accept none (fail closed).
    hub_node: String,
}

impl MeshIngest {
    /// Build an ingest core that admits flags only from `hub_node` (the hub's NodeId hex).
    pub fn new(store: Arc<Store>, hub_node: String) -> Self {
        Self { store, hub_node }
    }

    /// Receive one inbound message: filter topic, authorize by sender NodeId, deserialize, store.
    ///
    /// Returns the verdict. Only [`Ingested::Stored`] mutates the store. Authorization is strict:
    /// an unset/empty `hub_node` accepts nothing (fail closed).
    pub fn handle(&self, msg: &InboundMessage) -> Ingested {
        if msg.topic != FLAG_TOPIC {
            return Ingested::WrongTopic;
        }
        // AUTHORIZE BY SENDER: the node proved `msg.from`; only the hub may push flags.
        if self.hub_node.is_empty() || msg.from != self.hub_node {
            tracing::warn!(
                from = %msg.from,
                "ce-monitor: dropping flag from unauthorized sender (not the configured hub node)"
            );
            return Ingested::Unauthorized;
        }
        let event: FlagEvent = match serde_json::from_slice(&msg.payload) {
            Ok(ev) => ev,
            Err(e) => {
                tracing::warn!(error = %e, "ce-monitor: dropping flag with undeserializable payload");
                return Ingested::BadPayload;
            }
        };
        match self.store.append(event) {
            Ok(seq) => {
                tracing::info!(seq, from = %msg.from, "ce-monitor: stored mesh flag");
                Ingested::Stored
            }
            Err(e) => {
                tracing::error!(error = %e, "ce-monitor: store append failed for mesh flag");
                // Append failure is a storage fault, not a policy outcome; surface as BadPayload so
                // the caller does not treat it as stored. (The flag is lost; logged loudly above.)
                Ingested::BadPayload
            }
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
                tracing::info!(node_url = %ce.base_url(), topic = FLAG_TOPIC, "ce-monitor mesh inbox up");
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

    fn flag_json() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "ts": 1_700_000_000u64,
            "node_id": "ip:203.0.113.7",
            "ip": "203.0.113.7",
            "heuristic": "H2",
            "reason": "repeat-signature: count_primes x47 in 5m",
            "severity": "high",
            "sample": { "func": "count_primes" }
        }))
        .unwrap()
    }

    fn msg(from: &str, topic: &str, payload: Vec<u8>) -> InboundMessage {
        InboundMessage { from: from.into(), topic: topic.into(), payload }
    }

    /// A flag from the configured hub NodeId on the flag topic is admitted and stored.
    #[test]
    fn hub_sender_admits_and_stores() {
        let dir = temp_dir();
        let store = Arc::new(Store::open(dir.clone()).unwrap());
        let ingest = MeshIngest::new(store.clone(), HUB.to_string());

        let verdict = ingest.handle(&msg(HUB, FLAG_TOPIC, flag_json()));
        assert_eq!(verdict, Ingested::Stored);

        // The flag actually landed in the store.
        assert_eq!(store.head_seq(), 1);
        let flags = store.query(None, None, None, None, 10);
        assert_eq!(flags.len(), 1);
        assert_eq!(flags[0].event.heuristic, "H2");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A flag from any sender that is NOT the configured hub is rejected and NOT stored.
    #[test]
    fn non_hub_sender_rejected() {
        let dir = temp_dir();
        let store = Arc::new(Store::open(dir.clone()).unwrap());
        let ingest = MeshIngest::new(store.clone(), HUB.to_string());

        let verdict = ingest.handle(&msg(OTHER, FLAG_TOPIC, flag_json()));
        assert_eq!(verdict, Ingested::Unauthorized);
        assert_eq!(store.head_seq(), 0, "an unauthorized sender must not store anything");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With no configured hub node (empty), nothing is accepted (fail closed) even on the right topic.
    #[test]
    fn empty_hub_node_accepts_nothing() {
        let dir = temp_dir();
        let store = Arc::new(Store::open(dir.clone()).unwrap());
        let ingest = MeshIngest::new(store.clone(), String::new());

        let verdict = ingest.handle(&msg(HUB, FLAG_TOPIC, flag_json()));
        assert_eq!(verdict, Ingested::Unauthorized);
        assert_eq!(store.head_seq(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A message on a different topic is ignored (even from the hub) and not stored.
    #[test]
    fn wrong_topic_ignored() {
        let dir = temp_dir();
        let store = Arc::new(Store::open(dir.clone()).unwrap());
        let ingest = MeshIngest::new(store.clone(), HUB.to_string());

        let verdict = ingest.handle(&msg(HUB, "ce-monitor/other", flag_json()));
        assert_eq!(verdict, Ingested::WrongTopic);
        assert_eq!(store.head_seq(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A hub message whose payload is not valid FlagEvent JSON is dropped, not stored.
    #[test]
    fn bad_payload_dropped() {
        let dir = temp_dir();
        let store = Arc::new(Store::open(dir.clone()).unwrap());
        let ingest = MeshIngest::new(store.clone(), HUB.to_string());

        let verdict = ingest.handle(&msg(HUB, FLAG_TOPIC, b"not json".to_vec()));
        assert_eq!(verdict, Ingested::BadPayload);
        assert_eq!(store.head_seq(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Draining a mixed batch of injected messages stores exactly the authorized hub flags.
    #[test]
    fn injected_source_drains_only_authorized() {
        let dir = temp_dir();
        let store = Arc::new(Store::open(dir.clone()).unwrap());
        let ingest = MeshIngest::new(store.clone(), HUB.to_string());

        // An injected message source: a plain vec the test feeds through the ingest core, exactly as
        // the live loop feeds the SSE stream. No live node required.
        let source = vec![
            msg(HUB, FLAG_TOPIC, flag_json()),       // stored
            msg(OTHER, FLAG_TOPIC, flag_json()),     // unauthorized
            msg(HUB, "ce-monitor/other", flag_json()), // wrong topic
            msg(HUB, FLAG_TOPIC, b"{".to_vec()),     // bad payload
            msg(HUB, FLAG_TOPIC, flag_json()),       // stored
        ];
        let mut stored = 0;
        for m in &source {
            if ingest.handle(m) == Ingested::Stored {
                stored += 1;
            }
        }
        assert_eq!(stored, 2);
        assert_eq!(store.head_seq(), 2, "only the two authorized hub flags are stored");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The `From<AppMessage>` bridge carries through `from`/`topic` and hex-decodes the payload.
    #[test]
    fn app_message_bridge_decodes() {
        let am: ce_rs::AppMessage = serde_json::from_value(serde_json::json!({
            "from": HUB,
            "topic": FLAG_TOPIC,
            "payload_hex": hex::encode(flag_json()),
            "received_at": 1u64,
        }))
        .unwrap();
        let inbound = InboundMessage::from(am);
        assert_eq!(inbound.from, HUB);
        assert_eq!(inbound.topic, FLAG_TOPIC);
        let ev: FlagEvent = serde_json::from_slice(&inbound.payload).unwrap();
        assert_eq!(ev.heuristic, "H2");
    }
}
