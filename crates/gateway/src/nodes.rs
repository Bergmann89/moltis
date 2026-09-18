use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use tracing::warn;

use crate::{
    broadcast::{BroadcastOpts, broadcast},
    state::GatewayState,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("node not found")]
    NodeNotFound,
}

pub type Result<T> = std::result::Result<T, Error>;

/// A provider discovered on a remote node.
#[derive(Debug, Clone)]
pub struct NodeProviderEntry {
    pub provider: String,
    pub models: Vec<String>,
}

/// A connected device node (macOS, iOS, Android).
#[derive(Debug, Clone)]
pub struct NodeSession {
    pub node_id: String,
    pub conn_id: String,
    pub display_name: Option<String>,
    pub platform: String,
    pub version: String,
    pub capabilities: Vec<String>,
    pub commands: Vec<String>,
    pub permissions: HashMap<String, bool>,
    pub path_env: Option<String>,
    pub remote_ip: Option<String>,
    pub connected_at: Instant,
    // ── Telemetry fields (updated by node.telemetry events) ──────────
    pub mem_total: Option<u64>,
    pub mem_available: Option<u64>,
    pub cpu_count: Option<u32>,
    pub cpu_usage: Option<f32>,
    pub uptime_secs: Option<u64>,
    pub services: Vec<String>,
    pub last_telemetry: Option<Instant>,
    // ── Extended telemetry (P1) ──────────────────────────────────────
    pub disk_total: Option<u64>,
    pub disk_available: Option<u64>,
    pub runtimes: Vec<String>,
    // ── Provider discovery (P1) ─────────────────────────────────────
    pub providers: Vec<NodeProviderEntry>,
}

impl NodeSession {
    /// The last moment this node gave any sign of life.
    ///
    /// `connected_at` is the floor: `last_telemetry` is `None` until the first
    /// report and the node skips its first tick, so before that the connection
    /// itself is the proof the node is there.
    pub fn last_seen(&self) -> Instant {
        match self.last_telemetry {
            Some(telemetry) => telemetry.max(self.connected_at),
            None => self.connected_at,
        }
    }
}

/// Registry of connected device nodes and their capabilities.
pub struct NodeRegistry {
    /// node_id → NodeSession
    nodes: HashMap<String, NodeSession>,
    /// conn_id → node_id (reverse lookup for cleanup on disconnect)
    by_conn: HashMap<String, String>,
}

impl Default for NodeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeRegistry {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            by_conn: HashMap::new(),
        }
    }

    /// Register a node session, replacing any previous session for the same node.
    ///
    /// A reconnecting node arrives on a fresh connection while the stale one may
    /// still be in the map, so the previous `by_conn` entry pointing at this
    /// `node_id` is evicted here rather than left behind to be cleaned up by a
    /// later disconnect of the dead connection.
    pub fn register(&mut self, session: NodeSession) {
        if let Some(previous) = self.nodes.get(&session.node_id)
            && previous.conn_id != session.conn_id
        {
            self.by_conn.remove(&previous.conn_id);
        }
        self.by_conn
            .insert(session.conn_id.clone(), session.node_id.clone());
        self.nodes.insert(session.node_id.clone(), session);
    }

    /// Remove the session owned by `conn_id`, if that connection still owns it.
    ///
    /// Returns `None` when the connection is stale - i.e. the node has since
    /// reconnected on another connection - so a late disconnect of the dead
    /// connection can never tear down the healthy session.
    pub fn unregister_by_conn(&mut self, conn_id: &str) -> Option<NodeSession> {
        let node_id = self.by_conn.remove(conn_id)?;
        match self.nodes.get(&node_id) {
            Some(session) if session.conn_id == conn_id => self.nodes.remove(&node_id),
            _ => None,
        }
    }

    pub fn get(&self, node_id: &str) -> Option<&NodeSession> {
        self.nodes.get(node_id)
    }

    pub fn get_mut(&mut self, node_id: &str) -> Option<&mut NodeSession> {
        self.nodes.get_mut(node_id)
    }

    pub fn list(&self) -> Vec<&NodeSession> {
        self.nodes.values().collect()
    }

    pub fn has_mobile_node(&self) -> bool {
        self.nodes
            .values()
            .any(|n| n.platform == "ios" || n.platform == "android")
    }

    pub fn rename(&mut self, node_id: &str, display_name: &str) -> Result<()> {
        let node = self.nodes.get_mut(node_id).ok_or(Error::NodeNotFound)?;
        node.display_name = Some(display_name.to_string());
        Ok(())
    }

    /// Update telemetry data for a node.
    pub fn update_telemetry(
        &mut self,
        node_id: &str,
        mem_total: Option<u64>,
        mem_available: Option<u64>,
        cpu_count: Option<u32>,
        cpu_usage: Option<f32>,
        uptime_secs: Option<u64>,
        services: Vec<String>,
        disk_total: Option<u64>,
        disk_available: Option<u64>,
        runtimes: Vec<String>,
    ) -> Result<()> {
        let node = self.nodes.get_mut(node_id).ok_or(Error::NodeNotFound)?;
        node.mem_total = mem_total;
        node.mem_available = mem_available;
        node.cpu_count = cpu_count;
        node.cpu_usage = cpu_usage;
        node.uptime_secs = uptime_secs;
        node.services = services;
        node.disk_total = disk_total;
        node.disk_available = disk_available;
        node.runtimes = runtimes;
        node.last_telemetry = Some(Instant::now());
        Ok(())
    }

    /// Remove all nodes (used when disconnecting all clients).
    pub fn clear(&mut self) {
        self.nodes.clear();
        self.by_conn.clear();
    }

    pub fn count(&self) -> usize {
        self.nodes.len()
    }

    /// Remove every node that has shown no sign of life for `max_idle`.
    ///
    /// Staleness is measured from [`NodeSession::last_seen`], so a node that
    /// connected and has not reported yet is spared while one that connected
    /// and then went quiet is not.  Both maps are cleared, and `by_conn` only
    /// for the connection the removed session actually owns.
    pub fn reap_stale(&mut self, max_idle: Duration) -> Vec<NodeSession> {
        let now = Instant::now();
        let stale: Vec<String> = self
            .nodes
            .values()
            .filter(|session| now.duration_since(session.last_seen()) > max_idle)
            .map(|session| session.node_id.clone())
            .collect();

        stale
            .into_iter()
            .filter_map(|node_id| {
                let session = self.nodes.remove(&node_id)?;
                self.by_conn.remove(&session.conn_id);
                Some(session)
            })
            .collect()
    }
}

// ── Presence reaper ─────────────────────────────────────────────────────────

/// How long a node may go without any sign of life before it is unregistered.
pub const NODE_STALE_AFTER: Duration = Duration::from_secs(70);

/// How often the reaper looks for stale nodes.
pub const NODE_REAPER_INTERVAL: Duration = Duration::from_secs(10);

/// Reap stale nodes once and announce every node that went away.
pub async fn reap_stale_nodes_once(state: &Arc<GatewayState>, max_idle: Duration) -> usize {
    let reaped = state.reap_stale_nodes(max_idle).await;
    for session in &reaped {
        warn!(
            node_id = %session.node_id,
            conn_id = %session.conn_id,
            "node reaped: no sign of life",
        );
        broadcast(
            state,
            "presence",
            serde_json::json!({
                "type": "node.disconnected",
                "nodeId": session.node_id,
            }),
            BroadcastOpts::default(),
        )
        .await;
    }
    reaped.len()
}

/// Background loop that keeps the registry honest about which nodes are there.
pub async fn run_node_reaper(state: Arc<GatewayState>) {
    let mut interval = tokio::time::interval(NODE_REAPER_INTERVAL);
    loop {
        interval.tick().await;
        reap_stale_nodes_once(&state, NODE_STALE_AFTER).await;
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn session(node_id: &str, conn_id: &str) -> NodeSession {
        NodeSession {
            node_id: node_id.to_string(),
            conn_id: conn_id.to_string(),
            display_name: None,
            platform: "linux".to_string(),
            version: "0.0.0".to_string(),
            capabilities: Vec::new(),
            commands: Vec::new(),
            permissions: HashMap::new(),
            path_env: None,
            remote_ip: None,
            connected_at: Instant::now(),
            mem_total: None,
            mem_available: None,
            cpu_count: None,
            cpu_usage: None,
            uptime_secs: None,
            services: Vec::new(),
            last_telemetry: None,
            disk_total: None,
            disk_available: None,
            runtimes: Vec::new(),
            providers: Vec::new(),
        }
    }

    fn aged_session(node_id: &str, conn_id: &str, age: Duration) -> NodeSession {
        let mut session = session(node_id, conn_id);
        session.connected_at = Instant::now()
            .checked_sub(age)
            .expect("the test clock must reach back that far");
        session
    }

    #[test]
    fn reap_stale_removes_a_silent_node_from_both_maps() {
        let mut registry = NodeRegistry::new();
        let mut node = aged_session("node-x", "conn-1", Duration::from_secs(600));
        node.last_telemetry = Instant::now().checked_sub(Duration::from_secs(300));
        registry.register(node);

        let reaped = registry.reap_stale(Duration::from_secs(70));

        assert_eq!(reaped.len(), 1);
        assert_eq!(reaped[0].node_id, "node-x");
        assert!(registry.get("node-x").is_none());
        assert!(
            registry.by_conn.is_empty(),
            "the reaper must clear by_conn too, not leave a dangling entry"
        );
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn reap_stale_spares_a_node_that_has_not_reported_yet() {
        let mut registry = NodeRegistry::new();
        // last_telemetry stays None until the first report, and the node skips
        // its first tick - so a fresh node is live on connected_at alone.
        registry.register(session("node-x", "conn-1"));

        assert!(registry.reap_stale(Duration::from_secs(70)).is_empty());
        assert!(registry.get("node-x").is_some());
        assert_eq!(registry.count(), 1);
    }

    #[test]
    fn reap_stale_uses_the_newer_of_telemetry_and_connect_time() {
        let mut registry = NodeRegistry::new();
        // Reconnected a moment ago, carrying an ancient last_telemetry: the
        // fresh connection is the newer sign of life and must win.
        let mut node = session("node-x", "conn-2");
        node.last_telemetry = Instant::now().checked_sub(Duration::from_secs(600));
        registry.register(node);

        assert!(registry.reap_stale(Duration::from_secs(70)).is_empty());
        assert!(registry.get("node-x").is_some());
    }

    #[test]
    fn reconnect_then_stale_unregister_keeps_the_live_session() {
        let mut registry = NodeRegistry::new();

        registry.register(session("node-x", "conn-1"));
        registry.register(session("node-x", "conn-2"));

        let removed = registry.unregister_by_conn("conn-1");

        assert!(
            removed.is_none(),
            "a stale conn must not report a removal it did not perform"
        );
        assert!(
            registry.get("node-x").is_some(),
            "the live session must survive the stale conn's cleanup"
        );
        assert_eq!(registry.count(), 1);
        assert!(!registry.by_conn.contains_key("conn-1"));
        assert_eq!(
            registry.by_conn.get("conn-2").map(String::as_str),
            Some("node-x")
        );
    }
}
