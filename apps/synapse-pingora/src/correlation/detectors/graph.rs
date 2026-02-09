//! Graph-Based Correlation Detector
//!
//! Maintains a graph of relationships between entities (IPs, fingerprints, tokens, ASNs).
//! Detects campaigns by identifying connected components in the graph.
//!
//! # Graph Structure
//! - **Nodes**: Strings with type prefixes (e.g., "ip:1.2.3.4", "fp:abc", "token:xyz")
//! - **Edges**: Undirected connections representing observed co-occurrence
//!
//! # Detection Logic
//! - Finds connected components of IP addresses linked by shared attributes
//! - Triggers campaign if component size exceeds threshold
//! - Supports depth-limited traversal to limit performance impact

use super::{Detector, DetectorResult};
use crate::correlation::{CampaignUpdate, CorrelationReason, CorrelationType, FingerprintIndex};
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Options for graph export
#[derive(Debug, Clone, Default)]
pub struct GraphExportOptions {
    /// Maximum number of nodes to return (default: 500)
    pub limit: Option<usize>,
    /// Skip this many nodes (for pagination)
    pub offset: Option<usize>,
    /// Hash sensitive identifiers (IPs, tokens) for external exposure
    pub hash_identifiers: bool,
}

/// Paginated graph export result
#[derive(Debug, Clone, serde::Serialize)]
pub struct PaginatedGraph {
    /// Cytoscape-format nodes and edges
    pub nodes: Vec<serde_json::Value>,
    pub edges: Vec<serde_json::Value>,
    /// Total node count (before pagination)
    pub total_nodes: usize,
    /// Whether there are more nodes
    pub has_more: bool,
    /// Snapshot version for consistency checking
    pub snapshot_version: u64,
}

/// Hash an identifier for external exposure
fn hash_identifier(id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(id.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)[..12].to_string() // First 12 hex chars
}

/// Configuration for GraphDetector.
#[derive(Debug, Clone)]
pub struct GraphConfig {
    /// Minimum number of unique IPs in a connected component to trigger detection.
    /// Default: 3
    pub min_component_size: usize,

    /// Maximum depth for graph traversal (BFS).
    /// Default: 3 (e.g., IP -> FP -> IP -> Token -> IP)
    pub max_traversal_depth: usize,

    /// Time window to keep edges alive.
    /// Default: 3600 seconds (1 hour)
    pub edge_ttl: Duration,

    /// Weight of this detector in campaign scoring.
    /// Default: 20
    pub weight: u8,

    /// Maximum number of nodes in the graph to prevent memory exhaustion.
    /// Default: 10,000
    pub max_nodes: usize,

    /// Maximum edges per node to prevent star explosion attacks.
    /// Default: 1,000
    pub max_edges_per_node: usize,

    /// Maximum BFS iterations to prevent CPU exhaustion.
    /// Default: 50,000
    pub max_bfs_iterations: usize,
}

impl Default for GraphConfig {
    fn default() -> Self {
        Self {
            min_component_size: 3,
            max_traversal_depth: 3,
            edge_ttl: Duration::from_secs(3600),
            weight: 20,
            max_nodes: 10_000,
            max_edges_per_node: 1_000,
            max_bfs_iterations: 50_000,
        }
    }
}

/// Node in the correlation graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct GraphNode {
    id: String,
    node_type: NodeType,
    last_seen: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum NodeType {
    Ip,
    Fingerprint,
    Token,
    Asn,
    Other,
}

impl NodeType {
    fn from_id(id: &str) -> Self {
        if id.starts_with("ip:") {
            NodeType::Ip
        } else if id.starts_with("fp:") {
            NodeType::Fingerprint
        } else if id.starts_with("token:") {
            NodeType::Token
        } else if id.starts_with("asn:") {
            NodeType::Asn
        } else {
            NodeType::Other
        }
    }
}

/// Graph-based correlation detector.
pub struct GraphDetector {
    config: GraphConfig,
    /// Adjacency list: Node -> Set of connected Nodes
    /// Stores just string IDs to reduce cloning overhead
    adjacency: DashMap<String, HashSet<String>>,
    /// Node metadata (last seen, type)
    nodes: DashMap<String, GraphNode>,
    /// Last cleanup timestamp
    last_cleanup: std::sync::Mutex<Instant>,
    /// Statistics
    edges_count: AtomicU64,
}

impl GraphDetector {
    pub fn new(config: GraphConfig) -> Self {
        Self {
            config,
            adjacency: DashMap::new(),
            nodes: DashMap::new(),
            last_cleanup: std::sync::Mutex::new(Instant::now()),
            edges_count: AtomicU64::new(0),
        }
    }

    /// Record a relationship between two entities.
    /// e.g., IP "1.2.3.4" used Fingerprint "abc"
    ///
    /// Returns false if graph bounds are exceeded.
    pub fn record_relation(&self, entity_a: &str, entity_b: &str) -> bool {
        if entity_a == entity_b {
            return true;
        }

        let now = Instant::now();

        // Check node count limit before adding new nodes
        let current_node_count = self.nodes.len();
        let is_a_new = !self.nodes.contains_key(entity_a);
        let is_b_new = !self.nodes.contains_key(entity_b);
        let new_nodes_needed = (is_a_new as usize) + (is_b_new as usize);

        if current_node_count + new_nodes_needed > self.config.max_nodes {
            tracing::warn!(
                current = current_node_count,
                max = self.config.max_nodes,
                "Graph node limit reached, skipping relation"
            );
            return false;
        }

        // Update or create nodes using atomic entry API
        self.update_node(entity_a, now);
        self.update_node(entity_b, now);

        // Check edge count limit per node before adding
        let mut edge_added = false;

        // Add edge a -> b (if within limit)
        {
            let mut entry = self.adjacency.entry(entity_a.to_string()).or_default();
            if entry.len() < self.config.max_edges_per_node {
                entry.insert(entity_b.to_string());
                edge_added = true;
            } else {
                tracing::debug!(
                    node = entity_a,
                    edges = entry.len(),
                    "Edge limit reached for node"
                );
            }
        }

        // Add edge b -> a (if within limit)
        {
            let mut entry = self.adjacency.entry(entity_b.to_string()).or_default();
            if entry.len() < self.config.max_edges_per_node {
                entry.insert(entity_a.to_string());
            }
        }

        if edge_added {
            self.edges_count.fetch_add(1, Ordering::Relaxed);
        }

        true
    }

    /// Update or create a node using atomic entry API (fixes race condition).
    fn update_node(&self, id: &str, now: Instant) {
        // Use entry API for atomic update-or-insert (fixes race condition)
        self.nodes
            .entry(id.to_string())
            .and_modify(|node| {
                node.last_seen = now;
            })
            .or_insert_with(|| GraphNode {
                id: id.to_string(),
                node_type: NodeType::from_id(id),
                last_seen: now,
            });
    }

    /// Helpers to format IDs
    pub fn ip_id(ip: &str) -> String {
        format!("ip:{}", ip)
    }
    pub fn fp_id(fp: &str) -> String {
        format!("fp:{}", fp)
    }
    pub fn token_id(token: &str) -> String {
        format!("token:{}", token)
    }
    pub fn asn_id(asn: &str) -> String {
        format!("asn:{}", asn)
    }

    /// BFS to find component
    fn find_connected_ips(&self, start_node: &str) -> HashSet<String> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut ips = HashSet::new();
        let mut iterations: usize = 0;

        queue.push_back((start_node.to_string(), 0));
        visited.insert(start_node.to_string());

        while let Some((current_id, depth)) = queue.pop_front() {
            // Check iteration limit to prevent CPU exhaustion
            iterations += 1;
            if iterations > self.config.max_bfs_iterations {
                tracing::warn!(
                    start = start_node,
                    iterations = iterations,
                    max = self.config.max_bfs_iterations,
                    "BFS iteration limit reached, returning partial result"
                );
                break;
            }

            if depth >= self.config.max_traversal_depth {
                continue;
            }

            // If current node is an IP, add to results
            if NodeType::from_id(&current_id) == NodeType::Ip {
                // Strip prefix
                if let Some(ip) = current_id.strip_prefix("ip:") {
                    ips.insert(ip.to_string());
                }
            }

            // Visit neighbors
            if let Some(neighbors) = self.adjacency.get(&current_id) {
                for neighbor in neighbors.iter() {
                    if !visited.contains(neighbor) {
                        visited.insert(neighbor.clone());
                        queue.push_back((neighbor.clone(), depth + 1));
                    }
                }
            }
        }

        ips
    }

    /// Export graph data for a connected component starting from a given set of IPs.
    /// Legacy method - delegates to get_cytoscape_data_paginated with default options.
    pub fn get_cytoscape_data(&self, ips: &[String]) -> serde_json::Value {
        let result = self.get_cytoscape_data_paginated(ips, GraphExportOptions::default());
        serde_json::json!({
            "nodes": result.nodes,
            "edges": result.edges
        })
    }

    /// Export graph data with pagination and optional identifier hashing.
    /// P1 fix: Adds pagination to prevent unbounded memory usage and
    /// hashes identifiers to prevent information disclosure.
    pub fn get_cytoscape_data_paginated(
        &self,
        ips: &[String],
        options: GraphExportOptions,
    ) -> PaginatedGraph {
        let limit = options.limit.unwrap_or(500);
        let offset = options.offset.unwrap_or(0);
        let hash_ids = options.hash_identifiers;

        let mut all_nodes = Vec::new();
        let mut edges = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        // Start from all campaign IPs
        for ip in ips {
            let id = Self::ip_id(ip);
            if !visited.contains(&id) {
                visited.insert(id.clone());
                queue.push_back((id, 0));
            }
        }

        while let Some((current_id, depth)) = queue.pop_front() {
            // Create display ID (hashed or raw)
            let display_id = if hash_ids {
                let node_type = NodeType::from_id(&current_id);
                let prefix = match node_type {
                    NodeType::Ip => "ip",
                    NodeType::Fingerprint => "fp",
                    NodeType::Token => "tok",
                    NodeType::Asn => "asn",
                    _ => "unk",
                };
                format!("{}:{}", prefix, hash_identifier(&current_id))
            } else {
                current_id.clone()
            };

            // Add node
            let node_type = NodeType::from_id(&current_id);
            all_nodes.push((
                current_id.clone(),
                serde_json::json!({
                    "data": {
                        "id": display_id.clone(),
                        "label": if hash_ids {
                            display_id.split(':').nth(1).unwrap_or(&display_id).to_string()
                        } else {
                            current_id.split(':').nth(1).unwrap_or(&current_id).to_string()
                        },
                        "type": match node_type {
                            NodeType::Ip => "ip",
                            NodeType::Fingerprint => "actor", // Mapping to UI terminology
                            NodeType::Token => "token",
                            NodeType::Asn => "asn",
                            _ => "other",
                        }
                    }
                }),
            ));

            if depth >= self.config.max_traversal_depth {
                continue;
            }

            // Add neighbors and edges
            if let Some(neighbors) = self.adjacency.get(&current_id) {
                for neighbor in neighbors.iter() {
                    // Create display IDs for edge
                    let source_display = if hash_ids {
                        let node_type = NodeType::from_id(&current_id);
                        let prefix = match node_type {
                            NodeType::Ip => "ip",
                            NodeType::Fingerprint => "fp",
                            NodeType::Token => "tok",
                            NodeType::Asn => "asn",
                            _ => "unk",
                        };
                        format!("{}:{}", prefix, hash_identifier(&current_id))
                    } else {
                        current_id.clone()
                    };

                    let target_display = if hash_ids {
                        let node_type = NodeType::from_id(neighbor);
                        let prefix = match node_type {
                            NodeType::Ip => "ip",
                            NodeType::Fingerprint => "fp",
                            NodeType::Token => "tok",
                            NodeType::Asn => "asn",
                            _ => "unk",
                        };
                        format!("{}:{}", prefix, hash_identifier(neighbor))
                    } else {
                        neighbor.clone()
                    };

                    // Always add edge (deduplicated below)
                    let mut edge_ids = [source_display.as_str(), target_display.as_str()];
                    edge_ids.sort();
                    let edge_id = format!("e_{}_{}", edge_ids[0], edge_ids[1]);

                    edges.push(serde_json::json!({
                        "data": {
                            "id": edge_id,
                            "source": source_display,
                            "target": target_display,
                            "label": "linked"
                        }
                    }));

                    if !visited.contains(neighbor) {
                        visited.insert(neighbor.clone());
                        queue.push_back((neighbor.clone(), depth + 1));
                    }
                }
            }
        }

        let total_nodes = all_nodes.len();

        // Apply pagination to nodes
        let paginated_nodes: Vec<serde_json::Value> = all_nodes
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|(_, node)| node)
            .collect();

        // Deduplicate edges
        let mut unique_edges = Vec::new();
        let mut edge_id_set = HashSet::new();
        for edge in edges {
            let id = edge["data"]["id"].as_str().unwrap().to_string();
            if edge_id_set.insert(id) {
                unique_edges.push(edge);
            }
        }

        PaginatedGraph {
            nodes: paginated_nodes,
            edges: unique_edges,
            total_nodes,
            has_more: offset + limit < total_nodes,
            snapshot_version: self.edges_count.load(Ordering::Relaxed),
        }
    }

    /// Clean up old nodes and edges.
    fn cleanup(&self) {
        let now = Instant::now();
        let ttl = self.config.edge_ttl;

        // Remove old nodes
        self.nodes
            .retain(|_, node| now.duration_since(node.last_seen) < ttl);

        // Clean up adjacency list (remove keys that no longer exist in nodes)
        // This is expensive, so it should run infrequently
        self.adjacency.retain(|k, _| self.nodes.contains_key(k));

        // We also need to remove values from the HashSets inside adjacency
        // This requires iterating all values. For performance in this PoC,
        // we might rely on the fact that if A links to B, and B expires,
        // A's link to B becomes a dead end which find_connected_ips handles gracefully
        // (it just won't find B in adjacency or won't find B's neighbors).
        // A complete cleanup would iterate all sets.
    }
}

impl Detector for GraphDetector {
    fn name(&self) -> &'static str {
        "graph_correlation"
    }

    fn analyze(&self, _index: &FingerprintIndex) -> DetectorResult<Vec<CampaignUpdate>> {
        let mut updates = Vec::new();
        let mut processed_ips = HashSet::new();

        // Iterate over all IP nodes to find components
        // We clone the keys to avoid holding locks during traversal
        let ip_nodes: Vec<String> = self
            .nodes
            .iter()
            .filter(|r| r.value().node_type == NodeType::Ip)
            .map(|r| r.key().clone())
            .collect();

        for ip_node in ip_nodes {
            // Skip if already part of a processed component
            // Note: `processed_ips` tracks raw IPs ("1.2.3.4"), `ip_node` is "ip:1.2.3.4"
            let raw_ip = ip_node.strip_prefix("ip:").unwrap_or(&ip_node);
            if processed_ips.contains(raw_ip) {
                continue;
            }

            // BFS to find component
            let component_ips = self.find_connected_ips(&ip_node);

            // Mark all as processed
            for ip in &component_ips {
                processed_ips.insert(ip.clone());
            }

            // Check if component meets threshold
            if component_ips.len() >= self.config.min_component_size {
                let reason = CorrelationReason {
                    correlation_type: CorrelationType::BehavioralSimilarity, // Graph falls under behavioral/structural
                    confidence: 0.9, // High confidence for graph connections
                    evidence: component_ips.into_iter().collect(),
                    description: format!(
                        "Graph correlation: {} IPs connected via shared attributes (depth {})",
                        self.config.min_component_size, self.config.max_traversal_depth
                    ),
                };

                updates.push(CampaignUpdate {
                    campaign_id: None, // New campaign or update existing
                    status: None,
                    risk_score: None,
                    add_correlation_reason: Some(reason),
                    attack_types: Some(vec!["coordinated_botnet".to_string()]),
                    confidence: Some(0.9),
                    add_member_ips: None,
                    increment_requests: None,
                    increment_blocked: None,
                    increment_rules: None,
                });
            }
        }

        // Run cleanup if needed (e.g., every 5 minutes)
        if let Ok(mut last) = self.last_cleanup.try_lock() {
            if last.elapsed() > Duration::from_secs(300) {
                *last = Instant::now();
                // Spawn cleanup to avoid blocking analyze?
                // For safety in this trait method, we'll run it synchronously but it might be slow.
                // In production, use a background task.
                self.cleanup();
            }
        }

        Ok(updates)
    }

    fn should_trigger(&self, _ip: &std::net::IpAddr, _index: &FingerprintIndex) -> bool {
        // Graph updates are implicit via record_relation, this check is less relevant
        // unless we want to do immediate subgraph checks.
        // For now, return false to rely on periodic analyze().
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graph_connection() {
        let detector = GraphDetector::new(GraphConfig::default());

        // Link IP1 -> FP1 -> IP2
        assert!(detector.record_relation(
            &GraphDetector::ip_id("1.1.1.1"),
            &GraphDetector::fp_id("fp_a")
        ));
        assert!(detector.record_relation(
            &GraphDetector::fp_id("fp_a"),
            &GraphDetector::ip_id("2.2.2.2")
        ));

        let ips = detector.find_connected_ips(&GraphDetector::ip_id("1.1.1.1"));
        assert!(ips.contains("1.1.1.1"));
        assert!(ips.contains("2.2.2.2"));
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn test_component_detection() {
        // Chain: IP1 -> FP -> IP2 -> Token -> IP3
        // This requires depth 5 to traverse (0->1->2->3->4)
        let detector = GraphDetector::new(GraphConfig {
            min_component_size: 3,
            max_traversal_depth: 5, // Need depth 5 to reach ip:3
            ..Default::default()
        });

        // Triangle: IP1-FP-IP2, IP2-Token-IP3
        assert!(detector.record_relation("ip:1", "fp:a"));
        assert!(detector.record_relation("fp:a", "ip:2"));
        assert!(detector.record_relation("ip:2", "tok:x"));
        assert!(detector.record_relation("tok:x", "ip:3"));

        let updates = detector.analyze(&FingerprintIndex::new()).unwrap();
        assert_eq!(updates.len(), 1);

        let update = &updates[0];
        let reason = update.add_correlation_reason.as_ref().unwrap();
        assert!(reason.evidence.contains(&"1".to_string()));
        assert!(reason.evidence.contains(&"2".to_string()));
        assert!(reason.evidence.contains(&"3".to_string()));
    }

    #[test]
    fn test_node_limit_enforced() {
        let detector = GraphDetector::new(GraphConfig {
            max_nodes: 5,
            ..Default::default()
        });

        // Add 5 unique nodes (should succeed)
        assert!(detector.record_relation("ip:1", "fp:a")); // 2 nodes
        assert!(detector.record_relation("ip:2", "fp:b")); // 4 nodes
        assert!(detector.record_relation("ip:3", "fp:a")); // 5 nodes (ip:3 is new, fp:a exists)

        // Try to add 2 more new nodes (should fail - would exceed limit)
        assert!(!detector.record_relation("ip:4", "fp:c")); // Would need 2 new nodes

        // But adding a relation between existing nodes should work
        assert!(detector.record_relation("ip:1", "ip:2"));
    }

    #[test]
    fn test_edge_limit_enforced() {
        let detector = GraphDetector::new(GraphConfig {
            max_edges_per_node: 2,
            ..Default::default()
        });

        // Add edges up to limit
        assert!(detector.record_relation("ip:hub", "fp:a"));
        assert!(detector.record_relation("ip:hub", "fp:b"));

        // Third edge should be rejected (but relation still returns true since node exists)
        detector.record_relation("ip:hub", "fp:c");

        // Verify hub only has 2 edges
        let neighbors = detector.adjacency.get("ip:hub").unwrap();
        assert_eq!(neighbors.len(), 2);
    }

    #[test]
    fn test_bfs_iteration_limit() {
        let detector = GraphDetector::new(GraphConfig {
            max_bfs_iterations: 10,
            max_traversal_depth: 100, // High depth to ensure iteration limit is hit
            ..Default::default()
        });

        // Create a chain of nodes
        for i in 0..20 {
            detector.record_relation(&format!("ip:{}", i), &format!("fp:{}", i));
            if i > 0 {
                detector.record_relation(&format!("fp:{}", i), &format!("ip:{}", i - 1));
            }
        }

        // BFS should terminate early
        let ips = detector.find_connected_ips("ip:0");
        // Due to iteration limit, we may not find all IPs
        assert!(
            ips.len() < 20,
            "Should have stopped early due to iteration limit"
        );
    }
}
