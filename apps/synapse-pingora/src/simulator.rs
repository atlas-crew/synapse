//! Procedural traffic simulator for synapse demo mode.
//!
//! # Architecture
//!
//! The simulator runs as a tokio background task that procedurally generates
//! HTTP requests from a small library of "attacker archetypes" (credential
//! stuffer, vulnerability scanner, DLP-leaking insider, noisy benign user)
//! and feeds them through the **real** WAF detection engine and shared
//! managers. The result: horizon's existing admin endpoints — which already
//! poll `EntityManager`, `CampaignManager`, `BlockLog` etc. — see live
//! data populated by simulated traffic, with zero new endpoints and zero
//! horizon changes.
//!
//! # Why not call the full filter chain?
//!
//! `request_filter` in main.rs is bound to Pingora's `Session` and the
//! production socket lifecycle. Faking a session per simulated request
//! works (see `tests/filter_chain_integration.rs`) but it's ~50 lines of
//! plumbing per call. For the demo loop we don't care about the network
//! layer — we just need the engine + the state updates downstream of it.
//! So the simulator calls `DetectionEngine::analyze_with_signals` directly
//! and then mirrors the small set of state-update calls that
//! `request_filter` makes after the analyze (entity touch, campaign
//! register, block log record, external risk on block).
//!
//! If the production state-update set drifts from this list, the demo will
//! silently start showing less data than production. A periodic audit
//! against `request_filter` is the simplest mitigation; longer term we
//! should extract a `process_request_state(request, verdict)` helper that
//! both paths call.
//!
//! # Tick model
//!
//! The loop ticks on a configurable interval (default 200ms). Each tick
//! picks one archetype round-robin and asks it to generate `requests_per_tick`
//! synthetic requests. The archetype owns its own state machine — e.g.
//! the credential stuffer cycles through a fixed pool of source IPs, each
//! using the same JA4 (the giveaway), POSTing varied passwords against
//! `/api/login`. Each request is fed through the engine + state updates.
//!
//! # Resource bounds
//!
//! Per-IP and global caps in `EntityManager`, `Ja4RotationDetector`, and
//! `FingerprintIndex` (TASK-65) bound state growth even if the simulator
//! runs forever. Decay windows in the rotation/velocity detectors mean
//! old simulated events naturally fall off the dashboards as new ones
//! push in, so the loop wraps seamlessly without explicit resets.

use crate::DetectionEngine;
use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use std::sync::Arc;
use std::time::Duration;
use synapse_pingora::block_log::{BlockEvent, BlockLog};
use synapse_pingora::correlation::CampaignManager;
use synapse_pingora::entity::EntityManager;
use synapse_pingora::fingerprint::{generate_ja4h, ClientFingerprint, HttpHeaders};
use synapse_pingora::health::WafStats;
use synapse_pingora::horizon::{HorizonManager, Severity, SignalType, ThreatSignal};
use tokio::task::JoinHandle;
use tracing::{debug, info};

/// A single simulated HTTP request produced by an archetype.
#[derive(Debug, Clone)]
pub struct SyntheticRequest {
    pub method: String,
    pub uri: String,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub body: Option<Bytes>,
    pub source_ip: String,
    /// Optional pre-computed JA4 string (None if archetype is a normal
    /// browser-shaped client). When present this is fed into the engine
    /// as a `ClientFingerprint`.
    pub ja4_raw: Option<String>,
}

/// Trait for procedural traffic generators. Each implementation owns its
/// own state machine and produces a synthetic request each time it is
/// asked. Archetypes should be cheap to construct and stable across calls
/// — the simulator keeps a single instance per archetype for the lifetime
/// of the loop.
pub trait Archetype: Send + Sync {
    /// Display name for logging.
    fn name(&self) -> &'static str;

    /// Produce the next synthetic request. Stateful — called repeatedly
    /// on the same instance.
    fn next_request(&mut self) -> SyntheticRequest;
}

// ============================================================================
// CredentialStuffer
// ============================================================================

/// A botnet credential-stuffing archetype. Cycles through a pool of source
/// IPs, all sharing the same suspicious JA4 fingerprint (the canonical
/// botnet tell), POSTing varied username/password JSON to `/api/login`.
///
/// This single archetype exercises a lot of the dashboards: distinct IPs
/// with shared fingerprint trips the JA4 IP-cluster detector, sequential
/// failed logins increase entity risk, the shared fingerprint registers
/// in `FingerprintIndex` and creates a campaign correlation.
pub struct CredentialStuffer {
    /// Pool of source IPs the bot uses. Cycles round-robin.
    ip_pool: Vec<String>,
    /// Index into ip_pool.
    ip_cursor: usize,
    /// Username pool to cycle through.
    user_pool: Vec<String>,
    /// Username cursor.
    user_cursor: usize,
    /// The JA4 fingerprint shared across all IPs (the botnet signature).
    /// Picked to look like a generic Go HTTP client.
    shared_ja4: String,
}

impl Default for CredentialStuffer {
    fn default() -> Self {
        Self {
            ip_pool: (0..20).map(|i| format!("198.51.100.{}", 10 + i)).collect(),
            ip_cursor: 0,
            user_pool: vec![
                "alice@acme.com".to_string(),
                "bob@acme.com".to_string(),
                "carol@acme.com".to_string(),
                "dave@acme.com".to_string(),
                "admin@acme.com".to_string(),
                "support@acme.com".to_string(),
                "billing@acme.com".to_string(),
                "test@acme.com".to_string(),
            ],
            user_cursor: 0,
            // t13d251200_ — TLS 1.3, 25 ciphers, no extensions, no ALPN.
            // Looks like a Go default http.Client (the canonical bot tell).
            shared_ja4: "t13d251200_a1b2c3d4e5f6_000000000000".to_string(),
        }
    }
}

impl Archetype for CredentialStuffer {
    fn name(&self) -> &'static str {
        "credential_stuffer"
    }

    fn next_request(&mut self) -> SyntheticRequest {
        let ip = self.ip_pool[self.ip_cursor].clone();
        self.ip_cursor = (self.ip_cursor + 1) % self.ip_pool.len();

        let user = self.user_pool[self.user_cursor].clone();
        self.user_cursor = (self.user_cursor + 1) % self.user_pool.len();

        let body = format!(
            r#"{{"username":"{}","password":"Summer2026!"}}"#,
            user
        );
        let body_bytes = Bytes::from(body.into_bytes());

        let headers = vec![
            (
                HeaderName::from_static("host"),
                HeaderValue::from_static("api.acme-corp.com"),
            ),
            (
                HeaderName::from_static("user-agent"),
                HeaderValue::from_static("Go-http-client/1.1"),
            ),
            (
                HeaderName::from_static("content-type"),
                HeaderValue::from_static("application/json"),
            ),
            (
                HeaderName::from_static("accept"),
                HeaderValue::from_static("*/*"),
            ),
        ];

        SyntheticRequest {
            method: "POST".to_string(),
            uri: "/api/login".to_string(),
            headers,
            body: Some(body_bytes),
            source_ip: ip,
            ja4_raw: Some(self.shared_ja4.clone()),
        }
    }
}

// ============================================================================
// VulnScanner
// ============================================================================

/// A vulnerability scanner archetype. Cycles through a list of well-known
/// attack payloads (SQLi, XSS, path traversal, command injection) hitting
/// varied URIs from a single source IP. Designed to trip the production
/// WAF rules and accumulate blocks + entity risk in the dashboards.
///
/// Uses a single source IP so the entity risk on that one IP grows
/// quickly to the blocking threshold, demonstrating progressive
/// mitigation. A future archetype can spread the same payload across many
/// IPs to demonstrate distributed-attack correlation.
pub struct VulnScanner {
    /// Scanner source IP (single IP that climbs the entity risk ladder).
    source_ip: String,
    /// Attack payload corpus — (method, uri, body) tuples.
    payloads: Vec<(&'static str, &'static str, Option<&'static str>)>,
    /// Cursor into payloads.
    cursor: usize,
}

impl Default for VulnScanner {
    fn default() -> Self {
        Self {
            source_ip: "203.0.113.99".to_string(),
            payloads: vec![
                // Classic SQLi probes — should trip rules in the 1xxxx
                // (injection) range from production_rules.json.
                ("GET", "/api/users?id=1%20OR%201%3D1", None),
                ("GET", "/api/search?q=%27%20UNION%20SELECT%20*%20FROM%20users--", None),
                ("GET", "/products?cat=1%3B%20DROP%20TABLE%20users", None),
                // XSS attempts.
                ("GET", "/comments?text=%3Cscript%3Ealert(1)%3C%2Fscript%3E", None),
                ("GET", "/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", None),
                // Path traversal.
                ("GET", "/files?name=..%2F..%2F..%2Fetc%2Fpasswd", None),
                ("GET", "/download?file=....%2F....%2Fetc%2Fshadow", None),
                // Command injection.
                ("GET", "/ping?host=127.0.0.1%3B%20cat%20%2Fetc%2Fpasswd", None),
                // Recon / scanner UA pattern (matched by bot-detection rules).
                ("GET", "/.env", None),
                ("GET", "/wp-admin/", None),
                ("GET", "/.git/config", None),
            ],
            cursor: 0,
        }
    }
}

impl Archetype for VulnScanner {
    fn name(&self) -> &'static str {
        "vuln_scanner"
    }

    fn next_request(&mut self) -> SyntheticRequest {
        let (method, uri, body) = self.payloads[self.cursor];
        self.cursor = (self.cursor + 1) % self.payloads.len();

        let headers = vec![
            (
                HeaderName::from_static("host"),
                HeaderValue::from_static("api.acme-corp.com"),
            ),
            (
                HeaderName::from_static("user-agent"),
                // Sqlmap-style user agent so bot/scanner UA rules trip too.
                HeaderValue::from_static("sqlmap/1.7.2#stable (https://sqlmap.org)"),
            ),
            (
                HeaderName::from_static("accept"),
                HeaderValue::from_static("*/*"),
            ),
        ];

        SyntheticRequest {
            method: method.to_string(),
            uri: uri.to_string(),
            headers,
            body: body.map(|b| Bytes::from(b.as_bytes())),
            source_ip: self.source_ip.clone(),
            // No JA4 — the scanner archetype represents a tool that
            // doesn't share a botnet fingerprint, so the engine's
            // entity-risk accumulation has to rely on rule matches
            // rather than fingerprint correlation.
            ja4_raw: None,
        }
    }
}

// ============================================================================
// SimulatorLoop
// ============================================================================

/// Background task that drives a set of archetypes through the real WAF
/// engine and shared managers. Construct with `new`, then call `start` to
/// spawn the tokio task and get back a JoinHandle.
pub struct SimulatorLoop {
    archetypes: Vec<Box<dyn Archetype>>,
    entity_manager: Arc<EntityManager>,
    campaign_manager: Arc<CampaignManager>,
    block_log: Arc<BlockLog>,
    waf_stats: Arc<WafStats>,
    /// Optional horizon WebSocket client. When present, every blocked
    /// request mirrors the production `request_filter` ThreatSignal emit
    /// so synthetic traffic flows through the same /ws/sensors gateway
    /// real sensors use, ending up in horizon's Prisma store and the
    /// dashboards' per-actor / per-campaign panels.
    horizon_manager: Option<Arc<HorizonManager>>,
    /// Tick interval. Default 200ms = 5 ticks/sec.
    tick_interval: Duration,
    /// How many synthetic requests to generate per tick. Multiplied across
    /// archetypes — at 5 ticks/sec × 4 requests × 1 archetype = 20 RPS.
    requests_per_tick: usize,
}

impl SimulatorLoop {
    pub fn new(
        entity_manager: Arc<EntityManager>,
        campaign_manager: Arc<CampaignManager>,
        block_log: Arc<BlockLog>,
        waf_stats: Arc<WafStats>,
        horizon_manager: Option<Arc<HorizonManager>>,
    ) -> Self {
        Self {
            archetypes: vec![
                Box::new(CredentialStuffer::default()),
                Box::new(VulnScanner::default()),
            ],
            entity_manager,
            campaign_manager,
            block_log,
            waf_stats,
            horizon_manager,
            tick_interval: Duration::from_millis(200),
            requests_per_tick: 4,
        }
    }

    /// Add an archetype to the rotation.
    pub fn with_archetype(mut self, archetype: Box<dyn Archetype>) -> Self {
        self.archetypes.push(archetype);
        self
    }

    /// Spawn the simulator loop as a tokio background task.
    pub fn start(mut self) -> JoinHandle<()> {
        info!(
            "synapse simulator starting: {} archetype(s), tick_interval={:?}, \
             requests_per_tick={}",
            self.archetypes.len(),
            self.tick_interval,
            self.requests_per_tick
        );

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(self.tick_interval);
            // Don't bunch up if we miss ticks (e.g. under load).
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut archetype_cursor = 0usize;

            loop {
                ticker.tick().await;

                if self.archetypes.is_empty() {
                    continue;
                }

                // Round-robin one archetype per tick. Each archetype produces
                // `requests_per_tick` requests.
                let archetype_idx = archetype_cursor % self.archetypes.len();
                archetype_cursor = archetype_cursor.wrapping_add(1);

                for _ in 0..self.requests_per_tick {
                    let req = self.archetypes[archetype_idx].next_request();
                    self.process_request(req);
                }
            }
        })
    }

    /// Drive a single synthetic request through the engine and mirror the
    /// production state-update calls. This is the seam between the
    /// simulator and the rest of synapse — keep it tight and audited.
    fn process_request(&self, req: SyntheticRequest) {
        // Build a ClientFingerprint if the archetype provided a JA4. The
        // JA4H is computed from the synthetic headers exactly the same way
        // production computes it from real headers.
        let ja4h = generate_ja4h(&HttpHeaders {
            headers: &req.headers,
            method: &req.method,
            http_version: "1.1",
        });

        let fingerprint = req.ja4_raw.as_ref().map(|raw| {
            // The simulator only needs the raw string for the engine's
            // substring-match rules and the fingerprint index. We construct
            // a minimal Ja4Fingerprint with parsed-but-stub fields — the
            // fields that matter for evaluation (raw) are populated, the
            // rest get plausible defaults. If a future rule starts
            // matching on cipher_count etc. against simulated traffic,
            // extend this constructor.
            ClientFingerprint {
                ja4: Some(synapse_pingora::fingerprint::Ja4Fingerprint {
                    raw: Arc::from(raw.as_str()),
                    protocol: synapse_pingora::fingerprint::Ja4Protocol::TCP,
                    tls_version: 13,
                    sni_type: synapse_pingora::fingerprint::Ja4SniType::Domain,
                    cipher_count: 25,
                    ext_count: 12,
                    alpn: "h2".to_string(),
                    cipher_hash: "a1b2c3d4e5f6".to_string(),
                    ext_hash: "000000000000".to_string(),
                }),
                ja4h: ja4h.clone(),
                combined_hash: format!(
                    "sim_{}_{}",
                    &raw[..8.min(raw.len())],
                    &ja4h.raw[..8.min(ja4h.raw.len())]
                ),
            }
        });

        // Run the real engine.
        let body_slice = req.body.as_deref();
        let result = DetectionEngine::analyze_with_signals(
            &req.method,
            &req.uri,
            &req.headers,
            body_slice,
            &req.source_ip,
            fingerprint.as_ref(),
            None,
        );

        // Record the analysis in the global WafStats counters that the
        // /_sensor/status and /stats endpoints read from. Without this,
        // horizon's polled "analyzed" / "blocked" / "blockRate" values
        // stay at zero even though the engine is running.
        self.waf_stats.record(result.blocked, result.detection_time_us);

        // Mirror the production state updates that request_filter does
        // after the analyze call. Keep this list aligned with main.rs.
        if self.entity_manager.is_enabled() {
            let ja4_str = fingerprint.as_ref().and_then(|fp| {
                fp.ja4.as_ref().map(|j| -> &str { &j.raw })
            });
            let _ = self.entity_manager.touch_entity_with_fingerprint(
                &req.source_ip,
                ja4_str,
                None,
            );
        }

        if let Ok(ip_addr) = req.source_ip.parse::<std::net::IpAddr>() {
            let ja4_arc = fingerprint
                .as_ref()
                .and_then(|fp| fp.ja4.as_ref().map(|j| Arc::clone(&j.raw)));
            let ja4h_arc = fingerprint.as_ref().map(|fp| Arc::clone(&fp.ja4h.raw));
            self.campaign_manager
                .register_fingerprints(ip_addr, ja4_arc, ja4h_arc);
        }

        if result.blocked {
            self.block_log.record(BlockEvent::new(
                req.source_ip.clone(),
                req.method.clone(),
                req.uri.clone(),
                result.risk_score,
                result.matched_rules.clone(),
                result
                    .block_reason
                    .clone()
                    .unwrap_or_else(|| "simulator".to_string()),
                fingerprint.as_ref().map(|fp| fp.combined_hash.clone()),
            ));

            // Apply the engine's risk to the entity so the dashboards show
            // accumulating pressure on this IP across requests.
            self.entity_manager.apply_external_risk(
                &req.source_ip,
                result.risk_score as f64,
                "simulator_block",
            );

            debug!(
                "simulator BLOCK: {} {} from {} (risk={}, rules={:?})",
                req.method, req.uri, req.source_ip, result.risk_score, result.matched_rules
            );
        }

        // Mirror request_filter's ThreatSignal emission (main.rs:2022-2050)
        // so simulated traffic shows up in horizon's per-actor / per-campaign
        // dashboards via the same /ws/sensors path real sensors use.
        //
        // Emit on EVERY analyze (not just blocks) because horizon's actor
        // service correlates signals across requests, not just blocks. A
        // credential-stuffer pattern is interesting BEFORE any individual
        // request blocks because the signal is the cluster of failed
        // logins, not the single 403.
        if let Some(ref horizon) = self.horizon_manager {
            let severity = if result.risk_score >= 80 {
                Severity::Critical
            } else if result.risk_score >= 60 {
                Severity::High
            } else if result.risk_score >= 40 {
                Severity::Medium
            } else {
                Severity::Low
            };

            let mut signal = ThreatSignal::new(SignalType::IpThreat, severity)
                .with_source_ip(&req.source_ip)
                .with_confidence(result.risk_score as f64 / 100.0);

            if let Some(ja4) = fingerprint.as_ref().and_then(|fp| fp.ja4.as_ref()) {
                signal = signal.with_fingerprint(&ja4.raw);
            }

            let rule_ids: Vec<String> = result
                .matched_rules
                .iter()
                .map(|r| format!("rule_{}", r))
                .collect();
            if !rule_ids.is_empty() {
                signal = signal.with_metadata(serde_json::json!({
                    "rule_ids": rule_ids,
                    "source": "simulator",
                }));
            } else {
                signal = signal.with_metadata(serde_json::json!({
                    "source": "simulator",
                }));
            }

            horizon.report_signal(signal);
        }
    }
}
