use crate::dlp::DlpMatch;
use crate::fingerprint::ClientFingerprint;
use crate::profiler::{EndpointProfile, ValidationResult};
use crate::waf::{
    Action as SynapseAction, Header as SynapseHeader, Request as SynapseRequest, Synapse,
    Verdict as SynapseVerdict,
};
use http::header::{HeaderName, HeaderValue};
use log::{debug, info, warn};
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub blocked: bool,
    pub risk_score: u16,
    pub matched_rules: Vec<u32>,
    pub entity_risk: f64,
    pub block_reason: Option<String>,
    pub detection_time_us: u64,
}

/// Captured request headers as seen on the wire.
///
/// Callers own the header names and values so snapshots can be reused across
/// request evaluation phases without borrowing the underlying session object.
pub type HeaderSnapshot = (HeaderName, HeaderValue);

impl Default for DetectionResult {
    fn default() -> Self {
        Self {
            blocked: false,
            risk_score: 0,
            matched_rules: Vec::new(),
            entity_risk: 0.0,
            block_reason: None,
            detection_time_us: 0,
        }
    }
}

impl From<SynapseVerdict> for DetectionResult {
    fn from(verdict: SynapseVerdict) -> Self {
        Self {
            blocked: verdict.action == SynapseAction::Block,
            risk_score: verdict.risk_score,
            matched_rules: verdict.matched_rules,
            entity_risk: verdict.entity_risk,
            block_reason: verdict.block_reason,
            detection_time_us: 0,
        }
    }
}

static RULES_DATA: Lazy<Option<Vec<u8>>> = Lazy::new(|| {
    let rules_paths = [
        "data/rules.json",
        "rules.json",
        "/etc/synapse-pingora/rules.json",
    ];

    for path in &rules_paths {
        if Path::new(path).exists() {
            match fs::read(path) {
                Ok(rules_json) => {
                    info!("Found rules at {} ({} bytes)", path, rules_json.len());
                    return Some(rules_json);
                }
                Err(e) => {
                    warn!("Failed to read rules from {}: {}", path, e);
                }
            }
        }
    }

    warn!(
        "No external rules.json found at data/rules.json, rules.json, or /etc/synapse-pingora/rules.json; falling back to embedded production rules"
    );
    None
});

static SYNAPSE: Lazy<Arc<RwLock<Synapse>>> =
    Lazy::new(|| Arc::new(RwLock::new(create_synapse_engine())));

static WAF_REGEX_TIMEOUT_US: AtomicU64 = AtomicU64::new(100_000);

fn create_synapse_engine() -> Synapse {
    let mut synapse = Synapse::new();

    if let Some(ref rules_json) = *RULES_DATA {
        match synapse.load_rules(rules_json) {
            Ok(count) => debug!("Loaded {} rules from external file", count),
            Err(e) => warn!("Failed to parse rules: {}", e),
        }
    } else {
        let production_rules = include_str!("production_rules.json");
        match synapse.load_rules(production_rules.as_bytes()) {
            Ok(count) => debug!("Loaded {} embedded production rules", count),
            Err(e) => panic!(
                "FATAL: embedded production_rules.json failed to load at startup: {}. \
                 This should never happen in a released binary because \
                 test_production_rules_load_into_current_engine gates it in CI. \
                 If you see this panic, the binary is corrupted or a regression \
                 slipped past CI. Do not run a WAF proxy with zero rules.",
                e
            ),
        }
    }

    synapse
}

/// Build a Synapse request view from the proxy's observed request state.
///
/// `dlp_matches` must only be populated for the deferred analysis path so
/// request-phase evaluation cannot accidentally consume deferred-only rules.
fn build_request<'a>(
    method: &'a str,
    uri: &'a str,
    headers: &'a [HeaderSnapshot],
    body: Option<&'a [u8]>,
    client_ip: &'a str,
    fingerprint: Option<&'a ClientFingerprint>,
    schema_result: Option<&'a ValidationResult>,
    dlp_matches: Option<&'a [DlpMatch]>,
) -> SynapseRequest<'a> {
    let mut synapse_headers = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        if let Ok(value_str) = value.to_str() {
            synapse_headers.push(SynapseHeader::new(name.as_str(), value_str));
        }
    }

    SynapseRequest {
        method,
        path: uri,
        query: None,
        headers: synapse_headers,
        body,
        client_ip,
        is_static: false,
        fingerprint,
        dlp_matches,
        schema_result,
    }
}

/// Library-owned facade for the global Synapse WAF engine.
///
/// This keeps the engine lifecycle and request-evaluation entrypoints in the
/// library crate while still preserving the historical `DetectionEngine::...`
/// call sites used by the binary and integration tests.
pub struct DetectionEngine;

impl DetectionEngine {
    /// Analyze a request against the full production ruleset.
    ///
    /// Regex-heavy rules are evaluated under the configured timeout budget to
    /// prevent ReDoS-style request amplification. The returned
    /// `detection_time_us` includes request construction plus Synapse verdict
    /// evaluation.
    #[inline]
    pub fn analyze(
        method: &str,
        uri: &str,
        headers: &[HeaderSnapshot],
        body: Option<&[u8]>,
        client_ip: &str,
    ) -> DetectionResult {
        let start = Instant::now();
        let request = build_request(method, uri, headers, body, client_ip, None, None, None);
        let timeout = Duration::from_micros(WAF_REGEX_TIMEOUT_US.load(Ordering::Relaxed));
        let verdict = SYNAPSE.read().analyze_with_timeout(&request, timeout);
        let elapsed = start.elapsed();

        DetectionResult {
            detection_time_us: elapsed.as_micros() as u64,
            ..verdict.into()
        }
    }

    /// Analyze a request while incorporating precomputed security signals.
    ///
    /// This is the synchronous path used when fingerprinting and schema
    /// validation results are already available on the request path. Rules
    /// that depend on `dlp_violation` are evaluated separately by
    /// [`Self::analyze_deferred`].
    #[inline]
    pub fn analyze_with_signals(
        method: &str,
        uri: &str,
        headers: &[HeaderSnapshot],
        body: Option<&[u8]>,
        client_ip: &str,
        fingerprint: Option<&ClientFingerprint>,
        schema_result: Option<&ValidationResult>,
    ) -> DetectionResult {
        let start = Instant::now();
        let request = build_request(
            method,
            uri,
            headers,
            body,
            client_ip,
            fingerprint,
            schema_result,
            None,
        );
        let timeout = Duration::from_micros(WAF_REGEX_TIMEOUT_US.load(Ordering::Relaxed));
        let verdict = SYNAPSE.read().analyze_with_timeout(&request, timeout);
        let elapsed = start.elapsed();

        DetectionResult {
            detection_time_us: elapsed.as_micros() as u64,
            ..verdict.into()
        }
    }

    /// Analyze deferred-only rules after the request body has been inspected.
    ///
    /// This path is reserved for detections that depend on post-body signals,
    /// such as DLP matches, and intentionally avoids re-running the full
    /// request-rule set on the deferred pass. When no deferred-only rules are
    /// loaded, Synapse returns the default allow verdict so the outer request
    /// pipeline can continue without introducing a synthetic block.
    #[inline]
    pub fn analyze_deferred(
        method: &str,
        uri: &str,
        headers: &[HeaderSnapshot],
        body: Option<&[u8]>,
        client_ip: &str,
        fingerprint: Option<&ClientFingerprint>,
        schema_result: Option<&ValidationResult>,
        dlp_matches: &[DlpMatch],
    ) -> DetectionResult {
        let start = Instant::now();
        let request = build_request(
            method,
            uri,
            headers,
            body,
            client_ip,
            fingerprint,
            schema_result,
            Some(dlp_matches),
        );
        let timeout = Duration::from_micros(WAF_REGEX_TIMEOUT_US.load(Ordering::Relaxed));
        let verdict = SYNAPSE
            .read()
            .analyze_deferred_with_timeout(&request, timeout);
        let elapsed = start.elapsed();

        DetectionResult {
            detection_time_us: elapsed.as_micros() as u64,
            ..verdict.into()
        }
    }

    pub fn record_status(path: &str, status: u16) {
        SYNAPSE.read().record_response_status(path, status);
    }

    pub fn get_profiles() -> Vec<EndpointProfile> {
        SYNAPSE.read().get_profiles()
    }

    /// Load persisted endpoint profiles into the shared engine.
    ///
    /// `Synapse` stores profiles in a `ProfileStore` backed by `DashMap`,
    /// so the historical read-lock access pattern remains valid here.
    pub fn load_profiles(profiles: Vec<EndpointProfile>) {
        SYNAPSE.read().load_profiles(profiles);
    }

    pub fn rule_count() -> usize {
        SYNAPSE.read().rule_count()
    }

    pub fn reload_rules(json: &[u8]) -> Result<usize, crate::waf::WafError> {
        SYNAPSE.write().load_rules(json)
    }

    /// Return the shared engine for infrastructure wiring.
    ///
    /// This escape hatch exists for legacy integration points such as config
    /// management, admin APIs, and the TUI. Callers should treat it as
    /// infrastructure-only, avoid holding the write lock across await points,
    /// and prefer the facade helpers above on request-path code.
    ///
    /// TODO(TASK-70): replace raw engine sharing with narrower handoff helpers
    /// for config, admin, and TUI wiring so request-path code never needs the
    /// synchronization primitive.
    pub fn shared_engine() -> Arc<RwLock<Synapse>> {
        Arc::clone(&SYNAPSE)
    }

    /// Borrow the external rules payload, if one was found on disk.
    ///
    /// Embedded fallback rules are intentionally excluded so callers that use
    /// this for fleet-level external-rules drift reporting preserve the
    /// pre-refactor contract.
    pub fn rules_data() -> Option<&'static [u8]> {
        RULES_DATA.as_deref()
    }

    /// Update the regex evaluation budget used by all request analysis paths.
    ///
    /// The timeout is clamped into the 1ms..=500ms range because Synapse
    /// executes regex-heavy rules inline on the request path and values
    /// outside that range either weaken coverage or materially increase ReDoS
    /// exposure during attacker-controlled traffic.
    pub fn set_regex_timeout_ms(timeout_ms: u64) -> u64 {
        let applied_ms = timeout_ms.clamp(1, 500);
        if timeout_ms < applied_ms {
            warn!(
                "Requested WAF regex timeout {}ms is below the safety floor; clamping to {}ms",
                timeout_ms, applied_ms
            );
        } else if timeout_ms > applied_ms {
            warn!(
                "Requested WAF regex timeout {}ms exceeds safety cap; clamping to {}ms",
                timeout_ms, applied_ms
            );
        }
        WAF_REGEX_TIMEOUT_US.store(applied_ms * 1000, Ordering::Relaxed);
        applied_ms
    }
}
