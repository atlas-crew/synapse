//! Synapse-Pingora: High-performance WAF proxy using Cloudflare Pingora.
//!
//! This library provides multi-site reverse proxy capabilities with integrated
//! WAF detection using the Synapse engine.
//!
//! # Phase 1 Modules (Core Features)
//!
//! - [`vhost`] - Virtual host matching for multi-site routing
//! - [`config`] - Configuration loading and validation
//! - [`tls`] - TLS certificate management with SNI support
//! - [`health`] - Health check endpoint for monitoring
//! - [`site_waf`] - Per-site WAF configuration management
//!
//! # Phase 2 Modules (Management Features)
//!
//! - [`metrics`] - Prometheus metrics endpoint
//! - [`reload`] - Configuration hot-reload via SIGHUP
//! - [`access`] - CIDR-based allow/deny access lists
//! - [`ratelimit`] - Per-site rate limiting with token bucket
//! - [`api`] - Management HTTP API
//!
//! # Phase 3 Modules (Feature Migration from risk-server)
//!
//! - [`fingerprint`] - JA4/JA4H TLS and HTTP fingerprinting
//! - [`entity`] - Per-IP entity tracking with risk scoring and decay
//! - [`tarpit`] - Progressive response delays for slow-drip defense
//! - [`dlp`] - Data Loss Prevention with 23 sensitive data patterns

// Phase 1: Core Features
pub mod utils;
pub mod config;
pub mod config_manager;
pub mod health;
pub mod site_waf;
pub mod tls;
pub mod vhost;

// Phase 2: Management Features
pub mod access;
pub mod admin_server;
pub mod api;
pub mod intelligence;
pub mod metrics;
pub mod ratelimit;
pub mod reload;

// Phase 3: Feature Migration from risk-server
pub mod fingerprint;
pub mod entity;
pub mod tarpit;
pub mod dlp;

// Phase 6: Security Hardening
pub mod validation;
pub mod sni_validation;

// Phase 7: Persistence
pub mod persistence;

// Phase 3: Telemetry (Alerting)
pub mod telemetry;
pub mod signals;

// Phase 3: Honeypot Trap Detection
pub mod trap;

// Phase 4: Campaign Correlation
pub mod correlation;

// Phase 5: Actor State Management
pub mod actor;

// Phase 5: Session State Management
pub mod session;

// Phase 6: Interrogator System (Progressive Challenge Escalation)
pub mod interrogator;

// Phase 7: Shadow Mirroring (Honeypot Integration)
pub mod shadow;

// Phase 8: API Profiler (Behavioral Learning)
pub mod profiler;

// Phase 9: Risk-Server Port (Payload, Crawler, Trends, Horizon)
pub mod crawler;
pub mod horizon;
pub mod tunnel;
pub mod payload;
pub mod trends;

// Phase 10: Libsynapse Consolidation (Geo, WAF Engine, Credential Stuffing)
pub mod geo;
pub mod waf;
pub mod detection;

// Dashboard support
pub mod block_log;

// Header Manipulation
pub mod headers;

// Body Inspection
pub mod body;

// Block Page Rendering
pub mod block_page;

// Re-export commonly used types from Phase 1
pub use config::{ConfigFile, ConfigLoader, GlobalConfig};
pub use health::{HealthChecker, HealthResponse, HealthStatus};
pub use site_waf::{SiteWafConfig, SiteWafManager, WafAction};
pub use tls::{TlsManager, TlsVersion};
pub use vhost::{SiteConfig, VhostMatcher};

// Re-export commonly used types from Phase 2
pub use access::{AccessList, AccessListManager, AccessDecision};
pub use api::{ApiHandler, ApiResponse, EvaluateResult};
pub use metrics::{MetricsRegistry, BandwidthStats, BandwidthDataPoint, ProfilingMetrics};
pub use ratelimit::{RateLimitConfig, RateLimitManager, RateLimitDecision};
pub use reload::{ConfigReloader, ReloadResult};

// Re-export commonly used types from Phase 3
pub use fingerprint::{
    Ja4Fingerprint, Ja4hFingerprint, ClientFingerprint,
    Ja4Protocol, Ja4SniType, Ja4Analysis, Ja4hAnalysis,
    HttpHeaders,
    parse_ja4_from_header, generate_ja4h, extract_client_fingerprint,
    analyze_ja4, analyze_ja4h,
};
pub use entity::{
    EntityConfig, EntityState, EntityManager,
    BlockDecision, RiskApplication, EntitySnapshot, EntityMetrics,
};
pub use tarpit::{
    TarpitConfig, TarpitState, TarpitStats,
    TarpitManager, TarpitDecision,
};
pub use dlp::{
    DlpConfig, DlpScanner, DlpMatch, DlpStats, ScanResult,
    SensitiveDataType, PatternSeverity,
    validate_credit_card, validate_ssn, validate_phone, validate_iban,
};

// Re-export validation utilities
pub use validation::{
    ValidationError, ValidationResult,
    validate_domain_name, validate_certificate_file, validate_private_key_file,
    validate_tls_config,
};

// Re-export SNI validation types (domain fronting prevention)
pub use sni_validation::{
    SniValidator, SniValidationConfig, SniValidationMode, SniValidationResult,
};

// Re-export honeypot trap types
pub use trap::{TrapConfig, TrapMatcher};

// Re-export dashboard support types
pub use block_log::{BlockLog, BlockEvent};

// Re-export actor management types
pub use actor::{ActorConfig, ActorManager, ActorState, ActorStats, RuleMatch};

// Re-export session management types
pub use session::{
    SessionConfig, SessionManager, SessionState, SessionStats,
    SessionDecision, HijackAlert, HijackType,
};

// Re-export interrogator types
pub use interrogator::{
    ChallengeResponse, ValidationResult as ChallengeValidationResult, Interrogator,
    CookieConfig, CookieManager, CookieChallenge, CookieStats,
    JsChallengeConfig, JsChallengeManager, JsChallenge, JsChallengeStats,
    ProgressionConfig, ProgressionManager, ChallengeLevel, ActorChallengeState, ProgressionStats,
};

// Re-export shadow mirroring types
pub use shadow::{
    ShadowMirrorConfig, ShadowMirrorManager, ShadowMirrorStats,
    ShadowMirrorClient, ShadowMirrorError, ShadowClientStats,
    MirrorPayload, RateLimiter as ShadowRateLimiter, RateLimiterStats as ShadowRateLimiterStats,
};

// Re-export profiler types
pub use profiler::{
    Profiler, EndpointProfile, ParameterSchema,
    Distribution, PercentilesTracker, RateTracker,
    AnomalyResult, AnomalySignal, AnomalySignalType,
    // Schema learning types (ported from libsynapse)
    SchemaLearner, SchemaLearnerConfig, SchemaLearnerStats,
    ProfileStore, ProfileStoreConfig, ProfileStoreMetrics, SegmentCardinality,
    JsonEndpointSchema, FieldSchema, FieldType, PatternType,
    SchemaViolation, ViolationSeverity, ViolationType,
    detect_pattern, matches_pattern,
    // Header profiling types (W4.1 HeaderProfiler)
    HeaderProfiler, HeaderProfilerStats,
    HeaderAnomaly, HeaderAnomalyResult, HeaderBaseline, ValueStats,
    shannon_entropy, normalized_entropy, is_entropy_anomaly, entropy_z_score,
};

// Re-export profiler config
pub use config::ProfilerConfig;

// Re-export crawler detection types
pub use crawler::{
    CrawlerDetector, CrawlerConfig, CrawlerDetection, CrawlerVerificationResult,
    CrawlerStats, CrawlerStatsSnapshot, VerificationMethod, DnsFailurePolicy,
    CrawlerDefinition, BadBotSignature, BadBotSeverity,
};

// Re-export Signal Horizon integration types
pub use horizon::{
    HorizonManager, HorizonConfig, HorizonStats, HorizonStatsSnapshot,
    HorizonClient, HorizonError, ClientStats,
    ThreatSignal, SignalType, Severity, ConnectionState,
    BlocklistCache, BlocklistEntry, BlocklistUpdate, BlockType,
};

// Re-export payload profiling types
pub use payload::{
    PayloadManager, PayloadConfig, PayloadSummary, EndpointSortBy,
    EndpointPayloadStats, EndpointPayloadStatsSnapshot, PayloadWindow, SizeStats,
    EntityBandwidth, BandwidthBucket,
    PayloadAnomaly, PayloadAnomalyType, PayloadAnomalySeverity, PayloadAnomalyMetadata,
};

// Re-export trends/signal tracking types
pub use trends::{
    TrendsManager, TrendsConfig, TrendsManagerStats, TrendsStats,
    AnomalyDetector, AnomalyDetectorConfig,
    SignalExtractor, TimeStore, TimeStoreStats, SignalBucket,
    CorrelationEngine, Correlation, CorrelationMetadata, CorrelationType,
    Signal, SignalCategory, SignalMetadata, SignalTrend,
    Anomaly, AnomalyType, AnomalySeverity, AnomalyMetadata, AnomalyQueryOptions,
    TrendQueryOptions, TrendsSummary, TrendHistogramBucket, BucketSummary, CategorySummary,
};

// Re-export intelligence signal aggregation types
pub use intelligence::{
    SignalManager, SignalManagerConfig, SignalQueryOptions,
    SignalCategory as IntelligenceSignalCategory,
    Signal as IntelligenceSignal,
    SignalSummary as IntelligenceSignalSummary,
    TopSignalType as IntelligenceTopSignalType,
};

// Re-export geo/impossible travel types
pub use geo::{
    ImpossibleTravelDetector, GeoLocation, LoginEvent, TravelAlert, TravelConfig, TravelStats,
    Severity as GeoSeverity, haversine_distance, is_valid_coordinates, calculate_speed,
};

// Re-export WAF engine types (Phase 10)
pub use waf::{
    Engine as WafEngine, WafError, Synapse,
    WafRule, MatchCondition, MatchValue, boolean_operands,
    RuleIndex, IndexedRule, CandidateCache, CandidateCacheKey,
    build_rule_index, get_candidate_rule_indices, method_to_mask,
    StateStore, now_ms,
    Request as WafRequest, Header as WafHeader, Verdict as WafVerdict,
    Action as WafRuleAction, EvalContext, ArgEntry,
    RiskContribution as WafRiskContribution,
    AnomalyType as WafAnomalyType, AnomalySignal as WafAnomalySignal,
    AnomalySignalType as WafAnomalySignalType,
    RiskConfig as WafRiskConfig, BlockingMode as WafBlockingMode,
    AnomalyContribution as WafAnomalyContribution, repeat_multiplier,
};

// Re-export credential stuffing detection types (Phase 10)
pub use detection::{
    CredentialStuffingDetector, StuffingStats, StuffingState,
    AuthAttempt, AuthMetrics, AuthResult, DistributedAttack, EntityEndpointKey,
    StuffingConfig, StuffingEvent, StuffingSeverity, StuffingVerdict, TakeoverAlert,
};

// ============================================================================
// Integration Tests: ActorManager + SessionManager Integration
// ============================================================================
// These tests verify the wiring between actor/session managers and the pipeline
// ============================================================================

#[cfg(test)]
mod actor_session_integration_tests {
    use super::*;
    use std::net::IpAddr;
    use std::sync::Arc;

    // ========================================================================
    // Test Helpers
    // ========================================================================

    fn create_test_actor_manager() -> Arc<ActorManager> {
        Arc::new(ActorManager::new(ActorConfig {
            max_actors: 1000,
            decay_interval_secs: 900,
            correlation_threshold: 0.7,
            risk_decay_factor: 0.9,
            max_rule_matches: 100,
            max_session_ids: 50,
            enabled: true,
            max_risk: 100.0,
            persist_interval_secs: 300,
            max_fingerprints_per_actor: 20,
            max_fingerprint_mappings: 500_000,
        }))
    }

    fn create_test_session_manager() -> Arc<SessionManager> {
        Arc::new(SessionManager::new(SessionConfig {
            max_sessions: 1000,
            session_ttl_secs: 3600,
            idle_timeout_secs: 900,
            cleanup_interval_secs: 300,
            enable_ja4_binding: true,
            enable_ip_binding: false,
            ja4_mismatch_threshold: 1,
            ip_change_window_secs: 60,
            max_alerts_per_session: 10,
            enabled: true,
        }))
    }

    fn create_test_ip(last_octet: u8) -> IpAddr {
        format!("192.168.1.{}", last_octet).parse().unwrap()
    }

    // ========================================================================
    // 1. Actor Creation from Request Tests
    // ========================================================================

    #[test]
    fn test_request_with_ip_creates_actor() {
        let actor_manager = create_test_actor_manager();
        let ip = create_test_ip(100);

        let actor_id = actor_manager.get_or_create_actor(ip, None);

        assert!(!actor_id.is_empty());
        assert_eq!(actor_manager.len(), 1);

        let actor = actor_manager.get_actor(&actor_id).unwrap();
        assert!(actor.ips.contains(&ip));
        assert!(!actor.is_blocked);
        assert_eq!(actor.risk_score, 0.0);
    }

    #[test]
    fn test_request_with_ip_and_fingerprint_creates_actor() {
        let actor_manager = create_test_actor_manager();
        let ip = create_test_ip(101);
        let fingerprint = "t13d1516h2_abc123_ja4hash";

        let actor_id = actor_manager.get_or_create_actor(ip, Some(fingerprint));

        let actor = actor_manager.get_actor(&actor_id).unwrap();
        assert!(actor.ips.contains(&ip));
        assert!(actor.fingerprints.contains(fingerprint));
    }

    #[test]
    fn test_multiple_ips_correlated_via_fingerprint() {
        let actor_manager = create_test_actor_manager();
        let ip1 = create_test_ip(1);
        let ip2 = create_test_ip(2);
        let ip3 = create_test_ip(3);
        let shared_fingerprint = "t13d1516h2_shared_fingerprint";

        let actor_id1 = actor_manager.get_or_create_actor(ip1, Some(shared_fingerprint));
        let actor_id2 = actor_manager.get_or_create_actor(ip2, Some(shared_fingerprint));
        let actor_id3 = actor_manager.get_or_create_actor(ip3, Some(shared_fingerprint));

        assert_eq!(actor_id1, actor_id2);
        assert_eq!(actor_id2, actor_id3);
        assert_eq!(actor_manager.len(), 1);

        let actor = actor_manager.get_actor(&actor_id1).unwrap();
        assert!(actor.ips.contains(&ip1));
        assert!(actor.ips.contains(&ip2));
        assert!(actor.ips.contains(&ip3));
        assert_eq!(actor.ips.len(), 3);
    }

    #[test]
    fn test_same_ip_subsequent_requests_correlate() {
        let actor_manager = create_test_actor_manager();
        let ip = create_test_ip(50);

        let actor_id1 = actor_manager.get_or_create_actor(ip, None);
        let actor_id2 = actor_manager.get_or_create_actor(ip, None);
        let actor_id3 = actor_manager.get_or_create_actor(ip, None);

        assert_eq!(actor_id1, actor_id2);
        assert_eq!(actor_id2, actor_id3);
        assert_eq!(actor_manager.len(), 1);
    }

    #[test]
    fn test_different_ips_without_fingerprint_create_separate_actors() {
        let actor_manager = create_test_actor_manager();
        let ip1 = create_test_ip(10);
        let ip2 = create_test_ip(20);

        let actor_id1 = actor_manager.get_or_create_actor(ip1, None);
        let actor_id2 = actor_manager.get_or_create_actor(ip2, None);

        assert_ne!(actor_id1, actor_id2);
        assert_eq!(actor_manager.len(), 2);
    }

    // ========================================================================
    // 2. Rule Match Recording Tests
    // ========================================================================

    #[test]
    fn test_matched_rules_recorded_to_actor_history() {
        let actor_manager = create_test_actor_manager();
        let ip = create_test_ip(100);

        let actor_id = actor_manager.get_or_create_actor(ip, None);
        actor_manager.record_rule_match(&actor_id, "sqli-001", 25.0, "sqli");

        let actor = actor_manager.get_actor(&actor_id).unwrap();
        assert_eq!(actor.rule_matches.len(), 1);
        assert_eq!(actor.rule_matches[0].rule_id, "sqli-001");
        assert_eq!(actor.rule_matches[0].category, "sqli");
        assert_eq!(actor.rule_matches[0].risk_contribution, 25.0);
    }

    #[test]
    fn test_risk_score_accumulates_correctly() {
        let actor_manager = create_test_actor_manager();
        let ip = create_test_ip(101);

        let actor_id = actor_manager.get_or_create_actor(ip, None);

        actor_manager.record_rule_match(&actor_id, "sqli-001", 25.0, "sqli");
        actor_manager.record_rule_match(&actor_id, "xss-001", 20.0, "xss");
        actor_manager.record_rule_match(&actor_id, "path-001", 15.0, "path_traversal");

        let actor = actor_manager.get_actor(&actor_id).unwrap();
        assert_eq!(actor.risk_score, 60.0);
        assert_eq!(actor.rule_matches.len(), 3);
    }

    #[test]
    fn test_risk_score_capped_at_max() {
        let actor_manager = create_test_actor_manager();
        let ip = create_test_ip(102);

        let actor_id = actor_manager.get_or_create_actor(ip, None);

        for i in 0..15 {
            actor_manager.record_rule_match(&actor_id, &format!("rule-{}", i), 10.0, "attack");
        }

        let actor = actor_manager.get_actor(&actor_id).unwrap();
        assert!(actor.risk_score <= 100.0);
        assert_eq!(actor.risk_score, 100.0);
    }

    #[test]
    fn test_category_mapping_works() {
        let actor_manager = create_test_actor_manager();
        let ip = create_test_ip(103);

        let actor_id = actor_manager.get_or_create_actor(ip, None);

        actor_manager.record_rule_match(&actor_id, "rule_940001", 10.0, "sqli");
        actor_manager.record_rule_match(&actor_id, "rule_941001", 10.0, "xss");
        actor_manager.record_rule_match(&actor_id, "rule_930001", 10.0, "path_traversal");
        actor_manager.record_rule_match(&actor_id, "rule_932001", 10.0, "rce");
        actor_manager.record_rule_match(&actor_id, "rule_913001", 10.0, "scanner");

        let actor = actor_manager.get_actor(&actor_id).unwrap();
        let categories: Vec<&str> = actor.rule_matches.iter().map(|m| m.category.as_str()).collect();
        assert!(categories.contains(&"sqli"));
        assert!(categories.contains(&"xss"));
        assert!(categories.contains(&"path_traversal"));
        assert!(categories.contains(&"rce"));
        assert!(categories.contains(&"scanner"));
    }

    // ========================================================================
    // 3. Actor Blocking Tests
    // ========================================================================

    #[test]
    fn test_high_risk_actor_gets_blocked() {
        let actor_manager = create_test_actor_manager();
        let ip = create_test_ip(100);

        let actor_id = actor_manager.get_or_create_actor(ip, None);
        assert!(!actor_manager.is_blocked(&actor_id));

        let blocked = actor_manager.block_actor(&actor_id, "High risk score exceeded threshold");

        assert!(blocked);
        assert!(actor_manager.is_blocked(&actor_id));

        let actor = actor_manager.get_actor(&actor_id).unwrap();
        assert!(actor.is_blocked);
        assert_eq!(actor.block_reason, Some("High risk score exceeded threshold".to_string()));
        assert!(actor.blocked_since.is_some());
    }

    #[test]
    fn test_block_decision_enforced_in_subsequent_requests() {
        let actor_manager = create_test_actor_manager();
        let ip = create_test_ip(101);
        let fingerprint = "blocked_actor_fingerprint";

        let actor_id = actor_manager.get_or_create_actor(ip, Some(fingerprint));
        actor_manager.block_actor(&actor_id, "Malicious activity detected");

        let actor_id2 = actor_manager.get_or_create_actor(ip, Some(fingerprint));
        assert_eq!(actor_id, actor_id2);
        assert!(actor_manager.is_blocked(&actor_id2));

        let ip2 = create_test_ip(102);
        let actor_id3 = actor_manager.get_or_create_actor(ip2, Some(fingerprint));
        assert_eq!(actor_id, actor_id3);
        assert!(actor_manager.is_blocked(&actor_id3));
    }

    #[test]
    fn test_unblock_actor() {
        let actor_manager = create_test_actor_manager();
        let ip = create_test_ip(103);

        let actor_id = actor_manager.get_or_create_actor(ip, None);

        actor_manager.block_actor(&actor_id, "Test block");
        assert!(actor_manager.is_blocked(&actor_id));

        let unblocked = actor_manager.unblock_actor(&actor_id);
        assert!(unblocked);
        assert!(!actor_manager.is_blocked(&actor_id));

        let actor = actor_manager.get_actor(&actor_id).unwrap();
        assert!(!actor.is_blocked);
        assert!(actor.block_reason.is_none());
        assert!(actor.blocked_since.is_none());
    }

    #[test]
    fn test_list_blocked_actors() {
        let actor_manager = create_test_actor_manager();

        for i in 0..10 {
            let ip = create_test_ip(i);
            let actor_id = actor_manager.get_or_create_actor(ip, None);
            if i % 2 == 0 {
                actor_manager.block_actor(&actor_id, &format!("Blocked actor {}", i));
            }
        }

        let blocked = actor_manager.list_blocked_actors();
        assert_eq!(blocked.len(), 5);

        for actor in blocked {
            assert!(actor.is_blocked);
        }
    }

    #[test]
    fn test_blocking_updates_statistics() {
        let actor_manager = create_test_actor_manager();
        let ip = create_test_ip(105);

        let actor_id = actor_manager.get_or_create_actor(ip, None);

        let stats = actor_manager.stats().snapshot();
        assert_eq!(stats.blocked_actors, 0);

        actor_manager.block_actor(&actor_id, "Test");

        let stats = actor_manager.stats().snapshot();
        assert_eq!(stats.blocked_actors, 1);

        actor_manager.unblock_actor(&actor_id);

        let stats = actor_manager.stats().snapshot();
        assert_eq!(stats.blocked_actors, 0);
    }

    // ========================================================================
    // 4. Session Validation Tests
    // ========================================================================

    #[test]
    fn test_session_token_extraction_and_validation() {
        let session_manager = create_test_session_manager();
        let ip = create_test_ip(100);
        let token_hash = "abc123def456";

        let decision = session_manager.validate_request(token_hash, ip, None);
        assert_eq!(decision, SessionDecision::New);
        assert_eq!(session_manager.len(), 1);

        let decision = session_manager.validate_request(token_hash, ip, None);
        assert_eq!(decision, SessionDecision::Valid);
        assert_eq!(session_manager.len(), 1);
    }

    #[test]
    fn test_valid_session_passes() {
        let session_manager = create_test_session_manager();
        let ip = create_test_ip(101);
        let token_hash = "valid_session_hash";
        let ja4 = "t13d1516h2_fingerprint";

        session_manager.create_session(token_hash, ip, Some(ja4));

        let decision = session_manager.validate_request(token_hash, ip, Some(ja4));
        assert_eq!(decision, SessionDecision::Valid);
    }

    #[test]
    fn test_ja4_mismatch_triggers_alert() {
        let session_manager = create_test_session_manager();
        let ip = create_test_ip(102);
        let token_hash = "session_for_hijack_test";
        let original_ja4 = "t13d1516h2_original_fingerprint";
        let new_ja4 = "t13d1516h2_different_fingerprint";

        session_manager.create_session(token_hash, ip, Some(original_ja4));

        let decision = session_manager.validate_request(token_hash, ip, Some(new_ja4));

        match decision {
            SessionDecision::Suspicious(alert) => {
                assert_eq!(alert.alert_type, HijackType::Ja4Mismatch);
                assert_eq!(alert.original_value, original_ja4);
                assert_eq!(alert.new_value, new_ja4);
                assert!(alert.confidence >= 0.9, "JA4 mismatch should have high confidence");
            }
            _ => panic!("Expected Suspicious decision for JA4 mismatch, got {:?}", decision),
        }
    }

    #[test]
    fn test_expired_session_detected() {
        let config = SessionConfig {
            session_ttl_secs: 0, // Immediate expiration
            idle_timeout_secs: 3600,
            ..SessionConfig::default()
        };
        let session_manager = Arc::new(SessionManager::new(config));
        let ip = create_test_ip(103);
        let token_hash = "expiring_session";

        session_manager.create_session(token_hash, ip, None);
        std::thread::sleep(std::time::Duration::from_millis(10));

        let decision = session_manager.validate_request(token_hash, ip, None);
        assert_eq!(decision, SessionDecision::Expired);
    }

    #[test]
    fn test_session_request_count_increments() {
        let session_manager = create_test_session_manager();
        let ip = create_test_ip(104);
        let token_hash = "counting_session";

        session_manager.validate_request(token_hash, ip, None); // New
        session_manager.validate_request(token_hash, ip, None); // Valid
        session_manager.validate_request(token_hash, ip, None); // Valid
        session_manager.validate_request(token_hash, ip, None); // Valid

        let session = session_manager.get_session(token_hash).unwrap();
        assert_eq!(session.request_count, 4);
    }

    #[test]
    fn test_first_ja4_binds_to_session() {
        let session_manager = create_test_session_manager();
        let ip = create_test_ip(105);
        let token_hash = "binding_session";
        let ja4 = "t13d1516h2_bound_fingerprint";

        session_manager.create_session(token_hash, ip, None);

        let session = session_manager.get_session(token_hash).unwrap();
        assert!(session.bound_ja4.is_none());

        session_manager.validate_request(token_hash, ip, Some(ja4));

        let session = session_manager.get_session(token_hash).unwrap();
        assert_eq!(session.bound_ja4, Some(ja4.to_string()));
    }

    #[test]
    fn test_session_with_no_ja4_binding_allows_any_fingerprint() {
        let config = SessionConfig {
            enable_ja4_binding: false,
            ..SessionConfig::default()
        };
        let session_manager = Arc::new(SessionManager::new(config));
        let ip = create_test_ip(106);
        let token_hash = "unbound_session";

        session_manager.create_session(token_hash, ip, Some("original_ja4"));

        let decision = session_manager.validate_request(token_hash, ip, Some("different_ja4"));
        assert_eq!(decision, SessionDecision::Valid);
    }

    // ========================================================================
    // 5. Admin API Integration Tests
    // ========================================================================

    #[test]
    fn test_get_actors_returns_real_data() {
        let actor_manager = create_test_actor_manager();

        for i in 0..5 {
            let ip = create_test_ip(i);
            let actor_id = actor_manager.get_or_create_actor(ip, None);
            actor_manager.record_rule_match(&actor_id, &format!("rule-{}", i), 10.0, "test");
        }

        let api_handler = api::ApiHandler::builder()
            .actor_manager(Arc::clone(&actor_manager))
            .build();

        let actors = api_handler.handle_list_actors(10);

        assert_eq!(actors.len(), 5);
        for actor in &actors {
            assert!(!actor.actor_id.is_empty());
            assert_eq!(actor.rule_matches.len(), 1);
            assert_eq!(actor.risk_score, 10.0);
        }
    }

    #[test]
    fn test_get_sessions_returns_real_data() {
        let session_manager = create_test_session_manager();

        for i in 0..5 {
            let ip = create_test_ip(i);
            let token_hash = format!("session_token_{}", i);
            session_manager.create_session(&token_hash, ip, Some(&format!("ja4_{}", i)));
        }

        let api_handler = api::ApiHandler::builder()
            .session_manager(Arc::clone(&session_manager))
            .build();

        let sessions = api_handler.handle_list_sessions(10);

        assert_eq!(sessions.len(), 5);
        for session in &sessions {
            assert!(!session.session_id.is_empty());
            assert!(session.session_id.starts_with("sess-"));
            assert!(session.bound_ja4.is_some());
        }
    }

    #[test]
    fn test_get_actor_stats_returns_real_data() {
        let actor_manager = create_test_actor_manager();

        for i in 0..10 {
            let ip = create_test_ip(i);
            let actor_id = actor_manager.get_or_create_actor(ip, None);
            actor_manager.record_rule_match(&actor_id, "test-rule", 5.0, "test");
            if i % 3 == 0 {
                actor_manager.block_actor(&actor_id, "Test block");
            }
        }

        let api_handler = api::ApiHandler::builder()
            .actor_manager(Arc::clone(&actor_manager))
            .build();

        let stats = api_handler.handle_actor_stats();

        assert!(stats.is_some());
        let stats = stats.unwrap();
        assert_eq!(stats.total_actors, 10);
        assert_eq!(stats.blocked_actors, 4); // 0, 3, 6, 9
        assert_eq!(stats.total_created, 10);
        assert_eq!(stats.total_rule_matches, 10);
    }

    #[test]
    fn test_get_session_stats_returns_real_data() {
        let session_manager = create_test_session_manager();

        for i in 0..5 {
            let ip = create_test_ip(i);
            let token_hash = format!("session_{}", i);
            session_manager.create_session(&token_hash, ip, None);
        }

        let api_handler = api::ApiHandler::builder()
            .session_manager(Arc::clone(&session_manager))
            .build();

        let stats = api_handler.handle_session_stats();

        assert!(stats.is_some());
        let stats = stats.unwrap();
        assert_eq!(stats.total_sessions, 5);
        assert_eq!(stats.active_sessions, 5);
        assert_eq!(stats.total_created, 5);
    }

    #[test]
    fn test_api_handler_without_managers_returns_empty() {
        let api_handler = api::ApiHandler::builder().build();

        let actors = api_handler.handle_list_actors(10);
        assert!(actors.is_empty());

        let sessions = api_handler.handle_list_sessions(10);
        assert!(sessions.is_empty());

        let actor_stats = api_handler.handle_actor_stats();
        assert!(actor_stats.is_none());

        let session_stats = api_handler.handle_session_stats();
        assert!(session_stats.is_none());
    }

    #[test]
    fn test_list_actors_respects_limit() {
        let actor_manager = create_test_actor_manager();

        for i in 0..20 {
            let ip = create_test_ip(i);
            actor_manager.get_or_create_actor(ip, None);
        }

        let api_handler = api::ApiHandler::builder()
            .actor_manager(Arc::clone(&actor_manager))
            .build();

        let actors = api_handler.handle_list_actors(5);
        assert_eq!(actors.len(), 5);

        let actors = api_handler.handle_list_actors(100);
        assert_eq!(actors.len(), 20);
    }

    // ========================================================================
    // 6. Combined Actor + Session Integration Tests
    // ========================================================================

    #[test]
    fn test_session_bound_to_actor() {
        let actor_manager = create_test_actor_manager();
        let session_manager = create_test_session_manager();
        let ip = create_test_ip(100);
        let fingerprint = "combined_test_fingerprint";
        let token_hash = "combined_session_token";

        let actor_id = actor_manager.get_or_create_actor(ip, Some(fingerprint));
        session_manager.create_session(token_hash, ip, Some(fingerprint));
        session_manager.bind_to_actor(token_hash, &actor_id);

        let session = session_manager.get_session(token_hash).unwrap();
        assert_eq!(session.actor_id, Some(actor_id.clone()));

        let actor_sessions = session_manager.get_actor_sessions(&actor_id);
        assert_eq!(actor_sessions.len(), 1);
        assert_eq!(actor_sessions[0].token_hash, token_hash);
    }

    #[test]
    fn test_multi_session_single_actor() {
        let actor_manager = create_test_actor_manager();
        let session_manager = create_test_session_manager();
        let ip = create_test_ip(101);
        let fingerprint = "multi_session_fingerprint";

        let actor_id = actor_manager.get_or_create_actor(ip, Some(fingerprint));

        session_manager.create_session("session_tab_1", ip, Some(fingerprint));
        session_manager.create_session("session_tab_2", ip, Some(fingerprint));
        session_manager.create_session("session_mobile", ip, Some(fingerprint));

        session_manager.bind_to_actor("session_tab_1", &actor_id);
        session_manager.bind_to_actor("session_tab_2", &actor_id);
        session_manager.bind_to_actor("session_mobile", &actor_id);

        let actor_sessions = session_manager.get_actor_sessions(&actor_id);
        assert_eq!(actor_sessions.len(), 3);
    }

    #[test]
    fn test_blocked_actor_affects_all_sessions() {
        let actor_manager = create_test_actor_manager();
        let session_manager = create_test_session_manager();
        let ip = create_test_ip(102);
        let fingerprint = "blocked_user_fingerprint";

        let actor_id = actor_manager.get_or_create_actor(ip, Some(fingerprint));
        session_manager.create_session("blocked_user_session_1", ip, Some(fingerprint));
        session_manager.create_session("blocked_user_session_2", ip, Some(fingerprint));
        session_manager.bind_to_actor("blocked_user_session_1", &actor_id);
        session_manager.bind_to_actor("blocked_user_session_2", &actor_id);

        actor_manager.block_actor(&actor_id, "Malicious activity");

        assert!(actor_manager.is_blocked(&actor_id));

        let sessions = session_manager.get_actor_sessions(&actor_id);
        assert_eq!(sessions.len(), 2);

        let actor_id_check = actor_manager.get_or_create_actor(ip, Some(fingerprint));
        assert_eq!(actor_id, actor_id_check);
        assert!(actor_manager.is_blocked(&actor_id_check));
    }

    #[test]
    fn test_risk_accumulation_workflow() {
        let actor_manager = create_test_actor_manager();
        let ip = create_test_ip(103);

        let actor_id = actor_manager.get_or_create_actor(ip, None);

        actor_manager.record_rule_match(&actor_id, "sqli-001", 30.0, "sqli");
        let actor = actor_manager.get_actor(&actor_id).unwrap();
        assert_eq!(actor.risk_score, 30.0);
        assert!(!actor_manager.is_blocked(&actor_id));

        actor_manager.record_rule_match(&actor_id, "sqli-002", 40.0, "sqli");
        let actor = actor_manager.get_actor(&actor_id).unwrap();
        assert_eq!(actor.risk_score, 70.0);
        assert!(!actor_manager.is_blocked(&actor_id));

        actor_manager.record_rule_match(&actor_id, "xss-001", 20.0, "xss");
        let actor = actor_manager.get_actor(&actor_id).unwrap();
        assert_eq!(actor.risk_score, 90.0);

        if actor.risk_score >= 80.0 {
            actor_manager.block_actor(&actor_id, "Risk threshold exceeded");
        }

        assert!(actor_manager.is_blocked(&actor_id));
    }
}
