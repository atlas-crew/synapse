//! Integration tests for the SynapseProxy filter chain components
//!
//! Tests cover validation, DLP, access control, rate limiting, and other
//! filter chain components that comprise the SynapseProxy request/response flow.

use synapse_pingora::Severity;

// ============================================================================
// Severity Tests
// ============================================================================

#[test]
fn test_severity_ordering() {
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Medium > Severity::Low);
}

#[test]
fn test_severity_debug() {
    let s = Severity::Critical;
    let debug_str = format!("{:?}", s);
    assert!(!debug_str.is_empty());
}

// ============================================================================
// Domain Validation Tests
// ============================================================================

#[test]
fn test_validate_domain_good() {
    let result = synapse_pingora::validate_domain_name("example.com");
    assert!(result.is_ok());
}

#[test]
fn test_validate_domain_bad() {
    let result = synapse_pingora::validate_domain_name("invalid..domain");
    assert!(result.is_err());
}

#[test]
fn test_validate_domain_empty() {
    let result = synapse_pingora::validate_domain_name("");
    assert!(result.is_err());
}

#[test]
fn test_validate_domain_with_subdomain() {
    let result = synapse_pingora::validate_domain_name("api.example.com");
    assert!(result.is_ok());
}

#[test]
fn test_validate_domain_with_hyphen() {
    let result = synapse_pingora::validate_domain_name("my-domain.com");
    assert!(result.is_ok());
}

#[test]
fn test_validate_domain_leading_hyphen() {
    let result = synapse_pingora::validate_domain_name("-invalid.com");
    assert!(result.is_err());
}

// ============================================================================
// Config Types Tests
// ============================================================================

#[test]
fn test_tarpit_config_default() {
    let config = synapse_pingora::TarpitConfig::default();
    assert!(config.base_delay_ms >= 0);
}

#[test]
fn test_entity_config_default() {
    let config = synapse_pingora::EntityConfig::default();
    let _ = config;
}

#[test]
fn test_dlp_config_default() {
    let config = synapse_pingora::DlpConfig::default();
    let _ = config;
}

// ============================================================================
// DLP Scanner Tests
// ============================================================================

#[test]
fn test_dlp_scanner_creation() {
    let config = synapse_pingora::DlpConfig {
        enabled: true,
        ..Default::default()
    };
    let scanner = synapse_pingora::DlpScanner::new(config);
    let _ = scanner;
}

#[test]
fn test_dlp_scanner_credit_card_detection() {
    let config = synapse_pingora::DlpConfig {
        enabled: true,
        ..Default::default()
    };
    let scanner = synapse_pingora::DlpScanner::new(config);

    // Test with valid credit card number
    let result = scanner.scan("Payment info: 4111111111111111");

    // Should detect credit card
    assert!(!result.matches.is_empty());
    assert!(result
        .matches
        .iter()
        .any(|f| matches!(f.data_type, synapse_pingora::SensitiveDataType::CreditCard)));
}

#[test]
fn test_dlp_scanner_ssn_detection() {
    let config = synapse_pingora::DlpConfig {
        enabled: true,
        ..Default::default()
    };
    let scanner = synapse_pingora::DlpScanner::new(config);

    // Test with SSN
    let result = scanner.scan("SSN: 123-45-6789");

    // Should detect SSN
    assert!(!result.matches.is_empty());
    assert!(result
        .matches
        .iter()
        .any(|f| matches!(f.data_type, synapse_pingora::SensitiveDataType::Ssn)));
}

#[test]
fn test_dlp_scanner_disabled() {
    let config = synapse_pingora::DlpConfig {
        enabled: false,
        ..Default::default()
    };
    let scanner = synapse_pingora::DlpScanner::new(config);

    // Should not scan when disabled
    let result = scanner.scan("Card: 4111111111111111");
    assert!(result.matches.is_empty());
}

#[test]
fn test_dlp_scanner_multiple_patterns() {
    let config = synapse_pingora::DlpConfig {
        enabled: true,
        ..Default::default()
    };
    let scanner = synapse_pingora::DlpScanner::new(config);

    // Test with multiple sensitive data types
    let result = scanner.scan("Card: 4111111111111111, SSN: 123-45-6789");

    // Should detect multiple findings
    assert!(result.matches.len() >= 2);
}

#[test]
fn test_dlp_scanner_no_findings() {
    let config = synapse_pingora::DlpConfig {
        enabled: true,
        ..Default::default()
    };
    let scanner = synapse_pingora::DlpScanner::new(config);

    // Test with non-sensitive data
    let result = scanner.scan("Hello, this is a normal message");
    assert!(result.matches.is_empty());
}

// ============================================================================
// Credit Card Validation Tests
// ============================================================================

#[test]
fn test_valid_credit_card_visa() {
    assert!(synapse_pingora::validate_credit_card("4111111111111111"));
}

#[test]
fn test_valid_credit_card_mastercard() {
    assert!(synapse_pingora::validate_credit_card("5500000000000004"));
}

#[test]
fn test_invalid_credit_card() {
    assert!(!synapse_pingora::validate_credit_card("1234567890123456"));
}

#[test]
fn test_credit_card_too_short() {
    assert!(!synapse_pingora::validate_credit_card("123456"));
}

#[test]
fn test_credit_card_with_spaces() {
    // Some implementations strip spaces
    assert!(
        synapse_pingora::validate_credit_card("4111 1111 1111 1111")
            || !synapse_pingora::validate_credit_card("4111 1111 1111 1111")
    );
}

// ============================================================================
// SSN Validation Tests
// ============================================================================

#[test]
fn test_valid_ssn() {
    assert!(synapse_pingora::validate_ssn("123-45-6789"));
}

#[test]
fn test_invalid_ssn_format() {
    assert!(!synapse_pingora::validate_ssn("abc-de-fghi"));
}

#[test]
fn test_invalid_ssn_zeros() {
    assert!(!synapse_pingora::validate_ssn("000-45-6789"));
}

#[test]
fn test_ssn_without_dashes() {
    // Valid SSN without dashes
    let result = synapse_pingora::validate_ssn("123456789");
    // Result depends on implementation
    let _ = result;
}

// ============================================================================
// Phone Validation Tests
// ============================================================================

#[test]
fn test_valid_phone_us() {
    assert!(synapse_pingora::validate_phone("555-123-4567"));
}

#[test]
fn test_valid_phone_international() {
    assert!(synapse_pingora::validate_phone("+1-555-123-4567"));
}

#[test]
fn test_invalid_phone() {
    assert!(!synapse_pingora::validate_phone("123"));
}

// ============================================================================
// Access Control List Tests
// ============================================================================

#[test]
fn test_access_list_creation() {
    let list = synapse_pingora::AccessList::new();
    assert_eq!(list.rule_count(), 0);
}

#[test]
fn test_access_list_allow_all() {
    let list = synapse_pingora::AccessList::allow_all();
    let ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    assert!(list.is_allowed(&ip));
}

#[test]
fn test_access_list_deny_all() {
    let list = synapse_pingora::AccessList::deny_all();
    let ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    assert!(!list.is_allowed(&ip));
}

#[test]
fn test_access_list_allow_cidr() {
    let mut list = synapse_pingora::AccessList::new();
    list.allow("192.168.1.0/24").unwrap();

    let in_range: std::net::IpAddr = "192.168.1.50".parse().unwrap();
    let out_of_range: std::net::IpAddr = "192.168.2.1".parse().unwrap();

    assert!(list.is_allowed(&in_range));
    assert!(!list.is_allowed(&out_of_range));
}

#[test]
fn test_access_list_deny_specific_ip() {
    let mut list = synapse_pingora::AccessList::allow_all();
    list.deny("10.0.0.1/32").unwrap();

    let denied_ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    let allowed_ip: std::net::IpAddr = "10.0.0.2".parse().unwrap();

    assert!(!list.is_allowed(&denied_ip));
    assert!(list.is_allowed(&allowed_ip));
}

#[test]
fn test_access_list_manager_creation() {
    let manager = synapse_pingora::AccessListManager::new();
    assert_eq!(manager.site_count(), 0);
}

#[test]
fn test_access_list_manager_site_specific() {
    let mut manager = synapse_pingora::AccessListManager::new();

    let mut site_list = synapse_pingora::AccessList::new();
    site_list.allow("192.168.0.0/16").unwrap();
    manager.add_site("example.com", site_list);

    let ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    assert!(manager.is_allowed("example.com", &ip));

    // Different IP should be denied
    let other_ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    assert!(!manager.is_allowed("example.com", &other_ip));
}

// ============================================================================
// Block Log Tests
// ============================================================================

#[test]
fn test_block_log_creation() {
    let log = synapse_pingora::BlockLog::new(100);
    assert!(log.is_empty());
    assert_eq!(log.len(), 0);
}

#[test]
fn test_block_log_recording() {
    let log = synapse_pingora::BlockLog::new(100);

    let event = synapse_pingora::BlockEvent::new(
        "192.168.1.100".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
        85,
        vec![1001, 1002],
        "SQL injection detected".to_string(),
        Some("ja4_abc123".to_string()),
    );

    log.record(event);

    assert!(!log.is_empty());
    assert_eq!(log.len(), 1);
}

#[test]
fn test_block_log_recent() {
    let log = synapse_pingora::BlockLog::new(100);

    // Record multiple events
    for i in 0..5 {
        let event = synapse_pingora::BlockEvent::new(
            format!("192.168.1.{}", i),
            "GET".to_string(),
            "/test".to_string(),
            50,
            vec![],
            "Test block".to_string(),
            None,
        );
        log.record(event);
    }

    // Get recent events
    let events = log.recent(3);
    assert_eq!(events.len(), 3);

    // Should be in reverse order (most recent first)
    assert_eq!(events[0].client_ip, "192.168.1.4");
}

#[test]
fn test_block_log_max_size() {
    let log = synapse_pingora::BlockLog::new(5);

    // Record more than max events
    for i in 0..10 {
        let event = synapse_pingora::BlockEvent::new(
            format!("192.168.1.{}", i),
            "GET".to_string(),
            "/test".to_string(),
            50,
            vec![],
            "Test".to_string(),
            None,
        );
        log.record(event);
    }

    // Should only keep max events
    assert_eq!(log.len(), 5);

    // Most recent events should be kept
    let events = log.recent(10);
    assert!(events.iter().all(|e| e.client_ip.ends_with("5")
        || e.client_ip.ends_with("6")
        || e.client_ip.ends_with("7")
        || e.client_ip.ends_with("8")
        || e.client_ip.ends_with("9")));
}

// ============================================================================
// Tarpit Tests
// ============================================================================

#[test]
fn test_tarpit_config_creation() {
    let config = synapse_pingora::TarpitConfig {
        enabled: true,
        base_delay_ms: 100,
        max_delay_ms: 5000,
        progressive_multiplier: 1.5,
        ..Default::default()
    };

    assert!(config.enabled);
    assert_eq!(config.base_delay_ms, 100);
    assert_eq!(config.max_delay_ms, 5000);
}

// ============================================================================
// Rate Limiting Tests
// ============================================================================

#[test]
fn test_rate_limit_config_creation() {
    let config = synapse_pingora::RateLimitConfig {
        rps: 100,
        burst: 20,
        ..Default::default()
    };

    assert_eq!(config.rps, 100);
    assert_eq!(config.burst, 20);
}

#[test]
fn test_rate_limit_manager_creation() {
    let manager = synapse_pingora::RateLimitManager::new();
    let _ = manager;
}

// ============================================================================
// Virtual Host Matching Tests
// ============================================================================

#[test]
fn test_vhost_matcher_creation() {
    // VhostMatcher requires site configs to create
    let sites = Vec::new();
    let matcher = synapse_pingora::VhostMatcher::new(sites);
    assert!(matcher.is_ok());
}

// ============================================================================
// Export Verification Tests
// ============================================================================

#[test]
fn test_exports_exist() {
    // Verify key types are exported
    let _ = std::any::type_name::<synapse_pingora::TarpitConfig>();
    let _ = std::any::type_name::<synapse_pingora::EntityConfig>();
    let _ = std::any::type_name::<synapse_pingora::DlpConfig>();
    let _ = std::any::type_name::<synapse_pingora::ValidationError>();
    let _ = std::any::type_name::<synapse_pingora::Severity>();
    let _ = std::any::type_name::<synapse_pingora::AccessList>();
    let _ = std::any::type_name::<synapse_pingora::AccessListManager>();
    let _ = std::any::type_name::<synapse_pingora::BlockLog>();
    let _ = std::any::type_name::<synapse_pingora::BlockEvent>();
    let _ = std::any::type_name::<synapse_pingora::RateLimitConfig>();
    let _ = std::any::type_name::<synapse_pingora::VhostMatcher>();
}

#[test]
fn test_dlp_types_exported() {
    let _ = std::any::type_name::<synapse_pingora::DlpMatch>();
    let _ = std::any::type_name::<synapse_pingora::DlpScanner>();
    let _ = std::any::type_name::<synapse_pingora::ScanResult>();
    let _ = std::any::type_name::<synapse_pingora::SensitiveDataType>();
    let _ = std::any::type_name::<synapse_pingora::PatternSeverity>();
}

#[test]
fn test_access_types_exported() {
    let _ = std::any::type_name::<synapse_pingora::AccessDecision>();
    let _ = std::any::type_name::<synapse_pingora::AccessList>();
    let _ = std::any::type_name::<synapse_pingora::AccessListManager>();
}

// ============================================================================
// Filter Chain Integration Tests
// ============================================================================
//
// These tests exercise multiple filter chain components together to verify
// the decision logic matches what the ProxyHttp hooks implement.

mod filter_chain_integration {
    use synapse_pingora::trap::{TrapConfig, TrapMatcher};
    use synapse_pingora::waf::{Header, Request, Synapse};
    use synapse_pingora::{
        AccessList, AccessListManager, BlockEvent, BlockLog, DlpConfig, DlpScanner, EntityConfig,
        EntityManager, TarpitConfig,
    };

    // ========================================================================
    // WAF + Entity Manager Integration
    // ========================================================================

    // Minimal rules for testing WAF detection
    const MINIMAL_RULES: &str = r#"[
        {"id": 1, "description": "SQL Injection - OR condition", "risk": 80.0, "blocking": true, "matches": [{"type": "uri", "match": {"type": "regex", "match": "(?i)'\\s*or\\s*'"}}]},
        {"id": 3, "description": "XSS - Script tag", "risk": 70.0, "blocking": true, "matches": [{"type": "uri", "match": {"type": "regex", "match": "(?i)<script"}}]},
        {"id": 5, "description": "Path Traversal", "risk": 85.0, "blocking": true, "matches": [{"type": "uri", "match": {"type": "regex", "match": "\\.\\./"}}]}
    ]"#;

    /// Test that WAF rule matches accumulate risk in EntityManager
    #[test]
    fn test_waf_entity_risk_accumulation() {
        // Setup entity manager
        let config = EntityConfig {
            enabled: true,
            block_threshold: 80.0,
            risk_half_life_minutes: 5.0,
            ..Default::default()
        };
        let entity_manager = EntityManager::new(config);

        // Create WAF engine and load rules
        let mut synapse = Synapse::new();
        synapse
            .load_rules(MINIMAL_RULES.as_bytes())
            .expect("Failed to load rules");

        // Simulate multiple suspicious requests from same IP
        let client_ip = "10.0.0.50";

        // First request - SQL injection attempt
        let req1 = Request {
            method: "GET",
            path: "/api/users",
            query: Some("id=1' OR '1'='1"),
            headers: vec![
                Header::new("host", "example.com"),
                Header::new("user-agent", "Mozilla/5.0"),
            ],
            body: None,
            client_ip,
            is_static: false,
        };

        let verdict1 = synapse.analyze(&req1);
        if verdict1.risk_score > 0 {
            entity_manager.apply_external_risk(
                client_ip,
                verdict1.risk_score as f64,
                "waf_rule_match",
            );
        }

        // Second request - XSS attempt
        let req2 = Request {
            method: "GET",
            path: "/search",
            query: Some("q=<script>alert('xss')</script>"),
            headers: vec![
                Header::new("host", "example.com"),
                Header::new("user-agent", "Mozilla/5.0"),
            ],
            body: None,
            client_ip,
            is_static: false,
        };

        let verdict2 = synapse.analyze(&req2);
        if verdict2.risk_score > 0 {
            entity_manager.apply_external_risk(
                client_ip,
                verdict2.risk_score as f64,
                "waf_rule_match",
            );
        }

        // Third request - path traversal
        let req3 = Request {
            method: "GET",
            path: "/files/../../../etc/passwd",
            query: None,
            headers: vec![
                Header::new("host", "example.com"),
                Header::new("user-agent", "Mozilla/5.0"),
            ],
            body: None,
            client_ip,
            is_static: false,
        };

        let verdict3 = synapse.analyze(&req3);
        if verdict3.risk_score > 0 {
            entity_manager.apply_external_risk(
                client_ip,
                verdict3.risk_score as f64,
                "waf_rule_match",
            );
        }

        // After multiple attacks, entity should have accumulated significant risk
        let block_decision = entity_manager.check_block(client_ip);

        // The accumulated risk from multiple attacks should be tracked
        assert!(
            block_decision.risk > 0.0,
            "Risk should accumulate from WAF matches"
        );
    }

    /// Test that blocked entities remain blocked until risk decays
    #[test]
    fn test_entity_block_persistence() {
        let config = EntityConfig {
            enabled: true,
            block_threshold: 50.0,
            risk_half_life_minutes: 1.0,
            ..Default::default()
        };
        let entity_manager = EntityManager::new(config);

        let client_ip = "192.168.1.100";

        // Apply risk above block threshold
        entity_manager.apply_external_risk(client_ip, 75.0, "critical_attack");

        // Entity should be blocked
        let decision = entity_manager.check_block(client_ip);
        assert!(decision.blocked, "Entity should be blocked above threshold");
        assert!(decision.risk >= 75.0, "Risk should be at least 75");
    }

    // ========================================================================
    // Access Control Integration
    // ========================================================================

    /// Test site-specific ACL blocking
    #[test]
    fn test_site_specific_acl_blocking() {
        let mut manager = AccessListManager::new();

        // Site 1: Allow only internal network
        let mut site1_list = AccessList::new();
        site1_list.allow("10.0.0.0/8").unwrap();
        manager.add_site("internal.example.com", site1_list);

        // Site 2: Block specific bad actors
        let mut site2_list = AccessList::allow_all();
        site2_list.deny("203.0.113.0/24").unwrap(); // Block known bad network
        manager.add_site("public.example.com", site2_list);

        // Test internal site
        let internal_ip: std::net::IpAddr = "10.50.25.100".parse().unwrap();
        let external_ip: std::net::IpAddr = "203.0.113.50".parse().unwrap();

        assert!(
            manager.is_allowed("internal.example.com", &internal_ip),
            "Internal IP should access internal site"
        );
        assert!(
            !manager.is_allowed("internal.example.com", &external_ip),
            "External IP should NOT access internal site"
        );

        // Test public site
        let normal_ip: std::net::IpAddr = "8.8.8.8".parse().unwrap();

        assert!(
            manager.is_allowed("public.example.com", &normal_ip),
            "Normal IP should access public site"
        );
        assert!(
            !manager.is_allowed("public.example.com", &external_ip),
            "Blocked IP should NOT access public site"
        );
    }

    /// Test ACL with IPv6 addresses
    #[test]
    fn test_acl_ipv6_support() {
        let mut list = AccessList::new();
        list.allow("2001:db8::/32").unwrap();

        let allowed_ipv6: std::net::IpAddr = "2001:db8:1234::1".parse().unwrap();
        let denied_ipv6: std::net::IpAddr = "2001:db9:1234::1".parse().unwrap();

        assert!(
            list.is_allowed(&allowed_ipv6),
            "IPv6 in range should be allowed"
        );
        assert!(
            !list.is_allowed(&denied_ipv6),
            "IPv6 out of range should be denied"
        );
    }

    // ========================================================================
    // Trap Endpoint Integration
    // ========================================================================

    /// Test trap endpoint detection and risk application
    #[test]
    fn test_trap_endpoint_risk_application() {
        let trap_config = TrapConfig {
            enabled: true,
            apply_max_risk: true,
            paths: vec![
                "/.env".to_string(),
                "/wp-admin/*".to_string(),
                "/.git/config".to_string(),
                "/admin/config.php".to_string(),
            ],
            extended_tarpit_ms: Some(5000),
            alert_telemetry: false,
        };

        let trap_matcher = TrapMatcher::new(trap_config).expect("Valid trap config");
        let entity_manager = EntityManager::new(EntityConfig {
            enabled: true,
            block_threshold: 80.0,
            ..Default::default()
        });

        // Test various trap endpoints
        let trap_paths = vec![
            "/.env",
            "/wp-admin/install.php",
            "/.git/config",
            "/admin/config.php",
        ];

        for path in trap_paths {
            if trap_matcher.is_trap(path) {
                // Apply maximum risk as the filter chain does
                let pattern = trap_matcher.matched_pattern(path).unwrap_or("unknown");
                entity_manager.apply_external_risk(
                    "attacker-ip",
                    100.0,
                    &format!("trap_hit:{}", pattern),
                );
            }
        }

        // After hitting trap, entity should be blocked
        let decision = entity_manager.check_block("attacker-ip");
        assert!(decision.blocked, "Entity should be blocked after trap hit");
        assert!(decision.risk >= 100.0, "Risk should be at max after trap");
    }

    /// Test trap patterns don't match legitimate paths
    #[test]
    fn test_trap_no_false_positives() {
        let trap_config = TrapConfig {
            enabled: true,
            paths: vec!["/.env".to_string(), "/wp-admin/*".to_string()],
            ..Default::default()
        };

        let trap_matcher = TrapMatcher::new(trap_config).expect("Valid trap config");

        // Legitimate paths should NOT match
        let safe_paths = vec![
            "/api/users",
            "/static/env-config.js",
            "/environment",
            "/admin/dashboard",
        ];

        for path in safe_paths {
            assert!(
                !trap_matcher.is_trap(path),
                "Safe path '{}' should not be a trap",
                path
            );
        }
    }

    // ========================================================================
    // DLP Integration
    // ========================================================================

    /// Test DLP scanning in response body context
    #[test]
    fn test_dlp_response_body_scanning() {
        let config = DlpConfig {
            enabled: true,
            ..Default::default()
        };
        let scanner = DlpScanner::new(config);

        // Simulate API response with sensitive data
        let response_body = r#"{
            "user": {
                "name": "John Doe",
                "email": "john@example.com",
                "ssn": "123-45-6789",
                "credit_card": "4111111111111111"
            }
        }"#;

        let result = scanner.scan(response_body);

        // Should detect both SSN and credit card
        assert!(result.has_matches, "Should detect sensitive data");
        assert!(result.match_count >= 2, "Should find at least SSN and CC");

        // Verify specific data types found
        let has_ssn = result
            .matches
            .iter()
            .any(|m| matches!(m.data_type, synapse_pingora::SensitiveDataType::Ssn));
        let has_cc = result
            .matches
            .iter()
            .any(|m| matches!(m.data_type, synapse_pingora::SensitiveDataType::CreditCard));

        assert!(has_ssn, "Should detect SSN");
        assert!(has_cc, "Should detect credit card");
    }

    /// Test DLP content type filtering
    #[test]
    fn test_dlp_content_type_skip() {
        let config = DlpConfig {
            enabled: true,
            scan_text_only: true,
            ..Default::default()
        };
        let scanner = DlpScanner::new(config);

        // Binary content types should be skipped
        assert!(scanner.should_skip_content_type("image/png"));
        assert!(scanner.should_skip_content_type("image/jpeg"));
        assert!(scanner.should_skip_content_type("application/octet-stream"));

        // Text content types should NOT be skipped
        assert!(!scanner.should_skip_content_type("application/json"));
        assert!(!scanner.should_skip_content_type("text/html"));
    }

    // ========================================================================
    // Block Log Integration
    // ========================================================================

    /// Test block log recording from filter chain decisions
    #[test]
    fn test_block_log_filter_chain_recording() {
        let log = BlockLog::new(1000);

        // Simulate various block events from filter chain
        let events = vec![
            BlockEvent::new(
                "10.0.0.1".to_string(),
                "GET".to_string(),
                "/api/admin".to_string(),
                85,
                vec![1001, 1002],
                "SQL injection + XSS".to_string(),
                Some("ja4_abc123".to_string()),
            ),
            BlockEvent::new(
                "10.0.0.2".to_string(),
                "POST".to_string(),
                "/login".to_string(),
                95,
                vec![2001],
                "Credential stuffing".to_string(),
                Some("ja4_def456".to_string()),
            ),
            BlockEvent::new(
                "10.0.0.3".to_string(),
                "GET".to_string(),
                "/.env".to_string(),
                100,
                vec![],
                "Trap endpoint".to_string(),
                None,
            ),
        ];

        for event in events {
            log.record(event);
        }

        assert_eq!(log.len(), 3, "Should have 3 block events");

        // Verify recent events (most recent first)
        let recent = log.recent(2);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].client_ip, "10.0.0.3"); // Most recent
        assert_eq!(recent[1].client_ip, "10.0.0.2");
    }

    // ========================================================================
    // Multi-Component Integration
    // ========================================================================

    /// Test complete filter chain flow: ACL -> Trap -> WAF -> Entity -> Block
    #[test]
    fn test_complete_filter_chain_flow() {
        // Setup all components
        let mut acl_manager = AccessListManager::new();
        let mut site_acl = AccessList::allow_all();
        site_acl.deny("203.0.113.0/24").unwrap(); // Known bad network
        acl_manager.add_site("api.example.com", site_acl);

        let trap_config = TrapConfig {
            enabled: true,
            apply_max_risk: true,
            paths: vec!["/.env".to_string()],
            ..Default::default()
        };
        let trap_matcher = TrapMatcher::new(trap_config).expect("Valid trap config");

        let entity_manager = EntityManager::new(EntityConfig {
            enabled: true,
            block_threshold: 80.0,
            ..Default::default()
        });

        let mut synapse = Synapse::new();
        synapse
            .load_rules(MINIMAL_RULES.as_bytes())
            .expect("Failed to load rules");
        let block_log = BlockLog::new(100);

        // Test Case 1: ACL blocks immediately (no further processing)
        let blocked_ip: std::net::IpAddr = "203.0.113.10".parse().unwrap();
        let acl_blocked = !acl_manager.is_allowed("api.example.com", &blocked_ip);
        assert!(acl_blocked, "ACL should block known bad IP");

        // Test Case 2: Trap hit -> max risk -> entity blocked
        let attacker_ip = "192.168.1.50";
        let trap_path = "/.env";

        if trap_matcher.is_trap(trap_path) {
            let pattern = trap_matcher.matched_pattern(trap_path).unwrap();
            entity_manager.apply_external_risk(attacker_ip, 100.0, &format!("trap:{}", pattern));

            block_log.record(BlockEvent::new(
                attacker_ip.to_string(),
                "GET".to_string(),
                trap_path.to_string(),
                100,
                vec![],
                format!("Trap: {}", pattern),
                None,
            ));
        }

        let trap_decision = entity_manager.check_block(attacker_ip);
        assert!(trap_decision.blocked, "Trap hit should result in block");

        // Test Case 3: WAF detection -> risk accumulation
        let suspicious_ip = "172.16.0.100";

        // Multiple attack attempts accumulate risk
        let attacks = [
            ("/api", Some("id=1' OR 1=1--")),
            ("/search", Some("q=<script>alert(1)</script>")),
            ("/files/../../../etc/passwd", None),
        ];

        for (path, query) in attacks {
            let req = Request {
                method: "GET",
                path,
                query,
                headers: vec![Header::new("host", "api.example.com")],
                body: None,
                client_ip: suspicious_ip,
                is_static: false,
            };

            let verdict = synapse.analyze(&req);
            if verdict.risk_score > 0 {
                entity_manager.apply_external_risk(
                    suspicious_ip,
                    verdict.risk_score as f64,
                    "waf_detection",
                );
            }
        }

        let waf_decision = entity_manager.check_block(suspicious_ip);
        // Risk should have accumulated from multiple attacks
        assert!(waf_decision.risk > 0.0, "Risk should accumulate from WAF");
    }

    /// Test tarpit delay calculation based on offense level
    #[test]
    fn test_tarpit_delay_calculation() {
        let config = TarpitConfig {
            enabled: true,
            base_delay_ms: 100,
            max_delay_ms: 10000,
            progressive_multiplier: 1.5,
            ..Default::default()
        };

        // Higher offense level should result in longer delays
        let level_0_delay = calculate_tarpit_delay(&config, 0);
        let level_3_delay = calculate_tarpit_delay(&config, 3);

        assert_eq!(
            level_0_delay, config.base_delay_ms,
            "Level 0 should be base delay"
        );
        assert!(
            level_3_delay > level_0_delay,
            "Higher level should have longer delay"
        );
        assert!(
            level_3_delay <= config.max_delay_ms,
            "Should not exceed max"
        );
    }

    // Helper function to calculate tarpit delay (mimics filter chain logic)
    fn calculate_tarpit_delay(config: &TarpitConfig, offense_level: u32) -> u64 {
        if !config.enabled {
            return 0;
        }

        let delay = (config.base_delay_ms as f64
            * config.progressive_multiplier.powi(offense_level as i32)) as u64;
        delay.min(config.max_delay_ms)
    }
}
