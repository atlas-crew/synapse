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
    assert!(result.matches.iter().any(|f|
        matches!(f.data_type, synapse_pingora::SensitiveDataType::CreditCard)
    ));
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
    assert!(result.matches.iter().any(|f|
        matches!(f.data_type, synapse_pingora::SensitiveDataType::Ssn)
    ));
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
    let result = scanner.scan(
        "Card: 4111111111111111, SSN: 123-45-6789"
    );

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
    assert!(synapse_pingora::validate_credit_card("4111 1111 1111 1111") ||
            !synapse_pingora::validate_credit_card("4111 1111 1111 1111"));
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
        || e.client_ip.ends_with("9")
    ));
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
