//! JA4+ TLS/HTTP Fingerprinting Module
//!
//! Implements JA4 (TLS) and JA4H (HTTP) fingerprinting for client identification.
//! JA4 provides stable, human-readable fingerprints that persist across IP rotation.
//!
//! # Phase 3 Module (Feature Migration from risk-server)
//!
//! ## JA4 Format
//! `{protocol}{version}{sni}{cipher_count}{ext_count}_{cipher_hash}_{ext_hash}`
//! Example: `t13d1516h2_8daaf6152771_e5627efa2ab1`
//!
//! ## JA4H Format
//! `{method}{version}{cookie}{referer}{accept_lang}_{header_hash}_{cookie_hash}`
//! Example: `ge11cnrn_a1b2c3d4e5f6_000000000000`
//!
//! ## Feature Flags
//! - `ENABLE_PINGORA_JA4=true`: Enable JA4 fingerprinting in Pingora
//!
//! @see https://github.com/FoxIO-LLC/ja4

mod integrity;
mod ja4;

pub use ja4::{
    // Analysis
    analyze_ja4,
    analyze_ja4h,
    extract_client_fingerprint,
    fingerprints_match,
    // Generation
    generate_ja4h,
    is_valid_ja4,
    is_valid_ja4h,
    matches_pattern,
    // Parsing
    parse_ja4_from_header,
    // Utilities
    sha256_first12,
    ClientFingerprint,
    HttpHeaders,
    Ja4Analysis,
    // Types
    Ja4Fingerprint,
    Ja4Protocol,
    Ja4SniType,
    Ja4hAnalysis,
    Ja4hFingerprint,
};

pub use integrity::{
    analyze_integrity, analyze_integrity_with_ja4, analyze_ja4_spoofing, BrowserJa4Profile,
    IntegrityAnalysis, Ja4SpoofingAnalysis,
};
