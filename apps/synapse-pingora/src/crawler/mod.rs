//! Crawler Detection and Bad Bot Identification.
//!
//! Features:
//! - 18 legitimate crawler definitions with DNS verification
//! - 45+ bad bot signatures for attack tools and scrapers
//! - Async DNS verification using trust-dns-resolver
//! - LRU cache with TTL using moka crate

pub mod bad_bots;
pub mod cache;
pub mod config;
pub mod detector;
pub mod dns_resolver;
pub mod known_crawlers;

pub use bad_bots::{BadBotSeverity, BadBotSignature, BAD_BOT_SIGNATURES};
pub use cache::VerificationCache;
pub use config::{CrawlerConfig, DnsFailurePolicy};
pub use detector::{
    CrawlerDetection, CrawlerDetector, CrawlerStats, CrawlerStatsSnapshot,
    CrawlerVerificationResult, VerificationMethod,
};
pub use dns_resolver::DnsResolver;
pub use known_crawlers::{CrawlerDefinition, KNOWN_CRAWLERS};
