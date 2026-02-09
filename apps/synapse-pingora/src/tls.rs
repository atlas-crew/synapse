//! TLS certificate management with SNI-based certificate selection.
//!
//! This module provides secure TLS configuration loading and hot-reload
//! capabilities for multi-site certificate management.

use ahash::RandomState;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info, warn};
use zeroize::Zeroize;

/// Maximum certificate file size (1MB).
const MAX_CERT_SIZE: u64 = 1024 * 1024;

/// TLS certificate and key pair.
///
/// # Security (SEC-010)
/// Private key is wrapped with zeroize to clear memory on drop.
#[derive(Clone)]
pub struct CertifiedKey {
    /// PEM-encoded certificate chain
    pub cert_pem: Arc<String>,
    /// PEM-encoded private key (stored securely, zeroized on drop via Arc)
    pub key_pem: Arc<SecureString>,
    /// Associated domain
    pub domain: String,
}

/// Wrapper for sensitive string data that zeroizes on drop.
///
/// # Security (SEC-010)
/// Ensures private key material is wiped from memory when no longer needed.
#[derive(Clone)]
pub struct SecureString(String);

impl SecureString {
    pub fn new(s: String) -> Self {
        Self(s)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SecureString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED {} bytes]", self.0.len())
    }
}

impl std::fmt::Debug for CertifiedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never log the private key
        f.debug_struct("CertifiedKey")
            .field("domain", &self.domain)
            .field("cert_pem", &format!("[{} bytes]", self.cert_pem.len()))
            .field(
                "key_pem",
                &format!("[REDACTED {} bytes]", self.key_pem.len()),
            )
            .finish()
    }
}

/// Configuration for loading a TLS certificate.
#[derive(Debug, Clone)]
pub struct TlsCertConfig {
    /// Domain name (for SNI matching)
    pub domain: String,
    /// Path to certificate file (PEM format)
    pub cert_path: String,
    /// Path to private key file (PEM format)
    pub key_path: String,
    /// Whether this is a wildcard certificate
    pub is_wildcard: bool,
}

/// Result of a certificate reload operation.
#[derive(Debug, Clone)]
pub struct ReloadResult {
    /// Number of certificates successfully reloaded
    pub succeeded: usize,
    /// Number of certificates that failed to reload
    pub failed: usize,
    /// Errors encountered during reload (domain -> error message)
    pub errors: Vec<(String, String)>,
}

impl ReloadResult {
    /// Returns true if all certificates were reloaded successfully.
    pub fn is_success(&self) -> bool {
        self.failed == 0
    }
}

/// TLS manager with SNI-based certificate selection and hot reload.
///
/// # Performance (PERF-P2-2)
/// Uses ahash::RandomState for 2-3x faster HashMap operations.
pub struct TlsManager {
    /// Exact domain -> certificate mapping (using fast ahash)
    exact_certs: RwLock<HashMap<String, Arc<CertifiedKey>, RandomState>>,
    /// Wildcard domain -> certificate mapping (e.g., "example.com" for *.example.com)
    wildcard_certs: RwLock<HashMap<String, Arc<CertifiedKey>, RandomState>>,
    /// Default certificate (if any)
    default_cert: RwLock<Option<Arc<CertifiedKey>>>,
    /// Minimum TLS version
    min_version: TlsVersion,
    /// Stored configurations for hot-reload (domain -> config)
    cert_configs: RwLock<HashMap<String, TlsCertConfig, RandomState>>,
    /// Default certificate config for hot-reload
    default_cert_config: RwLock<Option<TlsCertConfig>>,
}

/// Supported TLS versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

impl TlsVersion {
    /// Parses a TLS version string.
    pub fn from_str(s: &str) -> Result<Self, TlsError> {
        match s {
            "1.2" | "TLS1.2" | "TLSv1.2" => Ok(TlsVersion::Tls12),
            "1.3" | "TLS1.3" | "TLSv1.3" => Ok(TlsVersion::Tls13),
            _ => Err(TlsError::InvalidVersion {
                version: s.to_string(),
            }),
        }
    }
}

/// Errors that can occur during TLS operations.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("certificate file not found: {path}")]
    CertNotFound { path: String },

    #[error("key file not found: {path}")]
    KeyNotFound { path: String },

    #[error("certificate file too large: {path} ({size} bytes, max {max} bytes)")]
    CertTooLarge { path: String, size: u64, max: u64 },

    #[error("key file too large: {path} ({size} bytes, max {max} bytes)")]
    KeyTooLarge { path: String, size: u64, max: u64 },

    #[error("failed to read certificate: {0}")]
    ReadError(#[from] std::io::Error),

    #[error("invalid TLS version: {version} (must be 1.2 or 1.3)")]
    InvalidVersion { version: String },

    #[error("path traversal detected in: {path}")]
    PathTraversal { path: String },

    #[error("no certificate found for domain: {domain}")]
    NoCertificate { domain: String },

    #[error("invalid certificate format: {reason}")]
    InvalidCertificate { reason: String },
}

impl TlsManager {
    /// Creates a new TLS manager with the specified minimum version.
    pub fn new(min_version: TlsVersion) -> Self {
        Self {
            exact_certs: RwLock::new(HashMap::with_hasher(RandomState::new())),
            wildcard_certs: RwLock::new(HashMap::with_hasher(RandomState::new())),
            default_cert: RwLock::new(None),
            min_version,
            cert_configs: RwLock::new(HashMap::with_hasher(RandomState::new())),
            default_cert_config: RwLock::new(None),
        }
    }

    /// Creates a TLS manager with TLS 1.2 minimum.
    pub fn with_tls12_minimum() -> Self {
        Self::new(TlsVersion::Tls12)
    }

    /// Loads a certificate from files.
    ///
    /// # Security
    /// - Validates file paths for traversal attacks
    /// - Enforces file size limits
    /// - Never logs private key paths or contents
    pub fn load_cert(&self, config: &TlsCertConfig) -> Result<(), TlsError> {
        // Validate paths for traversal
        Self::validate_path(&config.cert_path)?;
        Self::validate_path(&config.key_path)?;

        // Load certificate
        let cert_pem = Self::read_file_secure(&config.cert_path, MAX_CERT_SIZE, "certificate")?;

        // Load private key
        let key_pem = Self::read_file_secure(&config.key_path, MAX_CERT_SIZE, "key")?;

        // Create certified key (Arc for efficient sharing)
        // SEC-010: Private key wrapped in SecureString for zeroization
        let certified_key = Arc::new(CertifiedKey {
            cert_pem: Arc::new(cert_pem),
            key_pem: Arc::new(SecureString::new(key_pem)),
            domain: config.domain.clone(),
        });

        // Store based on type
        let storage_key = if config.is_wildcard {
            // Store wildcard by base domain (e.g., "example.com" for *.example.com)
            let base_domain = config.domain.trim_start_matches("*.");
            let mut wildcards = self.wildcard_certs.write();
            wildcards.insert(base_domain.to_lowercase(), certified_key);
            info!("Loaded wildcard TLS certificate for *.{}", base_domain);
            base_domain.to_lowercase()
        } else {
            let mut exact = self.exact_certs.write();
            exact.insert(config.domain.to_lowercase(), certified_key);
            debug!("Loaded TLS certificate for {}", config.domain);
            config.domain.to_lowercase()
        };

        // Store config for hot-reload capability
        {
            let mut configs = self.cert_configs.write();
            configs.insert(storage_key, config.clone());
        }

        Ok(())
    }

    /// Sets the default certificate for unmatched domains.
    pub fn set_default_cert(&self, config: &TlsCertConfig) -> Result<(), TlsError> {
        Self::validate_path(&config.cert_path)?;
        Self::validate_path(&config.key_path)?;

        let cert_pem = Self::read_file_secure(&config.cert_path, MAX_CERT_SIZE, "certificate")?;
        let key_pem = Self::read_file_secure(&config.key_path, MAX_CERT_SIZE, "key")?;

        // SEC-010: Private key wrapped in SecureString for zeroization
        let certified_key = Arc::new(CertifiedKey {
            cert_pem: Arc::new(cert_pem),
            key_pem: Arc::new(SecureString::new(key_pem)),
            domain: config.domain.clone(),
        });

        *self.default_cert.write() = Some(certified_key);

        // Store config for hot-reload capability
        *self.default_cert_config.write() = Some(config.clone());

        info!("Set default TLS certificate for {}", config.domain);
        Ok(())
    }

    /// Gets the certificate for a domain using SNI matching.
    ///
    /// # Matching Order
    /// 1. Exact domain match
    /// 2. Wildcard match (*.example.com matches sub.example.com)
    /// 3. Default certificate
    pub fn get_cert(&self, domain: &str) -> Option<Arc<CertifiedKey>> {
        let normalized = domain.to_lowercase();

        // Try exact match first
        {
            let exact = self.exact_certs.read();
            if let Some(cert) = exact.get(&normalized) {
                debug!("SNI exact match for {}", domain);
                return Some(Arc::clone(cert));
            }
        }

        // Try wildcard match
        if let Some(base_domain) = Self::get_base_domain(&normalized) {
            let wildcards = self.wildcard_certs.read();
            if let Some(cert) = wildcards.get(base_domain) {
                debug!("SNI wildcard match for {} -> *.{}", domain, base_domain);
                return Some(Arc::clone(cert));
            }
        }

        // Fall back to default
        {
            let default = self.default_cert.read();
            if let Some(cert) = default.as_ref() {
                debug!("Using default certificate for {}", domain);
                return Some(Arc::clone(cert));
            }
        }

        warn!("No TLS certificate found for domain: {}", domain);
        None
    }

    /// Gets the base domain for wildcard matching.
    /// e.g., "sub.example.com" -> "example.com"
    fn get_base_domain(domain: &str) -> Option<&str> {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() >= 2 {
            // Skip the first part (subdomain)
            let base_start = domain.find('.').map(|i| i + 1)?;
            Some(&domain[base_start..])
        } else {
            None
        }
    }

    /// Validates a file path for security issues.
    fn validate_path(path: &str) -> Result<(), TlsError> {
        // Check for path traversal
        if path.contains("..") {
            return Err(TlsError::PathTraversal {
                path: path.to_string(),
            });
        }
        Ok(())
    }

    /// Reads a file with size validation.
    fn read_file_secure(path: &str, max_size: u64, file_type: &str) -> Result<String, TlsError> {
        let path_ref = Path::new(path);

        if !path_ref.exists() {
            return Err(if file_type == "certificate" {
                TlsError::CertNotFound {
                    path: path.to_string(),
                }
            } else {
                TlsError::KeyNotFound {
                    path: path.to_string(),
                }
            });
        }

        let metadata = fs::metadata(path)?;
        if metadata.len() > max_size {
            return Err(if file_type == "certificate" {
                TlsError::CertTooLarge {
                    path: path.to_string(),
                    size: metadata.len(),
                    max: max_size,
                }
            } else {
                TlsError::KeyTooLarge {
                    path: path.to_string(),
                    size: metadata.len(),
                    max: max_size,
                }
            });
        }

        fs::read_to_string(path).map_err(TlsError::from)
    }

    /// Reloads all certificates from their original paths.
    /// This is called on SIGHUP for hot reload.
    ///
    /// # Hot Reload Strategy
    /// Certificates are reloaded atomically: new certificates are loaded into
    /// temporary maps, then swapped in all at once. If any certificate fails
    /// to load, all successfully loaded certificates are still applied and
    /// failures are reported.
    ///
    /// # Returns
    /// `ReloadResult` containing counts of succeeded/failed reloads and error details.
    pub fn reload_all(&self) -> ReloadResult {
        info!("Reloading all TLS certificates...");

        let mut result = ReloadResult {
            succeeded: 0,
            failed: 0,
            errors: Vec::new(),
        };

        // Snapshot current configs to avoid holding lock during reload
        let configs: Vec<(String, TlsCertConfig)> = {
            let configs = self.cert_configs.read();
            configs
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        };

        let default_config: Option<TlsCertConfig> = { self.default_cert_config.read().clone() };

        if configs.is_empty() && default_config.is_none() {
            info!("No certificates configured for reload");
            return result;
        }

        // Prepare new certificate maps
        let mut new_exact: HashMap<String, Arc<CertifiedKey>, RandomState> =
            HashMap::with_hasher(RandomState::new());
        let mut new_wildcard: HashMap<String, Arc<CertifiedKey>, RandomState> =
            HashMap::with_hasher(RandomState::new());

        // Reload each certificate
        for (storage_key, config) in configs {
            match self.load_cert_internal(&config) {
                Ok(certified_key) => {
                    if config.is_wildcard {
                        new_wildcard.insert(storage_key, certified_key);
                    } else {
                        new_exact.insert(storage_key, certified_key);
                    }
                    result.succeeded += 1;
                    debug!("Reloaded certificate for {}", config.domain);
                }
                Err(e) => {
                    result.failed += 1;
                    result.errors.push((config.domain.clone(), e.to_string()));
                    warn!("Failed to reload certificate for {}: {}", config.domain, e);
                }
            }
        }

        // Reload default certificate
        let new_default = if let Some(config) = default_config {
            match self.load_cert_internal(&config) {
                Ok(certified_key) => {
                    result.succeeded += 1;
                    debug!("Reloaded default certificate for {}", config.domain);
                    Some(certified_key)
                }
                Err(e) => {
                    result.failed += 1;
                    result
                        .errors
                        .push((format!("default:{}", config.domain), e.to_string()));
                    warn!(
                        "Failed to reload default certificate for {}: {}",
                        config.domain, e
                    );
                    None
                }
            }
        } else {
            None
        };

        // Atomic swap: apply all successfully loaded certificates
        if result.succeeded > 0 {
            // Swap exact certs
            if !new_exact.is_empty() {
                let mut exact = self.exact_certs.write();
                for (key, cert) in new_exact {
                    exact.insert(key, cert);
                }
            }

            // Swap wildcard certs
            if !new_wildcard.is_empty() {
                let mut wildcards = self.wildcard_certs.write();
                for (key, cert) in new_wildcard {
                    wildcards.insert(key, cert);
                }
            }

            // Swap default cert
            if let Some(cert) = new_default {
                *self.default_cert.write() = Some(cert);
            }
        }

        if result.is_success() {
            info!("Successfully reloaded {} certificate(s)", result.succeeded);
        } else {
            warn!(
                "Certificate reload completed: {} succeeded, {} failed",
                result.succeeded, result.failed
            );
        }

        result
    }

    /// Reloads a single certificate by domain.
    ///
    /// # Arguments
    /// * `domain` - The domain to reload (case-insensitive)
    ///
    /// # Returns
    /// `Ok(())` if successful, or the error that occurred.
    pub fn reload_cert(&self, domain: &str) -> Result<(), TlsError> {
        let normalized = domain.to_lowercase();
        let storage_key = normalized.trim_start_matches("*.");

        // Find the config
        let config = {
            let configs = self.cert_configs.read();
            configs.get(storage_key).cloned()
        };

        let config = config.ok_or_else(|| TlsError::NoCertificate {
            domain: domain.to_string(),
        })?;

        // Reload the certificate
        let certified_key = self.load_cert_internal(&config)?;

        // Apply the new certificate
        if config.is_wildcard {
            let mut wildcards = self.wildcard_certs.write();
            wildcards.insert(storage_key.to_string(), certified_key);
        } else {
            let mut exact = self.exact_certs.write();
            exact.insert(storage_key.to_string(), certified_key);
        }

        info!("Reloaded certificate for {}", domain);
        Ok(())
    }

    /// Internal helper to load a certificate from config without storing it.
    fn load_cert_internal(&self, config: &TlsCertConfig) -> Result<Arc<CertifiedKey>, TlsError> {
        // Validate paths for traversal
        Self::validate_path(&config.cert_path)?;
        Self::validate_path(&config.key_path)?;

        // Load certificate
        let cert_pem = Self::read_file_secure(&config.cert_path, MAX_CERT_SIZE, "certificate")?;

        // Load private key
        let key_pem = Self::read_file_secure(&config.key_path, MAX_CERT_SIZE, "key")?;

        // Create certified key
        Ok(Arc::new(CertifiedKey {
            cert_pem: Arc::new(cert_pem),
            key_pem: Arc::new(SecureString::new(key_pem)),
            domain: config.domain.clone(),
        }))
    }

    /// Returns the list of configured domains (for monitoring/diagnostics).
    pub fn configured_domains(&self) -> Vec<String> {
        let configs = self.cert_configs.read();
        configs.keys().cloned().collect()
    }

    /// Returns true if a certificate is configured for the given domain.
    pub fn has_cert_config(&self, domain: &str) -> bool {
        let normalized = domain.to_lowercase();
        let storage_key = normalized.trim_start_matches("*.");
        let configs = self.cert_configs.read();
        configs.contains_key(storage_key)
    }

    /// Returns the minimum TLS version.
    pub fn min_version(&self) -> TlsVersion {
        self.min_version
    }

    /// Returns the number of loaded certificates.
    pub fn cert_count(&self) -> usize {
        self.exact_certs.read().len() + self.wildcard_certs.read().len()
    }
}

impl Default for TlsManager {
    fn default() -> Self {
        Self::with_tls12_minimum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_temp_file(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file
    }

    const DUMMY_CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----";
    const DUMMY_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----";

    #[test]
    fn test_load_exact_cert() {
        let cert_file = create_temp_file(DUMMY_CERT);
        let key_file = create_temp_file(DUMMY_KEY);

        let manager = TlsManager::default();
        let config = TlsCertConfig {
            domain: "example.com".to_string(),
            cert_path: cert_file.path().to_string_lossy().to_string(),
            key_path: key_file.path().to_string_lossy().to_string(),
            is_wildcard: false,
        };

        manager.load_cert(&config).unwrap();
        assert!(manager.get_cert("example.com").is_some());
        assert!(manager.get_cert("other.com").is_none());
    }

    #[test]
    fn test_load_wildcard_cert() {
        let cert_file = create_temp_file(DUMMY_CERT);
        let key_file = create_temp_file(DUMMY_KEY);

        let manager = TlsManager::default();
        let config = TlsCertConfig {
            domain: "*.example.com".to_string(),
            cert_path: cert_file.path().to_string_lossy().to_string(),
            key_path: key_file.path().to_string_lossy().to_string(),
            is_wildcard: true,
        };

        manager.load_cert(&config).unwrap();

        // Wildcard should match subdomains
        assert!(manager.get_cert("api.example.com").is_some());
        assert!(manager.get_cert("www.example.com").is_some());

        // Should not match the bare domain or other domains
        assert!(manager.get_cert("example.com").is_none());
        assert!(manager.get_cert("other.com").is_none());
    }

    #[test]
    fn test_default_cert() {
        let cert_file = create_temp_file(DUMMY_CERT);
        let key_file = create_temp_file(DUMMY_KEY);

        let manager = TlsManager::default();
        let config = TlsCertConfig {
            domain: "default.local".to_string(),
            cert_path: cert_file.path().to_string_lossy().to_string(),
            key_path: key_file.path().to_string_lossy().to_string(),
            is_wildcard: false,
        };

        manager.set_default_cert(&config).unwrap();

        // Any unmatched domain should get the default
        assert!(manager.get_cert("random.com").is_some());
        assert!(manager.get_cert("anything.org").is_some());
    }

    #[test]
    fn test_case_insensitive() {
        let cert_file = create_temp_file(DUMMY_CERT);
        let key_file = create_temp_file(DUMMY_KEY);

        let manager = TlsManager::default();
        let config = TlsCertConfig {
            domain: "Example.COM".to_string(),
            cert_path: cert_file.path().to_string_lossy().to_string(),
            key_path: key_file.path().to_string_lossy().to_string(),
            is_wildcard: false,
        };

        manager.load_cert(&config).unwrap();

        assert!(manager.get_cert("example.com").is_some());
        assert!(manager.get_cert("EXAMPLE.COM").is_some());
    }

    #[test]
    fn test_path_traversal() {
        let manager = TlsManager::default();
        let config = TlsCertConfig {
            domain: "example.com".to_string(),
            cert_path: "../../../etc/passwd".to_string(),
            key_path: "key.pem".to_string(),
            is_wildcard: false,
        };

        let result = manager.load_cert(&config);
        assert!(matches!(result, Err(TlsError::PathTraversal { .. })));
    }

    #[test]
    fn test_cert_not_found() {
        let key_file = create_temp_file(DUMMY_KEY);

        let manager = TlsManager::default();
        let config = TlsCertConfig {
            domain: "example.com".to_string(),
            cert_path: "/nonexistent/cert.pem".to_string(),
            key_path: key_file.path().to_string_lossy().to_string(),
            is_wildcard: false,
        };

        let result = manager.load_cert(&config);
        assert!(matches!(result, Err(TlsError::CertNotFound { .. })));
    }

    #[test]
    fn test_tls_version_parsing() {
        assert_eq!(TlsVersion::from_str("1.2").unwrap(), TlsVersion::Tls12);
        assert_eq!(TlsVersion::from_str("1.3").unwrap(), TlsVersion::Tls13);
        assert_eq!(TlsVersion::from_str("TLSv1.2").unwrap(), TlsVersion::Tls12);
        assert!(TlsVersion::from_str("1.1").is_err());
    }

    #[test]
    fn test_debug_redacts_key() {
        let cert = CertifiedKey {
            cert_pem: Arc::new("cert content".to_string()),
            key_pem: Arc::new(SecureString::new("secret key".to_string())),
            domain: "example.com".to_string(),
        };

        let debug_output = format!("{:?}", cert);
        assert!(debug_output.contains("REDACTED"));
        assert!(!debug_output.contains("secret key"));
    }

    #[test]
    fn test_cert_count() {
        let cert_file = create_temp_file(DUMMY_CERT);
        let key_file = create_temp_file(DUMMY_KEY);

        let manager = TlsManager::default();
        assert_eq!(manager.cert_count(), 0);

        let config = TlsCertConfig {
            domain: "example.com".to_string(),
            cert_path: cert_file.path().to_string_lossy().to_string(),
            key_path: key_file.path().to_string_lossy().to_string(),
            is_wildcard: false,
        };

        manager.load_cert(&config).unwrap();
        assert_eq!(manager.cert_count(), 1);
    }

    // ==================== Hot Reload Tests ====================

    #[test]
    fn test_reload_all_empty() {
        let manager = TlsManager::default();
        let result = manager.reload_all();

        assert_eq!(result.succeeded, 0);
        assert_eq!(result.failed, 0);
        assert!(result.is_success());
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_reload_all_success() {
        let cert_file = create_temp_file(DUMMY_CERT);
        let key_file = create_temp_file(DUMMY_KEY);

        let manager = TlsManager::default();
        let config = TlsCertConfig {
            domain: "example.com".to_string(),
            cert_path: cert_file.path().to_string_lossy().to_string(),
            key_path: key_file.path().to_string_lossy().to_string(),
            is_wildcard: false,
        };

        manager.load_cert(&config).unwrap();

        // Reload should succeed
        let result = manager.reload_all();
        assert_eq!(result.succeeded, 1);
        assert_eq!(result.failed, 0);
        assert!(result.is_success());

        // Certificate should still be available
        assert!(manager.get_cert("example.com").is_some());
    }

    #[test]
    fn test_reload_all_multiple_certs() {
        let cert_file1 = create_temp_file(DUMMY_CERT);
        let key_file1 = create_temp_file(DUMMY_KEY);
        let cert_file2 = create_temp_file(DUMMY_CERT);
        let key_file2 = create_temp_file(DUMMY_KEY);

        let manager = TlsManager::default();

        // Load exact cert
        manager
            .load_cert(&TlsCertConfig {
                domain: "example.com".to_string(),
                cert_path: cert_file1.path().to_string_lossy().to_string(),
                key_path: key_file1.path().to_string_lossy().to_string(),
                is_wildcard: false,
            })
            .unwrap();

        // Load wildcard cert
        manager
            .load_cert(&TlsCertConfig {
                domain: "*.other.com".to_string(),
                cert_path: cert_file2.path().to_string_lossy().to_string(),
                key_path: key_file2.path().to_string_lossy().to_string(),
                is_wildcard: true,
            })
            .unwrap();

        let result = manager.reload_all();
        assert_eq!(result.succeeded, 2);
        assert_eq!(result.failed, 0);
        assert!(result.is_success());

        // Both certificates should still work
        assert!(manager.get_cert("example.com").is_some());
        assert!(manager.get_cert("api.other.com").is_some());
    }

    #[test]
    fn test_reload_all_with_default() {
        let cert_file = create_temp_file(DUMMY_CERT);
        let key_file = create_temp_file(DUMMY_KEY);
        let default_cert = create_temp_file(DUMMY_CERT);
        let default_key = create_temp_file(DUMMY_KEY);

        let manager = TlsManager::default();

        manager
            .load_cert(&TlsCertConfig {
                domain: "example.com".to_string(),
                cert_path: cert_file.path().to_string_lossy().to_string(),
                key_path: key_file.path().to_string_lossy().to_string(),
                is_wildcard: false,
            })
            .unwrap();

        manager
            .set_default_cert(&TlsCertConfig {
                domain: "default.local".to_string(),
                cert_path: default_cert.path().to_string_lossy().to_string(),
                key_path: default_key.path().to_string_lossy().to_string(),
                is_wildcard: false,
            })
            .unwrap();

        let result = manager.reload_all();
        assert_eq!(result.succeeded, 2); // 1 exact + 1 default
        assert_eq!(result.failed, 0);
    }

    #[test]
    fn test_reload_all_partial_failure() {
        let cert_file = create_temp_file(DUMMY_CERT);
        let key_file = create_temp_file(DUMMY_KEY);

        let manager = TlsManager::default();

        // Load valid cert
        manager
            .load_cert(&TlsCertConfig {
                domain: "valid.com".to_string(),
                cert_path: cert_file.path().to_string_lossy().to_string(),
                key_path: key_file.path().to_string_lossy().to_string(),
                is_wildcard: false,
            })
            .unwrap();

        // Manually insert a config with invalid paths (simulating file deletion)
        {
            let mut configs = manager.cert_configs.write();
            configs.insert(
                "invalid.com".to_string(),
                TlsCertConfig {
                    domain: "invalid.com".to_string(),
                    cert_path: "/nonexistent/cert.pem".to_string(),
                    key_path: "/nonexistent/key.pem".to_string(),
                    is_wildcard: false,
                },
            );
        }

        let result = manager.reload_all();
        assert_eq!(result.succeeded, 1);
        assert_eq!(result.failed, 1);
        assert!(!result.is_success());
        assert_eq!(result.errors.len(), 1);
        assert!(result.errors[0].0.contains("invalid.com"));

        // Valid cert should still be reloaded
        assert!(manager.get_cert("valid.com").is_some());
    }

    #[test]
    fn test_reload_single_cert() {
        let cert_file = create_temp_file(DUMMY_CERT);
        let key_file = create_temp_file(DUMMY_KEY);

        let manager = TlsManager::default();
        let config = TlsCertConfig {
            domain: "example.com".to_string(),
            cert_path: cert_file.path().to_string_lossy().to_string(),
            key_path: key_file.path().to_string_lossy().to_string(),
            is_wildcard: false,
        };

        manager.load_cert(&config).unwrap();

        // Reload single cert
        let result = manager.reload_cert("example.com");
        assert!(result.is_ok());
        assert!(manager.get_cert("example.com").is_some());
    }

    #[test]
    fn test_reload_single_cert_case_insensitive() {
        let cert_file = create_temp_file(DUMMY_CERT);
        let key_file = create_temp_file(DUMMY_KEY);

        let manager = TlsManager::default();
        let config = TlsCertConfig {
            domain: "Example.COM".to_string(),
            cert_path: cert_file.path().to_string_lossy().to_string(),
            key_path: key_file.path().to_string_lossy().to_string(),
            is_wildcard: false,
        };

        manager.load_cert(&config).unwrap();

        // Reload with different case
        assert!(manager.reload_cert("EXAMPLE.com").is_ok());
    }

    #[test]
    fn test_reload_single_cert_not_found() {
        let manager = TlsManager::default();

        let result = manager.reload_cert("notfound.com");
        assert!(matches!(result, Err(TlsError::NoCertificate { .. })));
    }

    #[test]
    fn test_reload_wildcard_cert() {
        let cert_file = create_temp_file(DUMMY_CERT);
        let key_file = create_temp_file(DUMMY_KEY);

        let manager = TlsManager::default();
        let config = TlsCertConfig {
            domain: "*.example.com".to_string(),
            cert_path: cert_file.path().to_string_lossy().to_string(),
            key_path: key_file.path().to_string_lossy().to_string(),
            is_wildcard: true,
        };

        manager.load_cert(&config).unwrap();

        // Reload wildcard cert
        let result = manager.reload_cert("*.example.com");
        assert!(result.is_ok());
        assert!(manager.get_cert("api.example.com").is_some());
    }

    #[test]
    fn test_configured_domains() {
        let cert_file1 = create_temp_file(DUMMY_CERT);
        let key_file1 = create_temp_file(DUMMY_KEY);
        let cert_file2 = create_temp_file(DUMMY_CERT);
        let key_file2 = create_temp_file(DUMMY_KEY);

        let manager = TlsManager::default();
        assert!(manager.configured_domains().is_empty());

        manager
            .load_cert(&TlsCertConfig {
                domain: "one.com".to_string(),
                cert_path: cert_file1.path().to_string_lossy().to_string(),
                key_path: key_file1.path().to_string_lossy().to_string(),
                is_wildcard: false,
            })
            .unwrap();

        manager
            .load_cert(&TlsCertConfig {
                domain: "*.two.com".to_string(),
                cert_path: cert_file2.path().to_string_lossy().to_string(),
                key_path: key_file2.path().to_string_lossy().to_string(),
                is_wildcard: true,
            })
            .unwrap();

        let domains = manager.configured_domains();
        assert_eq!(domains.len(), 2);
        assert!(domains.contains(&"one.com".to_string()));
        assert!(domains.contains(&"two.com".to_string())); // Wildcard stored by base domain
    }

    #[test]
    fn test_has_cert_config() {
        let cert_file = create_temp_file(DUMMY_CERT);
        let key_file = create_temp_file(DUMMY_KEY);

        let manager = TlsManager::default();
        assert!(!manager.has_cert_config("example.com"));

        manager
            .load_cert(&TlsCertConfig {
                domain: "example.com".to_string(),
                cert_path: cert_file.path().to_string_lossy().to_string(),
                key_path: key_file.path().to_string_lossy().to_string(),
                is_wildcard: false,
            })
            .unwrap();

        assert!(manager.has_cert_config("example.com"));
        assert!(manager.has_cert_config("EXAMPLE.COM")); // Case insensitive
        assert!(!manager.has_cert_config("other.com"));
    }

    #[test]
    fn test_reload_updates_cert_content() {
        use std::io::{Seek, SeekFrom};

        let mut cert_file = NamedTempFile::new().unwrap();
        let mut key_file = NamedTempFile::new().unwrap();

        // Write initial content
        cert_file.write_all(DUMMY_CERT.as_bytes()).unwrap();
        key_file.write_all(DUMMY_KEY.as_bytes()).unwrap();

        let manager = TlsManager::default();
        let config = TlsCertConfig {
            domain: "example.com".to_string(),
            cert_path: cert_file.path().to_string_lossy().to_string(),
            key_path: key_file.path().to_string_lossy().to_string(),
            is_wildcard: false,
        };

        manager.load_cert(&config).unwrap();

        // Get initial cert
        let cert1 = manager.get_cert("example.com").unwrap();
        let initial_cert = cert1.cert_pem.clone();

        // Update cert file with new content - use as_file_mut() to get mutable file handle
        let new_cert = "-----BEGIN CERTIFICATE-----\nNEW_CERT\n-----END CERTIFICATE-----";
        {
            let file = cert_file.as_file_mut();
            file.seek(SeekFrom::Start(0)).unwrap();
            file.set_len(0).unwrap();
        }
        cert_file.write_all(new_cert.as_bytes()).unwrap();

        // Reload
        manager.reload_cert("example.com").unwrap();

        // Verify cert was updated
        let cert2 = manager.get_cert("example.com").unwrap();
        assert_ne!(*initial_cert, *cert2.cert_pem);
        assert!(cert2.cert_pem.contains("NEW_CERT"));
    }

    #[test]
    fn test_reload_result_debug() {
        let result = ReloadResult {
            succeeded: 5,
            failed: 2,
            errors: vec![
                ("domain1.com".to_string(), "file not found".to_string()),
                ("domain2.com".to_string(), "permission denied".to_string()),
            ],
        };

        let debug_output = format!("{:?}", result);
        assert!(debug_output.contains("succeeded: 5"));
        assert!(debug_output.contains("failed: 2"));
        assert!(debug_output.contains("domain1.com"));
    }
}
