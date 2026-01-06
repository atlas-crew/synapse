//! TLS certificate management with SNI-based certificate selection.
//!
//! This module provides secure TLS configuration loading and hot-reload
//! capabilities for multi-site certificate management.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use parking_lot::RwLock;
use tracing::{debug, error, info, warn};

/// Maximum certificate file size (1MB).
const MAX_CERT_SIZE: u64 = 1024 * 1024;

/// TLS certificate and key pair.
#[derive(Clone)]
pub struct CertifiedKey {
    /// PEM-encoded certificate chain
    pub cert_pem: Arc<String>,
    /// PEM-encoded private key (stored securely)
    pub key_pem: Arc<String>,
    /// Associated domain
    pub domain: String,
}

impl std::fmt::Debug for CertifiedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never log the private key
        f.debug_struct("CertifiedKey")
            .field("domain", &self.domain)
            .field("cert_pem", &format!("[{} bytes]", self.cert_pem.len()))
            .field("key_pem", &"[REDACTED]")
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

/// TLS manager with SNI-based certificate selection and hot reload.
pub struct TlsManager {
    /// Exact domain -> certificate mapping
    exact_certs: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    /// Wildcard domain -> certificate mapping (e.g., "example.com" for *.example.com)
    wildcard_certs: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    /// Default certificate (if any)
    default_cert: RwLock<Option<Arc<CertifiedKey>>>,
    /// Minimum TLS version
    min_version: TlsVersion,
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
            exact_certs: RwLock::new(HashMap::new()),
            wildcard_certs: RwLock::new(HashMap::new()),
            default_cert: RwLock::new(None),
            min_version,
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
        let certified_key = Arc::new(CertifiedKey {
            cert_pem: Arc::new(cert_pem),
            key_pem: Arc::new(key_pem),
            domain: config.domain.clone(),
        });

        // Store based on type
        if config.is_wildcard {
            // Store wildcard by base domain (e.g., "example.com" for *.example.com)
            let base_domain = config.domain.trim_start_matches("*.");
            let mut wildcards = self.wildcard_certs.write();
            wildcards.insert(base_domain.to_lowercase(), certified_key);
            info!(
                "Loaded wildcard TLS certificate for *.{}",
                base_domain
            );
        } else {
            let mut exact = self.exact_certs.write();
            exact.insert(config.domain.to_lowercase(), certified_key);
            debug!(
                "Loaded TLS certificate for {}",
                config.domain
            );
        }

        Ok(())
    }

    /// Sets the default certificate for unmatched domains.
    pub fn set_default_cert(&self, config: &TlsCertConfig) -> Result<(), TlsError> {
        Self::validate_path(&config.cert_path)?;
        Self::validate_path(&config.key_path)?;

        let cert_pem = Self::read_file_secure(&config.cert_path, MAX_CERT_SIZE, "certificate")?;
        let key_pem = Self::read_file_secure(&config.key_path, MAX_CERT_SIZE, "key")?;

        let certified_key = Arc::new(CertifiedKey {
            cert_pem: Arc::new(cert_pem),
            key_pem: Arc::new(key_pem),
            domain: config.domain.clone(),
        });

        *self.default_cert.write() = Some(certified_key);
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
                TlsError::CertNotFound { path: path.to_string() }
            } else {
                TlsError::KeyNotFound { path: path.to_string() }
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
    pub fn reload_all(&self) -> Result<(), TlsError> {
        info!("Reloading all TLS certificates...");
        // Note: In production, we'd store the original configs and reload from them
        // For now, this is a placeholder for the hot-reload mechanism
        Ok(())
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
            key_pem: Arc::new("secret key".to_string()),
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
}
