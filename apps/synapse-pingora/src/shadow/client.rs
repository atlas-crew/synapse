//! Async HTTP client for shadow mirror delivery to honeypots.
//!
//! Uses fire-and-forget pattern to avoid impacting production latency.

use reqwest::Client;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::{debug, warn};

use super::protocol::MirrorPayload;

/// Async HTTP client for delivering shadow mirror payloads to honeypots.
///
/// Uses connection pooling and configurable timeouts for efficient delivery.
pub struct ShadowMirrorClient {
    /// Underlying HTTP client with connection pooling
    http_client: Client,
    /// HMAC secret for payload signing (optional)
    hmac_secret: Option<String>,
    /// Successful deliveries
    successes: AtomicU64,
    /// Failed deliveries
    failures: AtomicU64,
    /// Total bytes sent
    bytes_sent: AtomicU64,
}

impl ShadowMirrorClient {
    /// Creates a new shadow mirror client.
    ///
    /// # Arguments
    /// * `hmac_secret` - Optional secret for HMAC-SHA256 payload signing
    /// * `timeout` - Request timeout for honeypot delivery
    pub fn new(hmac_secret: Option<String>, timeout: Duration) -> Self {
        let http_client = Client::builder()
            .timeout(timeout)
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            http_client,
            hmac_secret,
            successes: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
        }
    }

    /// Sends a payload to one of the honeypot URLs.
    ///
    /// Uses round-robin URL selection based on request ID for load distribution.
    pub async fn send_to_honeypot(
        &self,
        urls: &[String],
        payload: MirrorPayload,
        timeout: Duration,
    ) -> Result<(), ShadowMirrorError> {
        if urls.is_empty() {
            return Err(ShadowMirrorError::NoHoneypotUrls);
        }

        // Round-robin URL selection based on request ID hash
        let url_index = self.select_url_index(&payload.request_id, urls.len());
        let url = &urls[url_index];

        let json = payload.to_json_bytes().map_err(ShadowMirrorError::Serialization)?;
        let json_len = json.len() as u64;

        let mut request = self.http_client
            .post(url)
            .timeout(timeout)
            .header("Content-Type", "application/json")
            .header("X-Shadow-Mirror", "1")
            .header("X-Request-ID", &payload.request_id)
            .header("X-Protocol-Version", &payload.protocol_version);

        // Add HMAC signature if configured
        if let Some(ref secret) = self.hmac_secret {
            let signature = self.compute_hmac(secret, &json);
            request = request.header("X-Signature", signature);
        }

        debug!(
            url = %url,
            request_id = %payload.request_id,
            payload_size = json_len,
            "Sending shadow mirror payload"
        );

        let result = request.body(json).send().await;

        match result {
            Ok(response) => {
                if response.status().is_success() {
                    self.successes.fetch_add(1, Ordering::Relaxed);
                    self.bytes_sent.fetch_add(json_len, Ordering::Relaxed);
                    debug!(
                        url = %url,
                        request_id = %payload.request_id,
                        status = %response.status(),
                        "Shadow mirror delivery succeeded"
                    );
                    Ok(())
                } else {
                    self.failures.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        url = %url,
                        request_id = %payload.request_id,
                        status = %response.status(),
                        "Shadow mirror delivery failed with non-success status"
                    );
                    Err(ShadowMirrorError::HttpError {
                        status: response.status().as_u16(),
                        url: url.clone(),
                    })
                }
            }
            Err(e) => {
                self.failures.fetch_add(1, Ordering::Relaxed);
                warn!(
                    url = %url,
                    request_id = %payload.request_id,
                    error = %e,
                    "Shadow mirror delivery failed"
                );
                Err(ShadowMirrorError::RequestFailed {
                    url: url.clone(),
                    reason: e.to_string(),
                })
            }
        }
    }

    /// Selects a URL index using simple hash-based distribution.
    fn select_url_index(&self, request_id: &str, url_count: usize) -> usize {
        // Simple hash from first 8 bytes of request ID
        let hash: u64 = request_id
            .bytes()
            .take(8)
            .enumerate()
            .map(|(i, b)| (b as u64) << (i * 8))
            .sum();

        (hash as usize) % url_count
    }

    /// Computes HMAC-SHA256 signature for the payload.
    fn compute_hmac(&self, secret: &str, data: &[u8]) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
            .expect("HMAC can accept any key length");
        mac.update(data);
        hex::encode(mac.finalize().into_bytes())
    }

    /// Returns statistics about the client.
    pub fn stats(&self) -> ShadowClientStats {
        ShadowClientStats {
            successes: self.successes.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
        }
    }

    /// Resets statistics.
    pub fn reset_stats(&self) {
        self.successes.store(0, Ordering::Relaxed);
        self.failures.store(0, Ordering::Relaxed);
        self.bytes_sent.store(0, Ordering::Relaxed);
    }
}

/// Shadow mirror client statistics.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ShadowClientStats {
    /// Number of successful deliveries
    pub successes: u64,
    /// Number of failed deliveries
    pub failures: u64,
    /// Total bytes sent to honeypots
    pub bytes_sent: u64,
}

impl ShadowClientStats {
    /// Returns the success rate as a percentage.
    pub fn success_rate(&self) -> f64 {
        let total = self.successes + self.failures;
        if total == 0 {
            100.0
        } else {
            (self.successes as f64 / total as f64) * 100.0
        }
    }
}

/// Errors that can occur during shadow mirror delivery.
#[derive(Debug, thiserror::Error)]
pub enum ShadowMirrorError {
    #[error("no honeypot URLs configured")]
    NoHoneypotUrls,

    #[error("failed to serialize payload: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("HTTP request to {url} failed with status {status}")]
    HttpError { status: u16, url: String },

    #[error("request to {url} failed: {reason}")]
    RequestFailed { url: String, reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_payload() -> MirrorPayload {
        MirrorPayload::new(
            "test-request-id".to_string(),
            "192.168.1.100".to_string(),
            55.0,
            "POST".to_string(),
            "/api/login".to_string(),
            "example.com".to_string(),
            "sensor-01".to_string(),
        )
    }

    #[test]
    fn test_client_creation() {
        let client = ShadowMirrorClient::new(None, Duration::from_secs(5));
        let stats = client.stats();
        assert_eq!(stats.successes, 0);
        assert_eq!(stats.failures, 0);
    }

    #[test]
    fn test_client_with_hmac() {
        let client = ShadowMirrorClient::new(
            Some("my-secret-key".to_string()),
            Duration::from_secs(5),
        );
        assert!(client.hmac_secret.is_some());
    }

    #[test]
    fn test_hmac_computation() {
        let client = ShadowMirrorClient::new(
            Some("test-secret".to_string()),
            Duration::from_secs(5),
        );

        let data = b"test payload data";
        let signature = client.compute_hmac("test-secret", data);

        // HMAC-SHA256 produces 64 hex characters
        assert_eq!(signature.len(), 64);
        // Should be consistent
        let signature2 = client.compute_hmac("test-secret", data);
        assert_eq!(signature, signature2);
    }

    #[test]
    fn test_url_selection_distribution() {
        let client = ShadowMirrorClient::new(None, Duration::from_secs(5));
        let urls = 3;

        let mut counts = [0u32; 3];

        // Test with various request IDs
        for i in 0..100 {
            let request_id = format!("request-{}", i);
            let index = client.select_url_index(&request_id, urls);
            counts[index] += 1;
        }

        // Each URL should get some traffic (basic distribution check)
        for (i, count) in counts.iter().enumerate() {
            assert!(*count > 0, "URL {} got no traffic", i);
        }
    }

    #[test]
    fn test_url_selection_consistent() {
        let client = ShadowMirrorClient::new(None, Duration::from_secs(5));

        // Same request ID should always select same URL
        let request_id = "consistent-request-id";
        let first = client.select_url_index(request_id, 5);
        let second = client.select_url_index(request_id, 5);
        assert_eq!(first, second);
    }

    #[test]
    fn test_stats_reset() {
        let client = ShadowMirrorClient::new(None, Duration::from_secs(5));

        // Manually increment counters for testing
        client.successes.store(10, Ordering::Relaxed);
        client.failures.store(5, Ordering::Relaxed);

        let stats = client.stats();
        assert_eq!(stats.successes, 10);
        assert_eq!(stats.failures, 5);

        client.reset_stats();

        let stats = client.stats();
        assert_eq!(stats.successes, 0);
        assert_eq!(stats.failures, 0);
    }

    #[test]
    fn test_success_rate() {
        let stats = ShadowClientStats {
            successes: 90,
            failures: 10,
            bytes_sent: 1000,
        };
        assert!((stats.success_rate() - 90.0).abs() < 0.01);

        let stats = ShadowClientStats {
            successes: 0,
            failures: 0,
            bytes_sent: 0,
        };
        assert!((stats.success_rate() - 100.0).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_send_empty_urls() {
        let client = ShadowMirrorClient::new(None, Duration::from_secs(1));
        let payload = create_test_payload();

        let result = client.send_to_honeypot(&[], payload, Duration::from_secs(1)).await;
        assert!(matches!(result, Err(ShadowMirrorError::NoHoneypotUrls)));
    }
}
