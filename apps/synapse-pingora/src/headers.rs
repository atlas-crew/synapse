//! Header manipulation logic for request and response headers.
//!
//! Provides functionality to add, set, and remove headers based on configuration.
//!
//! # Security
//!
//! Sensitive header values (Authorization, Cookie, API keys, etc.) are automatically
//! redacted in debug logs to prevent credential leakage through log aggregation systems.

use crate::config::{HeaderConfig, HeaderOps};
use crate::shadow::is_sensitive_header;
use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use pingora_http::{RequestHeader, ResponseHeader};
use tracing::debug;

/// Redact a header value for safe logging.
///
/// SECURITY: Sensitive header values are fully redacted to prevent credential leakage.
/// Non-sensitive headers show the full value for debugging purposes.
#[inline]
fn redact_for_log(name: &str, value: &str) -> String {
    if is_sensitive_header(name) {
        "[REDACTED]".to_string()
    } else {
        value.to_string()
    }
}

#[derive(Debug, Clone, Default)]
pub struct CompiledHeaderOps {
    pub(crate) add: Vec<CompiledHeaderValue>,
    pub(crate) set: Vec<CompiledHeaderValue>,
    pub(crate) remove: Vec<HeaderName>,
}

#[derive(Debug, Clone, Default)]
pub struct CompiledHeaderConfig {
    pub(crate) request: CompiledHeaderOps,
    pub(crate) response: CompiledHeaderOps,
}

impl CompiledHeaderConfig {
    /// Get the request header operations
    pub fn request(&self) -> &CompiledHeaderOps {
        &self.request
    }

    /// Get the response header operations
    pub fn response(&self) -> &CompiledHeaderOps {
        &self.response
    }
}

#[derive(Debug, Clone)]
struct CompiledHeaderValue {
    name: Bytes,
    value: HeaderValue,
}

impl CompiledHeaderOps {
    fn with_capacity(add: usize, set: usize, remove: usize) -> Self {
        Self {
            add: Vec::with_capacity(add),
            set: Vec::with_capacity(set),
            remove: Vec::with_capacity(remove),
        }
    }
}

impl HeaderConfig {
    pub fn compile(&self) -> CompiledHeaderConfig {
        CompiledHeaderConfig {
            request: self.request.compile(),
            response: self.response.compile(),
        }
    }
}

impl HeaderOps {
    pub fn compile(&self) -> CompiledHeaderOps {
        let mut compiled =
            CompiledHeaderOps::with_capacity(self.add.len(), self.set.len(), self.remove.len());

        for name in &self.remove {
            match HeaderName::from_bytes(name.as_bytes()) {
                Ok(header_name) => compiled.remove.push(header_name),
                Err(err) => debug!("Invalid remove header name '{}': {}", name, err),
            }
        }

        compiled.set = compile_header_entries(&self.set, "set");
        compiled.add = compile_header_entries(&self.add, "add");

        compiled
    }
}

fn compile_header_entries(
    entries: &std::collections::HashMap<String, String>,
    op: &'static str,
) -> Vec<CompiledHeaderValue> {
    let mut compiled = Vec::with_capacity(entries.len());

    for (name, value) in entries {
        if let Err(err) = HeaderName::from_bytes(name.as_bytes()) {
            debug!("Invalid {} header name '{}': {}", op, name, err);
            continue;
        }

        match HeaderValue::from_str(value) {
            Ok(header_value) => compiled.push(CompiledHeaderValue {
                name: Bytes::copy_from_slice(name.as_bytes()),
                value: header_value,
            }),
            Err(err) => debug!("Invalid {} header value for '{}': {}", op, name, err),
        }
    }

    compiled
}

#[inline]
fn header_name_for_log(name: &Bytes) -> &str {
    std::str::from_utf8(name.as_ref()).unwrap_or("<invalid>")
}

#[inline]
fn header_value_for_log(value: &HeaderValue) -> &str {
    value.to_str().unwrap_or("<binary>")
}

/// Apply header operations to a request header.
pub fn apply_request_headers(header: &mut RequestHeader, ops: &CompiledHeaderOps) {
    // 1. Remove headers
    for name in &ops.remove {
        if header.remove_header(name).is_some() {
            debug!("Removed request header: {}", name.as_str());
        }
    }

    // 2. Set headers (replace existing)
    for entry in &ops.set {
        let name = header_name_for_log(&entry.name);
        if let Err(e) = header.insert_header(entry.name.clone(), entry.value.clone()) {
            debug!("Failed to set request header {}: {}", name, e);
        } else {
            // SECURITY: Redact sensitive header values in logs
            let value = header_value_for_log(&entry.value);
            debug!(
                "Set request header: {} = {}",
                name,
                redact_for_log(name, value)
            );
        }
    }

    // 3. Add headers (append to existing)
    for entry in &ops.add {
        let name = header_name_for_log(&entry.name);
        if let Err(e) = header.append_header(entry.name.clone(), entry.value.clone()) {
            debug!("Failed to add request header {}: {}", name, e);
        } else {
            // SECURITY: Redact sensitive header values in logs
            let value = header_value_for_log(&entry.value);
            debug!(
                "Added request header: {} = {}",
                name,
                redact_for_log(name, value)
            );
        }
    }
}

/// Apply header operations to a response header.
pub fn apply_response_headers(header: &mut ResponseHeader, ops: &CompiledHeaderOps) {
    // 1. Remove headers
    for name in &ops.remove {
        if header.remove_header(name).is_some() {
            debug!("Removed response header: {}", name.as_str());
        }
    }

    // 2. Set headers (replace existing)
    for entry in &ops.set {
        let name = header_name_for_log(&entry.name);
        if let Err(e) = header.insert_header(entry.name.clone(), entry.value.clone()) {
            debug!("Failed to set response header {}: {}", name, e);
        } else {
            // SECURITY: Redact sensitive header values in logs
            let value = header_value_for_log(&entry.value);
            debug!(
                "Set response header: {} = {}",
                name,
                redact_for_log(name, value)
            );
        }
    }

    // 3. Add headers (append to existing)
    for entry in &ops.add {
        let name = header_name_for_log(&entry.name);
        if let Err(e) = header.append_header(entry.name.clone(), entry.value.clone()) {
            debug!("Failed to add response header {}: {}", name, e);
        } else {
            // SECURITY: Redact sensitive header values in logs
            let value = header_value_for_log(&entry.value);
            debug!(
                "Added response header: {} = {}",
                name,
                redact_for_log(name, value)
            );
        }
    }
}

#[inline]
fn ensure_response_header(header: &mut ResponseHeader, name: &'static str, value: &'static str) {
    if header.headers.get(name).is_some() {
        return;
    }

    if let Err(err) = header.insert_header(name, value) {
        debug!("Failed to set security header {}: {}", name, err);
    }
}

/// Inject baseline security headers onto a response.
///
/// Notes:
/// - Uses "set-if-missing" to avoid overriding application-owned policies.
/// - HSTS is only injected when the downstream request is HTTPS.
pub fn apply_security_response_headers(header: &mut ResponseHeader, is_https: bool) {
    // HSTS is only meaningful over HTTPS; avoid emitting it for cleartext HTTP.
    if is_https {
        ensure_response_header(
            header,
            "strict-transport-security",
            "max-age=31536000; includeSubDomains",
        );
    }

    ensure_response_header(header, "x-content-type-options", "nosniff");
    ensure_response_header(header, "x-frame-options", "DENY");
    ensure_response_header(header, "referrer-policy", "strict-origin-when-cross-origin");
    ensure_response_header(
        header,
        "permissions-policy",
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora_http::RequestHeader;

    #[test]
    fn test_redact_sensitive_headers() {
        // Sensitive headers should be fully redacted
        assert_eq!(
            redact_for_log("Authorization", "Bearer secret-token"),
            "[REDACTED]"
        );
        assert_eq!(
            redact_for_log("authorization", "Basic dXNlcjpwYXNz"),
            "[REDACTED]"
        );
        assert_eq!(redact_for_log("Cookie", "session=abc123"), "[REDACTED]");
        assert_eq!(redact_for_log("X-Api-Key", "sk-live-12345"), "[REDACTED]");
        assert_eq!(
            redact_for_log("X-Auth-Token", "auth-token-value"),
            "[REDACTED]"
        );
        assert_eq!(redact_for_log("X-CSRF-Token", "csrf123"), "[REDACTED]");
    }

    #[test]
    fn test_redact_non_sensitive_headers() {
        // Non-sensitive headers should show full value
        assert_eq!(
            redact_for_log("Content-Type", "application/json"),
            "application/json"
        );
        assert_eq!(redact_for_log("Accept", "text/html"), "text/html");
        assert_eq!(redact_for_log("User-Agent", "Mozilla/5.0"), "Mozilla/5.0");
        assert_eq!(redact_for_log("X-Request-Id", "req-123"), "req-123");
        assert_eq!(redact_for_log("Cache-Control", "no-cache"), "no-cache");
    }

    #[test]
    fn test_redact_case_insensitive() {
        // Header name matching should be case-insensitive
        assert_eq!(redact_for_log("AUTHORIZATION", "token"), "[REDACTED]");
        assert_eq!(redact_for_log("Authorization", "token"), "[REDACTED]");
        assert_eq!(redact_for_log("authorization", "token"), "[REDACTED]");
        assert_eq!(redact_for_log("COOKIE", "value"), "[REDACTED]");
        assert_eq!(redact_for_log("Cookie", "value"), "[REDACTED]");
        assert_eq!(redact_for_log("cookie", "value"), "[REDACTED]");
    }

    #[test]
    fn test_compile_header_ops_skips_invalid_entries() {
        let mut ops = HeaderOps::default();
        ops.add
            .insert("Bad Header".to_string(), "value".to_string());
        ops.set.insert("X-Good".to_string(), "ok".to_string());
        ops.remove.push("Another Bad Header".to_string());

        let compiled = ops.compile();

        assert_eq!(compiled.add.len(), 0);
        assert_eq!(compiled.set.len(), 1);
        assert_eq!(compiled.remove.len(), 0);
    }

    #[test]
    fn test_apply_compiled_request_headers() {
        let mut ops = HeaderOps::default();
        ops.add.insert("X-Added".to_string(), "value".to_string());
        ops.set.insert("X-Set".to_string(), "set-value".to_string());
        ops.remove.push("X-Remove".to_string());

        let compiled = ops.compile();
        let mut header = RequestHeader::build("GET", b"/", None).unwrap();
        header.insert_header("X-Remove", "bye").unwrap();

        apply_request_headers(&mut header, &compiled);

        assert!(header.headers.get("x-remove").is_none());
        assert_eq!(
            header.headers.get("x-added").unwrap().to_str().unwrap(),
            "value"
        );
        assert_eq!(
            header.headers.get("x-set").unwrap().to_str().unwrap(),
            "set-value"
        );
    }

    #[test]
    fn test_apply_security_response_headers_sets_missing_only() {
        let mut resp = ResponseHeader::build(200, None).unwrap();

        apply_security_response_headers(&mut resp, false);
        assert!(resp.headers.get("strict-transport-security").is_none());
        assert_eq!(
            resp.headers
                .get("x-content-type-options")
                .unwrap()
                .to_str()
                .unwrap(),
            "nosniff"
        );
        assert_eq!(
            resp.headers
                .get("x-frame-options")
                .unwrap()
                .to_str()
                .unwrap(),
            "DENY"
        );
        assert_eq!(
            resp.headers
                .get("referrer-policy")
                .unwrap()
                .to_str()
                .unwrap(),
            "strict-origin-when-cross-origin"
        );
        assert!(resp.headers.get("permissions-policy").is_some());

        // Should not overwrite existing application value
        resp.insert_header("x-frame-options", "SAMEORIGIN").unwrap();
        apply_security_response_headers(&mut resp, true);
        assert_eq!(
            resp.headers
                .get("x-frame-options")
                .unwrap()
                .to_str()
                .unwrap(),
            "SAMEORIGIN"
        );
        assert!(resp.headers.get("strict-transport-security").is_some());
    }
}
