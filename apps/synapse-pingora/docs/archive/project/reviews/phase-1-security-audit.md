# Phase 1 Security Audit: Synapse-Pingora

**Audit Date**: 2026-01-06
**Auditor**: Security Engineering
**Scope**: Phase 1 source files (vhost.rs, config.rs, tls.rs, health.rs, site_waf.rs)

## Executive Summary

This security audit reviewed 5 source files implementing virtual host routing, TLS termination, health checks, and per-site WAF configuration.

**Findings**: 1 P0 Critical, 3 P1 High, 4 P2 Medium, 3 P3 Low

**Overall Risk Assessment**: HIGH - P0 finding must be addressed before production deployment.

---

## P0 Critical Findings

### SYNAPSE-SEC-001: Private Key Path Logged in Debug Output

**CWE-532**: Insertion of Sensitive Information into Log File
**File**: `src/tls.rs`

The TLS configuration loading code logs the private key file path at debug level. This creates risk of sensitive path information leaking to log aggregators.

**Remediation**:
```rust
debug!(
    "Loaded TLS certificate for {}: cert={}, key=[REDACTED]",
    domain, cert_path
);
```

**Priority**: P0 - Block Release

---

## P1 High Findings

### SYNAPSE-SEC-002: Unbounded Configuration File Reading

**CWE-400**: Uncontrolled Resource Consumption
**File**: `src/config.rs`

Configuration file read into memory without size limit. Malicious config could exhaust server memory.

**Remediation**: Add 10MB size limit check before reading.

**Priority**: P1 - Fix Before Production

---

### SYNAPSE-SEC-003: ReDoS Vulnerability in Hostname Matching

**CWE-1333**: Inefficient Regular Expression Complexity
**File**: `src/vhost.rs`

Wildcard hostnames converted to regex without limiting complexity. Pattern like `*.*.*.*.*` could cause CPU exhaustion.

**Remediation**: Limit to max 3 wildcards and 253 character length.

**Priority**: P1 - Fix Before Production

---

### SYNAPSE-SEC-004: Host Header Not Sanitized Before Matching

**CWE-20**: Improper Input Validation
**File**: `src/vhost.rs`

Host header matched without sanitization for null bytes, encoded characters, or invalid DNS characters.

**Remediation**: Add validation for DNS-safe characters, reject null bytes.

**Priority**: P1 - Fix Before Production

---

## P2 Medium Findings

- SYNAPSE-SEC-005: TLS minimum version not enforced in config validation
- SYNAPSE-SEC-006: Health endpoint may leak version info
- SYNAPSE-SEC-007: WAF threshold allows zero value
- SYNAPSE-SEC-008: No path traversal protection for cert paths

## P3 Low Findings

- SYNAPSE-SEC-009: Missing rate limiting on health endpoint
- SYNAPSE-SEC-010: Clone of sensitive TLS configuration
- SYNAPSE-SEC-011: No warning when WAF disabled for site

---

## OWASP Top 10 2021 Coverage

| Category | Findings |
|----------|----------|
| A01: Broken Access Control | SEC-006, SEC-008 |
| A02: Cryptographic Failures | SEC-005, SEC-010 |
| A03: Injection | SEC-003, SEC-004 |
| A04: Insecure Design | SEC-007 |
| A05: Security Misconfiguration | SEC-002, SEC-009 |
| A09: Logging Failures | SEC-001, SEC-011 |

---

## Immediate Actions Required

1. Remove private key path from logs (SEC-001)
2. Add configuration file size limit (SEC-002)
3. Sanitize host header input (SEC-004)
4. Limit wildcard pattern complexity (SEC-003)
