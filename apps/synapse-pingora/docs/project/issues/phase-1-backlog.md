# Phase 1 Issues Backlog

**Created**: 2026-01-06
**Updated**: 2026-01-07
**Status**: Partially Resolved
**Source**: Phase 1C Quality Gate Reviews

This document tracks issues identified during Phase 1 quality gate reviews.

---

## ✅ Resolved Issues (P0/P1)

The following critical issues from the security audit have been addressed:

| ID | Issue | File | Resolution |
|----|-------|------|------------|
| SEC-001 (P0) | Private key path logged | tls.rs | ✅ Logs only domain, not paths |
| SEC-002 (P1) | Unbounded config file read | config.rs | ✅ MAX_CONFIG_SIZE limit added |
| SEC-003 (P1) | ReDoS in hostname matching | vhost.rs | ✅ MAX_WILDCARDS=3, MAX_HOSTNAME_LEN=253 |
| SEC-004 (P1) | Host header not sanitized | vhost.rs | ✅ sanitize_host() validates DNS chars, rejects null bytes |
| SEC-008 (P2) | Path traversal | tls.rs | ✅ validate_path() checks for traversal |

---

## 🔶 Outstanding P2 Medium Priority Issues

### Performance

| ID | Issue | File | Description |
|----|-------|------|-------------|
| PERF-P2-1 | Health response allocation | health.rs | Unnecessary String allocations in health response |
| PERF-P2-2 | Default HashMap hasher | vhost.rs, tls.rs | Consider ahash for 2-3x faster hashing |
| PERF-P2-3 | SiteConfig clone | site_waf.rs | Clone per-request adds overhead |

### Security

| ID | Issue | File | Description |
|----|-------|------|-------------|
| SEC-005 | TLS version validation | tls.rs | min_tls_version accepts invalid values |
| SEC-006 | Health endpoint info leak | health.rs | Version info aids fingerprinting |
| SEC-007 | WAF threshold bounds | site_waf.rs | Zero threshold allowed |

---

## P3 Low Priority Issues

### Performance

| ID | Issue | File | Description |
|----|-------|------|-------------|
| PERF-P3-1 | Vec pre-allocation | config.rs | Pre-allocate vector capacity |
| PERF-P3-2 | Inline hints | various | Add #[inline] to small accessors |
| PERF-P3-3 | Cow for errors | various | Use Cow<str> for static error messages |

### Security

| ID | Issue | File | Description |
|----|-------|------|-------------|
| SEC-009 | Health rate limiting | health.rs | No rate limit on health endpoint |
| SEC-010 | TlsConfig Clone | tls.rs | Sensitive paths duplicated in memory |
| SEC-011 | WAF disable warning | site_waf.rs | No audit log when WAF disabled |

---

## P4 Future Considerations

### Performance
- SIMD-accelerated string operations for hostname parsing
- Object pool for request context to avoid per-request allocations
- Cache-line alignment for hot structs

### Security
- Structured security logging
- Audit trail for configuration changes
- Configuration schema validation at startup

---

## 🔴 Outstanding Performance P1 Issues

From performance review - should be addressed for production scale:

| ID | Issue | File | Description | Impact |
|----|-------|------|-------------|--------|
| PERF-P0-1 | Hot path allocation | vhost.rs | `to_lowercase()` allocates on every request | ~500ns-2μs/req |
| PERF-P0-2 | Blocking file I/O | config.rs | `std::fs::read_to_string` blocks async | Runtime stalls |
| PERF-P1-1 | RwLock contention | vhost.rs | Read lock per-request under high concurrency | 10-50% throughput |
| PERF-P1-2 | Linear wildcard scan | vhost.rs | O(n) scan for wildcard matches | Scales with config |
| PERF-P1-3 | TLS cert clone | tls.rs | ✅ Now uses Arc<CertifiedKey> | Fixed |

---

## Recommended Dependencies (Future)

```toml
[dependencies]
ahash = "0.8"           # Faster hashing (PERF-P2-2)
arc-swap = "1.6"        # Lock-free pointer swap (PERF-P1-1)
unicase = "2.7"         # Case-insensitive comparison (PERF-P0-1)
```

---

## Status Summary

| Category | Total | Resolved | Outstanding |
|----------|-------|----------|-------------|
| Security P0/P1 | 4 | 4 | 0 |
| Security P2/P3 | 6 | 1 | 5 |
| Performance P0/P1 | 5 | 1 | 4 |
| Performance P2/P3 | 6 | 0 | 6 |

**Next Actions**:
- Performance P0/P1 issues should be addressed before high-scale production deployment
- Security P2/P3 issues are acceptable risk for initial deployment
- Consider ahash and arc-swap dependencies for Phase 6+ optimization
