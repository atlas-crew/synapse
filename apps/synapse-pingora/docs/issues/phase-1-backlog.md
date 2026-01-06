# Phase 1 Issues Backlog

**Created**: 2026-01-06
**Status**: Active
**Source**: Phase 1C Quality Gate Reviews

This document tracks P2-P4 issues identified during Phase 1 quality gate reviews that are documented for future work rather than blocking the current phase.

---

## P2 Medium Priority Issues

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
| SEC-008 | Path traversal | tls.rs | Cert paths not validated for traversal |

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

## Recommended Dependencies (Phase 2)

```toml
[dependencies]
ahash = "0.8"           # Faster hashing (PERF-P2-2)
arc-swap = "1.6"        # Lock-free pointer swap (P1 remediation)
unicase = "2.7"         # Case-insensitive comparison (P0 remediation)
```

---

## Review Schedule

- **Phase 2**: Address performance P2 issues during management features implementation
- **Phase 3**: Address UI-related backlog during dashboard integration
- **Phase 4**: Security hardening sweep to close remaining security backlog
