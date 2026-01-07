# Phase 1 Performance Review: Synapse-Pingora

**Review Date**: 2026-01-06
**Reviewer**: Performance Engineering
**Scope**: Phase 1 source files (vhost.rs, config.rs, tls.rs, health.rs, site_waf.rs)

## Executive Summary

The Phase 1 implementation demonstrates solid foundational architecture with appropriate use of Rust's ownership model and async patterns. Several optimization opportunities exist, primarily around allocation reduction in hot paths and lock contention management.

**Overall Assessment**: Good baseline with targeted optimization opportunities

| Category | Rating | Notes |
|----------|--------|-------|
| Allocation Efficiency | B | Some unnecessary cloning in hot paths |
| Async Correctness | A | Proper async/await usage throughout |
| Lock Contention | B- | RwLock patterns need attention |
| Data Structures | A- | Good choices, minor improvements possible |
| Memory Layout | B+ | Reasonable struct sizing |

---

## P0 Issues (Critical - Performance Regressions)

### P0-1: String Allocation in Hot Path - `vhost.rs`

**Impact**: High

`to_lowercase()` allocates a new String on every request lookup. With thousands of RPS, this creates significant allocation pressure.

**Recommendation**: Use case-insensitive comparison or pre-normalize hostnames at config load time.

**Estimated Impact**: ~500ns-2μs savings per request (significant for 2μs target)

---

### P0-2: Blocking File I/O in Async Context - `config.rs`

**Impact**: High

`std::fs::read_to_string` is a blocking syscall. If called from async context (e.g., hot reload), this blocks the Tokio runtime thread.

**Recommendation**: Use `tokio::fs::read_to_string` for async contexts or run on blocking thread pool.

**Estimated Impact**: Prevents potential runtime stalls during config reload

---

## P1 Issues (High Priority)

### P1-1: RwLock Contention Pattern - `vhost.rs`

**Impact**: Medium-High

If wrapped in `Arc<RwLock<>>` for hot reload, every request takes a read lock. Under high concurrency, this creates contention.

**Recommendation**: Use `arc_swap` crate for lock-free reads.

**Estimated Impact**: 10-50% throughput improvement under high concurrency

---

### P1-2: Wildcard Matching Linear Scan - `vhost.rs`

**Impact**: Medium-High (scales with config size)

Linear O(n) scan for each request when exact match fails. With many wildcard entries, this degrades performance.

**Recommendation**: Use trie-based structure or pre-sort wildcards by specificity.

**Estimated Impact**: O(n) → O(log n) or O(k) where k = hostname length

---

### P1-3: TLS Certificate Clone on Every Connection - `tls.rs`

**Impact**: Medium-High

If `CertifiedKey` contains owned data, cloning on every TLS handshake is expensive.

**Recommendation**: Return `Arc<CertifiedKey>` to share ownership without copying.

**Estimated Impact**: ~1-5μs savings per TLS handshake

---

## P2-P4 Issues (Backlog)

- P2-1: Unnecessary String allocation in health response
- P2-2: HashMap default hasher (consider ahash)
- P2-3: SiteConfig clone in WAF module
- P3-1: Vec pre-allocation in config parsing
- P3-2: Inline small functions
- P3-3: Use `Cow<str>` for error messages

---

## Recommended Dependencies

```toml
[dependencies]
ahash = "0.8"           # Faster hashing
arc-swap = "1.6"        # Lock-free pointer swap
unicase = "2.7"         # Case-insensitive comparison
```

---

## Conclusion

The Phase 1 implementation provides a solid foundation. P0 issues (hot path allocation, blocking I/O) should be addressed before production. P1 issues become critical at scale (>10k RPS) and should be planned for Phase 2.

With recommended optimizations, target latencies (26μs detection, 2μs clean) appear achievable.
