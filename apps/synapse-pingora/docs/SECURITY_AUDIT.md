# Security Audit Report

**Date**: 2026-01-16
**Auditor**: Security Analysis
**Scope**: Synapse-Pingora (Rust) and Signal-Horizon (TypeScript) newly implemented modules

## Executive Summary

This security audit examines seven newly implemented modules across two components:

**Synapse-Pingora (Rust)**:
- `actor/manager.rs` - Actor state management with LRU eviction
- `session/manager.rs` - Session tracking with hijack detection
- `interrogator/cookie_manager.rs` - Cookie-based challenge system
- `interrogator/js_challenge_manager.rs` - JavaScript PoW challenges
- `interrogator/progression_manager.rs` - Challenge escalation orchestrator

**Signal-Horizon (TypeScript)**:
- `services/fleet/rule-distributor.ts` - Rule deployment to sensor fleet
- `services/api-intelligence/index.ts` - API endpoint discovery and schema violation tracking

**Overall Assessment**: The codebase demonstrates strong security awareness with explicit mitigations for common attack vectors. Several areas require attention, with one critical finding related to cryptographic randomness.

---

## Findings Summary

| Severity | Count | Description |
|----------|-------|-------------|
| Critical | 1 | Weak PRNG for security-sensitive IDs |
| High | 2 | Race conditions, timing-based DoS |
| Medium | 5 | Input validation gaps, memory concerns |
| Low | 4 | Code quality, logging improvements |
| Informational | 3 | Best practices recommendations |

---

## Critical Findings

### C-01: Weak PRNG for Actor and Session ID Generation

**Location**: `actor/manager.rs:769-781`, `session/manager.rs:847-859`

**Description**: Both `generate_actor_id()` and `generate_session_id()` use `fastrand` for generating UUIDs. While `fastrand` is fast, it is not cryptographically secure. An attacker who can observe timing patterns or predict the PRNG state could potentially forge actor/session IDs.

```rust
// actor/manager.rs:769-781
fn generate_actor_id() -> String {
    let a = fastrand::u64(..);  // Not cryptographically secure
    let b = fastrand::u64(..);
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        ...
    )
}
```

**Risk**: Session prediction/hijacking, actor impersonation, bypassing security controls

**Recommendation**: Replace `fastrand` with a CSPRNG such as `rand::rngs::OsRng` or `getrandom` for security-sensitive ID generation. For high-throughput scenarios, consider a thread-local CSPRNG seeded from the OS entropy source.

---

## High Severity Findings

### H-01: Potential Race Condition in Actor/Session State Updates

**Location**: `actor/manager.rs:380-394`, `session/manager.rs:357-404`

**Description**: The `get_or_create_actor()` and `validate_request()` methods perform a check-then-act pattern that is not atomic. While DashMap provides thread-safe individual operations, the sequence of operations (correlate -> check -> insert) could lead to race conditions under high concurrency.

```rust
// actor/manager.rs:380-394
if let Some(actor_id) = self.correlate_actor(ip, fingerprint) {
    if let Some(mut entry) = self.actors.get_mut(&actor_id) {
        // Time window between correlate and get_mut where
        // another thread could evict or modify the actor
        entry.add_ip(ip);
        ...
    }
    return actor_id;
}
```

**Risk**: Lost updates, inconsistent state, potential security bypass where an actor's risk score or block status is not properly applied.

**Recommendation**: Use DashMap's `entry` API for atomic upsert operations, or implement a higher-level lock for the complete operation sequence.

### H-02: Unbounded Memory in JS Challenge Page Generation

**Location**: `js_challenge_manager.rs:255-389`

**Description**: The `generate_challenge_page()` function uses string formatting to embed untrusted values (prefix, challenge_id) directly into HTML/JavaScript. While the current implementation generates these values internally, any future modification that accepts user input for these fields would create XSS vulnerabilities.

Additionally, the generated HTML page is created on every challenge request without caching, which could be exploited for memory exhaustion under high load.

**Risk**: Memory exhaustion DoS, potential XSS if inputs are modified

**Recommendation**:
1. Add explicit documentation that `prefix` and `challenge_id` must be internally generated
2. Implement a template caching mechanism
3. Add rate limiting for challenge page generation

---

## Medium Severity Findings

### M-01: Nonce Length Validation After String Operations

**Location**: `js_challenge_manager.rs:184-199`

**Description**: The nonce validation in `validate_pow()` correctly limits nonce length to 32 characters and validates it contains only digits. However, the validation happens after the string is already allocated, meaning an attacker could send extremely large nonces to cause temporary memory allocation.

```typescript
pub fn validate_pow(&self, actor_id: &str, nonce: &str) -> ValidationResult {
    const MAX_NONCE_LENGTH: usize = 32;
    if nonce.len() > MAX_NONCE_LENGTH {  // Already allocated at this point
        return ValidationResult::Invalid(...);
    }
```

**Risk**: Temporary memory spike attacks

**Recommendation**: Validate nonce length at the HTTP layer before passing to the validation function. Consider using a streaming approach for input validation.

### M-02: Escalation History Unbounded Growth (Partially Mitigated)

**Location**: `progression_manager.rs:161-162`, `progression_manager.rs:278-289`

**Description**: The `max_escalation_history` configuration (default: 100) properly bounds the escalation history. However, the implementation uses `remove(0)` which is O(n) for Vec, making it potentially exploitable for algorithmic complexity attacks.

```rust
fn push_escalation_history(...) {
    if state.escalation_history.len() >= self.config.max_escalation_history {
        state.escalation_history.remove(0);  // O(n) operation
    }
    state.escalation_history.push((level, timestamp));
}
```

**Risk**: CPU exhaustion if attackers can trigger rapid escalations

**Recommendation**: Use `VecDeque` instead of `Vec` for O(1) removal from front.

### M-03: Missing Tenant Isolation in API Intelligence Service

**Location**: `api-intelligence/index.ts:58-69`, `api-intelligence/index.ts:203-225`

**Description**: Unlike the `RuleDistributor` which has explicit tenant validation, the `APIIntelligenceService` accepts `tenantId` as a parameter without validating that the calling user/sensor belongs to that tenant. It trusts the provided `tenantId`.

```typescript
async ingestSignal(signal: APIIntelligenceSignal, tenantId: string): Promise<void> {
    // No validation that the signal.sensorId belongs to tenantId
    this.logger.debug({ signal, tenantId }, 'Ingesting API intelligence signal');
    ...
}
```

**Risk**: Cross-tenant data injection, data pollution

**Recommendation**: Add sensor ownership validation similar to `RuleDistributor.validateSensorOwnership()`. Verify that `signal.sensorId` belongs to the specified `tenantId`.

### M-04: Cookie Manager All-Zeros Secret Key Check Is Necessary But Not Sufficient

**Location**: `cookie_manager.rs:139-143`

**Description**: The `CookieManager::new()` correctly rejects all-zeros secret keys. However, this is only one class of weak keys. Patterns like `[0x01; 32]`, `[0xFF; 32]`, or short repeated patterns are equally weak but would be accepted.

```rust
pub fn new(config: CookieConfig) -> Result<Self, CookieError> {
    if config.secret_key == [0u8; 32] {
        return Err(CookieError::InvalidSecretKey);
    }
    // Other weak patterns not checked
```

**Risk**: Weak cryptographic keys leading to cookie forgery

**Recommendation**:
1. Add entropy estimation for the secret key
2. Consider requiring keys to be loaded from secure environment variables or a secrets manager
3. Add tests for obviously weak patterns

### M-05: Sensitive Data in Logs

**Location**: Multiple files

**Description**: Several logging statements may include sensitive information:

- `rule-distributor.ts:89-97` - Logs sensor IDs during isolation violations (operational security concern)
- `api-intelligence/index.ts:157-165` - Logs full template patterns which may contain PII

**Risk**: Information disclosure through log aggregation systems

**Recommendation**: Implement log redaction for sensitive fields. Use structured logging with clear sensitivity markers.

---

## Low Severity Findings

### L-01: Scheduled Deployment Uses Unbounded setTimeout

**Location**: `rule-distributor.ts:449-452`

**Description**: The scheduled deployment feature uses `setTimeout` without storing or tracking the timeout handle. This makes it impossible to cancel scheduled deployments.

```typescript
setTimeout(() => {
    void this.deployImmediate(sensorIds, rules);
}, delayMs);
```

**Risk**: No ability to cancel scheduled operations, potential resource leaks

**Recommendation**: Store timeout handles in a Map keyed by deployment ID, provide cancellation API.

### L-02: Missing Input Validation on Rule IDs

**Location**: `rule-distributor.ts:216-223`

**Description**: The `distributeRules` method accepts `ruleIds` without validating their format. Malformed IDs could cause issues downstream.

**Risk**: Unexpected behavior, potential injection if IDs are used in queries

**Recommendation**: Add validation for rule ID format (e.g., UUID pattern matching).

### L-03: Actor/Session Statistics Use Relaxed Ordering

**Location**: `actor/manager.rs:274-283`, `session/manager.rs:238-249`

**Description**: All atomic operations use `Ordering::Relaxed`, which is correct for statistics but may lead to inconsistent snapshot views when reading multiple counters.

**Risk**: Inconsistent metrics in dashboards/monitoring

**Recommendation**: Use `Ordering::Acquire` when reading for snapshots to ensure consistency.

### L-04: No Jitter in Deployment Retry Delays

**Location**: `rule-distributor.ts:575-577`

**Description**: Rolling deployments use fixed 1-second delays between batches. This could cause thundering herd issues when multiple deployments complete simultaneously.

**Risk**: Coordinated load spikes on infrastructure

**Recommendation**: Add randomized jitter to delays (e.g., 800-1200ms instead of fixed 1000ms).

---

## Informational Findings

### I-01: Cookie Manager O(n) Actor Correlation

**Location**: `cookie_manager.rs:269-284`

**Description**: The `correlate_actor()` method iterates through all tracked challenges to find a matching actor. This is O(n) and documented as such, but could become a performance bottleneck at scale.

```rust
// Note: This is O(n) where n is number of tracked actors.
// For large scale, consider maintaining a reverse lookup table.
```

**Recommendation**: Implement the suggested reverse lookup table for production deployments.

### I-02: Consider Using Constant-Time Comparison More Broadly

**Location**: `cookie_manager.rs:384-391`

**Description**: The `constant_time_eq` function using the `subtle` crate is excellent for preventing timing attacks. This pattern should be applied consistently across all security-sensitive comparisons.

**Positive Finding**: Proper use of `subtle::ConstantTimeEq` for actor hash and signature verification.

**Recommendation**: Audit all string comparisons in security-sensitive contexts to ensure they use constant-time comparison.

### I-03: Good Tenant Isolation Pattern in Rule Distributor

**Location**: `rule-distributor.ts:52-99`

**Description**: The `TenantIsolationError` and `validateSensorOwnership()` pattern demonstrates excellent security hygiene. The pattern of validating ownership before any operation and treating non-existent sensors as unauthorized is correct.

```typescript
// Sensor not found - treat as unauthorized (don't leak info about non-existent sensors)
unauthorizedSensorIds.push(sensorId);
```

**Positive Finding**: This pattern should be replicated in other multi-tenant services.

---

## OWASP Top 10 Analysis

| Category | Status | Notes |
|----------|--------|-------|
| A01:2021-Broken Access Control | PARTIAL | Good tenant isolation in RuleDistributor, missing in APIIntelligence |
| A02:2021-Cryptographic Failures | WARN | Weak PRNG for IDs (C-01), proper HMAC for cookies |
| A03:2021-Injection | GOOD | Parameterized queries via Prisma, no SQL injection vectors |
| A04:2021-Insecure Design | GOOD | Challenge escalation well-designed |
| A05:2021-Security Misconfiguration | INFO | All-zeros key rejected, but not comprehensive |
| A06:2021-Vulnerable Components | N/A | Dependency audit not in scope |
| A07:2021-Authentication Failures | GOOD | Session hijack detection via JA4 fingerprinting |
| A08:2021-Software/Data Integrity | GOOD | Rule hash verification, HMAC signatures |
| A09:2021-Security Logging | PARTIAL | Good logging, but may include sensitive data |
| Atlas Crew:2021-SSRF | N/A | No outbound request functionality reviewed |

---

## DoS Vector Analysis

| Vector | Risk Level | Mitigation Status |
|--------|-----------|-------------------|
| Memory Exhaustion via Actor/Session Creation | LOW | LRU eviction with `max_actors`/`max_sessions` limits |
| Memory Exhaustion via Session IDs per Actor | LOW | Bounded by `max_session_ids` (default: 50) |
| Memory Exhaustion via Rule Matches | LOW | Bounded by `max_rule_matches` (default: 100) |
| Memory Exhaustion via Escalation History | LOW | Bounded by `max_escalation_history` (default: 100) |
| Memory Exhaustion via Hijack Alerts | LOW | Bounded by `max_alerts_per_session` (default: 10) |
| CPU Exhaustion via PoW Difficulty Manipulation | LOW | Difficulty configured server-side |
| CPU Exhaustion via Rapid Escalations | MEDIUM | O(n) history removal (M-02) |
| Algorithmic Complexity Attacks | LOW | Sampling-based LRU eviction |

---

## Recommendations Priority

### Immediate Action (Before Production)

1. **C-01**: Replace `fastrand` with CSPRNG for ID generation
2. **M-03**: Add tenant validation to APIIntelligenceService

### Short-Term (Next Sprint)

3. **H-01**: Implement atomic operations for actor/session state changes
4. **M-02**: Replace Vec with VecDeque for escalation history
5. **M-04**: Add comprehensive weak key detection

### Medium-Term (Backlog)

6. **H-02**: Implement template caching for challenge pages
7. **M-01**: Move nonce validation to HTTP layer
8. **M-05**: Implement log redaction for sensitive data
9. **L-01**: Add deployment cancellation API

---

## Positive Security Patterns Observed

The codebase demonstrates security-conscious development:

1. **Constant-time comparisons** using the `subtle` crate for signature verification
2. **Bounded data structures** with configurable limits to prevent memory exhaustion
3. **Tenant isolation enforcement** with explicit ownership validation
4. **Secure cookie attributes** (HttpOnly, Secure, SameSite by default)
5. **HMAC-SHA256 signatures** for cookie integrity
6. **JA4 fingerprint binding** for session hijack detection
7. **Progressive challenge escalation** to balance security and UX
8. **Lazy eviction** to bound memory while avoiding O(n) scans on every request
9. **Background cleanup tasks** for expired state management

---

## Conclusion

The reviewed modules demonstrate a mature security posture with explicit consideration for common attack vectors. The critical finding (C-01) regarding PRNG usage should be addressed before production deployment. The tenant isolation gap in APIIntelligenceService (M-03) should also be prioritized given its potential for cross-tenant data pollution.

The architecture's use of bounded data structures, constant-time comparisons, and progressive security challenges represents security best practices. With the recommended fixes applied, these modules would meet enterprise security standards.
