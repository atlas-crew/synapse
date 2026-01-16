# Performance Analysis Report

**Modules Analyzed:**
- Synapse-Pingora (Rust): ActorManager, SessionManager, Interrogator subsystem
- Signal-Horizon (TypeScript): RuleDistributor, APIIntelligenceService

**Analysis Date:** January 2026

---

## Executive Summary

The analyzed modules demonstrate solid performance foundations with DashMap-based concurrent data structures and lock-free operations. However, several bottlenecks exist that will impact performance at the target scale of 100K actors and 50K sessions. Key concerns include O(n) scan patterns in listing operations, sequential database operations in the TypeScript services, and potential memory exhaustion vectors that have been mitigated but require monitoring.

---

## 1. Synapse-Pingora: ActorManager

**Target Scale:** 100,000 concurrent actors

### 1.1 Time Complexity Analysis

| Operation | Current Complexity | Hot Path? | Assessment |
|-----------|-------------------|-----------|------------|
| `get_or_create_actor()` | O(1) amortized | YES | OPTIMAL - DashMap provides lock-free reads |
| `record_rule_match()` | O(1) | YES | OPTIMAL - Direct key lookup |
| `get_actor()` | O(1) | YES | OPTIMAL |
| `get_actor_by_ip()` | O(1) | YES | OPTIMAL - Secondary index lookup |
| `get_actor_by_fingerprint()` | O(1) | YES | OPTIMAL |
| `block_actor()` | O(1) | NO | OPTIMAL |
| `list_actors()` | **O(n log n)** | NO | CONCERN - Full scan + sort |
| `list_blocked_actors()` | **O(n)** | NO | CONCERN - Full scan with filter |
| `decay_scores()` | **O(n)** | NO (background) | ACCEPTABLE - Background task |
| `evict_oldest()` | O(sample_size log sample_size) | NO | OPTIMIZED - Sampling approach avoids O(n) |

**Hot Path Verdict:** All hot path operations are O(1). Performance requirements met.

### 1.2 Memory Usage Analysis

```rust
// Per-actor memory footprint (estimated)
struct ActorState {
    actor_id: String,              // ~40 bytes (UUID)
    risk_score: f64,               // 8 bytes
    rule_matches: Vec<RuleMatch>,  // 24 + (max 100 * ~80 bytes) = 8KB max
    anomaly_count: u64,            // 8 bytes
    session_ids: Vec<String>,      // 24 + (max 50 * ~40 bytes) = 2KB max
    first_seen: u64,               // 8 bytes
    last_seen: u64,                // 8 bytes
    ips: HashSet<IpAddr>,          // ~56 bytes + entries (unbounded!)
    fingerprints: HashSet<String>, // ~56 bytes + entries (unbounded!)
    is_blocked: bool,              // 1 byte
    block_reason: Option<String>,  // 24 bytes + string
    blocked_since: Option<u64>,    // 16 bytes
}
// Estimated per-actor: 10-12 KB typical, up to 15+ KB with many IPs/fingerprints
```

**Memory Projection at 100K actors:**
- Typical: ~1 GB
- Worst case (many IPs/fingerprints per actor): 1.5+ GB
- DashMap overhead: ~5-10%

**Critical Finding - UNBOUNDED COLLECTIONS:**
```rust
pub ips: HashSet<IpAddr>,           // No bounds! Memory exhaustion risk
pub fingerprints: HashSet<String>,  // No bounds! Memory exhaustion risk
```

**Recommendation P1:** Add bounds to `ips` and `fingerprints` similar to `max_session_ids`:
```rust
pub max_ips_per_actor: usize,         // Suggested: 100
pub max_fingerprints_per_actor: usize, // Suggested: 50
```

### 1.3 Concurrency Analysis

**Lock Contention:**
- DashMap uses sharded RwLocks (default 256 shards)
- At 100K actors across 256 shards: ~390 actors per shard
- Write contention expected to be minimal with good hash distribution

**Thread Safety Issues:** None identified. All state access through DashMap.

**Atomic Operations:**
```rust
pub struct ActorStats {
    pub total_actors: AtomicU64,      // Relaxed ordering - correct for counters
    pub blocked_actors: AtomicU64,
    pub correlations_made: AtomicU64,
    pub evictions: AtomicU64,
    pub total_created: AtomicU64,
    pub total_rule_matches: AtomicU64,
}
```
Assessment: Correct use of Relaxed ordering for non-critical statistics.

### 1.4 I/O Patterns

The ActorManager is **entirely in-memory** with no persistence I/O on the hot path.

**Background Tasks:**
- `decay_scores()`: Iterates all actors, modifies in-place. No I/O.
- `evict_oldest()`: Sampling-based eviction. No I/O.

**Recommendation P2:** Consider periodic persistence to survive restarts. Current implementation loses all actor state on restart.

### 1.5 Caching Effectiveness

**Secondary Index Design:**
```rust
ip_to_actor: DashMap<IpAddr, String>,           // O(1) IP lookup
fingerprint_to_actor: DashMap<String, String>,  // O(1) fingerprint lookup
```

**Assessment:** Excellent design. Both indexes enable O(1) correlation without scanning primary storage.

**Eviction Coherence:**
```rust
fn remove_actor(&self, actor_id: &str) {
    if let Some((_, actor)) = self.actors.remove(actor_id) {
        for ip in &actor.ips {
            self.ip_to_actor.remove(ip);  // Cleanup secondary indexes
        }
        for fp in &actor.fingerprints {
            self.fingerprint_to_actor.remove(fp);
        }
    }
}
```
**Assessment:** Correct - secondary indexes are cleaned up on eviction.

---

## 2. Synapse-Pingora: SessionManager

**Target Scale:** 50,000 concurrent sessions

### 2.1 Time Complexity Analysis

| Operation | Current Complexity | Hot Path? | Assessment |
|-----------|-------------------|-----------|------------|
| `validate_request()` | O(1) | YES | OPTIMAL |
| `create_session()` | O(1) | YES | OPTIMAL |
| `get_session()` | O(1) | NO | OPTIMAL |
| `touch_session()` | O(1) | YES | OPTIMAL |
| `bind_to_actor()` | O(1) amortized | NO | OPTIMAL |
| `list_sessions()` | **O(n log n)** | NO | CONCERN - Full scan + sort |
| `list_suspicious_sessions()` | **O(n)** | NO | CONCERN - Full scan |
| `cleanup_expired_sessions()` | **O(n)** | NO (background) | ACCEPTABLE |

**Hot Path Verdict:** All hot path operations are O(1). Performance requirements met.

### 2.2 Memory Usage Analysis

```rust
// Per-session memory footprint (estimated)
struct SessionState {
    session_id: String,          // ~45 bytes (sess-UUID)
    token_hash: String,          // ~64 bytes (SHA-256 hex)
    actor_id: Option<String>,    // ~48 bytes
    creation_time: u64,          // 8 bytes
    last_activity: u64,          // 8 bytes
    request_count: u64,          // 8 bytes
    bound_ja4: Option<String>,   // ~40 bytes
    bound_ip: Option<IpAddr>,    // ~24 bytes
    is_suspicious: bool,         // 1 byte
    hijack_alerts: Vec<HijackAlert>, // max_alerts_per_session * ~200 bytes
}
// Estimated per-session: 500-800 bytes typical, up to 2.5 KB with max alerts
```

**Memory Projection at 50K sessions:**
- Typical: ~25-40 MB
- With max alerts: ~125 MB

**Assessment:** Memory footprint is well-controlled. The `max_alerts_per_session` (default: 10) provides effective bounding.

### 2.3 Concurrency Analysis

**Multiple DashMaps with Cross-References:**
```rust
sessions: DashMap<String, SessionState>,      // Primary: token_hash -> session
session_by_id: DashMap<String, String>,       // session_id -> token_hash
actor_sessions: DashMap<String, Vec<String>>, // actor_id -> [session_ids]
```

**Race Condition Risk:**
```rust
fn remove_session(&self, token_hash: &str) -> bool {
    if let Some((_, session)) = self.sessions.remove(token_hash) {
        self.session_by_id.remove(&session.session_id);
        // Race window: session removed but actor_sessions still contains reference
        if let Some(actor_id) = &session.actor_id {
            if let Some(mut entry) = self.actor_sessions.get_mut(actor_id) {
                entry.retain(|id| id != &session.session_id);
            }
        }
    }
}
```

**Finding:** Small race window where `session_by_id` lookup could return stale data. Impact is low (phantom session ID that resolves to None).

**Recommendation P3:** Consider using `DashMap::entry()` API for atomic compound operations.

### 2.4 Hijack Detection Performance

```rust
fn detect_hijack(&self, session: &SessionState, ip: IpAddr, ja4: Option<&str>) -> Option<HijackAlert> {
    // JA4 check: O(1) string comparison
    if self.config.enable_ja4_binding {
        if let (Some(bound_ja4), Some(current_ja4)) = (&session.bound_ja4, ja4) {
            if bound_ja4 != current_ja4 {
                return Some(HijackAlert { ... });
            }
        }
    }
    // IP check: O(1)
    if self.config.enable_ip_binding { ... }
    None
}
```

**Assessment:** O(1) constant-time hijack detection. No performance concerns.

---

## 3. Synapse-Pingora: Interrogator Subsystem

### 3.1 ProgressionManager

**Time Complexity:**

| Operation | Complexity | Assessment |
|-----------|-----------|------------|
| `get_challenge()` | O(1) | OPTIMAL |
| `record_failure()` | O(1) | OPTIMAL |
| `record_success()` | O(1) | OPTIMAL |
| `list_actors_at_level()` | **O(n)** | CONCERN - Full scan |
| `list_all_actors()` | **O(n)** | CONCERN - Full scan |
| `run_maintenance()` | **O(n)** | Background - ACCEPTABLE |

**Memory Bounds (GOOD):**
```rust
/// Max escalation history entries per actor (default: 100)
/// Prevents unbounded memory growth from malicious actors
pub max_escalation_history: usize,
```

The `push_escalation_history()` correctly enforces this bound.

### 3.2 CookieManager

**Critical Performance Issue - O(n) Correlation:**
```rust
pub fn correlate_actor(&self, cookie_value: &str) -> Option<String> {
    // ...
    // Search for actor with matching hash (constant-time comparison)
    for entry in self.challenges.iter() {  // O(n) scan!
        let challenge = entry.value();
        let expected_hash = self.hash_actor_id(&challenge.actor_id);
        if constant_time_eq(actor_hash.as_bytes(), expected_hash.as_bytes()) {
            // ...
        }
    }
    None
}
```

**Recommendation P4 (HIGH):** Add reverse lookup index `hash_to_actor: DashMap<String, String>` to enable O(1) correlation.

### 3.3 JsChallengeManager

**Nonce Validation Security (GOOD):**
```rust
pub fn validate_pow(&self, actor_id: &str, nonce: &str) -> ValidationResult {
    // SECURITY: Validate nonce length to prevent memory exhaustion attacks.
    const MAX_NONCE_LENGTH: usize = 32;
    if nonce.len() > MAX_NONCE_LENGTH {
        return ValidationResult::Invalid(...);
    }
    // Validate nonce is numeric (expected from JS client)
    if !nonce.chars().all(|c| c.is_ascii_digit()) {
        return ValidationResult::Invalid("Nonce must be numeric".to_string());
    }
}
```

**Assessment:** Proper input validation prevents memory exhaustion attacks.

**SHA-256 Performance:**
```rust
fn compute_sha256_hex(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}
```

**Benchmark Estimate:** ~1 microsecond per hash verification. No concerns.

---

## 4. Signal-Horizon: RuleDistributor

### 4.1 Time Complexity Analysis

| Operation | Complexity | Assessment |
|-----------|-----------|------------|
| `validateSensorOwnership()` | O(s) where s = sensor count | Database query |
| `pushRules()` | O(s * r) | s = sensors, r = rules |
| `deployImmediate()` | **O(s * r)** | CONCERN - Sequential upserts |
| `deployCanary()` | O(s * r) | Same as immediate + delays |
| `deployRolling()` | O(s) | Sequential sensor deployment |
| `deployBlueGreen()` | O(s) | Parallel staging, sequential switch wait |

### 4.2 Critical Bottleneck - Sequential Database Operations

```typescript
// deployImmediate() - O(s * r) sequential upserts
for (const sensorId of sensorIds) {
  for (const rule of rules) {
    await this.prisma.ruleSyncState.upsert({  // BLOCKING!
      where: { sensorId_ruleId: { sensorId, ruleId: rule.id } },
      create: { sensorId, ruleId: rule.id, status: 'pending' },
      update: { status: 'pending', syncedAt: null, error: null },
    });
  }
}
```

**Impact at Scale:**
- 1000 sensors x 100 rules = 100,000 sequential database operations
- At 1ms per operation = 100 seconds minimum latency

**Recommendation P5 (CRITICAL):** Use batch operations:
```typescript
// Use Prisma transaction with createMany/updateMany
await this.prisma.$transaction([
  this.prisma.ruleSyncState.deleteMany({
    where: { sensorId: { in: sensorIds } }
  }),
  this.prisma.ruleSyncState.createMany({
    data: sensorIds.flatMap(sensorId =>
      rules.map(rule => ({
        sensorId,
        ruleId: rule.id,
        status: 'pending',
      }))
    ),
    skipDuplicates: true,
  }),
]);
```

### 4.3 Rolling Deployment Health Check Bottleneck

```typescript
private async waitForHealthConfirmation(
  sensorIds: string[],
  timeout: number,
  checkInterval: number
): Promise<HealthCheckResult[]> {
  while (Date.now() - startTime < timeout) {
    for (const sensorId of sensorIds) {
      const health = await this.checkSensorHealth(sensorId);  // Sequential!
    }
    await this.sleep(checkInterval);
  }
}
```

**Recommendation P6:** Use `Promise.all()` for parallel health checks:
```typescript
const healthPromises = sensorIds.map(id => this.checkSensorHealth(id));
const results = await Promise.all(healthPromises);
```

### 4.4 Blue/Green Deployment State Management

```typescript
private activeDeployments: Map<string, BlueGreenDeploymentState> = new Map();
```

**Finding:** In-memory deployment state is lost on service restart. Active blue/green deployments will be orphaned.

**Recommendation P7:** Persist deployment state to database with recovery mechanism on startup.

---

## 5. Signal-Horizon: APIIntelligenceService

### 5.1 Time Complexity Analysis

| Operation | Complexity | Assessment |
|-----------|-----------|------------|
| `ingestSignal()` | O(1) database + O(1) emit | OPTIMAL |
| `ingestBatch()` | **O(n)** sequential | CONCERN |
| `getDiscoveryStats()` | O(parallel queries) | GOOD - Uses Promise.all |
| `getTopViolatingEndpoints()` | O(v) where v = violations | In-memory aggregation |
| `getViolationTrends()` | O(v) | In-memory aggregation |
| `getDiscoveryTrend()` | **O(d)** sequential queries | CONCERN - d queries for d days |

### 5.2 Batch Ingestion Bottleneck

```typescript
async ingestBatch(batch: SignalBatch, tenantId: string): Promise<BatchIngestionResult> {
  for (const signal of batch.signals) {
    try {
      await this.ingestSignal(signal, tenantId);  // Sequential!
      accepted++;
    } catch (error) {
      rejected++;
    }
  }
}
```

**Recommendation P8:** Use parallel processing with concurrency limit:
```typescript
import pLimit from 'p-limit';
const limit = pLimit(10); // Max 10 concurrent

const results = await Promise.allSettled(
  batch.signals.map(signal =>
    limit(() => this.ingestSignal(signal, tenantId))
  )
);
```

### 5.3 Discovery Trend N+1 Query Problem

```typescript
private async getDiscoveryTrend(tenantId: string, days: number) {
  for (let i = days - 1; i >= 0; i--) {
    const count = await this.prisma.endpoint.count({  // One query per day!
      where: { tenantId, firstSeenAt: { gte: date, lt: nextDate } }
    });
    trend.push({ date: dateStr, count });
  }
}
```

**Recommendation P9:** Use single aggregation query:
```typescript
const trends = await this.prisma.$queryRaw`
  SELECT DATE(first_seen_at) as date, COUNT(*) as count
  FROM endpoints
  WHERE tenant_id = ${tenantId}
    AND first_seen_at >= ${since}
  GROUP BY DATE(first_seen_at)
  ORDER BY date
`;
```

### 5.4 Top Violating Endpoints In-Memory Aggregation

```typescript
private async getTopViolatingEndpoints(tenantId: string, since: Date) {
  const violations = await this.prisma.signal.findMany({
    where: { tenantId, signalType: 'SCHEMA_VIOLATION', createdAt: { gte: since } },
    select: { metadata: true },  // Fetches ALL violations into memory
  });

  // In-memory aggregation
  const endpointCounts = new Map<string, { method: string; count: number }>();
  for (const v of violations) { ... }
}
```

**Memory Concern:** At high violation volumes (100K+ per week), this could consume significant memory.

**Recommendation P10:** Push aggregation to database:
```typescript
// Use raw query for server-side aggregation
const topViolators = await this.prisma.$queryRaw`
  SELECT
    metadata->>'endpoint' as endpoint,
    metadata->>'method' as method,
    COUNT(*) as violation_count
  FROM signals
  WHERE tenant_id = ${tenantId}
    AND signal_type = 'SCHEMA_VIOLATION'
    AND created_at >= ${since}
  GROUP BY metadata->>'endpoint', metadata->>'method'
  ORDER BY violation_count DESC
  LIMIT 10
`;
```

---

## 6. Summary of Recommendations

### Priority 1 (Critical - Fix Before Scale)

| ID | Component | Issue | Recommendation |
|----|-----------|-------|----------------|
| P5 | RuleDistributor | O(s*r) sequential upserts | Batch database operations |
| P6 | RuleDistributor | Sequential health checks | Parallel Promise.all() |
| P8 | APIIntelligence | Sequential batch ingestion | Parallel with concurrency limit |

### Priority 2 (High - Fix Soon)

| ID | Component | Issue | Recommendation |
|----|-----------|-------|----------------|
| P1 | ActorManager | Unbounded ips/fingerprints | Add max_ips_per_actor, max_fingerprints_per_actor |
| P4 | CookieManager | O(n) correlation scan | Add hash_to_actor reverse index |
| P9 | APIIntelligence | N+1 trend queries | Single aggregation query |
| P10 | APIIntelligence | In-memory violation aggregation | Database-side aggregation |

### Priority 3 (Medium - Improve)

| ID | Component | Issue | Recommendation |
|----|-----------|-------|----------------|
| P2 | ActorManager | No persistence | Add periodic state snapshots |
| P3 | SessionManager | Minor race window | Use DashMap::entry() API |
| P7 | RuleDistributor | In-memory deployment state | Persist to database |

---

## 7. Performance Test Recommendations

### Load Testing Scenarios

1. **ActorManager at Scale:**
   - Create 100K actors with diverse IP/fingerprint patterns
   - Measure `get_or_create_actor()` latency percentiles (p50, p95, p99)
   - Monitor memory growth over 24h simulation

2. **SessionManager at Scale:**
   - Maintain 50K concurrent sessions
   - Simulate 10K requests/second across sessions
   - Measure hijack detection latency

3. **RuleDistributor Deployment:**
   - Deploy 100 rules to 1000 sensors
   - Measure end-to-end deployment time
   - Test blue/green switch atomicity under load

4. **APIIntelligence Ingestion:**
   - Batch ingestion of 10K signals
   - Measure throughput and database connection pool utilization

### Monitoring Metrics to Add

- ActorManager: actors_per_shard histogram (detect hot shards)
- SessionManager: sessions_per_actor histogram (detect anomalies)
- RuleDistributor: deployment_duration_seconds histogram
- APIIntelligence: batch_processing_duration_seconds histogram

---

## 8. Conclusion

The Synapse-Pingora Rust modules demonstrate **excellent hot-path performance** with O(1) operations for all critical request-processing paths. The DashMap-based architecture provides effective lock-free concurrency.

The Signal-Horizon TypeScript modules have **significant optimization opportunities** in batch processing and database query patterns. The sequential operation patterns will become bottlenecks at scale.

**Overall Assessment:**
- Rust components: Ready for 100K actors / 50K sessions with P1/P4 fixes
- TypeScript components: Require P5/P6/P8 fixes before scaling beyond 1000 sensors
