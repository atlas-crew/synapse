# Synapse-Pingora Gap Analysis

> **Technical Reference**: `09-Synapse-Technical-Reference.pdf` (54 pages)
> **Implementation**: `apps/synapse-pingora/` (43 Rust source files)
> **Analysis Date**: 2026-01-15

## Executive Summary

The synapse-pingora implementation covers **~60%** of the features documented in the Technical Reference. Core proxy functionality, WAF detection via libsynapse, and campaign correlation are well-implemented. However, several critical intelligence systems remain unimplemented, particularly around **Actor/Session Management**, the **Interrogator System** (challenge serving), and **Signal Intelligence**.

### Implementation Score by Category

| Category | Documented | Implemented | Coverage |
|----------|-----------|-------------|----------|
| Core Proxy | 12 features | 12 | ✅ 100% |
| WAF Detection | 8 features | 7 | ✅ 88% |
| Entity Tracking | 6 features | 5 | ✅ 83% |
| Campaign Correlation | 7 detectors | 7 | ✅ 100% |
| Interrogator System | 5 components | 1 | ❌ 20% |
| State Management | 3 stores | 1 | ❌ 33% |
| API Profiling | 4 components | 0.5 | ❌ 12% |
| Signal Intelligence | 4 components | 0 | ❌ 0% |
| Admin API | 80+ endpoints | ~50 | ⚠️ 63% |

---

## 🔴 P0 - Critical Gaps (Blocks Core Functionality)

### 1. ActorManager - Not Implemented

**PDF Reference**: Page 12, Component Architecture
**Expected Location**: `src/actor/manager.rs` or `src/state/actor_manager.rs`
**Current Status**: Only mentioned in comments (`persistence/mod.rs:6`)

```
PDF Specification:
- 100,000 actor LRU capacity
- Per-actor state: risk_score, rule_matches[], anomaly_count, session_ids[]
- 15-minute decay interval
- Persistence to disk every 5 minutes
```

**Impact**: Cannot track individual threat actors across requests or correlate behavior patterns.

---

### 2. SessionManager - Not Implemented

**PDF Reference**: Page 12, Component Architecture
**Expected Location**: `src/session/manager.rs`
**Current Status**: Only referenced in documentation

```
PDF Specification:
- 50,000 session LRU capacity
- Session tracking: token_hash, actor_id, creation_time, request_count
- Token rotation detection
- Session hijacking detection via JA4 fingerprint mismatch
```

**Impact**: Cannot detect session-based attacks (hijacking, token reuse, impossible travel).

---

### 3. Interrogator System - Partially Implemented

**PDF Reference**: Page 38, Interrogator System Architecture
**Current Status**: Only TarpitManager exists

| Component | Status | File |
|-----------|--------|------|
| TarpitManager | ✅ Implemented | `src/tarpit/manager.rs` |
| CookieManager | ❌ Missing | - |
| JsChallengeManager | ❌ Missing | - |
| ProgressionManager | ❌ Missing | - |
| Challenge Serving | ❌ Missing | Only enum `WafAction::Challenge` exists |

```
PDF Specification (Progressive Challenge Escalation):
1. Cookie Challenge - Silent tracking cookie
2. JS PoW Challenge - Proof-of-work computation
3. CAPTCHA Challenge - Human verification
4. Tarpit - Progressive delays (IMPLEMENTED)
5. Block - Hard block with custom page
```

**Impact**: Cannot challenge suspicious actors; only options are allow/log/block/tarpit.

---

## 🟠 P1 - High Priority Gaps (Significant Feature Missing)

### 4. ImpossibleTravel Detection - Not Implemented

**PDF Reference**: Page 24, Detection Modules
**Current Status**: Only mock data in `admin_server.rs:1229`

```
PDF Specification:
- Geo-velocity calculation: distance / time_delta
- Threshold: >500 mph triggers alert
- Requires: Session → Actor → IP geolocation chain
- Depends on: SessionManager, ActorManager
```

**Impact**: Cannot detect credential stuffing from geographically distributed botnets.

---

### 5. CredentialStuffingDetector - Partial Implementation

**PDF Reference**: Page 22, Detection Modules
**Current Status**: AuthTokenDetector tags campaigns with `credential_stuffing` type

**Implemented** (`correlation/detectors/auth_token.rs:145`):
```rust
attack_types: Some(vec!["credential_stuffing".to_string()]),
```

**Missing from PDF**:
- Login attempt velocity tracking (>5 failed logins/minute)
- Username enumeration detection
- Password spray pattern recognition
- Integration with ActorManager for cross-IP correlation

---

### 6. SchemaLearner - Not Implemented

**PDF Reference**: Page 34, API Profiling
**Current Status**: Stub endpoints only (`admin_server.rs:221-222`)

```
PDF Specification:
- Automatic JSON/XML schema inference
- Field type learning (string, number, boolean, array, object)
- Required vs optional field detection
- Validation enforcement after learning period
```

**API Stubs Present**:
- `/_sensor/profiling/schemas` - Returns placeholder data
- `/_sensor/profiling/schema/discovery` - Returns placeholder data

---

### 7. ProfilerManager / PayloadProfiler - Not Implemented

**PDF Reference**: Page 31-33, API Profiling
**Current Status**: Mentioned in comments (`persistence/mod.rs:4`)

```
PDF Specification:
- Path template extraction (/users/:id/orders/:orderId)
- Baseline request/response size learning
- Content-type validation
- 95th percentile anomaly thresholds
```

**ProfileStore** exists in comments but no actual struct implementation found.

---

## 🟡 P2 - Medium Priority Gaps (Feature Incomplete)

### 8. SignalManager - Not Implemented

**PDF Reference**: Page 27-28, Intelligence Systems
**Current Status**: No implementation

```
PDF Specification:
- 4 signal categories: Attack, Anomaly, Behavior, Intelligence
- 24-hour time-series storage per signal
- Signal aggregation and correlation
- External threat feed integration
```

---

### 9. TrendsManager - Not Implemented

**PDF Reference**: Page 29, Intelligence Systems
**Current Status**: Mock data only in `admin_server.rs`

```
PDF Specification:
- Hourly/daily/weekly trend aggregation
- Baseline deviation detection
- Seasonal pattern learning
- Capacity planning metrics
```

---

### 10. Full Admin API Coverage

**PDF Reference**: Pages 49-53, API Reference
**Documented**: 80+ endpoints
**Implemented**: ~50 endpoints

**Implemented Categories**:
- ✅ Site management (CRUD)
- ✅ WAF configuration
- ✅ Rate limiting
- ✅ Access lists
- ✅ Entity tracking
- ✅ Campaign queries
- ✅ Basic profiling stubs

**Missing Categories**:
- ❌ Actor management endpoints
- ❌ Session management endpoints
- ❌ Signal intelligence endpoints
- ❌ Trends analysis endpoints
- ❌ Challenge configuration endpoints

---

## 🟢 P3 - Low Priority Gaps (Nice to Have)

### 11. InjectionTracker - Not Implemented

**PDF Reference**: Page 25, Detection Modules
**Current Status**: Handled by libsynapse rules, no dedicated tracker

```
PDF Specification:
- SQL injection attempt counting per actor
- XSS payload fingerprinting
- Command injection pattern tracking
- Repeat offender escalation
```

**Note**: libsynapse provides detection; tracker would add state for escalation.

---

### 12. CookieManager (for Tracking, not Challenge)

**PDF Reference**: Page 38, Interrogator System
**Purpose**: Silent tracking cookie for actor correlation

**Note**: Lower priority if ActorManager uses IP + JA4 for correlation instead.

---

## ✅ Fully Implemented Features

### Core Proxy (100%)
| Feature | File | Status |
|---------|------|--------|
| VHost routing | `src/vhost.rs` | ✅ |
| TLS termination | `src/tls.rs` | ✅ |
| Health checks | `src/health.rs` | ✅ |
| Graceful shutdown | `src/shutdown.rs` | ✅ |
| Hot reload | `src/reload.rs` | ✅ |
| Header manipulation | `src/headers.rs` | ✅ |
| Body processing | `src/body.rs` | ✅ |
| Block pages | `src/block_page.rs` | ✅ |
| Block logging | `src/block_log.rs` | ✅ |

### WAF Detection (88%)
| Feature | File | Status |
|---------|------|--------|
| libsynapse integration | `src/api.rs` | ✅ |
| Per-site WAF config | `src/site_waf.rs` | ✅ |
| Rule action overrides | `src/site_waf.rs` | ✅ |
| Risk thresholds | `src/site_waf.rs` | ✅ |
| Validation | `src/validation.rs` | ✅ |
| Config management | `src/config_manager.rs` | ✅ |

### Entity Tracking (83%)
| Feature | File | Status |
|---------|------|--------|
| Per-IP state | `src/entity/store.rs` | ✅ |
| Risk accumulation | `src/entity/store.rs` | ✅ |
| Time-based decay | `src/entity/store.rs` | ✅ |
| JA4 reputation | `src/entity/store.rs` | ✅ |
| Block decisions | `src/entity/store.rs` | ✅ |

### Campaign Correlation (100%)
| Detector | File | Status |
|----------|------|--------|
| SharedFingerprint | `src/correlation/detectors/shared_fingerprint.rs` | ✅ |
| Ja4Rotation | `src/correlation/detectors/ja4_rotation.rs` | ✅ |
| AttackSequence | `src/correlation/detectors/attack_sequence.rs` | ✅ |
| AuthToken | `src/correlation/detectors/auth_token.rs` | ✅ |
| BehavioralSimilarity | `src/correlation/detectors/behavioral_similarity.rs` | ✅ |
| TimingCorrelation | `src/correlation/detectors/timing_correlation.rs` | ✅ |
| NetworkProximity | `src/correlation/detectors/network_proximity.rs` | ✅ |

### Operational Features
| Feature | File | Status |
|---------|------|--------|
| Prometheus metrics | `src/metrics.rs` | ✅ |
| Telemetry to Signal Horizon | `src/telemetry.rs` | ✅ |
| Snapshot persistence | `src/persistence/mod.rs` | ✅ |
| Rate limiting | `src/ratelimit.rs` | ✅ |
| CIDR access lists | `src/access.rs` | ✅ |
| Trap endpoints | `src/trap.rs` | ✅ |
| DLP scanning | `src/dlp/scanner.rs` | ✅ |
| JA4/JA4H fingerprinting | `src/fingerprint/ja4.rs` | ✅ |
| Tarpitting | `src/tarpit/manager.rs` | ✅ |

---

## Dependency Graph for Implementation

```
┌─────────────────────────────────────────────────────────────────┐
│                        P0 CRITICAL PATH                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ActorManager ──────────┬──────────► ImpossibleTravel           │
│       │                 │                   │                    │
│       │                 │                   ▼                    │
│       │                 └──────────► CredentialStuffing          │
│       │                                     │                    │
│       ▼                                     ▼                    │
│  SessionManager ──────────────────► SignalManager                │
│       │                                     │                    │
│       │                                     ▼                    │
│       └──────────────────────────► TrendsManager                 │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                     INTERROGATOR PATH                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  CookieManager ─────► JsChallengeManager ─────► ProgressionManager│
│       │                      │                        │          │
│       └──────────────────────┴────────────────────────┘          │
│                              │                                   │
│                              ▼                                   │
│                    TarpitManager (EXISTS)                        │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                      PROFILING PATH                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ProfilerManager ───► PayloadProfiler ───► SchemaLearner         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Recommended Implementation Order

### Phase 5A: State Management Foundation
1. **ActorManager** (~3-4 days)
   - LRU cache with 100k capacity
   - Per-actor state struct
   - Integration with EntityManager
   - Persistence hooks

2. **SessionManager** (~2-3 days)
   - LRU cache with 50k capacity
   - Token hash → session mapping
   - JA4 binding for hijack detection

### Phase 5B: Detection Enhancements
3. **ImpossibleTravel** (~2 days)
   - GeoIP lookup integration
   - Velocity calculation
   - Depends on: SessionManager

4. **CredentialStuffingDetector** (~2 days)
   - Login endpoint detection
   - Velocity thresholds
   - Depends on: ActorManager

### Phase 5C: Interrogator System
5. **CookieManager** (~1-2 days)
   - Signed tracking cookie
   - Actor correlation

6. **JsChallengeManager** (~2-3 days)
   - PoW generation/validation
   - Challenge page serving

7. **ProgressionManager** (~1-2 days)
   - Challenge escalation logic
   - Integration with all challenge types

### Phase 5D: Intelligence Systems
8. **SchemaLearner** (~3-4 days)
   - JSON/XML schema inference
   - Learning → enforcement transition

9. **SignalManager** (~2-3 days)
   - Time-series storage
   - Signal categorization

10. **TrendsManager** (~2 days)
    - Aggregation logic
    - Baseline calculation

---

## Files Modified for This Analysis

None - this is a read-only gap analysis.

## References

- Technical Reference PDF: `09-Synapse-Technical-Reference.pdf`
- Implementation: `apps/synapse-pingora/src/`
- Related TypeScript implementations: `apps/risk-server/src/`
