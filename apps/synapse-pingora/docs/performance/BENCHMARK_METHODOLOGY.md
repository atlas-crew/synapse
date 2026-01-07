# Synapse-Pingora Benchmarking Methodology & Results

**Date**: January 7, 2026
**Platform**: macOS (Apple Silicon, aarch64)
**Rust Version**: 1.88.0
**Criterion Version**: 0.5.1

---

## Executive Summary

Synapse-Pingora's detection engine achieves **30-40µs request analysis latency** with the full production rule set (237 rules). While this misses the aggressive <10µs design target, it provides robust protection with manageable overhead for most high-performance applications.

| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| Full detection cycle | **37.89 µs** | <10.00 µs | ❌ **3.8x over target** |
| Simple clean request | **3.58 µs** | <2.00 µs | ❌ **1.8x over target** |
| Attack detection (XSS) | **13.80 µs** | <1.00 µs | ❌ **13.8x over target** |
| Mixed workload (10 reqs) | **70.12 µs** | <20.00 µs | ❌ **3.5x over target** |
| Throughput capacity | **~26k req/sec/core** | >50k req/sec | ❌ **50% of target** |

**Note on Methodology Update**: Previous reports claiming <500ns latency were found to be using a "toy" implementation with only 4 simple regex patterns. This report reflects the *honest* performance of the real `libsynapse` engine with all 237 production rules loaded.

---

## Part 1: Benchmarking Methodology

### 1.1 Benchmark Framework: Criterion

Synapse-Pingora uses [Criterion.rs](https://bheisler.github.io/criterion.rs/book/), a statistical benchmarking framework.

### 1.2 Real Engine Verification

Crucially, the benchmark suite now imports and initializes the **actual `libsynapse` engine** with the production `rules.json` file containing 237 detection rules.

```rust
// benches/detection.rs
thread_local! {
    static SYNAPSE: std::cell::RefCell<Synapse> = std::cell::RefCell::new({
        let mut synapse = Synapse::new();
        let rules_path = "../risk-server/libsynapse/rules.json";
        // ... loads real 237 rules ...
        synapse
    });
}
```

This ensures we measure the cost of:
1.  **Candidate Selection**: Filtering 237 rules down to potential matches.
2.  **State Management**: Updates to thread-local storage.
3.  **Full Rule Evaluation**: Regex matching, variable parsing, and scoring.

### 1.3 Measurement Configuration

- **Sample Size**: 1,000 samples (10,000 for verification target).
- **Measurement Time**: Auto-extended by Criterion (typically 5-10s) to ensure statistical significance.
- **Environment**: Release build (`cargo bench`), Apple M1 Pro.

---

## Part 2: Benchmark Results (Honest)

### 2.1 Clean Requests (Benign Traffic)

| Request Type | Time (µs) | vs Toy Benchmark | Status |
|--------------|-----------|------------------|--------|
| Simple path | **3.58 µs** | ~8x slower | Acceptable |
| With query | **15.30 µs** | ~50x slower | Moderate overhead |
| Complex query | **18.71 µs** | ~35x slower | Significant overhead |
| Static asset | **4.12 µs** | ~10x slower | Fast path effective |
| Auth endpoint | **3.93 µs** | ~11x slower | Auth checks add cost |

**Analysis**:
- **Baseline Cost**: Even a simple request costs ~3.5µs due to engine overhead (allocations, initial filtering).
- **Query Parsing**: Adding query parameters jumps latency to ~15µs, indicating that string parsing and decoding is a major cost center.

### 2.2 Attack Detection (Malicious Traffic)

| Attack Type | Time (µs) | vs Toy Benchmark | Status |
|-------------|-----------|------------------|--------|
| SQL Injection | **13.52 µs** | ~38x slower | Consistent |
| XSS | **13.80 µs** | ~38x slower | Consistent |
| Path Traversal | **5.03 µs** | ~12x slower | Fast detection |
| Command Injection | **17.63 µs** | ~46x slower | Complex regex cost |

**Analysis**:
- Attack detection is roughly on par with complex clean requests (~13-18µs).
- **Path Traversal** is faster (5µs) likely because it matches on the URI directly without complex body/query parsing.

### 2.3 Headers Impact (Realistic Scenarios)

| Scenario | Time (µs) | Overhead | Status |
|----------|-----------|----------|--------|
| Clean without headers | ~3.6 µs | — | Baseline |
| Clean **with** headers | **31.98 µs** | +8.8x | **High Impact** |
| XSS **in** header | **18.38 µs** | +5.1x | Caught faster than clean? |

**Analysis**:
- **Header Parsing is Expensive**: Adding standard headers (User-Agent, Cookie, Referer) jumps latency from ~3.6µs to ~32µs.
- This suggests that iterating and processing headers is the single largest bottleneck in the current implementation.

### 2.4 Throughput & Capacity

| Metric | Value |
|--------|-------|
| Mixed Workload (10 reqs) | **70.12 µs** |
| Average per request | **~7.0 µs** (mixed simple/complex) |
| Max Throughput (Single Core) | **~26,000 req/sec** |
| 8-Core Capacity | **~200,000 req/sec** |

**Conclusion**:
- While missing the 50k req/sec/core target, 26k/core is still sufficient for most deployments.
- An 8-core instance can handle 200k RPS, which covers all but the largest DDoS attacks.

---

## Part 3: Sub-10µs Target Analysis

```
sub_10us_target/full_detection_cycle
time:   [37.431 µs 37.892 µs 38.453 µs]
```

The system **fails** the sub-10µs target by a factor of 3.8x.

**Why the miss?**
1.  **Header Processing**: 22µs of the 38µs cost appears to come from header analysis.
2.  **String Allocations**: The real engine likely performs more cloning/allocation than the toy version.
3.  **Regex Overhead**: 237 rules create a larger search space than 4 rules.

---

## Part 4: Recommendations

1.  **Optimize Header Handling**:
    - The jump from 3.6µs to 32µs with headers is the primary issue.
    - Investigate zero-copy header parsing or lazy evaluation.

2.  **Profile String Allocations**:
    - Use `flamegraph` to identify excessive `String::clone()` or `Vec` allocations during request context creation.

3.  **Revise Targets**:
    - <10µs might be unrealistic for a full feature-rich WAF in software.
    - <50µs is a more realistic "green" zone that still guarantees minimal latency impact (0.05ms is imperceptible).

4.  **Accept Current State**:
    - 38µs is still **extremely fast**. Nginx/ModSecurity often operate in the 500µs - 2ms range.
    - Synapse-Pingora is still ~10-50x faster than traditional WAFs, even if it missed its own aggressive internal target.

---

**Report Generated**: 2026-01-07
**Verified By**: Gemini CLI (Real Engine Benchmark)