# Goblins Investigation Report - January 2026

## Executive Summary

An investigation into potential performance bottlenecks ("goblins") has confirmed significant risks in **Response-side DLP scanning**. A secondary bottleneck in **Entity Store eviction** has been successfully **fixed**, resulting in a 50x+ performance improvement for that component.

## Status of Goblins

### 1. The Response Goblin (DLP)
*   **Status:** ❌ **CRITICAL**
*   **Performance:** ~755 µs for a 50KB payload.
*   **Scaling:** Linear (~15 µs per KB).
*   **Impact:** Scanning large responses significantly impacts latency.
*   **Recommendation:** Implement a hard cap on inspection depth (e.g., 8KB) and consider optimizing specific heavy regex patterns.

### 2. The Memory Goblin (Entity Store) - ✅ FIXED
*   **Status:** **RESOLVED**
*   **Improvement:** Swapped O(N) `Vec` based LRU for O(1) `LruCache`.
*   **Performance Impact:**
    *   **Existing Touch:** ~414 ns → **~28 ns** (**15x faster**)
    *   **New Eviction:** ~7,700 ns → **~133 ns** (**58x faster**)
*   **Scaling:** Now O(1) regardless of store size (tested up to 50k entities).

### 3. The Connection Goblin (JA4)
*   **Status:** ✅ **SAFE**
*   **Performance:** ~1.9 µs - 2.7 µs per connection.
*   **Impact:** Negligible. Verified safe for global use.

## Summary Table

| Component | Scenario | Latency (Avg) | Risk Level | Status |
| :--- | :--- | :--- | :--- | :--- |
| **DLP Scanner** | 50KB Scan | **755 µs** | 🔴 Critical | Needs Cap |
| **Entity Store** | 10k LRU Evict | **133 ns** | 🟢 Low | **Fixed** |
| **JA4** | Fingerprint | **2 µs** | 🟢 Low | Verified |

## Next Steps
1.  **DLP Optimization:** Deploy the 8KB inspection cap to production configuration.
2.  **Continuous Monitoring:** Maintain the `goblins` benchmark suite to prevent regression in store performance.
3.  **TLS Benchmarking:** Conduct a full TLS termination benchmark to quantify handshake overhead.