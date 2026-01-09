# Benchmark Report - January 2026

## Executive Summary

Recent benchmarks utilizing realistic industry-specific scenarios have confirmed a linear degradation in performance relative to payload size. The system exhibits excellent performance for light traffic but struggles significantly with heavy enterprise and healthcare workloads.

*   **Fast Path:** ~13-20 µs (Excellent)
*   **Medium Load (E-Comm/GraphQL):** ~125-136 µs (6x slower)
*   **Heavy Load (Healthcare):** ~209 µs (10x slower)
*   **Extreme Load (Bulk/Enterprise):** ~614 µs (30x slower)

## Vertical-Specific Performance

| Vertical | Scenario | Payload Size | Latency (Avg) | Assessment |
| :--- | :--- | :--- | :--- | :--- |
| **E-Commerce** | Order Creation (Nested JSON) | 3.8 KB | **136 µs** | Acceptable for most, but high variance. |
| **Financial/Tech** | GraphQL Mutation | 4.4 KB | **125 µs** | Comparable to E-Commerce. |
| **Healthcare** | Claims Submission (Compliance) | 6.9 KB | **209 µs** | **High Latency.** Approaching 0.25ms budget impact. |
| **Enterprise** | Bulk Import (Large Arrays) | 18.0 KB | **614 µs** | **Critical Bottleneck.** >0.5ms adds significant tail latency. |
| **Security** | SQLi Injection in Noise | 3.8 KB | **107 µs** | Faster than normal traffic? (Likely due to early block/exit). |

## Variance Drivers & Bottlenecks

### 1. Payload Size is the Primary Driver
The correlation between payload size and latency is nearly linear for the current engine implementation:
*   ~4 KB -> ~130 µs
*   ~7 KB -> ~210 µs
*   ~18 KB -> ~615 µs

This strongly suggests that **full body scanning (Regex/Pattern matching)** is the dominant cost factor. The engine appears to be scanning the entire request body byte-for-byte.

### 2. "Fast Path" vs "Heavy Path"
*   **Fast Path (<1KB):** The engine is highly efficient, handling headers and small bodies in <20µs.
*   **Heavy Path (>5KB):** Efficiency collapses. A single large request consumes the processing time of 30+ small requests.

## Recommendations

1.  **Optimization Priority:** Focus immediately on **Body Inspection Optimization**.
    *   *Streaming/Partial Scan:* Limit deep inspection to the first N bytes (e.g., 8KB) unless specific rules require more.
    *   *SIMD Acceleration:* Ensure regex engine utilizes SIMD (AVX2/NEON) for bulk scanning.
2.  **Architectural Limits:** Consider implementing a "fail-open" or "skip-inspection" threshold for extremely large bodies (e.g., >100KB) to prevent DoS via CPU exhaustion, or move them to an async analysis queue.
3.  **Vertical Weighting:** Benchmarks should heavily weight **Enterprise/SaaS (Bulk)** and **Healthcare** scenarios, as these represent the "worst-case" valid traffic that will drive tail latency.

## Methodology
Benchmarks conducted on **2026-01-08** using `synapse-pingora` v0.1.0.
*   **Harness:** Criterion.rs via `cargo bench`
*   **Data Source:** `apps/load-testing` generators (reproducible via `npm run bench:setup`)
*   **Scenarios:**
    *   `ecommerce_order_heavy`: Nested JSON, multiple items.
    *   `graphql_mutation_heavy`: Deeply nested structure.
    *   `healthcare_claim_heavy`: Medium size, arrays.
    *   `bulk_import_extreme`: Large array of objects.