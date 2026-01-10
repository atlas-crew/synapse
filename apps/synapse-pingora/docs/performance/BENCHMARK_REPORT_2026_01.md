# Benchmark Report - January 2026

## Executive Summary

End-to-end proxy benchmarks have provided a definitive "all-in" latency profile for the Synapse-Pingora system. While the internal WAF logic is highly efficient (~20µs), the total overhead for a standard business request including Proxy, WAF, and DLP scanning is approximately **450µs** with optimizations enabled.

*   **Fast Path (GET):** ~300 µs end-to-end
*   **Standard Business Payload (4-8KB):** ~450 µs end-to-end (Optimized)
*   **Heavy Payload (>18KB):** ~450 µs (Capped at 8KB inspection)
*   **Worst-Case (Blocked/Tarpitted):** ~1000 ms (intentional)

## End-to-End Performance Findings

### 1. The "Real World" Overhead
The difference between micro-benchmarks (~20µs) and end-to-end results (~450µs) is driven by the proxy framework (Pingora) and secondary security features (DLP, logging).

| Test Phase | Latency (Mean) | Latency (p95) | Notes |
| :--- | :--- | :--- | :--- |
| **WAF Micro-bench** | 15 - 40 µs | 50 µs | Pure CPU logic |
| **Proxy Baseline** | 300 µs | 450 µs | Network + Proxy parsing |
| **Realistic (Unoptimized)** | **601 µs** | **1.04 ms** | **Full body scanning (O(N))** |
| **Realistic (Optimized)** | **~450 µs** | **~600 µs** | **8KB Cap + Async DLP** |

### 2. Feature Impact & Optimizations
*   **DLP Scanning:** Originally O(N). 18KB payloads took ~664µs to scan.
*   **Optimization:** **Inspection Depth Cap (8KB)**.
*   **Result:** 18KB payloads now take **~134µs** to scan (truncated to 8KB). This caps the worst-case CPU usage per request.
*   **Async Execution:** DLP scanning runs in parallel with upstream connection establishment, hiding ~50-100µs of latency.

### 3. Stability under Concurrency
The system handled 100 concurrent VUs at 100 iterations/sec arrival rate. No memory spikes or crashes were observed during the sustained 30s test.

## Final Latency Claims (Defensible)

| Scenario | Claim |
| :--- | :--- |
| **Total Proxy Overhead** | **< 0.5 ms** |
| **WAF Detection Logic** | **< 50 µs** |
| **DLP Processing** | **< 150 µs (Capped)** |

## Recommendations
1.  **Marketing Update:** Standardize on "Sub-millisecond total overhead" instead of "Sub-30µs WAF". The former is more holistic and defensible.
2.  **Upstream Optimization:** The mock server bottlenecked during testing. High-performance backends are required to truly test the 100k+ RPS throughput limits of Pingora.
3.  **Production Config:** Ensure `max_body_inspection_bytes` is set to `8192` (8KB) in production `config.yaml` to enforce the latency guarantee.