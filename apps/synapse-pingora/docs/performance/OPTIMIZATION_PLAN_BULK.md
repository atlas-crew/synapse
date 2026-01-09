# Optimization Plan: Bulk Traffic Performance

## Problem Statement
Benchmarks have identified a critical performance bottleneck with "Bulk Import" style traffic (large JSON bodies >15KB). Latency scales linearly with payload size, reaching **~600µs** for an 18KB request, which is unacceptable for high-throughput enterprise environments.

**Root Cause:**
1.  **Full Body Copying:** The `build_raw_request` function allocates a new `String` and copies the entire body into it for every rule that inspects the full request.
2.  **Unbounded Regex Scanning:** The regex engine scans the entire payload buffer. For 200+ rules, this results in significant CPU consumption (O(N * M) where N=Body Size, M=Rule Count).

## Proposed Solution: Inspection Depth Limits

We propose implementing a configurable **Inspection Depth Limit** (default: 8KB). This ensures that latency remains bounded regardless of the actual request body size.

### 1. Architecture Changes

#### A. Add Configuration to `Engine`
Add a `max_inspection_size: usize` field to the `Engine` struct (default: 8192 bytes).

#### B. Modify `EvalContext`
Ensure `body_text` and `raw_body` in `EvalContext` are slices referencing only the first `max_inspection_size` bytes of the input.

#### C. Optimize `build_raw_request`
Modify `build_raw_request` to respect this limit, preventing massive allocations for 100KB+ bodies.

```rust
// Current (Allocating)
fn build_raw_request(ctx: &EvalContext) -> String {
    // ... constructs full string ...
}

// Proposed (Truncating)
fn build_raw_request(ctx: &EvalContext, limit: usize) -> String {
    // ...
    if let Some(body) = ctx.body_text {
        let len = body.len().min(limit);
        out.push_str(&body[..len]);
    }
    out
}
```

### 2. Expected Impact

| Metric | Current (18KB) | Projected (8KB Limit) | Improvement |
| :--- | :--- | :--- | :--- |
| **Latency** | 608 µs | ~250-300 µs | **~50%** |
| **Memory** | High (Copies) | Low (Bounded) | **Significant** |
| **Security** | Full Scan | First 8KB | Minimal Risk* |

*\*Risk Note: Most WAF evasions (SQLi, XSS) occur early in the payload or in specific fields. Deeply buried malicious payloads are rare in valid JSON and can often be caught by field-specific constraints instead of full-body regex.*

### 3. Implementation Plan

1.  **Refactor `EvalContext`:** Add logic to truncate body views during creation.
2.  **Update `Engine::analyze`:** Pass inspection limit configuration.
3.  **Benchmarking:** Re-run `bulk_import_extreme` benchmark to verify gains.

## Future Advanced Optimizations (Phase 2)
*   **Streaming Regex (Hyperscan/Vectorscan):** Use a streaming regex engine that doesn't require buffering the full payload.
*   **Structural Inspection:** For JSON payloads, parse the structure first and only run regexes on leaf string values, skipping keys and syntax overhead.
