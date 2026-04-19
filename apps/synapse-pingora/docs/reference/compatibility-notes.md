# Compatibility Notes

## 2026-04 Verdict Cleanup

`synapse_pingora::waf::Verdict` no longer exposes `anomaly_score`, `adjusted_threshold`, or `anomaly_signals`.

Those fields were dormant compatibility shims with no live producer path in the current Synapse WAF engine. Downstream consumers should rely on `risk_score`, `matched_rules`, `endpoint_template`, and `endpoint_risk`; profiler anomaly details continue to live in profiling outputs rather than the WAF verdict struct.
