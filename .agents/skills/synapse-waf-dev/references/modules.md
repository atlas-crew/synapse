# Synapse WAF Module Map

A high-level map of the `synapse-waf` crate's top-level `src/` modules.

| Module | Description |
|--------|-------------|
| `waf/` | Core rule engine, `WafRule` definitions, and evaluation logic. |
| `dlp/` | Data Loss Prevention scanner and patterns. |
| `detection/` | Detection engine façade and behavioral heuristics. |
| `entity/` | Entity (IP) tracking, risk scores, and reputation state. |
| `actor/` | Campaign correlation and cross-entity clustering. |
| `session/` | Session-level tracking and anomaly detection. |
| `correlation/` | Signal clustering and campaign-building logic. |
| `interrogator/` | Active-probing and target verification. |
| `horizon/` | Client to the Signal Horizon fleet management hub. |
| `tunnel/` | Encrypted connectivity to the fleet hub. |
| `simulator.rs`| Procedural traffic simulator for demo and load testing. |
| `admin_server.rs`| Axum-based admin and observability API. |
| `config_manager.rs`| Atomic configuration hot-reload logic. |
