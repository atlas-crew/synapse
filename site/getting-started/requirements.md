---
title: System Requirements
---

# System Requirements

::: tip Using Docker or npm?
If you're running Horizon and Synapse via [Docker](./installation#docker) or [npm](./installation#npm), most of the build dependencies below are not required. Docker needs only Docker Engine 20+. npm needs only Node.js 20+.
:::

## Horizon (API + UI)

| Dependency | Version | Notes |
| --- | --- | --- |
| **Node.js** | 20+ | LTS recommended |
| **pnpm** | 9+ | Workspace-aware package manager |
| **PostgreSQL** | 15+ | Primary data store |
| **ClickHouse** | 23.8+ | Optional — high-volume signal analytics |
| **Redis** | 7+ | Optional — caching and fleet pub/sub |

::: info ClickHouse and Redis are optional
Horizon works with PostgreSQL alone. ClickHouse enables time-series queries over large signal volumes. Redis adds shared caching for multi-instance Horizon deployments.
:::

## Synapse (Build from Source)

| Dependency | Version | Notes |
| --- | --- | --- |
| **Rust** | nightly | Pingora requires nightly features |
| **cmake** | 3.16+ | Build dependency for native crates |
| **OpenSSL** | 1.1+ or 3.x | TLS support |
| **clang** | 14+ | Required by bindgen |

**macOS:**

```sh
brew install cmake openssl
```

**Debian / Ubuntu:**

```sh
apt-get install -y build-essential cmake libssl-dev libclang-dev pkg-config
```

## Synapse (Pre-built Binary / Docker)

No runtime dependencies. The Docker image uses `debian:bookworm-slim`.

| Target | Base |
| --- | --- |
| Docker | `debian:bookworm-slim` |
| Linux | x86_64 or aarch64, glibc 2.36+ |
| macOS | 13+ (Ventura), Apple Silicon or Intel |

## Development Environment

| Tool | Version | Purpose |
| --- | --- | --- |
| **Node.js** | 20+ | Horizon API and UI |
| **pnpm** | 9+ | Package management |
| **Rust** | nightly | Synapse build |
| **Nx** | (workspace) | Task orchestration |
| **just** | 1.0+ | Task runner |

## Hardware Recommendations

### Synapse (per instance)

| Scale | CPU | RAM |
| --- | --- | --- |
| < 1K rps | 1 vCPU | 256 MB |
| 1K–10K rps | 2 vCPU | 512 MB |
| 10K+ rps | 4+ vCPU | 1 GB+ |

### Horizon

| Scale | CPU | RAM | PostgreSQL | ClickHouse |
| --- | --- | --- | --- | --- |
| < 10 sensors | 2 vCPU | 2 GB | Shared | Optional |
| 10–100 sensors | 4 vCPU | 4 GB | Dedicated | Recommended |
| 100+ sensors | 8+ vCPU | 8 GB+ | HA cluster | Dedicated cluster |

### Development

4+ cores, 16 GB RAM recommended (Rust compilation is heavily parallel).
