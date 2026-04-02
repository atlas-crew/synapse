---
title: Local Environment
---

# Local Environment Setup

::: info For contributors
This guide is for developers who want to build and run the platform from source. If you just want to use Horizon or Synapse, see the [Installation guide](../getting-started/installation) for Docker and npm options.
:::

## Prerequisites

| Tool | Version | Install |
| --- | --- | --- |
| Node.js | 20+ | [nodejs.org](https://nodejs.org) |
| pnpm | 9+ | `npm install -g pnpm` |
| Rust | nightly | `rustup default nightly` |
| just | 1.0+ | `cargo install just` or `brew install just` |
| cmake | 3.16+ | `brew install cmake` (macOS) |
| OpenSSL | 1.1+ | `brew install openssl` (macOS) |
| PostgreSQL | 15+ | `brew install postgresql@15` or Docker |

## 1. Clone and Install

```sh
git clone https://github.com/atlas-crew/edge-protection.git
cd edge-protection
pnpm install
```

## 2. Database Setup

Start PostgreSQL (if not already running):

```sh
brew services start postgresql@15
```

Create the database and run migrations:

```sh
createdb signal_horizon
just db-migrate
```

Copy the environment template:

```sh
cp apps/signal-horizon/api/.env.example apps/signal-horizon/api/.env
```

The default `DATABASE_URL` points to `localhost:5432/signal_horizon`.

## 3. Optional Services

### Redis

```sh
brew services start redis
```

### ClickHouse

```sh
just ch-start    # Start via launchd
just ch-init     # Initialize schema
```

Verify all services:

```sh
just services
```

Expected output:

```
Local services:
  Redis      (:6379): UP
  PostgreSQL (:5432): UP
  ClickHouse (:8123): UP
```

## 4. Start Development Servers

```sh
just dev
```

This starts:

| Service | Port |
| --- | --- |
| Horizon API | `:3100` |
| Horizon UI | `:5180` |
| Synapse (proxy) | `:6190` |
| Synapse (admin) | `:6191` |

Or start components individually:

```sh
just dev-horizon    # API + UI only
just dev-synapse    # Synapse only
```

## 5. Verify

```sh
curl -s http://localhost:3100/health | jq .
curl -s http://localhost:6191/status | jq .
```

Open `http://localhost:5180` for the Horizon dashboard.

## Environment Variables

Horizon API reads from `apps/signal-horizon/api/.env`. See the full [Horizon configuration reference](../configuration/horizon) for all variables.

Synapse reads from `apps/synapse-pingora/config.yaml`. See the [Synapse configuration reference](../configuration/synapse).
