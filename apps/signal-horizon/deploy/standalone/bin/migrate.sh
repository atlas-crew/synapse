#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

cd "$ROOT_DIR"

exec ./node_modules/.bin/prisma migrate deploy --schema ./prisma/schema.prisma "$@"
