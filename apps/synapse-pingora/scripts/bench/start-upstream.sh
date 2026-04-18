#!/usr/bin/env bash
# Start the null-backend nginx that sits behind Synapse during bench runs.
# Runs in the foreground — ctrl-C to stop. Uses upstream.conf in the same
# directory as this script.
#
# Runs the nginx-from-PATH; we don't bundle a binary. Install with:
#   macOS:  brew install nginx
#   Debian: apt-get install nginx-light   (or nginx; we only use core)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF="${SCRIPT_DIR}/upstream.conf"

if ! command -v nginx >/dev/null 2>&1; then
  echo "nginx is not installed. On macOS: 'brew install nginx'. On Debian: 'apt-get install nginx-light'." >&2
  exit 1
fi

if [[ ! -f "$CONF" ]]; then
  echo "Config not found: $CONF" >&2
  exit 1
fi

# Validate the config first so we fail loudly instead of silently binding
# with a half-parsed file.
nginx -t -c "$CONF" -p "$SCRIPT_DIR"

echo "==> Starting null-backend nginx on 127.0.0.1:8080"
echo "    (ctrl-C to stop. Synapse's config.bench.yaml should point upstreams here.)"
exec nginx -c "$CONF" -p "$SCRIPT_DIR"
