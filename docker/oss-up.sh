#!/usr/bin/env bash
set -e

cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  echo "No .env found — copying from .env.example"
  cp .env.example .env
fi

# Same stack as up.sh, but pinned to the open-source edition so you can test
# what self-hosters see: no webhooks, no invite-email theming, audit log
# capped to 30 days. up.sh (edition defaults to 'cloud') is the full build.
echo "Starting SyncSSH — OSS edition (SYNCSSH_EDITION=oss)"
SYNCSSH_EDITION=oss docker compose up --build "$@"
