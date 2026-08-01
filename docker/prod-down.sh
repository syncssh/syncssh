#!/usr/bin/env bash
# Stop the production stack. Pass --volumes to also wipe DB + certs.
set -e

cd "$(dirname "$0")/.."

docker compose --env-file .env.prod -f docker-compose.prod.yml down "$@"
