#!/usr/bin/env bash
# Tail logs from the production stack.
set -e

cd "$(dirname "$0")/.."

docker compose --env-file .env.prod -f docker-compose.prod.yml logs -f "$@"
