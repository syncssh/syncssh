#!/usr/bin/env bash
# Build + start the production stack (detached). Reads .env.prod.
set -e

cd "$(dirname "$0")/.."

if [ ! -f .env.prod ]; then
  echo "No .env.prod found — copying from .env.prod.example"
  cp .env.prod.example .env.prod
  echo
  echo "Edit .env.prod (domain, SECRET_KEY, DB password, SMTP) then re-run:"
  echo "  ./docker/prod-up.sh"
  exit 1
fi

docker compose --env-file .env.prod -f docker-compose.prod.yml up --build -d "$@"
echo
echo "Up. Logs: ./docker/prod-logs.sh   |   Stop: ./docker/prod-down.sh"
