#!/usr/bin/env bash
set -e

cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  echo "No .env found — copying from .env.example"
  cp .env.example .env
fi

docker compose up --build "$@"
