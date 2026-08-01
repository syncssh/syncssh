#!/usr/bin/env bash
# Production backend entrypoint: apply migrations + collect static, then serve.
set -e

python manage.py migrate --noinput
python manage.py collectstatic --noinput

# Workers default to 1 (correct rate limits without Redis). Raise GUNICORN_WORKERS
# only once REDIS_URL is set — see docker-compose.prod.yml.
exec gunicorn syncssh.wsgi:application \
    --workers "${GUNICORN_WORKERS:-1}" \
    --bind 0.0.0.0:8000 \
    --access-logfile - \
    --error-logfile -
