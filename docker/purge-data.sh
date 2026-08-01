#!/usr/bin/env bash
set -e

cd "$(dirname "$0")/.."

echo "Flushing all data..."
docker compose exec backend python manage.py flush --no-input

# Re-create the Site object allauth requires (SITE_ID=1)
docker compose exec backend python manage.py shell -c \
  "from django.contrib.sites.models import Site; Site.objects.get_or_create(id=1, defaults={'domain':'localhost','name':'localhost'})"

echo "Done. Database is empty, ready for a fresh signup."
