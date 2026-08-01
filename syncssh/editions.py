"""Open-core edition gating.

`settings.EDITION` ('oss' | 'cloud') selects a feature set; `settings.FEATURES`
holds the resolved flags. Everything commercial funnels through here so the
boundary stays in one place — never scatter `EDITION == 'cloud'` checks.

- `feature_enabled(name)`: the runtime check used by views and reported to the
  frontend so a single backend flag drives both.
- `FeatureGatedView`: mixin that 404s an entire view when its feature is off.
  404 (not 403) so a gated endpoint is indistinguishable from one that simply
  doesn't exist in this edition.
- `AUDIT_RETENTION_DAYS`: rolling window applied to the audit log when the
  'audit_unlimited_retention' feature is off.
"""

from django.conf import settings
from django.http import JsonResponse

AUDIT_RETENTION_DAYS = 30


def feature_enabled(name: str) -> bool:
    return bool(settings.FEATURES.get(name, False))


class FeatureGatedView:
    """Mixin for django.views.View. Set `required_feature` on the subclass;
    every HTTP method 404s when that feature is disabled."""

    required_feature: str | None = None

    def dispatch(self, request, *args, **kwargs):
        if self.required_feature and not feature_enabled(self.required_feature):
            return JsonResponse({"error": "Not found"}, status=404)
        return super().dispatch(request, *args, **kwargs)
