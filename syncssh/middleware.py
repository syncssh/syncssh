import os
import ipaddress

from django.http import HttpResponse
from django_ratelimit.exceptions import Ratelimited


class ClientIPMiddleware:
    """Restore the real client IP into REMOTE_ADDR when behind a trusted proxy.

    django-ratelimit keys on REMOTE_ADDR. With a reverse proxy (our Caddy) or
    Cloudflare in front, REMOTE_ADDR is the *proxy's* IP, so every visitor would
    share one rate-limit bucket. Controlled by the TRUSTED_PROXY env var:

      cloudflare → trust CF-Connecting-IP only when the immediate proxy and the
                   final X-Forwarded-For hop match configured trusted CIDRs.
      xff        → trust the *rightmost* X-Forwarded-For entry, which our single
                   reverse proxy appends and a client cannot forge.
      (unset)    → leave REMOTE_ADDR untouched (correct for direct/dev access).
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.mode = os.environ.get("TRUSTED_PROXY", "").strip().lower()
        self.trusted_proxy_networks = self._parse_networks(
            os.environ.get("TRUSTED_PROXY_CIDRS", "")
        )
        self.cloudflare_networks = self._parse_networks(
            os.environ.get("CLOUDFLARE_PROXY_CIDRS", "")
        )

    @staticmethod
    def _parse_networks(value):
        networks = []
        for entry in value.split(","):
            entry = entry.strip()
            if not entry:
                continue
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                continue
        return networks

    @staticmethod
    def _in_networks(value, networks):
        try:
            address = ipaddress.ip_address((value or "").strip())
        except ValueError:
            return False
        return any(address in network for network in networks)

    def __call__(self, request):
        peer_ip = request.META.get("REMOTE_ADDR")
        if not self._in_networks(peer_ip, self.trusted_proxy_networks):
            return self.get_response(request)

        if self.mode == "cloudflare":
            ip = request.META.get("HTTP_CF_CONNECTING_IP")
            xff = request.META.get("HTTP_X_FORWARDED_FOR", "")
            cloudflare_peer = xff.split(",")[-1].strip() if xff else ""
            if ip and self._in_networks(cloudflare_peer, self.cloudflare_networks):
                request.META["REMOTE_ADDR"] = ip.strip()
        elif self.mode == "xff":
            xff = request.META.get("HTTP_X_FORWARDED_FOR")
            if xff:
                request.META["REMOTE_ADDR"] = xff.split(",")[-1].strip()
        return self.get_response(request)


class RatelimitMiddleware:
    """Catch django-ratelimit's Ratelimited and return 429 instead of 403."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_exception(self, request, exception):
        if isinstance(exception, Ratelimited):
            return HttpResponse(
                "Rate limit exceeded. Try again later.",
                status=429,
                content_type="text/plain",
            )
        return None
