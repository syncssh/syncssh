"""Drain the webhook outbox.

Run from cron every minute (mirrors the agent's pull discipline), or as a
long-running sidecar with --loop for deployments without cron:

    * * * * * python manage.py drain_notifications
    python manage.py drain_notifications --loop 30
"""

import time

from django.core.management.base import BaseCommand
from django.utils import timezone

from core.models import OutboundNotification
from syncssh import notifications


class Command(BaseCommand):
    help = "Deliver pending webhook notifications (retries with backoff)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--loop",
            type=int,
            metavar="SECONDS",
            help="Run forever, draining every SECONDS instead of exiting.",
        )
        parser.add_argument(
            "--batch-size",
            type=int,
            default=50,
            help="Max deliveries per pass (default 50).",
        )

    def handle(self, *args, **options):
        while True:
            sent, failed = self._drain(options["batch_size"])
            if sent or failed:
                self.stdout.write(f"delivered={sent} errored={failed}")
            if options["loop"] is None:
                break
            time.sleep(options["loop"])

    def _drain(self, batch_size):
        due = (
            OutboundNotification.objects.filter(
                status=OutboundNotification.STATUS_PENDING,
                next_attempt_at__lte=timezone.now(),
            )
            .select_related("webhook", "organization")
            .order_by("created_at")[:batch_size]
        )
        sent = errored = 0
        for notification in due:
            notifications.deliver(notification)
            if notification.status == OutboundNotification.STATUS_SENT:
                sent += 1
            else:
                errored += 1
        return sent, errored
