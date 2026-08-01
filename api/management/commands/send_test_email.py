"""Send a test email through the configured EMAIL_BACKEND.

Exercises the real delivery path (the same one allauth uses for signup
verification) so you can confirm a deployment can actually send mail:

    python manage.py send_test_email someone@example.com

Honors whatever EMAIL_BACKEND is set — SMTP or the Lettermint HTTP API backend.
"""

from django.conf import settings
from django.core.mail import send_mail
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = 'Send a test email through the configured EMAIL_BACKEND.'

    def add_arguments(self, parser):
        parser.add_argument('recipient', help='Destination email address.')
        parser.add_argument(
            '--subject',
            default='SyncSSH test email',
            help='Override the subject line.',
        )

    def handle(self, *args, **options):
        recipient = options['recipient']
        subject = options['subject']

        if not settings.EMAIL_DELIVERY_CONFIGURED:
            self.stderr.write(self.style.WARNING(
                'EMAIL_DELIVERY_CONFIGURED is False — the active backend '
                f'({settings.EMAIL_BACKEND}) does not deliver real mail. '
                'Sending anyway so you can see the result.'
            ))

        body = (
            'This is a test email from SyncSSH.\n\n'
            f'Backend: {settings.EMAIL_BACKEND}\n'
            f'From:    {settings.DEFAULT_FROM_EMAIL}\n\n'
            'If you received this, signup verification email works.'
        )

        self.stdout.write(
            f'Sending via {settings.EMAIL_BACKEND} '
            f'from {settings.DEFAULT_FROM_EMAIL} to {recipient}...'
        )
        try:
            sent = send_mail(
                subject,
                body,
                settings.DEFAULT_FROM_EMAIL,
                [recipient],
                fail_silently=False,
            )
        except Exception as exc:
            raise CommandError(f'Send failed: {exc}') from exc

        if sent:
            self.stdout.write(self.style.SUCCESS(f'Sent ({sent} message).'))
        else:
            raise CommandError('Backend reported 0 messages sent.')
