import re

from django.core.management.commands.runserver import Command as BaseCommand


class Command(BaseCommand):
    help = "Runs the development server with client IP shown in request log"

    def handle(self, *args, **options):
        from django.core.servers.basehttp import WSGIRequestHandler

        _orig_log = WSGIRequestHandler.log_message

        def log_message(self, format, *args):
            # format is like: "GET /api/v1/auth/me/ HTTP/1.1" 200 2
            # client_address is (ip, port)
            client_ip = self.client_address[0]
            # Call original with ip prepended
            _orig_log(self, f"[{client_ip}] {format}", *args)

        WSGIRequestHandler.log_message = log_message
        super().handle(*args, **options)