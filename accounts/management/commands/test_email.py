"""
Test email configuration. Run from project root: python manage.py test_email your@email.com
Shows whether SMTP is configured and tries to send one test email.
"""
from django.core.management.base import BaseCommand
from django.core.mail import send_mail
from django.conf import settings
from pathlib import Path
import os


class Command(BaseCommand):
    help = "Test if OTP emails will be sent from farmityforyou@gmail.com to user inbox"

    def add_arguments(self, parser):
        parser.add_argument(
            'email',
            nargs='?',
            default='',
            help='Email address to send test OTP to (e.g. your@gmail.com)',
        )

    def handle(self, *args, **options):
        to_email = (options.get('email') or '').strip()
        if not to_email:
            to_email = getattr(settings, 'DEFAULT_FROM_EMAIL', '') or 'farmityforyou@gmail.com'

        # Check .env
        project_root = Path(settings.BASE_DIR) if hasattr(settings, 'BASE_DIR') else Path.cwd()
        env_path = project_root / '.env'
        self.stdout.write(f"Looking for .env at: {env_path}")
        self.stdout.write(f"  .env exists: {env_path.exists()}")

        # Config (do not print password)
        backend = getattr(settings, 'EMAIL_BACKEND', '')
        host = getattr(settings, 'EMAIL_HOST', '')
        user = getattr(settings, 'EMAIL_HOST_USER', '')
        pwd_set = bool(getattr(settings, 'EMAIL_HOST_PASSWORD', ''))
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', '')

        self.stdout.write("")
        self.stdout.write("Current email config:")
        self.stdout.write(f"  EMAIL_BACKEND: {backend}")
        self.stdout.write(f"  EMAIL_HOST: {host}")
        self.stdout.write(f"  EMAIL_HOST_USER: {user}")
        self.stdout.write(f"  DEFAULT_FROM_EMAIL: {from_email}")
        self.stdout.write(f"  EMAIL_HOST_PASSWORD set: {pwd_set}")
        self.stdout.write("")

        if 'console' in (backend or ''):
            self.stdout.write(self.style.WARNING(
                "SMTP is NOT active. Emails go to terminal only.\n"
                "Add a .env file in the SAME folder as manage.py with exactly:\n"
                "  EMAIL_HOST_PASSWORD=your16charapppassword\n"
                "(Gmail App Password for farmityforyou@gmail.com)"
            ))
            return

        self.stdout.write("Sending test email...")
        try:
            send_mail(
                subject='Farmity test – OTP would work',
                message=f'If you get this, OTP will be sent from {from_email} to your inbox.',
                from_email=from_email,
                recipient_list=[to_email],
                fail_silently=False,
            )
            self.stdout.write(self.style.SUCCESS(f"Test email sent to {to_email}. Check inbox (and spam)."))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Send failed: {e}"))
            import traceback
            traceback.print_exc()
