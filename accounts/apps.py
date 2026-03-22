from django.apps import AppConfig
import os


class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'accounts'

    def ready(self):
        """
        App ready method.
        Note: Google OAuth SocialApp should be configured manually via:
        - Django Admin: /admin/socialaccount/socialapp/
        - Management command: python manage.py setup_google_oauth
        
        Database access during app initialization is discouraged by Django.
        """
        # Optional fallback for platforms where shell access is unavailable:
        # auto-create/update a superuser from environment variables.
        # Enable with: AUTO_CREATE_SUPERUSER=1
        if os.environ.get('AUTO_CREATE_SUPERUSER', '0') != '1':
            return

        email = (os.environ.get('DJANGO_SUPERUSER_EMAIL') or '').strip()
        password = os.environ.get('DJANGO_SUPERUSER_PASSWORD') or ''
        if not email or not password:
            return

        try:
            from django.contrib.auth import get_user_model
            from django.db.utils import OperationalError, ProgrammingError
            User = get_user_model()

            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    'role': 'admin',
                    'is_staff': True,
                    'is_superuser': True,
                    'is_active': True,
                    'email_verified': True,
                }
            )
            changed = False
            if not user.is_superuser:
                user.is_superuser = True
                changed = True
            if not user.is_staff:
                user.is_staff = True
                changed = True
            if not user.is_active:
                user.is_active = True
                changed = True
            if getattr(user, 'role', None) != 'admin':
                user.role = 'admin'
                changed = True
            user.set_password(password)
            changed = True
            if changed:
                user.save()
        except (OperationalError, ProgrammingError):
            # DB not ready yet (e.g. before migrations); ignore safely.
            return
