from django.apps import AppConfig


class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'accounts'

    def ready(self):
        """
        App ready method.
        Note: Google OAuth SocialApp should be configured manually via:
        - Django Admin: /admin/socialaccount/socialapp/
        - Management command: python setup_google_oauth_simple.py
        - Script: python update_google_credentials.py
        
        Database access during app initialization is discouraged by Django.
        """
        # Removed database access from ready() to avoid RuntimeWarning.
        # Google OAuth setup should be done via management commands or admin panel.
        pass
