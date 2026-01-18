from django.apps import AppConfig


class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'accounts'

    def ready(self):
        """Create Google SocialApp if credentials are provided"""
        import django
        from django.conf import settings
        from django.db import connection
        
        # Only run if database is ready and migrations are complete
        try:
            # Check if database is accessible
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            
            from django.contrib.sites.models import Site
            from allauth.socialaccount.models import SocialApp
            
            # Check if credentials are provided
            google_client_id = getattr(settings, 'GOOGLE_CLIENT_ID', '')
            google_client_secret = getattr(settings, 'GOOGLE_CLIENT_SECRET', '')
            
            if google_client_id and google_client_secret:
                # Get the current site
                site = Site.objects.get_current()
                
                # Create or update Google SocialApp
                social_app, created = SocialApp.objects.get_or_create(
                    provider='google',
                    defaults={
                        'name': 'Google',
                        'client_id': google_client_id,
                        'secret': google_client_secret,
                        'key': '',
                    }
                )
                
                # Update if exists but credentials changed
                if not created:
                    if social_app.client_id != google_client_id or social_app.secret != google_client_secret:
                        social_app.client_id = google_client_id
                        social_app.secret = google_client_secret
                        social_app.save()
                
                # Ensure the app is associated with the current site
                if site not in social_app.sites.all():
                    social_app.sites.add(site)
                    
        except Exception:
            # Ignore errors during migration/initialization
            # This will be handled once the database is ready
            pass
