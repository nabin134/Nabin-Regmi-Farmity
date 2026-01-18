"""
Management command to set up Google OAuth SocialApp in database.
Run this command to interactively set up Google OAuth.
"""
from django.core.management.base import BaseCommand
from django.conf import settings
from django.contrib.sites.models import Site
from allauth.socialaccount.models import SocialApp


class Command(BaseCommand):
    help = 'Creates or updates Google OAuth SocialApp in the database'

    def add_arguments(self, parser):
        parser.add_argument(
            '--client-id',
            type=str,
            help='Google OAuth Client ID',
        )
        parser.add_argument(
            '--client-secret',
            type=str,
            help='Google OAuth Client Secret',
        )

    def handle(self, *args, **options):
        google_client_id = options.get('client_id') or getattr(settings, 'GOOGLE_CLIENT_ID', '')
        google_client_secret = options.get('client_secret') or getattr(settings, 'GOOGLE_CLIENT_SECRET', '')
        
        # If credentials not provided, ask interactively
        if not google_client_id or not google_client_secret:
            self.stdout.write(self.style.WARNING('\n' + '='*70))
            self.stdout.write(self.style.WARNING('GOOGLE OAUTH SETUP'))
            self.stdout.write(self.style.WARNING('='*70))
            self.stdout.write('\nTo use Google sign-in/signup, you need Google OAuth credentials.')
            self.stdout.write('\nTo get credentials:')
            self.stdout.write('1. Go to: https://console.cloud.google.com/')
            self.stdout.write('2. Create/select a project')
            self.stdout.write('3. Enable Google+ API')
            self.stdout.write('4. Configure OAuth consent screen')
            self.stdout.write('5. Create OAuth Client ID (Web application)')
            self.stdout.write('6. Add redirect URI: http://127.0.0.1:8000/accounts/google/login/callback/')
            self.stdout.write('\n' + '-'*70)
            
            if not google_client_id:
                google_client_id = input('\nEnter Google Client ID (or press Enter to skip): ').strip()
            if not google_client_secret:
                google_client_secret = input('Enter Google Client Secret (or press Enter to skip): ').strip()
            
            if not google_client_id or not google_client_secret:
                self.stdout.write(
                    self.style.ERROR(
                        '\n✗ Google OAuth credentials not provided.\n'
                        'Google sign-in will not work until credentials are set.\n'
                        'You can run this command again later or set environment variables:\n'
                        '  GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET'
                    )
                )
                return
        
        try:
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
                    self.stdout.write(self.style.SUCCESS('Updated existing Google SocialApp'))
                else:
                    self.stdout.write(self.style.SUCCESS('Google SocialApp already exists and is up to date'))
            else:
                self.stdout.write(self.style.SUCCESS('Created Google SocialApp'))
            
            # Ensure the app is associated with the current site
            if site not in social_app.sites.all():
                social_app.sites.add(site)
                self.stdout.write(self.style.SUCCESS(f'Associated Google SocialApp with site: {site.domain}'))
            else:
                self.stdout.write(self.style.SUCCESS(f'Google SocialApp already associated with site: {site.domain}'))
                
            self.stdout.write(self.style.SUCCESS('\n✓ Google OAuth setup complete!'))
            self.stdout.write(self.style.SUCCESS('You can now use Google sign-in/signup.'))
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error setting up Google OAuth: {str(e)}')
            )
