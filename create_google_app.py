"""
Quick script to create Google SocialApp in database.
Run: python manage.py shell
Then paste the code below, or run: python manage.py setup_google_oauth
"""
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Farmity.settings')

import django
django.setup()

from django.contrib.sites.models import Site
from allauth.socialaccount.models import SocialApp
from django.conf import settings

print("="*70)
print("GOOGLE OAUTH SETUP")
print("="*70)

# Get credentials from environment or settings
client_id = os.environ.get('GOOGLE_CLIENT_ID') or getattr(settings, 'GOOGLE_CLIENT_ID', '')
client_secret = os.environ.get('GOOGLE_CLIENT_SECRET') or getattr(settings, 'GOOGLE_CLIENT_SECRET', '')

if not client_id or not client_secret:
    print("\n⚠️  Google OAuth credentials not found in environment variables.")
    print("\nTo get Google OAuth credentials:")
    print("1. Go to: https://console.cloud.google.com/")
    print("2. Create/select a project")
    print("3. Enable Google+ API")
    print("4. Configure OAuth consent screen (External)")
    print("5. Create OAuth Client ID (Web application)")
    print("6. Add redirect URI: http://127.0.0.1:8000/accounts/google/login/callback/")
    print("\n" + "-"*70)
    client_id = input("\nEnter Google Client ID (or press Enter to create placeholder): ").strip()
    client_secret = input("Enter Google Client Secret (or press Enter to create placeholder): ").strip()
    
    if not client_id:
        client_id = 'PLACEHOLDER-CLIENT-ID.apps.googleusercontent.com'
        print("⚠️  Using placeholder Client ID. Google sign-in won't work until you add real credentials.")
    if not client_secret:
        client_secret = 'PLACEHOLDER-SECRET'
        print("⚠️  Using placeholder Secret. Google sign-in won't work until you add real credentials.")

try:
    site = Site.objects.get_current()
    print(f"\n✓ Site found: {site.domain} (ID: {site.id})")
    
    social_app, created = SocialApp.objects.get_or_create(
        provider='google',
        defaults={
            'name': 'Google',
            'client_id': client_id,
            'secret': client_secret,
            'key': '',
        }
    )
    
    if not created:
        # Update credentials
        social_app.client_id = client_id
        social_app.secret = client_secret
        social_app.save()
        print("✓ Updated existing Google SocialApp")
    else:
        print("✓ Created new Google SocialApp")
    
    # Ensure site association
    if site not in social_app.sites.all():
        social_app.sites.add(site)
        print(f"✓ Associated with site: {site.domain}")
    else:
        print(f"✓ Already associated with site: {site.domain}")
    
    print("\n" + "="*70)
    if 'PLACEHOLDER' in client_id or 'PLACEHOLDER' in client_secret:
        print("⚠️  PLACEHOLDER CREDENTIALS SET")
        print("="*70)
        print("\nGoogle sign-in will NOT work with placeholder credentials.")
        print("To enable Google sign-in:")
        print("1. Get real credentials from https://console.cloud.google.com/")
        print("2. Run this script again with real credentials, OR")
        print("3. Update via Django admin: http://127.0.0.1:8000/admin/socialaccount/socialapp/")
    else:
        print("✅ SUCCESS! Google OAuth is configured.")
        print("="*70)
        print("\n✓ Google sign-in/signup is now enabled!")
        print("Test it at: http://127.0.0.1:8000/login/ or /register/")
        
except Exception as e:
    print(f"\n✗ Error: {str(e)}")
    print("\nMake sure migrations are applied: python manage.py migrate")
