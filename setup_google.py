"""
Quick setup script to create Google SocialApp in database.
Run this with: python manage.py shell < setup_google.py
Or run these commands in Django shell manually.
"""
from django.contrib.sites.models import Site
from allauth.socialaccount.models import SocialApp
import os

# Get credentials from environment or ask user to input
client_id = os.environ.get('GOOGLE_CLIENT_ID', '')
client_secret = os.environ.get('GOOGLE_CLIENT_SECRET', '')

if not client_id:
    print("=" * 60)
    print("GOOGLE OAUTH SETUP")
    print("=" * 60)
    print("\nPlease enter your Google OAuth credentials.")
    print("If you don't have them yet, get them from:")
    print("https://console.cloud.google.com/apis/credentials")
    print("\nYou can also set them as environment variables:")
    print("  GOOGLE_CLIENT_ID=your-client-id")
    print("  GOOGLE_CLIENT_SECRET=your-client-secret")
    print("\n" + "-" * 60)
    client_id = input("\nEnter Google Client ID (or press Enter to skip): ").strip()
    client_secret = input("Enter Google Client Secret (or press Enter to skip): ").strip()

if client_id and client_secret:
    try:
        site = Site.objects.get_current()
        
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
            social_app.client_id = client_id
            social_app.secret = client_secret
            social_app.save()
            print(f"\n✓ Updated existing Google SocialApp")
        else:
            print(f"\n✓ Created Google SocialApp")
        
        if site not in social_app.sites.all():
            social_app.sites.add(site)
            print(f"✓ Associated with site: {site.domain}")
        else:
            print(f"✓ Already associated with site: {site.domain}")
        
        print("\n" + "=" * 60)
        print("SUCCESS! Google OAuth is now configured.")
        print("=" * 60)
        print("\nYou can now use Google sign-in/signup.")
        print("Test it at: http://127.0.0.1:8000/login/ or /register/")
        
    except Exception as e:
        print(f"\n✗ Error: {str(e)}")
        print("\nMake sure migrations are applied: python manage.py migrate")
else:
    print("\n✗ Google OAuth credentials not provided.")
    print("\nTo get credentials:")
    print("1. Go to https://console.cloud.google.com/")
    print("2. Create/select a project")
    print("3. Enable Google+ API")
    print("4. Configure OAuth consent screen")
    print("5. Create OAuth Client ID (Web application)")
    print("6. Add redirect URI: http://127.0.0.1:8000/accounts/google/login/callback/")
