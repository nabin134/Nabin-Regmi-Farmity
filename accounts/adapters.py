from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.conf import settings
from django.contrib.auth import get_user_model

User = get_user_model()

VALID_SIGNUP_ROLES = {'farmer', 'vendor', 'agricultural_expert', 'buyer'}


def get_user_display(user):
    """Custom function to display user - uses email instead of username"""
    if hasattr(user, 'email') and user.email:
        return user.email
    elif hasattr(user, 'get_full_name') and user.get_full_name():
        return user.get_full_name()
    elif hasattr(user, 'username') and user.username:
        return user.username
    return str(user)


class CustomAccountAdapter(DefaultAccountAdapter):
    def save_user(self, request, user, form, commit=True):
        user = super().save_user(request, user, form, commit)
        if commit:
            # Set default role to buyer for regular signups
            if not user.role:
                user.role = 'buyer'
                user.save()
            # Create profile for buyer
            from .models import UserProfile
            UserProfile.objects.get_or_create(user=user)
        return user

    def get_login_redirect_url(self, request):
        """Redirect to role-specific dashboard after login (including admin)."""
        if request.user.is_authenticated:
            from .views import _redirect_to_role_home
            user = request.user
            try:
                user.refresh_from_db()
            except Exception:
                pass
            redirect_url = _redirect_to_role_home(user)
            return str(redirect_url) if redirect_url else super().get_login_redirect_url(request)
        return super().get_login_redirect_url(request)


class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    def pre_social_login(self, request, sociallogin):
        """
        The selected Google email MUST determine which account opens.
        - Log out any authenticated user first.
        - If SocialAccount links this Google UID to a user whose email doesn't match
          the OAuth email (e.g. wrong link to admin), re-link to the user that owns
          the selected email.
        """
        from django.contrib.auth import logout

        if request.user.is_authenticated:
            logout(request)

        # Ensure the SocialAccount points to the user that owns the selected email.
        # Get OAuth email from extra_data or email_addresses (Google provides it).
        email = None
        if hasattr(sociallogin, 'account') and sociallogin.account:
            extra = getattr(sociallogin.account, 'extra_data', {}) or {}
            if isinstance(extra, dict):
                email = (
                    extra.get('email')
                    or extra.get('Email')
                    or extra.get('mail')
                )
                if email:
                    email = str(email).strip().lower()
        if not email and getattr(sociallogin, 'email_addresses', None):
            for ea in sociallogin.email_addresses:
                addr = getattr(ea, 'email', None)
                if addr:
                    email = str(addr).strip().lower()
                    break
        if email:
            correct_user = User.objects.filter(email__iexact=email).first()
            linked_user = sociallogin.user
            # Re-link when: (a) linked user differs from email owner, or
            # (b) linked user is admin but email belongs to a non-admin.
            needs_relink = (
                correct_user
                and linked_user
                and linked_user.pk
                and linked_user.pk != correct_user.pk
            )
            if needs_relink and hasattr(sociallogin, 'account') and sociallogin.account:
                if sociallogin.account.pk:
                    sociallogin.account.user = correct_user
                    sociallogin.account.save(update_fields=['user'])
                sociallogin.user = correct_user

    def populate_user(self, request, sociallogin, data):
        """
        Populate user with Google account data (name, email).
        Use signup_role from session when user came from role-specific register page.
        """
        user = super().populate_user(request, sociallogin, data)

        # Use role from session if present (user came from /register/?role=vendor etc.)
        signup_role = request.session.get('signup_role')
        if signup_role in VALID_SIGNUP_ROLES:
            user.role = signup_role
        elif not hasattr(user, 'role') or not user.role:
            user.role = 'buyer'

        # Extract email from Google account data
        if isinstance(data, dict):
            # Get email from Google data
            if not user.email and data.get('email'):
                user.email = data.get('email')
        
        # Also check extra_data from sociallogin account
        if not user.email and hasattr(sociallogin, 'account') and sociallogin.account:
            extra_data = getattr(sociallogin.account, 'extra_data', {})
            if isinstance(extra_data, dict) and extra_data.get('email'):
                user.email = extra_data.get('email')
        
        return user

    def save_user(self, request, sociallogin, form=None):
        """
        Save user after Google authentication.
        Retrieves name, email, and profile picture from Google account.
        This is called for both new signups and existing user logins.
        """
        user = super().save_user(request, sociallogin, form)
        if user:
            # Use signup_role only for NEW users (don't overwrite existing admin etc.)
            signup_role = request.session.get('signup_role')
            if signup_role in VALID_SIGNUP_ROLES and (not user.role or user.role == 'buyer'):
                user.role = signup_role
                request.session.pop('signup_role', None)
            elif not hasattr(user, 'role') or not user.role:
                user.role = 'buyer'

            # Auto-verify EMAIL and activate social logins (both signup and login)
            # Note: `is_verified` is used for KYC approval in this project, so we avoid setting it here.
            user.email_verified = True
            user.is_active = True
            user.save(update_fields=['role', 'email_verified', 'is_active'])
            
            from .models import UserProfile, FarmerProfile, VendorProfile, ExpertProfile
            import requests
            from django.core.files.base import ContentFile
            
            # Extract data from Google account
            name = ''
            picture_url = None
            
            try:
                # Get extra_data from social account
                if hasattr(sociallogin, 'account') and sociallogin.account:
                    extra_data = getattr(sociallogin.account, 'extra_data', {})
                    if isinstance(extra_data, dict):
                        # Get name (prefer full name, fallback to given_name)
                        name = extra_data.get('name') or extra_data.get('given_name', '')
                        # Get profile picture URL from Google
                        picture_url = extra_data.get('picture')
            except Exception as e:
                # Log error but continue
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"Error extracting Google account data: {str(e)}")
            
            # Fallback to email username if no name found
            if not name and user.email:
                name = user.email.split('@')[0]
            
            # Create role-specific profile
            if user.role == 'farmer':
                profile, _ = FarmerProfile.objects.get_or_create(user=user, defaults={'name': name})
                if not profile.name and name:
                    profile.name = name
            elif user.role == 'vendor':
                profile, _ = VendorProfile.objects.get_or_create(user=user, defaults={'company_name': name or user.email})
                if not profile.company_name and name:
                    profile.company_name = name
            elif user.role == 'agricultural_expert':
                profile, _ = ExpertProfile.objects.get_or_create(user=user, defaults={'name': name})
                if not profile.name and name:
                    profile.name = name
            else:
                profile, _ = UserProfile.objects.get_or_create(user=user, defaults={'name': name})
                if not profile.name and name:
                    profile.name = name

            if profile and picture_url:
                try:
                    resp = requests.get(picture_url, timeout=10)
                    if resp.status_code == 200:
                        ext = picture_url.split('.')[-1].split('?')[0] if '.' in picture_url else 'jpg'
                        if ext not in ['jpg', 'jpeg', 'png', 'gif']:
                            ext = 'jpg'
                        fname = f"google_profile_{user.id}.{ext}"
                        if user.role == 'vendor':
                            profile.logo.save(fname, ContentFile(resp.content), save=True)
                        elif hasattr(profile, 'photo'):
                            profile.photo.save(fname, ContentFile(resp.content), save=True)
                except Exception:
                    pass
            if profile:
                profile.save()
            
        return user

    def get_login_redirect_url(self, request):
        """Redirect after Google sign-in/signup to each role's own dashboard (including admin)."""
        if request.user.is_authenticated:
            from django.urls import reverse
            from .views import _redirect_to_role_home

            request.session.pop('signup_role', None)
            user = request.user
            try:
                user.refresh_from_db()
            except Exception:
                pass
            # Use same logic as _redirect_to_role_home so admin goes to admin panel
            redirect_url = _redirect_to_role_home(user)
            return str(redirect_url) if redirect_url else str(reverse('user_dashboard'))
        return super().get_login_redirect_url(request)
