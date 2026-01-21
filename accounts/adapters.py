from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.conf import settings
from django.contrib.auth import get_user_model

User = get_user_model()


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
        """Redirect to role-specific dashboard after login"""
        if request.user.is_authenticated:
            # Import here to avoid circular imports
            from .views import _redirect_to_role_home
            redirect_url = _redirect_to_role_home(request.user)
            return redirect_url
        return super().get_login_redirect_url(request)


class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    def pre_social_login(self, request, sociallogin):
        """
        Called before the social login is completed.
        This is where we can handle existing users connecting Google accounts.
        """
        # If user is already authenticated, connect the social account
        if request.user.is_authenticated:
            # Connect the social account to existing user
            sociallogin.connect(request, request.user)
        # For new users, let the default flow create the account

    def populate_user(self, request, sociallogin, data):
        """
        Populate user with Google account data (name, email).
        This is called before user is saved.
        """
        user = super().populate_user(request, sociallogin, data)
        
        # Set default role to buyer for social logins
        if not hasattr(user, 'role') or not user.role:
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
            # Set default role if not set (for new signups)
            if not hasattr(user, 'role') or not user.role:
                user.role = 'buyer'
            
            # Auto-verify and activate social logins (both signup and login)
            user.is_verified = True
            user.is_active = True
            user.save()
            
            # Create profile for buyer with Google account data
            from .models import UserProfile
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
            
            # Get or create user profile
            profile, created = UserProfile.objects.get_or_create(
                user=user,
                defaults={'name': name}
            )
            
            # Update name if it was empty and we now have it
            if not profile.name and name:
                profile.name = name
            
            # Download and save profile picture from Google if available
            if picture_url and (not profile.photo or created):
                try:
                    response = requests.get(picture_url, timeout=10)
                    if response.status_code == 200:
                        # Get file extension from URL or default to jpg
                        file_extension = picture_url.split('.')[-1].split('?')[0] if '.' in picture_url else 'jpg'
                        if file_extension not in ['jpg', 'jpeg', 'png', 'gif']:
                            file_extension = 'jpg'
                        
                        filename = f"google_profile_{user.id}.{file_extension}"
                        profile.photo.save(
                            filename,
                            ContentFile(response.content),
                            save=True
                        )
                except Exception as e:
                    # Log error but don't fail authentication
                    import logging
                    logger = logging.getLogger(__name__)
                    logger.warning(f"Error downloading Google profile picture: {str(e)}")
            
            profile.save()
            
        return user

    def get_login_redirect_url(self, request):
        """Redirect to role-specific dashboard after social login/signup"""
        if request.user.is_authenticated:
            # Import here to avoid circular imports
            from django.urls import reverse
            from .views import _redirect_to_role_home
            try:
                # Get the redirect URL path
                redirect_url = _redirect_to_role_home(request.user)
                # Ensure it's a string (reverse returns a string)
                if isinstance(redirect_url, str):
                    return redirect_url
                # If it's a reverse object, convert to string
                return str(redirect_url)
            except Exception as e:
                # Log error for debugging
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Error getting redirect URL for social login: {str(e)}")
                # Fallback to default dashboard
                return '/dashboard/'
        return super().get_login_redirect_url(request)
