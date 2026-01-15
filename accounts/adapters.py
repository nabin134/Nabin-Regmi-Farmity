from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.conf import settings
from django.contrib.auth import get_user_model

User = get_user_model()


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
        # This is called before the social login is completed
        # You can customize the user creation here
        pass

    def populate_user(self, request, sociallogin, data):
        user = super().populate_user(request, sociallogin, data)
        # Set default role to buyer for social logins
        if not user.role:
            user.role = 'buyer'
        # Extract email from social account data if not set
        if not user.email:
            # Try to get email from the social account data
            if hasattr(sociallogin, 'account') and sociallogin.account:
                extra_data = getattr(sociallogin.account, 'extra_data', {})
                if isinstance(extra_data, dict) and extra_data.get('email'):
                    user.email = extra_data.get('email')
            # Also try from the data parameter
            if not user.email and isinstance(data, dict) and data.get('email'):
                user.email = data.get('email')
        return user

    def save_user(self, request, sociallogin, form=None):
        user = super().save_user(request, sociallogin, form)
        if user:
            # Set default role if not set
            if not user.role:
                user.role = 'buyer'
            # Auto-verify social logins
            user.is_verified = True
            user.is_active = True
            user.save()
            
            # Create profile for buyer
            from .models import UserProfile
            # Extract name from Google account data
            name = ''
            try:
                # Try to get name from social account after it's saved
                if hasattr(sociallogin, 'account') and sociallogin.account:
                    extra_data = getattr(sociallogin.account, 'extra_data', {})
                    if isinstance(extra_data, dict):
                        name = extra_data.get('name') or extra_data.get('given_name', '')
            except Exception:
                pass
            
            # Fallback to email username if no name found
            if not name and user.email:
                name = user.email.split('@')[0]
            
            UserProfile.objects.get_or_create(
                user=user,
                defaults={
                    'name': name,
                }
            )
        return user

    def get_login_redirect_url(self, request):
        """Redirect to role-specific dashboard after social login"""
        if request.user.is_authenticated:
            # Import here to avoid circular imports
            from .views import _redirect_to_role_home
            redirect_url = _redirect_to_role_home(request.user)
            return redirect_url
        return super().get_login_redirect_url(request)
