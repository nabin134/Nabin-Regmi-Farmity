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
            redirect_response = _redirect_to_role_home(request.user)
            return redirect_response.url
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
        return user

    def save_user(self, request, sociallogin, form=None):
        user = super().save_user(request, sociallogin, form)
        if user and not user.role:
            user.role = 'buyer'
            user.is_verified = True  # Auto-verify social logins
            user.save()
            
            # Create profile for buyer
            from .models import UserProfile
            UserProfile.objects.get_or_create(
                user=user,
                defaults={
                    'name': user.email.split('@')[0] if user.email else '',
                }
            )
        return user

    def get_login_redirect_url(self, request):
        """Redirect to role-specific dashboard after social login"""
        if request.user.is_authenticated:
            # Import here to avoid circular imports
            from .views import _redirect_to_role_home
            redirect_response = _redirect_to_role_home(request.user)
            return redirect_response.url
        return super().get_login_redirect_url(request)
