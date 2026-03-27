import re
from rest_framework import serializers
from django.contrib.auth import password_validation
from .models import User


# Basic valid email pattern (consistent with Django's EmailValidator)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
PHONE_10_REGEX = re.compile(r'^\d{10}$')


class SignupSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True, help_text="Valid email address (one account per email)")
    password = serializers.CharField(write_only=True, min_length=8, trim_whitespace=False)
    confirmPassword = serializers.CharField(write_only=True, min_length=8, trim_whitespace=False, required=False, allow_blank=True)
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES, default='buyer', required=False)
    fullName = serializers.CharField(required=True, allow_blank=False, max_length=255)
    phone = serializers.CharField(required=True, allow_blank=False, max_length=32)
    location = serializers.CharField(required=True, allow_blank=False, max_length=255)

    class Meta:
        model = User
        fields = ('email', 'password', 'confirmPassword', 'role', 'fullName', 'phone', 'location')

    def validate_email(self, value):
        """Ensure email is valid and not already used by another account."""
        if not value or not value.strip():
            raise serializers.ValidationError("Email is required.")
        value = value.strip().lower()
        if not EMAIL_REGEX.match(value):
            raise serializers.ValidationError("Please enter a valid email address.")
        domain = value.split('@')[-1].lower() if '@' in value else ''
        if domain not in ('gmail.com', 'yahoo.com'):
            raise serializers.ValidationError("Only Gmail.com or Yahoo.com email addresses are allowed.")
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError(
                "This email is already registered. Please sign in or use a different email to create an account."
            )
        return value

    def validate_fullName(self, value):
        value = (value or '').strip()
        if not value:
            raise serializers.ValidationError("Full name is required.")
        if len(value) < 2:
            raise serializers.ValidationError("Full name is too short.")
        return value

    def validate_location(self, value):
        value = (value or '').strip()
        if not value:
            raise serializers.ValidationError("Address/Location is required.")
        if len(value) < 2:
            raise serializers.ValidationError("Address/Location is too short.")
        return value

    def validate_phone(self, value):
        raw = (value or '').strip()
        digits = re.sub(r'\D', '', raw)
        if not digits:
            raise serializers.ValidationError("Phone number is required.")
        if not PHONE_10_REGEX.match(digits):
            raise serializers.ValidationError("Phone number must be exactly 10 digits.")

        # Enforce uniqueness across users (new field) plus legacy profile fields.
        if User.objects.filter(phone=digits).exists():
            raise serializers.ValidationError("This phone number is already registered. Please use a different phone number.")

        # Legacy safety checks (older rows may store phone on profiles instead of User.phone)
        try:
            from .models import UserProfile, FarmerProfile, VendorProfile
            if UserProfile.objects.filter(phone=digits).exists() or FarmerProfile.objects.filter(contact=digits).exists() or VendorProfile.objects.filter(contact=digits).exists():
                raise serializers.ValidationError("This phone number is already registered. Please use a different phone number.")
        except Exception:
            # If imports fail for any reason, at least the User.phone uniqueness check is enforced.
            pass

        return digits

    def validate_role(self, value):
        """Validate that role is one of the allowed choices"""
        if not value:
            return 'buyer'  # Default role
        if value not in dict(User.ROLE_CHOICES):
            valid_roles = [choice[0] for choice in User.ROLE_CHOICES if choice[0] != 'admin']
            raise serializers.ValidationError(f"Invalid role. Must be one of: {', '.join(valid_roles)}")
        return value

    def validate_password(self, value):
        if not value:
            raise serializers.ValidationError("Password is required.")
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        # Basic character rules (stronger than just length)
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError("Password must contain at least 1 uppercase letter.")
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError("Password must contain at least 1 lowercase letter.")
        if not re.search(r'\d', value):
            raise serializers.ValidationError("Password must contain at least 1 number.")
        if not re.search(r'[^A-Za-z0-9]', value):
            raise serializers.ValidationError("Password must contain at least 1 special character.")
        return value

    def validate(self, attrs):
        pw = attrs.get('password')
        cpw = attrs.get('confirmPassword')
        # Frontend validates too, but backend must enforce.
        if cpw not in (None, '') and pw != cpw:
            raise serializers.ValidationError({'confirmPassword': ["Passwords do not match."]})

        # Run Django's configured validators too (common password, numeric-only, etc.)
        try:
            password_validation.validate_password(pw, user=None)
        except password_validation.ValidationError as e:
            raise serializers.ValidationError({'password': list(e.messages)})

        return attrs

    def create(self, validated_data):
        role = validated_data.get('role', 'buyer')
        # Ensure role is valid
        if role not in dict(User.ROLE_CHOICES):
            role = 'buyer'

        # Strip non-model fields
        full_name = validated_data.pop('fullName', '').strip()
        location = validated_data.pop('location', '').strip()
        phone = validated_data.get('phone')
        validated_data.pop('confirmPassword', None)

        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            role=role,
            phone=phone,
            is_active=False,
            email_verified=False,
        )

        # Create per-role profile data
        from .models import FarmerProfile, VendorProfile, ExpertProfile, UserProfile
        if user.role == 'farmer':
            FarmerProfile.objects.get_or_create(
                user=user,
                defaults={'name': full_name, 'location': location, 'contact': phone},
            )
        elif user.role == 'vendor':
            VendorProfile.objects.get_or_create(
                user=user,
                defaults={'company_name': full_name, 'address': location, 'contact': phone},
            )
        elif user.role == 'agricultural_expert':
            ExpertProfile.objects.get_or_create(user=user, defaults={'name': full_name})
        else:
            UserProfile.objects.get_or_create(
                user=user,
                defaults={'name': full_name, 'address': location, 'phone': phone},
            )

        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True, help_text="Email address (text field)")
    password = serializers.CharField(required=True, write_only=True, help_text="Password (text field)")


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'role', 'is_verified', 'date_joined')
        read_only_fields = ('id', 'is_verified', 'date_joined')


class OTPVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    otp = serializers.CharField(required=True, min_length=6, max_length=6, help_text="6-digit OTP code")
