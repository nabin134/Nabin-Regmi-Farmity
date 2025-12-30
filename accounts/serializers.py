from rest_framework import serializers
from .models import User


class SignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES, default='buyer', required=False)

    class Meta:
        model = User
        fields = ('email', 'password', 'role')

    def validate_role(self, value):
        """Validate that role is one of the allowed choices"""
        if not value:
            return 'buyer'  # Default role
        if value not in dict(User.ROLE_CHOICES):
            valid_roles = [choice[0] for choice in User.ROLE_CHOICES if choice[0] != 'admin']
            raise serializers.ValidationError(f"Invalid role. Must be one of: {', '.join(valid_roles)}")
        return value

    def create(self, validated_data):
        role = validated_data.get('role', 'buyer')
        # Ensure role is valid
        if role not in dict(User.ROLE_CHOICES):
            role = 'buyer'
        
        return User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            role=role
        )


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True, help_text="Email address (text field)")
    password = serializers.CharField(required=True, write_only=True, help_text="Password (text field)")


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'role', 'is_verified', 'date_joined')
        read_only_fields = ('id', 'is_verified', 'date_joined')
