from rest_framework import serializers
from .models import User


class SignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = User
        fields = ('email', 'password', 'role')

    def create(self, validated_data):
        return User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            role=validated_data.get('role', 'user')
        )


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True, help_text="Email address (text field)")
    password = serializers.CharField(required=True, write_only=True, help_text="Password (text field)")


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'role', 'is_verified', 'date_joined')
        read_only_fields = ('id', 'is_verified', 'date_joined')
