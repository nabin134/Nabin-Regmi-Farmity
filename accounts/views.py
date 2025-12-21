from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from django.contrib.auth import authenticate

from .serializers import SignupSerializer, LoginSerializer, UserSerializer


class SignupView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            
            # Auto-verify user (no email verification needed)
            user.is_verified = True
            user.save()
            
            return Response(
                {
                    "message": "Account created successfully"
                },
                status=status.HTTP_201_CREATED
            )
        return Response(
            {
                "error": "Validation failed",
                "details": serializer.errors
            },
            status=status.HTTP_400_BAD_REQUEST
        )


class LoginView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        # Validate input fields using serializer
        serializer = LoginSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                {
                    "error": "Validation failed",
                    "fields": {
                        "email": serializer.errors.get('email', []),
                        "password": serializer.errors.get('password', [])
                    },
                    "required_fields": {
                        "email": "Email address (text field)",
                        "password": "Password (text field)"
                    }
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        
        # Authenticate user
        user = authenticate(request, username=email, password=password)
        
        if user is None:
            return Response(
                {
                    "error": "Invalid email or password",
                    "fields": {
                        "email": email,
                        "password": "***"  # Don't show actual password
                    }
                },
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        if not user.is_active:
            return Response(
                {
                    "error": "User account is disabled"
                },
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Return success message with user details
        user_serializer = UserSerializer(user)
        return Response(
            {
                "message": "Login successful",
                "user": user_serializer.data
            },
            status=status.HTTP_200_OK
        )
