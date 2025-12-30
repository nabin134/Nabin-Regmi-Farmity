from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from django.contrib.auth import authenticate
from django.shortcuts import render

from .serializers import SignupSerializer, LoginSerializer, UserSerializer


# ======================
# SIGNUP API
# ======================
class SignupView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = SignupSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.save()
            user.is_verified = True
            user.save()

            return Response(
                {
                    "message": "Account created successfully",
                    "user": UserSerializer(user).data
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


# ======================
# LOGIN API (FIXED)
# ======================
class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(
                {
                    "error": "Validation failed",
                    "details": serializer.errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']

        # 🔥 FIX: authenticate with email
        user = authenticate(request, email=email, password=password)

        if user is None:
            return Response(
                {"error": "Invalid email or password"},
                status=status.HTTP_401_UNAUTHORIZED
            )

        if not user.is_active:
            return Response(
                {"error": "User account is disabled"},
                status=status.HTTP_403_FORBIDDEN
            )

        return Response(
            {
                "message": "Login successful",
                "user": UserSerializer(user).data
            },
            status=status.HTTP_200_OK
        )


# ======================
# FRONTEND PAGES
# ======================
def landing_page(request):
    return render(request, 'landing.html')


def role_selection(request):
    return render(request, 'role_selection.html')


def register_page(request):
    role = request.GET.get('role', 'buyer')
    return render(request, 'register.html', {'role': role})


def login_page(request):
    return render(request, 'login.html')


def dashboard(request):
    return render(request, 'dashboard.html')
