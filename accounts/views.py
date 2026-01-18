from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib import messages
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.core.mail import send_mail
from django.conf import settings
from django.db.models import Sum, Count, Q
from django.db.models.functions import TruncMonth
from django.urls import reverse
import secrets
import hashlib
import json
from datetime import timedelta, datetime

from .models import (
    KYCRequest,
    FarmerProfile,
    VendorProfile,
    ExpertProfile,
    FarmerProduct,
    VendorTool,
    FarmingTip,
    ExpertAppointment,
    ExpertChatThread,
    ExpertChatMessage,
    UserProfile,
    Order,
    CropSale,
)
from .serializers import SignupSerializer, LoginSerializer, UserSerializer
from .decorators import kyc_required, kyc_optional

# Password reset tokens storage (in production, use Redis or database)
password_reset_tokens = {}
otp_storage = {}  # Store OTPs: {email: {'otp': '123456', 'token': '...', 'created_at': ...}}

def _user_requires_kyc(user):
    return user.role in {'farmer', 'vendor', 'agricultural_expert'}

def _ensure_role_profile(user):
    if user.role == 'farmer':
        FarmerProfile.objects.get_or_create(user=user)
    elif user.role == 'vendor':
        VendorProfile.objects.get_or_create(user=user)
    elif user.role == 'agricultural_expert':
        ExpertProfile.objects.get_or_create(user=user)

def _redirect_to_role_home(user):
    """
    Redirect user to their role-specific dashboard.
    For roles requiring KYC, check status and redirect to KYC if needed.
    Returns the URL path as a string for API responses.
    """
    # Check KYC status for roles that require it
    if user.role in {'farmer', 'vendor', 'agricultural_expert'}:
        kyc_request = user.kyc_requests.first()
        kyc_status = kyc_request.status if kyc_request else None
        
        # If no KYC submitted, redirect to KYC page
        if kyc_status is None:
            return reverse('kyc')
    
    # Redirect to appropriate dashboard - return URL path
    if user.role == 'farmer':
        return reverse('farmer_dashboard')
    if user.role == 'vendor':
        return reverse('vendor_dashboard')
    if user.role == 'agricultural_expert':
        return reverse('expert_dashboard')
    if user.role == 'admin':
        return reverse('admin_dashboard')
    if user.role == 'buyer':
        return reverse('user_dashboard')
    return reverse('landing')


def _redirect_to_role_home_response(user):
    """
    Returns a redirect response object (for use in views that render templates).
    """
    url_path = _redirect_to_role_home(user)
    return redirect(url_path)


# ======================
# SIGNUP API
# ======================
class SignupView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            print(f"Signup attempt data: {request.data}")
            serializer = SignupSerializer(data=request.data)

            if serializer.is_valid():
                print("Signup validation successful")
                user = serializer.save()
                print(f"User created: {user.email} (ID: {user.id})")

                user.is_verified = user.role in {'buyer', 'admin'}
                user.save()
                print(f"User verified status: {user.is_verified}")
                
                # Get additional fields (frontend doesn't send them in JSON yet, need to fix frontend too)
                full_name = request.data.get('fullName')
                location = request.data.get('location')
                phone = request.data.get('phone')
                
                print(f"Profile data - Name: {full_name}, Phone: {phone}, Location: {location}")

                # Create profile with details
                if user.role == 'farmer':
                    FarmerProfile.objects.get_or_create(user=user, defaults={'name': full_name, 'location': location, 'contact': phone})
                    print("Farmer profile created/found")
                elif user.role == 'vendor':
                    VendorProfile.objects.get_or_create(user=user, defaults={'company_name': full_name, 'address': location, 'contact': phone})
                    print("Vendor profile created/found")
                elif user.role == 'agricultural_expert':
                    ExpertProfile.objects.get_or_create(user=user, defaults={'name': full_name})
                    print("Expert profile created/found")
                elif user.role == 'buyer':
                    UserProfile.objects.get_or_create(user=user, defaults={'name': full_name, 'address': location, 'phone': phone})
                    print("Buyer profile created/found")

                # Don't auto-login after signup - redirect to login page
                print("User created successfully, redirecting to login")

                return Response(
                    {
                        "message": "Account created successfully! Please login to continue.",
                        "user": UserSerializer(user).data,
                        "redirect_url": "/login/"
                    },
                    status=status.HTTP_201_CREATED
                )

            print(f"Signup validation errors: {serializer.errors}")
            return Response(
                {
                    "error": "Validation failed",
                    "details": serializer.errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response(
                {
                    "error": "An unexpected error occurred during registration.",
                    "details": {"exception": str(e)}
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



# ======================
# LOGIN API (FIXED)
# ======================
class LoginView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            print(f"Login attempt data: {request.data}")
            serializer = LoginSerializer(data=request.data)

            if not serializer.is_valid():
                print(f"Login validation errors: {serializer.errors}")
                return Response(
                    {
                        "error": "Validation failed",
                        "details": serializer.errors
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            email = serializer.validated_data['email']
            password = serializer.validated_data['password']

            print(f"Authenticating email: '{email}'")
            
            # 🔥 FIX: authenticate with username (since USERNAME_FIELD = 'email')
            # ModelBackend expects 'username' kwarg even if USERNAME_FIELD is 'email'
            user = authenticate(username=email, password=password)
            
            if user is None:
                # Try case-insensitive lookup
                User = get_user_model()
                try:
                    # Check if user exists with case-insensitive email
                    u = User.objects.get(email__iexact=email)
                    print(f"User found by case-insensitive search: {u.email}")
                    # Try authenticating with the stored email
                    user = authenticate(username=u.email, password=password)
                    if user:
                        print("Authentication successful after case correction")
                except User.DoesNotExist:
                    print("User not found even with case-insensitive search")
                except Exception as e:
                    print(f"Error during case-insensitive check: {e}")

            if user is None:
                print("Authentication failed")
                return Response(
                    {"error": "Invalid email or password"},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            if not user.is_active:
                # Activate inactive user on login attempt
                user.is_active = True
                user.save()

            # Continue with login if user is now active
            login(request, user)

            # Check KYC status for roles that require it
            if user.role in {'farmer', 'vendor', 'agricultural_expert'}:
                kyc_request = user.kyc_requests.first()
                kyc_status = kyc_request.status if kyc_request else None
                
                # If no KYC submitted, redirect to KYC page
                if kyc_status is None:
                    redirect_url = reverse('kyc')
                else:
                    # Get normal redirect URL (dashboard will show KYC alert if not approved)
                    redirect_url = _redirect_to_role_home(user)
            else:
                # Buyers and admins - no KYC required, normal redirect
                redirect_url = _redirect_to_role_home(user)

            return Response(
                {
                    "message": "Login successful",
                    "user": UserSerializer(user).data,
                    "redirect_url": redirect_url
                },
                status=status.HTTP_200_OK
            )
        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response(
                {
                    "error": "An unexpected error occurred during login.",
                    "details": {"exception": str(e)}
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# ======================
# FORGOT PASSWORD API
# ======================
class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            email = request.data.get('email', '').strip().lower()
            
            if not email:
                return Response(
                    {"error": "Email is required"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            User = get_user_model()
            try:
                user = User.objects.get(email__iexact=email)
            except User.DoesNotExist:
                # Don't reveal if email exists for security
                return Response(
                    {"message": "If an account with that email exists, a password reset link has been sent."},
                    status=status.HTTP_200_OK
                )
            
            # Generate 6-digit OTP
            otp = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
            
            # Generate secure token for password reset
            token = secrets.token_urlsafe(32)
            
            # Store OTP and token
            otp_storage[email.lower()] = {
                'otp': otp,
                'token': token,
                'user_id': user.id,
                'created_at': timezone.now()
            }
            
            # Store token for password reset
            password_reset_tokens[token] = {
                'user_id': user.id,
                'email': user.email,
                'created_at': timezone.now()
            }
            
            # Send OTP email (in production, use proper email backend)
            try:
                send_mail(
                    subject='Your Farmity Password Reset OTP',
                    message=f'''Hello {user.email},

You requested to reset your password for your Farmity account.

Your One-Time Password (OTP) is: {otp}

This OTP will expire in 10 minutes.

If you didn't request this, please ignore this email.

Best regards,
Farmity Team''',
                    from_email=settings.DEFAULT_FROM_EMAIL if hasattr(settings, 'DEFAULT_FROM_EMAIL') else 'noreply@farmity.com',
                    recipient_list=[user.email],
                    fail_silently=False,
                )
            except Exception as e:
                print(f"Email send error: {e}")
                # In development, log the OTP
                if settings.DEBUG:
                    print(f"DEBUG MODE - OTP for {email}: {otp}")
            
            return Response(
                {
                    "message": "If an account with that email exists, an OTP has been sent.",
                    "token": token  # Return token for OTP verification page
                },
                status=status.HTTP_200_OK
            )
        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response(
                {"error": "An error occurred. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# ======================
# VERIFY OTP API
# ======================
class VerifyOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            email = request.data.get('email', '').strip().lower()
            otp = request.data.get('otp', '').strip()
            token = request.data.get('token', '').strip()
            
            if not otp:
                return Response(
                    {"error": "OTP is required"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # If email is not provided, try to find it from token
            if not email and token:
                # Try to find email from password_reset_tokens
                if token in password_reset_tokens:
                    email = password_reset_tokens[token].get('email', '').lower()
            
            if not email:
                return Response(
                    {"error": "Email is required"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Check if OTP exists
            if email not in otp_storage:
                return Response(
                    {"error": "Invalid or expired OTP. Please request a new one."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            otp_data = otp_storage[email]
            
            # Check OTP expiry (10 minutes)
            if timezone.now() - otp_data['created_at'] > timedelta(minutes=10):
                del otp_storage[email]
                return Response(
                    {"error": "OTP has expired. Please request a new one."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Verify OTP
            if otp_data['otp'] != otp:
                return Response(
                    {"error": "Invalid OTP. Please try again."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # OTP verified - return reset token
            reset_token = otp_data.get('token', token)
            # Ensure token is stored in password_reset_tokens
            if reset_token not in password_reset_tokens and reset_token:
                # Store token if it doesn't exist
                password_reset_tokens[reset_token] = {
                    'user_id': otp_data['user_id'],
                    'email': email,
                    'created_at': timezone.now()
                }
            
            del otp_storage[email]
            
            return Response(
                {
                    "message": "OTP verified successfully",
                    "reset_token": reset_token
                },
                status=status.HTTP_200_OK
            )
        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response(
                {"error": "An error occurred. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# ======================
# RESET PASSWORD API
# ======================
class ResetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            token = request.data.get('token', '').strip()
            new_password = request.data.get('password', '').strip()
            
            if not token or not new_password:
                return Response(
                    {"error": "Token and password are required"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            if len(new_password) < 8:
                return Response(
                    {"error": "Password must be at least 8 characters long"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Check token
            if token not in password_reset_tokens:
                return Response(
                    {"error": "Invalid or expired token"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            token_data = password_reset_tokens[token]
            
            # Check token expiry (1 hour)
            if timezone.now() - token_data['created_at'] > timedelta(hours=1):
                del password_reset_tokens[token]
                return Response(
                    {"error": "Token has expired. Please request a new password reset."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Get user
            User = get_user_model()
            try:
                user = User.objects.get(id=token_data['user_id'])
            except User.DoesNotExist:
                del password_reset_tokens[token]
                return Response(
                    {"error": "User not found"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Reset password
            user.set_password(new_password)
            user.save()
            
            # Delete token
            del password_reset_tokens[token]
            
            return Response(
                {"message": "Password has been reset successfully. You can now login with your new password."},
                status=status.HTTP_200_OK
            )
        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response(
                {"error": "An error occurred. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# ======================
# FRONTEND PAGES
# ======================
def landing_page(request):
    return render(request, 'landing.html')


def role_selection(request):
    return render(request, 'role_selection.html')


def register_page(request):
    from django.conf import settings
    role = request.GET.get('role', '')
    # Clean up role - ensure no None/null values
    if role in ['None', 'null', 'undefined', None]:
        role = ''
    # Check if Google OAuth is configured
    google_oauth_enabled = 'google' in getattr(settings, 'SOCIALACCOUNT_PROVIDERS', {})
    
    context = {
        'role': role,
        'google_oauth_enabled': google_oauth_enabled
    }
    return render(request, 'register.html', context)


def login_page(request):
    from django.conf import settings
    # Check if Google OAuth is configured
    google_oauth_enabled = 'google' in getattr(settings, 'SOCIALACCOUNT_PROVIDERS', {})
    
    context = {
        'google_oauth_enabled': google_oauth_enabled
    }
    return render(request, 'login.html', context)


def forgot_password_page(request):
    # Check for messages from redirects
    context = {}
    return render(request, 'forgot_password.html', context)


def otp_verification_page(request):
    email = request.GET.get('email', '')
    token = request.GET.get('token', '')
    return render(request, 'otp_verification.html', {'email': email, 'token': token})


def reset_password_page(request):
    token = request.GET.get('token', '')
    if not token:
        messages.error(request, 'Invalid reset link.')
        return redirect('forgot_password')
    
    # Check if token exists and is valid (not expired)
    if token in password_reset_tokens:
        token_data = password_reset_tokens[token]
        # Check token expiry (1 hour)
        if timezone.now() - token_data['created_at'] > timedelta(hours=1):
            del password_reset_tokens[token]
            messages.error(request, 'Reset link has expired. Please request a new password reset.')
            return redirect('forgot_password')
    else:
        # Token doesn't exist, but still render the page
        # The frontend will handle the error when submitting
        messages.warning(request, 'Please verify your reset token is valid.')
    
    return render(request, 'reset_password.html', {'token': token})


def home_page(request):
    return render(request, 'home.html')


@login_required
def dashboard(request):
    return _redirect_to_role_home_response(request.user)


@login_required
def kyc_page(request):
    if not _user_requires_kyc(request.user):
        return _redirect_to_role_home_response(request.user)

    # Ensure profile exists for get_full_name() to work
    _ensure_role_profile(request.user)
    
    existing = request.user.kyc_requests.first()
    
    # Prevent duplicate submissions - only allow new submission if no existing request or if rejected
    if existing and existing.status not in [KYCRequest.STATUS_REJECTED]:
        # If there's a pending or approved KYC, don't allow new submission
        if existing.status == KYCRequest.STATUS_PENDING:
            messages.info(request, 'Your KYC verification is already pending. Please wait for approval.')
        elif existing.status == KYCRequest.STATUS_APPROVED:
            messages.success(request, 'Your KYC is already approved!')
        context = {
            'kyc': existing,
            'can_submit': False,
        }
        return render(request, 'kyc.html', context)
    
    if request.method == 'POST':
        full_name = (request.POST.get('full_name') or '').strip()
        id_number = (request.POST.get('id_number') or '').strip()
        id_document = request.FILES.get('id_document')
        selfie = request.FILES.get('selfie')
        company_document = request.FILES.get('company_document')
        certificate_document = request.FILES.get('certificate_document')

        errors = {}
        if not full_name:
            errors['full_name'] = 'Full name is required.'
        if not id_number:
            errors['id_number'] = 'ID number is required.'
        if not id_document:
            errors['id_document'] = 'ID document is required.'
        
        # Validate role-specific documents
        if request.user.role == 'vendor':
            if not company_document and not (existing and existing.company_document):
                errors['company_document'] = 'Company registration document is required for vendors.'
        elif request.user.role == 'agricultural_expert':
            if not certificate_document and not (existing and existing.certificate_document):
                errors['certificate_document'] = 'Professional certificate is required for agricultural experts.'

        if not errors:
            # Only create if no existing request or if previous was rejected
            if existing and existing.status == KYCRequest.STATUS_REJECTED:
                # Update existing rejected request
                existing.full_name = full_name
                existing.id_number = id_number
                if id_document:
                    existing.id_document = id_document
                if selfie:
                    existing.selfie = selfie
                if company_document:
                    existing.company_document = company_document
                if certificate_document:
                    existing.certificate_document = certificate_document
                existing.status = KYCRequest.STATUS_PENDING
                existing.rejection_reason = None
                existing.save()
                messages.success(request, 'KYC resubmitted successfully!')
            else:
                # Create new request only if none exists
                if not existing:
                    KYCRequest.objects.create(
                        user=request.user,
                        full_name=full_name,
                        id_number=id_number,
                        id_document=id_document,
                        selfie=selfie,
                        company_document=company_document,
                        certificate_document=certificate_document,
                        status=KYCRequest.STATUS_PENDING,
                    )
                    messages.success(request, 'KYC submitted successfully!')
                else:
                    messages.error(request, 'An error occurred. Please contact support.')
            
            request.user.is_verified = False
            request.user.save(update_fields=['is_verified'])
            existing = request.user.kyc_requests.first()
        else:
            # If there are validation errors, pass them to the template
            for field, error_msg in errors.items():
                messages.error(request, f"{field.replace('_', ' ').title()}: {error_msg}")

    context = {
        'kyc': existing,
        'can_submit': True,
    }
    return render(request, 'kyc.html', context)


@login_required
def profile_page(request):
    user = request.user
    context = {}
    
    if user.role == 'farmer':
        profile, _ = FarmerProfile.objects.get_or_create(user=user)
        if request.method == 'POST' and 'update_profile' in request.POST:
            profile.name = request.POST.get('name')
            profile.location = request.POST.get('location')
            profile.contact = request.POST.get('contact')
            profile.farm_size = request.POST.get('farm_size')
            profile.crop_types = request.POST.get('crop_types')
            if request.FILES.get('photo'):
                profile.photo = request.FILES.get('photo')
            profile.save()
            messages.success(request, 'Profile updated successfully!')
            return redirect('profile')
        context['profile'] = profile
        
    elif user.role == 'vendor':
        profile, _ = VendorProfile.objects.get_or_create(user=user)
        if request.method == 'POST' and 'update_profile' in request.POST:
            profile.company_name = request.POST.get('company_name', profile.company_name)
            profile.address = request.POST.get('address', profile.address)
            profile.contact = request.POST.get('contact', profile.contact)
            if request.FILES.get('photo'):
                profile.logo = request.FILES.get('photo')
            profile.save()
            messages.success(request, 'Profile updated successfully!')
            return redirect('profile')
        context['profile'] = profile
        
    elif user.role == 'agricultural_expert':
        profile, _ = ExpertProfile.objects.get_or_create(user=user)
        if request.method == 'POST' and 'update_profile' in request.POST:
            profile.name = request.POST.get('name', profile.name)
            profile.specialization = request.POST.get('specialization', profile.specialization)
            profile.experience = request.POST.get('experience', profile.experience)
            profile.qualification = request.POST.get('qualifications', profile.qualification)
            if request.FILES.get('photo'):
                profile.photo = request.FILES.get('photo')
            profile.save()
            messages.success(request, 'Profile updated successfully!')
            return redirect('profile')
        context['profile'] = profile
        
    elif user.role == 'buyer':
        profile, _ = UserProfile.objects.get_or_create(user=user)
        if request.method == 'POST' and 'update_profile' in request.POST:
            profile.name = request.POST.get('name', profile.name)
            profile.phone = request.POST.get('contact', profile.phone)
            profile.address = request.POST.get('location', profile.address)
            if request.FILES.get('photo'):
                profile.photo = request.FILES.get('photo')
            profile.save()
            messages.success(request, 'Profile updated successfully!')
            return redirect('profile')
        context['profile'] = profile
    else:
        context['profile'] = user

    return render(request, 'profile_details.html', context)


@login_required
def settings_page(request):
    return render(request, 'settings.html')


@login_required
def change_password(request):
    if request.method == 'POST':
        user = request.user
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        
        if not current_password or not new_password or not confirm_password:
            messages.error(request, 'All fields are required!')
            return redirect('settings')
        
        if not user.check_password(current_password):
            messages.error(request, 'Current password is incorrect!')
            return redirect('settings')
        
        if new_password != confirm_password:
            messages.error(request, 'New passwords do not match!')
            return redirect('settings')
        
        if len(new_password) < 8:
            messages.error(request, 'Password must be at least 8 characters long!')
            return redirect('settings')
        
        user.set_password(new_password)
        user.save()
        # Re-authenticate user after password change
        user = authenticate(username=user.email, password=new_password)
        if user:
            login(request, user)
        messages.success(request, 'Password updated successfully!')
        return redirect('settings')
    return redirect('settings')


@login_required
def farmer_dashboard(request):
    if request.user.role != 'farmer':
        return _redirect_to_role_home_response(request.user)
    
    # Ensure profile exists
    profile, created = FarmerProfile.objects.get_or_create(user=request.user)
    
    # Check KYC status - prevent duplicate submissions
    kyc_request = request.user.kyc_requests.first()
    kyc_status = kyc_request.status if kyc_request else None
    
    # Only allow access if KYC is approved
    if kyc_status != 'approved':
        # Still show dashboard but with KYC alert
        pass
    
    # Handle Profile Update
    if request.method == 'POST' and 'update_profile' in request.POST:
        profile.name = request.POST.get('name')
        profile.location = request.POST.get('location')
        profile.contact = request.POST.get('contact')
        profile.farm_size = request.POST.get('farm_size')
        profile.crop_types = request.POST.get('crop_types')
        profile.livestock_details = request.POST.get('livestock_details')
        if request.FILES.get('photo'):
            profile.photo = request.FILES.get('photo')
        profile.save()
        messages.success(request, 'Profile updated successfully!')
        return redirect('farmer_dashboard')

    # Handle Add Product - Require KYC approval
    if request.method == 'POST' and 'add_product' in request.POST:
        if kyc_status != 'approved':
            messages.error(request, 'KYC verification is required to add crops. Please complete your KYC verification first.')
            return redirect('farmer_dashboard')
        
        name = request.POST.get('product_name')
        quantity = request.POST.get('quantity')
        price = request.POST.get('price')
        if name and quantity and price:
            product = FarmerProduct.objects.create(
                farmer=profile,
                name=name,
                quantity=quantity,
                price_per_unit=price,
                unit=request.POST.get('unit', 'kg'),
                is_available=True
            )
            if request.FILES.get('product_image'):
                product.image = request.FILES.get('product_image')
                product.save()
            messages.success(request, 'Crop added successfully!')
        return redirect('farmer_dashboard')

    # Handle Edit Product - Require KYC approval
    if request.method == 'POST' and 'edit_product' in request.POST:
        if kyc_status != 'approved':
            messages.error(request, 'KYC verification is required to edit crops. Please complete your KYC verification first.')
            return redirect('farmer_dashboard')
        
        product_id = request.POST.get('product_id')
        try:
            product = FarmerProduct.objects.get(id=product_id, farmer=profile)
            product.name = request.POST.get('product_name')
            product.quantity = request.POST.get('quantity')
            product.price_per_unit = request.POST.get('price')
            product.unit = request.POST.get('unit', 'kg')
            product.is_available = request.POST.get('is_available') == 'on'
            if request.FILES.get('product_image'):
                product.image = request.FILES.get('product_image')
            product.save()
            messages.success(request, 'Crop updated successfully!')
        except FarmerProduct.DoesNotExist:
            messages.error(request, 'Product not found!')
        return redirect('farmer_dashboard')

    # Handle Delete Product - Require KYC approval
    if request.method == 'POST' and 'delete_product' in request.POST:
        if kyc_status != 'approved':
            messages.error(request, 'KYC verification is required to delete crops. Please complete your KYC verification first.')
            return redirect('farmer_dashboard')
        
        product_id = request.POST.get('product_id')
        try:
            product = FarmerProduct.objects.get(id=product_id, farmer=profile)
            product.delete()
            messages.success(request, 'Crop deleted successfully!')
        except FarmerProduct.DoesNotExist:
            messages.error(request, 'Product not found!')
        return redirect('farmer_dashboard')

    # Handle Tool Purchase - Require KYC approval for farmers
    if request.method == 'POST' and 'purchase_tool' in request.POST:
        if kyc_status != 'approved':
            messages.error(request, 'KYC verification is required to purchase tools. Please complete your KYC verification first.')
            return redirect('farmer_dashboard')
        
        from .models import Order, VendorTool
        tool_id = request.POST.get('tool_id')
        quantity = int(request.POST.get('quantity', 1))
        payment_method = request.POST.get('payment_method', Order.PAYMENT_COD)
        shipping_address = request.POST.get('shipping_address', '')
        notes = request.POST.get('notes', '')
        total_amount = request.POST.get('total_amount')
        
        try:
            tool = VendorTool.objects.get(id=tool_id, is_available=True)
            if tool.stock_quantity >= quantity:
                if not total_amount:
                    total_amount = tool.price * quantity
                else:
                    total_amount = float(total_amount)
                
                # Create order with payment method
                order = Order.objects.create(
                    buyer=request.user,
                    tool=tool,
                    quantity=quantity,
                    total_amount=total_amount,
                    status=Order.STATUS_CONFIRMED,
                    payment_method=payment_method,
                    payment_status='pending',
                    shipping_address=shipping_address,
                    notes=notes
                )
                
                # Update stock
                tool.stock_quantity -= quantity
                if tool.stock_quantity == 0:
                    tool.is_available = False
                tool.save()
                
                if payment_method == Order.PAYMENT_ESEWA:
                    messages.success(request, f'Order #{order.id} placed successfully! Payment method: eSewa.')
                else:
                    messages.success(request, f'Order #{order.id} placed successfully! You will pay Rs. {total_amount:.2f} on delivery.')
            else:
                messages.error(request, 'Insufficient stock!')
        except VendorTool.DoesNotExist:
            messages.error(request, 'Tool not found!')
        except Exception as e:
            messages.error(request, f'An error occurred: {str(e)}')
        return redirect('farmer_dashboard')

    # Get products
    products = FarmerProduct.objects.filter(farmer=profile).order_by('-created_at')
    
    # Calculate statistics
    from .models import CropSale, Order
    
    total_crops_added = products.count()
    total_crops_sold = CropSale.objects.filter(crop__farmer=profile).aggregate(
        total=Sum('quantity_sold')
    )['total'] or 0
    
    total_earnings = CropSale.objects.filter(crop__farmer=profile).aggregate(
        total=Sum('total_amount')
    )['total'] or 0
    
    active_listings = products.filter(is_available=True).count()
    
    # Get sales data for charts (last 6 months)
    six_months_ago = timezone.now() - timedelta(days=180)
    sales_data_raw = CropSale.objects.filter(
        crop__farmer=profile,
        sold_at__gte=six_months_ago
    ).annotate(
        month=TruncMonth('sold_at')
    ).values('month').annotate(
        total_sales=Sum('total_amount'),
        total_quantity=Sum('quantity_sold')
    ).order_by('month')
    
    # Convert to list for template
    sales_data = []
    for item in sales_data_raw:
        sales_data.append({
            'month': item['month'].strftime('%Y-%m') if item['month'] else 'N/A',
            'total_sales': float(item['total_sales'] or 0),
            'total_quantity': float(item['total_quantity'] or 0)
        })
    
    # If no sales data, create empty structure for charts
    if not sales_data:
        current_month = datetime.now().strftime('%Y-%m')
        sales_data = [
            {'month': current_month, 'total_sales': 0, 'total_quantity': 0},
        ]
    
    # Serialize for JavaScript
    sales_data_json = json.dumps(sales_data)
    
    # Get experts
    experts = ExpertProfile.objects.select_related('user').all()
    
    # Get farming tips
    tips = FarmingTip.objects.filter(is_published=True).select_related('expert', 'expert__user').order_by('-created_at')[:10]
    
    # Get appointments
    appointments = ExpertAppointment.objects.filter(requester=request.user).select_related('expert', 'expert__user').order_by('-created_at')
    
    # Get chat threads
    chat_threads = ExpertChatThread.objects.filter(created_by=request.user).select_related('expert', 'expert__user').order_by('-created_at')[:5]
    
    # Get available tools from vendors
    from .models import VendorTool
    available_tools = VendorTool.objects.filter(is_available=True, stock_quantity__gt=0).select_related('vendor', 'vendor__user').order_by('-created_at')[:12]
    
    # Get purchase history (orders)
    purchase_history = Order.objects.filter(buyer=request.user).select_related('tool', 'crop').order_by('-created_at')[:10]

    # Determine if features should be restricted
    features_restricted = (kyc_status != 'approved')
    
    context = {
        'profile': profile,
        'products': products,
        'experts': experts,
        'tips': tips,
        'appointments': appointments,
        'chat_threads': chat_threads,
        'kyc_request': kyc_request,
        'kyc_status': kyc_status,
        'features_restricted': features_restricted,
        'products_count': products.count(),
        # Statistics
        'total_crops_added': total_crops_added,
        'total_crops_sold': float(total_crops_sold),
        'total_earnings': float(total_earnings),
        'active_listings': active_listings,
        'sales_data': sales_data_json,
        # Tools and orders
        'available_tools': available_tools,
        'purchase_history': purchase_history,
    }
    return render(request, 'farmer_dashboard.html', context)


@login_required
def vendor_dashboard(request):
    if request.user.role != 'vendor':
        return _redirect_to_role_home_response(request.user)
    
    # Ensure profile exists
    profile, created = VendorProfile.objects.get_or_create(user=request.user)
    
    # Check KYC status
    kyc_request = request.user.kyc_requests.first()
    kyc_status = kyc_request.status if kyc_request else None
    
    # Handle Profile Update
    if request.method == 'POST' and 'update_profile' in request.POST:
        profile.company_name = request.POST.get('company_name', profile.company_name)
        profile.address = request.POST.get('address', profile.address)
        profile.contact = request.POST.get('contact', profile.contact)
        if request.FILES.get('photo'):
            profile.logo = request.FILES.get('photo')
        profile.save()
        messages.success(request, 'Profile updated successfully!')
        return redirect('vendor_dashboard')
    
    # Handle Add Tool - Require KYC approval
    if request.method == 'POST' and 'add_tool' in request.POST:
        if kyc_status != 'approved':
            messages.error(request, 'KYC verification is required to add tools. Please complete your KYC verification first.')
            return redirect('vendor_dashboard')
        
        name = request.POST.get('name')
        description = request.POST.get('description')
        price = request.POST.get('price')
        stock = request.POST.get('stock')
        is_available = request.POST.get('is_available') == 'on'
        
        if name and price and stock:
            tool = VendorTool.objects.create(
                vendor=profile,
                name=name,
                description=description,
                price=price,
                stock_quantity=int(stock),
                is_available=is_available
            )
            if request.FILES.get('image'):
                tool.image = request.FILES.get('image')
                tool.save()
            messages.success(request, 'Tool added successfully!')
        return redirect('vendor_dashboard')
    
    # Handle Edit Tool - Require KYC approval
    if request.method == 'POST' and 'edit_tool' in request.POST:
        if kyc_status != 'approved':
            messages.error(request, 'KYC verification is required to edit tools. Please complete your KYC verification first.')
            return redirect('vendor_dashboard')
        
        tool_id = request.POST.get('tool_id')
        try:
            tool = VendorTool.objects.get(id=tool_id, vendor=profile)
            tool.name = request.POST.get('name')
            tool.description = request.POST.get('description')
            tool.price = request.POST.get('price')
            tool.stock_quantity = int(request.POST.get('stock', 0))
            tool.is_available = request.POST.get('is_available') == 'on'
            if request.FILES.get('image'):
                tool.image = request.FILES.get('image')
            tool.save()
            messages.success(request, 'Tool updated successfully!')
        except VendorTool.DoesNotExist:
            messages.error(request, 'Tool not found!')
        return redirect('vendor_dashboard')
    
    # Handle Delete Tool - Require KYC approval
    if request.method == 'POST' and 'delete_tool' in request.POST:
        if kyc_status != 'approved':
            messages.error(request, 'KYC verification is required to delete tools. Please complete your KYC verification first.')
            return redirect('vendor_dashboard')
        
        tool_id = request.POST.get('tool_id')
        try:
            tool = VendorTool.objects.get(id=tool_id, vendor=profile)
            tool.delete()
            messages.success(request, 'Tool deleted successfully!')
        except VendorTool.DoesNotExist:
            messages.error(request, 'Tool not found!')
        return redirect('vendor_dashboard')
    
    # Handle Order Status Update
    if request.method == 'POST' and 'update_order_status' in request.POST:
        if kyc_status != 'approved':
            messages.error(request, 'KYC verification is required to manage orders. Please complete your KYC verification first.')
            return redirect('vendor_dashboard')
        
        order_id = request.POST.get('order_id')
        new_status = request.POST.get('status')
        tracking_number = request.POST.get('tracking_number', '').strip()
        
        try:
            order = Order.objects.get(id=order_id, tool__vendor=profile)
            order.status = new_status
            if tracking_number:
                order.tracking_number = tracking_number
            order.save()
            messages.success(request, f'Order #{order_id} status updated to {order.get_status_display()}')
        except Order.DoesNotExist:
            messages.error(request, 'Order not found!')
        return redirect('vendor_dashboard')
    
    # Get vendor tools
    tools = VendorTool.objects.filter(vendor=profile).order_by('-created_at')
    
    # Get orders for vendor's tools
    orders = Order.objects.filter(tool__vendor=profile).select_related('buyer', 'tool').order_by('-created_at')
    
    # Calculate statistics
    total_revenue = orders.aggregate(total=Sum('total_amount'))['total'] or 0
    total_orders = orders.count()
    pending_orders = orders.filter(status=Order.STATUS_PENDING).count()
    confirmed_orders = orders.filter(status=Order.STATUS_CONFIRMED).count()
    shipped_orders = orders.filter(status=Order.STATUS_SHIPPED).count()
    delivered_orders = orders.filter(status=Order.STATUS_DELIVERED).count()
    
    # Calculate revenue by month (last 6 months)
    six_months_ago = timezone.now() - timedelta(days=180)
    revenue_data_raw = orders.filter(
        created_at__gte=six_months_ago
    ).annotate(
        month=TruncMonth('created_at')
    ).values('month').annotate(
        total_revenue=Sum('total_amount'),
        order_count=Count('id')
    ).order_by('month')
    
    revenue_data = []
    for item in revenue_data_raw:
        revenue_data.append({
            'month': item['month'].strftime('%Y-%m') if item['month'] else 'N/A',
            'total_revenue': float(item['total_revenue'] or 0),
            'order_count': item['order_count']
        })
    
    if not revenue_data:
        current_month = datetime.now().strftime('%Y-%m')
        revenue_data = [{'month': current_month, 'total_revenue': 0, 'order_count': 0}]
    
    revenue_data_json = json.dumps(revenue_data)
    
    # Determine if features should be restricted
    features_restricted = (kyc_status != 'approved')
    
    context = {
        'profile': profile,
        'tools': tools,
        'orders': orders[:20],  # Show last 20 orders
        'kyc_request': kyc_request,
        'kyc_status': kyc_status,
        'features_restricted': features_restricted,
        'tools_count': tools.count(),
        'available_tools_count': tools.filter(is_available=True).count(),
        'sold_tools_count': tools.filter(is_available=False).count(),
        'total_revenue': float(total_revenue),
        'total_orders': total_orders,
        'pending_orders': pending_orders,
        'confirmed_orders': confirmed_orders,
        'shipped_orders': shipped_orders,
        'delivered_orders': delivered_orders,
        'revenue_data': revenue_data_json,
    }
    return render(request, 'vendor_dashboard.html', context)


@login_required
def expert_dashboard(request):
    if request.user.role != 'agricultural_expert':
        return _redirect_to_role_home_response(request.user)
    
    # Ensure profile exists
    profile, created = ExpertProfile.objects.get_or_create(user=request.user)
    
    # Check KYC status
    kyc_request = request.user.kyc_requests.first()
    kyc_status = kyc_request.status if kyc_request else None
    
    # Handle Profile Update
    if request.method == 'POST' and 'update_profile' in request.POST:
        profile.name = request.POST.get('name', profile.name)
        profile.qualification = request.POST.get('qualification', profile.qualification)
        profile.specialization = request.POST.get('specialization', profile.specialization)
        profile.experience = request.POST.get('experience', profile.experience)
        if request.FILES.get('photo'):
            profile.photo = request.FILES.get('photo')
        profile.save()
        messages.success(request, 'Profile updated successfully!')
        return redirect('expert_dashboard')
    
    # Handle Add Tip/Content - Require KYC approval
    if request.method == 'POST' and 'add_tip' in request.POST:
        if kyc_status != 'approved':
            messages.error(request, 'KYC verification is required to upload content. Please complete your KYC verification first.')
            return redirect('expert_dashboard')
        
        title = request.POST.get('title')
        content = request.POST.get('content')
        is_published = request.POST.get('is_published') == 'on'
        
        if title and content:
            tip = FarmingTip.objects.create(
                expert=profile,
                title=title,
                content=content,
                is_published=is_published
            )
            if request.FILES.get('image'):
                tip.image = request.FILES.get('image')
                tip.save()
            messages.success(request, 'Content uploaded successfully!')
        return redirect('expert_dashboard')
    
    # Handle Edit Tip - Require KYC approval
    if request.method == 'POST' and 'edit_tip' in request.POST:
        if kyc_status != 'approved':
            messages.error(request, 'KYC verification is required to edit content. Please complete your KYC verification first.')
            return redirect('expert_dashboard')
        
        tip_id = request.POST.get('tip_id')
        try:
            tip = FarmingTip.objects.get(id=tip_id, expert=profile)
            tip.title = request.POST.get('title')
            tip.content = request.POST.get('content')
            tip.is_published = request.POST.get('is_published') == 'on'
            if request.FILES.get('image'):
                tip.image = request.FILES.get('image')
            tip.save()
            messages.success(request, 'Content updated successfully!')
        except FarmingTip.DoesNotExist:
            messages.error(request, 'Content not found!')
        return redirect('expert_dashboard')
    
    # Handle Delete Tip - Require KYC approval
    if request.method == 'POST' and 'delete_tip' in request.POST:
        if kyc_status != 'approved':
            messages.error(request, 'KYC verification is required to delete content. Please complete your KYC verification first.')
            return redirect('expert_dashboard')
        
        tip_id = request.POST.get('tip_id')
        try:
            tip = FarmingTip.objects.get(id=tip_id, expert=profile)
            tip.delete()
            messages.success(request, 'Content deleted successfully!')
        except FarmingTip.DoesNotExist:
            messages.error(request, 'Content not found!')
        return redirect('expert_dashboard')
    
    # Handle Accept/Reject Appointment
    if request.method == 'POST' and ('accept_appointment' in request.POST or 'reject_appointment' in request.POST):
        if kyc_status != 'approved':
            messages.error(request, 'KYC verification is required to manage appointments. Please complete your KYC verification first.')
            return redirect('expert_dashboard')
        
        appointment_id = request.POST.get('appointment_id')
        try:
            appointment = ExpertAppointment.objects.get(id=appointment_id, expert=profile)
            if 'accept_appointment' in request.POST:
                appointment.status = ExpertAppointment.STATUS_ACCEPTED
                messages.success(request, 'Appointment accepted!')
            elif 'reject_appointment' in request.POST:
                appointment.status = ExpertAppointment.STATUS_REJECTED
                messages.info(request, 'Appointment rejected.')
            appointment.save()
        except ExpertAppointment.DoesNotExist:
            messages.error(request, 'Appointment not found!')
        return redirect('expert_dashboard')
    
    # Get expert content/tips
    tips = FarmingTip.objects.filter(expert=profile).order_by('-created_at')
    
    # Get appointments
    appointments = ExpertAppointment.objects.filter(expert=profile).select_related('requester').order_by('-created_at')
    
    # Get chat threads (for display - limited)
    chat_threads = ExpertChatThread.objects.filter(expert=profile).select_related('created_by').order_by('-created_at')[:10]
    
    # Get all chat threads for statistics (not limited)
    all_chat_threads = ExpertChatThread.objects.filter(expert=profile).select_related('created_by')
    
    # Calculate appointment statistics
    total_appointments = appointments.count()
    pending_appointments = appointments.filter(status=ExpertAppointment.STATUS_PENDING).count()
    accepted_appointments = appointments.filter(status=ExpertAppointment.STATUS_ACCEPTED).count()
    rejected_appointments = appointments.filter(status=ExpertAppointment.STATUS_REJECTED).count()
    
    # Get published vs draft content count
    published_content = tips.filter(is_published=True).count()
    draft_content = tips.filter(is_published=False).count()
    
    # Get recent messages count
    recent_messages = ExpertChatMessage.objects.filter(
        thread__expert=profile,
        created_at__gte=timezone.now() - timedelta(days=7)
    ).count()
    
    # Calculate farmers assisted (unique farmers who have appointments or chats)
    farmers_from_appointments = appointments.filter(requester__role='farmer').values_list('requester', flat=True).distinct()
    farmers_from_chats = all_chat_threads.filter(created_by__role='farmer').values_list('created_by', flat=True).distinct()
    total_farmers_assisted = len(set(list(farmers_from_appointments) + list(farmers_from_chats)))
    
    # Calculate users assisted (unique buyers who have appointments or chats)
    users_from_appointments = appointments.filter(requester__role='buyer').values_list('requester', flat=True).distinct()
    users_from_chats = all_chat_threads.filter(created_by__role='buyer').values_list('created_by', flat=True).distinct()
    total_users_assisted = len(set(list(users_from_appointments) + list(users_from_chats)))
    
    # Total people assisted
    total_people_assisted = total_farmers_assisted + total_users_assisted
    
    # Content views/engagement (can be enhanced later with actual view tracking)
    total_content_views = 0  # Placeholder for future implementation
    
    # Get chart data for appointments (last 6 months)
    six_months_ago = timezone.now() - timedelta(days=180)
    
    appointments_data_raw = appointments.filter(
        created_at__gte=six_months_ago
    ).annotate(
        month=TruncMonth('created_at')
    ).values('month').annotate(
        total_appointments=Count('id'),
        accepted_count=Count('id', filter=Q(status=ExpertAppointment.STATUS_ACCEPTED))
    ).order_by('month')
    
    # Convert to list for template
    appointments_data = []
    for item in appointments_data_raw:
        appointments_data.append({
            'month': item['month'].strftime('%Y-%m') if item['month'] else 'N/A',
            'total_appointments': item['total_appointments'] or 0,
            'accepted_count': item['accepted_count'] or 0
        })
    
    # If no data, create empty structure
    if not appointments_data:
        current_month = datetime.now().strftime('%Y-%m')
        appointments_data = [
            {'month': current_month, 'total_appointments': 0, 'accepted_count': 0},
        ]
    
    # Get chart data for content (last 6 months)
    content_data_raw = tips.filter(
        created_at__gte=six_months_ago
    ).annotate(
        month=TruncMonth('created_at')
    ).values('month').annotate(
        total_content=Count('id'),
        published_count=Count('id', filter=Q(is_published=True))
    ).order_by('month')
    
    # Convert to list for template
    content_data = []
    for item in content_data_raw:
        content_data.append({
            'month': item['month'].strftime('%Y-%m') if item['month'] else 'N/A',
            'total_content': item['total_content'] or 0,
            'published_count': item['published_count'] or 0
        })
    
    # If no data, create empty structure
    if not content_data:
        current_month = datetime.now().strftime('%Y-%m')
        content_data = [
            {'month': current_month, 'total_content': 0, 'published_count': 0},
        ]
    
    # Serialize for JavaScript
    appointments_data_json = json.dumps(appointments_data)
    content_data_json = json.dumps(content_data)
    
    # Determine if features should be restricted
    features_restricted = (kyc_status != 'approved')
    
    context = {
        'profile': profile,
        'tips': tips,
        'appointments': appointments[:20],  # Show last 20 appointments
        'chat_threads': chat_threads,
        'kyc_request': kyc_request,
        'kyc_status': kyc_status,
        'features_restricted': features_restricted,
        'content_count': tips.count(),
        'published_content': published_content,
        'draft_content': draft_content,
        'appointments_count': total_appointments,
        'pending_appointments': pending_appointments,
        'accepted_appointments': accepted_appointments,
        'rejected_appointments': rejected_appointments,
        'chats_count': chat_threads.count(),
        'recent_messages': recent_messages,
        'total_farmers_assisted': total_farmers_assisted,
        'total_users_assisted': total_users_assisted,
        'total_people_assisted': total_people_assisted,
        'total_content_views': total_content_views,
        'appointments_data': appointments_data_json,
        'content_data': content_data_json,
    }
    return render(request, 'expert_dashboard.html', context)


@login_required
def user_dashboard(request):
    if request.user.role != 'buyer':
        return _redirect_to_role_home_response(request.user)
    
    # Handle Crop Purchase
    if request.method == 'POST' and 'purchase_crop' in request.POST:
        crop_id = request.POST.get('crop_id')
        try:
            quantity = float(request.POST.get('quantity', 1))
        except (ValueError, TypeError):
            messages.error(request, 'Invalid quantity!')
            return redirect('user_dashboard')
        
        try:
            crop = FarmerProduct.objects.get(id=crop_id, is_available=True)
            if crop.quantity >= quantity:
                total_amount = crop.price_per_unit * quantity
                
                # Get payment method
                payment_method = request.POST.get('payment_method', Order.PAYMENT_COD)
                
                # Create order (quantity must be integer for Order model, but we store decimal in CropSale)
                order = Order.objects.create(
                    buyer=request.user,
                    crop=crop,
                    quantity=int(round(quantity)),  # Round and convert to int for Order model
                    total_amount=total_amount,
                    status=Order.STATUS_CONFIRMED,
                    payment_method=payment_method,
                    payment_status='pending',
                    shipping_address=request.POST.get('shipping_address', ''),
                    notes=request.POST.get('notes', '')
                )
                
                # Update crop quantity (keep as decimal)
                crop.quantity -= quantity
                if crop.quantity <= 0:
                    crop.is_available = False
                crop.save()
                
                # Create crop sale record (with actual decimal quantity)
                CropSale.objects.create(
                    crop=crop,
                    order=order,
                    quantity_sold=quantity,
                    price_per_unit=crop.price_per_unit,
                    total_amount=total_amount,
                    sold_to=request.user,
                    sold_at=timezone.now()
                )
                
                messages.success(request, f'Order placed successfully! Order #{order.id}')
            else:
                messages.error(request, f'Insufficient quantity. Available: {crop.quantity} {crop.unit}')
        except FarmerProduct.DoesNotExist:
            messages.error(request, 'Crop not found or no longer available!')
        except Exception as e:
            messages.error(request, f'An error occurred: {str(e)}')
        return redirect('user_dashboard')
    
    # Handle Tool Purchase
    if request.method == 'POST' and 'purchase_tool' in request.POST:
        tool_id = request.POST.get('tool_id')
        quantity = int(request.POST.get('quantity', 1))
        payment_method = request.POST.get('payment_method', Order.PAYMENT_COD)
        
        try:
            tool = VendorTool.objects.get(id=tool_id, is_available=True, stock_quantity__gt=0)
            if tool.stock_quantity >= quantity:
                total_amount = tool.price * quantity
                
                # Create order
                order = Order.objects.create(
                    buyer=request.user,
                    tool=tool,
                    quantity=quantity,
                    total_amount=total_amount,
                    status=Order.STATUS_CONFIRMED,
                    payment_method=payment_method,
                    payment_status='pending',
                    shipping_address=request.POST.get('shipping_address', ''),
                    notes=request.POST.get('notes', '')
                )
                
                # Update tool stock
                tool.stock_quantity -= quantity
                if tool.stock_quantity == 0:
                    tool.is_available = False
                tool.save()
                
                if payment_method == Order.PAYMENT_ESEWA:
                    messages.success(request, f'Order #{order.id} placed successfully! Payment method: eSewa.')
                else:
                    messages.success(request, f'Order #{order.id} placed successfully! You will pay Rs. {total_amount:.2f} on delivery.')
            else:
                messages.error(request, f'Insufficient stock. Available: {tool.stock_quantity} units')
        except VendorTool.DoesNotExist:
            messages.error(request, 'Tool not found or no longer available!')
        except Exception as e:
            messages.error(request, f'An error occurred: {str(e)}')
        return redirect('user_dashboard')
    
    # Buyers don't require KYC - full access immediately
    # Get all available tools from vendors
    tools = VendorTool.objects.filter(is_available=True, stock_quantity__gt=0).select_related('vendor', 'vendor__user').order_by('-created_at')
    
    # Get all available crops from farmers
    crops = FarmerProduct.objects.filter(is_available=True).select_related('farmer', 'farmer__user').order_by('-created_at')
    
    # Get all agricultural experts
    experts = ExpertProfile.objects.select_related('user').all()
    
    # Get farming tips/content from experts
    tips = FarmingTip.objects.filter(is_published=True).select_related('expert', 'expert__user').order_by('-created_at')[:10]
    
    # Get user's appointments
    appointments = ExpertAppointment.objects.filter(requester=request.user).select_related('expert', 'expert__user').order_by('-created_at')
    
    # Get user's chat threads with experts
    chat_threads = ExpertChatThread.objects.filter(created_by=request.user).select_related('expert', 'expert__user').order_by('-created_at')[:5]
    
    # Get or create user profile
    profile, _ = UserProfile.objects.get_or_create(user=request.user)
    
    # Handle Profile Update
    if request.method == 'POST' and 'update_profile' in request.POST:
        profile.name = request.POST.get('name', profile.name)
        profile.phone = request.POST.get('contact', profile.phone)
        profile.address = request.POST.get('location', profile.address)
        if request.FILES.get('photo'):
            profile.photo = request.FILES.get('photo')
        profile.save()
        messages.success(request, 'Profile updated successfully!')
        return redirect('user_dashboard')
    
    # Get purchase history with statistics
    purchase_history = Order.objects.filter(buyer=request.user).select_related('tool', 'crop', 'crop__farmer', 'tool__vendor').order_by('-created_at')
    
    # Calculate statistics
    total_orders = purchase_history.count()
    total_spent = purchase_history.aggregate(total=Sum('total_amount'))['total'] or 0
    pending_orders = purchase_history.filter(status=Order.STATUS_PENDING).count()
    completed_orders = purchase_history.filter(status=Order.STATUS_DELIVERED).count()
    
    context = {
        'tools': tools,
        'crops': crops,
        'experts': experts,
        'tips': tips,
        'appointments': appointments,
        'chat_threads': chat_threads,
        'profile': profile,
        'purchase_history': purchase_history[:20],  # Show last 20 orders
        'tools_count': tools.count(),
        'crops_count': crops.count(),
        'experts_count': experts.count(),
        'tips_count': tips.count(),
        'total_orders': total_orders,
        'total_spent': float(total_spent),
        'pending_orders': pending_orders,
        'completed_orders': completed_orders,
        'kyc_status': None,  # Buyers don't need KYC
    }
    return render(request, 'user_dashboard.html', context)


@login_required
def admin_dashboard(request):
    if request.user.role != 'admin':
        return _redirect_to_role_home_response(request.user)
    return render(request, 'admin_dashboard.html')


@login_required
def logout_view(request):
    logout(request)
    messages.success(request, 'You have been logged out successfully.')
    return redirect('landing')


@login_required
def appointment_request_page(request):
    if request.user.role not in {'buyer', 'farmer'}:
        return _redirect_to_role_home_response(request.user)

    # Check KYC for farmers (buyers don't need KYC)
    if request.user.role == 'farmer':
        kyc_request = request.user.kyc_requests.first()
        kyc_status = kyc_request.status if kyc_request else None
        if kyc_status != 'approved':
            messages.error(request, 'KYC verification is required to book appointments. Please complete your KYC verification first.')
            return redirect('farmer_dashboard')

    if request.method == 'POST':
        expert_id = (request.POST.get('expert_id') or '').strip()
        requested_date = (request.POST.get('requested_date') or '').strip()
        requested_time = (request.POST.get('requested_time') or '').strip()
        message = (request.POST.get('message') or '').strip() or None
        if expert_id and requested_date and requested_time:
            expert = ExpertProfile.objects.get(id=expert_id)
            ExpertAppointment.objects.create(
                expert=expert,
                requester=request.user,
                requested_date=requested_date,
                requested_time=requested_time,
                message=message,
                status=ExpertAppointment.STATUS_PENDING
            )
            messages.success(request, 'Appointment request sent successfully!')
            return redirect('appointment_request')
    
    experts = ExpertProfile.objects.select_related('user').all()
    context = {'experts': experts}
    return render(request, 'appointment_request.html', context)


@login_required
def chat_threads_page(request):
    if request.user.role not in {'buyer', 'farmer'}:
        return _redirect_to_role_home_response(request.user)
    
    threads = ExpertChatThread.objects.filter(created_by=request.user).select_related('expert', 'expert__user').order_by('-updated_at')
    context = {'threads': threads}
    return render(request, 'chat_threads.html', context)


@login_required
def chat_thread_detail(request, thread_id):
    if request.user.role not in {'buyer', 'farmer'}:
        return _redirect_to_role_home_response(request.user)
    
    # Check KYC for farmers (buyers don't need KYC)
    if request.user.role == 'farmer':
        kyc_request = request.user.kyc_requests.first()
        kyc_status = kyc_request.status if kyc_request else None
        if kyc_status != 'approved':
            messages.error(request, 'KYC verification is required to chat with experts. Please complete your KYC verification first.')
            return redirect('farmer_dashboard')
    
    try:
        thread = ExpertChatThread.objects.select_related('expert', 'expert__user', 'created_by').get(id=thread_id, created_by=request.user)
    except ExpertChatThread.DoesNotExist:
        messages.error(request, 'Chat thread not found.')
        return redirect('chat_threads')
    
    if request.method == 'POST':
        message_text = (request.POST.get('message') or '').strip()
        if message_text:
            ExpertChatMessage.objects.create(
                thread=thread,
                sender=request.user,
                message=message_text
            )
            thread.updated_at = timezone.now()
            thread.save()
            return redirect('chat_thread', thread_id=thread_id)
    
    messages_list = ExpertChatMessage.objects.filter(thread=thread).select_related('sender').order_by('created_at')
    context = {
        'thread': thread,
        'messages': messages_list,
    }
    return render(request, 'chat_thread_detail.html', context)
