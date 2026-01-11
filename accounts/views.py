from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from django.contrib.auth import authenticate, login, get_user_model
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib import messages
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.core.mail import send_mail
from django.conf import settings
import secrets
import hashlib
from datetime import timedelta

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
)
from .serializers import SignupSerializer, LoginSerializer, UserSerializer

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
    # Allow access to dashboards even without KYC - they'll see the KYC alert
    # KYC verification can be done from the dashboard
    if user.role == 'farmer':
        return redirect('farmer_dashboard')
    if user.role == 'vendor':
        return redirect('vendor_dashboard')
    if user.role == 'agricultural_expert':
        return redirect('expert_dashboard')
    if user.role == 'admin':
        return redirect('admin_dashboard')
    if user.role == 'buyer':
        return redirect('user_dashboard')
    return redirect('landing')


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

            # Get redirect URL
            redirect_response = _redirect_to_role_home(user)
            redirect_url = redirect_response.url

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
            
            if not email or not otp:
                return Response(
                    {"error": "Email and OTP are required"},
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
            reset_token = otp_data['token']
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
    role = request.GET.get('role', 'buyer')
    return render(request, 'register.html', {'role': role})


def login_page(request):
    return render(request, 'login.html')


def forgot_password_page(request):
    return render(request, 'forgot_password.html')


def otp_verification_page(request):
    email = request.GET.get('email', '')
    token = request.GET.get('token', '')
    return render(request, 'otp_verification.html', {'email': email, 'token': token})


def reset_password_page(request):
    token = request.GET.get('token', '')
    if not token:
        messages.error(request, 'Invalid reset link.')
        return redirect('forgot_password')
    
    # Check if token exists (basic validation)
    if token not in password_reset_tokens:
        messages.error(request, 'Invalid or expired reset link.')
        return redirect('forgot_password')
    
    return render(request, 'reset_password.html', {'token': token})


def home_page(request):
    return render(request, 'home.html')


@login_required
def dashboard(request):
    return _redirect_to_role_home(request.user)


@login_required
def kyc_page(request):
    if not _user_requires_kyc(request.user):
        return _redirect_to_role_home(request.user)

    existing = request.user.kyc_requests.first()
    if request.method == 'POST':
        full_name = (request.POST.get('full_name') or '').strip()
        id_number = (request.POST.get('id_number') or '').strip()
        id_document = request.FILES.get('id_document')
        selfie = request.FILES.get('selfie')

        errors = {}
        if not full_name:
            errors['full_name'] = 'Full name is required.'
        if not id_number:
            errors['id_number'] = 'ID number is required.'
        if not id_document:
            errors['id_document'] = 'ID document is required.'

        if not errors:
            KYCRequest.objects.create(
                user=request.user,
                full_name=full_name,
                id_number=id_number,
                id_document=id_document,
                selfie=selfie,
                status=KYCRequest.STATUS_PENDING,
            )
            request.user.is_verified = False
            request.user.save(update_fields=['is_verified'])
            existing = request.user.kyc_requests.first()

    context = {
        'kyc': existing,
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
        return _redirect_to_role_home(request.user)
    
    # Ensure profile exists
    profile, created = FarmerProfile.objects.get_or_create(user=request.user)
    
    # Check KYC status
    kyc_request = request.user.kyc_requests.first()
    kyc_status = kyc_request.status if kyc_request else None
    
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

    # Handle Add Product
    if request.method == 'POST' and 'add_product' in request.POST:
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

    # Handle Edit Product
    if request.method == 'POST' and 'edit_product' in request.POST:
        product_id = request.POST.get('product_id')
        try:
            product = FarmerProduct.objects.get(id=product_id, farmer=profile)
            product.name = request.POST.get('product_name')
            product.quantity = request.POST.get('quantity')
            product.price_per_unit = request.POST.get('price')
            product.unit = request.POST.get('unit', 'kg')
            if request.FILES.get('product_image'):
                product.image = request.FILES.get('product_image')
            product.save()
            messages.success(request, 'Crop updated successfully!')
        except FarmerProduct.DoesNotExist:
            messages.error(request, 'Product not found!')
        return redirect('farmer_dashboard')

    # Handle Delete Product
    if request.method == 'POST' and 'delete_product' in request.POST:
        product_id = request.POST.get('product_id')
        try:
            product = FarmerProduct.objects.get(id=product_id, farmer=profile)
            product.delete()
            messages.success(request, 'Crop deleted successfully!')
        except FarmerProduct.DoesNotExist:
            messages.error(request, 'Product not found!')
        return redirect('farmer_dashboard')

    # Get products
    products = FarmerProduct.objects.filter(farmer=profile).order_by('-created_at')
    
    # Get experts
    experts = ExpertProfile.objects.select_related('user').all()
    
    # Get farming tips
    tips = FarmingTip.objects.filter(is_published=True).select_related('expert', 'expert__user').order_by('-created_at')[:10]
    
    # Get appointments
    appointments = ExpertAppointment.objects.filter(requester=request.user).select_related('expert', 'expert__user').order_by('-created_at')
    
    # Get chat threads
    chat_threads = ExpertChatThread.objects.filter(created_by=request.user).select_related('expert', 'expert__user').order_by('-created_at')[:5]

    context = {
        'profile': profile,
        'products': products,
        'experts': experts,
        'tips': tips,
        'appointments': appointments,
        'chat_threads': chat_threads,
        'kyc_request': kyc_request,
        'kyc_status': kyc_status,
        'products_count': products.count(),
    }
    return render(request, 'farmer_dashboard.html', context)


@login_required
def vendor_dashboard(request):
    if request.user.role != 'vendor':
        return _redirect_to_role_home(request.user)
    
    # Ensure profile exists
    profile, created = VendorProfile.objects.get_or_create(user=request.user)
    
    # Check KYC status
    kyc_request = request.user.kyc_requests.first()
    kyc_status = kyc_request.status if kyc_request else None
    
    # Get vendor tools
    tools = VendorTool.objects.filter(vendor=profile).order_by('-created_at')
    
    context = {
        'profile': profile,
        'tools': tools,
        'kyc_request': kyc_request,
        'kyc_status': kyc_status,
        'tools_count': tools.count(),
        'available_tools_count': tools.filter(is_available=True).count(),
        'sold_tools_count': tools.filter(is_available=False).count(),
    }
    return render(request, 'vendor_dashboard.html', context)


@login_required
def expert_dashboard(request):
    if request.user.role != 'agricultural_expert':
        return _redirect_to_role_home(request.user)
    
    # Ensure profile exists
    profile, created = ExpertProfile.objects.get_or_create(user=request.user)
    
    # Check KYC status
    kyc_request = request.user.kyc_requests.first()
    kyc_status = kyc_request.status if kyc_request else None
    
    # Get expert content/tips
    tips = FarmingTip.objects.filter(expert=profile).order_by('-created_at')
    
    # Get appointments
    appointments = ExpertAppointment.objects.filter(expert=profile).select_related('requester').order_by('-created_at')
    
    # Get chat threads
    chat_threads = ExpertChatThread.objects.filter(expert=profile).select_related('created_by').order_by('-created_at')[:5]
    
    context = {
        'profile': profile,
        'tips': tips,
        'appointments': appointments,
        'chat_threads': chat_threads,
        'kyc_request': kyc_request,
        'kyc_status': kyc_status,
        'content_count': tips.count(),
        'appointments_count': appointments.count(),
        'chats_count': chat_threads.count(),
    }
    return render(request, 'expert_dashboard.html', context)


@login_required
def user_dashboard(request):
    if request.user.role != 'buyer':
        return _redirect_to_role_home(request.user)
    
    # Get all available tools from vendors
    tools = VendorTool.objects.filter(is_available=True).select_related('vendor', 'vendor__user').order_by('-created_at')
    
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
    
    context = {
        'tools': tools,
        'crops': crops,
        'experts': experts,
        'tips': tips,
        'appointments': appointments,
        'chat_threads': chat_threads,
        'profile': profile,
        'tools_count': tools.count(),
        'crops_count': crops.count(),
        'experts_count': experts.count(),
        'tips_count': tips.count(),
    }
    return render(request, 'user_dashboard.html', context)


@login_required
def admin_dashboard(request):
    if request.user.role != 'admin':
        return _redirect_to_role_home(request.user)
    return render(request, 'admin_dashboard.html')


@login_required
def appointment_request_page(request):
    if request.user.role not in {'buyer', 'farmer'}:
        return _redirect_to_role_home(request.user)

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
        return _redirect_to_role_home(request.user)
    
    threads = ExpertChatThread.objects.filter(created_by=request.user).select_related('expert', 'expert__user').order_by('-updated_at')
    context = {'threads': threads}
    return render(request, 'chat_threads.html', context)


@login_required
def chat_thread_detail(request, thread_id):
    if request.user.role not in {'buyer', 'farmer'}:
        return _redirect_to_role_home(request.user)
    
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
