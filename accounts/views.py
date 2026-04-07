from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse, Http404
from django.contrib import messages
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.core.mail import send_mail
from django.conf import settings
from django.db.models import Sum, Count, Q
from django.db.models.functions import TruncMonth, TruncDate
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from urllib.parse import urlencode
import secrets
import hashlib
import json
import logging
import smtplib
from datetime import timedelta, datetime, date
from decimal import Decimal, InvalidOperation
import calendar


def _parse_time_str(s):
    """Parse 'HH:MM' or 'HH:MM:SS' to time object. Returns None if empty or invalid."""
    if not s or not (s := (s or '').strip()):
        return None
    try:
        if len(s) <= 5:
            return datetime.strptime(s, '%H:%M').time()
        return datetime.strptime(s, '%H:%M:%S').time()
    except ValueError:
        return None

from .models import (
    KYCRequest,
    FarmerProfile,
    VendorProfile,
    ExpertProfile,
    FarmerProduct,
    VendorTool,
    FarmingTip,
    ExpertAppointment,
    ExpertAvailability,
    ExpertChatThread,
    ExpertChatMessage,
    UserProfile,
    Order,
    CropSale,
    OTP,
    FAQ,
    LandingFeature,
    SupportStaffProfile,
    SupportTicket,
    SupportMessage,
    UserNotification,
)
from .serializers import SignupSerializer, LoginSerializer, UserSerializer, OTPVerificationSerializer
from .decorators import kyc_required, kyc_optional
from .notifications import create_notification, get_admin_email_recipients, send_branded_email


def _chat_notification_link(recipient, thread_id):
    """For experts: link to expert dashboard chat section with thread. Others: link to current page with chat parameters."""
    if getattr(recipient, 'role', None) == 'agricultural_expert':
        return reverse('expert_dashboard') + '?section=chat&thread_id=' + str(thread_id)
    # For non-experts, return to current page with chat parameters
    return f'?open_chat=true&thread_id={thread_id}'


def get_user_profile_image(user):
    """Get user profile image URL based on user role."""
    try:
        if hasattr(user, 'expertprofile'):
            profile = user.expertprofile
            if profile and profile.photo:
                return profile.photo.url
        elif hasattr(user, 'farmerprofile'):
            profile = user.farmerprofile
            if profile and profile.photo:
                return profile.photo.url
        elif hasattr(user, 'userprofile'):
            profile = user.userprofile
            if profile and profile.photo:
                return profile.photo.url
    except:
        pass
    return '/static/images/default-avatar.png'


def get_user_display_name(user):
    """Best-effort display name for chat/UI."""
    try:
        if hasattr(user, 'expertprofile'):
            p = user.expertprofile
            if p and getattr(p, 'name', None):
                return p.name
        if hasattr(user, 'farmerprofile'):
            p = user.farmerprofile
            if p and getattr(p, 'name', None):
                return p.name
        if hasattr(user, 'vendorprofile'):
            p = user.vendorprofile
            if p and getattr(p, 'company_name', None):
                return p.company_name
        if hasattr(user, 'userprofile'):
            p = user.userprofile
            if p and getattr(p, 'name', None):
                return p.name
    except Exception:
        pass
    return (getattr(user, 'email', '') or 'User')


# Password reset tokens storage (in production, use Redis or database)
password_reset_tokens = {}
otp_storage = {}  # Store OTPs: {email: {'otp': '123456', 'token': '...', 'created_at': ...}}

def _user_requires_kyc(user):
    return user.role in {'farmer', 'vendor', 'agricultural_expert'}


def _to_decimal_or_none(value):
    try:
        return Decimal(str(value))
    except (TypeError, ValueError, InvalidOperation):
        return None

def _ensure_google_oauth(request=None):
    """
    Fix Google OAuth setup for local development:
    - Set Site domain to match request host (so redirect_uri matches Google Console)
    - Create/update SocialApp from env vars (GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET) if present
    """
    try:
        from django.contrib.sites.models import Site
        from allauth.socialaccount.models import SocialApp

        site = Site.objects.get_current()
        client_id = getattr(settings, 'GOOGLE_CLIENT_ID', '') or ''
        client_secret = getattr(settings, 'GOOGLE_CLIENT_SECRET', '') or ''

        # Fix Site domain: use request host so redirect_uri matches what user registered in Google Console
        if getattr(settings, 'DEBUG', False):
            needs_update = site.domain in ('example.com', 'localhost') or site.domain.startswith('127.0.0.1')
            if needs_update:
                if request and request.get_host():
                    site.domain = request.get_host()
                else:
                    site.domain = '127.0.0.1:8000'
                site.name = site.name or 'Farmity Local'
                site.save()

        # Auto-create SocialApp from env if credentials exist
        if client_id and client_secret and 'PLACEHOLDER' not in str(client_id):
            social_app, created = SocialApp.objects.get_or_create(
                provider='google',
                defaults={
                    'name': 'Google',
                    'client_id': client_id,
                    'secret': client_secret,
                    'key': '',
                }
            )
            if not created and (social_app.client_id != client_id or social_app.secret != client_secret):
                social_app.client_id = client_id
                social_app.secret = client_secret
                social_app.save()
            if site not in social_app.sites.all():
                social_app.sites.add(site)
    except Exception as e:
        if getattr(settings, 'DEBUG', False):
            import logging
            logging.getLogger(__name__).warning(f"Google OAuth setup: {e}")

def _ensure_role_profile(user):
    """Ensure every user has a profile for their role (including admin-created users)."""
    if user.role == 'farmer':
        FarmerProfile.objects.get_or_create(user=user)
    elif user.role == 'vendor':
        VendorProfile.objects.get_or_create(user=user)
    elif user.role == 'agricultural_expert':
        ExpertProfile.objects.get_or_create(user=user)
    elif user.role == 'buyer':
        UserProfile.objects.get_or_create(user=user)
    elif user.role == 'admin':
        UserProfile.objects.get_or_create(user=user)

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
    
    # Redirect to appropriate dashboard - return URL path.
    if user.role == 'admin':
        return reverse('admin_dashboard')
    if user.role == 'farmer':
        return reverse('farmer_dashboard')
    if user.role == 'vendor':
        return reverse('vendor_dashboard')
    if user.role == 'agricultural_expert':
        return reverse('expert_dashboard')
    if user.role == 'buyer':
        return reverse('user_dashboard')
    return reverse('landing')


def _redirect_to_role_home_response(user):
    """
    Returns a redirect response object (for use in views that render templates).
    """
    url_path = _redirect_to_role_home(user)
    return redirect(url_path)


def _redirect_same_page(request, view_name, section_param='return_section'):
    """
    Redirect to the same dashboard/page, optionally preserving section so the
    message is shown on the same view and same section (tab).
    """
    from urllib.parse import urlencode
    url = reverse(view_name)
    section = (request.POST.get(section_param) or request.GET.get('section') or '').strip()
    if section:
        url = reverse(view_name) + '?' + urlencode({'section': section})
    return redirect(url)


def _farmity_wants_ajax(request):
    """True when the client expects a JSON body (Fetch/XHR) instead of a redirect."""
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return True
    if str(request.POST.get('ajax', '')).strip() == '1':
        return True
    accept = request.headers.get('Accept') or ''
    return 'application/json' in accept


def _farmity_json_response(ok, message='', **extra):
    data = {'ok': bool(ok), 'message': message or ''}
    data.update(extra)
    return JsonResponse(data)


def _validate_profile_email_change(user, raw_email):
    """
    Returns (email_to_store, None) on success, or (None, error_message).
    """
    from django.core.validators import validate_email
    from django.core.exceptions import ValidationError

    User = get_user_model()
    candidate = (raw_email or '').strip()
    if not candidate:
        return None, 'Email is required.'
    try:
        validate_email(candidate)
    except ValidationError:
        return None, 'Please enter a valid email address.'
    normalized = User.objects.normalize_email(candidate)
    if normalized.lower() == (user.email or '').lower():
        return user.email, None
    if User.objects.filter(email__iexact=normalized).exclude(pk=user.pk).exists():
        return None, 'This email is already in use by another account.'
    return normalized, None


def _profile_finish(request, ok, message, extra_json=None):
    """JSON for AJAX posts; otherwise Django messages + redirect to profile."""
    if _farmity_wants_ajax(request):
        payload = {'ok': ok, 'message': message}
        if extra_json:
            payload.update(extra_json)
        return JsonResponse(payload)
    if ok:
        messages.success(request, message)
    else:
        messages.error(request, message)
    return redirect('profile')


def _redirect_same_admin_page(request, view_name):
    """
    Redirect back to the same admin page preserving all current GET parameters
    (section, status, search, etc.) so the user stays in the same place and
    messages display on that page.
    """
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
    fallback_url = reverse(view_name)

    # Preferred: state explicitly posted by frontend helper on form submit.
    return_path = (request.POST.get('_return_path') or '').strip()
    return_query = (request.POST.get('_return_query') or '').strip()
    return_scroll = (request.POST.get('_return_scroll') or '').strip()
    if return_query.startswith('?'):
        return_query = return_query[1:]

    if return_path.startswith('/') and not return_path.startswith('//'):
        url = return_path
        if return_query:
            url = url + '?' + return_query
    else:
        # Fallback: preserve current GET parameters
        url = fallback_url
        if request.GET:
            query = request.GET.copy()
            url = url + '?' + query.urlencode()

    # Preserve requested scroll position after POST->redirect
    if return_scroll:
        try:
            # Validate as int-like; ignore invalid values.
            int(return_scroll)
            parts = urlsplit(url)
            q = dict(parse_qsl(parts.query, keep_blank_values=True))
            q['_scroll'] = return_scroll
            url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))
        except (TypeError, ValueError):
            pass

    return redirect(url)


def _redirect_with_posted_ui_state(request, fallback_url):
    """
    Redirect to URL captured on form submit (_return_path/_return_query/_return_scroll),
    otherwise use provided fallback_url.
    """
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

    return_path = (request.POST.get('_return_path') or '').strip()
    return_query = (request.POST.get('_return_query') or '').strip()
    return_scroll = (request.POST.get('_return_scroll') or '').strip()
    if return_query.startswith('?'):
        return_query = return_query[1:]

    if return_path.startswith('/') and not return_path.startswith('//'):
        url = return_path
        if return_query:
            url = url + '?' + return_query
    else:
        url = fallback_url

    if return_scroll:
        try:
            int(return_scroll)
            parts = urlsplit(url)
            q = dict(parse_qsl(parts.query, keep_blank_values=True))
            q['_scroll'] = return_scroll
            url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))
        except (TypeError, ValueError):
            pass

    return redirect(url)


def _clear_stored_messages(request):
    """
    Clear any messages stored in the session so they are not shown on the next
    request (e.g. after login, so action notifications don't appear when opening
    another account's dashboard).
    """
    storage = messages.get_messages(request)
    storage.used = True


def _login_user(request, user):
    """Log the user in. With multiple AUTHENTICATION_BACKENDS, Django needs an explicit backend."""
    backend_path = None
    try:
        backend_path = getattr(user, "backend", None)
    except Exception:
        backend_path = None
    if not backend_path:
        backend_path = (getattr(settings, "AUTHENTICATION_BACKENDS", None) or [None])[0]
    if backend_path:
        login(request, user, backend=backend_path)
    else:
        login(request, user)


# ======================
# SIGNUP API
# ======================
@method_decorator(csrf_exempt, name='dispatch')
class SignupView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            print(f"Signup attempt data: {request.data}")
            serializer = SignupSerializer(data=request.data)

            if serializer.is_valid():
                print("Signup validation successful")
                user = serializer.save()
                print(f"User created: {user.email} (ID: {user.id})")
                # Send OTP and require email verification before KYC/dashboard.
                otp = OTP.generate_otp(user, expiry_minutes=30, purpose=OTP.PURPOSE_EMAIL_VERIFY)
                try:
                    send_mail(
                        subject='Verify your email - Farmity',
                        message=(
                            f'Your Farmity verification code is: {otp.otp_code}\n\n'
                            f'This code will expire in 30 minutes.\n\n'
                            f'Visit Farmity: https://tinyurl.com/Farmity\n\n'
                            f'If you did not create this account, please ignore this email.'
                        ),
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[user.email],
                        fail_silently=False,
                    )
                except Exception as e:
                    # Keep consistent signup UX even if SMTP fails in dev.
                    print(f"Error sending signup email verification OTP: {str(e)}")

                redirect_url = reverse('verify_email') + '?' + urlencode({'email': user.email})

                # Welcome email (user + admin copy).
                # Signup currently creates no in-app notification, so we send directly here.
                email_failed = False
                admin_emails = get_admin_email_recipients()

                recipient_list = []
                if user.email:
                    recipient_list.append(user.email)
                for e in admin_emails:
                    if e and e not in recipient_list:
                        recipient_list.append(e)

                if recipient_list:
                    kyc_next = redirect_url == reverse('kyc')
                    next_step_line = (
                        f"Next step: Complete your KYC verification here: {redirect_url}"
                        if kyc_next
                        else f"Next step: Go to your dashboard here: {redirect_url}"
                    )
                    role_name = (getattr(user, 'role', '') or '').replace('_', ' ').title() or 'Account'
                    welcome_body = (
                        f"Your account has been created successfully for {user.email}.\n"
                        f"Role: {role_name}\n\n"
                        f"{next_step_line}\n\n"
                        "We are excited to have you with us. If you need help, contact Farmity Support from the app."
                    )
                    email_failed = not send_branded_email(
                        subject="Welcome to Farmity",
                        title="Welcome to Farmity",
                        message=welcome_body,
                        recipient_list=recipient_list,
                        cta_link=redirect_url,
                        cta_text="Go to My Account",
                        retry_attempts=2,
                        role=getattr(user, "role", "") or "",
                        event_type="signup",
                    )

                response_data = {
                    "message": "Account created successfully. We sent a verification code (OTP) to your email.",
                    "email": user.email,
                    "redirect_url": redirect_url,
                }
                # Helpful for debugging SMTP issues.
                if getattr(settings, "DEBUG", False):
                    response_data["email_sent"] = not email_failed
                    if email_failed:
                        response_data["dev_note"] = (
                            "Welcome email did not send. Check Gmail SMTP settings in .env "
                            "(EMAIL_HOST_PASSWORD must be a 16-char Gmail App Password)."
                        )
                else:
                    response_data["email_sent"] = not email_failed

                return Response(response_data, status=status.HTTP_201_CREATED)

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


@method_decorator(csrf_exempt, name='dispatch')
class VerifyEmailView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            serializer = OTPVerificationSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(
                    {"error": "Validation failed", "details": serializer.errors},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            email = serializer.validated_data['email']
            otp_code = serializer.validated_data['otp']

            User = get_user_model()
            try:
                user = User.objects.get(email__iexact=email)
            except User.DoesNotExist:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            # Find a valid email-verification OTP (match code string; prefer latest)
            otp = (
                OTP.objects.filter(
                    user=user,
                    purpose=OTP.PURPOSE_EMAIL_VERIFY,
                    otp_code=otp_code,
                    is_used=False,
                    is_verified=False,
                )
                .order_by('-created_at')
                .first()
            )
            if not otp:
                return Response(
                    {"error": "Invalid or expired verification code. Please request a new one."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if otp.is_expired():
                return Response(
                    {"error": "Verification code has expired. Please request a new one."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            otp.is_verified = True
            otp.is_used = True
            otp.save(update_fields=['is_verified', 'is_used'])

            # Activate account
            user.email_verified = True
            user.is_active = True
            user.save(update_fields=['email_verified', 'is_active'])

            # Log the user in and send them to KYC (or role home if KYC not required)
            _login_user(request, user)
            redirect_url = reverse('kyc') if _user_requires_kyc(user) else _redirect_to_role_home(user)

            return Response(
                {"message": "Email verified successfully.", "email": user.email, "redirect_url": redirect_url},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response(
                {"error": "An unexpected error occurred during email verification.", "details": {"exception": str(e)}},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


@method_decorator(csrf_exempt, name='dispatch')
class ResendEmailVerificationView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            email = (request.data.get('email') or '').strip().lower()
            if not email:
                return Response(
                    {"error": "Validation failed", "details": {"email": ["Email is required."]}},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            User = get_user_model()
            try:
                user = User.objects.get(email__iexact=email)
            except User.DoesNotExist:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            if getattr(user, 'email_verified', False):
                return Response(
                    {"message": "Email is already verified.", "email": user.email},
                    status=status.HTTP_200_OK,
                )

            otp = OTP.generate_otp(user, expiry_minutes=30, purpose=OTP.PURPOSE_EMAIL_VERIFY)
            try:
                send_mail(
                    subject='Verify your email - Farmity',
                    message=(
                        f'Your Farmity verification code is: {otp.otp_code}\n\n'
                        f'This code will expire in 30 minutes.\n\n'
                        f'Visit Farmity: https://tinyurl.com/Farmity\n\n'
                        f'If you did not create this account, please ignore this email.'
                    ),
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.email],
                    fail_silently=False,
                )
            except Exception as e:
                print(f"Error resending email verification OTP: {str(e)}")
                return Response(
                    {"error": "Failed to send verification email. Please try again."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

            return Response(
                {"message": "Verification code resent. Please check your email.", "email": user.email},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response(
                {"error": "An unexpected error occurred.", "details": {"exception": str(e)}},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


# ======================
# LOGIN API (FIXED)
# ======================
@method_decorator(csrf_exempt, name='dispatch')
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

            # Block login until email is verified (and account is active)
            if not getattr(user, 'email_verified', False) or not user.is_active:
                return Response(
                    {"error": "Please verify your email to activate your account."},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Check if OTP is required (can be disabled in development)
            require_otp = getattr(settings, 'REQUIRE_OTP_FOR_LOGIN', True)
            
            # If OTP is not required (development mode), login directly
            if not require_otp:
                # Login the user directly
                _login_user(request, user)
                _clear_stored_messages(request)
                request.session['show_login_success'] = True
                request.session.modified = True
                
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
            
            # OTP is required - generate and send OTP
            otp = OTP.generate_otp(user, expiry_minutes=10, purpose=OTP.PURPOSE_LOGIN)
            
            # Send OTP via email
            try:
                send_mail(
                    subject='Your Login OTP - Farmity',
                    message=f'Your OTP code is: {otp.otp_code}\n\nThis code will expire in 10 minutes.\n\nClick here to enter your OTP: {request.build_absolute_uri("/otp-verification/")}\n\nVisit Farmity: https://tinyurl.com/Farmity\n\nIf you did not request this, please ignore this email.',
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.email],
                    fail_silently=False,
                )
                print(f"\n{'='*70}")
                print(f"OTP SENT TO: {user.email}")
                print(f"OTP CODE: {otp.otp_code}")
                print(f"EXPIRES AT: {otp.expires_at}")
                print(f"{'='*70}\n")
            except Exception as e:
                print(f"Error sending OTP email: {str(e)}")
                print(f"\n{'='*70}")
                print(f"OTP GENERATED (but email failed):")
                print(f"User: {user.email}")
                print(f"OTP CODE: {otp.otp_code}")
                print(f"EXPIRES AT: {otp.expires_at}")
                print(f"{'='*70}\n")
                # Still return success - OTP is generated, user can see it in console
                return Response(
                    {
                        "message": "OTP generated. Check Django console for OTP code.",
                        "email": user.email,
                        "requires_otp": True,
                        "otp_code": otp.otp_code,  # Include OTP in response for development
                        "console_message": f"OTP: {otp.otp_code} (Check Django console)"
                    },
                    status=status.HTTP_200_OK
                )

            return Response(
                {
                    "message": "OTP sent to your email. Please check your inbox.",
                    "email": user.email,
                    "requires_otp": True,
                    "otp_code": otp.otp_code,  # Include OTP in response for development
                    "console_message": f"OTP: {otp.otp_code} (Check Django console)"
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
# OTP VERIFICATION API
# ======================
@method_decorator(csrf_exempt, name='dispatch')
class OTPVerificationView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            serializer = OTPVerificationSerializer(data=request.data)
            
            if not serializer.is_valid():
                return Response(
                    {
                        "error": "Validation failed",
                        "details": serializer.errors
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            email = serializer.validated_data['email']
            otp_code = serializer.validated_data['otp']
            
            User = get_user_model()
            try:
                user = User.objects.get(email__iexact=email)
            except User.DoesNotExist:
                return Response(
                    {"error": "User not found"},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Find valid OTP for this user (prefer latest matching code)
            try:
                otp = (
                    OTP.objects.filter(
                        user=user,
                        purpose=OTP.PURPOSE_LOGIN,
                        otp_code=otp_code,
                        is_used=False,
                        is_verified=False,
                    )
                    .order_by('-created_at')
                    .first()
                )
                if not otp:
                    return Response(
                        {"error": "Invalid or expired OTP. Please request a new one."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                # Check if OTP is expired
                if otp.is_expired():
                    return Response(
                        {"error": "OTP has expired. Please request a new one."},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Mark OTP as verified and used
                otp.is_verified = True
                otp.is_used = True
                otp.save()
                
                # Login the user
                _login_user(request, user)
                _clear_stored_messages(request)
                request.session['show_login_success'] = True
                request.session.modified = True
                
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
                        "message": "OTP verified successfully. Login successful.",
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
                        "error": "Error verifying OTP",
                        "details": str(e)
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response(
                {
                    "error": "An unexpected error occurred during OTP verification.",
                    "details": {"exception": str(e)}
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# ======================
# RESEND OTP API
# ======================
@method_decorator(csrf_exempt, name='dispatch')
class ResendOTPView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            email = request.data.get('email')
            if not email:
                return Response(
                    {"error": "Email is required"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            User = get_user_model()
            try:
                user = User.objects.get(email__iexact=email)
            except User.DoesNotExist:
                return Response(
                    {"error": "User not found"},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Generate new OTP
            otp = OTP.generate_otp(user, expiry_minutes=10, purpose=OTP.PURPOSE_LOGIN)
            
            # Send OTP via email
            try:
                send_mail(
                    subject='Your Login OTP - Farmity',
                    message=f'Your OTP code is: {otp.otp_code}\n\nThis code will expire in 10 minutes.\n\nClick here to enter your OTP: {request.build_absolute_uri("/otp-verification/")}\n\nVisit Farmity: https://tinyurl.com/Farmity\n\nIf you did not request this, please ignore this email.',
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.email],
                    fail_silently=False,
                )
            except Exception as e:
                print(f"Error sending OTP email: {str(e)}")
                return Response(
                    {
                        "error": "Failed to send OTP. Please try again.",
                        "details": str(e)
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            return Response(
                {
                    "message": "OTP resent to your email. Please check your inbox.",
                    "email": user.email
                },
                status=status.HTTP_200_OK
            )
        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response(
                {
                    "error": "An unexpected error occurred.",
                    "details": {"exception": str(e)}
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# ======================
# FORGOT PASSWORD API
# ======================
@method_decorator(csrf_exempt, name='dispatch')
class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            # Support both JSON and form-encoded body
            email = (request.data.get('email') or request.POST.get('email') or '').strip().lower()
            
            if not email:
                return Response(
                    {"error": "Email is required"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            User = get_user_model()
            try:
                user = User.objects.get(email__iexact=email)
            except User.DoesNotExist:
                # Email is not registered in the system
                return Response(
                    {"error": "This email is not registered with Farmity. Please check your email address or create a new account."},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Generate 6-digit OTP
            otp = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
            
            # Generate secure token for password reset
            token = secrets.token_urlsafe(32)
            
            # Store OTP and token (use normalized email for lookup)
            otp_storage[email] = {
                'otp': otp,
                'token': token,
                'user_id': user.id,
                'created_at': timezone.now()
            }
            
            # Store token for password reset
            password_reset_tokens[token] = {
                'user_id': user.id,
                'email': email,
                'created_at': timezone.now()
            }
            
            # Send OTP to the same email address used for the reset request
            recipient_email = email
            email_failed = False
            try:
                sent = send_mail(
                    subject='Your Farmity Password Reset OTP',
                    message=f'''Hello,

You requested to reset your password for your Farmity account (email: {recipient_email}).

Your One-Time Password (OTP) is: {otp}

This OTP will expire in 10 minutes.

Click here to directly enter your OTP: {request.build_absolute_uri('/otp-verification/?token=' + token)}

Visit Farmity: https://tinyurl.com/Farmity

If you didn't request this, please ignore this email.

Best regards,
Farmity Team''',
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[recipient_email],
                    fail_silently=False,
                )
                if sent:
                    print(f"[Email] OTP sent successfully to: {recipient_email} (check inbox and spam folder)")
                else:
                    email_failed = True
                    print(f"[Email] send_mail returned 0 for {recipient_email}")
            except Exception as e:
                email_failed = True
                log = logging.getLogger(__name__)
                # 535 from Gmail: wrong password type or bad credentials — don't spam the console with a full traceback
                if isinstance(e, smtplib.SMTPAuthenticationError):
                    log.warning(
                        "Gmail SMTP auth failed (535): set EMAIL_HOST_PASSWORD to a 16-char "
                        "App Password (Google Account → Security → App passwords), not your normal password. "
                        "See EMAIL_SETUP.md."
                    )
                    if settings.DEBUG:
                        log.debug("OTP (email not sent, DEBUG only): %s", otp)
                else:
                    log.error("Forgot-password email failed: %s: %s", type(e).__name__, e)
                    if settings.DEBUG:
                        import traceback
                        traceback.print_exc()
                        log.debug("OTP (email not sent, DEBUG only): %s", otp)
            
            response_data = {
                "message": "If an account with that email exists, an OTP has been sent. Check your inbox and spam folder.",
                "token": token,
            }
            if settings.DEBUG:
                response_data["email_sent"] = not email_failed
                if email_failed:
                    response_data["dev_note"] = (
                        "Email did not send: fix Gmail App Password in .env (EMAIL_HOST_PASSWORD). "
                        "See EMAIL_SETUP.md."
                    )
            return Response(response_data, status=status.HTTP_200_OK)
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
@method_decorator(csrf_exempt, name='dispatch')
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
# KALIMATI LIVE PRICES (https://kalimatimarket.gov.np/price)
# ======================
KALIMATI_PRICE_URL = 'https://kalimatimarket.gov.np/price'


def _fetch_kalimati_prices():
    """Fetch and parse daily wholesale prices from Kalimati fruit & vegetable market (Nepal). Returns list of dicts or [] on failure."""
    import re
    try:
        import requests
        from bs4 import BeautifulSoup
    except ImportError:
        return []
    try:
        r = requests.get(KALIMATI_PRICE_URL, timeout=10, headers={'User-Agent': 'Farmity/1.0'})
        r.raise_for_status()
        r.encoding = r.apparent_encoding or 'utf-8'
        soup = BeautifulSoup(r.text, 'html.parser')
        table = soup.find('table')
        if not table:
            return []
        rows = table.find_all('tr')
        out = []
        for i, tr in enumerate(rows):
            cells = tr.find_all(['td', 'th'])
            if len(cells) < 5:
                continue
            # Skip header row (usually first row with न्यूनतम etc.)
            raw = [c.get_text(strip=True) for c in cells[:5]]
            name, unit, min_p, max_p, avg_p = raw[0], raw[1], raw[2], raw[3], raw[4]
            if not name or name in ('कृषि उपज', 'ईकाइ', 'न्यूनतम', 'अधिकतम', 'औसत') or not re.search(r'[\d.]', min_p):
                continue
            def parse_price(s):
                s = re.sub(r'[^\d.]', '', s.replace(',', ''))
                try:
                    return float(s) if s else None
                except ValueError:
                    return None
            min_val, max_val, avg_val = parse_price(min_p), parse_price(max_p), parse_price(avg_p)
            if min_val is None and max_val is None and avg_val is None:
                continue
            out.append({
                'name': name,
                'unit': unit or 'के.जी.',
                'min_price': min_val,
                'max_price': max_val,
                'avg_price': avg_val,
            })
        return out[:6]
    except Exception:
        return []


# ======================
# FRONTEND PAGES
# ======================
def landing_page(request):
    """Landing page with real data: crops, tools, vendors, experts, learning tips, and Kalimati live prices."""
    # Rotate featured items hourly (reset daily) for a predictable "change" effect on refresh.
    now = timezone.localtime(timezone.now())
    seed = ((now.date() - date(1970, 1, 1)).days * 24) + now.hour  # 0..23 per day, changes hourly

    from collections import defaultdict

    def _pick_cyclic(ids, n, start_offset=0):
        if not ids:
            return []
        start = (seed + start_offset) % len(ids)
        return [ids[(start + i) % len(ids)] for i in range(n)]

    # --- Featured Crops (show exactly 4, rotate hourly) ---
    crop_ids = list(
        FarmerProduct.objects.filter(is_available=True, quantity__gt=0)
        .order_by('-created_at', 'id')
        .values_list('id', flat=True)
    )
    selected_crop_ids = _pick_cyclic(crop_ids, 4)
    crop_qs = (
        FarmerProduct.objects.filter(id__in=selected_crop_ids)
        .select_related('farmer', 'farmer__user')
        .order_by('-created_at', 'id')
    )
    crops_map = {c.id: c for c in crop_qs}
    crops = [crops_map[cid] for cid in selected_crop_ids if cid in crops_map]

    # --- Featured Tools (show exactly 4, rotate hourly) ---
    tool_ids = list(
        VendorTool.objects.filter(is_available=True, stock_quantity__gt=0)
        .order_by('-created_at', 'id')
        .values_list('id', flat=True)
    )
    selected_tool_ids = _pick_cyclic(tool_ids, 4)
    tool_qs = (
        VendorTool.objects.filter(id__in=selected_tool_ids)
        .select_related('vendor', 'vendor__user')
        .order_by('-created_at', 'id')
    )
    tools_map = {t.id: t for t in tool_qs}
    tools = [tools_map[tid] for tid in selected_tool_ids if tid in tools_map]

    # --- Vendor Spotlight (show exactly 4 vendors, one featured tool per vendor changes hourly) ---
    vendor_ids = list(
        VendorProfile.objects.annotate(
            tool_count=Count('tools', filter=Q(tools__is_available=True, tools__stock_quantity__gt=0))
        )
        .filter(user__is_verified=True)
        .filter(tool_count__gt=0)
        .order_by('id')
        .values_list('id', flat=True)
    )
    # Show at most 4 distinct vendors. If there are only 3 registered vendors, show only 3 (no duplicates).
    selected_vendor_ids = _pick_cyclic(vendor_ids, min(4, len(vendor_ids)))

    vendors_qs = (
        VendorProfile.objects.annotate(
            tool_count=Count('tools', filter=Q(tools__is_available=True, tools__stock_quantity__gt=0))
        )
        .filter(id__in=set(selected_vendor_ids))
        .select_related('user')
    )
    vendors_map = {v.id: v for v in vendors_qs}
    vendors = [vendors_map[vid] for vid in selected_vendor_ids if vid in vendors_map]

    # Featured tool per vendor card (rotate hourly within each vendor's tools)
    spotlight_tool_qs = (
        VendorTool.objects.filter(
            vendor_id__in=set(selected_vendor_ids),
            is_available=True,
            stock_quantity__gt=0,
        )
        .select_related('vendor', 'vendor__user')
        .order_by('-created_at', 'id')
    )
    tools_by_vendor = defaultdict(list)
    for tool in spotlight_tool_qs:
        tools_by_vendor[tool.vendor_id].append(tool)

    for vendor_id in selected_vendor_ids:
        vendor = vendors_map.get(vendor_id)
        if not vendor:
            continue
        options = tools_by_vendor.get(vendor_id) or []
        if not options:
            continue
        pick_idx = (seed + vendor_id) % len(options)
        vendor.featured_tool = options[pick_idx]

    experts = ExpertProfile.objects.select_related('user').all()[:6]
    farming_tips = FarmingTip.objects.filter(is_published=True, approval_status=FarmingTip.APPROVAL_APPROVED).select_related('expert', 'expert__user').order_by('-created_at')[:4]
    farmers_count = FarmerProfile.objects.count()
    vendors_count = VendorProfile.objects.count()
    experts_count = ExpertProfile.objects.count()
    landing_features = LandingFeature.objects.filter(is_active=True).order_by('display_order', 'created_at')
    from django.db.models import Min
    crop_prices = list(FarmerProduct.objects.filter(is_available=True, quantity__gt=0).values('name').annotate(min_price=Min('price_per_unit')).order_by('name')[:6])
    kalimati_prices = _fetch_kalimati_prices()
    # Real produce images for first 6 live price cards (Unsplash, free to use)
    price_images = [
        'https://images.unsplash.com/photo-1546470427-e26264be0b0d?w=400',   # tomato
        'https://images.unsplash.com/photo-1518977676601-b53f82aba655?w=400', # potato
        'https://images.unsplash.com/photo-1580201092674-a0a6a6cafbb1?w=400', # onion
        'https://images.unsplash.com/photo-1598170845058-32b9d6a5da37?w=400', # carrot
        'https://images.unsplash.com/photo-1585325706348-66b0d4e1e0c2?w=400', # cabbage
        'https://images.unsplash.com/photo-1576045057995-568f588f82fb?w=400', # cauliflower
    ]
    for i, item in enumerate(kalimati_prices):
        item['image_url'] = price_images[i] if i < len(price_images) else None
    for i, item in enumerate(crop_prices):
        item['image_url'] = price_images[i] if i < len(price_images) else None
    context = {
        'crops': crops,
        'tools': tools,
        'experts': experts,
        'farming_tips': farming_tips,
        'vendors': vendors,
        'vendor_spotlight_count': len(vendors),
        'landing_features': landing_features,
        'farmers_count': farmers_count,
        'vendors_count': vendors_count,
        'experts_count': experts_count,
        'crop_prices': crop_prices,
        'kalimati_prices': kalimati_prices,
        'kalimati_price_url': KALIMATI_PRICE_URL,
    }
    return render(request, 'landing.html', context)


def role_selection(request):
    return render(request, 'role_selection.html')


def register_page(request):
    from django.contrib.sites.models import Site
    from allauth.socialaccount.models import SocialApp

    _ensure_google_oauth(request)

    role = (request.GET.get('role', '') or '').strip().lower()
    # Clean up role - ensure no None/null values and only allow valid roles
    if role in ['none', 'null', 'undefined', '']:
        role = ''
    valid_roles = {'farmer', 'buyer', 'vendor', 'agricultural_expert'}
    if role and role not in valid_roles:
        role = ''
    
    # Check if Google OAuth is configured
    google_oauth_enabled = False
    google_oauth_error = None
    
    try:
        # Check if SocialApp exists in database and is associated with current site
        site = Site.objects.get_current()
        social_app = SocialApp.objects.get(provider='google')
        
        # Check if associated with current site
        if site not in social_app.sites.all():
            google_oauth_error = "Google OAuth not associated with current site. Please configure in admin panel."
        # Check if credentials are valid
        elif social_app.client_id and social_app.secret and 'PLACEHOLDER' not in social_app.client_id:
            google_oauth_enabled = True
        else:
            google_oauth_error = "Google OAuth credentials not configured. Please set up Google OAuth in admin panel."
    except SocialApp.DoesNotExist:
        google_oauth_error = "Google OAuth not set up. Add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to .env, then run: python manage.py setup_google_oauth"
    except Exception as e:
        google_oauth_error = f"Error checking Google OAuth: {str(e)}"
    
    scheme = 'https' if request.is_secure() else 'http'
    host = request.get_host() if request.get_host() else '127.0.0.1:8000'
    google_redirect_uri = f"{scheme}://{host}/accounts/google/login/callback/"
    
    # Store signup role in session so Google OAuth callback can assign it to new users
    if role in {'farmer', 'vendor', 'agricultural_expert', 'buyer'}:
        request.session['signup_role'] = role
        request.session.modified = True

    # Signup page errors/success banners are shown via frontend (see register.html + main.js).

    context = {
        'role': role,
        'google_oauth_enabled': google_oauth_enabled,
        'google_oauth_error': google_oauth_error,
        'google_redirect_uri': google_redirect_uri,
    }
    return render(request, 'register.html', context)


def login_page(request):
    from django.contrib.sites.models import Site
    from allauth.socialaccount.models import SocialApp

    _ensure_google_oauth(request)

    # Check if Google OAuth is configured
    google_oauth_enabled = False
    google_oauth_error = None
    
    try:
        # Check if SocialApp exists in database and is associated with current site
        site = Site.objects.get_current()
        social_app = SocialApp.objects.get(provider='google')
        
        # Check if associated with current site
        if site not in social_app.sites.all():
            google_oauth_error = "Google OAuth not associated with current site. Please configure in admin panel."
        # Check if credentials are valid
        elif social_app.client_id and social_app.secret and 'PLACEHOLDER' not in social_app.client_id:
            google_oauth_enabled = True
        else:
            google_oauth_error = "Google OAuth credentials not configured. Please set up Google OAuth in admin panel."
    except SocialApp.DoesNotExist:
        google_oauth_error = "Google OAuth not set up. Add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to .env, then run: python manage.py setup_google_oauth"
    except Exception as e:
        google_oauth_error = f"Error checking Google OAuth: {str(e)}"
    
    # Build redirect URI hint for Google Console
    scheme = 'https' if request.is_secure() else 'http'
    host = request.get_host() if request.get_host() else '127.0.0.1:8000'
    google_redirect_uri = f"{scheme}://{host}/accounts/google/login/callback/"
    
    context = {
        'google_oauth_enabled': google_oauth_enabled,
        'google_oauth_error': google_oauth_error,
        'google_redirect_uri': google_redirect_uri,
    }
    return render(request, 'login.html', context)


def google_signup_start_view(request):
    """Set signup_role in session and redirect to Google OAuth. Ensures role is set right before OAuth."""
    role = (request.GET.get('role', '') or '').strip().lower()
    valid = {'farmer', 'vendor', 'agricultural_expert', 'buyer'}
    if role not in valid:
        role = 'buyer'
    request.session['signup_role'] = role
    request.session.modified = True
    return redirect(f'/accounts/google/login/?process=signup')


# ------------------------------
# eSewa ePay (Nepal) integration
# ------------------------------
@login_required
def esewa_initiate(request):
    """
    Initiate eSewa payment for an order. GET/POST: order_id (single order) or cart (cart checkout).
    Builds signed form and returns HTML that auto-posts to eSewa.
    """
    from .esewa import get_esewa_config, esewa_build_form_data
    from .models import Order, PaymentGroup

    merchant_code, secret, form_url, _ = get_esewa_config()
    if not merchant_code or not secret:
        messages.error(request, 'eSewa is not configured. Please use Cash on Delivery.')
        return _redirect_to_role_home_response(request.user)

    order_id = request.GET.get('order_id') or request.POST.get('order_id')
    if order_id:
        try:
            order_id = int(order_id)
            order = Order.objects.get(id=order_id, buyer=request.user, payment_method=Order.PAYMENT_ESEWA)
        except (ValueError, Order.DoesNotExist):
            messages.error(request, 'Order not found or invalid.')
            return _redirect_to_role_home_response(request.user)
        if order.payment_status == Order.PAYMENT_STATUS_COMPLETED:
            messages.info(request, 'This order is already paid.')
            return _redirect_to_role_home_response(request.user)
        total_amount = order.total_amount
        transaction_uuid = f'order-{order.id}'
        order_ids = [order.id]
    else:
        # Cart checkout: order ids stored in session
        order_ids = request.session.get('esewa_pending_order_ids', [])
        if not order_ids:
            messages.error(request, 'No pending eSewa payment found. Please try checkout again.')
            return _redirect_to_role_home_response(request.user)
        orders = Order.objects.filter(id__in=order_ids, buyer=request.user, payment_method=Order.PAYMENT_ESEWA)
        if orders.count() != len(order_ids):
            request.session.pop('esewa_pending_order_ids', None)
            messages.error(request, 'Invalid pending orders.')
            return _redirect_to_role_home_response(request.user)
        total_amount = sum(o.total_amount for o in orders)
        # Persist reconciliation data in DB so callbacks work even if session is lost
        ref = 'pg-' + secrets.token_urlsafe(16).replace('-', '').replace('_', '')[:32]
        PaymentGroup.objects.create(
            reference=ref,
            buyer=request.user,
            order_ids=list(order_ids),
            total_amount=total_amount,
            status=PaymentGroup.STATUS_PENDING,
        )
        transaction_uuid = ref

    scheme = 'https' if request.is_secure() else 'http'
    host = request.get_host() or '127.0.0.1:8000'
    base = f'{scheme}://{host}'
    success_url = base + reverse('esewa_success')
    failure_url = base + reverse('esewa_failure')

    form_data = esewa_build_form_data(
        total_amount=total_amount,
        transaction_uuid=transaction_uuid,
        success_url=success_url,
        failure_url=failure_url,
    )
    if not form_data:
        messages.error(request, 'eSewa configuration error.')
        return _redirect_to_role_home_response(request.user)

    # Store ref for success callback (cart: we need to know which orders to mark paid)
    request.session['esewa_transaction_ref'] = transaction_uuid
    request.session['esewa_order_ids'] = order_ids
    request.session.modified = True

    from django.conf import settings
    esewa_use_uat = getattr(settings, 'ESEWA_USE_UAT', True)
    return render(request, 'esewa_redirect.html', {
        'form_url': form_url,
        'form_data': form_data,
        'total_amount': total_amount,
        'order_count': len(order_ids),
        'esewa_use_uat': esewa_use_uat,
    })


def esewa_success(request):
    """
    eSewa redirects here after successful payment with ?data=<base64>.
    Decode, verify signature, update order(s) payment_status to completed.
    """
    from .esewa import get_esewa_config, esewa_verify_callback_signature
    from .models import Order, PaymentGroup, CropSale, FarmerProduct, VendorTool
    from urllib.parse import unquote
    import base64
    import json

    data_b64 = (request.GET.get('data') or request.GET.get('q') or '').strip()
    if not data_b64:
        messages.error(request, 'Invalid eSewa callback.')
        return redirect(reverse('user_dashboard'))

    # URL-decode in case eSewa sends encoded query string
    data_b64 = unquote(data_b64)
    raw = None
    for attempt in [data_b64, data_b64 + '=' * (4 - len(data_b64) % 4) if len(data_b64) % 4 else data_b64]:
        try:
            raw = base64.b64decode(attempt)
            break
        except Exception:
            try:
                raw = base64.urlsafe_b64decode(attempt.replace('-', '+').replace('_', '/'))
                break
            except Exception:
                continue
    if raw is None:
        messages.error(request, 'Invalid eSewa response.')
        return redirect(reverse('user_dashboard'))
    try:
        data_str = raw.decode('utf-8')
        data = json.loads(data_str)
    except Exception:
        messages.error(request, 'Invalid eSewa response.')
        return redirect(reverse('user_dashboard'))

    if data.get('status') != 'COMPLETE':
        messages.warning(request, 'Payment was not completed.')
        return redirect(reverse('user_dashboard'))

    from .esewa import esewa_verify_callback_signature
    _, secret, _, _ = get_esewa_config()
    if not secret or not esewa_verify_callback_signature(data, secret):
        messages.error(request, 'Payment verification failed.')
        return redirect(reverse('user_dashboard'))

    # Real-time verification: confirm with eSewa Status Check API when possible
    from .esewa import esewa_verify_transaction_realtime
    transaction_uuid = data.get('transaction_uuid', '')
    total_amount_callback = data.get('total_amount')
    product_code_callback = data.get('product_code', '')
    verification = esewa_verify_transaction_realtime(transaction_uuid, total_amount_callback, product_code_callback)
    if verification:
        status = (verification.get('status') or '').upper()
        if status != 'COMPLETE':
            err_msg = verification.get('error_message') or f"Payment status: {verification.get('status')}. Only completed payments are accepted. If you were charged, please contact support with your order details."
            messages.error(request, err_msg)
            return redirect(reverse('user_dashboard'))
        # Amount match (fraud check)
        try:
            verified_total = float(verification.get('total_amount', 0))
            expected_total = float(total_amount_callback)
            if abs(verified_total - expected_total) > 0.01:
                messages.error(request, 'Payment amount mismatch. Please contact support.')
                return redirect(reverse('user_dashboard'))
        except (TypeError, ValueError):
            pass
    # If verification is None (API timeout/unavailable), accept callback: signature already verified and status is COMPLETE

    transaction_uuid = data.get('transaction_uuid', '')
    order_ids_to_notify = []
    if transaction_uuid.startswith('order-'):
        try:
            order_id = int(transaction_uuid.replace('order-', ''))
            Order.objects.filter(id=order_id, payment_method=Order.PAYMENT_ESEWA).update(
                payment_status=Order.PAYMENT_STATUS_COMPLETED
            )
            order_ids_to_notify = [order_id]
        except ValueError:
            pass
    elif transaction_uuid.startswith('pg-'):
        pg = PaymentGroup.objects.filter(reference=transaction_uuid).first()
        if pg and pg.order_ids:
            Order.objects.filter(id__in=pg.order_ids, payment_method=Order.PAYMENT_ESEWA).update(
                payment_status=Order.PAYMENT_STATUS_COMPLETED
            )
            pg.status = PaymentGroup.STATUS_COMPLETED
            pg.save(update_fields=['status', 'updated_at'])
            order_ids_to_notify = list(pg.order_ids)
        # Session cleanup (optional)
        request.session.pop('esewa_order_ids', None)
        request.session.pop('esewa_pending_order_ids', None)
        request.session.pop('esewa_transaction_ref', None)
    redirect_after = request.session.pop('esewa_redirect_after', 'user_dashboard')
    request.session.pop('esewa_transaction_ref', None)
    request.session.pop('esewa_order_ids', None)
    request.session.pop('esewa_pending_order_ids', None)

    # Finalize inventory + crop sales for newly-paid orders (idempotent)
    if order_ids_to_notify:
        paid_orders = Order.objects.filter(id__in=order_ids_to_notify).select_related(
            'tool', 'tool__vendor', 'crop', 'crop__farmer', 'buyer'
        )
        for o in paid_orders:
            if o.inventory_deducted:
                continue
            # Tool order: deduct stock now
            if o.tool_id:
                tool = VendorTool.objects.filter(id=o.tool_id).first()
                if tool:
                    tool.stock_quantity = max(0, int(tool.stock_quantity) - int(o.quantity or 1))
                    if tool.stock_quantity == 0:
                        tool.is_available = False
                    tool.save(update_fields=['stock_quantity', 'is_available'])
            # Crop order: deduct crop quantity now + record CropSale once
            if o.crop_id:
                crop = FarmerProduct.objects.filter(id=o.crop_id).first()
                if crop:
                    # We store integer quantity on Order, but crop.quantity is Decimal.
                    q = Decimal(str(o.quantity or 1))
                    crop.quantity = crop.quantity - q
                    if crop.quantity <= 0:
                        crop.quantity = Decimal('0')
                        crop.is_available = False
                    crop.save(update_fields=['quantity', 'is_available'])
                    if not CropSale.objects.filter(order=o).exists():
                        CropSale.objects.create(
                            crop=crop,
                            order=o,
                            quantity_sold=q,
                            price_per_unit=crop.price_per_unit,
                            total_amount=(Decimal(str(crop.price_per_unit)) * q),
                            sold_to=o.buyer,
                            sold_at=timezone.now(),
                        )
            o.inventory_deducted = True
            o.save(update_fields=['inventory_deducted'])

    # Notify buyer and seller (vendor/farmer) for each paid order
    if order_ids_to_notify:
        orders = Order.objects.filter(id__in=order_ids_to_notify).select_related(
            'buyer', 'tool', 'tool__vendor', 'crop', 'crop__farmer'
        )
        for order in orders:
            item_name = (order.tool.name if order.tool else order.crop.name) if (order.tool or order.crop) else 'Order'
            amt = float(order.total_amount)
            if order.buyer:
                create_notification(
                    order.buyer,
                    'Payment successful',
                    f'Payment of Rs. {amt:.2f} received for Order #{order.id} ({item_name}).',
                    reverse('user_dashboard') + '?section=orders',
                    UserNotification.TYPE_ORDER
                )
            seller_user = None
            if order.tool and getattr(order.tool.vendor, 'user', None):
                seller_user = order.tool.vendor.user
            elif order.crop and getattr(order.crop.farmer, 'user', None):
                seller_user = order.crop.farmer.user
            if seller_user:
                create_notification(
                    seller_user,
                    'Payment received',
                    f'Order #{order.id}: {item_name} — Rs. {amt:.2f} paid by buyer.',
                    reverse('vendor_dashboard') if order.tool else (reverse('farmer_dashboard') + '?section=orders'),
                    UserNotification.TYPE_ORDER
                )

    messages.success(request, 'Payment successful! Your order has been confirmed.')
    redirect_url = reverse(redirect_after)
    if redirect_after == 'farmer_dashboard':
        from urllib.parse import urlencode
        redirect_url = redirect_url + '?' + urlencode({'checkout_success': '1', 'section': 'tools'})
    return render(request, 'esewa_result.html', {
        'success': True,
        'redirect_url': redirect_url,
    })


def esewa_failure(request):
    """eSewa redirects here on payment failure or cancel."""
    from .models import PaymentGroup
    # If this failure corresponds to a PaymentGroup, mark it failed (best-effort)
    ref = request.session.get('esewa_transaction_ref')
    if ref and isinstance(ref, str) and ref.startswith('pg-'):
        PaymentGroup.objects.filter(reference=ref).update(status=PaymentGroup.STATUS_FAILED)
    redirect_after = request.session.pop('esewa_redirect_after', 'user_dashboard')
    request.session.pop('esewa_order_ids', None)
    request.session.pop('esewa_pending_order_ids', None)
    request.session.pop('esewa_transaction_ref', None)
    messages.warning(request, 'eSewa payment was cancelled or failed. You can try again or use Cash on Delivery.')
    return render(request, 'esewa_result.html', {
        'success': False,
        'redirect_url': reverse(redirect_after),
    })


def favicon_view(request):
    """Avoid 404 for /favicon.ico; return no content so the browser stops requesting."""
    return HttpResponse(status=204)


def forgot_password_page(request):
    # Check for messages from redirects
    context = {}
    return render(request, 'forgot_password.html', context)


def otp_verification_page(request):
    email = request.GET.get('email', '')
    token = request.GET.get('token', '')
    return render(request, 'otp_verification.html', {'email': email, 'token': token})

def verify_email_page(request):
    email = request.GET.get('email', '')
    return render(request, 'email_verification.html', {'email': email})


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


@login_required
def order_detail_page(request, order_id):
    """Order detail view: visible to the buyer or the seller (farmer/vendor) of this order."""
    try:
        order = Order.objects.select_related(
            'buyer',
            'crop', 'crop__farmer', 'crop__farmer__user',
            'tool', 'tool__vendor', 'tool__vendor__user',
        ).get(pk=order_id)
    except Order.DoesNotExist:
        raise Http404("Order not found.")

    # Permission: buyer, or seller (farmer for crop orders, vendor for tool orders), or admin
    is_buyer = order.buyer_id == request.user.id
    seller_user = order.get_seller_user()
    is_seller = seller_user and seller_user.id == request.user.id
    is_admin = getattr(request.user, 'role', None) == 'admin'
    if not (is_buyer or is_seller or is_admin):
        raise Http404("You do not have access to this order.")

    # Back link: to orders section of the appropriate dashboard
    if is_buyer:
        if request.user.role == 'farmer':
            back_url = reverse('farmer_dashboard') + '?section=my_orders'
            back_label = 'Back to My Orders'
        else:
            back_url = reverse('user_dashboard') + '?section=orders'
            back_label = 'Back to My Orders'
    elif request.user.role == 'farmer':
        back_url = reverse('farmer_dashboard') + '?section=orders'
        back_label = 'Back to Received Orders'
    elif request.user.role == 'vendor':
        back_url = reverse('vendor_dashboard') + '?section=orders'
        back_label = 'Back to Customer Orders'
    else:
        back_url = reverse('dashboard')
        back_label = 'Back to Dashboard'

    order_product_subtotal = order.total_amount - (order.shipping_cost or Decimal('0'))
    # Commission breakdown: use stored values if set, else compute for display (e.g. legacy orders)
    if order.admin_commission and order.admin_commission > 0 and order.seller_amount and order.seller_amount > 0:
        display_admin_commission = order.admin_commission
        display_seller_amount = order.seller_amount
    else:
        display_admin_commission, display_seller_amount = Order.compute_commission(
            order.total_amount or 0,
            order.shipping_cost or 0,
            product_type='tool' if order.tool_id else ('crop' if order.crop_id else None),
        )
    context = {
        'order': order,
        'order_product_subtotal': order_product_subtotal,
        'display_admin_commission': display_admin_commission,
        'display_seller_amount': display_seller_amount,
        'is_admin': is_admin,
        'back_url': back_url,
        'back_label': back_label,
        'is_buyer': is_buyer,
        'is_seller': is_seller,
    }
    if request.GET.get('embed'):
        return render(request, 'order_detail_fragment.html', context)
    return render(request, 'order_detail.html', context)


def home_page(request):
    """Redirect /home/ to role dashboard or landing."""
    if request.user.is_authenticated:
        return _redirect_to_role_home_response(request.user)
    return redirect('landing')


@login_required
def dashboard(request):
    """Redirect to role-specific dashboard, preserving query string (e.g. section=chat&thread_id= for notifications)."""
    url_path = _redirect_to_role_home(request.user)
    qs = request.META.get('QUERY_STRING', '').strip()
    if qs:
        url_path = url_path + ('&' if '?' in url_path else '?') + qs
    return redirect(url_path)


@login_required
def kyc_page(request):
    if not getattr(request.user, 'email_verified', False):
        messages.error(request, 'Please verify your email (OTP) before continuing to KYC.')
        return redirect(reverse('verify_email') + '?' + urlencode({'email': request.user.email}))
    if not _user_requires_kyc(request.user):
        return _redirect_to_role_home_response(request.user)
    if request.session.pop('show_login_success', None):
        messages.success(request, 'Welcome back! You have been logged in successfully.')

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
        is_resubmission = bool(existing and existing.status == KYCRequest.STATUS_REJECTED)
        if not full_name:
            errors['full_name'] = 'Full name is required.'
        if not id_number:
            errors['id_number'] = 'ID number is required.'
        # On resubmission, allow keeping already-uploaded documents.
        if not id_document and not (is_resubmission and existing and existing.id_document):
            errors['id_document'] = 'ID document is required.'
        # Selfie is required for first-time submission, but optional on resubmission.
        if not selfie and not is_resubmission:
            errors['selfie'] = 'Selfie photo is required.'
        
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

                # Email copy for "KYC submitted/resubmitted" (user + admin).
                try:
                    create_notification(
                        request.user,
                        'KYC submitted',
                        'Your KYC verification has been submitted (resubmission) and is pending approval. You will receive an email after review (approved or rejected).',
                        reverse('kyc'),
                        UserNotification.TYPE_KYC,
                    )
                except Exception:
                    logging.getLogger(__name__).exception("Failed to send KYC resubmission email")
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

                    # Email copy for "KYC submitted" (user + admin).
                    try:
                        create_notification(
                            request.user,
                            'KYC submitted',
                            'Your KYC verification has been submitted and is pending approval. You will receive an email after review (approved or rejected).',
                            reverse('kyc'),
                            UserNotification.TYPE_KYC,
                        )
                    except Exception:
                        logging.getLogger(__name__).exception("Failed to send KYC submission email")
                else:
                    messages.error(request, 'An error occurred. Please contact support.')
            
            request.user.is_verified = False
            request.user.save(update_fields=['is_verified'])
            # Redirect to dashboard after KYC submit (pending approval); dashboard shows KYC status
            return _redirect_to_role_home_response(request.user)
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
    # Ensure profile exists for all users (including admin-created or legacy users)
    _ensure_role_profile(user)

    if user.role == 'farmer':
        profile, _ = FarmerProfile.objects.get_or_create(user=user)
        if request.method == 'POST':
            if 'update_photo' in request.POST:
                photo_file = request.FILES.get('photo')
                if photo_file:
                    profile.photo = photo_file
                    profile.save()
                    extra = {}
                    if profile.photo:
                        extra['photo_url'] = profile.photo.url
                    return _profile_finish(request, True, 'Profile picture updated successfully!', extra)
                return _profile_finish(request, False, 'Please select an image file.')
            elif 'update_profile' in request.POST:
                new_email = request.POST.get('email', '').strip()
                norm_email, email_err = _validate_profile_email_change(user, new_email)
                if email_err:
                    return _profile_finish(request, False, email_err, {'field_errors': {'email': email_err}})
                profile.name = request.POST.get('name', profile.name)
                profile.location = request.POST.get('location', profile.location)
                profile.contact = request.POST.get('contact', profile.contact)
                profile.farm_size = request.POST.get('farm_size', profile.farm_size)
                profile.crop_types = request.POST.get('crop_types', profile.crop_types)
                profile.livestock_details = request.POST.get('livestock_details', profile.livestock_details)
                profile.save()
                if norm_email != user.email:
                    user.email = norm_email
                    user.save()
                return _profile_finish(
                    request, True, 'Profile updated successfully.',
                    {'email': user.email},
                )
        context['profile'] = profile
        
    elif user.role == 'vendor':
        profile, _ = VendorProfile.objects.get_or_create(user=user)
        if request.method == 'POST':
            if 'update_photo' in request.POST:
                photo_file = request.FILES.get('photo')
                if photo_file:
                    profile.logo = photo_file
                    profile.save()
                    extra = {}
                    if profile.logo:
                        extra['photo_url'] = profile.logo.url
                    return _profile_finish(request, True, 'Profile picture updated successfully!', extra)
                return _profile_finish(request, False, 'Please select an image file.')
            elif 'update_profile' in request.POST:
                new_email = request.POST.get('email', '').strip()
                norm_email, email_err = _validate_profile_email_change(user, new_email)
                if email_err:
                    return _profile_finish(request, False, email_err, {'field_errors': {'email': email_err}})
                website = (request.POST.get('website') or '').strip() or None
                if website and not (website.startswith('http://') or website.startswith('https://')):
                    website = 'https://' + website
                profile.company_name = (request.POST.get('company_name') or profile.company_name or '').strip() or profile.company_name
                profile.address = (request.POST.get('address') or profile.address or '').strip() or profile.address
                profile.contact = (request.POST.get('contact') or profile.contact or '').strip() or profile.contact
                profile.website = website
                profile.business_type = (request.POST.get('business_type') or profile.business_type or '').strip() or profile.business_type
                profile.description = (request.POST.get('description') or profile.description or '').strip() or profile.description
                profile.save()
                if norm_email != user.email:
                    user.email = norm_email
                    user.save()
                return _profile_finish(
                    request, True, 'Profile updated successfully.',
                    {'email': user.email},
                )
        from .models import VendorTool
        context['profile'] = profile
        context['tools_count'] = VendorTool.objects.filter(vendor=profile).count()
        
    elif user.role == 'agricultural_expert':
        profile, _ = ExpertProfile.objects.get_or_create(user=user)
        if request.method == 'POST':
            if 'update_photo' in request.POST:
                photo_file = request.FILES.get('photo')
                if photo_file:
                    profile.photo = photo_file
                    profile.save()
                    extra = {}
                    if profile.photo:
                        extra['photo_url'] = profile.photo.url
                    return _profile_finish(request, True, 'Profile picture updated successfully!', extra)
                return _profile_finish(request, False, 'Please select an image file.')
            elif 'update_profile' in request.POST:
                new_email = request.POST.get('email', '').strip()
                norm_email, email_err = _validate_profile_email_change(user, new_email)
                if email_err:
                    return _profile_finish(request, False, email_err, {'field_errors': {'email': email_err}})
                profile.name = request.POST.get('name', profile.name)
                profile.specialization = request.POST.get('specialization', profile.specialization)
                profile.experience = request.POST.get('experience', profile.experience)
                profile.qualification = request.POST.get('qualifications', profile.qualification)
                profile.save()
                if norm_email != user.email:
                    user.email = norm_email
                    user.save()
                return _profile_finish(
                    request, True, 'Profile updated successfully.',
                    {'email': user.email},
                )
        context['profile'] = profile
        
    elif user.role == 'buyer':
        profile, _ = UserProfile.objects.get_or_create(user=user)
        if request.method == 'POST':
            if 'update_photo' in request.POST:
                photo_file = request.FILES.get('photo')
                if photo_file:
                    profile.photo = photo_file
                    profile.save()
                    extra = {}
                    if profile.photo:
                        extra['photo_url'] = profile.photo.url
                    return _profile_finish(request, True, 'Profile picture updated successfully!', extra)
                return _profile_finish(request, False, 'Please select an image file.')
            elif 'update_profile' in request.POST:
                new_email = request.POST.get('email', '').strip()
                norm_email, email_err = _validate_profile_email_change(user, new_email)
                if email_err:
                    return _profile_finish(request, False, email_err, {'field_errors': {'email': email_err}})
                profile.name = request.POST.get('name', profile.name)
                profile.phone = request.POST.get('contact', profile.phone)
                profile.address = request.POST.get('location', profile.address)
                profile.save()
                if norm_email != user.email:
                    user.email = norm_email
                    user.save()
                return _profile_finish(
                    request, True, 'Profile updated successfully.',
                    {'email': user.email},
                )
        context['profile'] = profile
    else:
        # Admin or unknown role: use UserProfile so profile is always editable
        profile, _ = UserProfile.objects.get_or_create(user=user)
        if request.method == 'POST':
            if 'update_photo' in request.POST:
                photo_file = request.FILES.get('photo')
                if photo_file:
                    profile.photo = photo_file
                    profile.save()
                    extra = {}
                    if profile.photo:
                        extra['photo_url'] = profile.photo.url
                    return _profile_finish(request, True, 'Profile picture updated successfully!', extra)
                return _profile_finish(request, False, 'Please select an image file.')
            elif 'update_profile' in request.POST:
                new_email = request.POST.get('email', '').strip()
                norm_email, email_err = _validate_profile_email_change(user, new_email)
                if email_err:
                    return _profile_finish(request, False, email_err, {'field_errors': {'email': email_err}})
                profile.name = request.POST.get('name', profile.name)
                profile.phone = request.POST.get('contact', profile.phone)
                profile.address = request.POST.get('location', profile.address)
                profile.save()
                if norm_email != user.email:
                    user.email = norm_email
                    user.save()
                return _profile_finish(
                    request, True, 'Profile updated successfully.',
                    {'email': user.email},
                )
        context['profile'] = profile

    context['role_display'] = (user.role or '').replace('_', ' ').title()
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

        def _finish(ok, msg, field_errors=None):
            if _farmity_wants_ajax(request):
                data = {'ok': ok, 'message': msg}
                if field_errors:
                    data['field_errors'] = field_errors
                return JsonResponse(data)
            if ok:
                messages.success(request, msg)
            else:
                messages.error(request, msg)
            return redirect('settings')

        if not current_password or not new_password or not confirm_password:
            return _finish(False, 'All fields are required!', {'current_password': 'Required.', 'new_password': 'Required.', 'confirm_password': 'Required.'})

        if not user.check_password(current_password):
            return _finish(False, 'Current password is incorrect!', {'current_password': 'Current password is incorrect.'})

        if new_password != confirm_password:
            return _finish(False, 'New passwords do not match!', {'confirm_password': 'Passwords do not match.'})

        if len(new_password) < 8:
            return _finish(False, 'Password must be at least 8 characters long!', {'new_password': 'Password must be at least 8 characters long.'})

        user.set_password(new_password)
        user.save()
        user = authenticate(username=user.email, password=new_password)
        if user:
            _login_user(request, user)
        return _finish(True, 'Password updated successfully!')
    return redirect('settings')


@login_required
def farmer_dashboard(request):
    if request.user.role != 'farmer':
        return _redirect_to_role_home_response(request.user)
    is_ajax = request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.POST.get('ajax') == '1'
    if request.session.pop('show_login_success', None):
        messages.success(request, 'Welcome back! You have been logged in successfully.')
    
    # Ensure profile exists
    profile, created = FarmerProfile.objects.get_or_create(user=request.user)
    
    # Check KYC status - prevent duplicate submissions
    kyc_request = request.user.kyc_requests.first()
    kyc_status = kyc_request.status if kyc_request else None
    
    # Only allow access if KYC is approved
    if kyc_status != 'approved':
        # Still show dashboard but with KYC alert
        pass
    
    # Handle Profile Photo (separate from profile details)
    if request.method == 'POST' and 'update_photo' in request.POST:
        photo_file = request.FILES.get('photo')
        if photo_file:
            profile.photo = photo_file
            profile.save()
            messages.success(request, 'Profile picture updated successfully!')
        else:
            messages.error(request, 'Please select an image file.')
        return _redirect_same_page(request, 'farmer_dashboard')

    # Handle Profile Update (details only; photo is changed separately)
    if request.method == 'POST' and 'update_profile' in request.POST:
        new_email = (request.POST.get('email') or '').strip()
        norm_email, email_err = _validate_profile_email_change(request.user, new_email)
        if email_err:
            if is_ajax:
                return _farmity_json_response(False, email_err, field_errors={'email': email_err})
            messages.error(request, email_err)
            return _redirect_same_page(request, 'farmer_dashboard')
        if 'name' in request.POST:
            profile.name = request.POST.get('name', profile.name) or profile.name
        if 'location' in request.POST:
            profile.location = request.POST.get('location', profile.location) or profile.location
        if 'contact' in request.POST:
            profile.contact = request.POST.get('contact', profile.contact) or profile.contact
        if 'farm_size' in request.POST:
            profile.farm_size = request.POST.get('farm_size', profile.farm_size) or profile.farm_size
        if 'crop_types' in request.POST:
            profile.crop_types = request.POST.get('crop_types', profile.crop_types) or profile.crop_types
        if 'livestock_details' in request.POST:
            profile.livestock_details = request.POST.get('livestock_details', profile.livestock_details) or profile.livestock_details
        profile.save()
        if norm_email != request.user.email:
            request.user.email = norm_email
            request.user.save(update_fields=['email'])
        if is_ajax:
            return _farmity_json_response(True, 'Profile updated successfully!', email=request.user.email)
        messages.success(request, 'Profile updated successfully!')
        return _redirect_same_page(request, 'farmer_dashboard')

    # Handle Add Product - Require KYC approval
    if request.method == 'POST' and 'add_product' in request.POST:
        if kyc_status != 'approved':
            messages.error(request, 'KYC verification is required to add crops. Please complete your KYC verification first.')
            return _redirect_same_page(request, 'farmer_dashboard')
        
        name = request.POST.get('product_name')
        quantity = request.POST.get('quantity')
        price = request.POST.get('price')
        if name and quantity and price:
            quantity_value = _to_decimal_or_none(quantity)
            if quantity_value is None or quantity_value < 0:
                messages.error(request, 'Please enter a valid crop quantity.')
                return _redirect_same_page(request, 'farmer_dashboard')
            product = FarmerProduct.objects.create(
                farmer=profile,
                name=name,
                quantity=quantity,
                price_per_unit=price,
                unit=request.POST.get('unit', 'kg'),
                is_available=quantity_value > 0
            )
            if request.FILES.get('product_image'):
                product.image = request.FILES.get('product_image')
                product.save()
            create_notification(
                request.user,
                'Crop listed',
                f'"{product.name}" is now available for buyers.',
                reverse('farmer_dashboard'),
                UserNotification.TYPE_ORDER
            )
            messages.success(request, 'Crop added successfully!')
        return _redirect_same_page(request, 'farmer_dashboard')

    # Handle Edit Product - Require KYC approval
    if request.method == 'POST' and 'edit_product' in request.POST:
        if kyc_status != 'approved':
            messages.error(request, 'KYC verification is required to edit crops. Please complete your KYC verification first.')
            return _redirect_same_page(request, 'farmer_dashboard')
        
        product_id = request.POST.get('product_id')
        try:
            product = FarmerProduct.objects.get(id=product_id, farmer=profile)
            quantity_raw = request.POST.get('quantity')
            quantity_value = _to_decimal_or_none(quantity_raw)
            if quantity_value is None or quantity_value < 0:
                messages.error(request, 'Please enter a valid crop quantity.')
                return _redirect_same_page(request, 'farmer_dashboard')
            product.name = request.POST.get('product_name')
            product.quantity = quantity_raw
            product.price_per_unit = request.POST.get('price')
            product.unit = request.POST.get('unit', 'kg')
            product.is_available = (request.POST.get('is_available') == 'on') and (quantity_value > 0)
            if request.FILES.get('product_image'):
                product.image = request.FILES.get('product_image')
            product.save()
            messages.success(request, 'Crop updated successfully!')
        except FarmerProduct.DoesNotExist:
            messages.error(request, 'Product not found!')
        return _redirect_same_page(request, 'farmer_dashboard')

    # Handle Delete Product - Require KYC approval
    if request.method == 'POST' and 'delete_product' in request.POST:
        if kyc_status != 'approved':
            messages.error(request, 'KYC verification is required to delete crops. Please complete your KYC verification first.')
            return _redirect_same_page(request, 'farmer_dashboard')
        
        product_id = request.POST.get('product_id')
        try:
            product = FarmerProduct.objects.get(id=product_id, farmer=profile)
            product.delete()
            messages.success(request, 'Crop deleted successfully!')
        except FarmerProduct.DoesNotExist:
            messages.error(request, 'Product not found!')
        return _redirect_same_page(request, 'farmer_dashboard')

    # Handle Tool Purchase - Require KYC approval for farmers
    if request.method == 'POST' and 'purchase_tool' in request.POST:
        if kyc_status != 'approved':
            messages.error(request, 'KYC verification is required to purchase tools. Please complete your KYC verification first.')
            return _redirect_same_page(request, 'farmer_dashboard')
        
        payment_method = request.POST.get('payment_method', Order.PAYMENT_COD)
        tool_id = request.POST.get('tool_id')
        quantity = int(request.POST.get('quantity', 1))
        shipping_address = request.POST.get('shipping_address', '')
        contact_number = (request.POST.get('contact_number') or '').strip()
        order_email = (request.POST.get('order_email') or '').strip() or None
        notes = request.POST.get('notes', '')
        total_amount = request.POST.get('total_amount')
        if not contact_number:
            messages.error(request, 'Contact number is required.')
            return _redirect_same_page(request, 'farmer_dashboard')
        try:
            tool = VendorTool.objects.get(id=tool_id, is_available=True)
            if tool.stock_quantity >= quantity:
                if not total_amount:
                    base_amount = tool.price * quantity
                else:
                    # Ignore any client-provided total; parse safely if present.
                    base_amount = _to_decimal_or_none(total_amount) or (tool.price * quantity)
                shipping_cost = Decimal('100.00')
                total_amount = (Decimal(str(base_amount)) + shipping_cost).quantize(Decimal('0.01'))
                admin_commission, seller_amount = Order.compute_commission(total_amount, shipping_cost, product_type='tool')
                # Create order with payment method
                order = Order.objects.create(
                    buyer=request.user,
                    tool=tool,
                    quantity=quantity,
                    total_amount=total_amount,
                    shipping_cost=shipping_cost,
                    admin_commission=admin_commission,
                    seller_amount=seller_amount,
                    status=Order.STATUS_CONFIRMED,
                    payment_method=payment_method,
                    payment_status='pending',
                    shipping_address=shipping_address,
                    contact_number=contact_number,
                    order_email=order_email,
                    notes=notes
                )
                
                if payment_method != Order.PAYMENT_ESEWA:
                    # Update stock immediately for COD
                    tool.stock_quantity -= quantity
                    if tool.stock_quantity == 0:
                        tool.is_available = False
                    tool.save()
                    order.inventory_deducted = True
                    order.save(update_fields=['inventory_deducted'])
                vendor_user = getattr(tool.vendor, 'user', None)
                if vendor_user:
                    create_notification(
                        vendor_user,
                        'New tool order',
                        f'Order #{order.id}: {tool.name} x{quantity} — Rs. {total_amount:.2f} (incl. shipping)',
                        reverse('vendor_dashboard'),
                        UserNotification.TYPE_ORDER
                    )
                create_notification(
                    request.user,
                    'Order placed',
                    f'Order #{order.id}: {tool.name} x{quantity} — Rs. {total_amount:.2f} (incl. shipping)',
                    reverse('farmer_dashboard') + '?section=tools',
                    UserNotification.TYPE_ORDER
                )
                if payment_method == Order.PAYMENT_ESEWA:
                    return redirect(reverse('esewa_initiate') + f'?order_id={order.id}')
                messages.success(request, f'Order successfully placed! You will pay Rs. {total_amount:.2f} on delivery.')
            else:
                messages.error(request, 'Insufficient stock!')
        except VendorTool.DoesNotExist:
            messages.error(request, 'Tool not found!')
        except Exception as e:
            messages.error(request, f'An error occurred: {str(e)}')
        return _redirect_same_page(request, 'farmer_dashboard')

    # Handle Tools Cart Checkout (multiple different tools in one go)
    if request.method == 'POST' and 'checkout_tools_cart' in request.POST:
        if kyc_status != 'approved':
            messages.error(request, 'KYC verification is required to purchase tools. Please complete your KYC verification first.')
            return _redirect_same_page(request, 'farmer_dashboard')
        cart_json = request.POST.get('cart_items', '[]')
        try:
            cart_items = json.loads(cart_json)
        except (ValueError, TypeError):
            messages.error(request, 'Invalid cart data. Please try again.')
            return _redirect_same_page(request, 'farmer_dashboard')
        if not cart_items:
            messages.error(request, 'Your tools cart is empty.')
            return _redirect_same_page(request, 'farmer_dashboard')
        payment_method = request.POST.get('payment_method', Order.PAYMENT_COD)
        shipping_address = (request.POST.get('shipping_address') or '').strip()
        contact_number = (request.POST.get('contact_number') or '').strip()
        order_email = (request.POST.get('order_email') or '').strip() or None
        notes = (request.POST.get('notes') or '').strip()
        if not shipping_address:
            messages.error(request, 'Shipping address is required.')
            return _redirect_same_page(request, 'farmer_dashboard')
        if not contact_number:
            messages.error(request, 'Contact number is required.')
            return _redirect_same_page(request, 'farmer_dashboard')
        errors = []
        orders_created = []
        for item in cart_items:
            if (item.get('type') or '').lower() != 'tool':
                continue
            item_id = item.get('id')
            try:
                qty = int(item.get('quantity', 1))
            except (ValueError, TypeError):
                errors.append(f"Invalid quantity for {item.get('name', item_id)}")
                continue
            if qty <= 0:
                continue
            try:
                tool = VendorTool.objects.get(id=item_id, is_available=True, stock_quantity__gt=0)
                if tool.stock_quantity < qty:
                    errors.append(f"{tool.name}: only {tool.stock_quantity} units available")
                    continue
                base_amount = (Decimal(str(tool.price)) * Decimal(str(qty))).quantize(Decimal('0.01'))
                shipping_cost = Decimal('100.00')
                total_amount = (base_amount + shipping_cost).quantize(Decimal('0.01'))
                admin_commission, seller_amount = Order.compute_commission(total_amount, shipping_cost, product_type='tool')
                order = Order.objects.create(
                    buyer=request.user,
                    tool=tool,
                    quantity=qty,
                    total_amount=total_amount,
                    shipping_cost=shipping_cost,
                    admin_commission=admin_commission,
                    seller_amount=seller_amount,
                    status=Order.STATUS_CONFIRMED,
                    payment_method=payment_method,
                    payment_status='pending',
                    shipping_address=shipping_address,
                    contact_number=contact_number,
                    order_email=order_email,
                    notes=notes
                )
                if payment_method != Order.PAYMENT_ESEWA:
                    tool.stock_quantity -= qty
                    if tool.stock_quantity == 0:
                        tool.is_available = False
                    tool.save()
                    order.inventory_deducted = True
                    order.save(update_fields=['inventory_deducted'])
                vendor_user = getattr(tool.vendor, 'user', None)
                if vendor_user:
                    create_notification(
                        vendor_user,
                        'New tool order',
                        f'Order #{order.id}: {tool.name} x{qty} — Rs. {total_amount:.2f} (incl. shipping)',
                        reverse('vendor_dashboard'),
                        UserNotification.TYPE_ORDER
                    )
                create_notification(
                    request.user,
                    'Order placed',
                    f'Order #{order.id}: {tool.name} x{qty} — Rs. {total_amount:.2f} (incl. shipping)',
                    reverse('farmer_dashboard') + '?section=tools',
                    UserNotification.TYPE_ORDER
                )
                orders_created.append(order)
            except VendorTool.DoesNotExist:
                errors.append(f"Tool (id {item_id}) no longer available")
        if errors:
            for err in errors[:5]:
                messages.error(request, err)
            if len(errors) > 5:
                messages.error(request, f"... and {len(errors) - 5} more issues.")
            return _redirect_same_page(request, 'farmer_dashboard')
        if not orders_created:
            messages.error(request, 'No valid items in cart.')
            return _redirect_same_page(request, 'farmer_dashboard')
        grand_total = sum(float(o.total_amount) for o in orders_created)
        if payment_method == Order.PAYMENT_ESEWA:
            request.session['esewa_pending_order_ids'] = [o.id for o in orders_created]
            request.session['esewa_redirect_after'] = 'farmer_dashboard'
            request.session.modified = True
            return redirect(reverse('esewa_initiate'))
        messages.success(request, f'Order placed for {len(orders_created)} tool(s)! Total: Rs. {grand_total:.2f} (Cash on Delivery).')
        from urllib.parse import urlencode
        params = {'checkout_success': '1', 'section': (request.POST.get('return_section') or 'tools').strip()}
        return redirect(reverse('farmer_dashboard') + '?' + urlencode(params))

    # Handle farmer order status update (crop orders only)
    if request.method == 'POST' and request.POST.get('update_order_status'):
        order_id = request.POST.get('order_id')
        new_status = (request.POST.get('status') or '').strip()
        allowed = (
            Order.STATUS_CONFIRMED,
            Order.STATUS_READY_TO_SHIP,
            Order.STATUS_SHIPPED,
            Order.STATUS_ON_THE_WAY,
            Order.STATUS_DELIVERED,
            Order.STATUS_CANCELLED,
        )
        try:
            order_id = int(order_id) if order_id else None
        except (TypeError, ValueError):
            order_id = None
        if order_id and new_status in allowed:
            try:
                order = Order.objects.select_related('crop', 'crop__farmer', 'buyer').get(
                    id=order_id, crop__farmer=profile
                )
                order.status = new_status
                order.save(update_fields=['status'])
                notify_statuses = {
                    Order.STATUS_READY_TO_SHIP,
                    Order.STATUS_SHIPPED,
                    Order.STATUS_ON_THE_WAY,
                    Order.STATUS_DELIVERED,
                    Order.STATUS_CANCELLED,
                }
                if order.buyer and new_status in notify_statuses:
                    try:
                        status_label = order.get_status_display()
                        item_name = (order.crop.name if order.crop else 'item') or 'item'
                        create_notification(
                            order.buyer,
                            'Order %s %s' % (order.id, status_label.lower()),
                            'Your order for %s is now %s.' % (item_name, status_label.lower()),
                            reverse('user_dashboard') + '?section=orders',
                            UserNotification.TYPE_ORDER
                        )
                    except Exception:
                        pass  # don't fail the update if notification fails
                messages.success(request, 'Order #%s status updated to %s.' % (order_id, order.get_status_display()))
            except Order.DoesNotExist:
                messages.error(request, 'Order not found.')
        else:
            messages.error(request, 'Invalid status update. Please select a status and try again.')
        return _redirect_same_page(request, 'farmer_dashboard')

    # Get products
    products = FarmerProduct.objects.filter(farmer=profile).order_by('-created_at')
    
    # Calculate statistics (Order, CropSale from top-level imports)
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
    
    # Expert available dates (expert_id -> list of date strings) for highlighting in booking modal
    today = timezone.now().date()
    expert_availability = {}
    for expert in experts:
        dates = list(
            ExpertAvailability.objects.filter(expert=expert, date__gte=today)
            .order_by('date').values_list('date', flat=True)
        )
        expert_availability[expert.id] = [d.isoformat() for d in dates]
    expert_availability_json = json.dumps(expert_availability)
    
    # Get farming tips
    tips = FarmingTip.objects.filter(is_published=True, approval_status=FarmingTip.APPROVAL_APPROVED).select_related('expert', 'expert__user').order_by('-created_at')[:10]
    
    # Get appointments
    appointments = ExpertAppointment.objects.filter(requester=request.user).select_related('expert', 'expert__user').order_by('-created_at')

    # Handle update appointment (change date/time) - requester only, pending only
    if request.method == 'POST' and 'update_appointment' in request.POST:
        appointment_id = request.POST.get('appointment_id')
        requested_date = (request.POST.get('requested_date') or '').strip()
        requested_time = (request.POST.get('requested_time') or '').strip()

        success = False
        out_message = ''
        payload = {}

        if appointment_id and requested_date and requested_time:
            try:
                req_date = date.fromisoformat(requested_date)
            except (ValueError, TypeError):
                req_date = None
            try:
                appointment = ExpertAppointment.objects.get(id=appointment_id, requester=request.user)
                if appointment.status != ExpertAppointment.STATUS_PENDING:
                    out_message = 'Only pending appointments can be rescheduled. Accepted appointments cannot be changed.'
                elif not req_date:
                    out_message = 'Invalid date format.'
                elif not ExpertAvailability.objects.filter(expert=appointment.expert, date=req_date).exists():
                    out_message = 'Appointment not available at this date. Please choose an available date.'
                else:
                    appointment.requested_date = requested_date
                    appointment.requested_time = requested_time
                    appointment.save()
                    success = True
                    out_message = 'Appointment date/time updated successfully.'
                    try:
                        time_display = appointment.requested_time.strftime('%I:%M %p') if appointment.requested_time else requested_time
                    except Exception:
                        time_display = requested_time

                    # Notify expert so they can review the updated pending appointment.
                    try:
                        create_notification(
                            appointment.expert.user,
                            'Appointment updated',
                            f'{request.user.email} updated an appointment request to {req_date.strftime("%b %d, %Y") if req_date else requested_date} at {time_display}.',
                            reverse('expert_dashboard') + '?section=appointments',
                            UserNotification.TYPE_APPOINTMENT,
                        )
                    except Exception:
                        logging.getLogger(__name__).exception("Failed to send appointment update email")
                    payload = {
                        'appointment_id': appointment.id,
                        'requested_date_iso': requested_date,
                        'requested_date_display': req_date.strftime('%b %d, %Y') if req_date else requested_date,
                        'requested_time_display': time_display,
                        'status': appointment.status,
                        'status_display': appointment.get_status_display(),
                    }
            except ExpertAppointment.DoesNotExist:
                out_message = 'Appointment not found.'
        else:
            out_message = 'Please provide date and time.'

        if is_ajax:
            status_code = 200 if success else 400
            return JsonResponse({'success': success, 'message': out_message, 'data': payload}, status=status_code)

        if success:
            messages.success(request, out_message)
        elif out_message:
            messages.error(request, out_message)
        return _redirect_same_page(request, 'farmer_dashboard')

    # Handle reapply (rejected appointment: edit and apply again)
    if request.method == 'POST' and 'reapply_appointment' in request.POST:
        appointment_id = request.POST.get('appointment_id')
        requested_date = (request.POST.get('requested_date') or '').strip()
        requested_time = (request.POST.get('requested_time') or '').strip()

        success = False
        out_message = ''
        payload = {}

        if appointment_id and requested_date and requested_time:
            try:
                req_date = date.fromisoformat(requested_date)
            except (ValueError, TypeError):
                req_date = None
            try:
                appointment = ExpertAppointment.objects.get(id=appointment_id, requester=request.user)
                if appointment.status != ExpertAppointment.STATUS_REJECTED:
                    out_message = 'Only rejected appointments can be reapplied.'
                elif not req_date:
                    out_message = 'Invalid date format.'
                elif not ExpertAvailability.objects.filter(expert=appointment.expert, date=req_date).exists():
                    out_message = 'Appointment not available at this date. Please choose an available date.'
                else:
                    appointment.requested_date = requested_date
                    appointment.requested_time = requested_time
                    appointment.status = ExpertAppointment.STATUS_PENDING
                    appointment.response_message = None  # fresh request for doctor
                    appointment.save()
                    success = True
                    out_message = 'Appointment updated and resubmitted. The doctor will review your new request.'
                    try:
                        time_display = appointment.requested_time.strftime('%I:%M %p') if appointment.requested_time else requested_time
                    except Exception:
                        time_display = requested_time

                    # Notify expert so they know about the resubmitted appointment.
                    try:
                        create_notification(
                            appointment.expert.user,
                            'Appointment resubmitted',
                            f'{request.user.email} resubmitted a pending appointment for {req_date.strftime("%b %d, %Y") if req_date else requested_date} at {time_display}.',
                            reverse('expert_dashboard') + '?section=appointments',
                            UserNotification.TYPE_APPOINTMENT,
                        )
                    except Exception:
                        logging.getLogger(__name__).exception("Failed to send appointment resubmission email")
                    payload = {
                        'appointment_id': appointment.id,
                        'requested_date_iso': requested_date,
                        'requested_date_display': req_date.strftime('%b %d, %Y') if req_date else requested_date,
                        'requested_time_display': time_display,
                        'status': appointment.status,
                        'status_display': appointment.get_status_display(),
                    }
            except ExpertAppointment.DoesNotExist:
                out_message = 'Appointment not found.'
        else:
            out_message = 'Please provide date and time.'

        if is_ajax:
            status_code = 200 if success else 400
            return JsonResponse({'success': success, 'message': out_message, 'data': payload}, status=status_code)

        if success:
            messages.success(request, out_message)
        elif out_message:
            messages.error(request, out_message)
        return _redirect_same_page(request, 'farmer_dashboard')
    
    # Get chat threads
    chat_threads = ExpertChatThread.objects.filter(created_by=request.user).select_related('expert', 'expert__user').order_by('-created_at')[:5]
    
    # Get available tools from vendors
    available_tools = VendorTool.objects.filter(is_available=True, stock_quantity__gt=0).select_related('vendor', 'vendor__user').order_by('-created_at')[:12]
    
    # Orders placed by buyers for THIS farmer's crops (shipping handled by admin)
    farmer_orders = Order.objects.filter(crop__farmer=profile).select_related('buyer', 'crop').order_by('-created_at')[:30]
    # Farmer's own orders (as buyer): tools from vendors or crops from other farmers
    farmer_my_orders = Order.objects.filter(buyer=request.user).select_related(
        'tool', 'tool__vendor', 'tool__vendor__user', 'crop', 'crop__farmer', 'crop__farmer__user'
    ).order_by('-created_at')[:50]
    purchase_history = farmer_my_orders[:10]  # kept for any existing use

    # Farmer earnings / payout stats (crop orders where payment collected)
    farmer_crop_orders = Order.objects.filter(crop__farmer=profile)
    farmer_collected = farmer_crop_orders.filter(payment_status=Order.PAYMENT_STATUS_COMPLETED)
    
    # For Mainali Tools and Technology vendor, check if they have actual sales
    mainali_orders = farmer_collected.filter(tool__vendor__user__email='np05cp4s240077@iic.edu.np')
    mainali_has_sales = mainali_orders.filter(tool__isnull=False).exists()
    
    if not mainali_has_sales:
        # Exclude Mainali Tools and Technology vendor if no actual sales
        farmer_collected = farmer_collected.exclude(tool__vendor__user__email='np05cp4s240077@iic.edu.np')
    # If they have sales, include them automatically
    farmer_amount_collected = farmer_collected.aggregate(total=Sum('seller_amount'))['total'] or farmer_collected.aggregate(total=Sum('total_amount'))['total'] or Decimal('0')
    farmer_pending_q = Q(payout_status__isnull=True) | Q(payout_status=Order.PAYOUT_PENDING)
    farmer_pending_release = farmer_collected.filter(farmer_pending_q).aggregate(total=Sum('seller_amount'))['total'] or farmer_collected.filter(farmer_pending_q).aggregate(total=Sum('total_amount'))['total'] or Decimal('0')
    farmer_paid = farmer_collected.filter(payout_status=Order.PAYOUT_PAID).order_by('-payout_at')
    farmer_released_payouts = list(
        farmer_paid.annotate(payout_date=TruncDate('payout_at'))
        .values('payout_date')
        .annotate(amount=Sum('seller_amount'), order_count=Count('id'))
        .order_by('-payout_date')
    )
    farmer_total_released = sum((p['amount'] or Decimal('0')) for p in farmer_released_payouts)
    # Farmer spend (tool orders where they are buyer, payment completed)
    farmer_spend_orders = Order.objects.filter(buyer=request.user, tool__isnull=False)
    farmer_total_spend = farmer_spend_orders.filter(payment_status=Order.PAYMENT_STATUS_COMPLETED).aggregate(
        total=Sum('total_amount')
    )['total'] or Decimal('0')
    farmer_sale_transactions = Order.objects.filter(crop__farmer=profile).select_related(
        'buyer', 'crop'
    ).order_by('-created_at')[:200]
    farmer_purchase_transactions = Order.objects.filter(buyer=request.user).select_related(
        'tool', 'tool__vendor', 'tool__vendor__user', 'crop', 'crop__farmer', 'crop__farmer__user'
    ).order_by('-created_at')[:200]

    # Determine if features should be restricted
    features_restricted = (kyc_status != 'approved')
    
    active_section = (request.GET.get('section') or 'dashboard').strip()
    context = {
        'profile': profile,
        'products': products,
        'experts': experts,
        'expert_availability': expert_availability,
        'expert_availability_json': expert_availability_json,
        'tips': tips,
        'appointments': appointments,
        'chat_threads': chat_threads,
        'kyc_request': kyc_request,
        'kyc_status': kyc_status,
        'features_restricted': features_restricted,
        'products_count': products.count(),
        'active_section': active_section,
        # Statistics
        'total_crops_added': total_crops_added,
        'total_crops_sold': float(total_crops_sold),
        'total_earnings': float(total_earnings),
        'active_listings': active_listings,
        'sales_data': sales_data_json,
        # Tools and orders
        'available_tools': available_tools,
        'purchase_history': purchase_history,
        'farmer_orders': farmer_orders,
        'farmer_my_orders': farmer_my_orders,
        'role_display': (request.user.role or '').replace('_', ' ').title(),
        # Earnings tab
        'farmer_amount_collected': farmer_amount_collected,
        'farmer_pending_release': farmer_pending_release,
        'farmer_total_released': farmer_total_released,
        'farmer_total_spend': farmer_total_spend,
        'farmer_released_payouts': farmer_released_payouts,
        'farmer_sale_transactions': farmer_sale_transactions,
        'farmer_purchase_transactions': farmer_purchase_transactions,
    }
    return render(request, 'farmer_dashboard.html', context)


@login_required
def vendor_dashboard(request):
    if request.user.role != 'vendor':
        return _redirect_to_role_home_response(request.user)
    is_ajax = request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.POST.get('ajax') == '1'
    if request.session.pop('show_login_success', None):
        messages.success(request, 'Welcome back! You have been logged in successfully.')
    
    # Ensure profile exists
    profile, created = VendorProfile.objects.get_or_create(user=request.user)
    
    # Check KYC status
    kyc_request = request.user.kyc_requests.first()
    kyc_status = kyc_request.status if kyc_request else None
    
    # Handle photo-only update (Change Logo in view mode)
    if request.method == 'POST' and 'update_photo' in request.POST:
        photo_file = request.FILES.get('photo')
        if photo_file:
            profile.logo = photo_file
            profile.save()
            messages.success(request, 'Logo updated successfully!')
        return _redirect_same_page(request, 'vendor_dashboard')
    
    # Handle Profile Update
    if request.method == 'POST' and 'update_profile' in request.POST:
        new_email = (request.POST.get('email') or '').strip()
        norm_email, email_err = _validate_profile_email_change(request.user, new_email)
        if email_err:
            if is_ajax:
                return _farmity_json_response(False, email_err, field_errors={'email': email_err})
            messages.error(request, email_err)
            return _redirect_same_page(request, 'vendor_dashboard')
        profile.company_name = (request.POST.get('company_name') or '').strip() or profile.company_name
        profile.address = (request.POST.get('address') or '').strip() or profile.address
        profile.contact = (request.POST.get('contact') or '').strip() or profile.contact
        website = (request.POST.get('website') or '').strip() or None
        if website and not (website.startswith('http://') or website.startswith('https://')):
            website = 'https://' + website
        profile.website = website
        profile.business_type = (request.POST.get('business_type') or '').strip() or profile.business_type
        if request.FILES.get('photo'):
            profile.logo = request.FILES.get('photo')
        profile.save()
        if norm_email != request.user.email:
            request.user.email = norm_email
            request.user.save(update_fields=['email'])
        if is_ajax:
            return _farmity_json_response(True, 'Profile updated successfully!', email=request.user.email)
        messages.success(request, 'Profile updated successfully!')
        return _redirect_same_page(request, 'vendor_dashboard')
    
    # Handle Add Tool - Require KYC approval
    if request.method == 'POST' and 'add_tool' in request.POST:
        if kyc_status != 'approved':
            messages.error(request, 'KYC verification is required to add tools. Please complete your KYC verification first.')
            return _redirect_same_page(request, 'vendor_dashboard')
        
        name = request.POST.get('name')
        description = request.POST.get('description')
        price = request.POST.get('price')
        stock = request.POST.get('stock')
        is_available = request.POST.get('is_available') == 'on'
        
        if name and price and stock:
            try:
                stock_value = int(stock)
            except (TypeError, ValueError):
                messages.error(request, 'Please enter a valid tool stock quantity.')
                return _redirect_same_page(request, 'vendor_dashboard')
            if stock_value < 0:
                messages.error(request, 'Stock quantity cannot be negative.')
                return _redirect_same_page(request, 'vendor_dashboard')
            tool = VendorTool.objects.create(
                vendor=profile,
                name=name,
                description=description,
                price=price,
                stock_quantity=stock_value,
                is_available=is_available and stock_value > 0
            )
            if request.FILES.get('image'):
                tool.image = request.FILES.get('image')
                tool.save()
            create_notification(
                request.user,
                'Tool added',
                f'"{tool.name}" has been listed. Buyers can now order it.',
                reverse('vendor_dashboard'),
                UserNotification.TYPE_ORDER
            )
            messages.success(request, 'Tool added successfully!')
        return _redirect_same_page(request, 'vendor_dashboard')
    
    # Handle Edit Tool - Require KYC approval
    if request.method == 'POST' and 'edit_tool' in request.POST:
        if kyc_status != 'approved':
            messages.error(request, 'KYC verification is required to edit tools. Please complete your KYC verification first.')
            return _redirect_same_page(request, 'vendor_dashboard')
        
        tool_id = request.POST.get('tool_id')
        try:
            tool = VendorTool.objects.get(id=tool_id, vendor=profile)
            stock_raw = request.POST.get('stock', 0)
            try:
                stock_value = int(stock_raw)
            except (TypeError, ValueError):
                messages.error(request, 'Please enter a valid tool stock quantity.')
                return _redirect_same_page(request, 'vendor_dashboard')
            if stock_value < 0:
                messages.error(request, 'Stock quantity cannot be negative.')
                return _redirect_same_page(request, 'vendor_dashboard')
            tool.name = request.POST.get('name')
            tool.description = request.POST.get('description')
            tool.price = request.POST.get('price')
            tool.stock_quantity = stock_value
            tool.is_available = (request.POST.get('is_available') == 'on') and (stock_value > 0)
            if request.FILES.get('image'):
                tool.image = request.FILES.get('image')
            tool.save()
            messages.success(request, 'Tool updated successfully!')
        except VendorTool.DoesNotExist:
            messages.error(request, 'Tool not found!')
        return _redirect_same_page(request, 'vendor_dashboard')
    
    # Handle Delete Tool - Require KYC approval
    if request.method == 'POST' and 'delete_tool' in request.POST:
        if kyc_status != 'approved':
            messages.error(request, 'KYC verification is required to delete tools. Please complete your KYC verification first.')
            return _redirect_same_page(request, 'vendor_dashboard')
        
        tool_id = request.POST.get('tool_id')
        try:
            tool = VendorTool.objects.get(id=tool_id, vendor=profile)
            tool.delete()
            messages.success(request, 'Tool deleted successfully!')
        except VendorTool.DoesNotExist:
            messages.error(request, 'Tool not found!')
        return _redirect_same_page(request, 'vendor_dashboard')
    
    # Handle Order Status Update
    if request.method == 'POST' and 'update_order_status' in request.POST:
        if kyc_status != 'approved':
            messages.error(request, 'KYC verification is required to manage orders. Please complete your KYC verification first.')
            return _redirect_same_page(request, 'vendor_dashboard')
        
        order_id = request.POST.get('order_id')
        new_status = request.POST.get('status')
        tracking_number = request.POST.get('tracking_number', '').strip()
        
        try:
            order = Order.objects.get(id=order_id, tool__vendor=profile)
            order.status = new_status
            if tracking_number:
                order.tracking_number = tracking_number
            order.save()
            # Notify buyer when order is on the way / delivered (and cancelled too).
            notify_statuses = {
                Order.STATUS_READY_TO_SHIP,
                Order.STATUS_SHIPPED,
                Order.STATUS_ON_THE_WAY,
                Order.STATUS_DELIVERED,
                Order.STATUS_CANCELLED,
            }
            if order.buyer and new_status in notify_statuses:
                status_label = order.get_status_display()
                create_notification(
                    order.buyer,
                    f'Order #{order.id} {status_label.lower()}',
                    f'Your order for {order.tool.name if order.tool else "item"} is now {status_label.lower()}.'
                    + (f' Tracking: {tracking_number}' if tracking_number else ''),
                    reverse('user_dashboard') + '?section=orders',
                    UserNotification.TYPE_ORDER
                )
            messages.success(request, f'Order #{order_id} status updated to {order.get_status_display()}')
        except Order.DoesNotExist:
            messages.error(request, 'Order not found!')
        return _redirect_same_page(request, 'vendor_dashboard')
    
    # Get vendor tools
    tools = VendorTool.objects.filter(vendor=profile).order_by('-created_at')
    
    # Get orders for vendor's tools
    orders = Order.objects.filter(tool__vendor=profile).select_related('buyer', 'tool').order_by('-created_at')
    vendor_transactions = orders[:200]
    
    # Orders where payment is collected (completed) — used for payout stats
    collected_orders = orders.filter(payment_status=Order.PAYMENT_STATUS_COMPLETED)
    # For Mainali Tools and Technology vendor, check if they have actual sales
    if request.user.email == 'np05cp4s240077@iic.edu.np':
        # Only include collected amount if they have actual tool sales
        actual_sales = collected_orders.filter(tool__isnull=False).exists()
        if not actual_sales:
            collected_orders = collected_orders.none()  # No actual sales, set to zero
        # If they have sales, use the real collected amount
    amount_collected = collected_orders.aggregate(total=Sum('seller_amount'))['total'] or collected_orders.aggregate(total=Sum('total_amount'))['total'] or Decimal('0')
    pending_payout_q = Q(payout_status__isnull=True) | Q(payout_status=Order.PAYOUT_PENDING)
    pending_release_amount = collected_orders.filter(pending_payout_q).aggregate(total=Sum('seller_amount'))['total'] or collected_orders.filter(pending_payout_q).aggregate(total=Sum('total_amount'))['total'] or Decimal('0')
    # Released payouts: when admin marked as paid (group by payout_at for each release batch)
    paid_orders = collected_orders.filter(payout_status=Order.PAYOUT_PAID).order_by('-payout_at')
    released_payouts = list(
        paid_orders.annotate(payout_date=TruncDate('payout_at'))
        .values('payout_date')
        .annotate(amount=Sum('seller_amount'), order_count=Count('id'))
        .order_by('-payout_date')
    )
    total_released_amount = sum((p['amount'] or Decimal('0')) for p in released_payouts)
    previous_released = getattr(profile, 'previous_released_amount', None) or Decimal('0')
    
    # For Mainali Tools and Technology vendor, set previous released to zero since they have no sales
    if request.user.email == 'np05cp4s240077@iic.edu.np':
        previous_released = Decimal('0')
    
    total_received = total_released_amount + previous_released
    # Total amount collect (sales + previous release by admin, for Earnings card)
    total_amount_collect = amount_collected + previous_released
    total_orders_received = collected_orders.count()
    
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
        'active_section': (request.GET.get('section') or 'dashboard').strip(),
        # Payout / amount collected (payment-completed orders only)
        'amount_collected': amount_collected,
        'pending_release_amount': pending_release_amount,
        'total_released_amount': total_released_amount,
        'total_received': total_received,
        'previous_released_amount': previous_released,
        'total_amount_collect': total_amount_collect,
        'total_orders_received': total_orders_received,
        'released_payouts': released_payouts,
        'vendor_transactions': vendor_transactions,
    }
    return render(request, 'vendor_dashboard.html', context)


@login_required
def expert_dashboard(request):
    if request.user.role != 'agricultural_expert':
        return _redirect_to_role_home_response(request.user)
    if request.session.pop('show_login_success', None):
        messages.success(request, 'Welcome back! You have been logged in successfully.')
    
    is_ajax = request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.POST.get('ajax') == '1'

    def _expert_finish(ok, msg, **extra):
        if is_ajax:
            return _farmity_json_response(ok, msg, **extra)
        if ok:
            messages.success(request, msg)
        else:
            messages.error(request, msg)
        return _redirect_same_page(request, 'expert_dashboard')

    # Ensure profile exists
    profile, created = ExpertProfile.objects.get_or_create(user=request.user)
    
    # Check KYC status
    kyc_request = request.user.kyc_requests.first()
    kyc_status = kyc_request.status if kyc_request else None
    
    # Handle Profile Photo (separate from profile details)
    if request.method == 'POST' and 'update_photo' in request.POST:
        photo_file = request.FILES.get('photo')
        if photo_file:
            profile.photo = photo_file
            profile.save()
            extra = {}
            if profile.photo:
                extra['photo_url'] = profile.photo.url
            return _expert_finish(True, 'Profile picture updated successfully!', **extra)
        return _expert_finish(False, 'Please select an image file.')

    # Handle Profile Update (details only; photo is changed separately)
    if request.method == 'POST' and 'update_profile' in request.POST:
        new_email = (request.POST.get('email') or '').strip()
        norm_email, email_err = _validate_profile_email_change(request.user, new_email)
        if email_err:
            return _expert_finish(False, email_err, field_errors={'email': email_err})
        profile.name = request.POST.get('name', profile.name)
        profile.qualification = request.POST.get('qualification', profile.qualification)
        profile.specialization = request.POST.get('specialization', profile.specialization)
        profile.experience = request.POST.get('experience', profile.experience)
        try:
            fee_val = request.POST.get('consultation_fee', '')
            profile.consultation_fee = Decimal(fee_val) if fee_val != '' and fee_val is not None else Decimal('0')
            if profile.consultation_fee < 0:
                profile.consultation_fee = Decimal('0')
        except (ValueError, TypeError, InvalidOperation):
            profile.consultation_fee = Decimal('0')
        profile.save()
        if norm_email != request.user.email:
            request.user.email = norm_email
            request.user.save(update_fields=['email'])
        return _expert_finish(True, 'Profile updated successfully!', email=request.user.email)
    
    # Handle Add Tip/Content - Require KYC approval
    if request.method == 'POST' and 'add_tip' in request.POST:
        if kyc_status != 'approved':
            messages.error(request, 'KYC verification is required to upload content. Please complete your KYC verification first.')
            return _redirect_same_page(request, 'expert_dashboard')
        
        title = request.POST.get('title')
        content = request.POST.get('content')
        
        if title and content:
            tip = FarmingTip.objects.create(
                expert=profile,
                title=title,
                content=content,
                is_published=False,
                approval_status=FarmingTip.APPROVAL_PENDING
            )
            if request.FILES.get('image'):
                tip.image = request.FILES.get('image')
                tip.save()
            messages.success(request, 'Content submitted for admin approval. It will be visible to users once approved.')
        return _redirect_same_page(request, 'expert_dashboard')
    
    # Handle Edit Tip - Require KYC approval
    if request.method == 'POST' and 'edit_tip' in request.POST:
        if kyc_status != 'approved':
            messages.error(request, 'KYC verification is required to edit content. Please complete your KYC verification first.')
            return _redirect_same_page(request, 'expert_dashboard')
        
        tip_id = request.POST.get('tip_id')
        try:
            tip = FarmingTip.objects.get(id=tip_id, expert=profile)
            tip.title = request.POST.get('title')
            tip.content = request.POST.get('content')
            if request.FILES.get('image'):
                tip.image = request.FILES.get('image')
            # If content was approved, editing sends it back to pending for re-approval
            if tip.approval_status == FarmingTip.APPROVAL_APPROVED:
                tip.approval_status = FarmingTip.APPROVAL_PENDING
                tip.is_published = False
                tip.save()
                messages.success(request, 'Content updated and submitted for admin approval again. It will be visible to users once approved.')
            else:
                tip.save()
                messages.success(request, 'Content updated successfully!')
        except FarmingTip.DoesNotExist:
            messages.error(request, 'Content not found!')
        return _redirect_same_page(request, 'expert_dashboard')
    
    # Handle Delete Tip - Require KYC approval
    if request.method == 'POST' and 'delete_tip' in request.POST:
        if kyc_status != 'approved':
            msg = 'KYC verification is required to delete content. Please complete your KYC verification first.'
            if _farmity_wants_ajax(request):
                return _farmity_json_response(False, msg)
            messages.error(request, msg)
            return _redirect_same_page(request, 'expert_dashboard')

        tip_id = request.POST.get('tip_id')
        removed_id = None
        try:
            tip = FarmingTip.objects.get(id=tip_id, expert=profile)
            removed_id = tip.id
            tip.delete()
            msg = 'Content deleted successfully!'
            if _farmity_wants_ajax(request):
                return _farmity_json_response(True, msg, removed_tip_id=removed_id)
            messages.success(request, msg)
        except (FarmingTip.DoesNotExist, ValueError, TypeError):
            msg = 'Content not found!'
            if _farmity_wants_ajax(request):
                return _farmity_json_response(False, msg)
            messages.error(request, msg)
        return _redirect_same_page(request, 'expert_dashboard')
    
    # Handle Add Availability (single date with optional time, or one week)
    if request.method == 'POST' and 'add_availability' in request.POST:
        if kyc_status != 'approved':
            if _farmity_wants_ajax(request):
                return _farmity_json_response(False, 'KYC verification is required to set availability. Please complete your KYC verification first.')
            messages.error(request, 'KYC verification is required to set availability. Please complete your KYC verification first.')
            return _redirect_same_page(request, 'expert_dashboard')
        
        add_type = (request.POST.get('availability_type') or 'date').strip()
        notes = (request.POST.get('availability_notes') or '').strip() or None
        start_t = _parse_time_str(request.POST.get('availability_start_time') or '')
        end_t = _parse_time_str(request.POST.get('availability_end_time') or '')
        # NEW rule: start/end time are mandatory for both single-day and week ranges.
        if not start_t or not end_t:
            if _farmity_wants_ajax(request):
                return _farmity_json_response(False, 'Start time and end time are required.')
            messages.error(request, 'Start time and end time are required.')
            return _redirect_same_page(request, 'expert_dashboard')
        if start_t >= end_t:
            if _farmity_wants_ajax(request):
                return _farmity_json_response(False, 'End time must be after start time.')
            messages.error(request, 'End time must be after start time.')
            return _redirect_same_page(request, 'expert_dashboard')

        def _add_one_day_slot(d, st, et, note):
            avail = ExpertAvailability.objects.create(expert=profile, date=d, start_time=st, end_time=et, notes=note)
            return True, avail

        if add_type == 'week':
            week_start_str = (request.POST.get('availability_week_start') or '').strip()
            week_end_str = (request.POST.get('availability_week_end') or '').strip()
            if not week_start_str or not week_end_str:
                if _farmity_wants_ajax(request):
                    return _farmity_json_response(False, 'Please select both the week start and week end dates.')
                messages.error(request, 'Please select both the week start and week end dates.')
                return _redirect_same_page(request, 'expert_dashboard')
            try:
                start_d = date.fromisoformat(week_start_str)
                end_d = date.fromisoformat(week_end_str)
                if end_d < start_d:
                    if _farmity_wants_ajax(request):
                        return _farmity_json_response(False, 'Week end date must be on or after the start date.')
                    messages.error(request, 'Week end date must be on or after the start date.')
                    return _redirect_same_page(request, 'expert_dashboard')
                if start_d < timezone.now().date():
                    if _farmity_wants_ajax(request):
                        return _farmity_json_response(False, 'Week start date cannot be in the past.')
                    messages.error(request, 'Week start date cannot be in the past.')
                    return _redirect_same_page(request, 'expert_dashboard')
                added = 0
                new_availabilities = []
                d = start_d
                while d <= end_d:
                    if d >= timezone.now().date():
                        success, avail = _add_one_day_slot(d, start_t, end_t, notes)
                        if success and avail:
                            added += 1
                            new_availabilities.append({
                                'id': avail.id,
                                'date': avail.date.isoformat(),
                                'start_time': avail.start_time.strftime('%H:%M') if avail.start_time else None,
                                'end_time': avail.end_time.strftime('%H:%M') if avail.end_time else None,
                                'notes': avail.notes or ''
                            })
                    d = d + timedelta(days=1)
                msg = f'Added {added} day(s) from {week_start_str} to {week_end_str}.'
                if _farmity_wants_ajax(request):
                    return _farmity_json_response(True, msg, new_availabilities=new_availabilities)
                messages.success(request, msg)
            except (ValueError, TypeError):
                if _farmity_wants_ajax(request):
                    return _farmity_json_response(False, 'Invalid date. Use YYYY-MM-DD.')
                messages.error(request, 'Invalid date. Use YYYY-MM-DD.')
        else:
            date_str = (request.POST.get('availability_date') or '').strip()
            if date_str:
                try:
                    d = date.fromisoformat(date_str)
                    if d >= timezone.now().date():
                        success, avail = _add_one_day_slot(d, start_t, end_t, notes)
                        if success:
                            msg = f'Date {date_str} {start_t.strftime("%H:%M")}-{end_t.strftime("%H:%M")} added to your availability.'
                            if _farmity_wants_ajax(request):
                                new_avail = None
                                if avail:
                                    new_avail = {
                                        'id': avail.id,
                                        'date': avail.date.isoformat(),
                                        'start_time': avail.start_time.strftime('%H:%M') if avail.start_time else None,
                                        'end_time': avail.end_time.strftime('%H:%M') if avail.end_time else None,
                                        'notes': avail.notes or ''
                                    }
                                return _farmity_json_response(True, msg, new_availability=new_avail)
                            messages.success(request, msg)
                        else:
                            msg = f'Date {date_str} is already in your availability.'
                            if _farmity_wants_ajax(request):
                                return _farmity_json_response(False, msg)
                            messages.error(request, msg)
                    else:
                        if _farmity_wants_ajax(request):
                            return _farmity_json_response(False, 'Cannot add past dates.')
                        messages.error(request, 'Cannot add past dates.')
                except (ValueError, TypeError):
                    if _farmity_wants_ajax(request):
                        return _farmity_json_response(False, 'Invalid date format. Use YYYY-MM-DD.')
                    messages.error(request, 'Invalid date format. Use YYYY-MM-DD.')
            else:
                if _farmity_wants_ajax(request):
                    return _farmity_json_response(False, 'Please select a date.')
                messages.error(request, 'Please select a date.')
        return _redirect_same_page(request, 'expert_dashboard')

    # Handle Remove Availability
    if request.method == 'POST' and 'remove_availability' in request.POST:
        if kyc_status != 'approved':
            return _expert_finish(False, 'KYC verification is required to manage availability.')
        avail_id = request.POST.get('availability_id')
        try:
            avail = ExpertAvailability.objects.get(id=avail_id, expert=profile)
            removed_id = avail.id
            avail.delete()
            return _expert_finish(True, 'Date removed from your availability.', removed_availability_id=removed_id)
        except (ExpertAvailability.DoesNotExist, ValueError):
            return _expert_finish(False, 'Availability entry not found.')

    # Handle Accept/Reject Appointment (with valid reason for reject)
    if request.method == 'POST' and ('accept_appointment' in request.POST or 'reject_appointment' in request.POST):
        if kyc_status != 'approved':
            return _expert_finish(False, 'KYC verification is required to manage appointments. Please complete your KYC verification first.')
        
        appointment_id = request.POST.get('appointment_id')
        response_message = (request.POST.get('response_message') or '').strip() or None
        try:
            appointment = ExpertAppointment.objects.get(id=appointment_id, expert=profile)
            if 'accept_appointment' in request.POST:
                appointment.status = ExpertAppointment.STATUS_ACCEPTED
                appointment.response_message = response_message or 'Appointment accepted. Looking forward to our session.'
                appointment.save()
                create_notification(
                    appointment.requester,
                    'Appointment accepted',
                    f'Your appointment with {profile.name or profile.user.email} on {appointment.requested_date} at {appointment.requested_time} has been accepted.',
                    reverse('user_dashboard') + '?section=appointments',
                    UserNotification.TYPE_APPOINTMENT
                )
                return _expert_finish(True, 'Appointment accepted! The requester will see your response.', 
                              appointment_status={'id': appointment.id, 'status': appointment.status, 'response_message': appointment.response_message})
            elif 'reject_appointment' in request.POST:
                if not response_message:
                    return _expert_finish(False, 'Please provide a valid reason for rejecting the appointment.')
                appointment.status = ExpertAppointment.STATUS_REJECTED
                appointment.response_message = response_message
                appointment.save()
                create_notification(
                    appointment.requester,
                    'Appointment not accepted',
                    f'Your appointment with {profile.name or profile.user.email} on {appointment.requested_date} at {appointment.requested_time} was not accepted. Reason: ' + (response_message or 'See your appointments.'),
                    reverse('user_dashboard') + '?section=appointments',
                    UserNotification.TYPE_APPOINTMENT
                )
                return _expert_finish(True, 'Appointment rejected. The requester will see your reason.',
                              appointment_status={'id': appointment.id, 'status': appointment.status, 'response_message': appointment.response_message})
        except ExpertAppointment.DoesNotExist:
            return _expert_finish(False, 'Appointment not found!')
    
    # Handle update visit status (for accepted appointments only)
    if request.method == 'POST' and 'update_visit_status' in request.POST:
        if kyc_status != 'approved':
            messages.error(request, 'KYC verification is required.')
            return _redirect_same_page(request, 'expert_dashboard')
        appointment_id = request.POST.get('appointment_id')
        visit_status = (request.POST.get('visit_status') or '').strip() or None
        try:
            appointment = ExpertAppointment.objects.get(id=appointment_id, expert=profile)
            if appointment.status != ExpertAppointment.STATUS_ACCEPTED:
                messages.error(request, 'Visit status can only be set for accepted appointments.')
            elif visit_status in (ExpertAppointment.VISIT_VISITED, ExpertAppointment.VISIT_WILL_VISIT, ExpertAppointment.VISIT_WAITING):
                appointment.visit_status = visit_status
                appointment.save()

                # Email copy for "will visit / visited / waiting" status updates.
                try:
                    visit_status_label = appointment.get_visit_status_display()
                    create_notification(
                        appointment.requester,
                        'Appointment visit status updated',
                        f'Your appointment on {appointment.requested_date} at {appointment.requested_time} is now: {visit_status_label}.',
                        reverse('user_dashboard') + '?section=appointments',
                        UserNotification.TYPE_APPOINTMENT,
                    )
                except Exception:
                    logging.getLogger(__name__).exception("Failed to send appointment visit-status email")
                messages.success(request, 'Visit status updated.')
            else:
                messages.error(request, 'Please select a valid visit status.')
        except ExpertAppointment.DoesNotExist:
            messages.error(request, 'Appointment not found!')
        return _redirect_same_page(request, 'expert_dashboard')
    
    # Get expert content/tips
    tips = FarmingTip.objects.filter(expert=profile).order_by('-created_at')
    
    # Get availability (future dates first, then past)
    availability = ExpertAvailability.objects.filter(expert=profile).order_by('date')

    # Get appointments
    appointments = ExpertAppointment.objects.filter(expert=profile).select_related('requester').order_by('-created_at')
    
    # Get chat threads (for display - limited)
    chat_threads = ExpertChatThread.objects.filter(expert=profile).select_related(
        'created_by', 'created_by__farmer_profile', 'created_by__user_profile'
    ).order_by('-updated_at')

    # Attach display name + avatar for chat list UI (thread sidebar)
    for t in chat_threads:
        try:
            t.created_by_display_name = get_user_display_name(t.created_by)
            t.created_by_avatar = get_user_profile_image(t.created_by)
        except Exception:
            t.created_by_display_name = (getattr(getattr(t, 'created_by', None), 'email', '') or 'User')
            t.created_by_avatar = '/static/images/default-avatar.png'
    
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
    
    today = timezone.now().date()
    context = {
        'profile': profile,
        'tips': tips,
        'appointments': appointments[:20],  # Show last 20 appointments
        'availability': availability,
        'today': today,
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
        'active_section': (request.GET.get('section') or 'dashboard').strip(),
        'role_display': (request.user.role or '').replace('_', ' ').title(),
    }
    return render(request, 'expert_dashboard.html', context)


@login_required
def user_dashboard(request):
    if request.user.role != 'buyer':
        return _redirect_to_role_home_response(request.user)
    is_ajax = request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.POST.get('ajax') == '1'
    if request.session.pop('show_login_success', None):
        messages.success(request, 'Welcome back! You have been logged in successfully.')
    
    # Handle Crop Purchase
    if request.method == 'POST' and 'purchase_crop' in request.POST:
        payment_method = request.POST.get('payment_method', Order.PAYMENT_COD)
        crop_id = (request.POST.get('crop_id') or '').strip()
        if not crop_id:
            messages.error(request, 'Please select a crop to purchase.')
            return _redirect_same_page(request, 'user_dashboard')
        qty_raw = (request.POST.get('quantity', '1') or '').strip()
        quantity = _to_decimal_or_none(qty_raw) or Decimal('1')
        if quantity <= 0:
            quantity = Decimal('1')
        if quantity < Decimal('0.01'):
            quantity = Decimal('0.01')
        
        contact_number = (request.POST.get('contact_number') or '').strip()
        order_email = (request.POST.get('order_email') or '').strip() or None
        if not contact_number:
            messages.error(request, 'Contact number is required.')
            return _redirect_same_page(request, 'user_dashboard')
        try:
            crop = FarmerProduct.objects.get(id=crop_id, is_available=True)
            if crop.quantity >= quantity:
                base_amount = (crop.price_per_unit * quantity).quantize(Decimal('0.01'))
                shipping_cost = Decimal('100.00')
                total_amount = (base_amount + shipping_cost).quantize(Decimal('0.01'))
                admin_commission, seller_amount = Order.compute_commission(total_amount, shipping_cost, product_type='crop')
                # Create order (quantity must be integer for Order model, but we store decimal in CropSale)
                order = Order.objects.create(
                    buyer=request.user,
                    crop=crop,
                    quantity=int(quantity.to_integral_value(rounding='ROUND_HALF_UP')),
                    total_amount=total_amount,
                    shipping_cost=shipping_cost,
                    admin_commission=admin_commission,
                    seller_amount=seller_amount,
                    status=Order.STATUS_CONFIRMED,
                    payment_method=payment_method,
                    payment_status='pending',
                    shipping_address=request.POST.get('shipping_address', ''),
                    contact_number=contact_number,
                    order_email=order_email,
                    notes=request.POST.get('notes', '')
                )
                
                if payment_method != Order.PAYMENT_ESEWA:
                    # COD: apply inventory + record sale immediately
                    crop.quantity -= quantity
                    if crop.quantity <= 0:
                        crop.is_available = False
                    crop.save()
                    CropSale.objects.create(
                        crop=crop,
                        order=order,
                        quantity_sold=quantity,
                        price_per_unit=crop.price_per_unit,
                        total_amount=base_amount,
                        sold_to=request.user,
                        sold_at=timezone.now()
                    )
                    order.inventory_deducted = True
                    order.save(update_fields=['inventory_deducted'])
                farmer_user = getattr(crop.farmer, 'user', None)
                if farmer_user:
                    create_notification(
                        farmer_user,
                        'New order for your crop',
                        f'Order #{order.id}: {crop.name} x{int(round(quantity))} — Rs. {total_amount:.2f} (incl. shipping)',
                        reverse('farmer_dashboard') + '?section=orders',
                        UserNotification.TYPE_ORDER
                    )
                create_notification(
                    request.user,
                    'Order placed',
                    f'Order #{order.id}: {crop.name} x{int(round(quantity))} — Rs. {total_amount:.2f} (incl. shipping)',
                    reverse('user_dashboard') + '?section=orders',
                    UserNotification.TYPE_ORDER
                )
                if payment_method == Order.PAYMENT_ESEWA:
                    return redirect(reverse('esewa_initiate') + f'?order_id={order.id}')
                messages.success(request, f'Order successfully placed! You will pay Rs. {total_amount:.2f} on delivery (incl. Rs. 100 shipping).')
            else:
                messages.error(request, f'Insufficient quantity. Available: {crop.quantity} {crop.unit}')
        except FarmerProduct.DoesNotExist:
            messages.error(request, 'Crop not found or no longer available!')
        except Exception as e:
            messages.error(request, f'An error occurred: {str(e)}')
        return _redirect_same_page(request, 'user_dashboard')
    
    # Handle Tool Purchase
    if request.method == 'POST' and 'purchase_tool' in request.POST:
        payment_method = request.POST.get('payment_method', Order.PAYMENT_COD)
        tool_id = (request.POST.get('tool_id') or '').strip()
        if not tool_id:
            messages.error(request, 'Please select a tool to purchase.')
            return _redirect_same_page(request, 'user_dashboard')
        try:
            qty_raw = request.POST.get('quantity', '1').strip()
            quantity = int(float(qty_raw)) if qty_raw else 1
            if quantity < 1:
                quantity = 1
        except (ValueError, TypeError):
            quantity = 1
        quantity = max(1, quantity)
        contact_number = (request.POST.get('contact_number') or '').strip()
        order_email = (request.POST.get('order_email') or '').strip() or None
        if not contact_number:
            messages.error(request, 'Contact number is required.')
            return _redirect_same_page(request, 'user_dashboard')
        try:
            tool = VendorTool.objects.get(id=tool_id, is_available=True, stock_quantity__gt=0)
            if tool.stock_quantity >= quantity:
                base_amount = tool.price * quantity
                shipping_cost = Decimal('100.00')
                total_amount = base_amount + shipping_cost
                admin_commission, seller_amount = Order.compute_commission(total_amount, shipping_cost, product_type='tool')
                # Create order
                order = Order.objects.create(
                    buyer=request.user,
                    tool=tool,
                    quantity=quantity,
                    total_amount=total_amount,
                    shipping_cost=shipping_cost,
                    admin_commission=admin_commission,
                    seller_amount=seller_amount,
                    status=Order.STATUS_CONFIRMED,
                    payment_method=payment_method,
                    payment_status='pending',
                    shipping_address=request.POST.get('shipping_address', ''),
                    contact_number=contact_number,
                    order_email=order_email,
                    notes=request.POST.get('notes', '')
                )
                
                if payment_method != Order.PAYMENT_ESEWA:
                    tool.stock_quantity -= quantity
                    if tool.stock_quantity == 0:
                        tool.is_available = False
                    tool.save()
                    order.inventory_deducted = True
                    order.save(update_fields=['inventory_deducted'])
                vendor_user = getattr(tool.vendor, 'user', None)
                if vendor_user:
                    create_notification(
                        vendor_user,
                        'New tool order',
                        f'Order #{order.id}: {tool.name} x{quantity} — Rs. {total_amount:.2f} (incl. shipping)',
                        reverse('vendor_dashboard'),
                        UserNotification.TYPE_ORDER
                    )
                create_notification(
                    request.user,
                    'Order placed',
                    f'Order #{order.id}: {tool.name} x{quantity} — Rs. {total_amount:.2f} (incl. shipping)',
                    reverse('user_dashboard') + '?section=orders',
                    UserNotification.TYPE_ORDER
                )
                if payment_method == Order.PAYMENT_ESEWA:
                    return redirect(reverse('esewa_initiate') + f'?order_id={order.id}')
                messages.success(request, f'Order successfully placed! You will pay Rs. {total_amount:.2f} on delivery (incl. Rs. 100 shipping).')
            else:
                messages.error(request, f'Insufficient stock. Available: {tool.stock_quantity} units')
        except VendorTool.DoesNotExist:
            messages.error(request, 'Tool not found or no longer available!')
        except Exception as e:
            messages.error(request, f'An error occurred: {str(e)}')
        return _redirect_same_page(request, 'user_dashboard')
    
    # Handle Cart Checkout (multiple items, grocery-style)
    if request.method == 'POST' and 'checkout_cart' in request.POST:
        payment_method = request.POST.get('payment_method', Order.PAYMENT_COD)
        cart_json = request.POST.get('cart_items', '[]')
        try:
            cart_items = json.loads(cart_json)
        except (ValueError, TypeError):
            messages.error(request, 'Invalid cart data. Please try again.')
            return _redirect_same_page(request, 'user_dashboard')
        if not cart_items:
            messages.error(request, 'Your cart is empty.')
            return _redirect_same_page(request, 'user_dashboard')
        shipping_address = request.POST.get('shipping_address', '').strip()
        contact_number = (request.POST.get('contact_number') or '').strip()
        order_email = (request.POST.get('order_email') or '').strip() or None
        if not shipping_address:
            messages.error(request, 'Shipping address (location) is required.')
            return _redirect_same_page(request, 'user_dashboard')
        if not contact_number:
            messages.error(request, 'Contact number is required.')
            return _redirect_same_page(request, 'user_dashboard')
        notes = request.POST.get('notes', '')
        errors = []
        orders_created = []
        for item in cart_items:
            typ = (item.get('type') or '').lower()
            item_id = item.get('id')
            try:
                qty = (Decimal(str(item.get('quantity', 1))) if typ == 'crop' else int(item.get('quantity', 1)))
            except (ValueError, TypeError):
                errors.append(f"Invalid quantity for item {item.get('name', item_id)}")
                continue
            if qty <= 0:
                continue
            if typ == 'crop':
                try:
                    crop = FarmerProduct.objects.get(id=item_id, is_available=True)
                    if crop.quantity < qty:
                        errors.append(f"{crop.name}: only {crop.quantity} {crop.unit} available")
                        continue
                    base_amount = (Decimal(str(crop.price_per_unit)) * qty).quantize(Decimal('0.01'))
                    shipping_cost = Decimal('100.00')
                    total_amount = (base_amount + shipping_cost).quantize(Decimal('0.01'))
                    admin_commission, seller_amount = Order.compute_commission(total_amount, shipping_cost, product_type='crop')
                    order = Order.objects.create(
                        buyer=request.user,
                        crop=crop,
                        quantity=int(qty.to_integral_value(rounding='ROUND_HALF_UP')),
                        total_amount=total_amount,
                        shipping_cost=shipping_cost,
                        admin_commission=admin_commission,
                        seller_amount=seller_amount,
                        status=Order.STATUS_CONFIRMED,
                        payment_method=payment_method,
                        payment_status='pending',
                        shipping_address=shipping_address,
                        contact_number=contact_number,
                        order_email=order_email,
                        notes=notes
                    )
                    if payment_method != Order.PAYMENT_ESEWA:
                        crop.quantity -= qty
                        if crop.quantity <= 0:
                            crop.is_available = False
                        crop.save()
                        CropSale.objects.create(
                            crop=crop,
                            order=order,
                            quantity_sold=qty,
                            price_per_unit=crop.price_per_unit,
                            total_amount=base_amount,
                            sold_to=request.user,
                            sold_at=timezone.now()
                        )
                        order.inventory_deducted = True
                        order.save(update_fields=['inventory_deducted'])
                    farmer_user = getattr(crop.farmer, 'user', None)
                    if farmer_user:
                        create_notification(
                            farmer_user,
                            'New order for your crop',
                            f'Order #{order.id}: {crop.name} x{int(round(qty))} — Rs. {total_amount:.2f} (incl. shipping)',
                            reverse('farmer_dashboard') + '?section=orders',
                            UserNotification.TYPE_ORDER
                        )
                    create_notification(
                        request.user,
                        'Order placed',
                        f'Order #{order.id}: {crop.name} x{int(round(qty))} — Rs. {total_amount:.2f} (incl. shipping)',
                        reverse('user_dashboard') + '?section=orders',
                        UserNotification.TYPE_ORDER
                    )
                    orders_created.append(order)
                except FarmerProduct.DoesNotExist:
                    errors.append(f"Crop (id {item_id}) no longer available")
            elif typ == 'tool':
                try:
                    tool = VendorTool.objects.get(id=item_id, is_available=True, stock_quantity__gt=0)
                    if tool.stock_quantity < qty:
                        errors.append(f"{tool.name}: only {tool.stock_quantity} units available")
                        continue
                    base_amount = (Decimal(str(tool.price)) * Decimal(str(qty))).quantize(Decimal('0.01'))
                    shipping_cost = Decimal('100.00')
                    total_amount = (base_amount + shipping_cost).quantize(Decimal('0.01'))
                    admin_commission, seller_amount = Order.compute_commission(total_amount, shipping_cost, product_type='tool')
                    order = Order.objects.create(
                        buyer=request.user,
                        tool=tool,
                        quantity=int(qty),
                        total_amount=total_amount,
                        shipping_cost=shipping_cost,
                        admin_commission=admin_commission,
                        seller_amount=seller_amount,
                        status=Order.STATUS_CONFIRMED,
                        payment_method=payment_method,
                        payment_status='pending',
                        shipping_address=shipping_address,
                        contact_number=contact_number,
                        order_email=order_email,
                        notes=notes
                    )
                    if payment_method != Order.PAYMENT_ESEWA:
                        tool.stock_quantity -= int(qty)
                        if tool.stock_quantity == 0:
                            tool.is_available = False
                        tool.save()
                        order.inventory_deducted = True
                        order.save(update_fields=['inventory_deducted'])
                    vendor_user = getattr(tool.vendor, 'user', None)
                    if vendor_user:
                        create_notification(
                            vendor_user,
                            'New tool order',
                            f'Order #{order.id}: {tool.name} x{qty} — Rs. {total_amount:.2f} (incl. shipping)',
                            reverse('vendor_dashboard'),
                            UserNotification.TYPE_ORDER
                        )
                    create_notification(
                        request.user,
                        'Order placed',
                        f'Order #{order.id}: {tool.name} x{qty} — Rs. {total_amount:.2f} (incl. shipping)',
                        reverse('user_dashboard') + '?section=orders',
                        UserNotification.TYPE_ORDER
                    )
                    orders_created.append(order)
                except VendorTool.DoesNotExist:
                    errors.append(f"Tool (id {item_id}) no longer available")
            else:
                errors.append(f"Unknown item type: {typ}")
        if errors:
            for err in errors[:5]:
                messages.error(request, err)
            if len(errors) > 5:
                messages.error(request, f"... and {len(errors) - 5} more issues.")
            return _redirect_same_page(request, 'user_dashboard')
        grand_total = sum(float(o.total_amount) for o in orders_created)
        if payment_method == Order.PAYMENT_ESEWA:
            request.session['esewa_pending_order_ids'] = [o.id for o in orders_created]
            request.session.modified = True
            return redirect(reverse('esewa_initiate'))
        messages.success(request, f'Order placed for {len(orders_created)} item(s)! Total: Rs. {grand_total:.2f} (Cash on Delivery).')
        from urllib.parse import urlencode
        url = reverse('user_dashboard')
        section = (request.POST.get('return_section') or request.GET.get('section') or '').strip()
        params = {'checkout_success': '1'}
        if section:
            params['section'] = section
        url = url + '?' + urlencode(params)
        return redirect(url)
    
    # Buyers don't require KYC - full access immediately
    # Get all available tools from vendors
    tools = VendorTool.objects.filter(is_available=True, stock_quantity__gt=0).select_related('vendor', 'vendor__user').order_by('-created_at')
    
    # Get all available crops from farmers
    crops = FarmerProduct.objects.filter(is_available=True).select_related('farmer', 'farmer__user').order_by('-created_at')
    
    # Experts and appointments are only for farmers; buyers do not see them
    experts = []
    expert_availability_json = '{}'
    appointments = []
    chat_threads = []
    # Blogs (expert content) are visible to all users
    blogs = FarmingTip.objects.filter(is_published=True, approval_status=FarmingTip.APPROVAL_APPROVED).select_related('expert', 'expert__user').order_by('-created_at')[:15]
    
    # Handle update appointment (change date/time) - requester only, pending only (no-op for buyers; kept for URL compatibility)
    if request.method == 'POST' and 'update_appointment' in request.POST:
        appointment_id = request.POST.get('appointment_id')
        requested_date = (request.POST.get('requested_date') or '').strip()
        requested_time = (request.POST.get('requested_time') or '').strip()
        success = False
        payload = {}
        out_message = ''
        if appointment_id and requested_date and requested_time:
            try:
                req_date = date.fromisoformat(requested_date)
            except (ValueError, TypeError):
                req_date = None
            try:
                appointment = ExpertAppointment.objects.get(id=appointment_id, requester=request.user)
                if appointment.status != ExpertAppointment.STATUS_PENDING:
                    out_message = 'Only pending appointments can be rescheduled. Accepted appointments cannot be changed.'
                elif not req_date:
                    out_message = 'Invalid date format.'
                elif not ExpertAvailability.objects.filter(expert=appointment.expert, date=req_date).exists():
                    out_message = 'Appointment not available at this date. Please choose an available date.'
                else:
                    appointment.requested_date = requested_date
                    appointment.requested_time = requested_time
                    appointment.save()
                    success = True
                    out_message = 'Appointment date/time updated successfully.'
                    payload = {
                        'appointment_id': appointment.id,
                        'requested_date_display': req_date.strftime('%b %d, %Y') if req_date else requested_date,
                        'requested_time_display': appointment.requested_time.strftime('%I:%M %p') if appointment.requested_time else requested_time,
                        'status': appointment.status,
                        'status_display': appointment.get_status_display(),
                    }
            except ExpertAppointment.DoesNotExist:
                out_message = 'Appointment not found.'
        else:
            out_message = 'Please provide date and time.'
        if is_ajax:
            code = 200 if success else 400
            return JsonResponse({'success': success, 'message': out_message, 'data': payload}, status=code)
        if success:
            messages.success(request, out_message)
        else:
            messages.error(request, out_message)
        return _redirect_same_page(request, 'user_dashboard')
    
    # Handle reapply (rejected appointment: edit and apply again)
    if request.method == 'POST' and 'reapply_appointment' in request.POST:
        appointment_id = request.POST.get('appointment_id')
        requested_date = (request.POST.get('requested_date') or '').strip()
        requested_time = (request.POST.get('requested_time') or '').strip()
        success = False
        payload = {}
        out_message = ''
        if appointment_id and requested_date and requested_time:
            try:
                req_date = date.fromisoformat(requested_date)
            except (ValueError, TypeError):
                req_date = None
            try:
                appointment = ExpertAppointment.objects.get(id=appointment_id, requester=request.user)
                if appointment.status != ExpertAppointment.STATUS_REJECTED:
                    out_message = 'Only rejected appointments can be reapplied.'
                elif not req_date:
                    out_message = 'Invalid date format.'
                elif not ExpertAvailability.objects.filter(expert=appointment.expert, date=req_date).exists():
                    out_message = 'Appointment not available at this date. Please choose an available date.'
                else:
                    appointment.requested_date = requested_date
                    appointment.requested_time = requested_time
                    appointment.status = ExpertAppointment.STATUS_PENDING
                    appointment.response_message = None
                    appointment.save()
                    success = True
                    out_message = 'Appointment updated and resubmitted. The doctor will review your new request.'
                    payload = {
                        'appointment_id': appointment.id,
                        'requested_date_display': req_date.strftime('%b %d, %Y') if req_date else requested_date,
                        'requested_time_display': appointment.requested_time.strftime('%I:%M %p') if appointment.requested_time else requested_time,
                        'status': appointment.status,
                        'status_display': appointment.get_status_display(),
                    }
            except ExpertAppointment.DoesNotExist:
                out_message = 'Appointment not found.'
        else:
            out_message = 'Please provide date and time.'
        if is_ajax:
            code = 200 if success else 400
            return JsonResponse({'success': success, 'message': out_message, 'data': payload}, status=code)
        if success:
            messages.success(request, out_message)
        else:
            messages.error(request, out_message)
        return _redirect_same_page(request, 'user_dashboard')
    
    # Get or create user profile
    profile, _ = UserProfile.objects.get_or_create(user=request.user)
    
    # Handle Profile Photo (separate from profile details)
    if request.method == 'POST' and 'update_photo' in request.POST:
        photo_file = request.FILES.get('photo')
        if photo_file:
            profile.photo = photo_file
            profile.save()
            messages.success(request, 'Profile picture updated successfully!')
        else:
            messages.error(request, 'Please select an image file.')
        return _redirect_same_page(request, 'user_dashboard')

    # Handle Profile Update (details only; photo is changed separately)
    if request.method == 'POST' and 'update_profile' in request.POST:
        new_email = (request.POST.get('email') or '').strip()
        norm_email, email_err = _validate_profile_email_change(request.user, new_email)
        if email_err:
            if is_ajax:
                return _farmity_json_response(False, email_err, field_errors={'email': email_err})
            messages.error(request, email_err)
            return _redirect_same_page(request, 'user_dashboard')
        name = (request.POST.get('name') or '').strip()
        contact = (request.POST.get('contact') or '').strip()
        location = (request.POST.get('location') or '').strip()
        if name is not None:
            profile.name = name or profile.name
        if contact is not None:
            profile.phone = contact or profile.phone
        if location is not None:
            profile.address = location or profile.address
        try:
            profile.save()
            if norm_email != request.user.email:
                request.user.email = norm_email
                request.user.save(update_fields=['email'])
            if is_ajax:
                return _farmity_json_response(True, 'Profile updated successfully.', email=request.user.email)
            messages.success(request, 'Profile updated successfully.')
        except Exception as e:
            if is_ajax:
                return _farmity_json_response(False, f'Could not save profile: {str(e)}')
            messages.error(request, f'Could not save profile: {str(e)}')
        return _redirect_same_page(request, 'user_dashboard')
    
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
        'expert_availability_json': expert_availability_json,
        'blogs': blogs,
        'appointments': appointments,
        'chat_threads': chat_threads,
        'profile': profile,
        'purchase_history': purchase_history[:20],  # Show last 20 orders
        'tools_count': tools.count(),
        'crops_count': crops.count(),
        'experts_count': len(experts),
        'blogs_count': len(blogs),
        'total_orders': total_orders,
        'total_spent': float(total_spent),
        'pending_orders': pending_orders,
        'completed_orders': completed_orders,
        'kyc_status': None,  # Buyers don't need KYC
        'active_section': _buyer_active_section(request.GET),
        'role_display': (request.user.role or '').replace('_', ' ').title(),
    }
    return render(request, 'user_dashboard.html', context)


def _buyer_active_section(get_query):
    """Buyer dashboard: experts/appointments/tips/chat are farmer-only; default to crops."""
    section = (get_query.get('section') if get_query else None) or 'crops'
    section = (section or 'crops').strip()
    if section in ('experts', 'appointments', 'chat'):
        return 'crops'
    return section


@login_required
def admin_dashboard(request):
    if request.user.role != 'admin':
        return _redirect_to_role_home_response(request.user)
    if request.session.pop('show_login_success', None):
        messages.success(request, 'Welcome back! You have been logged in successfully.')
    
    # Get all users by role
    User = get_user_model()
    total_users = User.objects.count()
    farmers = User.objects.filter(role='farmer').count()
    vendors = User.objects.filter(role='vendor').count()
    experts = User.objects.filter(role='agricultural_expert').count()
    normal_users = User.objects.filter(role='buyer').count()
    
    # KYC Statistics
    pending_kyc = KYCRequest.objects.filter(status=KYCRequest.STATUS_PENDING).count()
    approved_kyc = KYCRequest.objects.filter(status=KYCRequest.STATUS_APPROVED).count()
    rejected_kyc = KYCRequest.objects.filter(status=KYCRequest.STATUS_REJECTED).count()
    
    # Transaction Statistics
    total_transactions = Order.objects.count()
    total_revenue = Order.objects.aggregate(total=Sum('total_amount'))['total'] or 0
    completed_transactions = Order.objects.filter(status=Order.STATUS_DELIVERED).count()
    pending_transactions = Order.objects.filter(status=Order.STATUS_PENDING).count()
    
    # Active Listings (only with available stock for tools)
    active_crop_listings = FarmerProduct.objects.filter(is_available=True).count()
    active_tool_listings = VendorTool.objects.filter(is_available=True, stock_quantity__gt=0).count()
    total_active_listings = active_crop_listings + active_tool_listings
    
    # Recent Activity
    recent_kyc_requests = KYCRequest.objects.select_related('user').order_by('-created_at')[:5]
    recent_orders = Order.objects.select_related('buyer', 'tool', 'crop').order_by('-created_at')[:5]
    recent_users = User.objects.order_by('-date_joined')[:5]
    admin_transactions = Order.objects.select_related(
        'buyer',
        'tool',
        'tool__vendor',
        'tool__vendor__user',
        'crop',
        'crop__farmer',
        'crop__farmer__user'
    ).order_by('-created_at')[:200]
    
    # Chart Data - User Growth (last 6 months)
    six_months_ago = timezone.now() - timedelta(days=180)
    user_growth_raw = User.objects.filter(
        date_joined__gte=six_months_ago
    ).annotate(
        month=TruncMonth('date_joined')
    ).values('month', 'role').annotate(
        count=Count('id')
    ).order_by('month')
    
    # Convert to list and format dates
    user_growth = []
    for item in user_growth_raw:
        user_growth.append({
            'month': item['month'].isoformat() if item['month'] else None,
            'role': item['role'],
            'count': item['count']
        })
    
    # Chart Data - Revenue by Month (last 6 months)
    revenue_data_raw = Order.objects.filter(
        created_at__gte=six_months_ago
    ).annotate(
        month=TruncMonth('created_at')
    ).values('month').annotate(
        total=Sum('total_amount'),
        count=Count('id')
    ).order_by('month')
    
    # Convert to list and format dates
    revenue_data = []
    for item in revenue_data_raw:
        revenue_data.append({
            'month': item['month'].isoformat() if item['month'] else None,
            'total': float(item['total'] or 0),
            'count': item['count']
        })
    
    context = {
        # Analytics Cards
        'total_users': total_users,
        'farmers': farmers,
        'vendors': vendors,
        'experts': experts,
        'normal_users': normal_users,
        'pending_kyc': pending_kyc,
        'approved_kyc': approved_kyc,
        'rejected_kyc': rejected_kyc,
        'total_transactions': total_transactions,
        'total_revenue': float(total_revenue),
        'completed_transactions': completed_transactions,
        'pending_transactions': pending_transactions,
        'active_listings': total_active_listings,
        'active_crop_listings': active_crop_listings,
        'active_tool_listings': active_tool_listings,
        
        # Recent Activity
        'recent_kyc_requests': recent_kyc_requests,
        'recent_orders': recent_orders,
        'recent_users': recent_users,
        'admin_transactions': admin_transactions,
        
        # Chart Data - JSON serialized
        'user_growth': json.dumps(user_growth),
        'revenue_data': json.dumps(revenue_data),
        'open_support_count': SupportTicket.objects.filter(
            status__in=[SupportTicket.STATUS_OPEN, SupportTicket.STATUS_IN_PROGRESS]
        ).count(),
    }
    
    return render(request, 'admin_dashboard.html', context)


@login_required
def admin_collections_payouts(request):
    """Admin: view all amounts collected (paid orders) and pay out to farmers/vendors (e.g. weekly)."""
    if request.user.role != 'admin':
        return _redirect_to_role_home_response(request.user)

    # Orders where payment is collected by admin (eSewa completed or COD delivered)
    collected_orders = Order.objects.filter(
        payment_status=Order.PAYMENT_STATUS_COMPLETED
    ).select_related('crop', 'crop__farmer', 'crop__farmer__user', 'tool', 'tool__vendor', 'tool__vendor__user')
    
    # For Mainali Tools and Technology vendor, check if they have actual sales
    mainali_vendor_orders = collected_orders.filter(tool__vendor__user__email='np05cp4s240077@iic.edu.np')
    mainali_has_sales = mainali_vendor_orders.filter(tool__isnull=False).exists()
    
    if not mainali_has_sales:
        # Exclude Mainali Tools and Technology vendor if no actual sales
        collected_orders = collected_orders.exclude(tool__vendor__user__email='np05cp4s240077@iic.edu.np')
    # If they have sales, include them automatically

    total_collected = collected_orders.aggregate(total=Sum('total_amount'))['total'] or Decimal('0')
    total_admin_commission = collected_orders.aggregate(t=Sum('admin_commission'))['t'] or Decimal('0')
    # Pending payout: collected but not yet paid to seller (use seller_amount: 80% of product + shipping)
    pending_q = Q(payout_status__isnull=True) | Q(payout_status=Order.PAYOUT_PENDING)
    pending_orders = collected_orders.filter(pending_q)
    total_pending_payout = pending_orders.aggregate(total=Sum('seller_amount'))['total'] or Decimal('0')

    # Amount per seller uses seller_amount ((product - commission) + shipping). Fallback to total_amount for old orders.
    def _order_seller_amount(o):
        return (o.seller_amount if o.seller_amount and o.seller_amount > 0 else o.total_amount)

    # Group ALL collected by farmer (crop orders) — amount to pay = seller_amount
    farmer_collected = {}
    for o in collected_orders.filter(crop__isnull=False).exclude(crop__farmer__isnull=True):
        fid = o.crop.farmer.id
        if fid not in farmer_collected:
            farmer_collected[fid] = {
                'profile': o.crop.farmer,
                'display_name': o.crop.farmer.name or o.crop.farmer.user.email,
                'amount': Decimal('0'),
            }
        farmer_collected[fid]['amount'] += _order_seller_amount(o)
    # Group ALL collected by vendor (tool orders)
    vendor_collected = {}
    for o in collected_orders.filter(tool__isnull=False).exclude(tool__vendor__isnull=True):
        vid = o.tool.vendor.id
        if vid not in vendor_collected:
            vendor_collected[vid] = {
                'profile': o.tool.vendor,
                'display_name': o.tool.vendor.company_name or o.tool.vendor.user.email,
                'amount': Decimal('0'),
            }
        vendor_collected[vid]['amount'] += _order_seller_amount(o)

    # Group pending by farmer (crop orders)
    farmer_pending = {}
    for o in pending_orders.filter(crop__isnull=False).exclude(crop__farmer__isnull=True):
        fid = o.crop.farmer.id
        if fid not in farmer_pending:
            farmer_pending[fid] = {
                'profile': o.crop.farmer,
                'display_name': o.crop.farmer.name or o.crop.farmer.user.email,
                'amount': Decimal('0'),
                'orders': [],
            }
        farmer_pending[fid]['amount'] += _order_seller_amount(o)
        farmer_pending[fid]['orders'].append(o)

    # Group pending by vendor (tool orders)
    vendor_pending = {}
    for o in pending_orders.filter(tool__isnull=False).exclude(tool__vendor__isnull=True):
        vid = o.tool.vendor.id
        if vid not in vendor_pending:
            vendor_pending[vid] = {
                'profile': o.tool.vendor,
                'display_name': o.tool.vendor.company_name or o.tool.vendor.user.email,
                'amount': Decimal('0'),
                'orders': [],
            }
        vendor_pending[vid]['amount'] += _order_seller_amount(o)
        vendor_pending[vid]['orders'].append(o)

    # Handle POST: mark payout paid for a seller
    if request.method == 'POST' and request.POST.get('action') == 'mark_payout_paid':
        seller_type = request.POST.get('seller_type')  # 'farmer' | 'vendor'
        seller_id = request.POST.get('seller_id')
        if seller_type == 'farmer' and seller_id:
            try:
                farmer = FarmerProfile.objects.get(id=seller_id)
                orders_to_pay = pending_orders.filter(crop__farmer=farmer)
                total_paid = orders_to_pay.aggregate(t=Sum('seller_amount'))['t'] or Decimal('0')
                if total_paid == 0:
                    total_paid = orders_to_pay.aggregate(t=Sum('total_amount'))['t'] or Decimal('0')
                now = timezone.now()
                orders_to_pay.update(payout_status=Order.PAYOUT_PAID, payout_at=now)
                seller_user = getattr(farmer, 'user', None)
                if seller_user:
                    create_notification(
                        seller_user,
                        'Payout received',
                        f'Rs. {total_paid:.2f} has been transferred to you for your orders (weekly payout from Farmity admin).',
                        reverse('farmer_dashboard') + '?section=orders',
                        UserNotification.TYPE_ORDER
                    )
                messages.success(request, f'Payout of Rs. {total_paid:.2f} marked as paid to farmer {farmer.name or farmer.user.email}. They have been notified.')
            except FarmerProfile.DoesNotExist:
                messages.error(request, 'Farmer not found.')
        elif seller_type == 'vendor' and seller_id:
            try:
                vendor = VendorProfile.objects.get(id=seller_id)
                orders_to_pay = pending_orders.filter(tool__vendor=vendor)
                total_paid = orders_to_pay.aggregate(t=Sum('seller_amount'))['t'] or Decimal('0')
                if total_paid == 0:
                    total_paid = orders_to_pay.aggregate(t=Sum('total_amount'))['t'] or Decimal('0')
                now = timezone.now()
                orders_to_pay.update(payout_status=Order.PAYOUT_PAID, payout_at=now)
                seller_user = getattr(vendor, 'user', None)
                if seller_user:
                    create_notification(
                        seller_user,
                        'Payout received',
                        f'Rs. {total_paid:.2f} has been transferred to you for your orders (weekly payout from Farmity admin).',
                        reverse('vendor_dashboard'),
                        UserNotification.TYPE_ORDER
                    )
                messages.success(request, f'Payout of Rs. {total_paid:.2f} marked as paid to vendor {vendor.company_name or vendor.user.email}. They have been notified.')
            except VendorProfile.DoesNotExist:
                messages.error(request, 'Vendor not found.')
        else:
            messages.error(request, 'Invalid payout request.')
        return _redirect_same_admin_page(request, 'admin_collections_payouts')

    # Total paid out = total collected - still pending
    total_paid_out = total_collected - total_pending_payout

    # Build per-order rows for Collections tab (admin can see each order-level collection)
    collected_order_rows = []
    for o in collected_orders:
        if o.crop_id:
            product_name = o.crop.name
            product_type = 'Crop'
            seller_name = o.crop.farmer.name or o.crop.farmer.user.email if o.crop and o.crop.farmer else 'Unknown'
        elif o.tool_id:
            product_name = o.tool.name
            product_type = 'Tool'
            seller_name = o.tool.vendor.company_name or o.tool.vendor.user.email if o.tool and o.tool.vendor else 'Unknown'
        else:
            product_name = '—'
            product_type = '—'
            seller_name = '—'
        collected_order_rows.append({
            'order': o,
            'product_name': product_name,
            'product_type': product_type,
            'seller_name': seller_name,
            'total_collected': o.total_amount or Decimal('0'),
            'shipping_cost': o.shipping_cost or Decimal('0'),
            'admin_commission': o.admin_commission or Decimal('0'),
            'payout_amount': _order_seller_amount(o),
        })
    # Build per-order rows for Payouts tab (pending only, with full transaction details)
    pending_payout_rows = []
    for o in pending_orders:
        if o.crop_id:
            product_name = o.crop.name
            product_type = 'Crop'
            seller_name = o.crop.farmer.name or o.crop.farmer.user.email if o.crop and o.crop.farmer else 'Unknown'
        elif o.tool_id:
            product_name = o.tool.name
            product_type = 'Tool'
            seller_name = o.tool.vendor.company_name or o.tool.vendor.user.email if o.tool and o.tool.vendor else 'Unknown'
        else:
            product_name = '—'
            product_type = '—'
            seller_name = '—'
        pending_payout_rows.append({
            'order': o,
            'product_name': product_name,
            'product_type': product_type,
            'seller_name': seller_name,
            'payout_amount': _order_seller_amount(o),
        })
    context = {
        'total_collected': float(total_collected),
        'total_admin_commission': float(total_admin_commission),
        'total_pending_payout': float(total_pending_payout),
        'total_paid_out': float(total_paid_out),
        'collected_order_rows': collected_order_rows,
        'farmer_collected_list': list(farmer_collected.values()),
        'vendor_collected_list': list(vendor_collected.values()),
        'farmer_pending_list': list(farmer_pending.values()),
        'vendor_pending_list': list(vendor_pending.values()),
        'pending_payout_rows': pending_payout_rows,
        'open_support_count': SupportTicket.objects.filter(
            status__in=[SupportTicket.STATUS_OPEN, SupportTicket.STATUS_IN_PROGRESS]
        ).count(),
    }
    return render(request, 'admin_collections_payouts.html', context)


@login_required
def admin_kyc_view_json(request, kyc_id):
    """Return KYC details as JSON for modal view"""
    if request.user.role != 'admin':
        from django.http import JsonResponse
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    try:
        kyc = KYCRequest.objects.select_related('user').get(id=kyc_id)
        from django.http import JsonResponse
        return JsonResponse({
            'user_email': kyc.user.email,
            'full_name': kyc.full_name,
            'id_number': kyc.id_number,
            'role': kyc.user.get_role_display(),
            'status': kyc.status,
            'status_display': kyc.get_status_display(),
            'id_document': kyc.id_document.url if kyc.id_document else '',
            'selfie': kyc.selfie.url if kyc.selfie else None,
            'company_document': kyc.company_document.url if kyc.company_document else None,
            'certificate_document': kyc.certificate_document.url if kyc.certificate_document else None,
            'rejection_reason': kyc.rejection_reason or '',
            'created_at': kyc.created_at.strftime('%B %d, %Y'),
        })
    except KYCRequest.DoesNotExist:
        from django.http import JsonResponse
        return JsonResponse({'error': 'KYC not found'}, status=404)


@login_required
def admin_kyc_management(request):
    """KYC Management page for admin"""
    if request.user.role != 'admin':
        return _redirect_to_role_home_response(request.user)
    
    # Handle KYC approval/rejection/edit
    if request.method == 'POST':
        kyc_id = request.POST.get('kyc_id')
        action = request.POST.get('action')  # 'approve', 'reject', 'edit_kyc'
        rejection_reason = request.POST.get('rejection_reason', '').strip()
        
        try:
            kyc = KYCRequest.objects.get(id=kyc_id)
            
            if action == 'approve':
                kyc.status = KYCRequest.STATUS_APPROVED
                kyc.reviewed_by = request.user
                kyc.reviewed_at = timezone.now()
                kyc.rejection_reason = None
                kyc.save()
                kyc.user.is_verified = True
                kyc.user.save()
                create_notification(
                    kyc.user,
                    'KYC approved',
                    'Your KYC verification has been approved. You now have full access to your account features.',
                    reverse('kyc') if kyc.user.role in ('farmer', 'vendor', 'agricultural_expert') else reverse('profile'),
                    UserNotification.TYPE_KYC
                )
                messages.success(request, f'KYC request for {kyc.user.email} has been approved.')
            elif action == 'reject':
                if not rejection_reason:
                    messages.error(request, 'Rejection reason is required.')
                else:
                    kyc.status = KYCRequest.STATUS_REJECTED
                    kyc.reviewed_by = request.user
                    kyc.reviewed_at = timezone.now()
                    kyc.rejection_reason = rejection_reason
                    kyc.save()
                    kyc.user.is_verified = False
                    kyc.user.save()
                    create_notification(
                        kyc.user,
                        'KYC rejected',
                        'Your KYC verification was not approved. Reason: ' + (rejection_reason or 'See details in KYC page.'),
                        reverse('kyc') if kyc.user.role in ('farmer', 'vendor', 'agricultural_expert') else reverse('profile'),
                        UserNotification.TYPE_KYC
                    )
                    messages.success(request, f'KYC request for {kyc.user.email} has been rejected.')
            elif action == 'edit_kyc':
                # Update KYC details
                old_status = kyc.status
                kyc.full_name = request.POST.get('full_name', kyc.full_name)
                kyc.id_number = request.POST.get('id_number', kyc.id_number)
                kyc.status = request.POST.get('status', kyc.status)
                kyc.rejection_reason = request.POST.get('rejection_reason', '') or None
                
                # Update documents if new ones are uploaded
                if request.FILES.get('id_document'):
                    kyc.id_document = request.FILES.get('id_document')
                if request.FILES.get('selfie'):
                    kyc.selfie = request.FILES.get('selfie')
                if request.FILES.get('company_document'):
                    kyc.company_document = request.FILES.get('company_document')
                if request.FILES.get('certificate_document'):
                    kyc.certificate_document = request.FILES.get('certificate_document')
                
                # Update reviewed info if status changed
                if kyc.status in [KYCRequest.STATUS_APPROVED, KYCRequest.STATUS_REJECTED]:
                    kyc.reviewed_by = request.user
                    kyc.reviewed_at = timezone.now()
                    # Update user verification status
                    kyc.user.is_verified = (kyc.status == KYCRequest.STATUS_APPROVED)
                    kyc.user.save()
                
                kyc.save()

                # Ensure notification + email is sent when status is changed via edit flow too.
                if old_status != kyc.status:
                    if kyc.status == KYCRequest.STATUS_APPROVED:
                        create_notification(
                            kyc.user,
                            'KYC approved',
                            'Your KYC verification has been approved. You now have full access to your account features.',
                            reverse('kyc') if kyc.user.role in ('farmer', 'vendor', 'agricultural_expert') else reverse('profile'),
                            UserNotification.TYPE_KYC
                        )
                    elif kyc.status == KYCRequest.STATUS_REJECTED:
                        create_notification(
                            kyc.user,
                            'KYC rejected',
                            'Your KYC verification was not approved. Reason: ' + (kyc.rejection_reason or 'See details in KYC page.'),
                            reverse('kyc') if kyc.user.role in ('farmer', 'vendor', 'agricultural_expert') else reverse('profile'),
                            UserNotification.TYPE_KYC
                        )
                messages.success(request, f'KYC details for {kyc.user.email} have been updated.')
        except KYCRequest.DoesNotExist:
            messages.error(request, 'KYC request not found.')
        except Exception as e:
            messages.error(request, f'Error updating KYC: {str(e)}')
    
    # Get filter parameters
    status_filter = request.GET.get('status', 'all')
    role_filter = request.GET.get('role', 'all')
    search_query = request.GET.get('search', '').strip()
    
    # Build query
    kyc_requests = KYCRequest.objects.select_related('user', 'reviewed_by').order_by('-created_at')
    
    if status_filter != 'all':
        kyc_requests = kyc_requests.filter(status=status_filter)
    
    if role_filter != 'all':
        kyc_requests = kyc_requests.filter(user__role=role_filter)
    
    if search_query:
        kyc_requests = kyc_requests.filter(
            Q(user__email__icontains=search_query) |
            Q(full_name__icontains=search_query) |
            Q(id_number__icontains=search_query)
        )
    
    context = {
        'kyc_requests': kyc_requests,
        'status_filter': status_filter,
        'role_filter': role_filter,
        'search_query': search_query,
        'pending_count': KYCRequest.objects.filter(status=KYCRequest.STATUS_PENDING).count(),
        'approved_count': KYCRequest.objects.filter(status=KYCRequest.STATUS_APPROVED).count(),
        'rejected_count': KYCRequest.objects.filter(status=KYCRequest.STATUS_REJECTED).count(),
    }
    
    return render(request, 'admin_kyc_management.html', context)


@login_required
def admin_user_view_json(request, user_id):
    """Return user details as JSON for modal view"""
    if request.user.role != 'admin':
        from django.http import JsonResponse
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    try:
        User = get_user_model()
        user = User.objects.get(id=user_id)
        
        data = {
            'email': user.email,
            'role': user.role,
            'is_active': user.is_active,
            'is_verified': user.is_verified,
        }
        
        # Get profile data based on role
        if user.role == 'farmer' and hasattr(user, 'farmer_profile'):
            profile = user.farmer_profile
            data['farmer_profile'] = {
                'name': profile.name or '',
                'location': profile.location or '',
                'contact': profile.contact or '',
                'farm_size': profile.farm_size or '',
                'crop_types': profile.crop_types or '',
                'livestock_details': profile.livestock_details or '',
            }
        elif user.role == 'vendor' and hasattr(user, 'vendor_profile'):
            profile = user.vendor_profile
            data['vendor_profile'] = {
                'company_name': profile.company_name or '',
                'address': profile.address or '',
                'contact': profile.contact or '',
            }
        elif user.role == 'agricultural_expert' and hasattr(user, 'expert_profile'):
            profile = user.expert_profile
            data['expert_profile'] = {
                'name': profile.name or '',
                'qualification': profile.qualification or '',
                'specialization': profile.specialization or '',
                'experience': profile.experience or '',
            }
        elif user.role == 'buyer' and hasattr(user, 'user_profile'):
            profile = user.user_profile
            data['user_profile'] = {
                'name': profile.name or '',
                'address': profile.address or '',
                'phone': profile.phone or '',
            }
        
        from django.http import JsonResponse
        return JsonResponse(data)
    except User.DoesNotExist:
        from django.http import JsonResponse
        return JsonResponse({'error': 'User not found'}, status=404)


@login_required
def admin_user_management(request):
    """User Management page for admin"""
    if request.user.role != 'admin':
        return _redirect_to_role_home_response(request.user)
    
    User = get_user_model()
    
    # Handle user actions
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        action = request.POST.get('action')  # 'activate', 'deactivate', 'block', 'edit_user', 'delete_user', 'add_user'
        
        if action == 'add_user':
            # Create new user
            email = request.POST.get('email', '').strip()
            password = request.POST.get('password', '').strip()
            role = request.POST.get('role', 'buyer')
            is_active = request.POST.get('is_active') == 'on'
            is_verified = request.POST.get('is_verified') == 'on'
            
            if not email or not password:
                messages.error(request, 'Email and password are required.')
            elif User.objects.filter(email=email).exists():
                messages.error(request, 'User with this email already exists.')
            else:
                try:
                    user = User.objects.create_user(
                        email=email,
                        password=password,
                        role=role,
                        is_active=is_active,
                        email_verified=is_active,  # admin-created active users should be able to login immediately
                    )
                    user.is_verified = is_verified
                    user.save(update_fields=['is_verified'])
                    
                    # Create profile based on role
                    if role == 'farmer':
                        profile = FarmerProfile.objects.create(user=user)
                        profile.name = request.POST.get('profile_name', '')
                        profile.location = request.POST.get('location', '')
                        profile.contact = request.POST.get('contact', '')
                        profile.farm_size = request.POST.get('farm_size', '')
                        profile.crop_types = request.POST.get('crop_types', '')
                        profile.livestock_details = request.POST.get('livestock_details', '')
                        if request.FILES.get('photo'):
                            profile.photo = request.FILES.get('photo')
                        profile.save()
                    elif role == 'vendor':
                        profile = VendorProfile.objects.create(user=user)
                        profile.company_name = request.POST.get('company_name', '')
                        profile.address = request.POST.get('address', '')
                        profile.contact = request.POST.get('contact', '')
                        if request.FILES.get('logo'):
                            profile.logo = request.FILES.get('logo')
                        profile.save()
                    elif role == 'agricultural_expert':
                        profile = ExpertProfile.objects.create(user=user)
                        profile.name = request.POST.get('profile_name', '')
                        profile.qualification = request.POST.get('qualification', '')
                        profile.specialization = request.POST.get('specialization', '')
                        profile.experience = request.POST.get('experience', '')
                        if request.FILES.get('photo'):
                            profile.photo = request.FILES.get('photo')
                        profile.save()
                    elif role == 'buyer':
                        profile = UserProfile.objects.create(user=user)
                        profile.name = request.POST.get('profile_name', '')
                        profile.address = request.POST.get('address', '')
                        profile.phone = request.POST.get('phone', '')
                        if request.FILES.get('photo'):
                            profile.photo = request.FILES.get('photo')
                        profile.save()
                    
                    messages.success(request, f'User {email} has been created successfully.')
                except Exception as e:
                    messages.error(request, f'Error creating user: {str(e)}')
        
        elif action == 'delete_user':
            try:
                user = User.objects.get(id=user_id)
                # Prevent deleting yourself
                if user.id == request.user.id:
                    messages.error(request, 'You cannot delete your own account.')
                else:
                    email = user.email
                    user.delete()
                    messages.success(request, f'User {email} has been deleted successfully.')
            except User.DoesNotExist:
                messages.error(request, 'User not found.')
            except Exception as e:
                messages.error(request, f'Error deleting user: {str(e)}')
        
        elif user_id:
            try:
                user = User.objects.get(id=user_id)
                
                if action == 'activate':
                    user.is_active = True
                    user.save()
                    messages.success(request, f'User {user.email} has been activated.')
                elif action == 'deactivate':
                    user.is_active = False
                    user.save()
                    messages.success(request, f'User {user.email} has been deactivated.')
                elif action == 'block':
                    user.is_active = False
                    user.save()
                    messages.warning(request, f'User {user.email} has been blocked.')
                elif action == 'edit_user':
                    # Update user fields
                    new_email = request.POST.get('email', '').strip()
                    new_role = request.POST.get('role', user.role)
                    user.is_active = request.POST.get('is_active') == 'on'
                    user.is_verified = request.POST.get('is_verified') == 'on'
                    
                    # Check if email is being changed and if it's unique
                    if new_email and new_email != user.email:
                        if User.objects.filter(email=new_email).exclude(id=user.id).exists():
                            messages.error(request, 'Email already exists.')
                            return _redirect_same_admin_page(request, 'admin_user_management')
                        user.email = new_email
                    
                    user.role = new_role
                    user.save()
                    
                    # Update profile based on role
                    if user.role == 'farmer':
                        profile, _ = FarmerProfile.objects.get_or_create(user=user)
                        profile.name = request.POST.get('profile_name', '')
                        profile.location = request.POST.get('location', '')
                        profile.contact = request.POST.get('contact', '')
                        profile.farm_size = request.POST.get('farm_size', '')
                        profile.crop_types = request.POST.get('crop_types', '')
                        profile.livestock_details = request.POST.get('livestock_details', '')
                        if request.FILES.get('photo'):
                            profile.photo = request.FILES.get('photo')
                        profile.save()
                    elif user.role == 'vendor':
                        profile, _ = VendorProfile.objects.get_or_create(user=user)
                        profile.company_name = request.POST.get('company_name', '')
                        profile.address = request.POST.get('address', '')
                        profile.contact = request.POST.get('contact', '')
                        if request.FILES.get('logo'):
                            profile.logo = request.FILES.get('logo')
                        profile.save()
                    elif user.role == 'agricultural_expert':
                        profile, _ = ExpertProfile.objects.get_or_create(user=user)
                        profile.name = request.POST.get('profile_name', '')
                        profile.qualification = request.POST.get('qualification', '')
                        profile.specialization = request.POST.get('specialization', '')
                        profile.experience = request.POST.get('experience', '')
                        if request.FILES.get('photo'):
                            profile.photo = request.FILES.get('photo')
                        profile.save()
                    elif user.role == 'buyer':
                        profile, _ = UserProfile.objects.get_or_create(user=user)
                        profile.name = request.POST.get('profile_name', '')
                        profile.address = request.POST.get('address', '')
                        profile.phone = request.POST.get('phone', '')
                        if request.FILES.get('photo'):
                            profile.photo = request.FILES.get('photo')
                        profile.save()
                    
                    messages.success(request, f'User {user.email} has been updated successfully.')
            except User.DoesNotExist:
                messages.error(request, 'User not found.')
            except Exception as e:
                messages.error(request, f'Error updating user: {str(e)}')
    
    # Get filter parameters
    role_filter = request.GET.get('role', 'all')
    status_filter = request.GET.get('status', 'all')
    search_query = request.GET.get('search', '').strip()
    
    # Build query
    users = User.objects.all().order_by('-date_joined')
    
    if role_filter != 'all':
        users = users.filter(role=role_filter)
    
    if status_filter == 'active':
        users = users.filter(is_active=True)
    elif status_filter == 'inactive':
        users = users.filter(is_active=False)
    elif status_filter == 'verified':
        users = users.filter(is_verified=True)
    elif status_filter == 'unverified':
        users = users.filter(is_verified=False)
    
    if search_query:
        users = users.filter(
            Q(email__icontains=search_query) |
            Q(role__icontains=search_query)
        )
    
    # Statistics
    total_users = User.objects.count()
    active_users = User.objects.filter(is_active=True).count()
    inactive_users = User.objects.filter(is_active=False).count()
    verified_users = User.objects.filter(is_verified=True).count()
    
    context = {
        'users': users,
        'role_filter': role_filter,
        'status_filter': status_filter,
        'search_query': search_query,
        'total_users': total_users,
        'active_users': active_users,
        'inactive_users': inactive_users,
        'verified_users': verified_users,
    }
    
    return render(request, 'admin_user_management.html', context)


@login_required
def admin_content_management(request):
    """Content Management page for admin"""
    if request.user.role != 'admin':
        return _redirect_to_role_home_response(request.user)
    
    # Handle POST requests for CRUD operations
    if request.method == 'POST':
        action = request.POST.get('action')
        ajax = _farmity_wants_ajax(request)
        result_ok = False
        result_msg = 'No action was performed.'
        removed_tip_id = None
        tip_status_update = None  # {id, approval_status, label} for live badge update

        if action == 'edit_tip':
            tip_id = request.POST.get('tip_id')
            try:
                tip = FarmingTip.objects.get(id=tip_id)
                if tip.approval_status == FarmingTip.APPROVAL_APPROVED:
                    result_ok = False
                    result_msg = 'Approved content cannot be edited. It is locked once approved.'
                else:
                    tip.title = request.POST.get('title', tip.title)
                    tip.content = request.POST.get('content', tip.content)
                    is_pub = request.POST.get('is_published') == 'on'
                    tip.is_published = is_pub
                    if is_pub:
                        tip.approval_status = FarmingTip.APPROVAL_APPROVED
                    if request.FILES.get('image'):
                        tip.image = request.FILES.get('image')
                    tip.save()
                    result_ok = True
                    result_msg = 'Content updated successfully!'
                    tip_status_update = {
                        'id': tip.id,
                        'approval_status': tip.approval_status,
                        'is_published': tip.is_published,
                    }
            except FarmingTip.DoesNotExist:
                result_ok = False
                result_msg = 'Content not found!'

        elif action == 'delete_tip':
            tip_id = request.POST.get('tip_id')
            try:
                tip = FarmingTip.objects.get(id=tip_id)
                removed_tip_id = tip.id
                tip.delete()
                result_ok = True
                result_msg = 'Content deleted successfully!'
            except FarmingTip.DoesNotExist:
                result_ok = False
                result_msg = 'Content not found!'

        elif action == 'approve_tip':
            tip_id = request.POST.get('tip_id')
            try:
                tip = FarmingTip.objects.get(id=tip_id)
                tip.approval_status = FarmingTip.APPROVAL_APPROVED
                tip.is_published = True
                tip.save()
                result_ok = True
                result_msg = f'"{tip.title}" approved and now visible to users.'
                tip_status_update = {
                    'id': tip.id,
                    'approval_status': tip.approval_status,
                    'is_published': tip.is_published,
                }
            except FarmingTip.DoesNotExist:
                result_ok = False
                result_msg = 'Content not found!'

        elif action == 'reject_tip':
            tip_id = request.POST.get('tip_id')
            try:
                tip = FarmingTip.objects.get(id=tip_id)
                tip.approval_status = FarmingTip.APPROVAL_REJECTED
                tip.is_published = False
                tip.save()
                result_ok = True
                result_msg = f'"{tip.title}" rejected.'
                tip_status_update = {
                    'id': tip.id,
                    'approval_status': tip.approval_status,
                    'is_published': tip.is_published,
                }
            except FarmingTip.DoesNotExist:
                result_ok = False
                result_msg = 'Content not found!'

        if ajax:
            payload = {'ok': result_ok, 'message': result_msg, 'action': action or ''}
            if removed_tip_id is not None:
                payload['removed_tip_id'] = removed_tip_id
            if tip_status_update is not None:
                payload['tip_status'] = tip_status_update
            return JsonResponse(payload)

        if result_ok:
            messages.success(request, result_msg)
        else:
            messages.error(request, result_msg)
        return _redirect_same_admin_page(request, 'admin_content_management')
    
    # Get filter parameters
    content_type = request.GET.get('type', 'all')  # 'tips', 'all'
    status_filter = request.GET.get('status', 'all')
    search_query = request.GET.get('search', '').strip()
    
    # Get expert content (tips)
    tips = FarmingTip.objects.select_related('expert', 'expert__user').order_by('-created_at')
    
    if status_filter == 'published':
        tips = tips.filter(approval_status=FarmingTip.APPROVAL_APPROVED)
    elif status_filter == 'pending':
        tips = tips.filter(approval_status=FarmingTip.APPROVAL_PENDING)
    elif status_filter == 'rejected':
        tips = tips.filter(approval_status=FarmingTip.APPROVAL_REJECTED)
    elif status_filter == 'unpublished':
        tips = tips.filter(approval_status__in=(FarmingTip.APPROVAL_PENDING, FarmingTip.APPROVAL_REJECTED))
    
    if search_query:
        tips = tips.filter(
            Q(title__icontains=search_query) |
            Q(content__icontains=search_query) |
            Q(expert__name__icontains=search_query) |
            Q(expert__user__email__icontains=search_query)
        )
    
    # Statistics
    total_tips = FarmingTip.objects.count()
    published_tips = FarmingTip.objects.filter(approval_status=FarmingTip.APPROVAL_APPROVED).count()
    pending_tips = FarmingTip.objects.filter(approval_status=FarmingTip.APPROVAL_PENDING).count()
    unpublished_tips = FarmingTip.objects.filter(approval_status__in=(FarmingTip.APPROVAL_PENDING, FarmingTip.APPROVAL_REJECTED)).count()
    total_experts = ExpertProfile.objects.count()
    
    context = {
        'tips': tips,
        'content_type': content_type,
        'status_filter': status_filter,
        'search_query': search_query,
        'total_tips': total_tips,
        'published_tips': published_tips,
        'pending_tips': pending_tips,
        'unpublished_tips': unpublished_tips,
        'total_experts': total_experts,
    }
    
    return render(request, 'admin_content_management.html', context)


@login_required
def admin_marketplace_oversight(request):
    """Marketplace Oversight page for admin"""
    if request.user.role != 'admin':
        return _redirect_to_role_home_response(request.user)
    
    # Handle POST requests for CRUD operations
    if request.method == 'POST':
        action = request.POST.get('action')
        
        # Crop operations
        if action == 'add_crop':
            farmer_id = request.POST.get('farmer_id')
            name = request.POST.get('name')
            quantity = request.POST.get('quantity')
            unit = request.POST.get('unit', 'kg')
            price_per_unit = request.POST.get('price_per_unit')
            is_available = request.POST.get('is_available') == 'on'
            
            try:
                farmer = FarmerProfile.objects.get(id=farmer_id)
                crop = FarmerProduct.objects.create(
                    farmer=farmer,
                    name=name,
                    quantity=quantity,
                    unit=unit,
                    price_per_unit=price_per_unit,
                    is_available=is_available
                )
                if request.FILES.get('image'):
                    crop.image = request.FILES.get('image')
                    crop.save()
                messages.success(request, 'Crop added successfully!')
            except FarmerProfile.DoesNotExist:
                messages.error(request, 'Farmer not found!')
            except Exception as e:
                messages.error(request, f'Error: {str(e)}')
        
        elif action == 'edit_crop':
            crop_id = request.POST.get('crop_id')
            try:
                crop = FarmerProduct.objects.get(id=crop_id)
                crop.name = request.POST.get('name', crop.name)
                crop.quantity = request.POST.get('quantity', crop.quantity)
                crop.unit = request.POST.get('unit', crop.unit)
                crop.price_per_unit = request.POST.get('price_per_unit', crop.price_per_unit)
                crop.is_available = request.POST.get('is_available') == 'on'
                if request.FILES.get('image'):
                    crop.image = request.FILES.get('image')
                crop.save()
                messages.success(request, 'Crop updated successfully!')
            except FarmerProduct.DoesNotExist:
                messages.error(request, 'Crop not found!')
        
        elif action == 'delete_crop':
            crop_id = request.POST.get('crop_id')
            try:
                crop = FarmerProduct.objects.get(id=crop_id)
                crop.delete()
                messages.success(request, 'Crop deleted successfully!')
            except FarmerProduct.DoesNotExist:
                messages.error(request, 'Crop not found!')
        
        # Tool operations
        elif action == 'add_tool':
            vendor_id = request.POST.get('vendor_id')
            name = request.POST.get('name')
            description = request.POST.get('description', '')
            price = request.POST.get('price')
            stock_quantity = request.POST.get('stock_quantity', 0)
            is_available = request.POST.get('is_available') == 'on'
            
            try:
                vendor = VendorProfile.objects.get(id=vendor_id)
                tool = VendorTool.objects.create(
                    vendor=vendor,
                    name=name,
                    description=description,
                    price=price,
                    stock_quantity=stock_quantity,
                    is_available=is_available
                )
                if request.FILES.get('image'):
                    tool.image = request.FILES.get('image')
                    tool.save()
                messages.success(request, 'Tool added successfully!')
            except VendorProfile.DoesNotExist:
                messages.error(request, 'Vendor not found!')
            except Exception as e:
                messages.error(request, f'Error: {str(e)}')
        
        elif action == 'edit_tool':
            tool_id = request.POST.get('tool_id')
            try:
                tool = VendorTool.objects.get(id=tool_id)
                tool.name = request.POST.get('name', tool.name)
                tool.description = request.POST.get('description', tool.description)
                tool.price = request.POST.get('price', tool.price)
                tool.stock_quantity = request.POST.get('stock_quantity', tool.stock_quantity)
                tool.is_available = request.POST.get('is_available') == 'on'
                if request.FILES.get('image'):
                    tool.image = request.FILES.get('image')
                tool.save()
                messages.success(request, 'Tool updated successfully!')
            except VendorTool.DoesNotExist:
                messages.error(request, 'Tool not found!')
        
        elif action == 'delete_tool':
            tool_id = request.POST.get('tool_id')
            try:
                tool = VendorTool.objects.get(id=tool_id)
                tool.delete()
                messages.success(request, 'Tool deleted successfully!')
            except VendorTool.DoesNotExist:
                messages.error(request, 'Tool not found!')
        
        # Order operations
        elif action == 'edit_order':
            order_id = request.POST.get('order_id')
            try:
                order = Order.objects.select_related('buyer', 'tool', 'tool__vendor', 'crop', 'crop__farmer').get(id=order_id)
                old_status = order.status
                old_payment_status = order.payment_status or ''
                order.status = request.POST.get('status', order.status)
                order.payment_status = request.POST.get('payment_status', order.payment_status)
                order.payment_method = request.POST.get('payment_method', order.payment_method)
                order.tracking_number = request.POST.get('tracking_number', order.tracking_number)
                order.shipping_address = request.POST.get('shipping_address', order.shipping_address)
                if request.POST.get('contact_number') is not None:
                    order.contact_number = request.POST.get('contact_number', '')
                if request.POST.get('order_email') is not None:
                    order.order_email = request.POST.get('order_email', '') or None
                order.notes = request.POST.get('notes', order.notes)
                order.save()
                # COD: when order is marked delivered, treat payment as collected by admin
                if (order.status == Order.STATUS_DELIVERED and
                        (order.payment_method or '').lower() == Order.PAYMENT_COD and
                        order.payment_status != Order.PAYMENT_STATUS_COMPLETED):
                    order.payment_status = Order.PAYMENT_STATUS_COMPLETED
                    order.save(update_fields=['payment_status'])
                # Notify buyer when order status moves through delivery lifecycle (and cancelled).
                if order.buyer and order.status != old_status and order.status in (
                    Order.STATUS_READY_TO_SHIP,
                    Order.STATUS_SHIPPED,
                    Order.STATUS_ON_THE_WAY,
                    Order.STATUS_DELIVERED,
                    Order.STATUS_CANCELLED,
                ):
                    status_label = order.get_status_display()
                    item_name = (order.tool.name if order.tool else order.crop.name) if (order.tool or order.crop) else 'item'
                    create_notification(
                        order.buyer,
                        f'Order #{order.id} {status_label.lower()}',
                        f'Your order for {item_name} is now {status_label.lower()}.'
                        + (f' Tracking: {order.tracking_number}' if order.tracking_number else ''),
                        reverse('user_dashboard') + '?section=orders',
                        UserNotification.TYPE_ORDER
                    )
                # Notify buyer and seller when payment status changes to completed
                if order.payment_status == Order.PAYMENT_STATUS_COMPLETED and order.payment_status != old_payment_status:
                    item_name = (order.tool.name if order.tool else order.crop.name) if (order.tool or order.crop) else 'Order'
                    amt = float(order.total_amount)
                    if order.buyer:
                        create_notification(
                            order.buyer,
                            'Payment recorded',
                            f'Payment of Rs. {amt:.2f} for Order #{order.id} ({item_name}) has been recorded.',
                            reverse('user_dashboard') + '?section=orders',
                            UserNotification.TYPE_ORDER
                        )
                    seller_user = None
                    if order.tool and getattr(order.tool.vendor, 'user', None):
                        seller_user = order.tool.vendor.user
                    elif order.crop and getattr(order.crop.farmer, 'user', None):
                        seller_user = order.crop.farmer.user
                    if seller_user:
                        create_notification(
                            seller_user,
                            'Payment recorded',
                            f'Order #{order.id}: {item_name} — Rs. {amt:.2f} payment recorded by admin.',
                            reverse('vendor_dashboard') if order.tool else (reverse('farmer_dashboard') + '?section=orders'),
                            UserNotification.TYPE_ORDER
                        )
                messages.success(request, 'Order updated successfully!')
            except Order.DoesNotExist:
                messages.error(request, 'Order not found!')
        
        elif action == 'delete_order':
            order_id = request.POST.get('order_id')
            try:
                order = Order.objects.get(id=order_id)
                order.delete()
                messages.success(request, 'Order deleted successfully!')
            except Order.DoesNotExist:
                messages.error(request, 'Order not found!')
        
        # Redirect back to the same page with all filters preserved
        return _redirect_same_admin_page(request, 'admin_marketplace_oversight')
    
    # Get filter parameters
    section = request.GET.get('section', 'overview')  # 'overview', 'tools', 'crops', 'orders', 'payments'
    status_filter = request.GET.get('status', 'all')
    search_query = request.GET.get('search', '').strip()
    
    context = {}
    
    # Get all farmers and vendors for dropdowns (always needed for add forms)
    context['farmers'] = FarmerProfile.objects.select_related('user').all()
    context['vendors'] = VendorProfile.objects.select_related('user').all()
    
    # Always load tools when section is tools or overview
    if section == 'overview' or section == 'tools':
        tools = VendorTool.objects.select_related('vendor', 'vendor__user').order_by('-created_at')
        if status_filter == 'available':
            tools = tools.filter(is_available=True)
        elif status_filter == 'unavailable':
            tools = tools.filter(is_available=False)
        if search_query:
            tools = tools.filter(
                Q(name__icontains=search_query) |
                Q(vendor__company_name__icontains=search_query) |
                Q(vendor__user__email__icontains=search_query)
            )
        context['tools'] = tools
        context['total_tools'] = VendorTool.objects.count()
        context['available_tools'] = VendorTool.objects.filter(is_available=True, stock_quantity__gt=0).count()
    else:
        # Initialize empty queryset for other sections
        context['tools'] = VendorTool.objects.none()
        context['total_tools'] = VendorTool.objects.count()
        context['available_tools'] = VendorTool.objects.filter(is_available=True, stock_quantity__gt=0).count()
    
    # Always load crops when section is crops or overview
    if section == 'overview' or section == 'crops':
        crops = FarmerProduct.objects.select_related('farmer', 'farmer__user').order_by('-created_at')
        if status_filter == 'available':
            crops = crops.filter(is_available=True)
        elif status_filter == 'unavailable':
            crops = crops.filter(is_available=False)
        if search_query:
            crops = crops.filter(
                Q(name__icontains=search_query) |
                Q(farmer__name__icontains=search_query) |
                Q(farmer__user__email__icontains=search_query)
            )
        context['crops'] = crops
        context['total_crops'] = FarmerProduct.objects.count()
        context['available_crops'] = FarmerProduct.objects.filter(is_available=True).count()
    else:
        # Initialize empty queryset for other sections
        context['crops'] = FarmerProduct.objects.none()
        context['total_crops'] = FarmerProduct.objects.count()
        context['available_crops'] = FarmerProduct.objects.filter(is_available=True).count()
    
    if section == 'overview' or section == 'orders':
        orders = Order.objects.select_related('buyer', 'tool', 'tool__vendor', 'crop', 'crop__farmer').order_by('-created_at')
        if status_filter != 'all':
            orders = orders.filter(status=status_filter)
        if search_query:
            orders = orders.filter(
                Q(buyer__email__icontains=search_query) |
                Q(tool__name__icontains=search_query) |
                Q(crop__name__icontains=search_query) |
                Q(tracking_number__icontains=search_query)
            )
        context['orders'] = orders
        context['total_orders'] = Order.objects.count()
        context['pending_orders'] = Order.objects.filter(status=Order.STATUS_PENDING).count()
        context['completed_orders'] = Order.objects.filter(status=Order.STATUS_DELIVERED).count()
    
    if section == 'overview' or section == 'payments':
        orders = Order.objects.select_related('buyer', 'tool', 'crop').order_by('-created_at')
        total_revenue = Order.objects.aggregate(total=Sum('total_amount'))['total'] or 0
        completed_payments = Order.objects.filter(payment_status=Order.PAYMENT_STATUS_COMPLETED).count()
        pending_payments = Order.objects.filter(payment_status=Order.PAYMENT_STATUS_PENDING).count()
        failed_payments = Order.objects.filter(payment_status=Order.PAYMENT_STATUS_FAILED).count()
        
        if status_filter != 'all':
            orders = orders.filter(payment_status=status_filter)
        if search_query:
            orders = orders.filter(
                Q(buyer__email__icontains=search_query) |
                Q(tool__name__icontains=search_query) |
                Q(crop__name__icontains=search_query)
            )
        
        context['payment_orders'] = orders
        context['total_revenue'] = float(total_revenue)
        context['completed_payments'] = completed_payments
        context['pending_payments'] = pending_payments
        context['failed_payments'] = failed_payments
    
    context['section'] = section
    context['status_filter'] = status_filter
    context['search_query'] = search_query
    
    return render(request, 'admin_marketplace_oversight.html', context)


@login_required
def admin_appointment_management(request):
    """Appointment Management page for admin"""
    if request.user.role != 'admin':
        return _redirect_to_role_home_response(request.user)
    
    # Handle POST requests for CRUD operations
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'edit_appointment':
            appointment_id = request.POST.get('appointment_id')
            try:
                appointment = ExpertAppointment.objects.get(id=appointment_id)
                old_status = appointment.status
                old_requested_date = appointment.requested_date
                old_requested_time = appointment.requested_time
                appointment.requested_date = request.POST.get('requested_date', appointment.requested_date)
                appointment.requested_time = request.POST.get('requested_time', appointment.requested_time)
                appointment.status = request.POST.get('status', appointment.status)
                appointment.message = request.POST.get('message', appointment.message)
                appointment.response_message = request.POST.get('response_message', appointment.response_message)
                appointment.save()

                # Email copy for important appointment status updates (user + admin).
                try:
                    if appointment.status != old_status:
                        if appointment.status == ExpertAppointment.STATUS_ACCEPTED:
                            create_notification(
                                appointment.requester,
                                'Appointment accepted',
                                f'Your appointment with {appointment.expert.name or appointment.expert.user.email} on {appointment.requested_date} at {appointment.requested_time} has been accepted.',
                                reverse('user_dashboard') + '?section=appointments',
                                UserNotification.TYPE_APPOINTMENT,
                            )
                        elif appointment.status == ExpertAppointment.STATUS_REJECTED:
                            create_notification(
                                appointment.requester,
                                'Appointment not accepted',
                                f'Your appointment with {appointment.expert.name or appointment.expert.user.email} on {appointment.requested_date} at {appointment.requested_time} was not accepted. Reason: ' + (appointment.response_message or 'See your appointments.'),
                                reverse('user_dashboard') + '?section=appointments',
                                UserNotification.TYPE_APPOINTMENT,
                            )
                        elif appointment.status == ExpertAppointment.STATUS_PENDING:
                            create_notification(
                                appointment.expert.user,
                                'Appointment resubmitted',
                                f'Appointment is pending for {appointment.requested_date} at {appointment.requested_time}.',
                                reverse('expert_dashboard') + '?section=appointments',
                                UserNotification.TYPE_APPOINTMENT,
                            )
                    # If admin only changed date/time while pending, notify expert as well.
                    elif appointment.status == ExpertAppointment.STATUS_PENDING and (
                        old_requested_date != appointment.requested_date or old_requested_time != appointment.requested_time
                    ):
                        create_notification(
                            appointment.expert.user,
                            'Appointment updated',
                            f'Appointment date/time updated to {appointment.requested_date} at {appointment.requested_time} (pending).',
                            reverse('expert_dashboard') + '?section=appointments',
                            UserNotification.TYPE_APPOINTMENT,
                        )
                except Exception:
                    logging.getLogger(__name__).exception("Failed to send appointment admin email")
                messages.success(request, 'Appointment updated successfully!')
            except ExpertAppointment.DoesNotExist:
                messages.error(request, 'Appointment not found!')
        
        elif action == 'delete_appointment':
            appointment_id = request.POST.get('appointment_id')
            try:
                appointment = ExpertAppointment.objects.get(id=appointment_id)
                requester = appointment.requester
                expert_user = appointment.expert.user
                appt_date = appointment.requested_date
                appt_time = appointment.requested_time
                appointment.delete()

                # Email copy for cancelled appointment (admin action).
                try:
                    create_notification(
                        requester,
                        'Appointment cancelled',
                        f'Your appointment on {appt_date} at {appt_time} was cancelled by Farmity admin.',
                        reverse('user_dashboard') + '?section=appointments',
                        UserNotification.TYPE_APPOINTMENT,
                    )
                    create_notification(
                        expert_user,
                        'Appointment cancelled',
                        f'An appointment on {appt_date} at {appt_time} was cancelled by Farmity admin.',
                        reverse('expert_dashboard') + '?section=appointments',
                        UserNotification.TYPE_APPOINTMENT,
                    )
                except Exception:
                    logging.getLogger(__name__).exception("Failed to send appointment cancellation email")
                messages.success(request, 'Appointment deleted successfully!')
            except ExpertAppointment.DoesNotExist:
                messages.error(request, 'Appointment not found!')
        
        return _redirect_same_admin_page(request, 'admin_appointment_management')
    
    # Get filter parameters
    status_filter = request.GET.get('status', 'all')
    search_query = request.GET.get('search', '').strip()
    
    # Get all appointments
    appointments = ExpertAppointment.objects.select_related(
        'expert', 'expert__user', 'requester'
    ).order_by('-created_at')
    
    if status_filter != 'all':
        appointments = appointments.filter(status=status_filter)
    
    if search_query:
        appointments = appointments.filter(
            Q(expert__name__icontains=search_query) |
            Q(expert__user__email__icontains=search_query) |
            Q(requester__email__icontains=search_query)
        )
    
    # Statistics
    total_appointments = ExpertAppointment.objects.count()
    pending_appointments = ExpertAppointment.objects.filter(status=ExpertAppointment.STATUS_PENDING).count()
    accepted_appointments = ExpertAppointment.objects.filter(status=ExpertAppointment.STATUS_ACCEPTED).count()
    rejected_appointments = ExpertAppointment.objects.filter(status=ExpertAppointment.STATUS_REJECTED).count()
    
    context = {
        'appointments': appointments,
        'status_filter': status_filter,
        'search_query': search_query,
        'total_appointments': total_appointments,
        'pending_appointments': pending_appointments,
        'accepted_appointments': accepted_appointments,
        'rejected_appointments': rejected_appointments,
    }
    
    return render(request, 'admin_appointment_management.html', context)


@login_required
def admin_chat_reports(request):
    """Chat and Reports Monitoring page for admin"""
    if request.user.role != 'admin':
        return _redirect_to_role_home_response(request.user)
    
    # Get filter parameters
    section = request.GET.get('section', 'overview')  # 'overview', 'chats', 'reports'
    search_query = request.GET.get('search', '').strip()
    
    context = {}
    
    # Chat Statistics
    total_threads = ExpertChatThread.objects.count()
    total_messages = ExpertChatMessage.objects.count()
    total_experts = ExpertProfile.objects.count()
    total_chat_users = ExpertChatThread.objects.values('created_by').distinct().count()
    
    # Get chat threads
    chat_threads = ExpertChatThread.objects.select_related(
        'expert', 'expert__user', 'created_by'
    ).order_by('-updated_at')
    
    if search_query:
        chat_threads = chat_threads.filter(
            Q(expert__name__icontains=search_query) |
            Q(expert__user__email__icontains=search_query) |
            Q(created_by__email__icontains=search_query)
        )
    
    # Get messages count per thread
    threads_with_counts = []
    for thread in chat_threads[:50]:  # Limit to 50 most recent
        message_count = ExpertChatMessage.objects.filter(thread=thread).count()
        threads_with_counts.append({
            'thread': thread,
            'message_count': message_count,
        })
    
    # Platform Usage Statistics
    User = get_user_model()
    total_users = User.objects.count()
    active_users_30d = User.objects.filter(
        date_joined__gte=timezone.now() - timedelta(days=30)
    ).count()
    
    # Recent activity
    recent_threads = ExpertChatThread.objects.select_related(
        'expert', 'expert__user', 'created_by'
    ).order_by('-created_at')[:10]
    
    context.update({
        'section': section,
        'search_query': search_query,
        'total_threads': total_threads,
        'total_messages': total_messages,
        'total_experts': total_experts,
        'total_chat_users': total_chat_users,
        'threads_with_counts': threads_with_counts,
        'total_users': total_users,
        'active_users_30d': active_users_30d,
        'recent_threads': recent_threads,
    })
    
    return render(request, 'admin_chat_reports.html', context)


@login_required
def admin_chat_thread_view(request, thread_id):
    """Admin read-only view of a single chat thread."""
    if request.user.role != 'admin':
        return _redirect_to_role_home_response(request.user)
    try:
        thread = ExpertChatThread.objects.select_related(
            'expert', 'expert__user', 'created_by'
        ).get(id=thread_id)
    except ExpertChatThread.DoesNotExist:
        messages.error(request, 'Chat thread not found.')
        return redirect('admin_chat_reports')
    messages_list = ExpertChatMessage.objects.filter(thread=thread).select_related('sender').order_by('created_at')
    context = {
        'thread': thread,
        'messages_list': messages_list,
    }
    return render(request, 'admin_chat_thread_view.html', context)


@login_required
def logout_view(request):
    # Accept both GET and POST so links and forms work
    next_url = request.GET.get('next') or (request.POST.get('next') if request.method == 'POST' else None)
    logout(request)
    messages.success(request, 'You have been logged out successfully.')
    if next_url and next_url.startswith('/'):
        return redirect(next_url)
    return redirect('landing')


@login_required
def appointment_request_page(request):
    if request.user.role not in {'buyer', 'farmer'}:
        return _redirect_to_role_home_response(request.user)

    is_ajax = request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.POST.get('ajax') == '1'

    # Check KYC for farmers (buyers don't need KYC)
    if request.user.role == 'farmer':
        kyc_request = request.user.kyc_requests.first()
        kyc_status = kyc_request.status if kyc_request else None
        if kyc_status != 'approved':
            error_msg = 'KYC verification is required to book appointments. Please complete your KYC verification first.'
            if is_ajax:
                return JsonResponse({'success': False, 'message': error_msg}, status=400)
            messages.error(request, error_msg)
            return redirect('farmer_dashboard')

    if request.method == 'POST':
        expert_id = (request.POST.get('expert_id') or '').strip()
        requested_date = (request.POST.get('requested_date') or '').strip()
        requested_time = (request.POST.get('requested_time') or '').strip()
        message = (request.POST.get('message') or '').strip() or None
        success = False
        out_message = ''
        payload = {}

        if expert_id and requested_date and requested_time:
            try:
                req_date = date.fromisoformat(requested_date)
            except (ValueError, TypeError):
                req_date = None

            if not req_date:
                out_message = 'Invalid date format.'
            else:
                expert = ExpertProfile.objects.get(id=expert_id)
                if not ExpertAvailability.objects.filter(expert=expert, date=req_date).exists():
                    out_message = "Appointment not available at this date. Please choose an available date from the expert's calendar."
                else:
                    appt = ExpertAppointment.objects.create(
                        expert=expert,
                        requester=request.user,
                        requested_date=requested_date,
                        requested_time=requested_time,
                        message=message,
                        status=ExpertAppointment.STATUS_PENDING
                    )
                    create_notification(
                        expert.user,
                        'New appointment request',
                        f'{request.user.email} requested an appointment on {requested_date} at {requested_time}.',
                        reverse('expert_dashboard') + '?section=appointments',
                        UserNotification.TYPE_APPOINTMENT
                    )
                    success = True
                    out_message = 'Appointment booked successfully! The doctor has been notified and will accept or reject your request. Go to My Appointments to see status and change date if needed.'
                    # Basic payload so frontend can optimistically update UI
                    try:
                        time_display = appt.requested_time.strftime('%I:%M %p') if appt.requested_time else requested_time
                    except Exception:
                        time_display = requested_time
                    payload = {
                        'appointment': {
                            'id': appt.id,
                            'expert_name': expert.name or expert.user.email,
                            'requested_date_iso': requested_date,
                            'requested_date_display': req_date.strftime('%b %d, %Y'),
                            'requested_time_display': time_display,
                            'status': appt.status,
                            'status_display': appt.get_status_display(),
                            'message': message or '',
                        }
                    }
        else:
            out_message = 'Please provide expert, date, and time.'

        if is_ajax:
            status_code = 200 if success else 400
            return JsonResponse({'success': success, 'message': out_message, 'data': payload}, status=status_code)

        if success:
            messages.success(request, out_message)
            if request.user.role == 'farmer':
                return redirect('farmer_dashboard')
            return redirect('user_dashboard')
        else:
            if out_message:
                messages.error(request, out_message)
            if request.user.role == 'farmer':
                return redirect('farmer_dashboard')
            return redirect('user_dashboard')
    
    experts = ExpertProfile.objects.select_related('user').all()
    context = {'experts': experts}
    return render(request, 'appointment_request.html', context)


@login_required
def chat_threads_page(request):
    if request.user.role not in {'buyer', 'farmer', 'agricultural_expert'}:
        return _redirect_to_role_home_response(request.user)
    
    if request.user.role == 'agricultural_expert':
        profile = ExpertProfile.objects.get(user=request.user)
        threads = ExpertChatThread.objects.filter(expert=profile).select_related('created_by', 'expert', 'expert__user').order_by('-updated_at')
    else:
        # Farmer or buyer - their threads with experts
        if request.user.role == 'farmer':
            kyc_request = request.user.kyc_requests.first()
            kyc_status = kyc_request.status if kyc_request else None
            if kyc_status != 'approved':
                messages.error(request, 'KYC verification is required to chat with experts. Please complete your KYC verification first.')
                return redirect('farmer_dashboard')
        threads = ExpertChatThread.objects.filter(created_by=request.user).select_related('expert', 'expert__user').order_by('-updated_at')
    
    context = {'threads': threads}
    return render(request, 'chat_threads.html', context)


@login_required
def chat_start(request, expert_id):
    """Farmer or buyer starts a chat with an expert. Creates thread if not exists."""
    if request.user.role not in {'buyer', 'farmer'}:
        return _redirect_to_role_home_response(request.user)
    
    if request.user.role == 'farmer':
        kyc_request = request.user.kyc_requests.first()
        kyc_status = kyc_request.status if kyc_request else None
        if kyc_status != 'approved':
            messages.error(request, 'KYC verification is required to chat with experts. Please complete your KYC verification first.')
            return redirect('farmer_dashboard')
    
    try:
        expert = ExpertProfile.objects.get(id=expert_id)
    except ExpertProfile.DoesNotExist:
        messages.error(request, 'Expert not found.')
        return redirect('chat_threads')
    
    thread, created = ExpertChatThread.objects.get_or_create(
        expert=expert,
        created_by=request.user
    )
    if created and expert.user_id:
        create_notification(
            expert.user,
            'New chat started',
            f'{request.user.email} started a chat with you.',
            _chat_notification_link(expert.user, thread.id),
            UserNotification.TYPE_CHAT
        )
    return redirect('chat_thread', thread_id=thread.id)


@login_required
def chat_thread_detail(request, thread_id):
    if request.user.role not in {'buyer', 'farmer', 'agricultural_expert'}:
        return _redirect_to_role_home_response(request.user)
    
    # Experts always use the dashboard chat UI – redirect to it (no standalone chat page for experts)
    if request.user.role == 'agricultural_expert':
        return redirect(reverse('expert_dashboard') + '?section=chat&thread_id=' + str(thread_id))
    
    # Check KYC for farmers (buyers don't need KYC)
    if request.user.role == 'farmer':
        kyc_request = request.user.kyc_requests.first()
        kyc_status = kyc_request.status if kyc_request else None
        if kyc_status != 'approved':
            messages.error(request, 'KYC verification is required to chat with experts. Please complete your KYC verification first.')
            return redirect('farmer_dashboard')
    
    try:
        thread = ExpertChatThread.objects.select_related('expert', 'expert__user', 'created_by').get(id=thread_id)
    except ExpertChatThread.DoesNotExist:
        messages.error(request, 'Chat thread not found.')
        return redirect('chat_threads')
    
    # Check access: farmer/buyer must be created_by
    if request.user.role != 'agricultural_expert':
        if thread.created_by_id != request.user.id:
            messages.error(request, 'You do not have access to this chat.')
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
            # Notify the other participant in the chat
            recipient = thread.created_by if thread.expert.user_id == request.user.id else thread.expert.user
            if recipient and recipient.id != request.user.id:
                preview = (message_text[:60] + '…') if len(message_text) > 60 else message_text
                create_notification(
                    recipient,
                    'New chat message',
                    f'{request.user.email}: {preview}',
                    _chat_notification_link(recipient, thread_id),
                    UserNotification.TYPE_CHAT
                )
            return redirect('chat_thread', thread_id=thread_id)
    
    messages_list = ExpertChatMessage.objects.filter(thread=thread).select_related('sender').order_by('created_at')
    
    # Add profile images to messages
    for msg in messages_list:
        msg.sender_profile_image = get_user_profile_image(msg.sender)
    
    context = {
        'thread': thread,
        'messages_list': messages_list,
    }
    return render(request, 'chat_thread_detail.html', context)


# ---------- Chat API (for inline chat, no redirect) ----------
def _check_chat_access(request, thread):
    """Returns (ok, error_response). If ok, error_response is None."""
    if request.user.role == 'agricultural_expert':
        profile = ExpertProfile.objects.get(user=request.user)
        if thread.expert_id != profile.id:
            return False, JsonResponse({'error': 'Access denied'}, status=403)
    else:
        if thread.created_by_id != request.user.id:
            return False, JsonResponse({'error': 'Access denied'}, status=403)
    return True, None


@login_required
def api_chat_messages(request, thread_id):
    """GET: Return JSON list of messages for a thread."""
    try:
        thread = ExpertChatThread.objects.get(id=thread_id)
    except ExpertChatThread.DoesNotExist:
        return JsonResponse({'error': 'Thread not found'}, status=404)
    ok, err = _check_chat_access(request, thread)
    if not ok:
        return err
    msgs = ExpertChatMessage.objects.filter(thread=thread).select_related('sender').order_by('created_at')
    data = [{
        'id': m.id,
        'message': m.message,
        'sender_name': get_user_display_name(m.sender),
        'sender_email': m.sender.email,
        'sender_id': m.sender_id,
        'sender_profile_image': get_user_profile_image(m.sender),
        'created_at': m.created_at.strftime('%b %d, %I:%M %p'),
        'is_mine': m.sender_id == request.user.id,
    } for m in msgs]
    return JsonResponse({'messages': data})


@login_required
def api_chat_send(request, thread_id):
    """POST: Send a message. Returns JSON with new message."""
    try:
        thread = ExpertChatThread.objects.select_related('expert', 'expert__user', 'created_by').get(id=thread_id)
    except ExpertChatThread.DoesNotExist:
        return JsonResponse({'error': 'Thread not found'}, status=404)
    ok, err = _check_chat_access(request, thread)
    if not ok:
        return err
    message_text = (request.POST.get('message') or '').strip()
    if not message_text:
        return JsonResponse({'error': 'Message is required'}, status=400)
    msg = ExpertChatMessage.objects.create(
        thread=thread,
        sender=request.user,
        message=message_text
    )
    thread.updated_at = timezone.now()
    thread.save()
    # Notify the other participant in the chat
    recipient = thread.created_by if thread.expert.user_id == request.user.id else thread.expert.user
    if recipient and recipient.id != request.user.id:
        preview = (message_text[:60] + '…') if len(message_text) > 60 else message_text
        create_notification(
            recipient,
            'New chat message',
            f'{request.user.email}: {preview}',
            _chat_notification_link(recipient, thread_id),
            UserNotification.TYPE_CHAT
        )
    return JsonResponse({
        'id': msg.id,
        'message': msg.message,
        'sender_name': get_user_display_name(msg.sender),
        'sender_email': msg.sender.email,
        'sender_id': msg.sender_id,
        'sender_profile_image': get_user_profile_image(msg.sender),
        'created_at': msg.created_at.strftime('%b %d, %I:%M %p'),
        'is_mine': True,
    })


@login_required
def api_chat_start(request, expert_id):
    """POST: Start or get thread with expert. Returns JSON with thread_id."""
    if request.user.role not in {'buyer', 'farmer'}:
        return JsonResponse({'error': 'For farmers and buyers only'}, status=403)
    if request.user.role == 'farmer':
        kyc_request = request.user.kyc_requests.first()
        if kyc_request and kyc_request.status != 'approved':
            return JsonResponse({'error': 'KYC verification required'}, status=403)
    try:
        expert = ExpertProfile.objects.select_related('user').get(id=expert_id)
    except ExpertProfile.DoesNotExist:
        return JsonResponse({'error': 'Expert not found'}, status=404)
    thread, created = ExpertChatThread.objects.get_or_create(
        expert=expert,
        created_by=request.user
    )
    if created and getattr(expert, 'user', None):
        create_notification(
            expert.user,
            'New chat started',
            f'{request.user.email} started a chat with you.',
            _chat_notification_link(expert.user, thread.id),
            UserNotification.TYPE_CHAT
        )
    return JsonResponse({
        'thread_id': thread.id,
        'expert_name': expert.name or expert.user.email,
        'qualification': expert.qualification or '',
        'specialization': expert.specialization or '',
        'experience': expert.experience or '',
    })


# ======================
# Customer Support
# ======================

def _is_support_staff(user):
    """Return True if user can handle support: admin only for now, or has SupportStaffProfile (addable by admin)."""
    if user.role == 'admin':
        return True
    return SupportStaffProfile.objects.filter(user=user).exists()


def support_hub(request):
    """Public support page: anonymous users see FAQ + contact; logged-in users see full hub. Support staff → Admin desk."""
    # Logged-in support staff see the admin desk instead
    if request.user.is_authenticated and _is_support_staff(request.user):
        return redirect('admin_support_desk')

    # POST create_ticket: only for authenticated users
    if request.method == 'POST' and request.POST.get('action') == 'create_ticket':
        if not request.user.is_authenticated:
            messages.info(request, 'Please sign in to submit a support request.')
            return redirect(reverse('login') + '?next=' + reverse('support_hub'))
        subject = (request.POST.get('subject') or '').strip()
        message = (request.POST.get('message') or '').strip()
        if subject and message:
            ticket = SupportTicket.objects.create(
                user=request.user,
                subject=subject,
                status=SupportTicket.STATUS_OPEN,
            )
            SupportMessage.objects.create(ticket=ticket, sender=request.user, message=message)
            messages.success(request, 'Support request created. You can view and reply below.')
            return redirect('support_ticket', ticket_id=ticket.id)
        else:
            messages.error(request, 'Please provide both subject and message.')

    # Public content for everyone (anonymous + logged-in)
    faqs = FAQ.objects.filter(is_active=True).order_by('order', 'created_at')
    support_staff = SupportStaffProfile.objects.filter(is_available=True).select_related('user')

    if request.user.is_authenticated:
        all_my_tickets = SupportTicket.objects.filter(user=request.user).select_related('assigned_to').order_by('-updated_at')
        open_tickets = [t for t in all_my_tickets if t.status in (SupportTicket.STATUS_OPEN, SupportTicket.STATUS_IN_PROGRESS)]
        past_tickets = [t for t in all_my_tickets if t.status in (SupportTicket.STATUS_ANSWERED, SupportTicket.STATUS_CLOSED)]
    else:
        all_my_tickets = []
        open_tickets = []
        past_tickets = []

    context = {
        'faqs': faqs,
        'support_staff': support_staff,
        'my_tickets': all_my_tickets,
        'open_tickets': open_tickets,
        'past_tickets': past_tickets,
        'is_support_staff': False,
        'open_tickets_for_staff': [],
        'user_is_anonymous': not request.user.is_authenticated,
    }
    return render(request, 'support.html', context)


@login_required
def admin_support_desk(request):
    """Support desk inside admin dashboard UI: list and manage tickets."""
    if request.user.role != 'admin' and not _is_support_staff(request.user):
        messages.error(request, 'You do not have access to the support desk.')
        return redirect('support_hub')
    status_filter = request.GET.get('status', '').strip()
    qs = SupportTicket.objects.select_related('user', 'assigned_to').order_by('-updated_at')
    if status_filter and status_filter in dict(SupportTicket.STATUS_CHOICES):
        qs = qs.filter(status=status_filter)
    tickets = qs
    open_count = SupportTicket.objects.filter(
        status__in=[SupportTicket.STATUS_OPEN, SupportTicket.STATUS_IN_PROGRESS]
    ).count()
    pending_kyc = KYCRequest.objects.filter(status=KYCRequest.STATUS_PENDING).count()
    context = {
        'tickets': tickets,
        'status_filter': status_filter,
        'status_choices': SupportTicket.STATUS_CHOICES,
        'open_count': open_count,
        'open_support_count': open_count,
        'pending_kyc': pending_kyc,
    }
    return render(request, 'admin_support_desk.html', context)


@login_required
def support_ticket_detail(request, ticket_id):
    """View a ticket and its messages; reply or (if staff) assign/update status."""
    try:
        ticket = SupportTicket.objects.select_related('user', 'assigned_to').get(id=ticket_id)
    except SupportTicket.DoesNotExist:
        messages.error(request, 'Support ticket not found.')
        return redirect('support_hub')
    is_staff = _is_support_staff(request.user)
    is_owner = ticket.user_id == request.user.id
    if not is_owner and not is_staff:
        messages.error(request, 'You do not have access to this ticket.')
        return redirect('support_hub')

    # Customers cannot open ended conversations; staff can still view them
    if is_owner and not is_staff and ticket.status in (SupportTicket.STATUS_ANSWERED, SupportTicket.STATUS_CLOSED):
        messages.info(request, 'This conversation has ended and can no longer be opened.')
        return redirect('support_hub')

    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'reply':
            if ticket.status in (SupportTicket.STATUS_ANSWERED, SupportTicket.STATUS_CLOSED):
                messages.error(request, 'This conversation has ended. No further replies can be added.')
                return _redirect_with_posted_ui_state(
                    request, reverse('support_ticket', kwargs={'ticket_id': ticket_id})
                )
            msg_text = (request.POST.get('message') or '').strip()
            if msg_text:
                SupportMessage.objects.create(
                    ticket=ticket,
                    sender=request.user,
                    message=msg_text
                )
                ticket.updated_at = timezone.now()
                if is_staff and ticket.status == SupportTicket.STATUS_OPEN:
                    ticket.status = SupportTicket.STATUS_IN_PROGRESS
                ticket.save()
                messages.success(request, 'Message sent.')
                return _redirect_with_posted_ui_state(
                    request, reverse('support_ticket', kwargs={'ticket_id': ticket_id})
                )
        elif action == 'assign_me' and is_staff:
            ticket.assigned_to = request.user
            ticket.status = SupportTicket.STATUS_IN_PROGRESS
            ticket.updated_at = timezone.now()
            ticket.save()
            messages.success(request, 'Ticket assigned to you.')
            return _redirect_with_posted_ui_state(
                request, reverse('support_ticket', kwargs={'ticket_id': ticket_id})
            )
        elif action == 'update_status' and is_staff:
            new_status = request.POST.get('status')
            if new_status in dict(SupportTicket.STATUS_CHOICES):
                ticket.status = new_status
                ticket.updated_at = timezone.now()
                ticket.save()
                messages.success(request, 'Status updated.')
                return _redirect_with_posted_ui_state(
                    request, reverse('support_ticket', kwargs={'ticket_id': ticket_id})
                )

    messages_list = SupportMessage.objects.filter(ticket=ticket).select_related('sender').order_by('created_at')
    context = {
        'ticket': ticket,
        'messages_list': messages_list,
        'is_support_staff': is_staff,
    }
    if is_staff:
        context['pending_kyc'] = KYCRequest.objects.filter(status=KYCRequest.STATUS_PENDING).count()
        context['open_support_count'] = SupportTicket.objects.filter(
            status__in=[SupportTicket.STATUS_OPEN, SupportTicket.STATUS_IN_PROGRESS]
        ).count()
        return render(request, 'admin_support_ticket_detail.html', context)
    return render(request, 'support_ticket_detail.html', context)


# ---------- Support widget APIs (JSON for floating widget) ----------
def api_support_config(request):
    """Allow anonymous: landing page widget needs config without login. Returns is_staff: false when not logged in."""
    if request.user.is_authenticated:
        return JsonResponse({'is_staff': _is_support_staff(request.user)})
    return JsonResponse({'is_staff': False})


def api_support_faqs(request):
    """Allow anonymous: widget can show FAQs on landing page without login."""
    faqs = FAQ.objects.filter(is_active=True).order_by('order', 'created_at')
    data = [{'id': f.id, 'question': f.question, 'answer': f.answer, 'category': f.category or ''} for f in faqs]
    return JsonResponse({'faqs': data})


@login_required
def api_support_my_tickets(request):
    tickets = SupportTicket.objects.filter(user=request.user).select_related('assigned_to').order_by('-updated_at')
    data = [{
        'id': t.id,
        'subject': t.subject,
        'status': t.status,
        'status_display': t.get_status_display(),
        'updated_at': t.updated_at.strftime('%b %d, %H:%M'),
        'assigned_to': t.assigned_to.email if t.assigned_to else None,
    } for t in tickets]
    return JsonResponse({'tickets': data})


@login_required
def api_support_create_ticket(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    subject = (request.POST.get('subject') or '').strip()
    message = (request.POST.get('message') or '').strip()
    if not subject or not message:
        return JsonResponse({'error': 'Subject and message required'}, status=400)
    ticket = SupportTicket.objects.create(user=request.user, subject=subject, status=SupportTicket.STATUS_OPEN)
    SupportMessage.objects.create(ticket=ticket, sender=request.user, message=message)

    # Notify user (and email admins) that the support ticket was created.
    try:
        create_notification(
            request.user,
            'Support ticket created',
            f'#{ticket.id}: {ticket.subject}',
            reverse('support_ticket', args=[ticket.id]),
            UserNotification.TYPE_SUPPORT,
        )
    except Exception:
        logging.getLogger(__name__).exception("Failed to create support ticket notification")
    return JsonResponse({
        'id': ticket.id,
        'subject': ticket.subject,
        'status': ticket.status,
        'status_display': ticket.get_status_display(),
        'updated_at': ticket.updated_at.strftime('%b %d, %H:%M'),
    })


def _api_support_ticket_to_json(ticket):
    return {
        'id': ticket.id,
        'subject': ticket.subject,
        'status': ticket.status,
        'status_display': ticket.get_status_display(),
        'user_email': ticket.user.email,
        'assigned_to': ticket.assigned_to.email if ticket.assigned_to else None,
        'created_at': ticket.created_at.strftime('%b %d, %Y %H:%M'),
        'updated_at': ticket.updated_at.strftime('%b %d, %H:%M'),
    }


@login_required
def api_support_ticket_detail(request, ticket_id):
    try:
        ticket = SupportTicket.objects.select_related('user', 'assigned_to').get(id=ticket_id)
    except SupportTicket.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)
    is_staff = _is_support_staff(request.user)
    if ticket.user_id != request.user.id and not is_staff:
        return JsonResponse({'error': 'Forbidden'}, status=403)
    messages_list = SupportMessage.objects.filter(ticket=ticket).select_related('sender').order_by('created_at')
    msgs = [{
        'id': m.id,
        'message': m.message,
        'sender_email': m.sender.email,
        'sender_id': m.sender_id,
        'created_at': m.created_at.strftime('%b %d, %H:%M'),
        'is_mine': m.sender_id == request.user.id,
    } for m in messages_list]
    return JsonResponse({
        'ticket': _api_support_ticket_to_json(ticket),
        'messages': msgs,
        'is_staff': is_staff,
    })


@login_required
def api_support_reply(request, ticket_id):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    try:
        ticket = SupportTicket.objects.get(id=ticket_id)
    except SupportTicket.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)
    is_staff = _is_support_staff(request.user)
    if ticket.user_id != request.user.id and not is_staff:
        return JsonResponse({'error': 'Forbidden'}, status=403)
    if ticket.status in (SupportTicket.STATUS_CLOSED, SupportTicket.STATUS_ANSWERED):
        return JsonResponse({'error': 'This conversation has ended.'}, status=400)
    message = (request.POST.get('message') or '').strip()
    if not message:
        return JsonResponse({'error': 'Message required'}, status=400)
    SupportMessage.objects.create(ticket=ticket, sender=request.user, message=message)
    ticket.updated_at = timezone.now()
    if is_staff and ticket.status == SupportTicket.STATUS_OPEN:
        ticket.status = SupportTicket.STATUS_IN_PROGRESS
    ticket.save()
    if is_staff and ticket.user_id != request.user.id:
        create_notification(
            ticket.user,
            'New reply on your support ticket',
            f'#{ticket.id}: {ticket.subject}',
            reverse('support_ticket', args=[ticket.id]),
            UserNotification.TYPE_SUPPORT
        )
    return JsonResponse({'ok': True})


@login_required
def api_support_open_tickets(request):
    if not _is_support_staff(request.user):
        return JsonResponse({'error': 'Forbidden'}, status=403)
    tickets = SupportTicket.objects.filter(
        status__in=[SupportTicket.STATUS_OPEN, SupportTicket.STATUS_IN_PROGRESS]
    ).exclude(user=request.user).select_related('user', 'assigned_to').order_by('-updated_at')[:30]
    data = [{
        'id': t.id,
        'subject': t.subject,
        'status': t.status,
        'status_display': t.get_status_display(),
        'user_email': t.user.email,
        'assigned_to': t.assigned_to.email if t.assigned_to else None,
        'updated_at': t.updated_at.strftime('%b %d, %H:%M'),
    } for t in tickets]
    return JsonResponse({'tickets': data})


@login_required
def api_support_assign(request, ticket_id):
    if request.method != 'POST' or not _is_support_staff(request.user):
        return JsonResponse({'error': 'Forbidden'}, status=403)
    try:
        ticket = SupportTicket.objects.get(id=ticket_id)
    except SupportTicket.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)
    ticket.assigned_to = request.user
    ticket.status = SupportTicket.STATUS_IN_PROGRESS
    ticket.updated_at = timezone.now()
    ticket.save()
    return JsonResponse({'ok': True})


@login_required
def api_support_status(request, ticket_id):
    if request.method != 'POST' or not _is_support_staff(request.user):
        return JsonResponse({'error': 'Forbidden'}, status=403)
    try:
        ticket = SupportTicket.objects.get(id=ticket_id)
    except SupportTicket.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)
    status_val = (request.POST.get('status') or '').strip()
    if status_val not in dict(SupportTicket.STATUS_CHOICES):
        return JsonResponse({'error': 'Invalid status'}, status=400)
    ticket.status = status_val
    ticket.updated_at = timezone.now()
    ticket.save()
    return JsonResponse({'ok': True})


def _notification_fallback_link(request, notification_type='', title='', message=''):
    """Fallback link if notification link is missing/invalid."""
    role = (getattr(request.user, 'role', '') or '').strip().lower()
    ntype = (notification_type or UserNotification.TYPE_INFO).strip().lower()
    text = f"{title or ''} {message or ''}".lower()

    if ntype == UserNotification.TYPE_ORDER:
        if role == 'farmer':
            return reverse('farmer_dashboard') + '?section=orders'
        if role == 'vendor':
            return reverse('vendor_dashboard') + '?section=orders'
        if role == 'admin':
            return reverse('admin_marketplace_oversight')
        return reverse('user_dashboard') + '?section=orders'

    if ntype == UserNotification.TYPE_KYC:
        if role == 'admin':
            return reverse('admin_kyc_management')
        if role in {'farmer', 'vendor', 'agricultural_expert'}:
            return reverse('kyc')
        return reverse('profile')

    if ntype == UserNotification.TYPE_APPOINTMENT:
        if role == 'agricultural_expert':
            return reverse('expert_dashboard') + '?section=appointments'
        if role == 'farmer':
            return reverse('farmer_dashboard') + '?section=appointments'
        return reverse('appointment_request')

    if ntype == UserNotification.TYPE_SUPPORT:
        return reverse('admin_support_desk') if role == 'admin' else reverse('support_hub')

    if ntype == UserNotification.TYPE_CHAT:
        if role == 'agricultural_expert':
            return reverse('expert_dashboard') + '?section=chat'
        return reverse('chat_threads')

    # TYPE_INFO and unknowns
    if 'profile' in text:
        return reverse('profile')
    if 'booking' in text or 'appointment' in text:
        if role == 'agricultural_expert':
            return reverse('expert_dashboard') + '?section=appointments'
        if role == 'farmer':
            return reverse('farmer_dashboard') + '?section=appointments'
        return reverse('appointment_request')
    if 'kyc' in text or 'verification' in text:
        if role == 'admin':
            return reverse('admin_kyc_management')
        if role in {'farmer', 'vendor', 'agricultural_expert'}:
            return reverse('kyc')
    if 'order' in text or 'payment' in text or 'payout' in text:
        if role == 'farmer':
            return reverse('farmer_dashboard') + '?section=orders'
        if role == 'vendor':
            return reverse('vendor_dashboard') + '?section=orders'
        if role == 'admin':
            return reverse('admin_marketplace_oversight')
        return reverse('user_dashboard') + '?section=orders'
    if role == 'admin':
        return reverse('admin_dashboard')
    if role == 'agricultural_expert':
        return reverse('expert_dashboard')
    if role == 'farmer':
        return reverse('farmer_dashboard')
    if role == 'vendor':
        return reverse('vendor_dashboard')
    return reverse('user_dashboard')


def _notification_link_for_user(request, link, notification_type='', title='', message=''):
    """Normalize notification links and always return a contextual destination."""
    fallback_link = _notification_fallback_link(request, notification_type, title, message)
    if not link or not link.strip():
        return fallback_link
    link = link.strip()
    # Security: reject dangerous pseudo URLs.
    if link.lower().startswith('javascript:') or link.lower().startswith('data:'):
        return fallback_link
    
    # Handle relative URLs (current page redirection)
    if link.startswith('?'):
        # Return current URL with additional query parameters
        current_url = request.get_full_path()
        current_params = request.GET.dict()
        
        # Merge with new parameters
        new_params = current_params.copy()
        link_params = {}
        for param in link[1:].split('&'):
            if '=' in param:
                key, value = param.split('=', 1)
                link_params[key] = value
        
        new_params.update(link_params)
        
        # Build new URL
        from urllib.parse import urlencode
        query_string = urlencode(new_params)
        return f"{current_url}?{query_string}" if query_string else current_url
    
    # Rewrite old generic /dashboard/?section=... to role-specific dashboard so redirect lands in the right place
    if link.startswith('/dashboard/') or (link.startswith('/dashboard') and '?' in link):
        qs = link.split('?', 1)[-1] if '?' in link else ''
        if request.user.role == 'agricultural_expert':
            return reverse('expert_dashboard') + ('?' + qs if qs else '')
        if request.user.role == 'farmer':
            return reverse('farmer_dashboard') + ('?' + qs if qs else '')
        if request.user.role == 'buyer':
            return reverse('user_dashboard') + ('?' + qs if qs else '')
        if request.user.role == 'vendor':
            return reverse('vendor_dashboard') + ('?' + qs if qs else '')
        if request.user.role == 'admin':
            return reverse('admin_dashboard') + ('?' + qs if qs else '')
    # External links: allow only HTTPS to keep navigation secure.
    if link.startswith('http://'):
        return fallback_link
    if link.startswith('https://'):
        return link
    # Ensure internal paths start with / so frontend can navigate from any page
    if link and not link.startswith('/') and not link.startswith('http') and not link.startswith('?'):
        return '/' + link.lstrip('?')
    return link or fallback_link


# ---------- Notifications API (for bell dropdown on all user dashboards) ----------
@login_required
def api_notifications_list(request):
    """GET: list recent notifications for current user (JSON). Links point to the page where the notification came from.
    Buyers do not see chat notifications."""
    limit = min(int(request.GET.get('limit', 20)), 50)
    qs = UserNotification.objects.filter(user=request.user).order_by('-created_at')
    if getattr(request.user, 'role', None) == 'buyer':
        qs = qs.exclude(notification_type=UserNotification.TYPE_CHAT)
    qs = qs[:limit]
    unread_qs = UserNotification.objects.filter(user=request.user, is_read=False)
    if getattr(request.user, 'role', None) == 'buyer':
        unread_qs = unread_qs.exclude(notification_type=UserNotification.TYPE_CHAT)
    unread_count = unread_qs.count()
    items = []
    for n in qs:
        link = _notification_link_for_user(
            request,
            n.link,
            n.notification_type,
            n.title,
            n.message,
        )
        items.append({
            'id': n.id,
            'title': n.title,
            'message': n.message,
            'link': link,
            'type': n.notification_type,
            'is_read': n.is_read,
            'created_at': n.created_at.strftime('%b %d, %H:%M'),
        })
    return JsonResponse({'notifications': items, 'unread_count': unread_count})


@login_required
def api_notification_mark_read(request, notification_id):
    """POST: mark one notification as read."""
    try:
        n = UserNotification.objects.get(id=notification_id, user=request.user)
    except UserNotification.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)
    n.is_read = True
    n.save()
    return JsonResponse({'ok': True})


@login_required
def api_notification_mark_all_read(request):
    """POST: mark all notifications as read for current user."""
    UserNotification.objects.filter(user=request.user, is_read=False).update(is_read=True)
    return JsonResponse({'ok': True})
