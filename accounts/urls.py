from django.urls import path
from .views import (
    SignupView, LoginView, ForgotPasswordView, ResetPasswordView, VerifyOTPView,
    landing_page, role_selection, register_page, login_page, home_page, dashboard,
    farmer_dashboard, vendor_dashboard, expert_dashboard, user_dashboard, admin_dashboard,
    kyc_page, profile_page, settings_page, change_password,
    appointment_request_page,
    chat_threads_page, chat_thread_detail,
    forgot_password_page, reset_password_page, otp_verification_page
)
urlpatterns = [
    # Frontend pages
    path('', landing_page, name='landing'),
    path('home/', home_page, name='home'),
    path('role-selection/', role_selection, name='role-selection'),
    path('register/', register_page, name='register'),
    path('login/', login_page, name='login'),
    path('forgot-password/', forgot_password_page, name='forgot_password'),
    path('otp-verification/', otp_verification_page, name='otp_verification'),
    path('reset-password/', reset_password_page, name='reset_password'),
    path('dashboard/', dashboard, name='dashboard'),
    path('profile/', profile_page, name='profile'),
    path('settings/', settings_page, name='settings'),
    path('settings/change-password/', change_password, name='change_password'),
    path('kyc/', kyc_page, name='kyc'),
    path('farmer-dashboard/', farmer_dashboard, name='farmer_dashboard'),
    path('vendor-dashboard/', vendor_dashboard, name='vendor_dashboard'),
    path('expert-dashboard/', expert_dashboard, name='expert_dashboard'),
    path('user-dashboard/', user_dashboard, name='user_dashboard'),
    path('admin-dashboard/', admin_dashboard, name='admin_dashboard'),
    path('appointments/request/', appointment_request_page, name='appointment_request'),
    path('chat/', chat_threads_page, name='chat_threads'),
    path('chat/<int:thread_id>/', chat_thread_detail, name='chat_thread'),
]

api_urlpatterns = [
    path('signup/', SignupView.as_view(), name='api-signup'),
    path('login/', LoginView.as_view(), name='api-login'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='api-forgot-password'),
    path('verify-otp/', VerifyOTPView.as_view(), name='api-verify-otp'),
    path('reset-password/', ResetPasswordView.as_view(), name='api-reset-password'),
]
