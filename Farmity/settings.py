"""
Django settings for Farmity project.
"""

from pathlib import Path
import os


# Load .env so EMAIL_HOST_PASSWORD is read – OTP then sends from farmityforyou@gmail.com
_project_root = Path(__file__).resolve().parent.parent  # same folder as manage.py
try:
    from dotenv import load_dotenv
    load_dotenv(_project_root / '.env')
    load_dotenv(Path.cwd() / '.env')
except ImportError:
    pass
# Fallback: read .env manually if env var still missing (e.g. dotenv not installed or wrong path)
if not os.environ.get('EMAIL_HOST_PASSWORD') and (_project_root / '.env').exists():
    try:
        with open(_project_root / '.env', 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, _, val = line.partition('=')
                    key, val = key.strip(), val.strip().strip('"').strip("'").replace(' ', '')
                    if key == 'EMAIL_HOST_PASSWORD' and val:
                        os.environ['EMAIL_HOST_PASSWORD'] = val
                        break
    except Exception:
        pass

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Security
SECRET_KEY = os.environ.get(
    'SECRET_KEY',
    'django-insecure-change-this-in-production'
)

DEBUG = True

ALLOWED_HOSTS = ['127.0.0.1', 'localhost','https://nabin-regmi-farmity.onrender.com', 'https://onrender.com']

# OTP Settings
REQUIRE_OTP_FOR_LOGIN = False  # Set to False to skip OTP in development, True for production


# ======================
# APPLICATIONS
# ======================
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sites',  # Required for allauth

    'rest_framework',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.google',
    'accounts',
]

SITE_ID = 1


# ======================
# MIDDLEWARE
# ======================
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'allauth.account.middleware.AccountMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]


# ======================
# URLS & TEMPLATES
# ======================
ROOT_URLCONF = 'Farmity.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],  # OK
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'accounts.context_processors.admin_collections_payouts_summary',
            ],
        },
    },
]

WSGI_APPLICATION = 'Farmity.wsgi.application'


# ======================
# DATABASE
# ======================
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.sqlite3',
#         'NAME': BASE_DIR / 'db.sqlite3',
#     }
# }
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME":"farmity_foryou",
        "USER":"farmity_foryou_user",
        "PASSWORD":"sAFOb3zsrUFbFmw38ogKymHyECMgFp3v" ,
        "HOST": "dpg-d6vbo46uk2gs738mckm0-a",
        "PORT": "5432",

    }
}


# ======================
# CUSTOM USER MODEL (CORRECT)
# ======================
AUTH_USER_MODEL = 'accounts.User'


# 🔥 THIS WAS MISSING (VERY IMPORTANT)
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'allauth.account.auth_backends.AuthenticationBackend',
]


# ======================
# PASSWORD VALIDATION
# ======================
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]


# ======================
# INTERNATIONALIZATION
# ======================
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True


# ======================
# STATIC FILES (FIXED)
# ======================
STATIC_URL = '/static/'   # 🔥 must start & end with /
STATICFILES_DIRS = [BASE_DIR / 'static']

# ======================
# MEDIA FILES
# ======================
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'


# ======================
# DEFAULT PRIMARY KEY
# ======================
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# ======================
# EMAIL – OTP sent to the user from farmityforyou@gmail.com
# ======================
# Gmail: You must use an App Password, not your normal password.
# 1. Go to https://myaccount.google.com/security
# 2. Turn on 2-Step Verification if needed
# 3. App passwords → Generate for "Mail" → copy the 16-character password
# 4. Put it in .env as EMAIL_HOST_PASSWORD=xxxxxxxxxxxxxxxx (16 chars, NO SPACES – Gmail shows "xxxx xxxx xxxx xxxx" but paste as one word)
# If you get 535 "Username and Password not accepted", see EMAIL_SETUP.md in the project root.
DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', 'farmityforyou@gmail.com')

EMAIL_HOST = os.environ.get('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.environ.get('EMAIL_PORT', '587'))
EMAIL_USE_TLS = os.environ.get('EMAIL_USE_TLS', 'true').lower() in ('true', '1', 'yes')
EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER', 'farmityforyou@gmail.com')
# Strip whitespace so trailing newline or accidental spaces in .env don't break Gmail login
EMAIL_HOST_PASSWORD = (os.environ.get('EMAIL_HOST_PASSWORD', '') or '').strip().replace(' ', '')

if EMAIL_HOST and EMAIL_HOST_USER and EMAIL_HOST_PASSWORD:
    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
    import sys
    if 'runserver' in sys.argv:
        print("[Email] Using SMTP: sending from", EMAIL_HOST_USER)
else:
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
    import sys
    if 'runserver' in sys.argv:
        print("[Email] WARNING: SMTP not configured. Set EMAIL_HOST_PASSWORD in .env (Gmail App Password). See comments in settings.py.")

# ======================
# ALLAUTH SETTINGS
# ======================
LOGIN_REDIRECT_URL = '/dashboard/'  # Redirect to dashboard after login
ACCOUNT_LOGOUT_REDIRECT_URL = '/login/'
ACCOUNT_SIGNUP_FIELDS = ['email*', 'password1*', 'password2*']  # Required fields for signup
ACCOUNT_LOGIN_METHODS = ['email']  # Login using email
ACCOUNT_EMAIL_VERIFICATION = 'none'  # Set to 'mandatory' in production
ACCOUNT_UNIQUE_EMAIL = True
ACCOUNT_USER_MODEL_USERNAME_FIELD = None  # Don't use username field
# ACCOUNT_SIGNUP_FIELDS above = ['email*', 'password1*', 'password2*'] implies email required, no username
ACCOUNT_ADAPTER = 'accounts.adapters.CustomAccountAdapter'
SOCIALACCOUNT_ADAPTER = 'accounts.adapters.CustomSocialAccountAdapter'

# Social Account Settings
SOCIALACCOUNT_AUTO_SIGNUP = True  # Automatically create user account on first Google login
SOCIALACCOUNT_EMAIL_REQUIRED = False  # Email not required for social accounts
SOCIALACCOUNT_QUERY_EMAIL = True  # Request email from Google
SOCIALACCOUNT_STORE_TOKENS = False  # Don't store OAuth tokens
SOCIALACCOUNT_EMAIL_VERIFICATION = 'none'  # No email verification for social accounts
# Skip "Sign In Via Google" confirmation page – redirect straight to Google account selection
SOCIALACCOUNT_LOGIN_ON_GET = True

# Google OAuth Settings (set these in environment variables or .env file)
# Only configure Google OAuth if credentials are provided

SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = os.getenv("GOOGLE_CLIENT_ID")
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

# eSewa ePay (Nepal) - https://developer.esewa.com.np/pages/Epay-V2
# UAT: product_code EPAYTEST, secret 8gBm/:&EnhH.1/q . For production get credentials from eSewa.
ESEWA_MERCHANT_CODE = os.environ.get('ESEWA_MERCHANT_CODE', 'EPAYTEST')
ESEWA_SECRET_KEY = os.environ.get('ESEWA_SECRET_KEY', '8gBm/:&EnhH.1/q')
ESEWA_USE_UAT = os.environ.get('ESEWA_USE_UAT', 'true').lower() in ('1', 'true', 'yes')

# Google provider: credentials come from SocialApp in DB (via setup_google_oauth or _ensure_google_oauth)
# APP in settings is NOT used - django-allauth uses SocialApp model
SOCIALACCOUNT_PROVIDERS = {
    'google': {
        'SCOPE': ['profile', 'email'],
        'AUTH_PARAMS': {
            'access_type': 'online',
            'prompt': 'select_account',
        },
        'OAUTH_PKCE_ENABLED': True,
        'FETCH_USERINFO': True,  # Fetch avatar for users with private profile pics
    }
}


# ======================
# DJANGO REST FRAMEWORK
# ======================
REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.AllowAny',
    ],
    'EXCEPTION_HANDLER': 'accounts.exceptions.custom_exception_handler',
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.JSONParser',
        'rest_framework.parsers.FormParser',
        'rest_framework.parsers.MultiPartParser',
    ],
}
