"""
Django settings for Farmity project.
"""

from pathlib import Path
from datetime import timedelta
import os

import dj_database_url


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

DEBUG = os.environ.get('DEBUG', 'true').lower() in ('1', 'true', 'yes', 'on')


def _split_csv_env(name, default=''):
    raw = os.environ.get(name, default) or ''
    return [item.strip() for item in raw.split(',') if item.strip()]


# Host list should contain hostnames only (no scheme)
ALLOWED_HOSTS = _split_csv_env(
    'ALLOWED_HOSTS',
    '127.0.0.1,localhost,nabin-regmi-farmity.onrender.com,.onrender.com'
)

# CSRF requires full origins (with scheme)
CSRF_TRUSTED_ORIGINS = _split_csv_env(
    'CSRF_TRUSTED_ORIGINS',
    'http://127.0.0.1:8000,http://localhost:8000,https://nabin-regmi-farmity.onrender.com'
)

# Render/Proxy HTTPS handling
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
USE_X_FORWARDED_HOST = True

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
    'django.contrib.humanize',
    'rest_framework',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.google',
    'channels',
    'accounts',
]

SITE_ID = 1


# ======================
# MIDDLEWARE
# ======================
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
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
# ASGI CONFIGURATION FOR REAL-TIME FEATURES
# ======================
ASGI_APPLICATION = 'Farmity.asgi.application'

# Channels configuration
CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels_redis.core.RedisChannelLayer',
        'CONFIG': {
            'hosts': [('127.0.0.1', 6379)],
        },
    },
}

# Redis configuration for real-time features
REDIS_URL = os.environ.get('REDIS_URL', 'redis://127.0.0.1:6379/0')


# ======================
# DATABASE
# ======================
# One default database at a time (Django does not use two DBs for the same app in parallel).
#
# Local dev (SQLite): Google OAuth, OTP, email — use db.sqlite3. Omit DATABASE_URL from .env, or set
# USE_LOCAL_SQLITE=true if DATABASE_URL is present but you still want SQLite (e.g. copied Render env).
#
# Render: set DATABASE_URL from PostgreSQL. Do not set USE_LOCAL_SQLITE. Render also sets RENDER=true.
_use_local_sqlite = os.environ.get('USE_LOCAL_SQLITE', '').lower() in ('1', 'true', 'yes')
_on_render = os.environ.get('RENDER', '').lower() in ('1', 'true', 'yes')
_database_url = (os.environ.get('DATABASE_URL') or '').strip()
_use_postgres = bool(_database_url) and (not _use_local_sqlite or _on_render)

# if _use_postgres:
#     DATABASES = {
#         'default': dj_database_url.config(
#             conn_max_age=600,
#             ssl_require=os.environ.get('DATABASE_SSL_REQUIRE', 'true').lower()
#             in ('1', 'true', 'yes'),
#         )
#     }
# else:
#     DATABASES = {
#         'default': {
#             'ENGINE': 'django.db.backends.sqlite3',
#             'NAME': BASE_DIR / 'db.sqlite3',
#         }
#     }

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'farmity_db',
        'USER': 'postgres',
        'PASSWORD': '1234',
        'HOST': 'localhost',
        'PORT': '5432'
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

# Celery Configuration (moved here to use TIME_ZONE)
CELERY_BROKER_URL = REDIS_URL
CELERY_RESULT_BACKEND = REDIS_URL
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = TIME_ZONE


# ======================
# STATIC FILES (FIXED)
# ======================
STATIC_URL = '/static/'   # 🔥 must start & end with /
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_STORAGE = 'whitenoise.storage.CompressedStaticFilesStorage'

if not DEBUG:
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    # HSTS: enable only when the whole site is served over HTTPS (e.g. Render with custom domain).
    SECURE_HSTS_SECONDS = int(os.environ.get('SECURE_HSTS_SECONDS', '31536000'))
    SECURE_HSTS_INCLUDE_SUBDOMAINS = os.environ.get(
        'SECURE_HSTS_INCLUDE_SUBDOMAINS', 'false'
    ).lower() in ('1', 'true', 'yes')

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
# If Django sees http://127.0.0.1 but eSewa must redirect to a public HTTPS URL (ngrok / production),
# set this to that origin, e.g. https://yourdomain.com or https://xxxx.ngrok-free.app (no trailing slash).
# Without this, eSewa may send users to failure/cancel because it cannot reach your success_url, or the bank app may block non-HTTPS redirects.
ESEWA_PUBLIC_BASE_URL = os.environ.get('ESEWA_PUBLIC_BASE_URL', '').strip().rstrip('/')

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

# JWT lifetimes for tokens returned by login / verify-otp (djangorestframework-simplejwt)
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(
        minutes=int(os.environ.get('JWT_ACCESS_TOKEN_MINUTES', '60'))
    ),
    'REFRESH_TOKEN_LIFETIME': timedelta(
        days=int(os.environ.get('JWT_REFRESH_TOKEN_DAYS', '7'))
    ),
    'SIGNING_KEY': SECRET_KEY,
}
