"""
Django settings for Farmity project.
"""

from pathlib import Path
import os

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Security
SECRET_KEY = os.environ.get(
    'SECRET_KEY',
    'django-insecure-change-this-in-production'
)

DEBUG = True

ALLOWED_HOSTS = ['127.0.0.1', 'localhost']


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

    'rest_framework',
    'accounts',
]


# ======================
# MIDDLEWARE
# ======================
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
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
            ],
        },
    },
]

WSGI_APPLICATION = 'Farmity.wsgi.application'


# ======================
# DATABASE
# ======================
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# ======================
# CUSTOM USER MODEL (CORRECT)
# ======================
AUTH_USER_MODEL = 'accounts.User'


# 🔥 THIS WAS MISSING (VERY IMPORTANT)
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
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
# DEFAULT PRIMARY KEY
# ======================
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# ======================
# EMAIL (DEV)
# ======================
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'


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
