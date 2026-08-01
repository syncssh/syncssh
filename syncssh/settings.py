import os
import sys
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent.parent

DEBUG = os.environ.get('DEBUG', 'False') == 'True'

# In DEBUG mode we tolerate a missing SECRET_KEY so local dev / tests boot.
# In production a missing/empty SECRET_KEY MUST crash the process — a silent
# fallback would let an attacker forge sessions against a known constant.
if DEBUG:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'django-insecure-fallback-dev-only')
else:
    try:
        SECRET_KEY = os.environ['SECRET_KEY']
    except KeyError as exc:
        raise RuntimeError(
            "SECRET_KEY environment variable is required when DEBUG=False."
        ) from exc
    if not SECRET_KEY or SECRET_KEY.startswith('django-insecure'):
        raise RuntimeError(
            "SECRET_KEY must be a strong, non-default value when DEBUG=False."
        )

ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')


# Open-core edition switch. 'cloud' unlocks the commercial features; 'oss' is
# the self-host build. Defaults to 'cloud' so existing deployments keep every
# feature without a config change — the OSS distribution opts out explicitly
# with SYNCSSH_EDITION=oss. FEATURES is the single source of truth consulted
# by syncssh.editions.feature_enabled() and reported to the frontend via /me.
EDITION = os.environ.get('SYNCSSH_EDITION', 'cloud').strip().lower()
if EDITION not in ('oss', 'cloud'):
    EDITION = 'cloud'

_CLOUD_ONLY = EDITION == 'cloud'
FEATURES = {
    # Outbound security webhooks + notification delivery.
    'webhooks': _CLOUD_ONLY,
    # White-label theming of invitation emails.
    'invite_email_theming': _CLOUD_ONLY,
    # Unlimited audit-log history; OSS keeps a rolling window (see editions).
    'audit_unlimited_retention': _CLOUD_ONLY,
}


INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sites',
    'django.contrib.postgres',

    'organizations.apps.OrganizationsConfig',
    'core.apps.CoreConfig',
    'api.apps.ApiConfig',

    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'corsheaders',
]

SITE_ID = 1

# django.contrib.sites row used by allauth in email subjects/bodies
# ("Hello from <name>!"). Without this it stays the default "example.com".
# Synced into the Site table on every migrate (see core.apps). Domain defaults
# to the frontend host so links and branding match the deployment.
SITE_NAME = os.environ.get('SITE_NAME', 'SyncSSH')
SITE_DOMAIN = os.environ.get(
    'SITE_DOMAIN',
    urlparse(os.environ.get('FRONTEND_BASE_URL', 'http://localhost:5173')).netloc,
)

MIDDLEWARE = [
    # Must run before anything that reads the client IP (rate limiting, audit).
    'syncssh.middleware.ClientIPMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    # Serves collected static (admin assets) directly from gunicorn in prod, so
    # no separate static webserver is needed. Must sit right after Security.
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'allauth.account.middleware.AccountMiddleware',
    'syncssh.middleware.RatelimitMiddleware',
    'syncssh.audit.AuditContextMiddleware',
]

# Disable ratelimits during `manage.py test` runs; individual rate-limit tests
# re-enable via @override_settings(RATELIMIT_ENABLE=True).
RATELIMIT_ENABLE = "test" not in sys.argv

ROOT_URLCONF = 'syncssh.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        # Our overrides go in /templates at the repo root. Currently used to
        # provide a styled wrapper around allauth's login/signup pages so
        # anonymous invite-accept doesn't drop visitors into unstyled forms.
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'syncssh.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('DB_NAME', 'syncssh'),
        'USER': os.environ.get('DB_USER', 'postgres'),
        'PASSWORD': os.environ.get('DB_PASSWORD', 'postgres'),
        'HOST': os.environ.get('DB_HOST', 'localhost'),
        'PORT': os.environ.get('DB_PORT', '5432'),
    }
}

# Optional Redis cache for shared rate-limit state across gunicorn workers.
# No-op until REDIS_URL is set: a single worker uses the default per-process
# LocMemCache, which is correct. Set REDIS_URL + run >1 worker to scale out.
_redis_url = os.environ.get('REDIS_URL')
if _redis_url:
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.redis.RedisCache',
            'LOCATION': _redis_url,
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
# collectstatic destination — required in production so gunicorn (via WhiteNoise)
# can serve the Django admin's CSS/JS. Defaults under the repo for dev.
STATIC_ROOT = os.environ.get('STATIC_ROOT', str(BASE_DIR / 'staticfiles'))

EMAIL_BACKEND = os.environ.get(
    'EMAIL_BACKEND',
    'django.core.mail.backends.console.EmailBackend',
)
DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', 'noreply@syncssh.dev')

# SMTP — only consulted when EMAIL_BACKEND is the smtp backend. Point these at
# any provider (Lettermint, SES, Mailgun, Gmail…). Without them the smtp
# backend silently falls back to localhost:25 and drops mail on the floor.
EMAIL_HOST = os.environ.get('EMAIL_HOST', 'localhost')
EMAIL_PORT = int(os.environ.get('EMAIL_PORT', '25'))
EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD', '')
EMAIL_USE_TLS = os.environ.get('EMAIL_USE_TLS', 'True').lower() in ('1', 'true', 'yes')

# Lettermint HTTP API — only consulted when EMAIL_BACKEND is the Lettermint
# backend (syncssh.email_backends.LettermintAPIBackend). Avoids outbound SMTP
# entirely, which some hosts block.
LETTERMINT_TOKEN = os.environ.get('LETTERMINT_TOKEN', '')

# True only when the configured backend actually delivers mail. The console /
# dummy / in-memory backends don't, so signup verification + invite emails
# never reach a real inbox — the dashboard surfaces a warning when this is
# False so an operator doesn't ship a deployment nobody can sign up to. The
# Lettermint backend also can't deliver without its token.
EMAIL_DELIVERY_CONFIGURED = not any(
    marker in EMAIL_BACKEND for marker in ('console', 'dummy', 'locmem')
)
if 'LettermintAPIBackend' in EMAIL_BACKEND and not LETTERMINT_TOKEN:
    EMAIL_DELIVERY_CONFIGURED = False

AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'allauth.account.auth_backends.AuthenticationBackend',
]

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

ACCOUNT_SIGNUP_FIELDS = ['email*', 'username*', 'password1*', 'password2*']
ACCOUNT_EMAIL_VERIFICATION = 'mandatory'
ACCOUNT_LOGIN_ON_EMAIL_CONFIRMATION = True
ACCOUNT_DEFAULT_HTTP_PROTOCOL = os.environ.get('ACCOUNT_DEFAULT_HTTP_PROTOCOL', 'http')
# No "remember me" checkbox: allauth logins get the same persistent session
# (Django's default 2-week cookie) the API LoginView issues, so both login
# paths behave identically.
ACCOUNT_SESSION_REMEMBER = True

# Browser-resolvable URL of the frontend (Vite, :5173). Every post-auth
# redirect — email-confirmation landing, login redirect, the root "/" bounce —
# sends the user's browser here, so it must resolve from the browser, not from
# inside docker. Defaults to localhost for single-host dev.
FRONTEND_BASE_URL = os.environ.get('FRONTEND_BASE_URL', 'http://localhost:5173')
ACCOUNT_EMAIL_CONFIRMATION_URL = f"{FRONTEND_BASE_URL}/login"
# Relative on purpose: /accounts/* is served same-origin with the SPA (Vite
# proxy in dev, Caddy in prod), so after an allauth login the browser should
# stay on whatever host it used (LAN IP, localhost, prod domain) instead of
# being teleported to FRONTEND_BASE_URL's host.
LOGIN_REDIRECT_URL = "/"

_cors_origins = os.environ.get(
    'CORS_ORIGINS',
    'http://localhost:5173,http://127.0.0.1:5173',
).split(',')

CORS_ALLOWED_ORIGINS = _cors_origins
CSRF_TRUSTED_ORIGINS = _cors_origins
CORS_ALLOW_CREDENTIALS = True

# Production hardening — only applied when DEBUG=False so local dev over plain
# HTTP keeps working. Behind a reverse proxy that terminates TLS, the X-Forwarded-Proto
# header tells Django the original request was HTTPS.
if not DEBUG:
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    CSRF_COOKIE_SAMESITE = 'Lax'
    SECURE_SSL_REDIRECT = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    SECURE_REFERRER_POLICY = 'same-origin'
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = 'DENY'
