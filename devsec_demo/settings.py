"""
Django settings for devsec_demo project.

Environment-aware configuration: all sensitive values are read from
environment variables (via python-dotenv in development, or the host
environment in production).  See .env.example for the full variable list.

Deployment checklist:
  https://docs.djangoproject.com/en/6.0/howto/deployment/checklist/
"""
import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured
from dotenv import load_dotenv

load_dotenv()

# ── Paths ──────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent


# ── Environment detection ──────────────────────────────────────────────────
# DJANGO_DEBUG must be explicitly set to the string "True" to enable debug
# mode.  Any other value (including absence) results in DEBUG=False, which
# is the correct default for production.
#
# WHY: Django's own docs warn "never deploy a site into production with
# DEBUG turned on."  DEBUG=True leaks stack traces, SQL queries, and local
# variables to any browser that triggers an error.
DEBUG = os.environ.get('DJANGO_DEBUG', 'False') == 'True'


# ── Secret key ────────────────────────────────────────────────────────────
# The secret key signs sessions, CSRF tokens, password-reset links, and
# other security-sensitive data.  Exposure or predictability of this value
# compromises all of those mechanisms simultaneously.
#
# Production  : DJANGO_SECRET_KEY MUST be set in the environment.
#               If it is absent, startup fails loudly — a silent None would
#               make the app appear to work while accepting forged tokens.
# Development : If not set, a well-marked insecure fallback is used so
#               local dev works out of the box without touching .env.
_secret_key_env = os.environ.get('DJANGO_SECRET_KEY', '').strip()
if not _secret_key_env:
    if DEBUG:
        # Insecure development-only fallback — deliberately ugly so it is
        # never accidentally used in a production deployment.
        _secret_key_env = (
            'django-insecure-DEV-ONLY-do-not-use-in-production-00000000000000'
        )
    else:
        raise ImproperlyConfigured(
            "DJANGO_SECRET_KEY environment variable is not set. "
            "This is required in production. "
            "Generate one with: python -c \"from django.core.management.utils "
            "import get_random_secret_key; print(get_random_secret_key())\""
        )

SECRET_KEY = _secret_key_env


# ── Allowed hosts ─────────────────────────────────────────────────────────
# ALLOWED_HOSTS guards against HTTP Host header injection attacks.
#
# Production  : Set DJANGO_ALLOWED_HOSTS to a comma-separated list of the
#               domains / IP addresses that will receive traffic
#               (e.g. "example.com,www.example.com").  A wildcard ("*") is
#               explicitly rejected because it defeats the protection.
# Development : Falls back to localhost/loopback only.
#
# WHY no wildcard: an attacker who can forge the Host header can poison
# password-reset links and cache-poisoning attacks; explicit hosts prevent
# this entirely.
_allowed_hosts_env = os.environ.get('DJANGO_ALLOWED_HOSTS', '').strip()
if _allowed_hosts_env:
    ALLOWED_HOSTS = [h.strip() for h in _allowed_hosts_env.split(',') if h.strip()]
    if '*' in ALLOWED_HOSTS:
        raise ImproperlyConfigured(
            "Wildcard '*' in DJANGO_ALLOWED_HOSTS is not permitted. "
            "Specify explicit hostnames instead."
        )
elif DEBUG:
    # Safe localhost-only defaults for local development
    ALLOWED_HOSTS = ['localhost', '127.0.0.1', '[::1]']
else:
    raise ImproperlyConfigured(
        "DJANGO_ALLOWED_HOSTS must be set in production. "
        "Provide a comma-separated list of valid hostnames."
    )


# ── Application definition ─────────────────────────────────────────────────

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # User Authentication Service
    'mupenz_fulgence',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'devsec_demo.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                # RBAC: injects user_role, is_instructor, is_staff_member, is_admin
                'mupenz_fulgence.context_processors.user_roles',
            ],
        },
    },
]

WSGI_APPLICATION = 'devsec_demo.wsgi.application'


# ── Database ───────────────────────────────────────────────────────────────
# Credentials are read from environment variables — never hardcoded.
#
# Development default: SQLite (zero-configuration, single file).
# Production recommendation: PostgreSQL or MySQL.
#   Set DJANGO_DB_ENGINE, DJANGO_DB_NAME, DJANGO_DB_USER, DJANGO_DB_PASSWORD,
#   DJANGO_DB_HOST, and DJANGO_DB_PORT as needed.
#
# WHY: Hardcoded database passwords in source code are exposed to anyone
# with repository access (current or historical), including after rotation.
DATABASES = {
    'default': {
        'ENGINE': os.environ.get(
            'DJANGO_DB_ENGINE',
            'django.db.backends.sqlite3',
        ),
        'NAME': os.environ.get(
            'DJANGO_DB_NAME',
            str(BASE_DIR / 'db.sqlite3'),
        ),
        'USER':     os.environ.get('DJANGO_DB_USER', ''),
        'PASSWORD': os.environ.get('DJANGO_DB_PASSWORD', ''),
        'HOST':     os.environ.get('DJANGO_DB_HOST', ''),
        'PORT':     os.environ.get('DJANGO_DB_PORT', ''),
    }
}


# ── Password validation ────────────────────────────────────────────────────

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# ── Internationalization ───────────────────────────────────────────────────

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True


# ── Static & media files ───────────────────────────────────────────────────
# STATIC_ROOT is required for `manage.py collectstatic` in production.
# Point your web server (Nginx/Apache) at this directory.
#
# MEDIA_ROOT stores user uploads.  Documents are never served via MEDIA_URL;
# they are only accessible through DocumentServeView, which enforces
# per-user ownership.  In production, configure your web server to:
#   • Serve MEDIA_ROOT/avatars/ directly (public, cache-friendly).
#   • Deny all direct requests to MEDIA_ROOT/documents/ — route them
#     through Django so ownership checks are enforced.
STATIC_URL  = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'

MEDIA_URL  = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# ── Upload size limits ─────────────────────────────────────────────────────
# In-memory upload threshold and maximum request body size.
# Per-type security limits (extension whitelist, magic bytes) are enforced
# in validators.py — these are the coarse Django-level caps.
FILE_UPLOAD_MAX_MEMORY_SIZE = 2 * 1024 * 1024    # 2 MB in-memory threshold
DATA_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024   # 10 MB max request body


# ═══════════════════════════════════════════════════════════════════════════
# SECURITY SETTINGS
# ═══════════════════════════════════════════════════════════════════════════
# All settings in this section are active in production (DEBUG=False) and
# disabled/relaxed in development (DEBUG=True) to keep local dev convenient.
# The DEBUG flag is the single control point — set it correctly per env.


# ── Clickjacking protection ────────────────────────────────────────────────
# X-Frame-Options: DENY prevents this site from being embedded in any
# <iframe> or <frame>, eliminating UI redress (clickjacking) attacks.
#
# WHY DENY over SAMEORIGIN: the app has no legitimate iframing use case even
# on the same origin, so the stricter value is preferable.
X_FRAME_OPTIONS = 'DENY'


# ── MIME-type sniffing protection ─────────────────────────────────────────
# Instructs browsers NOT to sniff the Content-Type of responses.
# Without this, a browser might execute an uploaded file (e.g. an HTML file
# saved with a .txt extension) as HTML, enabling stored-XSS-style attacks.
#
# Sends: X-Content-Type-Options: nosniff
SECURE_CONTENT_TYPE_NOSNIFF = True


# ── Referrer policy ───────────────────────────────────────────────────────
# Controls how much URL information is included in the Referer header when
# navigating away from this site.  "strict-origin-when-cross-origin" sends
# the full path for same-origin requests but only the origin for
# cross-origin ones, preventing accidental leakage of path-encoded tokens
# (e.g. password-reset links appearing in third-party server logs).
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'


# ── Cookie security ────────────────────────────────────────────────────────
# SESSION_COOKIE_SECURE / CSRF_COOKIE_SECURE
#   Instruct the browser to send these cookies only over HTTPS connections.
#   If True on a plain HTTP connection, the cookies are never sent and the
#   app breaks — which is why these are False in DEBUG mode (HTTP dev server).
#
# SESSION_COOKIE_HTTPONLY
#   Prevents JavaScript from reading the session cookie via document.cookie.
#   This is Django's default (True), but we set it explicitly so the intent
#   is visible and auditable.  Mitigates XSS-based session hijacking.
#
# SESSION_COOKIE_SAMESITE / CSRF_COOKIE_SAMESITE
#   'Lax'  — cookies are sent on same-site requests AND top-level cross-site
#             navigations (GET).  This is the recommended value: it blocks
#             most CSRF vectors while keeping OAuth-style redirects working.
#   'Strict' would break OAuth and any link-based login flows.
#   'None'   would require Secure=True and re-enable cross-site sending.
#
# WHY these matter together: an attacker who can read your cookie (XSS) or
# forge cross-site requests (CSRF) can act as the victim user.  HttpOnly
# defeats cookie theft via XSS; Secure defeats cookie theft via network
# sniffing; SameSite defeats CSRF by restricting when cookies are attached.
SESSION_COOKIE_SECURE   = not DEBUG   # True in production, False in dev
SESSION_COOKIE_HTTPONLY = True        # Always on — JS never needs the session id
SESSION_COOKIE_SAMESITE = 'Lax'      # Blocks CSRF without breaking OAuth flows
SESSION_COOKIE_AGE      = 1209600     # 2 weeks (Django default) — explicit for auditability

CSRF_COOKIE_SECURE   = not DEBUG      # True in production, False in dev
CSRF_COOKIE_HTTPONLY = False          # Must stay False: JS reads it to send the token
CSRF_COOKIE_SAMESITE = 'Lax'


# ── Transport security (HTTPS) ─────────────────────────────────────────────
# SECURE_SSL_REDIRECT
#   Django redirects every non-HTTPS request to HTTPS.  Disabled in
#   development because runserver uses plain HTTP.
#
# SECURE_HSTS_SECONDS
#   Sends Strict-Transport-Security with max-age = this many seconds.
#   Once a browser has seen this header it will refuse plain HTTP connections
#   to this site for the max-age period, even if the user types "http://".
#
#   31 536 000 = 1 year — the value recommended for HSTS preload eligibility.
#
#   ⚠️  HSTS has a ramp-up period: start with a short value (e.g. 3600),
#       confirm everything works over HTTPS, then increase to 31 536 000.
#       An incorrect HSTS setting can lock users out of your site for the
#       entire max-age period.
#
# SECURE_HSTS_INCLUDE_SUBDOMAINS
#   Extends HSTS to all subdomains of this domain.  Enable only if ALL
#   subdomains are also served over HTTPS.
#
# SECURE_HSTS_PRELOAD
#   Adds the `preload` directive.  Required to submit the domain to
#   browser HSTS preload lists (hardcoded HTTPS enforcement, no first-visit
#   vulnerability).  Only enable after testing with a long HSTS max-age.
#
# WHY: HTTPS-only transport prevents session cookies and CSRF tokens from
# being intercepted on the network, making Secure cookies actually effective.
SECURE_SSL_REDIRECT          = not DEBUG    # True in production, False in dev
SECURE_HSTS_SECONDS          = 0 if DEBUG else int(
    os.environ.get('DJANGO_HSTS_SECONDS', 31_536_000)   # 1 year default
)
SECURE_HSTS_INCLUDE_SUBDOMAINS = not DEBUG
SECURE_HSTS_PRELOAD            = not DEBUG

# Tells Django's SecurityMiddleware that a TLS-terminating proxy (Nginx,
# load balancer) signals HTTPS via this header.  Required when SSL is
# terminated upstream, otherwise SECURE_SSL_REDIRECT causes redirect loops.
# Only trust this header if your proxy actually sets it (and strips it from
# incoming client requests to prevent spoofing).
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')


# ═══════════════════════════════════════════════════════════════════════════
# APPLICATION-SPECIFIC SETTINGS
# ═══════════════════════════════════════════════════════════════════════════

# ── Authentication routing ─────────────────────────────────────────────────
LOGIN_REDIRECT_URL  = '/auth/'
LOGOUT_REDIRECT_URL = '/auth/login/'
LOGIN_URL           = '/auth/login/'


# ── Cache ──────────────────────────────────────────────────────────────────
# Development default: in-process LocMemCache (no external server needed).
# Production / multi-process: set DJANGO_CACHE_BACKEND and
# DJANGO_CACHE_LOCATION to a shared Redis or Memcached instance so that
# login-lockout state is consistent across all worker processes.
CACHES = {
    'default': {
        'BACKEND': os.environ.get(
            'DJANGO_CACHE_BACKEND',
            'django.core.cache.backends.locmem.LocMemCache',
        ),
        'LOCATION': os.environ.get('DJANGO_CACHE_LOCATION', 'mf-auth-cache'),
    }
}


# ── Login brute-force protection ──────────────────────────────────────────
LOGIN_MAX_ATTEMPTS    = int(os.environ.get('LOGIN_MAX_ATTEMPTS',    5))
LOGIN_LOCKOUT_DURATION = int(os.environ.get('LOGIN_LOCKOUT_DURATION', 900))   # 15 min
LOGIN_ATTEMPT_WINDOW  = int(os.environ.get('LOGIN_ATTEMPT_WINDOW',   900))    # 15 min


# ── Email ──────────────────────────────────────────────────────────────────
# Development default: prints emails to the console (no SMTP needed).
# Production: set DJANGO_EMAIL_BACKEND to an SMTP or transactional backend
# and DJANGO_DEFAULT_FROM_EMAIL to a deliverable address.
EMAIL_BACKEND = os.environ.get(
    'DJANGO_EMAIL_BACKEND',
    'django.core.mail.backends.console.EmailBackend',
)
DEFAULT_FROM_EMAIL = os.environ.get(
    'DJANGO_DEFAULT_FROM_EMAIL',
    'noreply@mf-auth.local',
)


# ── Password reset token validity ─────────────────────────────────────────
# Tokens expire after 1 hour.  Limits the window during which an intercepted
# link remains exploitable.  Tokens are also single-use (password hash is
# an HMAC input, so it changes the moment the password is reset).
PASSWORD_RESET_TIMEOUT = 3600   # 1 hour


# ── Default primary key field ──────────────────────────────────────────────
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
