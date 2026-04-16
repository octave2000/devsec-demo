"""
mupenz_fulgence.audit_logger
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Centralized audit logging for every security-relevant event in the UAS.

Design principles
─────────────────
Single logger
    All audit records flow through 'mupenz_fulgence.audit'.  Production
    deployments route that logger to a dedicated file, syslog, or a log-
    aggregation service (ELK, CloudWatch, Splunk) via settings.LOGGING —
    no code changes required.

Structured key=value format
    Each record is a flat string of key=value pairs so that log aggregators
    (e.g. Logstash, Fluent Bit) can parse fields without custom grok rules:
        event=LOGIN_SUCCESS user=id=7 username='alice' ip=10.0.0.1

Sensitive-data contract  ← CRITICAL
    ✗ Never log raw passwords.
    ✗ Never log password hashes.
    ✗ Never log reset tokens or one-time links.
    ✗ Never log session IDs or cookie values.
    ✓ Log user_id + username only (not email — PII).
    ✓ Log IP addresses for incident response (see note in _get_ip).
    ✓ Log event type, status, and safe contextual metadata.
"""
import logging

_logger = logging.getLogger('mupenz_fulgence.audit')


# ── Event type constants ───────────────────────────────────────────────────────

class AuditEvent:
    """Namespace for audit event type strings used in every log record."""

    # ── Authentication ────────────────────────────────────────────────────────
    REGISTER_SUCCESS         = 'REGISTER_SUCCESS'
    LOGIN_SUCCESS            = 'LOGIN_SUCCESS'
    LOGIN_FAILURE            = 'LOGIN_FAILURE'
    LOGIN_LOCKOUT            = 'LOGIN_LOCKOUT'
    LOGOUT                   = 'LOGOUT'

    # ── Account security ──────────────────────────────────────────────────────
    PASSWORD_CHANGED         = 'PASSWORD_CHANGED'
    PASSWORD_RESET_REQUESTED = 'PASSWORD_RESET_REQUESTED'
    PASSWORD_RESET_COMPLETED = 'PASSWORD_RESET_COMPLETED'

    # ── Authorization ─────────────────────────────────────────────────────────
    ROLE_GRANTED             = 'ROLE_GRANTED'
    ROLE_REVOKED             = 'ROLE_REVOKED'


# ── Internal helpers ───────────────────────────────────────────────────────────

def _get_ip(request) -> str:
    """
    Return the best-effort client IP for logging.

    Checks HTTP_X_FORWARDED_FOR first (populated by reverse proxies such as
    nginx, Caddy, or AWS ALB).  Falls back to REMOTE_ADDR.

    Security note: X-Forwarded-For can be spoofed if the application is not
    behind a trusted proxy that strips client-supplied headers.  This value
    is used for *logging only* and must never be used for access-control
    decisions.
    """
    xff = request.META.get('HTTP_X_FORWARDED_FOR', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', 'unknown')


def _user_label(user) -> str:
    """
    Return a log-safe identifier string for *user*.

    Uses user_id and username — never email (PII), password hash, or any
    session token.  Returns the string 'anonymous' when no authenticated
    user is available (e.g. a login-failure event).
    """
    if user is None or not hasattr(user, 'pk') or user.pk is None:
        return 'anonymous'
    return f'id={user.pk} username={user.username!r}'


# ── Public API ─────────────────────────────────────────────────────────────────

def log_event(event: str, *, request=None, user=None, **extra) -> None:
    """
    Emit a structured audit log entry at INFO level.

    Parameters
    ----------
    event   : str
        One of the AuditEvent constants (e.g. AuditEvent.LOGIN_SUCCESS).
    request : HttpRequest | None
        When provided, the client IP and User-Agent are extracted and
        included in the log record.
    user    : User model instance | None
        The subject of the event.  AnonymousUser and None are handled
        gracefully — both produce 'anonymous' in the output.
    **extra : str | int | bool
        Additional structured key=value pairs for context.

        Allowed examples:
            attempted_username='alice'   (login failure — username is safe)
            groups='Instructor, Student' (role change)
            reason='threshold_reached'   (lockout subtype)

        Forbidden examples — callers MUST NOT pass:
            password=...      raw or hashed password
            token=...         reset or auth token
            session_key=...   session identifier

    Output format
    -------------
    INFO:mupenz_fulgence.audit:event=LOGIN_SUCCESS user=id=7 username='alice' ip=127.0.0.1
    """
    parts = [f'event={event}', f'user={_user_label(user)}']

    if request is not None:
        parts.append(f'ip={_get_ip(request)}')
        ua = request.META.get('HTTP_USER_AGENT', '').strip()
        if ua:
            # Cap at 120 chars — prevents log-line bloat and log-injection
            # via a crafted User-Agent header value.
            parts.append(f'ua={ua[:120]!r}')

    for key, val in extra.items():
        parts.append(f'{key}={val!r}')

    _logger.info(' '.join(parts))
