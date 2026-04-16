"""
mupenz_fulgence.signals
~~~~~~~~~~~~~~~~~~~~~~~~
Django signal handlers for the User Authentication Service.

Responsibilities
────────────────
Profile management
    Auto-create / auto-save a Profile row whenever a User is saved.

Audit logging (via audit_logger.py)
    Hook into Django's built-in auth signals to record security events
    without modifying the built-in authentication machinery:

    django.contrib.auth.signals.user_logged_in   → LOGIN_SUCCESS
    django.contrib.auth.signals.user_logged_out  → LOGOUT
    django.contrib.auth.signals.user_login_failed → LOGIN_FAILURE

    django.db.models.signals.m2m_changed (User.groups) → ROLE_GRANTED
                                                        / ROLE_REVOKED

Why signals for login/logout?
    Django fires user_logged_in inside auth.login() and user_logged_out
    inside auth.logout().  Using signals means the audit record is emitted
    regardless of which view, third-party package, or management command
    triggers authentication — we cannot miss an event.

Why signals for group changes?
    Group membership can be modified via user.groups.add/remove/set, the
    Django admin, or management commands.  The m2m_changed signal fires for
    ALL of these paths so audit coverage is complete.

Note on login failures
    user_login_failed fires inside django.contrib.auth.authenticate() when
    no authentication backend succeeds.  At that point Django has already
    replaced the raw password in the credentials dict with the string
    '********************', so logging credentials['username'] is safe.
"""
from django.contrib.auth.models import User
from django.contrib.auth.signals import (
    user_logged_in,
    user_logged_out,
    user_login_failed,
)
from django.db.models.signals import m2m_changed, post_save
from django.dispatch import receiver

from .audit_logger import AuditEvent, log_event
from .models import Profile


# ── Profile management ─────────────────────────────────────────────────────────

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """Automatically create a Profile row whenever a new User is saved."""
    if created:
        Profile.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """Keep the Profile row in sync whenever the User row is updated."""
    if hasattr(instance, 'profile'):
        instance.profile.save()


# ── Audit: authentication events ──────────────────────────────────────────────

@receiver(user_logged_in)
def on_user_logged_in(sender, request, user, **kwargs):
    """
    Fired by django.contrib.auth.login() on every successful authentication.
    Covers the login form and any other code path that calls auth.login().
    """
    log_event(AuditEvent.LOGIN_SUCCESS, request=request, user=user)


@receiver(user_logged_out)
def on_user_logged_out(sender, request, user, **kwargs):
    """
    Fired by django.contrib.auth.logout() before the session is flushed.
    'user' may be AnonymousUser if the session was already invalid — the
    _user_label() helper handles that gracefully, emitting 'anonymous'.
    """
    log_event(AuditEvent.LOGOUT, request=request, user=user)


@receiver(user_login_failed)
def on_user_login_failed(sender, credentials, request, **kwargs):
    """
    Fired by django.contrib.auth.authenticate() when every backend rejects
    the supplied credentials.

    Sensitive-data note:
    Django replaces credentials['password'] with '********************'
    before dispatching this signal, so it is safe to read credentials here.
    We log only the attempted username — never the (already-redacted) password.
    """
    attempted_username = credentials.get('username', 'unknown')
    log_event(
        AuditEvent.LOGIN_FAILURE,
        request=request,
        user=None,
        attempted_username=attempted_username,
    )


# ── Audit: role / group changes ────────────────────────────────────────────────

@receiver(m2m_changed, sender=User.groups.through)
def on_group_membership_changed(sender, instance, action, pk_set, **kwargs):
    """
    Fired whenever a User's group membership changes via the Django ORM:
        user.groups.add(group)
        user.groups.remove(group)
        user.groups.set([...])
        user.groups.clear()
        group.user_set.add(user)  ← note: instance is the Group here

    Only 'post_add' and 'post_remove' are handled — 'pre_' variants fire
    before the database write and are not suitable for audit purposes.

    'instance' is the source side of the M2M relation.  When accessed via
    user.groups.*, instance is a User.  When accessed via group.user_set.*,
    instance is a Group — we skip that direction to avoid double-logging
    (the same DB write fires both orientations).
    """
    if action not in ('post_add', 'post_remove'):
        return
    if not pk_set:
        return
    # Only handle the User-as-instance direction to avoid duplicate records.
    if not isinstance(instance, User):
        return

    from django.contrib.auth.models import Group  # local import avoids circular
    event = AuditEvent.ROLE_GRANTED if action == 'post_add' else AuditEvent.ROLE_REVOKED
    group_names = ', '.join(
        sorted(Group.objects.filter(pk__in=pk_set).values_list('name', flat=True))
    )
    log_event(event, user=instance, groups=group_names)
