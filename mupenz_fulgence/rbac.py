"""
mupenz_fulgence.rbac
~~~~~~~~~~~~~~~~~~~~
Reusable mixins and decorators that enforce role-based access control
on top of Django's built-in authentication layer.

Role hierarchy (lowest → highest privilege):
    anonymous  →  user  →  student  →  instructor  →  staff  →  admin

Design principles:
  - Unauthenticated requests are redirected to login (never shown a 403).
  - Authenticated requests that lack the required role receive HTTP 403.
  - All checks are server-side; templates only consume the results.
"""
from functools import wraps

from django.contrib.auth.mixins import UserPassesTestMixin
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect
from django.urls import reverse_lazy


# ── Role helpers ───────────────────────────────────────────────────────────────

def is_student(user):
    """
    Return True for Student group members and everyone with higher privilege
    (instructor, staff, admin).  Students are the lowest authenticated role.
    """
    return user.is_authenticated and (
        user.is_staff
        or user.is_superuser
        or user.groups.filter(name__in=['Student', 'Instructor']).exists()
    )


def is_instructor(user):
    """
    Return True when the user has at least instructor-level access:
    members of the 'Instructor' group, staff, or superusers.
    """
    return user.is_authenticated and (
        user.is_staff
        or user.is_superuser
        or user.groups.filter(name='Instructor').exists()
    )


def is_staff_or_admin(user):
    """Return True for users with is_staff=True or is_superuser=True."""
    return user.is_authenticated and (user.is_staff or user.is_superuser)


def is_admin(user):
    """Return True for superusers only."""
    return user.is_authenticated and user.is_superuser


def get_user_role(user):
    """
    Return a single string label for the user's highest role.
    Used by the context processor and admin display helpers.
    """
    if not user.is_authenticated:
        return 'anonymous'
    if user.is_superuser:
        return 'admin'
    if user.is_staff:
        return 'staff'
    if user.groups.filter(name='Instructor').exists():
        return 'instructor'
    if user.groups.filter(name='Student').exists():
        return 'student'
    return 'user'


# ── CBV Mixins ─────────────────────────────────────────────────────────────────

class _RoleCheckMixin(UserPassesTestMixin):
    """
    Base mixin shared by all role-gate mixins.

    Behaviour:
      - Not logged in  → redirect to login with ?next= preserved.
      - Logged in but lacking role  → raise PermissionDenied (HTTP 403).
    """
    login_url = reverse_lazy('mupenz_fulgence:login')

    def handle_no_permission(self):
        if not self.request.user.is_authenticated:
            return redirect(f'{self.login_url}?next={self.request.path}')
        raise PermissionDenied


class StudentRequiredMixin(_RoleCheckMixin):
    """Allow Student group members, instructors, staff, and admins."""

    def test_func(self):
        return is_student(self.request.user)


class InstructorRequiredMixin(_RoleCheckMixin):
    """Allow Instructor group members, staff, and admins."""

    def test_func(self):
        return is_instructor(self.request.user)


class StaffRequiredMixin(_RoleCheckMixin):
    """Allow staff (is_staff=True) and superusers only."""

    def test_func(self):
        return is_staff_or_admin(self.request.user)


class AdminRequiredMixin(_RoleCheckMixin):
    """Allow superusers only."""

    def test_func(self):
        return is_admin(self.request.user)


# ── FBV Decorators ─────────────────────────────────────────────────────────────

def _make_decorator(test_fn):
    """
    Factory that wraps a boolean user-test function into an FBV decorator.
    Applies the same redirect / 403 logic as _RoleCheckMixin.
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                login = reverse_lazy('mupenz_fulgence:login')
                return redirect(f'{login}?next={request.path}')
            if not test_fn(request.user):
                raise PermissionDenied
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


student_required    = _make_decorator(is_student)
instructor_required = _make_decorator(is_instructor)
staff_required      = _make_decorator(is_staff_or_admin)
admin_required      = _make_decorator(is_admin)
