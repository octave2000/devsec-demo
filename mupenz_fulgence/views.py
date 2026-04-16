from django.contrib import messages
from django.contrib.auth import views as auth_views
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import Group, User
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse_lazy
from django.views.generic import CreateView, ListView, TemplateView, UpdateView

from .forms import ProfileUpdateForm, RegistrationForm
from .models import Profile
from .rbac import (
    AdminRequiredMixin,
    InstructorRequiredMixin,
    StaffRequiredMixin,
    get_user_role,
    is_staff_or_admin,
)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

class RegisterView(CreateView):
    """
    Handles new user sign-up.
    Redirects already-authenticated users straight to the dashboard.
    On success, redirects to the login page with a confirmation message.
    """
    model = User
    form_class = RegistrationForm
    template_name = 'mupenz_fulgence/registration/register.html'
    success_url = reverse_lazy('mupenz_fulgence:login')

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect(reverse_lazy('mupenz_fulgence:dashboard'))
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(
            self.request,
            f'Account created for "{self.object.username}". You can now sign in.',
        )
        return response

    def form_invalid(self, form):
        messages.error(
            self.request,
            'Registration failed. Please correct the errors below.',
        )
        return super().form_invalid(form)


# ---------------------------------------------------------------------------
# Login / Logout — thin wrappers around Django's built-in auth views
# ---------------------------------------------------------------------------

class UserLoginView(auth_views.LoginView):
    """
    Authenticates users via Django's built-in LoginView.
    Redirects already-authenticated users away from the login page.
    """
    template_name = 'mupenz_fulgence/registration/login.html'
    redirect_authenticated_user = True

    def form_valid(self, form):
        user = form.get_user()
        name = user.get_short_name() or user.username
        messages.success(self.request, f'Welcome back, {name}!')
        return super().form_valid(form)

    def form_invalid(self, form):
        messages.error(
            self.request,
            'Invalid username or password. Please try again.',
        )
        return super().form_invalid(form)


class UserLogoutView(auth_views.LogoutView):
    """
    Logs the user out (POST only — Django 5+ requirement).
    Adds a farewell message before the session is flushed.
    The message survives because FallbackStorage writes to a cookie first.
    """
    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            messages.info(request, 'You have been logged out. See you soon!')
        return super().post(request, *args, **kwargs)


# ---------------------------------------------------------------------------
# Dashboard (protected)
# ---------------------------------------------------------------------------

class DashboardView(LoginRequiredMixin, TemplateView):
    """
    Home page for authenticated users — shows account and profile summary.
    """
    template_name = 'mupenz_fulgence/dashboard.html'
    login_url = reverse_lazy('mupenz_fulgence:login')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # get_or_create is a safety net for superusers created before the app
        profile, _ = Profile.objects.get_or_create(user=self.request.user)
        context['profile'] = profile
        return context


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------

class ProfileView(LoginRequiredMixin, UpdateView):
    """
    Lets the authenticated user view and update their profile.
    Always operates on the currently logged-in user's profile.
    """
    model = Profile
    form_class = ProfileUpdateForm
    template_name = 'mupenz_fulgence/profile.html'
    login_url = reverse_lazy('mupenz_fulgence:login')
    success_url = reverse_lazy('mupenz_fulgence:profile')

    def get_object(self, queryset=None):
        # Safety net: create the profile on-the-fly if it doesn't exist
        profile, _ = Profile.objects.get_or_create(user=self.request.user)
        return profile

    def form_valid(self, form):
        messages.success(self.request, 'Your profile has been updated successfully.')
        return super().form_valid(form)

    def form_invalid(self, form):
        messages.error(self.request, 'Update failed. Please correct the errors below.')
        return super().form_invalid(form)


# ---------------------------------------------------------------------------
# Password Change
# ---------------------------------------------------------------------------

class UserPasswordChangeView(LoginRequiredMixin, auth_views.PasswordChangeView):
    """
    Allows authenticated users to change their password.
    Django's built-in implementation calls update_session_auth_hash()
    automatically, so the user stays logged in after the change.
    """
    template_name = 'mupenz_fulgence/registration/password_change.html'
    login_url = reverse_lazy('mupenz_fulgence:login')
    success_url = reverse_lazy('mupenz_fulgence:dashboard')

    def form_valid(self, form):
        messages.success(self.request, 'Your password has been changed successfully.')
        return super().form_valid(form)

    def form_invalid(self, form):
        messages.error(
            self.request,
            'Password change failed. Please review the errors below.',
        )
        return super().form_invalid(form)


# ---------------------------------------------------------------------------
# Custom 403 handler
# ---------------------------------------------------------------------------

def permission_denied_view(request, exception=None):
    """Renders a styled 403 page instead of Django's plain default."""
    return render(request, '403.html', status=403)


# ---------------------------------------------------------------------------
# RBAC — Instructor Panel  (Instructor group | staff | admin)
# ---------------------------------------------------------------------------

class InstructorPanelView(InstructorRequiredMixin, TemplateView):
    """
    Accessible to Instructor group members, staff, and admins.
    Shows a read-only overview of registered users.
    """
    template_name = 'mupenz_fulgence/instructor_panel.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['total_users'] = User.objects.filter(is_active=True).count()
        context['recent_users'] = (
            User.objects.filter(is_active=True)
            .order_by('-date_joined')[:8]
        )
        return context


# ---------------------------------------------------------------------------
# RBAC — Staff Dashboard  (staff | admin)
# ---------------------------------------------------------------------------

class StaffDashboardView(StaffRequiredMixin, TemplateView):
    """
    Management overview for staff and admins.
    Shows user counts broken down by role plus recent registrations.
    """
    template_name = 'mupenz_fulgence/staff_dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        instructor_group = Group.objects.filter(name='Instructor').first()
        student_group    = Group.objects.filter(name='Student').first()
        instructor_ids = set(
            instructor_group.user_set.values_list('id', flat=True)
            if instructor_group else []
        )
        student_ids = set(
            student_group.user_set.values_list('id', flat=True)
            if student_group else []
        )

        context['total_users']       = User.objects.count()
        context['total_active']      = User.objects.filter(is_active=True).count()
        context['total_staff']       = User.objects.filter(is_staff=True, is_superuser=False).count()
        context['total_admins']      = User.objects.filter(is_superuser=True).count()
        context['total_instructors'] = len(instructor_ids)
        context['total_students']    = len(student_ids)
        context['total_regular']     = (
            User.objects.filter(is_staff=False, is_superuser=False)
            .exclude(id__in=instructor_ids | student_ids)
            .count()
        )
        context['recent_users'] = (
            User.objects.order_by('-date_joined')
            .prefetch_related('groups')[:10]
        )
        return context


# ---------------------------------------------------------------------------
# RBAC — User List  (staff | admin)
# ---------------------------------------------------------------------------

class UserListView(StaffRequiredMixin, ListView):
    """
    Paginated, searchable list of all users with their computed roles.
    Accessible to staff and admins only.
    """
    model = User
    template_name = 'mupenz_fulgence/user_list.html'
    context_object_name = 'users'
    paginate_by = 20

    _ROLE_BADGE = {
        'admin':      'danger',
        'staff':      'warning',
        'instructor': 'info',
        'student':    'success',
        'user':       'secondary',
    }

    def get_queryset(self):
        qs = (
            User.objects.order_by('-date_joined')
            .prefetch_related('groups')
            .select_related('profile')
        )
        q = self.request.GET.get('q', '').strip()
        if q:
            qs = qs.filter(
                Q(username__icontains=q)
                | Q(email__icontains=q)
                | Q(first_name__icontains=q)
                | Q(last_name__icontains=q)
            )
        return qs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Annotate each user with a pre-computed role (groups already prefetched)
        group_pks = {
            name: pk for name, pk in
            Group.objects.filter(name__in=['Instructor', 'Student'])
            .values_list('name', 'pk')
        }
        instructor_pk = group_pks.get('Instructor')
        student_pk    = group_pks.get('Student')

        for u in context['users']:
            if u.is_superuser:
                role = 'admin'
            elif u.is_staff:
                role = 'staff'
            else:
                user_group_pks = {g.pk for g in u.groups.all()}
                if instructor_pk and instructor_pk in user_group_pks:
                    role = 'instructor'
                elif student_pk and student_pk in user_group_pks:
                    role = 'student'
                else:
                    role = 'user'
            u.computed_role    = role
            u.role_badge_class = self._ROLE_BADGE[role]
            # Profile pk for the detail-view link; None when profile absent
            try:
                u.profile_pk = u.profile.pk
            except Profile.DoesNotExist:
                u.profile_pk = None
        context['search_query'] = self.request.GET.get('q', '')
        return context


# ---------------------------------------------------------------------------
# RBAC — Admin Dashboard  (superuser only)
# ---------------------------------------------------------------------------

class AdminDashboardView(AdminRequiredMixin, TemplateView):
    """
    Full system overview for superusers only.
    """
    template_name = 'mupenz_fulgence/admin_dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['total_users']    = User.objects.count()
        context['total_staff']    = User.objects.filter(is_staff=True).count()
        context['total_admins']   = User.objects.filter(is_superuser=True).count()
        context['total_inactive'] = User.objects.filter(is_active=False).count()
        groups = list(Group.objects.prefetch_related('user_set', 'permissions'))
        for g in groups:
            g.member_count = g.user_set.count()
        context['groups'] = groups
        context['recent_users'] = User.objects.order_by('-date_joined')[:5]
        return context


# ---------------------------------------------------------------------------
# IDOR / Broken Access Control — User Profile Detail  (all authenticated users)
# ---------------------------------------------------------------------------

class UserProfileDetailView(LoginRequiredMixin, TemplateView):
    """
    Read-only profile detail page keyed by Profile primary key.

    ── IDOR / Broken Access Control protection ──────────────────────────────────
    Vulnerability class : Insecure Direct Object Reference (IDOR)
    OWASP category      : A01:2021 – Broken Access Control

    INSECURE pattern (never use):
        profile = get_object_or_404(Profile, pk=pk)
        # Any authenticated user can read ANY profile by enumerating pk values.

    SECURE pattern used here:
        Regular users  → get_object_or_404(Profile, pk=pk, user=request.user)
            • Returns HTTP 404 for every foreign pk value.
            • 404 rather than 403 is deliberate: a 403 would confirm the pk
              exists, leaking object existence to an enumerating attacker.
              HTTP 404 is indistinguishable from "not found".

        Staff / admins → get_object_or_404(Profile, pk=pk)
            • Staff legitimately need full profile access for user management.
            • The unrestricted query only executes after the role check passes.
    ─────────────────────────────────────────────────────────────────────────────
    """
    template_name = 'mupenz_fulgence/user_profile_detail.html'
    login_url = reverse_lazy('mupenz_fulgence:login')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        pk = self.kwargs['pk']
        if is_staff_or_admin(self.request.user):
            # Staff / admins: unrestricted access for user management purposes
            profile = get_object_or_404(Profile, pk=pk)
        else:
            # Regular users: ownership filter prevents IDOR
            # Returns 404 (not 403) to avoid leaking whether the object exists
            profile = get_object_or_404(Profile, pk=pk, user=self.request.user)
        context['profile']     = profile
        context['viewed_user'] = profile.user
        context['viewed_role'] = get_user_role(profile.user)
        return context


# ---------------------------------------------------------------------------
# Password Reset — thin wrappers around Django's built-in auth views
#
# Security rationale
# ──────────────────
# Django's PasswordResetTokenGenerator produces HMAC-SHA256 tokens whose
# inputs include: user pk, password hash, last-login timestamp, and a
# seconds-since-epoch value (for expiry).  Consequences:
#
#   • Forgery-resistant   — an attacker who knows only the uidb64 cannot
#                           construct a valid token without the SECRET_KEY.
#   • Single-use          — the password hash changes on reset, so the old
#                           token becomes invalid immediately.
#   • Time-limited        — PASSWORD_RESET_TIMEOUT (1 h here) caps the
#                           validity window even if the token is not used.
#   • Referer-safe        — Django 3.2+ stores the real token in the session
#                           and redirects to a /set-password/ URL, so the
#                           one-time token never appears in the Referer
#                           header when the confirmation form is submitted.
#   • Anti-enumeration    — PasswordResetView always redirects to the "done"
#                           page, whether or not the email matches an account.
#                           No branch in the response reveals account existence.
# ---------------------------------------------------------------------------

class UserPasswordResetView(auth_views.PasswordResetView):
    """
    Step 1 — User submits their email address to request a reset link.

    Anti-enumeration guarantee: Django's implementation unconditionally
    redirects to success_url after the form is submitted.  No email is sent
    for unknown addresses, but the HTTP response is identical in both cases,
    making it impossible for an attacker to enumerate registered emails via
    this endpoint.
    """
    template_name         = 'mupenz_fulgence/registration/password_reset_form.html'
    email_template_name   = 'mupenz_fulgence/registration/password_reset_email.txt'
    subject_template_name = 'mupenz_fulgence/registration/password_reset_subject.txt'
    success_url           = reverse_lazy('mupenz_fulgence:password_reset_done')


class UserPasswordResetDoneView(auth_views.PasswordResetDoneView):
    """
    Step 2 — Generic "check your inbox" confirmation page.

    The message shown is intentionally vague: it never confirms whether the
    submitted address belongs to a registered account.
    """
    template_name = 'mupenz_fulgence/registration/password_reset_done.html'


class UserPasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    """
    Step 3 — User arrives via the emailed link and sets a new password.

    Token validation flow (Django 3.2+):
      GET  /reset/<uidb64>/<real-token>/
          → validates token, stores it in session, redirects to
            /reset/<uidb64>/set-password/    (token no longer in URL)
      GET  /reset/<uidb64>/set-password/
          → renders the new-password form (context: validlink=True)
      POST /reset/<uidb64>/set-password/
          → saves password, invalidates token, redirects to complete page

    Invalid or expired tokens skip the redirect and render this template
    immediately with validlink=False, showing a clear error message.
    """
    template_name = 'mupenz_fulgence/registration/password_reset_confirm.html'
    success_url   = reverse_lazy('mupenz_fulgence:password_reset_complete')

    def form_valid(self, form):
        messages.success(
            self.request,
            'Your password has been reset. You can now sign in with your new password.',
        )
        return super().form_valid(form)


class UserPasswordResetCompleteView(auth_views.PasswordResetCompleteView):
    """
    Step 4 — Final confirmation page; directs the user back to the login page.
    """
    template_name = 'mupenz_fulgence/registration/password_reset_complete.html'
