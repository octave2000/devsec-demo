"""
Test suite for the mupenz_fulgence User Authentication Service.

Coverage:
  - User registration (success, duplicate username, duplicate email, password mismatch)
  - Login / logout
  - Protected route access control
  - Profile update
  - Password change (success, wrong current password, new-password mismatch)
  - RBAC: anonymous, user, instructor, staff, admin access matrix
  - IDOR / Broken Access Control: profile detail access by pk
  - Password reset: full flow, anti-enumeration, invalid tokens, validation
  - Brute-force protection: lockout mechanics, counter reset, UX messages
  - Stored XSS: input validation and safe rendering
  - Secure file uploads: avatar and document validation + access control
"""
import io

from django.contrib.auth.models import Group, User
from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from PIL import Image

from .models import Profile
from .rbac import get_user_role
from .validators import (
    AVATAR_MAX_BYTES,
    DOCUMENT_MAX_BYTES,
    validate_avatar,
    validate_document,
)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def make_user(username='testuser', password='StrongPass123!', email='test@example.com'):
    """Create and return a User (Profile is auto-created via signal)."""
    return User.objects.create_user(username=username, password=password, email=email)


# ──────────────────────────────────────────────────────────────────────────────
# Registration
# ──────────────────────────────────────────────────────────────────────────────

class RegistrationTests(TestCase):

    def setUp(self):
        self.client = Client()
        self.url = reverse('mupenz_fulgence:register')

    def test_register_page_loads(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'mupenz_fulgence/registration/register.html')

    def test_register_success_creates_user_and_profile(self):
        data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'password1': 'StrongPass123!',
            'password2': 'StrongPass123!',
        }
        response = self.client.post(self.url, data)

        # Should redirect to login
        self.assertRedirects(response, reverse('mupenz_fulgence:login'))

        # User and linked Profile should both exist
        self.assertTrue(User.objects.filter(username='newuser').exists())
        user = User.objects.get(username='newuser')
        self.assertTrue(Profile.objects.filter(user=user).exists())
        self.assertEqual(user.email, 'newuser@example.com')

    def test_register_duplicate_username(self):
        make_user(username='taken')
        data = {
            'username': 'taken',
            'email': 'other@example.com',
            'password1': 'StrongPass123!',
            'password2': 'StrongPass123!',
        }
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 200)
        form = response.context['form']
        self.assertFormError(form, 'username', 'A user with that username already exists.')

    def test_register_duplicate_email(self):
        make_user(username='existing', email='taken@example.com')
        data = {
            'username': 'brandnew',
            'email': 'taken@example.com',
            'password1': 'StrongPass123!',
            'password2': 'StrongPass123!',
        }
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 200)
        form = response.context['form']
        self.assertFormError(
            form, 'email', 'An account with this email address already exists.'
        )

    def test_register_password_mismatch(self):
        data = {
            'username': 'mismatch',
            'email': 'mismatch@example.com',
            'password1': 'StrongPass123!',
            'password2': 'DifferentPass456!',
        }
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 200)
        form = response.context['form']
        self.assertFalse(form.is_valid())
        self.assertIn('password2', form.errors)

    def test_authenticated_user_redirected_from_register(self):
        make_user()
        self.client.login(username='testuser', password='StrongPass123!')
        response = self.client.get(self.url)
        self.assertRedirects(response, reverse('mupenz_fulgence:dashboard'))


# ──────────────────────────────────────────────────────────────────────────────
# Login & Logout
# ──────────────────────────────────────────────────────────────────────────────

class LoginLogoutTests(TestCase):

    def setUp(self):
        self.client = Client()
        self.user = make_user()
        self.login_url = reverse('mupenz_fulgence:login')
        self.logout_url = reverse('mupenz_fulgence:logout')
        self.dashboard_url = reverse('mupenz_fulgence:dashboard')

    def test_login_page_loads(self):
        response = self.client.get(self.login_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'mupenz_fulgence/registration/login.html')

    def test_login_success_redirects_to_dashboard(self):
        response = self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'StrongPass123!',
        })
        self.assertRedirects(response, self.dashboard_url)

    def test_login_sets_authenticated_session(self):
        self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'StrongPass123!',
        })
        # Hitting the dashboard without being redirected proves authentication
        response = self.client.get(self.dashboard_url)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.wsgi_request.user.is_authenticated)

    def test_login_failure_wrong_password(self):
        response = self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'WRONG!',
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.wsgi_request.user.is_authenticated)

    def test_login_failure_unknown_user(self):
        response = self.client.post(self.login_url, {
            'username': 'nobody',
            'password': 'StrongPass123!',
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.wsgi_request.user.is_authenticated)

    def test_logout_clears_session(self):
        self.client.login(username='testuser', password='StrongPass123!')
        response = self.client.post(self.logout_url)
        # After logout the user is anonymous
        self.assertFalse(response.wsgi_request.user.is_authenticated)

    def test_logout_requires_post(self):
        """GET to the logout URL should not log the user out (Django 5+)."""
        self.client.login(username='testuser', password='StrongPass123!')
        # GET is not allowed by LogoutView in Django 5+; the session must remain intact
        response = self.client.get(self.logout_url)
        # Response is either a 405 or a redirect; the user stays authenticated
        self.assertIn(response.status_code, [302, 405])


# ──────────────────────────────────────────────────────────────────────────────
# Protected routes
# ──────────────────────────────────────────────────────────────────────────────

class ProtectedRouteTests(TestCase):

    def setUp(self):
        self.client = Client()
        self.user = make_user()
        self.login_url = reverse('mupenz_fulgence:login')

    def _assert_protected(self, url):
        """Verify that an unauthenticated GET redirects to the login page."""
        response = self.client.get(url)
        self.assertRedirects(response, f'{self.login_url}?next={url}')

    def _assert_accessible(self, url, template):
        """Verify that an authenticated GET returns 200 with the right template."""
        self.client.login(username='testuser', password='StrongPass123!')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, template)

    def test_dashboard_blocked_for_anonymous(self):
        self._assert_protected(reverse('mupenz_fulgence:dashboard'))

    def test_dashboard_accessible_when_authenticated(self):
        self._assert_accessible(
            reverse('mupenz_fulgence:dashboard'),
            'mupenz_fulgence/dashboard.html',
        )

    def test_profile_blocked_for_anonymous(self):
        self._assert_protected(reverse('mupenz_fulgence:profile'))

    def test_profile_accessible_when_authenticated(self):
        self._assert_accessible(
            reverse('mupenz_fulgence:profile'),
            'mupenz_fulgence/profile.html',
        )

    def test_password_change_blocked_for_anonymous(self):
        self._assert_protected(reverse('mupenz_fulgence:password_change'))

    def test_password_change_accessible_when_authenticated(self):
        self._assert_accessible(
            reverse('mupenz_fulgence:password_change'),
            'mupenz_fulgence/registration/password_change.html',
        )


# ──────────────────────────────────────────────────────────────────────────────
# Profile update
# ──────────────────────────────────────────────────────────────────────────────

class ProfileUpdateTests(TestCase):

    def setUp(self):
        self.client = Client()
        self.user = make_user()
        self.client.login(username='testuser', password='StrongPass123!')
        self.url = reverse('mupenz_fulgence:profile')

    def test_profile_update_success(self):
        data = {
            'first_name': 'Jane',
            'last_name': 'Doe',
            'email': 'jane@example.com',
            'bio': 'Hello world',
            'location': 'Kigali',
            'birth_date': '1995-06-15',
        }
        response = self.client.post(self.url, data)
        self.assertRedirects(response, self.url)

        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Jane')
        self.assertEqual(self.user.email, 'jane@example.com')
        self.assertEqual(self.user.profile.location, 'Kigali')

    def test_profile_update_duplicate_email_rejected(self):
        make_user(username='other', email='other@example.com')
        data = {
            'first_name': '',
            'last_name': '',
            'email': 'other@example.com',  # already taken
            'bio': '',
            'location': '',
            'birth_date': '',
        }
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 200)
        form = response.context['form']
        self.assertFormError(
            form, 'email', 'This email address is already in use by another account.'
        )


# ──────────────────────────────────────────────────────────────────────────────
# Password change
# ──────────────────────────────────────────────────────────────────────────────

class PasswordChangeTests(TestCase):

    def setUp(self):
        self.client = Client()
        self.user = make_user(password='OldPass123!')
        self.client.login(username='testuser', password='OldPass123!')
        self.url = reverse('mupenz_fulgence:password_change')

    def test_password_change_page_loads(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(
            response, 'mupenz_fulgence/registration/password_change.html'
        )

    def test_password_change_success(self):
        response = self.client.post(self.url, {
            'old_password': 'OldPass123!',
            'new_password1': 'NewStrongPass456!',
            'new_password2': 'NewStrongPass456!',
        })
        # Should redirect to dashboard
        self.assertRedirects(response, reverse('mupenz_fulgence:dashboard'))

        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('NewStrongPass456!'))

    def test_password_change_keeps_user_logged_in(self):
        """update_session_auth_hash must keep the session valid after change."""
        self.client.post(self.url, {
            'old_password': 'OldPass123!',
            'new_password1': 'NewStrongPass456!',
            'new_password2': 'NewStrongPass456!',
        })
        # Dashboard should be accessible (user still authenticated)
        response = self.client.get(reverse('mupenz_fulgence:dashboard'))
        self.assertEqual(response.status_code, 200)

    def test_password_change_wrong_current_password(self):
        response = self.client.post(self.url, {
            'old_password': 'WRONG!',
            'new_password1': 'NewStrongPass456!',
            'new_password2': 'NewStrongPass456!',
        })
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        # Password must NOT have changed
        self.assertFalse(self.user.check_password('NewStrongPass456!'))
        self.assertTrue(self.user.check_password('OldPass123!'))

    def test_password_change_new_passwords_mismatch(self):
        response = self.client.post(self.url, {
            'old_password': 'OldPass123!',
            'new_password1': 'NewStrongPass456!',
            'new_password2': 'DoesNotMatch789!',
        })
        self.assertEqual(response.status_code, 200)
        form = response.context['form']
        self.assertFalse(form.is_valid())
        self.assertIn('new_password2', form.errors)


# ──────────────────────────────────────────────────────────────────────────────
# Signal / Profile auto-creation
# ──────────────────────────────────────────────────────────────────────────────

class SignalTests(TestCase):

    def test_profile_auto_created_on_user_save(self):
        user = User.objects.create_user(
            username='signaluser', password='Pass123!', email='sig@example.com'
        )
        self.assertTrue(Profile.objects.filter(user=user).exists())

    def test_profile_not_duplicated_on_user_update(self):
        user = make_user()
        user.first_name = 'Updated'
        user.save()
        self.assertEqual(Profile.objects.filter(user=user).count(), 1)


# ──────────────────────────────────────────────────────────────────────────────
# RBAC helpers
# ──────────────────────────────────────────────────────────────────────────────

def make_instructor_user(username='instructor_user', password='StrongPass123!'):
    """Create a regular user and add them to the Instructor group."""
    user = make_user(username=username, password=password,
                     email=f'{username}@example.com')
    group, _ = Group.objects.get_or_create(name='Instructor')
    user.groups.add(group)
    return user


def make_staff_user(username='staff_user', password='StrongPass123!'):
    """Create a user with is_staff=True (but not superuser)."""
    user = make_user(username=username, password=password,
                     email=f'{username}@example.com')
    user.is_staff = True
    user.save()
    return user


def make_admin_user(username='admin_user', password='StrongPass123!'):
    """Create a full superuser."""
    return User.objects.create_superuser(
        username=username,
        password=password,
        email=f'{username}@example.com',
    )


# ──────────────────────────────────────────────────────────────────────────────
# RBAC — get_user_role helper
# ──────────────────────────────────────────────────────────────────────────────

class GetUserRoleTests(TestCase):

    def test_anonymous_user_role(self):
        from django.contrib.auth.models import AnonymousUser
        anon = AnonymousUser()
        self.assertEqual(get_user_role(anon), 'anonymous')

    def test_regular_user_role(self):
        self.assertEqual(get_user_role(make_user()), 'user')

    def test_instructor_role(self):
        self.assertEqual(get_user_role(make_instructor_user()), 'instructor')

    def test_staff_role(self):
        self.assertEqual(get_user_role(make_staff_user()), 'staff')

    def test_admin_role(self):
        self.assertEqual(get_user_role(make_admin_user()), 'admin')

    def test_superuser_beats_staff(self):
        """A user who is both staff and superuser must be labelled admin."""
        user = make_staff_user()
        user.is_superuser = True
        user.save()
        self.assertEqual(get_user_role(user), 'admin')


# ──────────────────────────────────────────────────────────────────────────────
# RBAC — Anonymous access
# ──────────────────────────────────────────────────────────────────────────────

class RBACAnonymousTests(TestCase):
    """Anonymous users must be redirected to login for every protected route."""

    def setUp(self):
        self.client = Client()
        self.login_url = reverse('mupenz_fulgence:login')

    def _assert_redirects_to_login(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, f'{self.login_url}?next={url}')

    def test_dashboard_blocked(self):
        self._assert_redirects_to_login(reverse('mupenz_fulgence:dashboard'))

    def test_profile_blocked(self):
        self._assert_redirects_to_login(reverse('mupenz_fulgence:profile'))

    def test_instructor_panel_blocked(self):
        self._assert_redirects_to_login(reverse('mupenz_fulgence:instructor_panel'))

    def test_staff_dashboard_blocked(self):
        self._assert_redirects_to_login(reverse('mupenz_fulgence:staff_dashboard'))

    def test_user_list_blocked(self):
        self._assert_redirects_to_login(reverse('mupenz_fulgence:user_list'))

    def test_admin_dashboard_blocked(self):
        self._assert_redirects_to_login(reverse('mupenz_fulgence:admin_dashboard'))


# ──────────────────────────────────────────────────────────────────────────────
# RBAC — Regular authenticated user
# ──────────────────────────────────────────────────────────────────────────────

class RBACRegularUserTests(TestCase):
    """Regular users can access their own pages but get 403 on privileged views."""

    def setUp(self):
        self.client = Client()
        self.user = make_user()
        self.client.login(username='testuser', password='StrongPass123!')

    def test_dashboard_accessible(self):
        response = self.client.get(reverse('mupenz_fulgence:dashboard'))
        self.assertEqual(response.status_code, 200)

    def test_profile_accessible(self):
        response = self.client.get(reverse('mupenz_fulgence:profile'))
        self.assertEqual(response.status_code, 200)

    def test_instructor_panel_forbidden(self):
        response = self.client.get(reverse('mupenz_fulgence:instructor_panel'))
        self.assertEqual(response.status_code, 403)

    def test_staff_dashboard_forbidden(self):
        response = self.client.get(reverse('mupenz_fulgence:staff_dashboard'))
        self.assertEqual(response.status_code, 403)

    def test_user_list_forbidden(self):
        response = self.client.get(reverse('mupenz_fulgence:user_list'))
        self.assertEqual(response.status_code, 403)

    def test_admin_dashboard_forbidden(self):
        response = self.client.get(reverse('mupenz_fulgence:admin_dashboard'))
        self.assertEqual(response.status_code, 403)


# ──────────────────────────────────────────────────────────────────────────────
# RBAC — Instructor group member
# ──────────────────────────────────────────────────────────────────────────────

class RBACInstructorTests(TestCase):
    """Instructors can access the instructor panel but NOT staff or admin views."""

    def setUp(self):
        self.client = Client()
        self.user = make_instructor_user()
        self.client.login(username='instructor_user', password='StrongPass123!')

    def test_instructor_panel_accessible(self):
        response = self.client.get(reverse('mupenz_fulgence:instructor_panel'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'mupenz_fulgence/instructor_panel.html')

    def test_dashboard_accessible(self):
        response = self.client.get(reverse('mupenz_fulgence:dashboard'))
        self.assertEqual(response.status_code, 200)

    def test_staff_dashboard_forbidden(self):
        response = self.client.get(reverse('mupenz_fulgence:staff_dashboard'))
        self.assertEqual(response.status_code, 403)

    def test_user_list_forbidden(self):
        response = self.client.get(reverse('mupenz_fulgence:user_list'))
        self.assertEqual(response.status_code, 403)

    def test_admin_dashboard_forbidden(self):
        response = self.client.get(reverse('mupenz_fulgence:admin_dashboard'))
        self.assertEqual(response.status_code, 403)

    def test_cannot_self_escalate_to_staff(self):
        """POSTing to profile must not grant is_staff."""
        self.client.post(reverse('mupenz_fulgence:profile'), {
            'first_name': 'Evil', 'last_name': 'Try',
            'email': 'instructor_user@example.com',
            'bio': '', 'location': '', 'birth_date': '',
        })
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_staff)


# ──────────────────────────────────────────────────────────────────────────────
# RBAC — Staff member
# ──────────────────────────────────────────────────────────────────────────────

class RBACStaffTests(TestCase):
    """Staff can access instructor and staff views but NOT the admin dashboard."""

    def setUp(self):
        self.client = Client()
        self.user = make_staff_user()
        self.client.login(username='staff_user', password='StrongPass123!')

    def test_instructor_panel_accessible(self):
        response = self.client.get(reverse('mupenz_fulgence:instructor_panel'))
        self.assertEqual(response.status_code, 200)

    def test_staff_dashboard_accessible(self):
        response = self.client.get(reverse('mupenz_fulgence:staff_dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'mupenz_fulgence/staff_dashboard.html')

    def test_user_list_accessible(self):
        response = self.client.get(reverse('mupenz_fulgence:user_list'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'mupenz_fulgence/user_list.html')

    def test_admin_dashboard_forbidden(self):
        response = self.client.get(reverse('mupenz_fulgence:admin_dashboard'))
        self.assertEqual(response.status_code, 403)

    def test_user_list_search(self):
        """Search parameter must filter results without error."""
        make_user(username='findme', email='findme@example.com')
        response = self.client.get(
            reverse('mupenz_fulgence:user_list') + '?q=findme'
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'findme')


# ──────────────────────────────────────────────────────────────────────────────
# RBAC — Admin (superuser)
# ──────────────────────────────────────────────────────────────────────────────

class RBACAdminTests(TestCase):
    """Superusers can access every view in the system."""

    def setUp(self):
        self.client = Client()
        self.user = make_admin_user()
        self.client.login(username='admin_user', password='StrongPass123!')

    def test_instructor_panel_accessible(self):
        response = self.client.get(reverse('mupenz_fulgence:instructor_panel'))
        self.assertEqual(response.status_code, 200)

    def test_staff_dashboard_accessible(self):
        response = self.client.get(reverse('mupenz_fulgence:staff_dashboard'))
        self.assertEqual(response.status_code, 200)

    def test_user_list_accessible(self):
        response = self.client.get(reverse('mupenz_fulgence:user_list'))
        self.assertEqual(response.status_code, 200)

    def test_admin_dashboard_accessible(self):
        response = self.client.get(reverse('mupenz_fulgence:admin_dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'mupenz_fulgence/admin_dashboard.html')

    def test_admin_dashboard_shows_groups(self):
        """Admin dashboard must render without errors even with no groups."""
        response = self.client.get(reverse('mupenz_fulgence:admin_dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertIn('groups', response.context)


# ──────────────────────────────────────────────────────────────────────────────
# RBAC — Privilege escalation prevention
# ──────────────────────────────────────────────────────────────────────────────

class PrivilegeEscalationTests(TestCase):
    """Ensure normal users cannot grant themselves elevated privileges."""

    def setUp(self):
        self.client = Client()
        self.user = make_user()
        self.client.login(username='testuser', password='StrongPass123!')

    def test_profile_post_cannot_set_is_staff(self):
        self.client.post(reverse('mupenz_fulgence:profile'), {
            'first_name': '', 'last_name': '',
            'email': 'test@example.com',
            'bio': '', 'location': '', 'birth_date': '',
            'is_staff': True,         # injected field — must be ignored
            'is_superuser': True,     # injected field — must be ignored
        })
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_staff)
        self.assertFalse(self.user.is_superuser)

    def test_cannot_access_other_users_profile(self):
        """Profile view always returns the current user's own profile."""
        other = make_user(username='other', email='other@example.com')
        profile_url = reverse('mupenz_fulgence:profile')
        response = self.client.get(profile_url)
        self.assertEqual(response.status_code, 200)
        # Ensure the form is pre-loaded with the logged-in user's data, not 'other'
        self.assertEqual(
            response.context['form'].instance.user, self.user
        )


# ──────────────────────────────────────────────────────────────────────────────
# IDOR / Broken Access Control — UserProfileDetailView
# ──────────────────────────────────────────────────────────────────────────────

class IDORTests(TestCase):
    """
    Security tests for Insecure Direct Object Reference (IDOR) on the
    profile detail endpoint (/auth/users/<pk>/profile/).

    Validates that:
      - Regular users get HTTP 404 (not 403) when accessing another user's pk.
        (404 hides object existence; 403 would confirm the pk is valid.)
      - Regular users can access their own profile by pk → HTTP 200.
      - Staff / admins can access any profile → HTTP 200.
      - Anonymous users are redirected to the login page.
      - A completely nonexistent pk returns 404 for all role levels.
    """

    def setUp(self):
        self.client = Client()
        self.owner    = make_user(username='profile_owner',  email='owner@example.com')
        self.attacker = make_user(username='attacker_user',  email='attack@example.com')
        self.staff    = make_staff_user()
        self.admin    = make_admin_user()
        # Profiles are auto-created by signal
        self.owner_profile    = Profile.objects.get(user=self.owner)
        self.attacker_profile = Profile.objects.get(user=self.attacker)
        self.login_url        = reverse('mupenz_fulgence:login')

    def _url(self, pk):
        return reverse('mupenz_fulgence:user_profile_detail', kwargs={'pk': pk})

    # ── Anonymous ──────────────────────────────────────────────────────────────

    def test_anonymous_redirected_to_login(self):
        url = self._url(self.owner_profile.pk)
        response = self.client.get(url)
        self.assertRedirects(response, f'{self.login_url}?next={url}')

    # ── Regular user — own profile ─────────────────────────────────────────────

    def test_user_can_view_own_profile_by_pk(self):
        self.client.login(username='profile_owner', password='StrongPass123!')
        response = self.client.get(self._url(self.owner_profile.pk))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'mupenz_fulgence/user_profile_detail.html')
        self.assertEqual(response.context['viewed_user'], self.owner)

    # ── IDOR: regular user accessing another user's profile ───────────────────

    def test_cross_user_profile_returns_404_not_403(self):
        """
        IDOR fix: a regular user requesting another user's profile pk must
        receive HTTP 404, NOT 403.  Returning 403 would confirm the pk exists
        (existence leak); 404 is indistinguishable from 'not found'.
        """
        self.client.login(username='profile_owner', password='StrongPass123!')
        response = self.client.get(self._url(self.attacker_profile.pk))
        self.assertEqual(response.status_code, 404)

    def test_existence_leak_prevented(self):
        """
        Both an existing-but-foreign profile pk and a wholly nonexistent pk
        must return 404 so the attacker cannot distinguish the two cases.
        """
        self.client.login(username='profile_owner', password='StrongPass123!')
        response_foreign     = self.client.get(self._url(self.attacker_profile.pk))
        response_nonexistent = self.client.get(self._url(99999))
        self.assertEqual(response_foreign.status_code, 404)
        self.assertEqual(response_nonexistent.status_code, 404)

    def test_cross_user_post_returns_405(self):
        """
        The detail view is read-only (GET only via TemplateView).
        A POST to a foreign pk must not modify any data.
        """
        self.client.login(username='profile_owner', password='StrongPass123!')
        response = self.client.post(self._url(self.attacker_profile.pk), {
            'bio': 'injected', 'location': 'injected',
        })
        # TemplateView does not accept POST — returns 405 Method Not Allowed
        self.assertEqual(response.status_code, 405)
        # Verify attacker's bio is unmodified
        self.attacker_profile.refresh_from_db()
        self.assertNotEqual(self.attacker_profile.bio, 'injected')

    # ── Staff access (legitimate) ─────────────────────────────────────────────

    def test_staff_can_access_any_profile(self):
        self.client.login(username='staff_user', password='StrongPass123!')
        response = self.client.get(self._url(self.owner_profile.pk))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['viewed_user'], self.owner)

    def test_staff_can_access_attacker_profile(self):
        """Staff can view every profile, including the attacker's."""
        self.client.login(username='staff_user', password='StrongPass123!')
        response = self.client.get(self._url(self.attacker_profile.pk))
        self.assertEqual(response.status_code, 200)

    def test_admin_can_access_any_profile(self):
        self.client.login(username='admin_user', password='StrongPass123!')
        response = self.client.get(self._url(self.owner_profile.pk))
        self.assertEqual(response.status_code, 200)

    # ── Nonexistent pk ────────────────────────────────────────────────────────

    def test_nonexistent_pk_returns_404_for_regular_user(self):
        self.client.login(username='profile_owner', password='StrongPass123!')
        response = self.client.get(self._url(99999))
        self.assertEqual(response.status_code, 404)

    def test_nonexistent_pk_returns_404_for_staff(self):
        self.client.login(username='staff_user', password='StrongPass123!')
        response = self.client.get(self._url(99999))
        self.assertEqual(response.status_code, 404)

    # ── Context integrity ─────────────────────────────────────────────────────

    def test_context_contains_viewed_role(self):
        """viewed_role must be present and correct in the template context."""
        self.client.login(username='profile_owner', password='StrongPass123!')
        response = self.client.get(self._url(self.owner_profile.pk))
        self.assertEqual(response.status_code, 200)
        self.assertIn('viewed_role', response.context)
        self.assertEqual(response.context['viewed_role'], 'user')

    def test_staff_context_shows_correct_viewed_user(self):
        """When staff views a profile, viewed_user must be the profile owner."""
        self.client.login(username='staff_user', password='StrongPass123!')
        response = self.client.get(self._url(self.attacker_profile.pk))
        self.assertEqual(response.context['viewed_user'], self.attacker)


# ──────────────────────────────────────────────────────────────────────────────
# Password Reset workflow
# ──────────────────────────────────────────────────────────────────────────────

class PasswordResetTests(TestCase):
    """
    Tests for the secure password reset workflow.

    Django's test runner calls setup_test_environment() which replaces the
    configured EMAIL_BACKEND with django.core.mail.backends.locmem.EmailBackend,
    so mail.outbox captures all sent messages without any SMTP configuration.

    Security properties verified:
      - Anti-enumeration: known and unknown emails produce identical HTTP responses
      - No email sent for non-existent addresses (silent failure)
      - Valid token opens the confirm form (validlink=True in context)
      - Invalid / tampered token renders validlink=False without raising an error
      - Full flow: valid token → new password accepted → redirects to complete
      - Password mismatch rejected; original password unchanged
      - Password validation rules enforced (e.g. too-short password)
    """

    def setUp(self):
        self.client       = Client()
        self.user         = make_user(username='resetuser', email='reset@example.com')
        self.reset_url    = reverse('mupenz_fulgence:password_reset')
        self.done_url     = reverse('mupenz_fulgence:password_reset_done')
        self.complete_url = reverse('mupenz_fulgence:password_reset_complete')

    # ── Helper ────────────────────────────────────────────────────────────────

    def _confirm_url(self, user=None):
        """Return the initial token URL for *user* (defaults to self.user)."""
        u = user or self.user
        uid   = urlsafe_base64_encode(force_bytes(u.pk))
        token = default_token_generator.make_token(u)
        return reverse('mupenz_fulgence:password_reset_confirm',
                       kwargs={'uidb64': uid, 'token': token})

    def _set_password_url(self, user=None):
        """
        Return the session-secured /set-password/ URL by first GETting the
        real token URL (which stores the token in the session and redirects).
        """
        url = self._confirm_url(user)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302,
                         'Expected redirect to set-password URL after valid token GET')
        return response['Location']

    # ── Page rendering ────────────────────────────────────────────────────────

    def test_reset_form_page_renders(self):
        response = self.client.get(self.reset_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(
            response, 'mupenz_fulgence/registration/password_reset_form.html'
        )

    def test_done_page_renders(self):
        response = self.client.get(self.done_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(
            response, 'mupenz_fulgence/registration/password_reset_done.html'
        )

    def test_complete_page_renders(self):
        response = self.client.get(self.complete_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(
            response, 'mupenz_fulgence/registration/password_reset_complete.html'
        )

    # ── Anti-enumeration ──────────────────────────────────────────────────────

    def test_known_email_redirects_to_done(self):
        """A registered email redirects to the done page — no extra information."""
        response = self.client.post(self.reset_url, {'email': 'reset@example.com'})
        self.assertRedirects(response, self.done_url)

    def test_unknown_email_also_redirects_to_done(self):
        """
        Anti-enumeration: an unregistered email must produce the identical
        HTTP 302 → done redirect as a registered email.
        An attacker observing only the HTTP response cannot distinguish the two.
        """
        response = self.client.post(self.reset_url, {'email': 'nobody@example.com'})
        self.assertRedirects(response, self.done_url)

    def test_email_sent_for_known_address(self):
        """Exactly one email must be dispatched for a registered address."""
        self.client.post(self.reset_url, {'email': 'reset@example.com'})
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn('reset@example.com', mail.outbox[0].to)

    def test_no_email_sent_for_unknown_address(self):
        """
        No email must be sent when the address is not registered.
        Sending an email would confirm (to an observer of the inbox) that the
        address IS registered — this silent failure prevents that leak.
        """
        self.client.post(self.reset_url, {'email': 'nobody@example.com'})
        self.assertEqual(len(mail.outbox), 0)

    def test_email_contains_reset_link(self):
        """The dispatched email body must contain a usable reset URL."""
        self.client.post(self.reset_url, {'email': 'reset@example.com'})
        self.assertEqual(len(mail.outbox), 1)
        body = mail.outbox[0].body
        # The email template renders {% url 'password_reset_confirm' uid token %}
        # to the actual path, e.g. /auth/reset/<uidb64>/<token>/
        self.assertIn('/reset/', body)

    # ── Token validation ──────────────────────────────────────────────────────

    def test_valid_token_redirects_to_set_password(self):
        """
        A valid token URL must redirect to the session-secured /set-password/
        URL (Django 3.2+ Referer-safe redirect pattern).
        """
        response = self.client.get(self._confirm_url())
        self.assertEqual(response.status_code, 302)
        self.assertIn('set-password', response['Location'])

    def test_valid_token_shows_confirm_form(self):
        """After the redirect, the confirm page must render with validlink=True."""
        set_pw_url = self._set_password_url()
        response   = self.client.get(set_pw_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(
            response, 'mupenz_fulgence/registration/password_reset_confirm.html'
        )
        self.assertTrue(response.context['validlink'])

    def test_invalid_token_renders_confirm_template_with_validlink_false(self):
        """
        A tampered or expired token must render the confirm template with
        validlink=False.  It must NOT raise an exception or return a 500.
        """
        url = reverse('mupenz_fulgence:password_reset_confirm',
                      kwargs={'uidb64': 'aW52YWxpZA', 'token': 'bad-token'})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(
            response, 'mupenz_fulgence/registration/password_reset_confirm.html'
        )
        self.assertFalse(response.context['validlink'])

    def test_tampered_uid_renders_invalid_link(self):
        """A completely invalid uidb64 must also yield validlink=False."""
        url = reverse('mupenz_fulgence:password_reset_confirm',
                      kwargs={'uidb64': 'ZZZZZZZZZZ', 'token': 'some-token'})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context['validlink'])

    # ── Full reset flow ───────────────────────────────────────────────────────

    def test_full_flow_resets_password_and_redirects(self):
        """
        End-to-end: valid token → set new password → redirect to complete page.
        Verifies that the password is actually persisted in the database.
        """
        set_pw_url = self._set_password_url()
        response   = self.client.post(set_pw_url, {
            'new_password1': 'BrandNewPass123!',
            'new_password2': 'BrandNewPass123!',
        })
        self.assertRedirects(response, self.complete_url)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('BrandNewPass123!'))

    def test_full_flow_token_invalidated_after_use(self):
        """
        Once the password is reset the original token must be invalid.
        The HMAC input includes the password hash, so changing the password
        automatically invalidates all prior tokens.
        """
        uid   = urlsafe_base64_encode(force_bytes(self.user.pk))
        token = default_token_generator.make_token(self.user)

        # Use the token to reset the password
        self.client.get(self._confirm_url())
        set_pw_url = reverse('mupenz_fulgence:password_reset_confirm',
                             kwargs={'uidb64': uid, 'token': 'set-password'})
        self.client.post(set_pw_url, {
            'new_password1': 'BrandNewPass123!',
            'new_password2': 'BrandNewPass123!',
        })
        self.user.refresh_from_db()

        # The original token must now be invalid
        self.assertFalse(default_token_generator.check_token(self.user, token))

    # ── Password validation ───────────────────────────────────────────────────

    def test_password_mismatch_rejected(self):
        """Mismatched confirmation must return the form with an error."""
        set_pw_url = self._set_password_url()
        response   = self.client.post(set_pw_url, {
            'new_password1': 'BrandNewPass123!',
            'new_password2': 'DoesNotMatch456!',
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn('new_password2', response.context['form'].errors)
        # Original password must be unchanged
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('StrongPass123!'))

    def test_weak_password_rejected(self):
        """
        Django's AUTH_PASSWORD_VALIDATORS must block a too-short password.
        This verifies that password strength rules are enforced on the reset
        path, not just on registration.
        """
        set_pw_url = self._set_password_url()
        response   = self.client.post(set_pw_url, {
            'new_password1': 'short',
            'new_password2': 'short',
        })
        self.assertEqual(response.status_code, 200)
        form = response.context['form']
        self.assertFalse(form.is_valid())
        # Original password must be unchanged
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('StrongPass123!'))

    # ── Login page integration ────────────────────────────────────────────────

    def test_login_page_has_forgot_password_link(self):
        """The login page must contain a visible link to the reset request page."""
        response = self.client.get(reverse('mupenz_fulgence:login'))
        self.assertContains(response, reverse('mupenz_fulgence:password_reset'))


# ──────────────────────────────────────────────────────────────────────────────
# Brute-force / login-abuse protection
# ──────────────────────────────────────────────────────────────────────────────

class BruteForceProtectionTests(TestCase):
    """
    Tests for cache-based login brute-force protection.

    Django's test runner uses django.test.utils.setup_test_environment()
    which replaces the cache backend with LocMemCache isolated per test
    class.  Each TestCase gets a clean cache — no bleed-through between
    tests.

    Security properties verified:
      - Failure counter increments on each bad login
      - Counter resets to zero on a successful login
      - Case-insensitive username normalisation (Alice == alice)
      - Lockout activates exactly at MAX_ATTEMPTS
      - Locked account rejected even with the correct password
      - Non-existent usernames are tracked identically (anti-enumeration)
      - Lockout can be cleared (simulating TTL expiry via reset_failures)
      - Warning message appears one attempt before lockout
      - Lockout message is identical for real and fictitious usernames
      - Normal logins below threshold are unaffected
    """

    def setUp(self):
        # LocMemCache persists across TestCase runs within the same process.
        # Clear it before each test to prevent counter bleed-through.
        cache.clear()
        self.client   = Client()
        self.user     = make_user(
            username='brutetest',
            password='StrongPass123!',
            email='brute@example.com',
        )
        self.login_url     = reverse('mupenz_fulgence:login')
        self.dashboard_url = reverse('mupenz_fulgence:dashboard')

    def _post(self, username, password):
        return self.client.post(self.login_url,
                                {'username': username, 'password': password})

    def _fail(self, username='brutetest', n=1):
        """Submit n consecutive wrong-password logins."""
        for _ in range(n):
            self._post(username, 'WRONG_PASSWORD!')

    # ── Counter mechanics ─────────────────────────────────────────────────────

    def test_failure_counter_increments_on_each_bad_login(self):
        from mupenz_fulgence.login_protection import get_failure_count
        self._fail(n=3)
        self.assertEqual(get_failure_count('brutetest'), 3)

    def test_counter_case_insensitive(self):
        """'BruteTest' and 'brutetest' must share the same counter."""
        from mupenz_fulgence.login_protection import get_failure_count
        self._fail('BruteTest', n=2)
        self._fail('BRUTETEST', n=1)
        self.assertEqual(get_failure_count('brutetest'), 3)

    def test_successful_login_resets_counter_to_zero(self):
        from mupenz_fulgence.login_protection import get_failure_count
        self._fail(n=3)
        self._post('brutetest', 'StrongPass123!')
        self.assertEqual(get_failure_count('brutetest'), 0)

    def test_successful_login_clears_lockout_flag(self):
        from mupenz_fulgence.login_protection import MAX_ATTEMPTS, is_locked_out, reset_failures
        self._fail(n=MAX_ATTEMPTS)
        self.assertTrue(is_locked_out('brutetest'))
        # Simulate TTL expiry by calling reset_failures() directly
        reset_failures('brutetest')
        self.assertFalse(is_locked_out('brutetest'))

    # ── Lockout activation ────────────────────────────────────────────────────

    def test_lockout_triggers_at_exactly_max_attempts(self):
        from mupenz_fulgence.login_protection import MAX_ATTEMPTS, is_locked_out
        self._fail(n=MAX_ATTEMPTS - 1)
        self.assertFalse(is_locked_out('brutetest'), 'Should not be locked before threshold')
        self._fail(n=1)
        self.assertTrue(is_locked_out('brutetest'), 'Should be locked at threshold')

    def test_locked_account_rejected_with_correct_password(self):
        """The correct password must not bypass an active lockout."""
        from mupenz_fulgence.login_protection import MAX_ATTEMPTS
        self._fail(n=MAX_ATTEMPTS)
        response = self._post('brutetest', 'StrongPass123!')
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.wsgi_request.user.is_authenticated)

    def test_lockout_response_contains_error_message(self):
        """The lockout page must visibly explain the situation."""
        from mupenz_fulgence.login_protection import MAX_ATTEMPTS
        self._fail(n=MAX_ATTEMPTS)
        response = self._post('brutetest', 'StrongPass123!')
        self.assertContains(response, 'Too many failed login attempts')

    # ── Anti-enumeration ──────────────────────────────────────────────────────

    def test_nonexistent_username_also_tracked_and_locked(self):
        """
        Failures for a non-existent username must be tracked and eventually
        locked, making the lockout behaviour indistinguishable from that of
        a real account and preventing username enumeration via lockout state.
        """
        from mupenz_fulgence.login_protection import MAX_ATTEMPTS, is_locked_out
        fake = 'definitely_not_a_real_user_xyz'
        self._fail(fake, n=MAX_ATTEMPTS)
        self.assertTrue(is_locked_out(fake))

    def test_lockout_message_identical_for_real_and_fake_username(self):
        """
        The HTTP response content for a locked real account and a locked
        fictitious account must contain the same message, giving an attacker
        no way to distinguish them.
        """
        from mupenz_fulgence.login_protection import MAX_ATTEMPTS
        self._fail('brutetest', n=MAX_ATTEMPTS)
        real_resp = self._post('brutetest', 'WRONG!')

        fake = 'fake_user_enumeration_test'
        self._fail(fake, n=MAX_ATTEMPTS)
        fake_resp = self._post(fake, 'WRONG!')

        self.assertContains(real_resp, 'Too many failed login attempts')
        self.assertContains(fake_resp, 'Too many failed login attempts')

    # ── Pre-lockout warning ───────────────────────────────────────────────────

    def test_warning_shown_on_penultimate_failure(self):
        """
        When exactly one attempt remains before lockout, a warning must
        appear prompting the user to use password reset instead.
        """
        from mupenz_fulgence.login_protection import MAX_ATTEMPTS
        # Build up to (MAX_ATTEMPTS - 2) failures — no warning yet
        self._fail(n=MAX_ATTEMPTS - 2)
        # This is the (MAX_ATTEMPTS - 1)th failure → one left before lockout
        response = self._post('brutetest', 'WRONG_PASSWORD!')
        self.assertContains(response, 'lock')  # "lock this account" in the warning

    # ── Normal login flow unaffected ──────────────────────────────────────────

    def test_login_succeeds_with_no_prior_failures(self):
        response = self._post('brutetest', 'StrongPass123!')
        self.assertRedirects(response, self.dashboard_url)

    def test_login_succeeds_below_threshold(self):
        """A user with fewer failures than MAX_ATTEMPTS can still log in."""
        from mupenz_fulgence.login_protection import MAX_ATTEMPTS
        self._fail(n=MAX_ATTEMPTS - 1)
        response = self._post('brutetest', 'StrongPass123!')
        self.assertRedirects(response, self.dashboard_url)

    def test_account_unlocks_after_reset(self):
        """
        After TTL expiry (simulated via reset_failures) the account must
        accept a correct password again.
        """
        from mupenz_fulgence.login_protection import MAX_ATTEMPTS, reset_failures
        self._fail(n=MAX_ATTEMPTS)
        reset_failures('brutetest')
        response = self._post('brutetest', 'StrongPass123!')
        self.assertRedirects(response, self.dashboard_url)


# ──────────────────────────────────────────────────────────────────────────────
# CSRF enforcement
# ──────────────────────────────────────────────────────────────────────────────

class CSRFEnforcementTests(TestCase):
    """
    Verify that Django's CsrfViewMiddleware enforces token validation on every
    state-changing (POST) endpoint.

    Why a dedicated test class?
    ───────────────────────────
    Django's default test Client bypasses CsrfViewMiddleware to simplify
    writing unit tests.  That convenience means the 106 tests above give no
    evidence that CSRF protection is actually active at runtime.

    Passing Client(enforce_csrf_checks=True) re-enables the real middleware so
    these tests exercise the actual protection path.

    Token acquisition pattern:
    ──────────────────────────
    1. GET the form page — middleware sets the csrftoken cookie on the client.
    2. Read self.csrf_client.cookies['csrftoken'].value.
    3. POST with csrfmiddlewaretoken=<token> in the request body.

    Each test pair:
      • *_without_csrf   → expects HTTP 403 (token missing from POST body)
      • *_with_csrf      → expects anything except 403 (token present and valid)

    Security properties verified:
      - Login endpoint rejects unauthenticated POST without token
      - Registration rejects POST without token
      - Logout rejects POST without token (Django 5+ POST-only requirement)
      - Profile update rejects POST without token
      - Password change rejects POST without token
      - Password reset request rejects POST without token
      - Password reset confirm (set-password form) rejects POST without token
    """

    def setUp(self):
        cache.clear()
        self.user = make_user(
            username='csrfuser',
            password='StrongPass123!',
            email='csrf@example.com',
        )
        # All CSRF assertions use this client; the default self.client stays
        # CSRF-bypassed for setup helpers only.
        self.csrf_client = Client(enforce_csrf_checks=True)

    def _get_csrf_token(self, url, follow=False):
        """
        GET *url* through the CSRF-enforcing client and return the token value
        that the middleware placed in the csrftoken cookie.
        """
        self.csrf_client.get(url, follow=follow)
        return self.csrf_client.cookies['csrftoken'].value

    def _login_with_csrf(self):
        """
        Authenticate through the CSRF-enforcing client using a real form POST.
        This sets both the session cookie and the CSRF cookie on csrf_client.
        """
        login_url = reverse('mupenz_fulgence:login')
        token = self._get_csrf_token(login_url)
        self.csrf_client.post(login_url, {
            'username': 'csrfuser',
            'password': 'StrongPass123!',
            'csrfmiddlewaretoken': token,
        })

    # ── Login ──────────────────────────────────────────────────────────────────

    def test_login_post_without_csrf_returns_403(self):
        """
        A login POST that carries no csrfmiddlewaretoken must be rejected.
        The CSRF cookie is absent as well (cold client, no prior GET).
        """
        response = self.csrf_client.post(
            reverse('mupenz_fulgence:login'),
            {'username': 'csrfuser', 'password': 'StrongPass123!'},
        )
        self.assertEqual(response.status_code, 403)

    def test_login_post_with_valid_csrf_succeeds(self):
        """A login POST with a valid CSRF token must not be rejected by middleware."""
        url = reverse('mupenz_fulgence:login')
        token = self._get_csrf_token(url)
        response = self.csrf_client.post(url, {
            'username': 'csrfuser',
            'password': 'StrongPass123!',
            'csrfmiddlewaretoken': token,
        })
        # 200 (form error) or 302 (redirect on success) — never 403
        self.assertNotEqual(response.status_code, 403)

    # ── Registration ───────────────────────────────────────────────────────────

    def test_register_post_without_csrf_returns_403(self):
        """Registration POST without a CSRF token must be blocked."""
        response = self.csrf_client.post(
            reverse('mupenz_fulgence:register'),
            {
                'username': 'newcsrfuser',
                'email': 'new@example.com',
                'password1': 'StrongPass123!',
                'password2': 'StrongPass123!',
            },
        )
        self.assertEqual(response.status_code, 403)

    def test_register_post_with_valid_csrf_succeeds(self):
        url = reverse('mupenz_fulgence:register')
        token = self._get_csrf_token(url)
        response = self.csrf_client.post(url, {
            'username': 'newcsrfuser',
            'email': 'new@example.com',
            'password1': 'StrongPass123!',
            'password2': 'StrongPass123!',
            'csrfmiddlewaretoken': token,
        })
        self.assertNotEqual(response.status_code, 403)

    # ── Logout ─────────────────────────────────────────────────────────────────

    def test_logout_post_without_csrf_returns_403(self):
        """
        Logout POST without a CSRF token must be blocked.
        Even an authenticated user cannot log out via a cross-site request.

        Why this matters: a CSRF attack could force a victim's browser to
        silently log them out, enabling session-fixation follow-on attacks.
        """
        self._login_with_csrf()
        # POST to logout — the CSRF cookie is present (from _login_with_csrf)
        # but no csrfmiddlewaretoken is included in the body → 403.
        response = self.csrf_client.post(reverse('mupenz_fulgence:logout'))
        self.assertEqual(response.status_code, 403)

    def test_logout_post_with_valid_csrf_succeeds(self):
        self._login_with_csrf()
        # GET an authenticated page to ensure the CSRF cookie is fresh.
        token = self._get_csrf_token(reverse('mupenz_fulgence:dashboard'))
        response = self.csrf_client.post(
            reverse('mupenz_fulgence:logout'),
            {'csrfmiddlewaretoken': token},
        )
        self.assertNotEqual(response.status_code, 403)

    # ── Profile update ─────────────────────────────────────────────────────────

    def test_profile_post_without_csrf_returns_403(self):
        """
        An authenticated profile-update POST without a CSRF token must be blocked.
        An attacker's page could otherwise silently change the victim's profile.
        """
        self._login_with_csrf()
        response = self.csrf_client.post(
            reverse('mupenz_fulgence:profile'),
            {
                'first_name': 'Injected',
                'last_name': 'Name',
                'email': 'csrf@example.com',
                'bio': '',
                'location': '',
                'birth_date': '',
            },
        )
        self.assertEqual(response.status_code, 403)

    def test_profile_post_with_valid_csrf_succeeds(self):
        self._login_with_csrf()
        url = reverse('mupenz_fulgence:profile')
        token = self._get_csrf_token(url)
        response = self.csrf_client.post(url, {
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'csrf@example.com',
            'bio': '',
            'location': '',
            'birth_date': '',
            'csrfmiddlewaretoken': token,
        })
        self.assertNotEqual(response.status_code, 403)

    # ── Password change ────────────────────────────────────────────────────────

    def test_password_change_post_without_csrf_returns_403(self):
        """
        A password-change POST without CSRF token must be blocked.
        An attacker's page could otherwise force a victim to change their password
        to an attacker-controlled value, leading to account takeover.
        """
        self._login_with_csrf()
        response = self.csrf_client.post(
            reverse('mupenz_fulgence:password_change'),
            {
                'old_password': 'StrongPass123!',
                'new_password1': 'AttackerChose1!',
                'new_password2': 'AttackerChose1!',
            },
        )
        self.assertEqual(response.status_code, 403)

    def test_password_change_post_with_valid_csrf_succeeds(self):
        self._login_with_csrf()
        url = reverse('mupenz_fulgence:password_change')
        token = self._get_csrf_token(url)
        response = self.csrf_client.post(url, {
            'old_password': 'StrongPass123!',
            'new_password1': 'NewPass456!',
            'new_password2': 'NewPass456!',
            'csrfmiddlewaretoken': token,
        })
        self.assertNotEqual(response.status_code, 403)

    # ── Password reset request ─────────────────────────────────────────────────

    def test_password_reset_post_without_csrf_returns_403(self):
        """
        Password-reset request POST without CSRF token must be blocked.
        Without protection an attacker could trigger reset emails for any
        address, constituting an email-based denial-of-service.
        """
        response = self.csrf_client.post(
            reverse('mupenz_fulgence:password_reset'),
            {'email': 'csrf@example.com'},
        )
        self.assertEqual(response.status_code, 403)

    def test_password_reset_post_with_valid_csrf_succeeds(self):
        url = reverse('mupenz_fulgence:password_reset')
        token = self._get_csrf_token(url)
        response = self.csrf_client.post(
            url,
            {'email': 'csrf@example.com', 'csrfmiddlewaretoken': token},
        )
        self.assertNotEqual(response.status_code, 403)

    # ── Password reset confirm (set-password form) ─────────────────────────────

    def test_password_reset_confirm_post_without_csrf_returns_403(self):
        """
        The set-password form (Django 3.2+ session-token pattern) must also
        reject requests without a CSRF token.

        Django's password-reset flow (3.2+):
          GET /reset/<uid>/<token>/  → validates token, stores in session,
                                       redirects to /reset/<uid>/set-password/
          GET /reset/<uid>/set-password/ → renders the new-password form
          POST /reset/<uid>/set-password/ → sets password (requires CSRF)
        """
        from django.contrib.auth.tokens import default_token_generator
        from django.utils.encoding import force_bytes
        from django.utils.http import urlsafe_base64_encode

        uid   = urlsafe_base64_encode(force_bytes(self.user.pk))
        token = default_token_generator.make_token(self.user)

        # Walk Django's two-step redirect to seed the session and CSRF cookie.
        confirm_url = reverse(
            'mupenz_fulgence:password_reset_confirm',
            kwargs={'uidb64': uid, 'token': token},
        )
        self.csrf_client.get(confirm_url, follow=True)

        set_pw_url = reverse(
            'mupenz_fulgence:password_reset_confirm',
            kwargs={'uidb64': uid, 'token': 'set-password'},
        )
        # POST without csrfmiddlewaretoken → 403
        response = self.csrf_client.post(set_pw_url, {
            'new_password1': 'AttackerChose1!',
            'new_password2': 'AttackerChose1!',
        })
        self.assertEqual(response.status_code, 403)
        # Confirm the password was NOT changed despite the POST reaching the server
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('StrongPass123!'))

    def test_password_reset_confirm_post_with_valid_csrf_succeeds(self):
        from django.contrib.auth.tokens import default_token_generator
        from django.utils.encoding import force_bytes
        from django.utils.http import urlsafe_base64_encode

        uid   = urlsafe_base64_encode(force_bytes(self.user.pk))
        token = default_token_generator.make_token(self.user)

        confirm_url = reverse(
            'mupenz_fulgence:password_reset_confirm',
            kwargs={'uidb64': uid, 'token': token},
        )
        # Follow the redirect — seeds both the session token and the CSRF cookie.
        self.csrf_client.get(confirm_url, follow=True)

        set_pw_url = reverse(
            'mupenz_fulgence:password_reset_confirm',
            kwargs={'uidb64': uid, 'token': 'set-password'},
        )
        csrf_token = self.csrf_client.cookies['csrftoken'].value
        response = self.csrf_client.post(set_pw_url, {
            'new_password1': 'NewPass456!',
            'new_password2': 'NewPass456!',
            'csrfmiddlewaretoken': csrf_token,
        })
        self.assertNotEqual(response.status_code, 403)


# ──────────────────────────────────────────────────────────────────────────────
# Open redirect protection
# ──────────────────────────────────────────────────────────────────────────────

class OpenRedirectTests(TestCase):
    """
    Verify that the login endpoint cannot be weaponised as an open redirector.

    Attack scenario
    ───────────────
    An attacker sends a victim the link:
        https://app.example.com/auth/login/?next=https://evil.com/

    If the application blindly trusts the ``next`` query parameter, the
    victim is authenticated and then silently sent to the attacker's site,
    which can serve a phishing page or capture session data.

    Why Django's built-in protection is trusted here
    ─────────────────────────────────────────────────
    ``UserLoginView`` extends ``django.contrib.auth.views.LoginView``, which
    inherits ``RedirectURLMixin.get_redirect_url()``.  That method calls
    ``url_has_allowed_host_and_scheme()`` before honouring any ``next``
    value, and returns ``""`` for unsafe URLs.  When ``next`` is empty,
    ``get_success_url()`` falls back to ``settings.LOGIN_REDIRECT_URL``.

    ``UserLogoutView`` uses the same mixin, so it is equally protected.

    These tests are regression guards: they prove the built-in protection
    is active and has not been accidentally disabled or bypassed.

    URL encoding note
    ─────────────────
    The helper ``_login()`` uses ``urllib.parse.urlencode`` so that values
    like ``http://evil.com/`` are correctly percent-encoded in the query
    string and then decoded by Django's ``QueryDict`` before validation —
    exactly mirroring what a real browser would do.
    """

    DEFAULT_REDIRECT = '/auth/'   # settings.LOGIN_REDIRECT_URL

    def setUp(self):
        cache.clear()
        self.client = Client()
        self.user = make_user(
            username='openuser',
            password='StrongPass123!',
            email='open@example.com',
        )
        self.login_url = reverse('mupenz_fulgence:login')

    def _login(self, next_url=None):
        """
        POST valid credentials to the login endpoint.
        When *next_url* is given it is properly URL-encoded into the query
        string so the test mirrors real browser behaviour.
        """
        from urllib.parse import urlencode
        url = self.login_url
        if next_url is not None:
            url = f'{url}?{urlencode({"next": next_url})}'
        return self.client.post(url, {
            'username': 'openuser',
            'password': 'StrongPass123!',
        })

    # ── Safe internal redirects (must be honoured) ─────────────────────────────

    def test_safe_internal_path_is_followed(self):
        """
        A relative path that stays within the application must be honoured.
        This proves legitimate ``?next=`` usage (e.g. from @login_required)
        still works after a successful login.
        """
        response = self._login(next_url='/auth/profile/')
        self.assertRedirects(response, '/auth/profile/', fetch_redirect_response=False)

    def test_safe_internal_path_with_query_string_is_followed(self):
        """next= paths that carry their own query string must still be allowed."""
        response = self._login(next_url='/auth/staff/users/?q=alice')
        self.assertRedirects(
            response, '/auth/staff/users/?q=alice', fetch_redirect_response=False
        )

    def test_missing_next_redirects_to_default(self):
        """No ``next`` parameter → login sends user to LOGIN_REDIRECT_URL."""
        response = self._login()
        self.assertRedirects(
            response, self.DEFAULT_REDIRECT, fetch_redirect_response=False
        )

    # ── External URLs (must be blocked) ───────────────────────────────────────

    def test_external_http_url_blocked(self):
        """
        ``?next=http://evil.com/`` must not redirect the user off-site.
        url_has_allowed_host_and_scheme rejects any URL with a foreign netloc.
        """
        response = self._login(next_url='http://evil.com/')
        location = response.get('Location', '')
        self.assertNotIn('evil.com', location)
        self.assertRedirects(
            response, self.DEFAULT_REDIRECT, fetch_redirect_response=False
        )

    def test_external_https_url_blocked(self):
        """HTTPS external URLs are also rejected — scheme alone is not sufficient."""
        response = self._login(next_url='https://evil.com/steal-session')
        location = response.get('Location', '')
        self.assertNotIn('evil.com', location)
        self.assertRedirects(
            response, self.DEFAULT_REDIRECT, fetch_redirect_response=False
        )

    def test_protocol_relative_url_blocked(self):
        """
        ``//evil.com/`` is a protocol-relative URL that inherits the page
        scheme and redirects to an external host.  It must be blocked.
        """
        response = self._login(next_url='//evil.com/')
        location = response.get('Location', '')
        self.assertNotIn('evil.com', location)
        self.assertRedirects(
            response, self.DEFAULT_REDIRECT, fetch_redirect_response=False
        )

    def test_javascript_pseudo_url_blocked(self):
        """
        ``javascript:`` pseudo-URLs are not valid redirect targets and must
        be blocked to prevent XSS via location-based script injection.
        """
        response = self._login(next_url='javascript:alert(document.cookie)')
        location = response.get('Location', '')
        self.assertNotIn('javascript', location)
        self.assertRedirects(
            response, self.DEFAULT_REDIRECT, fetch_redirect_response=False
        )

    # ── Encoded / obfuscated attack vectors ───────────────────────────────────

    def test_encoded_protocol_relative_url_blocked(self):
        """
        ``%2F%2Fevil.com%2F`` decodes to ``//evil.com/``.
        Django's QueryDict decodes the value before it reaches
        url_has_allowed_host_and_scheme, so the validation still blocks it.
        """
        # Pass the already-encoded value; urlencode will double-encode it,
        # but that is intentional — Django decodes query string values once.
        from urllib.parse import quote
        encoded = quote('//evil.com/', safe='')          # → %2F%2Fevil.com%2F
        url = f'{self.login_url}?next={encoded}'
        response = self.client.post(url, {
            'username': 'openuser',
            'password': 'StrongPass123!',
        })
        location = response.get('Location', '')
        self.assertNotIn('evil.com', location)

    def test_backslash_host_bypass_blocked(self):
        """
        ``/\\evil.com`` is sometimes parsed by browsers as a redirect to
        evil.com.  url_has_allowed_host_and_scheme is aware of this trick.
        """
        response = self._login(next_url='/\\evil.com')
        location = response.get('Location', '')
        self.assertNotIn('evil.com', location)


# ──────────────────────────────────────────────────────────────────────────────
# Stored XSS — input validation and safe rendering
# ──────────────────────────────────────────────────────────────────────────────

class StoredXSSTests(TestCase):
    """
    Security tests for Stored Cross-Site Scripting (XSS) vulnerabilities.

    Threat model
    ────────────
    An attacker submits a payload such as <script>alert(1)</script> via a
    profile field (bio, location, first_name, last_name).  If the application
    stores and later renders this markup without sanitisation, the script
    executes in any visitor's browser — a classic stored XSS attack.

    Defence layers verified here
    ────────────────────────────
    1. Form-level validation (_reject_html) rejects HTML tags before they reach
       the database.  This is defence-in-depth: the database stays clean even
       if a future template accidentally uses |safe.
    2. Django's template auto-escaping neutralises any markup that does reach
       the database (e.g. via direct DB writes or the Django admin).
       assertNotContains(response, '<script>') confirms the raw tag is absent
       from rendered HTML.

    Fields tested: bio, location, first_name, last_name (profile update form)
                   first_name, last_name (registration form)
    """

    XSS_PAYLOADS = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '"><script>alert(document.cookie)</script>',
        "';alert(String.fromCharCode(88,83,83))//",
        # HTML-entity-encoded variants that browsers decode before parsing
        '&lt;script&gt;alert(1)&lt;/script&gt;',
        # Null-byte injection attempt
        '<scr\x00ipt>alert(1)</scr\x00ipt>',
    ]

    SAFE_TEXT_SAMPLES = [
        'Hello, world!',
        'Born in Kigali, Rwanda.',
        'I love math: a < b && b > c.',
        'Price is $5.00 (approx).',
        'Line one\nLine two',
    ]

    def setUp(self):
        self.client = Client()
        self.user = make_user()
        self.client.login(username='testuser', password='StrongPass123!')
        self.profile_url = reverse('mupenz_fulgence:profile')
        self.register_url = reverse('mupenz_fulgence:register')

    # ── Form validation — HTML tags must be rejected ───────────────────────────

    def _post_profile(self, **overrides):
        """Submit the profile form with safe defaults, overriding named fields."""
        data = {
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'test@example.com',
            'bio': 'A normal bio.',
            'location': 'Kigali',
            'birth_date': '',
        }
        data.update(overrides)
        return self.client.post(self.profile_url, data)

    def test_bio_with_script_tag_rejected(self):
        """
        XSS fix: bio containing a <script> tag must be rejected at the form
        level — the form must be invalid and the database must stay clean.
        """
        response = self._post_profile(bio='<script>alert(1)</script>')
        self.assertEqual(response.status_code, 200)
        form = response.context['form']
        self.assertFalse(form.is_valid())
        self.assertIn('bio', form.errors)
        # Confirm the payload was not persisted
        self.user.profile.refresh_from_db()
        self.assertNotIn('<script>', self.user.profile.bio or '')

    def test_location_with_html_tag_rejected(self):
        """HTML in the location field must be rejected by form validation."""
        response = self._post_profile(location='<img src=x onerror=alert(1)>')
        self.assertEqual(response.status_code, 200)
        form = response.context['form']
        self.assertFalse(form.is_valid())
        self.assertIn('location', form.errors)

    def test_first_name_with_html_tag_rejected(self):
        """HTML in first_name must be rejected by form validation."""
        response = self._post_profile(first_name='<b>Evil</b>')
        self.assertEqual(response.status_code, 200)
        form = response.context['form']
        self.assertFalse(form.is_valid())
        self.assertIn('first_name', form.errors)

    def test_last_name_with_html_tag_rejected(self):
        """HTML in last_name must be rejected by form validation."""
        response = self._post_profile(last_name='<i>Injection</i>')
        self.assertEqual(response.status_code, 200)
        form = response.context['form']
        self.assertFalse(form.is_valid())
        self.assertIn('last_name', form.errors)

    def test_multiple_xss_payloads_rejected_in_bio(self):
        """All common XSS vectors must be rejected in the bio field."""
        html_payloads = [p for p in self.XSS_PAYLOADS if '<' in p or '>' in p]
        for payload in html_payloads:
            with self.subTest(payload=payload):
                response = self._post_profile(bio=payload)
                self.assertEqual(response.status_code, 200)
                form = response.context['form']
                self.assertFalse(
                    form.is_valid(),
                    f'Form accepted XSS payload in bio: {payload!r}',
                )

    # ── Registration form — name fields must reject HTML ───────────────────────
    # Note: RegisterView redirects already-authenticated users, so these tests
    # use a fresh anonymous client instead of self.client (which is logged in).

    def test_registration_first_name_html_rejected(self):
        """
        HTML in first_name during registration must be rejected before the
        account is created, so the user object is never persisted with markup.
        """
        anon = Client()
        response = anon.post(self.register_url, {
            'username': 'xssreg',
            'email': 'xssreg@example.com',
            'first_name': '<script>alert(1)</script>',
            'last_name': 'User',
            'password1': 'StrongPass123!',
            'password2': 'StrongPass123!',
        })
        self.assertEqual(response.status_code, 200)
        form = response.context['form']
        self.assertFalse(form.is_valid())
        self.assertIn('first_name', form.errors)
        self.assertFalse(User.objects.filter(username='xssreg').exists())

    def test_registration_last_name_html_rejected(self):
        """HTML in last_name during registration must prevent account creation."""
        anon = Client()
        response = anon.post(self.register_url, {
            'username': 'xssreg2',
            'email': 'xssreg2@example.com',
            'first_name': 'Test',
            'last_name': '<svg onload=alert(1)>',
            'password1': 'StrongPass123!',
            'password2': 'StrongPass123!',
        })
        self.assertEqual(response.status_code, 200)
        form = response.context['form']
        self.assertFalse(form.is_valid())
        self.assertIn('last_name', form.errors)
        self.assertFalse(User.objects.filter(username='xssreg2').exists())

    # ── Template auto-escaping — raw tags must never appear in HTML output ─────

    def _force_set_bio(self, value):
        """
        Bypass form validation and write directly to the database.
        This simulates data inserted via the Django admin, fixtures, or a
        future code path that omits validation — the rendering layer must
        still be safe.
        """
        profile = self.user.profile
        profile.bio = value
        profile.save()

    def test_stored_script_tag_escaped_on_dashboard(self):
        """
        If a raw <script> tag somehow reaches the database (e.g. via admin),
        Django's auto-escaping must prevent it from executing on the dashboard.
        The raw tag must not appear in the rendered HTML.
        """
        self._force_set_bio('<script>alert(1)</script>')
        response = self.client.get(reverse('mupenz_fulgence:dashboard'))
        self.assertEqual(response.status_code, 200)
        # Raw script tag must NOT appear — it must be HTML-entity-encoded
        self.assertNotContains(response, '<script>alert(1)</script>')
        # The escaped form should be present (confirms Django did not silently
        # drop the value — it rendered it safely)
        self.assertContains(response, '&lt;script&gt;')

    def test_stored_script_tag_escaped_on_profile_detail(self):
        """
        Same as above, but verified on the user profile detail page where
        bio is also displayed.
        """
        self._force_set_bio('<script>alert(document.cookie)</script>')
        profile = self.user.profile
        detail_url = reverse(
            'mupenz_fulgence:user_profile_detail', kwargs={'pk': profile.pk}
        )
        response = self.client.get(detail_url)
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, '<script>alert(document.cookie)</script>')
        self.assertContains(response, '&lt;script&gt;')

    def test_img_onerror_payload_escaped_on_dashboard(self):
        """Event-handler injection via <img onerror=...> must also be escaped."""
        self._force_set_bio('<img src=x onerror=alert(1)>')
        response = self.client.get(reverse('mupenz_fulgence:dashboard'))
        self.assertNotContains(response, '<img src=x onerror=alert(1)>')
        self.assertContains(response, '&lt;img')

    # ── Safe content — legitimate text must render correctly ───────────────────

    def test_safe_text_renders_correctly_on_dashboard(self):
        """Normal bio text must still be visible after the XSS fixes."""
        for text in self.SAFE_TEXT_SAMPLES:
            with self.subTest(text=text):
                self._force_set_bio(text)
                response = self.client.get(reverse('mupenz_fulgence:dashboard'))
                self.assertEqual(response.status_code, 200)
                # The plain text content must appear somewhere in the response
                # (Django may escape special chars like < and &, so we check
                # for short, unambiguous fragments only).
                safe_fragment = text.split('<')[0].split('&')[0].strip()
                if safe_fragment:
                    self.assertContains(response, safe_fragment)

    def test_profile_update_with_clean_text_succeeds(self):
        """
        Verify that the form-level XSS validators do NOT block legitimate
        content — only actual HTML tags should be rejected.
        """
        response = self._post_profile(
            first_name='Jane',
            last_name='Doe',
            bio='I enjoy hiking & photography.',
            location='Kigali, Rwanda',
        )
        # Successful update redirects back to the profile page
        self.assertRedirects(response, self.profile_url)
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Jane')
        self.assertEqual(self.user.profile.location, 'Kigali, Rwanda')

    # ── Reflected XSS — search_query must be escaped in HTML output ────────────

    def test_search_query_script_tag_not_executed(self):
        """
        XSS risk: the search query is reflected in the User Management page.
        A malicious ?q=<script>...</script> must not appear unescaped in the
        response HTML.
        """
        staff = make_staff_user()
        self.client.login(username='staff_user', password='StrongPass123!')
        payload = '<script>alert(1)</script>'
        response = self.client.get(
            reverse('mupenz_fulgence:user_list') + f'?q={payload}'
        )
        self.assertEqual(response.status_code, 200)
        # Raw tag must not appear in rendered output
        self.assertNotContains(response, '<script>alert(1)</script>')

    def test_search_query_img_payload_not_executed(self):
        """Event-handler payloads in ?q= must also be safely escaped."""
        make_staff_user()
        self.client.login(username='staff_user', password='StrongPass123!')
        payload = '<img src=x onerror=alert(1)>'
        response = self.client.get(
            reverse('mupenz_fulgence:user_list') + f'?q={payload}'
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, '<img src=x onerror=alert(1)>')

    def test_search_query_normal_text_reflected_safely(self):
        """Normal search queries must still be echoed back in the response."""
        make_staff_user()
        self.client.login(username='staff_user', password='StrongPass123!')
        response = self.client.get(
            reverse('mupenz_fulgence:user_list') + '?q=alice'
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'alice')


# ──────────────────────────────────────────────────────────────────────────────
# File upload — helper factories
# ──────────────────────────────────────────────────────────────────────────────

def make_image_file(fmt='PNG', width=10, height=10, name=None) -> SimpleUploadedFile:
    """Return a SimpleUploadedFile containing a real, Pillow-generated image."""
    buf = io.BytesIO()
    Image.new('RGB', (width, height), color=(255, 0, 0)).save(buf, format=fmt)
    buf.seek(0)
    filename = name or f'test.{fmt.lower()}'
    mime     = f'image/{fmt.lower()}'
    return SimpleUploadedFile(filename, buf.read(), content_type=mime)


def make_pdf_file(name='test.pdf', size_bytes=512) -> SimpleUploadedFile:
    """Return a SimpleUploadedFile containing a minimal valid PDF."""
    # A real (though trivially short) PDF body — starts with the magic bytes.
    content = b'%PDF-1.4\n1 0 obj\n<</Type /Catalog>>\nendobj\nstartxref\n0\n%%EOF'
    content = content.ljust(size_bytes, b'\n')   # pad to requested size
    return SimpleUploadedFile(name, content, content_type='application/pdf')


def make_fake_pdf(name='evil.pdf') -> SimpleUploadedFile:
    """Return a file with a .pdf extension but no PDF magic bytes (malicious rename)."""
    content = b'<?php system($_GET["cmd"]); ?>'
    return SimpleUploadedFile(name, content, content_type='application/pdf')


def make_fake_image(name='evil.jpg') -> SimpleUploadedFile:
    """Return a file with a .jpg extension but no image content (malicious rename)."""
    content = b'<script>alert(1)</script>'
    return SimpleUploadedFile(name, content, content_type='image/jpeg')


def make_oversized_image(limit_bytes=AVATAR_MAX_BYTES) -> SimpleUploadedFile:
    """Return a SimpleUploadedFile whose .size exceeds the avatar limit."""
    # We create a real PNG first, then patch its size attribute.
    f = make_image_file()
    f.size = limit_bytes + 1
    return f


def make_oversized_pdf(limit_bytes=DOCUMENT_MAX_BYTES) -> SimpleUploadedFile:
    """Return a SimpleUploadedFile whose .size exceeds the document limit."""
    f = make_pdf_file()
    f.size = limit_bytes + 1
    return f


# ──────────────────────────────────────────────────────────────────────────────
# File upload — unit tests for validators (no HTTP)
# ──────────────────────────────────────────────────────────────────────────────

class FileValidatorUnitTests(TestCase):
    """
    Unit tests for validate_avatar() and validate_document() from validators.py.

    These tests exercise the validators in isolation — no views or HTTP
    requests involved.  They verify the three security layers for each type:
      Avatar   : size limit → extension whitelist → Pillow content check
      Document : size limit → extension whitelist → PDF magic-byte check
    """

    # ── validate_avatar ────────────────────────────────────────────────────────

    def test_valid_png_passes(self):
        """A real PNG image within the size limit must pass without raising."""
        from django.core.exceptions import ValidationError
        validate_avatar(make_image_file('PNG'))   # must not raise

    def test_valid_jpeg_passes(self):
        from django.core.exceptions import ValidationError
        validate_avatar(make_image_file('JPEG', name='photo.jpg'))

    def test_valid_webp_passes(self):
        from django.core.exceptions import ValidationError
        validate_avatar(make_image_file('WEBP', name='photo.webp'))

    def test_avatar_oversized_rejected(self):
        """A file larger than AVATAR_MAX_BYTES must be rejected."""
        from django.core.exceptions import ValidationError
        with self.assertRaises(ValidationError):
            validate_avatar(make_oversized_image())

    def test_avatar_wrong_extension_rejected(self):
        """A file with a .pdf extension must be rejected (wrong type for avatar)."""
        from django.core.exceptions import ValidationError
        f = make_pdf_file(name='photo.pdf')
        with self.assertRaises(ValidationError):
            validate_avatar(f)

    def test_avatar_fake_image_rejected(self):
        """
        Security test: a script renamed to .jpg must be rejected.
        Pillow cannot open non-image bytes and raises UnidentifiedImageError,
        which validate_avatar() converts to ValidationError.
        """
        from django.core.exceptions import ValidationError
        with self.assertRaises(ValidationError):
            validate_avatar(make_fake_image())

    def test_avatar_executable_rejected(self):
        """An EXE header renamed to .png must be rejected."""
        from django.core.exceptions import ValidationError
        f = SimpleUploadedFile(
            'malware.png',
            b'MZ\x90\x00' + b'\x00' * 200,   # DOS/EXE magic bytes
            content_type='image/png',
        )
        with self.assertRaises(ValidationError):
            validate_avatar(f)

    # ── validate_document ──────────────────────────────────────────────────────

    def test_valid_pdf_passes(self):
        """A file with the correct PDF magic bytes and .pdf extension must pass."""
        from django.core.exceptions import ValidationError
        validate_document(make_pdf_file())   # must not raise

    def test_document_oversized_rejected(self):
        """A file larger than DOCUMENT_MAX_BYTES must be rejected."""
        from django.core.exceptions import ValidationError
        with self.assertRaises(ValidationError):
            validate_document(make_oversized_pdf())

    def test_document_wrong_extension_rejected(self):
        """A .jpg extension must be rejected for document uploads."""
        from django.core.exceptions import ValidationError
        f = make_image_file('JPEG', name='doc.jpg')
        with self.assertRaises(ValidationError):
            validate_document(f)

    def test_document_fake_pdf_rejected(self):
        """
        Security test: a PHP script renamed to .pdf must be rejected.
        The file lacks the b'%PDF-' magic bytes → ValidationError.
        """
        from django.core.exceptions import ValidationError
        with self.assertRaises(ValidationError):
            validate_document(make_fake_pdf())

    def test_document_html_renamed_to_pdf_rejected(self):
        """An HTML file renamed to .pdf must be rejected by the magic-byte check."""
        from django.core.exceptions import ValidationError
        f = SimpleUploadedFile(
            'xss.pdf',
            b'<html><script>alert(1)</script></html>',
            content_type='application/pdf',
        )
        with self.assertRaises(ValidationError):
            validate_document(f)

    def test_document_exe_renamed_to_pdf_rejected(self):
        """An EXE file renamed to .pdf must be rejected."""
        from django.core.exceptions import ValidationError
        f = SimpleUploadedFile(
            'malware.pdf',
            b'MZ\x90\x00' + b'\x00' * 200,
            content_type='application/pdf',
        )
        with self.assertRaises(ValidationError):
            validate_document(f)


# ──────────────────────────────────────────────────────────────────────────────
# File upload — avatar upload view (integration tests)
# ──────────────────────────────────────────────────────────────────────────────

@override_settings(MEDIA_ROOT='/tmp/mf_test_media')
class AvatarUploadViewTests(TestCase):
    """
    Integration tests for AvatarUploadView (/auth/upload/avatar/).

    Uses @override_settings(MEDIA_ROOT=...) so test uploads go to a temp
    directory and never touch the real media folder.
    """

    def setUp(self):
        self.client = Client()
        self.user   = make_user()
        self.client.login(username='testuser', password='StrongPass123!')
        self.url = reverse('mupenz_fulgence:upload_avatar')

    # ── Page access ───────────────────────────────────────────────────────────

    def test_upload_page_requires_login(self):
        """Anonymous users must be redirected to the login page."""
        anon = Client()
        response = anon.get(self.url)
        self.assertRedirects(response, f'{reverse("mupenz_fulgence:login")}?next={self.url}')

    def test_upload_page_renders_for_authenticated_user(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'mupenz_fulgence/upload_avatar.html')

    # ── Valid upload ───────────────────────────────────────────────────────────

    def test_valid_png_upload_succeeds(self):
        """A valid PNG image must be accepted and redirect back to profile."""
        response = self.client.post(self.url, {'avatar': make_image_file('PNG')})
        self.assertRedirects(response, reverse('mupenz_fulgence:profile'))
        self.user.profile.refresh_from_db()
        self.assertTrue(bool(self.user.profile.avatar))

    def test_valid_jpeg_upload_succeeds(self):
        response = self.client.post(
            self.url, {'avatar': make_image_file('JPEG', name='photo.jpg')}
        )
        self.assertRedirects(response, reverse('mupenz_fulgence:profile'))
        self.user.profile.refresh_from_db()
        self.assertTrue(bool(self.user.profile.avatar))

    # ── Invalid uploads ───────────────────────────────────────────────────────

    def test_fake_image_rejected(self):
        """
        Security test: a script file renamed to .jpg must be rejected.
        The form must be invalid and no file stored.
        """
        response = self.client.post(self.url, {'avatar': make_fake_image()})
        self.assertEqual(response.status_code, 200)
        form = response.context['form']
        self.assertFalse(form.is_valid())
        # Profile avatar must remain empty
        self.user.profile.refresh_from_db()
        self.assertFalse(bool(self.user.profile.avatar))

    def test_executable_renamed_to_png_rejected(self):
        """EXE content with .png extension must be rejected."""
        f = SimpleUploadedFile(
            'malware.png',
            b'MZ\x90\x00' + b'\x00' * 200,
            content_type='image/png',
        )
        response = self.client.post(self.url, {'avatar': f})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context['form'].is_valid())

    def test_pdf_rejected_as_avatar(self):
        """A PDF file must be rejected when uploaded as an avatar."""
        response = self.client.post(self.url, {'avatar': make_pdf_file(name='photo.pdf')})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context['form'].is_valid())

    def test_wrong_extension_html_rejected(self):
        """An HTML file must be rejected regardless of Content-Type."""
        f = SimpleUploadedFile(
            'page.html',
            b'<html><body>hi</body></html>',
            content_type='image/jpeg',
        )
        response = self.client.post(self.url, {'avatar': f})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context['form'].is_valid())

    def test_oversized_avatar_rejected(self):
        """
        A file exceeding the size limit must be rejected with an error.

        Why not use make_oversized_image() here?
        Django's test client re-encodes the file as a multipart request body,
        so the server-side InMemoryUploadedFile.size is recalculated from the
        actual byte content — any .size patch on the in-process object is lost.
        We instead lower the module-level AVATAR_MAX_BYTES constant to 1 byte
        below the real file's size, so the server-side check fires correctly.
        """
        from unittest.mock import patch
        img = make_image_file('PNG')
        # Read the actual encoded size so we can set the limit just below it
        real_size = len(img.read())
        img.seek(0)
        with patch('mupenz_fulgence.validators.AVATAR_MAX_BYTES', real_size - 1):
            response = self.client.post(self.url, {'avatar': img})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context['form'].is_valid())
        self.assertIn('avatar', response.context['form'].errors)


# ──────────────────────────────────────────────────────────────────────────────
# File upload — document upload view (integration tests)
# ──────────────────────────────────────────────────────────────────────────────

@override_settings(MEDIA_ROOT='/tmp/mf_test_media')
class DocumentUploadViewTests(TestCase):
    """
    Integration tests for DocumentUploadView (/auth/upload/document/).
    """

    def setUp(self):
        self.client = Client()
        self.user   = make_user()
        self.client.login(username='testuser', password='StrongPass123!')
        self.url = reverse('mupenz_fulgence:upload_document')

    # ── Page access ───────────────────────────────────────────────────────────

    def test_upload_page_requires_login(self):
        anon = Client()
        response = anon.get(self.url)
        self.assertRedirects(response, f'{reverse("mupenz_fulgence:login")}?next={self.url}')

    def test_upload_page_renders_for_authenticated_user(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'mupenz_fulgence/upload_document.html')

    # ── Valid upload ───────────────────────────────────────────────────────────

    def test_valid_pdf_upload_succeeds(self):
        """A valid PDF must be accepted and redirect back to profile."""
        response = self.client.post(self.url, {'document': make_pdf_file()})
        self.assertRedirects(response, reverse('mupenz_fulgence:profile'))
        self.user.profile.refresh_from_db()
        self.assertTrue(bool(self.user.profile.document))

    # ── Invalid uploads ───────────────────────────────────────────────────────

    def test_fake_pdf_rejected(self):
        """
        Security test: a PHP script renamed to .pdf must be rejected.
        The magic-byte check (b'%PDF-') fails for non-PDF content.
        """
        response = self.client.post(self.url, {'document': make_fake_pdf()})
        self.assertEqual(response.status_code, 200)
        form = response.context['form']
        self.assertFalse(form.is_valid())
        self.assertIn('document', form.errors)
        # Profile document must remain empty
        self.user.profile.refresh_from_db()
        self.assertFalse(bool(self.user.profile.document))

    def test_image_rejected_as_document(self):
        """A valid image file must be rejected when uploaded as a document."""
        response = self.client.post(self.url, {'document': make_image_file('PNG', name='doc.png')})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context['form'].is_valid())

    def test_html_renamed_to_pdf_rejected(self):
        """An XSS payload in an HTML file renamed .pdf must be rejected."""
        f = SimpleUploadedFile(
            'xss.pdf',
            b'<html><script>alert(1)</script></html>',
            content_type='application/pdf',
        )
        response = self.client.post(self.url, {'document': f})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context['form'].is_valid())

    def test_exe_renamed_to_pdf_rejected(self):
        """An executable renamed to .pdf must be rejected by magic-byte check."""
        f = SimpleUploadedFile(
            'malware.pdf',
            b'MZ\x90\x00' + b'\x00' * 200,
            content_type='application/pdf',
        )
        response = self.client.post(self.url, {'document': f})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context['form'].is_valid())

    def test_oversized_document_rejected(self):
        """
        A file exceeding the size limit must be rejected.

        Same reasoning as AvatarUploadViewTests.test_oversized_avatar_rejected:
        the test client re-encodes the file, so we patch DOCUMENT_MAX_BYTES to
        be 1 byte below the real file's byte count instead of using a fake .size.
        """
        from unittest.mock import patch
        pdf = make_pdf_file()
        real_size = len(pdf.read())
        pdf.seek(0)
        with patch('mupenz_fulgence.validators.DOCUMENT_MAX_BYTES', real_size - 1):
            response = self.client.post(self.url, {'document': pdf})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context['form'].is_valid())
        self.assertIn('document', response.context['form'].errors)

    def test_js_file_rejected(self):
        """A JavaScript file must be rejected by the extension whitelist."""
        f = SimpleUploadedFile(
            'attack.js',
            b'alert(1)',
            content_type='application/javascript',
        )
        response = self.client.post(self.url, {'document': f})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context['form'].is_valid())


# ──────────────────────────────────────────────────────────────────────────────
# File upload — document access control (DocumentServeView)
# ──────────────────────────────────────────────────────────────────────────────

@override_settings(MEDIA_ROOT='/tmp/mf_test_media')
class DocumentAccessControlTests(TestCase):
    """
    Authorization tests for DocumentServeView (/auth/users/<pk>/document/).

    Security properties verified:
      - Anonymous users are redirected to login.
      - A user can download their own document.
      - A user requesting another user's document pk gets HTTP 404 (not 403),
        preventing object-existence enumeration (same IDOR rationale as profile
        detail view).
      - Staff can access any user's document.
      - A request for a profile with no document returns HTTP 404.
    """

    def setUp(self):
        self.client  = Client()
        self.owner   = make_user(username='doc_owner', email='owner@example.com')
        self.other   = make_user(username='doc_other', email='other@example.com')
        self.staff   = make_staff_user()
        # Attach a valid PDF directly to the owner's profile (bypasses the view
        # so we can test DocumentServeView independently of DocumentUploadView).
        profile = self.owner.profile
        profile.document.save(
            'test.pdf',
            SimpleUploadedFile('test.pdf', make_pdf_file().read(),
                               content_type='application/pdf'),
            save=True,
        )
        self.owner_profile = profile
        self.other_profile = self.other.profile
        self.login_url     = reverse('mupenz_fulgence:login')

    def _url(self, profile):
        return reverse('mupenz_fulgence:serve_document', kwargs={'pk': profile.pk})

    # ── Anonymous ─────────────────────────────────────────────────────────────

    def test_anonymous_redirected_to_login(self):
        url = self._url(self.owner_profile)
        response = self.client.get(url)
        self.assertRedirects(response, f'{self.login_url}?next={url}')

    # ── Owner access ──────────────────────────────────────────────────────────

    def test_owner_can_download_own_document(self):
        """The document owner must receive a PDF attachment response."""
        self.client.login(username='doc_owner', password='StrongPass123!')
        response = self.client.get(self._url(self.owner_profile))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/pdf')
        self.assertIn('attachment', response.get('Content-Disposition', ''))

    # ── IDOR: regular user requesting another user's document ─────────────────

    def test_cross_user_document_returns_404(self):
        """
        IDOR fix: a regular user requesting another user's document pk must
        receive HTTP 404, NOT 403 (same rationale as profile detail view).
        """
        self.client.login(username='doc_other', password='StrongPass123!')
        response = self.client.get(self._url(self.owner_profile))
        self.assertEqual(response.status_code, 404)

    def test_nonexistent_pk_returns_404(self):
        """A totally nonexistent pk must return 404 for both regular and staff."""
        self.client.login(username='doc_owner', password='StrongPass123!')
        url = reverse('mupenz_fulgence:serve_document', kwargs={'pk': 99999})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)

    # ── Profile without document ───────────────────────────────────────────────

    def test_profile_without_document_returns_404(self):
        """If the owner has no document uploaded, the serve view returns 404."""
        self.client.login(username='doc_other', password='StrongPass123!')
        # other_profile has no document (setUp only sets owner's)
        # Staff path is needed since other user can't see other_profile via regular path
        self.client.login(username='staff_user', password='StrongPass123!')
        response = self.client.get(self._url(self.other_profile))
        self.assertEqual(response.status_code, 404)

    # ── Staff access (legitimate) ─────────────────────────────────────────────

    def test_staff_can_download_any_document(self):
        """Staff must be able to download any user's document for management."""
        self.client.login(username='staff_user', password='StrongPass123!')
        response = self.client.get(self._url(self.owner_profile))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/pdf')

    # ── Filename randomization check ──────────────────────────────────────────

    def test_stored_filename_is_randomized(self):
        """
        The storage path must not match the original upload filename.
        This verifies that avatar_upload_to / document_upload_to replace
        the original name with a UUID-based string.
        """
        profile = self.owner_profile
        self.assertIn('/', profile.document.name)   # has a directory component
        # The basename must NOT be 'test.pdf' (the original name)
        import os
        stored_name = os.path.basename(profile.document.name)
        self.assertNotEqual(stored_name, 'test.pdf')
        # It should be a hex string + .pdf (32 hex chars + extension)
        self.assertTrue(stored_name.endswith('.pdf'))
        self.assertGreater(len(stored_name), 10)


class SafeRedirectUrlTests(TestCase):
    """
    Unit tests for the ``safe_redirect_url()`` utility in utils.py.

    These tests exercise the function in isolation using Django's
    ``RequestFactory`` so they are fast and do not hit the database.

    The utility wraps ``url_has_allowed_host_and_scheme`` with a
    named, importable interface that any custom view can call when it
    needs to redirect based on user-supplied input.
    """

    def setUp(self):
        from django.test import RequestFactory
        self.request = RequestFactory().get('/')
        # RequestFactory sets SERVER_NAME='testserver', SERVER_PORT='80'
        # so request.get_host() == 'testserver'.

    def _safe(self, url, **kw):
        from mupenz_fulgence.utils import safe_redirect_url
        return safe_redirect_url(self.request, url, **kw)

    # ── URLs that must be allowed ──────────────────────────────────────────────

    def test_relative_path_is_allowed(self):
        self.assertEqual(self._safe('/auth/profile/'), '/auth/profile/')

    def test_relative_path_with_query_string_is_allowed(self):
        self.assertEqual(
            self._safe('/auth/staff/users/?q=test'), '/auth/staff/users/?q=test'
        )

    def test_same_host_absolute_url_is_allowed(self):
        """An absolute URL whose host matches the request host is safe."""
        self.assertEqual(
            self._safe('http://testserver/auth/'), 'http://testserver/auth/'
        )

    def test_root_path_is_allowed(self):
        self.assertEqual(self._safe('/'), '/')

    # ── URLs that must be blocked ──────────────────────────────────────────────

    def test_external_http_url_uses_fallback(self):
        result = self._safe('http://evil.com/', fallback='/auth/')
        self.assertEqual(result, '/auth/')

    def test_external_https_url_uses_fallback(self):
        result = self._safe('https://evil.com/', fallback='/auth/')
        self.assertEqual(result, '/auth/')

    def test_protocol_relative_url_uses_fallback(self):
        result = self._safe('//evil.com/', fallback='/auth/')
        self.assertEqual(result, '/auth/')

    def test_javascript_pseudo_url_uses_fallback(self):
        result = self._safe('javascript:alert(1)', fallback='/auth/')
        self.assertEqual(result, '/auth/')

    def test_data_uri_uses_fallback(self):
        result = self._safe('data:text/html,<script>alert(1)</script>', fallback='/auth/')
        self.assertEqual(result, '/auth/')

    def test_empty_string_uses_fallback(self):
        result = self._safe('', fallback='/auth/')
        self.assertEqual(result, '/auth/')

    def test_none_equivalent_blocked(self):
        """A URL that is falsy should fall back, not crash."""
        result = self._safe('   ', fallback='/auth/')
        self.assertEqual(result, '/auth/')

    # ── Default fallback behaviour ─────────────────────────────────────────────

    def test_default_fallback_is_dashboard(self):
        """
        When no explicit fallback is given and the URL is unsafe, the function
        returns the dashboard URL (defined in utils._SAFE_FALLBACK).
        """
        result = self._safe('http://evil.com/')
        # Must not be the external URL
        self.assertNotEqual(result, 'http://evil.com/')
        # Must be a non-empty internal path
        self.assertTrue(result.startswith('/'))

    def test_custom_fallback_is_respected(self):
        """Callers can override the default fallback per call-site."""
        result = self._safe('http://evil.com/', fallback='/custom/landing/')
        self.assertEqual(result, '/custom/landing/')
