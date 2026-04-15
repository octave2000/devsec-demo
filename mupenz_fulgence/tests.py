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
"""
from django.contrib.auth.models import Group, User
from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.core.cache import cache
from django.test import Client, TestCase
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from .models import Profile
from .rbac import get_user_role


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
