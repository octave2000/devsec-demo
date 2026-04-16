"""
Usage:
    python manage.py setup_groups

Creates the default RBAC groups, assigns model-level permissions,
and provisions one demo user per group.

Safe to run multiple times (fully idempotent).

Groups & demo accounts:
  Student    — view_profile permission | demo user: demo_student  / Student@Demo1
  Instructor — view_profile permission | demo user: demo_instructor / Instructor@Demo1
"""
from django.contrib.auth.models import Group, Permission, User
from django.contrib.contenttypes.models import ContentType
from django.core.management.base import BaseCommand

from mupenz_fulgence.models import Profile


# Demo credentials — printed to stdout so the developer can log in immediately
_DEMO_USERS = [
    {
        'username':   'demo_student',
        'password':   'Student@Demo1',
        'email':      'demo.student@mfauth.local',
        'first_name': 'Demo',
        'last_name':  'Student',
        'group':      'Student',
    },
    {
        'username':   'demo_instructor',
        'password':   'Instructor@Demo1',
        'email':      'demo.instructor@mfauth.local',
        'first_name': 'Demo',
        'last_name':  'Instructor',
        'group':      'Instructor',
    },
]


class Command(BaseCommand):
    help = 'Create default RBAC groups and demo users for mupenz_fulgence.'

    def handle(self, *args, **options):
        self.stdout.write('Configuring RBAC groups...\n')

        profile_ct = ContentType.objects.get_for_model(Profile)
        view_perm  = Permission.objects.get(
            codename='view_profile',
            content_type=profile_ct,
        )

        # ── Groups ────────────────────────────────────────────────────────────
        for group_name in ('Student', 'Instructor'):
            group, created = Group.objects.get_or_create(name=group_name)
            group.permissions.set([view_perm])
            status = 'created' if created else 'already exists'
            self.stdout.write(
                self.style.SUCCESS(f'  [OK] {group_name} group {status}.')
            )

        self.stdout.write('')

        # ── Demo users ────────────────────────────────────────────────────────
        self.stdout.write('Provisioning demo users...\n')

        for spec in _DEMO_USERS:
            user, created = User.objects.get_or_create(
                username=spec['username'],
                defaults={
                    'email':      spec['email'],
                    'first_name': spec['first_name'],
                    'last_name':  spec['last_name'],
                },
            )

            if created:
                user.set_password(spec['password'])
                user.save()
                # Ensure the signal-created Profile is saved (already done by signal)
                Profile.objects.get_or_create(user=user)
                action = 'created'
            else:
                action = 'already exists'

            # Always (re-)assign to the correct group
            group = Group.objects.get(name=spec['group'])
            user.groups.set([group])

            self.stdout.write(
                self.style.SUCCESS(
                    f'  [OK] {spec["username"]} ({spec["group"]}) — {action}.'
                )
            )

        # ── Summary ───────────────────────────────────────────────────────────
        self.stdout.write('')
        self.stdout.write(self.style.SUCCESS('Setup complete.\n'))
        self.stdout.write('Demo credentials:')
        self.stdout.write('-' * 42)
        for spec in _DEMO_USERS:
            self.stdout.write(
                f'  Role       : {spec["group"]}'
            )
            self.stdout.write(f'  Username   : {spec["username"]}')
            self.stdout.write(f'  Password   : {spec["password"]}')
            self.stdout.write(f'  Login URL  : http://127.0.0.1:8000/auth/login/')
            self.stdout.write('-' * 42)
