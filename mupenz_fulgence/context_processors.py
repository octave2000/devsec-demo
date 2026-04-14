"""
mupenz_fulgence.context_processors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Injects role flags into every template context so that templates can
conditionally render UI elements without duplicating role-check logic.

Available in every template (no import needed):
    {{ user_role }}       — 'anonymous' | 'user' | 'student' | 'instructor' | 'staff' | 'admin'
    {{ is_student }}      — True if student, instructor, staff, or admin
    {{ is_instructor }}   — True if instructor, staff, or admin
    {{ is_staff_member }} — True if is_staff or superuser
    {{ is_admin }}        — True if superuser

Register in settings.py under TEMPLATES[0]['OPTIONS']['context_processors'].
"""
from .rbac import get_user_role


def user_roles(request):
    user = request.user

    if not user.is_authenticated:
        return {
            'user_role':       'anonymous',
            'is_student':      False,
            'is_instructor':   False,
            'is_staff_member': False,
            'is_admin':        False,
        }

    is_admin_user   = user.is_superuser
    is_staff_member = user.is_staff

    # Batch the group name lookup into a single query
    group_names = set(
        user.groups.values_list('name', flat=True)
    ) if not (is_staff_member or is_admin_user) else set()

    is_instructor_member = 'Instructor' in group_names
    is_student_member    = 'Student' in group_names

    return {
        'user_role':       get_user_role(user),
        'is_student':      is_student_member or is_instructor_member or is_staff_member or is_admin_user,
        'is_instructor':   is_instructor_member or is_staff_member or is_admin_user,
        'is_staff_member': is_staff_member or is_admin_user,
        'is_admin':        is_admin_user,
    }
