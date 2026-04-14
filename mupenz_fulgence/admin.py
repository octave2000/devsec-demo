from django.contrib import admin
from django.contrib.auth.admin import GroupAdmin as BaseGroupAdmin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import Group, User
from django.utils.html import format_html

from .models import Profile
from .rbac import get_user_role


# ── Helpers ────────────────────────────────────────────────────────────────────

_ROLE_COLOURS = {
    'admin':      '#dc3545',   # red
    'staff':      '#fd7e14',   # orange
    'instructor': '#0dcaf0',   # cyan
    'student':    '#198754',   # green
    'user':       '#6c757d',   # grey
}


# ── Profile inline ─────────────────────────────────────────────────────────────

class ProfileInline(admin.StackedInline):
    model = Profile
    can_delete = False
    verbose_name_plural = 'Profile'
    fields = ('bio', 'location', 'birth_date')


# ── Admin actions ──────────────────────────────────────────────────────────────

@admin.action(description='Add selected users to the Student group')
def make_student(modeladmin, request, queryset):
    group, _ = Group.objects.get_or_create(name='Student')
    for user in queryset:
        user.groups.add(group)
    modeladmin.message_user(
        request,
        f'{queryset.count()} user(s) added to the Student group.',
    )


@admin.action(description='Remove selected users from the Student group')
def remove_student(modeladmin, request, queryset):
    try:
        group = Group.objects.get(name='Student')
    except Group.DoesNotExist:
        modeladmin.message_user(request, 'Student group does not exist.', level='warning')
        return
    for user in queryset:
        user.groups.remove(group)
    modeladmin.message_user(
        request,
        f'{queryset.count()} user(s) removed from the Student group.',
    )


@admin.action(description='Add selected users to the Instructor group')
def make_instructor(modeladmin, request, queryset):
    group, _ = Group.objects.get_or_create(name='Instructor')
    for user in queryset:
        user.groups.add(group)
    modeladmin.message_user(
        request,
        f'{queryset.count()} user(s) added to the Instructor group.',
    )


@admin.action(description='Remove selected users from the Instructor group')
def remove_instructor(modeladmin, request, queryset):
    try:
        group = Group.objects.get(name='Instructor')
    except Group.DoesNotExist:
        modeladmin.message_user(request, 'Instructor group does not exist.', level='warning')
        return
    for user in queryset:
        user.groups.remove(group)
    modeladmin.message_user(
        request,
        f'{queryset.count()} user(s) removed from the Instructor group.',
    )


# ── Enhanced User admin ────────────────────────────────────────────────────────

class UserAdmin(BaseUserAdmin):
    inlines = (ProfileInline,)
    actions = [make_student, remove_student, make_instructor, remove_instructor]

    list_display = (
        'username', 'email', 'first_name', 'last_name',
        'role_badge', 'is_active', 'date_joined',
    )
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'groups')
    search_fields = ('username', 'email', 'first_name', 'last_name')

    @admin.display(description='Role', ordering='is_superuser')
    def role_badge(self, obj):
        role = get_user_role(obj)
        colour = _ROLE_COLOURS.get(role, '#6c757d')
        return format_html(
            '<span style="'
            'background:{colour};color:#fff;padding:2px 8px;'
            'border-radius:10px;font-size:11px;font-weight:600;'
            '">{role}</span>',
            colour=colour,
            role=role.upper(),
        )


admin.site.unregister(User)
admin.site.register(User, UserAdmin)


# ── Enhanced Group admin ───────────────────────────────────────────────────────

class GroupAdmin(BaseGroupAdmin):
    list_display = ('name', 'member_count', 'permission_count')

    @admin.display(description='Members')
    def member_count(self, obj):
        return obj.user_set.count()

    @admin.display(description='Permissions')
    def permission_count(self, obj):
        return obj.permissions.count()


admin.site.unregister(Group)
admin.site.register(Group, GroupAdmin)


# ── Profile admin ──────────────────────────────────────────────────────────────

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'location', 'birth_date', 'created_at', 'updated_at')
    search_fields = ('user__username', 'user__email', 'location')
    readonly_fields = ('created_at', 'updated_at')
    list_select_related = ('user',)
