from django.urls import path

from . import views

app_name = 'mupenz_fulgence'

urlpatterns = [
    # ── Public ───────────────────────────────────────────────────────────────
    path('register/', views.RegisterView.as_view(),   name='register'),
    path('login/',    views.UserLoginView.as_view(),   name='login'),
    path('logout/',   views.UserLogoutView.as_view(),  name='logout'),

    # ── Authenticated users ───────────────────────────────────────────────────
    path('',                  views.DashboardView.as_view(),          name='dashboard'),
    path('profile/',          views.ProfileView.as_view(),            name='profile'),
    path('password/change/',  views.UserPasswordChangeView.as_view(), name='password_change'),

    # ── RBAC — Instructor+ ────────────────────────────────────────────────────
    path('instructor/', views.InstructorPanelView.as_view(), name='instructor_panel'),

    # ── RBAC — Staff+ ────────────────────────────────────────────────────────
    path('staff/',        views.StaffDashboardView.as_view(), name='staff_dashboard'),
    path('staff/users/',  views.UserListView.as_view(),       name='user_list'),

    # ── RBAC — Admin only ─────────────────────────────────────────────────────
    path('admin-panel/', views.AdminDashboardView.as_view(), name='admin_dashboard'),
]
