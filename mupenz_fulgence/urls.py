from django.urls import path

from . import views

app_name = 'mupenz_fulgence'

urlpatterns = [
    # ── Public ───────────────────────────────────────────────────────────────
    path('register/', views.RegisterView.as_view(),   name='register'),
    path('login/',    views.UserLoginView.as_view(),   name='login'),
    path('logout/',   views.UserLogoutView.as_view(),  name='logout'),

    # ── Password reset (public — unauthenticated users) ───────────────────────
    # Step 1: request form
    path('password-reset/',
         views.UserPasswordResetView.as_view(),
         name='password_reset'),
    # Step 2: "check your inbox" confirmation
    path('password-reset/done/',
         views.UserPasswordResetDoneView.as_view(),
         name='password_reset_done'),
    # Step 3: new-password form (token from emailed link)
    path('reset/<uidb64>/<token>/',
         views.UserPasswordResetConfirmView.as_view(),
         name='password_reset_confirm'),
    # Step 4: success page after password saved
    path('reset/done/',
         views.UserPasswordResetCompleteView.as_view(),
         name='password_reset_complete'),

    # ── Authenticated users ───────────────────────────────────────────────────
    path('',                  views.DashboardView.as_view(),          name='dashboard'),
    path('profile/',          views.ProfileView.as_view(),            name='profile'),
    path('password/change/',  views.UserPasswordChangeView.as_view(), name='password_change'),

    # ── RBAC — Instructor+ ────────────────────────────────────────────────────
    path('instructor/', views.InstructorPanelView.as_view(), name='instructor_panel'),

    # ── RBAC — Staff+ ────────────────────────────────────────────────────────
    path('staff/',        views.StaffDashboardView.as_view(), name='staff_dashboard'),
    path('staff/users/',  views.UserListView.as_view(),       name='user_list'),

    # ── IDOR-safe profile detail (own profile for users; any for staff/admin) ──
    path('users/<int:pk>/profile/', views.UserProfileDetailView.as_view(), name='user_profile_detail'),

    # ── RBAC — Admin only ─────────────────────────────────────────────────────
    path('admin-panel/', views.AdminDashboardView.as_view(), name='admin_dashboard'),
]
