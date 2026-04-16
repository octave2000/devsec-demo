"""
URL configuration for devsec_demo project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

# Custom 403 handler — renders a styled page instead of Django's plain default
handler403 = 'mupenz_fulgence.views.permission_denied_view'

urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/', include('mupenz_fulgence.urls')),
]

# ── Development media serving ──────────────────────────────────────────────
# In development (DEBUG=True), Django's dev server can serve uploaded media
# files.  In production, the web server (Nginx / Apache) should serve
# MEDIA_ROOT/avatars/ directly.
#
# SECURITY: MEDIA_ROOT/documents/ must NOT be served here or by the web
# server directly.  All document access goes through DocumentServeView which
# enforces per-user ownership.  If you add Nginx rules for MEDIA_ROOT, add
# an explicit "deny all" for the documents/ subdirectory.
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)


