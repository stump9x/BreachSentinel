from django.urls import path

from .access_views import AccessRequestActionView, AccessRequestListView
from .auth_views import LoginView, LogoutView, MeView, RegisterView
from .views import HealthView

urlpatterns = [
    path("health/", HealthView.as_view(), name="health"),
    path("v1/auth/login/", LoginView.as_view(), name="auth-login"),
    path("v1/auth/register/", RegisterView.as_view(), name="auth-register"),
    path("v1/auth/logout/", LogoutView.as_view(), name="auth-logout"),
    path("v1/auth/me/", MeView.as_view(), name="auth-me"),
    path(
        "v1/admin/access-requests/",
        AccessRequestListView.as_view(),
        name="access-request-list",
    ),
    path(
        "v1/admin/access-requests/<int:pk>/<str:action>/",
        AccessRequestActionView.as_view(),
        name="access-request-action",
    ),
]
