from django.urls import path

from .access_views import AccessRequestActionView, AccessRequestListView
from .auth_views import LoginView, LogoutView, MeView, RegisterView
from .password_reset_views import (
    PasswordResetCreateView,
    PasswordResetRequestActionView,
    PasswordResetRequestListView,
)
from .views import HealthView

urlpatterns = [
    path("health/", HealthView.as_view(), name="health"),
    path("v1/auth/login/", LoginView.as_view(), name="auth-login"),
    path("v1/auth/register/", RegisterView.as_view(), name="auth-register"),
    path(
        "v1/auth/password-reset/",
        PasswordResetCreateView.as_view(),
        name="password-reset-create",
    ),
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
    path(
        "v1/admin/password-reset-requests/",
        PasswordResetRequestListView.as_view(),
        name="password-reset-request-list",
    ),
    path(
        "v1/admin/password-reset-requests/<int:pk>/<str:action>/",
        PasswordResetRequestActionView.as_view(),
        name="password-reset-request-action",
    ),
]
