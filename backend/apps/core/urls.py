from django.urls import path

from .auth_views import LoginView, LogoutView, MeView
from .views import HealthView

urlpatterns = [
    path("health/", HealthView.as_view(), name="health"),
    path("v1/auth/login/", LoginView.as_view(), name="auth-login"),
    path("v1/auth/logout/", LogoutView.as_view(), name="auth-logout"),
    path("v1/auth/me/", MeView.as_view(), name="auth-me"),
]
