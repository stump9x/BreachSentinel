from django.contrib.auth import get_user_model
from django.core.cache import cache
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.test import APITestCase

from apps.core.models import AccessRequest, AccessRequestAudit


class AccessRequestApiTests(APITestCase):
    password = "Strong-Test-Password-9481"

    def setUp(self):
        cache.clear()

    def register(self, username="new-analyst"):
        return self.client.post(
            "/api/v1/auth/register/",
            {
                "username": username,
                "password": self.password,
                "password_confirm": self.password,
            },
            format="json",
        )

    def test_registration_creates_inactive_pending_user(self):
        response = self.register()
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        user = get_user_model().objects.get(username="new-analyst")
        self.assertFalse(user.is_active)
        self.assertFalse(user.is_staff)
        self.assertTrue(user.check_password(self.password))
        self.assertEqual(user.access_request.status, AccessRequest.Status.PENDING)
        self.assertTrue(
            user.access_request.audit_events.filter(
                action=AccessRequestAudit.Action.REGISTERED
            ).exists()
        )

    def test_registration_rejects_duplicate_username_case_insensitively(self):
        get_user_model().objects.create_user(username="ExistingUser", password=self.password)
        response = self.register("existinguser")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(get_user_model().objects.filter(username__iexact="existinguser").count(), 1)

    def test_pending_user_receives_pending_status_and_no_token(self):
        self.register()
        response = self.client.post(
            "/api/v1/auth/login/",
            {"username": "new-analyst", "password": self.password},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["code"], "account_pending")
        self.assertFalse(Token.objects.filter(user__username="new-analyst").exists())

    def test_superuser_can_approve_staff_and_user_can_login(self):
        self.register()
        access_request = AccessRequest.objects.get(user__username="new-analyst")
        admin = get_user_model().objects.create_superuser(
            username="root-admin",
            password=self.password,
        )
        self.client.force_authenticate(admin)
        response = self.client.post(
            f"/api/v1/admin/access-requests/{access_request.id}/approve/",
            {"role": "staff"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        access_request.refresh_from_db()
        access_request.user.refresh_from_db()
        self.assertEqual(access_request.status, AccessRequest.Status.APPROVED)
        self.assertTrue(access_request.user.is_active)
        self.assertTrue(access_request.user.is_staff)
        self.assertEqual(access_request.reviewed_by, admin)

        self.client.force_authenticate(user=None)
        login = self.client.post(
            "/api/v1/auth/login/",
            {"username": "new-analyst", "password": self.password},
            format="json",
        )
        self.assertEqual(login.status_code, status.HTTP_200_OK)
        self.assertTrue(login.data["is_staff"])
        self.assertFalse(login.data["is_superuser"])

    def test_non_superuser_cannot_review_requests(self):
        self.register()
        access_request = AccessRequest.objects.get(user__username="new-analyst")
        staff = get_user_model().objects.create_user(
            username="staff-reviewer",
            password=self.password,
            is_staff=True,
        )
        self.client.force_authenticate(staff)
        listing = self.client.get("/api/v1/admin/access-requests/")
        approval = self.client.post(
            f"/api/v1/admin/access-requests/{access_request.id}/approve/",
            {"role": "analyst"},
            format="json",
        )
        self.assertEqual(listing.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(approval.status_code, status.HTTP_403_FORBIDDEN)

    def test_revoke_disables_user_and_deletes_token(self):
        user = get_user_model().objects.create_user(
            username="approved-user",
            password=self.password,
            is_active=True,
        )
        access_request = AccessRequest.objects.create(
            user=user,
            status=AccessRequest.Status.APPROVED,
        )
        Token.objects.create(user=user)
        admin = get_user_model().objects.create_superuser(
            username="root-admin",
            password=self.password,
        )
        self.client.force_authenticate(admin)
        response = self.client.post(
            f"/api/v1/admin/access-requests/{access_request.id}/revoke/",
            {},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        user.refresh_from_db()
        access_request.refresh_from_db()
        self.assertFalse(user.is_active)
        self.assertFalse(user.is_staff)
        self.assertEqual(access_request.status, AccessRequest.Status.REVOKED)
        self.assertFalse(Token.objects.filter(user=user).exists())
