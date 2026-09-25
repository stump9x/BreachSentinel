from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.core.cache import cache
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.test import APITestCase

from apps.core.models import AccessRequest, PasswordResetRequest


class PasswordResetApiTests(APITestCase):
    old_password = "Strong-Old-Password-9481"
    new_password = "Strong-New-Password-5832"

    def setUp(self):
        cache.clear()
        self.user = get_user_model().objects.create_user(
            username="approved-user",
            password=self.old_password,
            is_active=True,
        )
        AccessRequest.objects.create(
            user=self.user,
            status=AccessRequest.Status.APPROVED,
        )
        self.admin = get_user_model().objects.create_superuser(
            username="root-admin",
            password=self.old_password,
        )

    def request_reset(self, username="approved-user"):
        return self.client.post(
            "/api/v1/auth/password-reset/",
            {
                "username": username,
                "password": self.new_password,
                "password_confirm": self.new_password,
            },
            format="json",
        )

    def test_approved_user_can_submit_hashed_password_for_review(self):
        response = self.request_reset()
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        reset_request = PasswordResetRequest.objects.get(user=self.user)
        self.assertEqual(reset_request.status, PasswordResetRequest.Status.PENDING)
        self.assertNotEqual(reset_request.new_password_hash, self.new_password)
        self.assertTrue(check_password(self.new_password, reset_request.new_password_hash))
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.old_password))
        self.assertFalse(self.user.check_password(self.new_password))

    def test_unknown_and_unapproved_accounts_receive_same_generic_response(self):
        unknown = self.request_reset("missing-user")
        pending_user = get_user_model().objects.create_user(
            username="pending-user",
            password=self.old_password,
            is_active=False,
        )
        AccessRequest.objects.create(user=pending_user)
        pending = self.request_reset("pending-user")
        self.assertEqual(unknown.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(pending.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(unknown.data["detail"], pending.data["detail"])
        self.assertFalse(PasswordResetRequest.objects.filter(user=pending_user).exists())

    def test_password_mismatch_is_rejected(self):
        response = self.client.post(
            "/api/v1/auth/password-reset/",
            {
                "username": self.user.username,
                "password": self.new_password,
                "password_confirm": "Different-Password-1593",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(PasswordResetRequest.objects.filter(user=self.user).exists())

    def test_superuser_approval_applies_password_and_revokes_sessions(self):
        self.request_reset()
        reset_request = PasswordResetRequest.objects.get(user=self.user)
        Token.objects.create(user=self.user)
        self.client.force_authenticate(self.admin)
        response = self.client.post(
            f"/api/v1/admin/password-reset-requests/{reset_request.id}/approve/",
            {},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        reset_request.refresh_from_db()
        self.assertTrue(self.user.check_password(self.new_password))
        self.assertFalse(self.user.check_password(self.old_password))
        self.assertFalse(Token.objects.filter(user=self.user).exists())
        self.assertEqual(reset_request.status, PasswordResetRequest.Status.APPROVED)
        self.assertEqual(reset_request.new_password_hash, "")
        self.assertEqual(reset_request.reviewed_by, self.admin)

    def test_superuser_can_reject_without_changing_password(self):
        self.request_reset()
        reset_request = PasswordResetRequest.objects.get(user=self.user)
        self.client.force_authenticate(self.admin)
        response = self.client.post(
            f"/api/v1/admin/password-reset-requests/{reset_request.id}/reject/",
            {},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        reset_request.refresh_from_db()
        self.assertTrue(self.user.check_password(self.old_password))
        self.assertEqual(reset_request.status, PasswordResetRequest.Status.REJECTED)
        self.assertEqual(reset_request.new_password_hash, "")

    def test_non_superuser_cannot_list_or_review_reset_requests(self):
        self.request_reset()
        reset_request = PasswordResetRequest.objects.get(user=self.user)
        self.client.force_authenticate(self.user)
        listing = self.client.get("/api/v1/admin/password-reset-requests/")
        approval = self.client.post(
            f"/api/v1/admin/password-reset-requests/{reset_request.id}/approve/",
            {},
            format="json",
        )
        self.assertEqual(listing.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(approval.status_code, status.HTTP_403_FORBIDDEN)
