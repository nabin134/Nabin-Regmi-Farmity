"""
Critical auth edge cases: email OTP verification, session expiry, Google ID token checks.
"""
from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from accounts.tests.google_token import verify_google_id_token
from accounts.models import OTP

User = get_user_model()


class EmailVerificationOtpApiTests(TestCase):
    """POST /api/auth/verify-email/ — valid code, wrong code, expired OTP, unknown user."""

    def setUp(self):
        self.client = APIClient()
        self.email = "verify_otp_buyer@gmail.com"
        self.user = User.objects.create_user(
            email=self.email,
            password="Str0ng!Pass1",
            role="buyer",
            phone="9810000001",
            is_active=False,
            email_verified=False,
        )

    def test_verify_email_valid_otp_activates_and_returns_redirect(self):
        otp = OTP.generate_otp(
            self.user, expiry_minutes=30, purpose=OTP.PURPOSE_EMAIL_VERIFY
        )
        url = reverse("api-verify-email")
        response = self.client.post(
            url,
            {"email": self.email, "otp": otp.otp_code},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.assertEqual(response.data.get("message"), "Email verified successfully.")
        self.assertIn("redirect_url", response.data)
        self.assertEqual(response.data["redirect_url"], reverse("user_dashboard"))
        self.user.refresh_from_db()
        self.assertTrue(self.user.email_verified)
        self.assertTrue(self.user.is_active)

    def test_verify_email_farmer_redirects_to_kyc(self):
        farmer = User.objects.create_user(
            email="verify_otp_farmer@gmail.com",
            password="Str0ng!Pass1",
            role="farmer",
            phone="9810000003",
            is_active=False,
            email_verified=False,
        )
        otp = OTP.generate_otp(
            farmer, expiry_minutes=30, purpose=OTP.PURPOSE_EMAIL_VERIFY
        )
        response = self.client.post(
            reverse("api-verify-email"),
            {"email": farmer.email, "otp": otp.otp_code},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("redirect_url"), reverse("kyc"))

    def test_verify_email_invalid_otp_returns_400_and_safe_message(self):
        OTP.generate_otp(
            self.user, expiry_minutes=30, purpose=OTP.PURPOSE_EMAIL_VERIFY
        )
        url = reverse("api-verify-email")
        response = self.client.post(
            url,
            {"email": self.email, "otp": "000000"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data.get("error"),
            "Invalid or expired verification code. Please request a new one.",
        )
        self.user.refresh_from_db()
        self.assertFalse(self.user.email_verified)

    def test_verify_email_expired_otp_returns_distinct_error(self):
        fresh = OTP.generate_otp(
            self.user, expiry_minutes=30, purpose=OTP.PURPOSE_EMAIL_VERIFY
        )
        OTP.objects.filter(pk=fresh.pk).update(
            expires_at=timezone.now() - timedelta(minutes=1)
        )
        url = reverse("api-verify-email")
        response = self.client.post(
            url,
            {"email": self.email, "otp": fresh.otp_code},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data.get("error"),
            "Verification code has expired. Please request a new one.",
        )

    def test_verify_email_unknown_user_returns_404(self):
        url = reverse("api-verify-email")
        response = self.client.post(
            url,
            {"email": "nobody@gmail.com", "otp": "123456"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data.get("error"), "User not found")

    def test_verify_email_malformed_otp_returns_validation_error(self):
        url = reverse("api-verify-email")
        response = self.client.post(
            url,
            {"email": self.email, "otp": "12ab45"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("error"), "Validation failed")


class SessionExpiryReauthTests(TestCase):
    """Expired DB sessions must not stay authenticated on protected routes."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            email="session_farmer@gmail.com",
            password="Str0ng!Pass1",
            role="farmer",
            phone="9810000002",
            is_active=True,
            email_verified=True,
        )

    def _expire_current_session_in_db(self):
        key = self.client.session.session_key
        self.assertIsNotNone(key, "session_key missing after login")
        Session.objects.filter(session_key=key).update(
            expire_date=timezone.now() - timedelta(hours=1)
        )

    def test_expired_session_redirects_to_login_with_next(self):
        self.client.force_login(self.user)
        self._expire_current_session_in_db()

        kyc_url = reverse("kyc")
        response = self.client.get(kyc_url)
        self.assertEqual(response.status_code, 302)
        loc = response.headers.get("Location", "")
        self.assertTrue(
            "login" in loc.lower(),
            msg=f"Expected login redirect, got Location={loc!r}",
        )
        self.assertIn("next=", loc, msg="Login redirect should preserve ?next= for UX")

    def test_fresh_session_reaches_protected_page(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("kyc"))
        self.assertEqual(response.status_code, 200)


@patch("accounts.tests.google_token.requests.get")
class GoogleIdTokenValidationTests(TestCase):
    """Mock HTTP: valid payload, invalid (400), expired exp claim, network failure."""

    def test_valid_token_returns_payload(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "aud": "client-id",
            "sub": "google-subject",
            "email": "user@gmail.com",
            "exp": int(timezone.now().timestamp()) + 7200,
        }
        mock_get.return_value = mock_resp

        payload, err = verify_google_id_token("good.token.value")
        self.assertIsNone(err)
        self.assertIsNotNone(payload)
        self.assertEqual(payload.get("email"), "user@gmail.com")
        mock_get.assert_called_once()

    def test_http_400_maps_to_invalid_token(self, mock_get):
        mock_get.return_value = MagicMock(status_code=400)
        payload, err = verify_google_id_token("bad.token")
        self.assertIsNone(payload)
        self.assertEqual(err, "invalid_token")

    def test_expired_exp_claim(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "email": "user@gmail.com",
            "exp": int(timezone.now().timestamp()) - 3600,
        }
        mock_get.return_value = mock_resp

        payload, err = verify_google_id_token("expired.token")
        self.assertIsNone(payload)
        self.assertEqual(err, "expired_token")

    def test_network_error(self, mock_get):
        import requests

        mock_get.side_effect = requests.ConnectionError("unreachable")
        payload, err = verify_google_id_token("any")
        self.assertIsNone(payload)
        self.assertEqual(err, "network_error")

    def test_missing_token(self, mock_get):
        payload, err = verify_google_id_token("")
        self.assertIsNone(payload)
        self.assertEqual(err, "missing_token")
        mock_get.assert_not_called()

    def test_error_field_in_json(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "error": "invalid_grant",
            "error_description": "Token expired",
        }
        mock_get.return_value = mock_resp
        payload, err = verify_google_id_token("rejected")
        self.assertIsNone(payload)
        self.assertEqual(err, "expired_token")
