from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework import status
from django.contrib.auth import get_user_model

User = get_user_model()

class AuthTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.email = "test@example.com"
        self.password = "Password123!"
        # Ensure role is set for redirect logic
        self.user = User.objects.create_user(email=self.email, password=self.password, role='farmer')

    def test_login_success(self):
        """
        Ensure we can login with valid credentials.
        """
        url = '/api/auth/login/'
        data = {
            'email': self.email,
            'password': self.password
        }
        response = self.client.post(url, data, format='json')
        print(f"\nLogin Response (Success Case): {response.data}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue('user' in response.data)
        self.assertTrue('redirect_url' in response.data)

    def test_login_success_case_insensitive(self):
        """
        Ensure we can login with mixed case email.
        """
        url = '/api/auth/login/'
        data = {
            'email': "Test@Example.com",
            'password': self.password
        }
        response = self.client.post(url, data, format='json')
        print(f"\nLogin Response (Case Insensitive): {response.data}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_login_failure(self):
        """
        Ensure login fails with invalid credentials.
        """
        url = '/api/auth/login/'
        data = {
            'email': self.email,
            'password': "WrongPassword"
        }
        response = self.client.post(url, data, format='json')
        print(f"\nLogin Response (Failure Case): {response.data}")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_invalid_email(self):
        url = '/api/auth/login/'
        data = {
            'email': "nonexistent@example.com",
            'password': "SomePassword"
        }
        response = self.client.post(url, data, format='json')
        print(f"\nResponse (Invalid Email): {response.data}")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], "Invalid email or password")

    def test_login_missing_fields(self):
        url = '/api/auth/login/'
        data = {
            'email': self.email
            # missing password
        }
        response = self.client.post(url, data, format='json')
        print(f"\nResponse (Missing Password): {response.data}")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['error'], "Validation failed")

    def test_login_empty_body(self):
        url = '/api/auth/login/'
        data = {}
        response = self.client.post(url, data, format='json')
        print(f"\nResponse (Empty Body): {response.data}")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
