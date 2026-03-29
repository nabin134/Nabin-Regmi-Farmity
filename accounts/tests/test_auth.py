from django.test import TestCase, Client
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from django.contrib.auth import get_user_model

User = get_user_model()


def _valid_signup_payload(email, **overrides):
    base = {
        'email': email,
        'password': 'Str0ng!Pass',
        'confirmPassword': 'Str0ng!Pass',
        'role': 'buyer',
        'fullName': 'Test User',
        'phone': '9800000001',
        'location': 'Kathmandu, Nepal',
        'gender': 'male',
    }
    base.update(overrides)
    return base


class AuthTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.email = 'test@example.com'
        self.password = 'Password123!'
        self.user = User.objects.create_user(
            email=self.email,
            password=self.password,
            role='farmer',
            is_active=True,
            email_verified=True,
        )

    def test_login_success(self):
        url = '/api/auth/login/'
        response = self.client.post(
            url, {'email': self.email, 'password': self.password}, format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('user', response.data)
        self.assertIn('redirect_url', response.data)

    def test_login_success_case_insensitive(self):
        url = '/api/auth/login/'
        response = self.client.post(
            url, {'email': 'Test@Example.com', 'password': self.password}, format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_login_failure(self):
        url = '/api/auth/login/'
        response = self.client.post(
            url, {'email': self.email, 'password': 'WrongPassword'}, format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_invalid_email(self):
        url = '/api/auth/login/'
        response = self.client.post(
            url,
            {'email': 'nonexistent@example.com', 'password': 'SomePassword'},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data.get('error'), 'Invalid email or password')

    def test_login_missing_fields(self):
        url = '/api/auth/login/'
        response = self.client.post(url, {'email': self.email}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('error'), 'Validation failed')

    def test_login_empty_body(self):
        url = '/api/auth/login/'
        response = self.client.post(url, {}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)


class SignupApiTests(TestCase):
    """POST /api/auth/signup/ — mirrors frontend + SignupSerializer rules (Gmail/Yahoo, etc.)."""

    def setUp(self):
        self.client = APIClient()

    def test_signup_success_gmail(self):
        url = '/api/auth/signup/'
        email = 'new_vendor_unit@gmail.com'
        data = _valid_signup_payload(
            email, role='vendor', phone='9801112233', gender='female'
        )
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.data)
        self.assertTrue(User.objects.filter(email=email).exists())
        self.assertIn('message', response.data)
        self.assertIn('redirect_url', response.data)

    def test_signup_success_yahoo(self):
        email = 'buyer_unit@yahoo.com'
        data = _valid_signup_payload(email, phone='9801112244')
        response = self.client.post('/api/auth/signup/', data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(email=email).exists())

    def test_signup_rejects_disallowed_email_domain(self):
        data = _valid_signup_payload('user@outlook.com', phone='9801112255')
        response = self.client.post('/api/auth/signup/', data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_signup_rejects_duplicate_email(self):
        email = 'dup@gmail.com'
        User.objects.create_user(
            email=email,
            password='Xyz9!aaaa',
            role='buyer',
            phone='9801112266',
            is_active=True,
            email_verified=True,
        )
        data = _valid_signup_payload(email, phone='9801112277')
        response = self.client.post('/api/auth/signup/', data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_signup_rejects_password_mismatch(self):
        email = 'mismatch@gmail.com'
        data = _valid_signup_payload(email)
        data['confirmPassword'] = 'Other1!Pass'
        response = self.client.post('/api/auth/signup/', data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_signup_requires_gender(self):
        email = 'nogender@gmail.com'
        data = _valid_signup_payload(email, phone='9801112288')
        del data['gender']
        response = self.client.post('/api/auth/signup/', data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class GoogleSignupStartTests(TestCase):
    """
    Unit-test the Farmity wrapper that sets session role and redirects into django-allauth.
    Full Google OAuth (token exchange, account creation) is an integration flow; test that separately or with mocks.
    """

    def setUp(self):
        self.client = Client()

    def test_redirects_to_allauth_google_signup(self):
        response = self.client.get(
            reverse('google_signup_start'), {'role': 'vendor'}
        )
        self.assertEqual(response.status_code, 302)
        loc = response.headers.get('Location', '')
        self.assertIn('/accounts/google/login/', loc)
        self.assertIn('process=signup', loc)

    def test_session_stores_valid_role(self):
        self.client.get(reverse('google_signup_start'), {'role': 'farmer'})
        session = self.client.session
        self.assertEqual(session.get('signup_role'), 'farmer')

    def test_invalid_role_defaults_to_buyer_in_session(self):
        self.client.get(reverse('google_signup_start'), {'role': 'not_a_role'})
        self.assertEqual(self.client.session.get('signup_role'), 'buyer')
