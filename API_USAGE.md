# API Usage Guide - User Registration and Login

## Prerequisites

1. Make sure Django server is running:
```bash
python manage.py runserver
```

2. Run migrations (if not done already):
```bash
python manage.py makemigrations
python manage.py migrate
```

## API Endpoints

### Base URL
```
http://127.0.0.1:8000
```

---

## 1. Register a New User

**Endpoint:** `POST /api/auth/signup/`

**Request Body:**
```json
{
    "email": "user@example.com",
    "password": "password123",
    "role": "user"
}
```

**Note:** 
- `role` is optional (defaults to "user")
- Valid roles: "admin", "Farmer", "user"
- Password must be at least 8 characters

**Example using cURL:**
```bash
curl -X POST http://127.0.0.1:8000/api/auth/signup/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123",
    "role": "user"
  }'
```

**Example using Python requests:**
```python
import requests

url = "http://127.0.0.1:8000/api/auth/signup/"
data = {
    "email": "user@example.com",
    "password": "password123",
    "role": "user"
}

response = requests.post(url, json=data)
print(response.json())
```

**Success Response (201 Created):**
```json
{
    "message": "Account created. Check email to verify."
}
```

**Error Response (400 Bad Request):**
```json
{
    "email": ["This field is required."],
    "password": ["This field is required."]
}
```

---

## 2. Login (Get JWT Tokens)

**Endpoint:** `POST /api/auth/login/`

**Request Body:**
```json
{
    "email": "user@example.com",
    "password": "password123"
}
```

**Example using cURL:**
```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'
```

**Example using Python requests:**
```python
import requests

url = "http://127.0.0.1:8000/api/auth/login/"
data = {
    "email": "user@example.com",
    "password": "password123"
}

response = requests.post(url, json=data)
tokens = response.json()
print(tokens)

# Save tokens for later use
access_token = tokens['access']
refresh_token = tokens['refresh']
```

**Success Response (200 OK):**
```json
{
    "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

**Error Response (401 Unauthorized):**
```json
{
    "detail": "No active account found with the given credentials"
}
```

---

## 3. Access Protected Endpoints

After login, use the `access` token in the Authorization header.

**Example: Get User Profile**

**Endpoint:** `GET /api/auth/profile/`

**Example using cURL:**
```bash
curl -X GET http://127.0.0.1:8000/api/auth/profile/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE"
```

**Example using Python requests:**
```python
import requests

url = "http://127.0.0.1:8000/api/auth/profile/"
headers = {
    "Authorization": "Bearer YOUR_ACCESS_TOKEN_HERE"
}

response = requests.get(url, headers=headers)
print(response.json())
```

**Success Response (200 OK):**
```json
{
    "id": 1,
    "email": "user@example.com",
    "role": "user",
    "is_verified": false,
    "date_joined": "2024-01-01T12:00:00Z"
}
```

---

## 4. Refresh Access Token

**Endpoint:** `POST /api/auth/refresh/`

**Request Body:**
```json
{
    "refresh": "YOUR_REFRESH_TOKEN_HERE"
}
```

**Example using cURL:**
```bash
curl -X POST http://127.0.0.1:8000/api/auth/refresh/ \
  -H "Content-Type: application/json" \
  -d '{
    "refresh": "YOUR_REFRESH_TOKEN_HERE"
  }'
```

**Success Response (200 OK):**
```json
{
    "access": "NEW_ACCESS_TOKEN_HERE"
}
```

---

## Complete Example: Register → Login → Get Profile

```python
import requests

BASE_URL = "http://127.0.0.1:8000"

# Step 1: Register
print("1. Registering user...")
register_data = {
    "email": "testuser@example.com",
    "password": "securepass123",
    "role": "user"
}
register_response = requests.post(f"{BASE_URL}/api/auth/signup/", json=register_data)
print(f"Registration: {register_response.status_code}")
print(register_response.json())

# Step 2: Login
print("\n2. Logging in...")
login_data = {
    "email": "testuser@example.com",
    "password": "securepass123"
}
login_response = requests.post(f"{BASE_URL}/api/auth/login/", json=login_data)
print(f"Login: {login_response.status_code}")
tokens = login_response.json()
print(f"Tokens received: {bool(tokens.get('access'))}")

# Step 3: Get Profile (using access token)
if tokens.get('access'):
    print("\n3. Getting user profile...")
    headers = {
        "Authorization": f"Bearer {tokens['access']}"
    }
    profile_response = requests.get(f"{BASE_URL}/api/auth/profile/", headers=headers)
    print(f"Profile: {profile_response.status_code}")
    print(profile_response.json())
```

---

## Postman Collection

### Register User
- **Method:** POST
- **URL:** `http://127.0.0.1:8000/api/auth/signup/`
- **Headers:** `Content-Type: application/json`
- **Body (raw JSON):**
```json
{
    "email": "user@example.com",
    "password": "password123",
    "role": "user"
}
```

### Login
- **Method:** POST
- **URL:** `http://127.0.0.1:8000/api/auth/login/`
- **Headers:** `Content-Type: application/json`
- **Body (raw JSON):**
```json
{
    "email": "user@example.com",
    "password": "password123"
}
```

### Get Profile
- **Method:** GET
- **URL:** `http://127.0.0.1:8000/api/auth/profile/`
- **Headers:** 
  - `Content-Type: application/json`
  - `Authorization: Bearer YOUR_ACCESS_TOKEN_HERE`

---

## Troubleshooting

### Common Issues:

1. **"No active account found"** - Check email and password are correct
2. **"Authentication credentials were not provided"** - Make sure to include `Authorization: Bearer TOKEN` header
3. **"Invalid token"** - Token may have expired, use refresh endpoint to get a new one
4. **Email validation errors** - Ensure email format is valid (e.g., user@example.com)
5. **Password too short** - Password must be at least 8 characters

### Testing with Django Shell:

```python
python manage.py shell

from accounts.models import User

# Create a user manually for testing
user = User.objects.create_user(
    email="test@example.com",
    password="testpass123"
)
print(f"User created: {user.email}")
```

---

## Notes

- Access tokens expire after 60 minutes (configurable in settings.py)
- Refresh tokens expire after 1 day (configurable in settings.py)
- Email verification is sent to console (check Django server logs) since we're using console email backend
- For production, configure proper email backend in settings.py

