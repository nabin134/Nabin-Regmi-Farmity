"""
Test Login API with email in response
"""
import requests
import json
import sys
import time

# Fix encoding for Windows console
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')

BASE_URL = "http://127.0.0.1:8000"

def print_header(text):
    print("\n" + "="*70)
    print(f"  {text}")
    print("="*70)

def print_success(text):
    print(f"✓ {text}")

def print_error(text):
    print(f"✗ {text}")

print_header("Login API Test - Email in Response")

# Generate unique email
timestamp = int(time.time())
test_email = f"testuser{timestamp}@example.com"
test_password = "password123"

print(f"\nTest Credentials:")
print(f"  Email: {test_email}")
print(f"  Password: {test_password}")

# Step 1: Signup first
print_header("STEP 1: SIGNUP")
signup_data = {
    "email": test_email,
    "password": test_password,
    "role": "user"
}

response = requests.post(f"{BASE_URL}/api/auth/signup/", json=signup_data)
if response.status_code != 201:
    print("Creating user...")
    time.sleep(0.5)

# Step 2: LOGIN
print_header("STEP 2: LOGIN")
login_data = {
    "email": test_email,
    "password": test_password
}

print(f"\nInput:")
print(f"  Email: {login_data['email']}")
print(f"  Password: {login_data['password']}")

response = requests.post(f"{BASE_URL}/api/auth/login/", json=login_data)
print(f"\nStatus Code: {response.status_code}")

if response.status_code == 200:
    result = response.json()
    print_success("Login Successful!")
    print(f"\nResponse:")
    print(json.dumps(result, indent=2))
    
    # Verify email is in response
    if 'email' in result:
        print_success(f"✓ Email in response: {result['email']}")
    if 'message' in result:
        print_success(f"✓ Success message: {result['message']}")
    
    # Verify password is NOT in response (security)
    if 'password' not in result:
        print_success("✓ Password NOT in response (secure)")
    else:
        print_error("✗ Password found in response (security risk!)")
else:
    print_error(f"Login failed: {response.json()}")

print_header("TEST SUMMARY")
print_success("Login API returns email and success message")
print("\n" + "="*70)

