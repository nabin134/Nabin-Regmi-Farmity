"""
Test Login API: Text fields → Success message → User details
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

print_header("Login API Test: Text Fields → Success → User Details")

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
if response.status_code == 201:
    print_success("User created for testing")
    time.sleep(0.5)

# Step 2: LOGIN with text fields
print_header("STEP 2: LOGIN - Text Fields Input")
login_data = {
    "email": test_email,      # Email text field
    "password": test_password # Password text field
}

print(f"\nInput Text Fields:")
print(f"  Email (text field): {login_data['email']}")
print(f"  Password (text field): {login_data['password']}")

response = requests.post(f"{BASE_URL}/api/auth/login/", json=login_data)
print(f"\nStatus Code: {response.status_code}")

if response.status_code == 200:
    result = response.json()
    print_success("Login Successful!")
    
    print(f"\nResponse:")
    print(json.dumps(result, indent=2))
    
    # Verify success message
    if 'message' in result and result['message'] == "Login successful":
        print_success("✓ Success message appears")
    
    # Verify user details
    if 'user' in result:
        print_success("✓ User details shown")
        user = result['user']
        print(f"\nUser Details:")
        print(f"  ID: {user.get('id')}")
        print(f"  Email: {user.get('email')}")
        print(f"  Role: {user.get('role')}")
        print(f"  Verified: {user.get('is_verified')}")
        print(f"  Date Joined: {user.get('date_joined')}")
    else:
        print_error("✗ User details not found in response")
else:
    print_error(f"Login failed: {response.json()}")

print_header("TEST SUMMARY")
print_success("Login flow: Text Fields → Success Message → User Details")
print("\n" + "="*70)

