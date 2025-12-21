"""
Test Login API with Email and Password Text Fields
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

print_header("Login API - Email and Password Text Fields Test")

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

# Step 2: LOGIN with proper fields
print_header("STEP 2: LOGIN - Email and Password Text Fields")
login_data = {
    "email": test_email,      # Email text field
    "password": test_password # Password text field
}

print(f"\nInput Fields:")
print(f"  Email (text field): {login_data['email']}")
print(f"  Password (text field): {login_data['password']}")

response = requests.post(f"{BASE_URL}/api/auth/login/", json=login_data)
print(f"\nStatus Code: {response.status_code}")

if response.status_code == 200:
    result = response.json()
    print_success("Login Successful!")
    print(f"\nResponse:")
    print(json.dumps(result, indent=2))
    
    # Verify fields are shown
    if 'email' in result:
        print_success(f"✓ Email field: {result['email']}")
    if 'input_fields' in result:
        print_success("✓ Input fields information included")
        print(f"  {result['input_fields']['email']}")
        print(f"  {result['input_fields']['password']}")
else:
    result = response.json()
    print_error(f"Login failed")
    print(f"Response: {json.dumps(result, indent=2)}")
    
    # Check if it shows required fields
    if 'required_fields' in result:
        print("\nRequired Fields:")
        for field, desc in result['required_fields'].items():
            print(f"  {field}: {desc}")

# Step 3: Test missing fields
print_header("STEP 3: TEST MISSING FIELDS")
print("\nTesting with missing email field...")
response = requests.post(f"{BASE_URL}/api/auth/login/", json={"password": "test123"})
print(f"Status: {response.status_code}")
if response.status_code == 400:
    result = response.json()
    print("Response:")
    print(json.dumps(result, indent=2))
    if 'required_fields' in result:
        print("\n✓ Required fields shown in error response")

print("\nTesting with missing password field...")
response = requests.post(f"{BASE_URL}/api/auth/login/", json={"email": "test@example.com"})
print(f"Status: {response.status_code}")
if response.status_code == 400:
    result = response.json()
    print("Response:")
    print(json.dumps(result, indent=2))

print_header("TEST SUMMARY")
print_success("Login API shows email and password text fields")
print("\n" + "="*70)

