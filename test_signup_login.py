"""
Simple Test: Signup and Login APIs only
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

print_header("Simple Signup & Login Test")

# Generate unique email
timestamp = int(time.time())
test_email = f"testuser{timestamp}@example.com"
test_password = "password123"

print(f"\nTest Credentials:")
print(f"  Email: {test_email}")
print(f"  Password: {test_password}")

# Step 1: SIGNUP
print_header("STEP 1: SIGNUP")
signup_data = {
    "email": test_email,
    "password": test_password,
    "role": "user"
}

try:
    response = requests.post(f"{BASE_URL}/api/auth/signup/", json=signup_data)
    print(f"Status Code: {response.status_code}")
    
    if response.status_code == 201:
        result = response.json()
        print_success("Signup Successful!")
        print(f"Response: {json.dumps(result, indent=2)}")
        
        if result.get('message') == "Account created successfully":
            print_success("✓ Success message received")
    else:
        error = response.json()
        if "already exists" in str(error):
            print("⚠ User already exists, will test login...")
        else:
            print_error(f"Signup failed: {error}")
            exit(1)
except Exception as e:
    print_error(f"Error: {e}")
    exit(1)

# Wait a moment
time.sleep(0.5)

# Step 2: LOGIN
print_header("STEP 2: LOGIN")
login_data = {
    "email": test_email,
    "password": test_password
}

try:
    response = requests.post(f"{BASE_URL}/api/auth/login/", json=login_data)
    print(f"Status Code: {response.status_code}")
    
    if response.status_code == 200:
        result = response.json()
        print_success("Login Successful!")
        print(f"Response: {json.dumps(result, indent=2)}")
        
        if result.get('message') == "Login successful":
            print_success("✓ Success message received")
        
        # Verify no extra data
        if len(result) == 1 and 'message' in result:
            print_success("✓ Only success message (no extra data)")
    else:
        print_error(f"Login failed: {response.json()}")
        exit(1)
except Exception as e:
    print_error(f"Error: {e}")
    exit(1)

# Summary
print_header("TEST SUMMARY")
print_success("Both APIs working correctly!")
print("\nAPIs:")
print("  1. ✓ POST /api/auth/signup/ - Returns success message")
print("  2. ✓ POST /api/auth/login/ - Returns success message")
print("\n" + "="*70)

