"""
Complete flow test: Signup → Login → Profile
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

def print_info(text):
    print(f"→ {text}")

print_header("Complete API Flow Test: Signup → Login → Profile")

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
        print(f"\nResponse:")
        print(json.dumps(result, indent=2))
        
        # Verify no tokens in response
        if 'tokens' not in result:
            print_success("✓ No tokens in signup response (as expected)")
        else:
            print_error("✗ Tokens found in signup response (should not be there)")
    else:
        error = response.json()
        if "already exists" in str(error):
            print_info("User already exists, will test login...")
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
        tokens = response.json()
        access_token = tokens.get('access')
        refresh_token = tokens.get('refresh')
        
        if access_token:
            print_success("Login Successful!")
            print(f"\nTokens Received:")
            print(f"  Access Token: {access_token[:60]}...")
            print(f"  Refresh Token: {refresh_token[:60]}...")
        else:
            print_error("No access token in login response")
            exit(1)
    else:
        print_error(f"Login failed: {response.json()}")
        exit(1)
except Exception as e:
    print_error(f"Error: {e}")
    exit(1)

# Step 3: PROFILE
print_header("STEP 3: GET PROFILE")
headers = {"Authorization": f"Bearer {access_token}"}

try:
    response = requests.get(f"{BASE_URL}/api/auth/profile/", headers=headers)
    print(f"Status Code: {response.status_code}")
    
    if response.status_code == 200:
        profile = response.json()
        print_success("Profile Retrieved Successfully!")
        print(f"\nProfile Details:")
        print(json.dumps(profile, indent=2))
        
        # Verify profile contains expected fields
        expected_fields = ['id', 'email', 'role', 'is_verified', 'date_joined']
        missing_fields = [field for field in expected_fields if field not in profile]
        
        if not missing_fields:
            print_success("✓ All expected fields present in profile")
        else:
            print_error(f"✗ Missing fields: {missing_fields}")
    else:
        print_error(f"Profile retrieval failed: {response.json()}")
        exit(1)
except Exception as e:
    print_error(f"Error: {e}")
    exit(1)

# Summary
print_header("TEST SUMMARY")
print_success("All steps completed successfully!")
print("\nFlow:")
print("  1. ✓ Signup - Account created (no tokens)")
print("  2. ✓ Login - Tokens received")
print("  3. ✓ Profile - User details retrieved")
print("\n" + "="*70)

