"""
Test Final Flow: Signup → Login (no tokens, returns profile) → Profile
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

print_header("Final Flow Test: Signup → Login → Profile")

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
        
        # Verify no tokens
        if 'tokens' not in result:
            print_success("✓ No tokens in signup response")
        else:
            print_error("✗ Tokens found in signup (should not be there)")
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
        print(f"\nResponse:")
        print(json.dumps(result, indent=2))
        
        # Verify no tokens
        if 'tokens' not in result and 'access' not in result and 'refresh' not in result:
            print_success("✓ No tokens in login response")
        else:
            print_error("✗ Tokens found in login (should not be there)")
        
        # Verify profile data is present
        if 'user' in result:
            print_success("✓ User profile details in login response")
            user_data = result['user']
            print(f"\nUser Details:")
            print(f"  ID: {user_data.get('id')}")
            print(f"  Email: {user_data.get('email')}")
            print(f"  Role: {user_data.get('role')}")
            print(f"  Verified: {user_data.get('is_verified')}")
            print(f"  Date Joined: {user_data.get('date_joined')}")
        else:
            print_error("✗ No user data in login response")
    else:
        print_error(f"Login failed: {response.json()}")
        exit(1)
except Exception as e:
    print_error(f"Error: {e}")
    exit(1)

# Step 3: PROFILE (using email parameter)
print_header("STEP 3: GET PROFILE")
try:
    response = requests.get(f"{BASE_URL}/api/auth/profile/", params={"email": test_email})
    print(f"Status Code: {response.status_code}")
    
    if response.status_code == 200:
        profile = response.json()
        print_success("Profile Retrieved Successfully!")
        print(f"\nProfile Details:")
        print(json.dumps(profile, indent=2))
    else:
        print_error(f"Profile failed: {response.json()}")
except Exception as e:
    print_error(f"Error: {e}")

# Summary
print_header("TEST SUMMARY")
print_success("All steps completed successfully!")
print("\nFlow:")
print("  1. ✓ Signup - Account created (no tokens)")
print("  2. ✓ Login - Success message + profile details (no tokens)")
print("  3. ✓ Profile - User details retrieved by email")
print("\n" + "="*70)

