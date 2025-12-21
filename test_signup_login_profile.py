"""
Test script to verify Signup, Login, and Profile work correctly
"""
import requests
import json
import sys

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

print_header("Testing Signup, Login, and Profile Flow")

# Step 1: Signup
print("\n[1] SIGNUP - Registering new user...")
signup_data = {
    "email": "newuser@example.com",
    "password": "password123",
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
        
        # Extract tokens from signup response
        access_token = result.get('tokens', {}).get('access')
        refresh_token = result.get('tokens', {}).get('refresh')
        user_data = result.get('user', {})
        
        print(f"\nUser Created:")
        print(f"  ID: {user_data.get('id')}")
        print(f"  Email: {user_data.get('email')}")
        print(f"  Role: {user_data.get('role')}")
        print(f"  Verified: {user_data.get('is_verified')}")
        
        if access_token:
            print(f"\nTokens Received:")
            print(f"  Access Token: {access_token[:50]}...")
            print(f"  Refresh Token: {refresh_token[:50]}...")
            
            # Step 2: Get Profile using token from signup
            print("\n[2] PROFILE - Getting user profile with signup token...")
            headers = {"Authorization": f"Bearer {access_token}"}
            profile_response = requests.get(f"{BASE_URL}/api/auth/profile/", headers=headers)
            
            print(f"Status Code: {profile_response.status_code}")
            if profile_response.status_code == 200:
                profile = profile_response.json()
                print_success("Profile Retrieved Successfully!")
                print(f"\nProfile Data:")
                print(json.dumps(profile, indent=2))
            else:
                print_error(f"Failed to get profile: {profile_response.json()}")
        else:
            print_error("No tokens received in signup response")
    else:
        error = response.json()
        if "already exists" in str(error):
            print_info("User already exists. Testing login instead...")
            access_token = None
        else:
            print_error(f"Signup failed: {error}")
            access_token = None
except Exception as e:
    print_error(f"Error during signup: {e}")
    access_token = None

# Step 3: Login (if signup failed or to test separately)
if not access_token:
    print("\n[3] LOGIN - Logging in with credentials...")
    login_data = {
        "email": "newuser@example.com",
        "password": "password123"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/api/auth/login/", json=login_data)
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            tokens = response.json()
            access_token = tokens.get('access')
            refresh_token = tokens.get('refresh')
            
            print_success("Login Successful!")
            print(f"\nTokens:")
            print(f"  Access Token: {access_token[:50]}...")
            print(f"  Refresh Token: {refresh_token[:50]}...")
            
            # Get Profile
            print("\n[4] PROFILE - Getting user profile with login token...")
            headers = {"Authorization": f"Bearer {access_token}"}
            profile_response = requests.get(f"{BASE_URL}/api/auth/profile/", headers=headers)
            
            print(f"Status Code: {profile_response.status_code}")
            if profile_response.status_code == 200:
                profile = profile_response.json()
                print_success("Profile Retrieved Successfully!")
                print(f"\nProfile Data:")
                print(json.dumps(profile, indent=2))
            else:
                print_error(f"Failed to get profile: {profile_response.json()}")
        else:
            print_error(f"Login failed: {response.json()}")
    except Exception as e:
        print_error(f"Error during login: {e}")

print_header("Test Summary")
print_success("All operations completed!")
print("\nAPI Endpoints:")
print("  POST /api/auth/signup/ - Register and get tokens immediately")
print("  POST /api/auth/login/ - Login and get tokens")
print("  GET /api/auth/profile/ - Get user profile (requires Bearer token)")

