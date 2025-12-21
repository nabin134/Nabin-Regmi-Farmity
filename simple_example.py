"""
Simple example: Signup → Login → Profile
No email verification needed - immediate access!
"""
import requests
import json
import sys

# Fix encoding for Windows console
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')

BASE_URL = "http://127.0.0.1:8000"

print("="*70)
print("SIMPLE SIGNUP & LOGIN EXAMPLE")
print("="*70)

# 1. SIGNUP - Register and get tokens immediately
print("\n[1] SIGNUP")
print("-" * 70)
signup_data = {
    "email": "demo@example.com",
    "password": "demo12345",
    "role": "user"
}

response = requests.post(f"{BASE_URL}/api/auth/signup/", json=signup_data)
print(f"Status: {response.status_code}")

if response.status_code == 201:
    result = response.json()
    print("✓ Account created successfully!")
    print(f"\nUser Info:")
    print(f"  Email: {result['user']['email']}")
    print(f"  Role: {result['user']['role']}")
    print(f"  Verified: {result['user']['is_verified']}")
    
    # Get tokens from signup response
    access_token = result['tokens']['access']
    print(f"\n✓ Tokens received immediately!")
    print(f"  Access Token: {access_token[:60]}...")
    
    # 2. Get Profile using the token
    print("\n[2] GET PROFILE")
    print("-" * 70)
    headers = {"Authorization": f"Bearer {access_token}"}
    profile_response = requests.get(f"{BASE_URL}/api/auth/profile/", headers=headers)
    
    if profile_response.status_code == 200:
        profile = profile_response.json()
        print("✓ Profile retrieved!")
        print(f"\nProfile Data:")
        print(json.dumps(profile, indent=2))
    else:
        print(f"✗ Profile error: {profile_response.json()}")
        
else:
    error = response.json()
    if "already exists" in str(error):
        print("⚠ User already exists. Testing login...")
        
        # 3. LOGIN - If user exists, login instead
        print("\n[3] LOGIN")
        print("-" * 70)
        login_data = {
            "email": "demo@example.com",
            "password": "demo12345"
        }
        
        login_response = requests.post(f"{BASE_URL}/api/auth/login/", json=login_data)
        
        if login_response.status_code == 200:
            tokens = login_response.json()
            access_token = tokens['access']
            print("✓ Login successful!")
            print(f"  Access Token: {access_token[:60]}...")
            
            # Get Profile
            print("\n[4] GET PROFILE")
            print("-" * 70)
            headers = {"Authorization": f"Bearer {access_token}"}
            profile_response = requests.get(f"{BASE_URL}/api/auth/profile/", headers=headers)
            
            if profile_response.status_code == 200:
                profile = profile_response.json()
                print("✓ Profile retrieved!")
                print(f"\nProfile Data:")
                print(json.dumps(profile, indent=2))
        else:
            print(f"✗ Login failed: {login_response.json()}")
    else:
        print(f"✗ Signup failed: {error}")

print("\n" + "="*70)
print("✓ Complete! No email verification needed - immediate access!")
print("="*70)

