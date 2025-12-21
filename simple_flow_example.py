"""
Simple Example: Signup → Login → Profile
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
print("SIMPLE FLOW: Signup → Login → Profile")
print("="*70)

# Step 1: SIGNUP
print("\n[1] SIGNUP")
print("-" * 70)
signup_data = {
    "email": "newuser@example.com",
    "password": "password123",
    "role": "user"
}

response = requests.post(f"{BASE_URL}/api/auth/signup/", json=signup_data)
print(f"Status: {response.status_code}")

if response.status_code == 201:
    result = response.json()
    print("✓ Account created successfully!")
    print(f"\nUser Created:")
    print(f"  ID: {result['user']['id']}")
    print(f"  Email: {result['user']['email']}")
    print(f"  Role: {result['user']['role']}")
    print(f"  Verified: {result['user']['is_verified']}")
    print("\n✓ No tokens in signup response (as expected)")
else:
    error = response.json()
    if "already exists" in str(error):
        print("⚠ User already exists. Proceeding to login...")
    else:
        print(f"✗ Signup failed: {error}")
        exit(1)

# Step 2: LOGIN
print("\n[2] LOGIN")
print("-" * 70)
login_data = {
    "email": "newuser@example.com",
    "password": "password123"
}

response = requests.post(f"{BASE_URL}/api/auth/login/", json=login_data)
print(f"Status: {response.status_code}")

if response.status_code == 200:
    tokens = response.json()
    access_token = tokens.get('access')
    refresh_token = tokens.get('refresh')
    
    print("✓ Login successful!")
    print(f"\nTokens Received:")
    print(f"  Access Token: {access_token[:60]}...")
    print(f"  Refresh Token: {refresh_token[:60]}...")
else:
    print(f"✗ Login failed: {response.json()}")
    exit(1)

# Step 3: PROFILE
print("\n[3] PROFILE")
print("-" * 70)
headers = {"Authorization": f"Bearer {access_token}"}
response = requests.get(f"{BASE_URL}/api/auth/profile/", headers=headers)

print(f"Status: {response.status_code}")

if response.status_code == 200:
    profile = response.json()
    print("✓ Profile retrieved successfully!")
    print(f"\nProfile Details:")
    print(json.dumps(profile, indent=2))
else:
    print(f"✗ Profile failed: {response.json()}")

print("\n" + "="*70)
print("✓ Complete Flow: Signup → Login → Profile")
print("="*70)

