"""
Simple Example: Signup → Login (returns profile) → Profile
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
    "email": "demo@example.com",
    "password": "password123",
    "role": "user"
}

response = requests.post(f"{BASE_URL}/api/auth/signup/", json=signup_data)
print(f"Status: {response.status_code}")

if response.status_code == 201:
    result = response.json()
    print("✓ Account created successfully!")
    print(f"  User ID: {result['user']['id']}")
    print(f"  Email: {result['user']['email']}")
    print(f"  Role: {result['user']['role']}")
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
    "email": "demo@example.com",
    "password": "password123"
}

response = requests.post(f"{BASE_URL}/api/auth/login/", json=login_data)
print(f"Status: {response.status_code}")

if response.status_code == 200:
    result = response.json()
    print("✓ Login successful!")
    print(f"\nMessage: {result['message']}")
    print(f"\nUser Profile Details:")
    user = result['user']
    print(f"  ID: {user['id']}")
    print(f"  Email: {user['email']}")
    print(f"  Role: {user['role']}")
    print(f"  Verified: {user['is_verified']}")
    print(f"  Date Joined: {user['date_joined']}")
    
    # Verify no tokens
    if 'tokens' not in result and 'access' not in result:
        print("\n✓ No tokens in response (as expected)")
else:
    print(f"✗ Login failed: {response.json()}")
    exit(1)

# Step 3: PROFILE
print("\n[3] PROFILE")
print("-" * 70)
response = requests.get(f"{BASE_URL}/api/auth/profile/", params={"email": "demo@example.com"})
print(f"Status: {response.status_code}")

if response.status_code == 200:
    profile = response.json()
    print("✓ Profile retrieved successfully!")
    print(f"\nProfile:")
    print(json.dumps(profile, indent=2))
else:
    print(f"✗ Profile failed: {response.json()}")

print("\n" + "="*70)
print("✓ Complete Flow: Signup → Login (with profile) → Profile")
print("="*70)

