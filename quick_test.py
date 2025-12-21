"""Quick API test without user input"""
import requests
import json
import sys

# Fix encoding for Windows console
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')

BASE_URL = "http://127.0.0.1:8000"

print("\n" + "="*60)
print("TESTING API ENDPOINTS")
print("="*60)

# Test 1: Register User
print("\n1. Testing User Registration...")
try:
    response = requests.post(
        f"{BASE_URL}/api/auth/signup/",
        json={
            "email": "testuser@example.com",
            "password": "securepass123",
            "role": "user"
        }
    )
    print(f"   Status: {response.status_code}")
    print(f"   Response: {json.dumps(response.json(), indent=2)}")
    if response.status_code == 201:
        print("   ✅ Registration successful!")
    else:
        print("   ⚠️  Registration had issues (user might already exist)")
except Exception as e:
    print(f"   ❌ Error: {e}")

# Test 2: Login
print("\n2. Testing User Login...")
try:
    response = requests.post(
        f"{BASE_URL}/api/auth/login/",
        json={
            "email": "testuser@example.com",
            "password": "securepass123"
        }
    )
    print(f"   Status: {response.status_code}")
    if response.status_code == 200:
        tokens = response.json()
        access_token = tokens.get('access')
        refresh_token = tokens.get('refresh')
        print(f"   ✅ Login successful!")
        print(f"   Access Token: {access_token[:50]}...")
        
        # Test 3: Get Profile
        print("\n3. Testing Get User Profile...")
        headers = {"Authorization": f"Bearer {access_token}"}
        profile_response = requests.get(f"{BASE_URL}/api/auth/profile/", headers=headers)
        print(f"   Status: {profile_response.status_code}")
        print(f"   Response: {json.dumps(profile_response.json(), indent=2)}")
        if profile_response.status_code == 200:
            print("   ✅ Profile retrieval successful!")
        
        # Test 4: Refresh Token
        print("\n4. Testing Refresh Token...")
        refresh_response = requests.post(
            f"{BASE_URL}/api/auth/refresh/",
            json={"refresh": refresh_token}
        )
        print(f"   Status: {refresh_response.status_code}")
        if refresh_response.status_code == 200:
            print("   ✅ Token refresh successful!")
    else:
        print(f"   Response: {json.dumps(response.json(), indent=2)}")
        print("   ❌ Login failed!")
except Exception as e:
    print(f"   ❌ Error: {e}")

print("\n" + "="*60)
print("TESTING COMPLETE")
print("="*60)
print("\nServer is running at: http://127.0.0.1:8000")
print("API Documentation: See API_USAGE.md")

