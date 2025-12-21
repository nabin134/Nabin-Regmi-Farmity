"""
Simple script to test User Registration and Login API
Run this after starting the Django server: python manage.py runserver
"""

import requests
import json

BASE_URL = "http://127.0.0.1:8000"

def print_response(title, response):
    """Helper function to print formatted response"""
    print(f"\n{'='*50}")
    print(f"{title}")
    print(f"{'='*50}")
    print(f"Status Code: {response.status_code}")
    try:
        print(f"Response: {json.dumps(response.json(), indent=2)}")
    except:
        print(f"Response: {response.text}")
    print(f"{'='*50}\n")

def test_register():
    """Test user registration"""
    print("🔵 Testing User Registration...")
    
    url = f"{BASE_URL}/api/auth/signup/"
    data = {
        "email": "testuser@example.com",
        "password": "securepass123",
        "role": "user"
    }
    
    response = requests.post(url, json=data)
    print_response("REGISTRATION RESPONSE", response)
    return response.status_code == 201

def test_login():
    """Test user login"""
    print("🟢 Testing User Login...")
    
    url = f"{BASE_URL}/api/auth/login/"
    data = {
        "email": "testuser@example.com",
        "password": "securepass123"
    }
    
    response = requests.post(url, json=data)
    print_response("LOGIN RESPONSE", response)
    
    if response.status_code == 200:
        tokens = response.json()
        return tokens.get('access'), tokens.get('refresh')
    return None, None

def test_profile(access_token):
    """Test getting user profile"""
    print("🟡 Testing Get User Profile...")
    
    url = f"{BASE_URL}/api/auth/profile/"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    
    response = requests.get(url, headers=headers)
    print_response("PROFILE RESPONSE", response)
    return response.status_code == 200

def test_refresh_token(refresh_token):
    """Test refreshing access token"""
    print("🟣 Testing Refresh Token...")
    
    url = f"{BASE_URL}/api/auth/refresh/"
    data = {
        "refresh": refresh_token
    }
    
    response = requests.post(url, json=data)
    print_response("REFRESH TOKEN RESPONSE", response)
    return response.status_code == 200

def main():
    """Run all tests"""
    print("\n" + "="*50)
    print("API TESTING SCRIPT")
    print("="*50)
    print("\nMake sure Django server is running on http://127.0.0.1:8000")
    print("Press Enter to continue or Ctrl+C to cancel...")
    try:
        input()
    except KeyboardInterrupt:
        print("\nCancelled.")
        return
    
    # Test 1: Register
    if test_register():
        print("✅ Registration successful!")
    else:
        print("❌ Registration failed!")
        return
    
    # Test 2: Login
    access_token, refresh_token = test_login()
    if access_token:
        print("✅ Login successful!")
        print(f"Access Token: {access_token[:50]}...")
    else:
        print("❌ Login failed!")
        return
    
    # Test 3: Get Profile
    if test_profile(access_token):
        print("✅ Profile retrieval successful!")
    else:
        print("❌ Profile retrieval failed!")
    
    # Test 4: Refresh Token
    if refresh_token and test_refresh_token(refresh_token):
        print("✅ Token refresh successful!")
    else:
        print("❌ Token refresh failed!")
    
    print("\n" + "="*50)
    print("TESTING COMPLETE")
    print("="*50)

if __name__ == "__main__":
    main()

