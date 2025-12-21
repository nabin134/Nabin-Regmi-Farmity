"""
Simple example showing how to register and login successfully
"""
import requests
import json

BASE_URL = "http://127.0.0.1:8000"

print("="*60)
print("SIMPLE REGISTRATION & LOGIN EXAMPLE")
print("="*60)

# Step 1: Register a new user
print("\n[1] Registering new user...")
register_data = {
    "email": "demo@example.com",
    "password": "demo12345",
    "role": "user"
}

response = requests.post(f"{BASE_URL}/api/auth/signup/", json=register_data)
print(f"Status: {response.status_code}")
print(f"Response: {response.json()}")

if response.status_code == 201:
    print("✓ Registration successful!")
    
    # Step 2: Login
    print("\n[2] Logging in...")
    login_data = {
        "email": "demo@example.com",
        "password": "demo12345"
    }
    
    response = requests.post(f"{BASE_URL}/api/auth/login/", json=login_data)
    print(f"Status: {response.status_code}")
    
    if response.status_code == 200:
        tokens = response.json()
        access_token = tokens['access']
        refresh_token = tokens['refresh']
        
        print("✓ Login successful!")
        print(f"\nAccess Token: {access_token[:60]}...")
        print(f"Refresh Token: {refresh_token[:60]}...")
        
        # Step 3: Get user profile
        print("\n[3] Getting user profile...")
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(f"{BASE_URL}/api/auth/profile/", headers=headers)
        
        if response.status_code == 200:
            profile = response.json()
            print("✓ Profile retrieved!")
            print(f"\nUser Info:")
            print(f"  Email: {profile['email']}")
            print(f"  Role: {profile['role']}")
            print(f"  Verified: {profile['is_verified']}")
            print(f"  Joined: {profile['date_joined']}")
        
        print("\n" + "="*60)
        print("✓ All operations completed successfully!")
        print("="*60)
    else:
        print(f"✗ Login failed: {response.json()}")
else:
    error = response.json()
    if "already exists" in str(error):
        print("⚠ User already exists. Trying login instead...")
        
        # Try login
        login_data = {
            "email": "demo@example.com",
            "password": "demo12345"
        }
        response = requests.post(f"{BASE_URL}/api/auth/login/", json=login_data)
        
        if response.status_code == 200:
            tokens = response.json()
            print("✓ Login successful!")
            print(f"Access Token: {tokens['access'][:60]}...")
        else:
            print(f"✗ Login failed: {response.json()}")
    else:
        print(f"✗ Registration failed: {error}")

