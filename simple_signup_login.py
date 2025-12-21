"""
Simple Example: Signup and Login APIs
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
print("SIMPLE SIGNUP & LOGIN APIs")
print("="*70)

# Step 1: SIGNUP
print("\n[1] SIGNUP")
print("-" * 70)
signup_data = {
    "email": "user@example.com",
    "password": "password123",
    "role": "user"
}

response = requests.post(f"{BASE_URL}/api/auth/signup/", json=signup_data)
print(f"Status: {response.status_code}")

if response.status_code == 201:
    result = response.json()
    print("✓ Signup Successful!")
    print(f"Message: {result['message']}")
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
    "email": "user@example.com",
    "password": "password123"
}

response = requests.post(f"{BASE_URL}/api/auth/login/", json=login_data)
print(f"Status: {response.status_code}")

if response.status_code == 200:
    result = response.json()
    print("✓ Login Successful!")
    print(f"Message: {result['message']}")
else:
    print(f"✗ Login failed: {response.json()}")

print("\n" + "="*70)
print("✓ Complete!")
print("="*70)

