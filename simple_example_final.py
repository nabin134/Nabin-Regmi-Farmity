"""
Simple Example: Signup and Login APIs
Login returns email and success message
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
print("SIGNUP & LOGIN APIs")
print("="*70)

# Step 1: SIGNUP
print("\n[1] SIGNUP")
print("-" * 70)
signup_data = {
    "email": "user@example.com",
    "password": "password123",
    "role": "user"
}

print("Input:")
print(f"  Email: {signup_data['email']}")
print(f"  Password: {signup_data['password']}")
print(f"  Role: {signup_data['role']}")

response = requests.post(f"{BASE_URL}/api/auth/signup/", json=signup_data)
print(f"\nStatus: {response.status_code}")

if response.status_code == 201:
    result = response.json()
    print("✓ Signup Successful!")
    print(f"Response: {json.dumps(result, indent=2)}")
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

print("Input:")
print(f"  Email: {login_data['email']}")
print(f"  Password: {login_data['password']}")

response = requests.post(f"{BASE_URL}/api/auth/login/", json=login_data)
print(f"\nStatus: {response.status_code}")

if response.status_code == 200:
    result = response.json()
    print("✓ Login Successful!")
    print(f"\nResponse:")
    print(json.dumps(result, indent=2))
    print(f"\n✓ Email in response: {result.get('email')}")
    print(f"✓ Success message: {result.get('message')}")
else:
    print(f"✗ Login failed: {response.json()}")

print("\n" + "="*70)
print("✓ Complete!")
print("="*70)

