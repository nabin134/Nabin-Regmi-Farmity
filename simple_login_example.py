"""
Simple Example: Login with Text Fields → Success Message → User Details
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
print("LOGIN API: Text Fields → Success → User Details")
print("="*70)

# LOGIN
print("\n[LOGIN]")
print("-" * 70)

# Text Fields Input
print("Text Fields:")
email = "user@example.com"      # Email text field
password = "password123"         # Password text field

print(f"  Email (text field): {email}")
print(f"  Password (text field): {password}")

login_data = {
    "email": email,
    "password": password
}

response = requests.post(f"{BASE_URL}/api/auth/login/", json=login_data)
print(f"\nStatus: {response.status_code}")

if response.status_code == 200:
    result = response.json()
    
    # Success Message
    print(f"\n✓ {result['message']}")
    
    # User Details
    if 'user' in result:
        user = result['user']
        print(f"\nUser Details:")
        print(f"  ID: {user['id']}")
        print(f"  Email: {user['email']}")
        print(f"  Role: {user['role']}")
        print(f"  Verified: {user['is_verified']}")
        print(f"  Date Joined: {user['date_joined']}")
    
    print(f"\nFull Response:")
    print(json.dumps(result, indent=2))
else:
    print(f"✗ Login failed: {response.json()}")

print("\n" + "="*70)
print("✓ Complete!")
print("="*70)

