"""
Test script to demonstrate JSON error handling
"""
import requests
import json

BASE_URL = "http://127.0.0.1:8000"

print("="*70)
print("Testing JSON Error Handling")
print("="*70)

# Test 1: Valid JSON
print("\n[Test 1] Valid JSON Request:")
try:
    response = requests.post(
        f"{BASE_URL}/api/auth/signup/",
        json={"email": "test@example.com", "password": "password123"},
        headers={"Content-Type": "application/json"}
    )
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
except Exception as e:
    print(f"Error: {e}")

# Test 2: Invalid JSON (extra data)
print("\n[Test 2] Invalid JSON - Extra data:")
try:
    response = requests.post(
        f"{BASE_URL}/api/auth/signup/",
        data='{"email": "test@example.com"} extra data',
        headers={"Content-Type": "application/json"}
    )
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
except Exception as e:
    print(f"Error: {e}")

# Test 3: Malformed JSON
print("\n[Test 3] Malformed JSON:")
try:
    response = requests.post(
        f"{BASE_URL}/api/auth/signup/",
        data='{"email": "test@example.com",}',
        headers={"Content-Type": "application/json"}
    )
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
except Exception as e:
    print(f"Error: {e}")

# Test 4: Empty body
print("\n[Test 4] Empty Request Body:")
try:
    response = requests.post(
        f"{BASE_URL}/api/auth/signup/",
        data="",
        headers={"Content-Type": "application/json"}
    )
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
except Exception as e:
    print(f"Error: {e}")

print("\n" + "="*70)

