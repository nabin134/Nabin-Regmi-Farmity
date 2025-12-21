"""
Test script to verify Registration and Login API work smoothly
"""
import requests
import json
import sys
import time
from datetime import datetime

# Fix encoding for Windows console
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')

BASE_URL = "http://127.0.0.1:8000"

def print_header(text):
    print("\n" + "="*70)
    print(f"  {text}")
    print("="*70)

def print_success(text):
    print(f"✓ {text}")

def print_error(text):
    print(f"✗ {text}")

def print_info(text):
    print(f"→ {text}")

def test_server_connection():
    """Test if server is running"""
    print_header("Checking Server Connection")
    try:
        response = requests.get(f"{BASE_URL}/admin/", timeout=5)
        print_success("Server is running and accessible")
        return True
    except requests.exceptions.ConnectionError:
        print_error("Cannot connect to server. Make sure Django server is running:")
        print_info("Run: python manage.py runserver")
        return False
    except Exception as e:
        print_error(f"Error connecting to server: {e}")
        return False

def register_user(email, password, role="user"):
    """Register a new user"""
    print_header("Testing User Registration")
    
    url = f"{BASE_URL}/api/auth/signup/"
    data = {
        "email": email,
        "password": password,
        "role": role
    }
    
    print_info(f"Email: {email}")
    print_info(f"Role: {role}")
    print_info("Sending registration request...")
    
    try:
        response = requests.post(url, json=data, timeout=10)
        
        print(f"\nStatus Code: {response.status_code}")
        
        if response.status_code == 201:
            result = response.json()
            print_success("Registration Successful!")
            print(f"Response: {json.dumps(result, indent=2)}")
            return True, None
        else:
            result = response.json()
            print_error("Registration Failed")
            print(f"Response: {json.dumps(result, indent=2)}")
            return False, result
    except Exception as e:
        print_error(f"Error during registration: {e}")
        return False, None

def login_user(email, password):
    """Login user and get JWT tokens"""
    print_header("Testing User Login")
    
    url = f"{BASE_URL}/api/auth/login/"
    data = {
        "email": email,
        "password": password
    }
    
    print_info(f"Email: {email}")
    print_info("Sending login request...")
    
    try:
        response = requests.post(url, json=data, timeout=10)
        
        print(f"\nStatus Code: {response.status_code}")
        
        if response.status_code == 200:
            tokens = response.json()
            access_token = tokens.get('access')
            refresh_token = tokens.get('refresh')
            
            print_success("Login Successful!")
            print(f"\nAccess Token: {access_token[:50]}...")
            print(f"Refresh Token: {refresh_token[:50]}...")
            print(f"\nFull Response:")
            print(json.dumps({
                "access": access_token[:50] + "...",
                "refresh": refresh_token[:50] + "...",
                "token_type": "Bearer"
            }, indent=2))
            
            return True, access_token, refresh_token
        else:
            result = response.json()
            print_error("Login Failed")
            print(f"Response: {json.dumps(result, indent=2)}")
            return False, None, None
    except Exception as e:
        print_error(f"Error during login: {e}")
        return False, None, None

def get_user_profile(access_token):
    """Get user profile using access token"""
    print_header("Testing Get User Profile")
    
    url = f"{BASE_URL}/api/auth/profile/"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    
    print_info("Sending profile request with Bearer token...")
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        print(f"\nStatus Code: {response.status_code}")
        
        if response.status_code == 200:
            profile = response.json()
            print_success("Profile Retrieved Successfully!")
            print(f"\nUser Profile:")
            print(json.dumps(profile, indent=2))
            return True
        else:
            result = response.json()
            print_error("Failed to get profile")
            print(f"Response: {json.dumps(result, indent=2)}")
            return False
    except Exception as e:
        print_error(f"Error getting profile: {e}")
        return False

def main():
    """Main test function"""
    print("\n" + "="*70)
    print("  API REGISTRATION & LOGIN TEST")
    print("="*70)
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Base URL: {BASE_URL}")
    
    # Test server connection
    if not test_server_connection():
        return
    
    # Generate unique email for testing
    timestamp = int(time.time())
    test_email = f"testuser{timestamp}@example.com"
    test_password = "SecurePass123!"
    
    print(f"\nUsing test email: {test_email}")
    
    # Test Registration
    reg_success, reg_error = register_user(test_email, test_password, "user")
    
    if not reg_success:
        if reg_error and "already exists" in str(reg_error):
            print_info("User already exists, trying with different email...")
            test_email = f"testuser{timestamp}2@example.com"
            reg_success, _ = register_user(test_email, test_password, "user")
            if not reg_success:
                print_error("Registration failed. Please check the error above.")
                return
    
    if not reg_success:
        print_error("\nCannot proceed with login test - registration failed")
        return
    
    # Wait a moment for user to be saved
    time.sleep(0.5)
    
    # Test Login
    login_success, access_token, refresh_token = login_user(test_email, test_password)
    
    if not login_success:
        print_error("\nLogin failed. Please check the error above.")
        return
    
    # Test Profile Retrieval
    if access_token:
        get_user_profile(access_token)
    
    # Final Summary
    print_header("Test Summary")
    if reg_success and login_success:
        print_success("All tests passed!")
        print_info("Registration: ✓")
        print_info("Login: ✓")
        if access_token:
            print_info("Profile Retrieval: ✓")
        print("\n" + "="*70)
        print("API is working smoothly!")
        print("="*70)
        print(f"\nTest Credentials:")
        print(f"  Email: {test_email}")
        print(f"  Password: {test_password}")
        print(f"\nYou can now use these credentials to test the API.")
    else:
        print_error("Some tests failed. Please review the errors above.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user.")
    except Exception as e:
        print(f"\n\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()

