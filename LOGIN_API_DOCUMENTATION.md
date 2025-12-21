# Login API Documentation

## Endpoint
**POST** `/api/auth/login/`

## Description
Login API with email and password text fields.

---

## Request

### Headers
```
Content-Type: application/json
```

### Body (JSON)
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

### Required Fields
- **email** (text field): Email address of the user
- **password** (text field): User's password

---

## Response

### Success Response (200 OK)
```json
{
  "message": "Login successful",
  "email": "user@example.com",
  "input_fields": {
    "email": "Email text field - user@example.com",
    "password": "Password text field - entered"
  }
}
```

### Error Responses

#### Missing Fields (400 Bad Request)
```json
{
  "error": "Validation failed",
  "fields": {
    "email": ["This field is required."],
    "password": []
  },
  "required_fields": {
    "email": "Email address (text field)",
    "password": "Password (text field)"
  }
}
```

#### Invalid Credentials (401 Unauthorized)
```json
{
  "error": "Invalid email or password",
  "fields": {
    "email": "user@example.com",
    "password": "***"
  }
}
```

---

## Example Usage

### Python
```python
import requests

response = requests.post(
    "http://127.0.0.1:8000/api/auth/login/",
    json={
        "email": "user@example.com",      # Email text field
        "password": "password123"          # Password text field
    }
)

result = response.json()
print(result['message'])           # "Login successful"
print(result['email'])             # "user@example.com"
print(result['input_fields'])      # Shows email and password fields
```

### cURL
```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'
```

### JavaScript
```javascript
fetch('http://127.0.0.1:8000/api/auth/login/', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify({
        email: 'user@example.com',    // Email text field
        password: 'password123'         // Password text field
    })
})
.then(response => response.json())
.then(data => {
    console.log(data.message);        // "Login successful"
    console.log(data.email);          // "user@example.com"
    console.log(data.input_fields);   // Shows email and password fields
});
```

---

## Field Descriptions

### Email Field
- **Type**: Text field
- **Format**: Email address
- **Required**: Yes
- **Example**: `user@example.com`

### Password Field
- **Type**: Text field (password input)
- **Required**: Yes
- **Note**: Password is not returned in response for security

---

## Notes

1. Both email and password are **required text fields**
2. Email must be a valid email format
3. Password is not returned in the response for security reasons
4. The response confirms which email was used for login
5. Input fields are clearly shown in the success response

