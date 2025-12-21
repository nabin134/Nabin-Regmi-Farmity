# JSON Parse Error Troubleshooting Guide

## Error: "JSON parse error - Extra data: line 1 column 10 (char 9)"

This error occurs when the API receives malformed JSON data. Here's how to fix it:

---

## Common Causes & Solutions

### 1. **Extra Data After JSON**

**Problem:** Extra characters or data after valid JSON
```json
{"email": "user@example.com"} extra text here
```

**Solution:** Remove any extra data after the JSON object
```json
{"email": "user@example.com"}
```

---

### 2. **Trailing Comma**

**Problem:** Trailing comma in JSON (not allowed in strict JSON)
```json
{
  "email": "user@example.com",
  "password": "password123",
}
```

**Solution:** Remove the trailing comma
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

---

### 3. **Missing Content-Type Header**

**Problem:** Not setting the Content-Type header to `application/json`

**Solution:** Always include the header:
```bash
curl -X POST http://127.0.0.1:8000/api/auth/signup/ \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'
```

**Python requests:**
```python
import requests

response = requests.post(
    "http://127.0.0.1:8000/api/auth/signup/",
    json={"email": "user@example.com", "password": "password123"},
    headers={"Content-Type": "application/json"}
)
```

---

### 4. **Multiple JSON Objects**

**Problem:** Sending multiple JSON objects in one request
```json
{"email": "user@example.com"}{"password": "password123"}
```

**Solution:** Combine into a single JSON object
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

---

### 5. **Using `data` instead of `json` in Python requests**

**Problem:** Using `data` parameter with a string instead of `json` parameter
```python
# WRONG
response = requests.post(url, data='{"email": "user@example.com"}')
```

**Solution:** Use `json` parameter (automatically sets Content-Type)
```python
# CORRECT
response = requests.post(url, json={"email": "user@example.com"})
```

---

## Correct Request Examples

### ✅ Using cURL (Windows CMD)
```cmd
curl -X POST http://127.0.0.1:8000/api/auth/signup/ ^
  -H "Content-Type: application/json" ^
  -d "{\"email\": \"user@example.com\", \"password\": \"password123\", \"role\": \"user\"}"
```

### ✅ Using cURL (Linux/Mac)
```bash
curl -X POST http://127.0.0.1:8000/api/auth/signup/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123",
    "role": "user"
  }'
```

### ✅ Using Python requests
```python
import requests

url = "http://127.0.0.1:8000/api/auth/signup/"
data = {
    "email": "user@example.com",
    "password": "password123",
    "role": "user"
}

response = requests.post(url, json=data)
print(response.json())
```

### ✅ Using JavaScript (Fetch API)
```javascript
fetch('http://127.0.0.1:8000/api/auth/signup/', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify({
        email: 'user@example.com',
        password: 'password123',
        role: 'user'
    })
})
.then(response => response.json())
.then(data => console.log(data));
```

### ✅ Using Postman
1. Set method to **POST**
2. Set URL to `http://127.0.0.1:8000/api/auth/signup/`
3. Go to **Headers** tab
4. Add header: `Content-Type: application/json`
5. Go to **Body** tab
6. Select **raw** and **JSON**
7. Enter:
```json
{
  "email": "user@example.com",
  "password": "password123",
  "role": "user"
}
```

---

## Testing Your JSON

Before sending, validate your JSON using:

1. **Online JSON Validator:** https://jsonlint.com/
2. **Python:**
```python
import json

try:
    json.loads('{"email": "user@example.com"}')
    print("Valid JSON")
except json.JSONDecodeError as e:
    print(f"Invalid JSON: {e}")
```

---

## Error Response Format

When a JSON error occurs, you'll now receive a helpful response:

```json
{
  "error": "Invalid JSON format",
  "detail": "JSON parse error - Extra data: line 1 column 10 (char 9)",
  "message": "Please ensure your request body contains valid JSON...",
  "tips": [
    "Make sure Content-Type header is set to 'application/json'",
    "Ensure JSON is properly formatted (no trailing commas)",
    "Check for extra characters or multiple JSON objects",
    "Verify all strings are properly quoted"
  ]
}
```

---

## Quick Checklist

- [ ] Content-Type header is set to `application/json`
- [ ] JSON is properly formatted (no trailing commas)
- [ ] No extra data after JSON object
- [ ] All strings are properly quoted
- [ ] Using `json` parameter in Python requests (not `data` with string)
- [ ] Single JSON object (not multiple objects)

---

## Still Having Issues?

1. **Check server logs** - Look at Django console output for detailed error messages
2. **Test with a simple request:**
```bash
curl -X POST http://127.0.0.1:8000/api/auth/signup/ \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"test@test.com\", \"password\": \"test12345\"}"
```

3. **Run the test script:**
```bash
python test_json_error.py
```

4. **Verify server is running:**
```bash
python manage.py runserver
```

