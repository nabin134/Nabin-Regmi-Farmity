from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
import json


def custom_exception_handler(exc, context):
    """
    Custom exception handler that provides better error messages for JSON parsing errors
    """
    response = exception_handler(exc, context)
    
    if response is not None:
        # Check if it's a JSON parse error
        if hasattr(exc, 'detail') and isinstance(exc.detail, str):
            if 'JSON parse error' in exc.detail or 'parse error' in exc.detail.lower():
                return Response(
                    {
                        "error": "Invalid JSON format",
                        "detail": exc.detail,
                        "message": "Please ensure your request body contains valid JSON. Example: {\"email\": \"user@example.com\", \"password\": \"password123\"}",
                        "tips": [
                            "Make sure Content-Type header is set to 'application/json'",
                            "Ensure JSON is properly formatted (no trailing commas)",
                            "Check for extra characters or multiple JSON objects",
                            "Verify all strings are properly quoted"
                        ]
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
    
    return response

