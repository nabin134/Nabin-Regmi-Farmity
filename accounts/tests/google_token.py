"""
Google ID token checks via Google's tokeninfo endpoint.

django-allauth handles OAuth in production; this module provides a small,
mock-friendly surface for validating ID tokens in tests or custom endpoints.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

GOOGLE_TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo"


def verify_google_id_token(
    id_token: str,
    *,
    timeout: float = 10.0,
) -> Tuple[Optional[dict[str, Any]], Optional[str]]:
    """
    Validate a Google ID token using the public tokeninfo endpoint.

    Returns:
        (payload_dict, None) on success.
        (None, error_code) on failure, where error_code is one of:
            missing_token, network_error, invalid_token, provider_error,
            expired_token, malformed_response
    """
    if not id_token or not str(id_token).strip():
        return None, "missing_token"

    token = str(id_token).strip()
    try:
        resp = requests.get(
            GOOGLE_TOKENINFO_URL,
            params={"id_token": token},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        logger.warning("Google tokeninfo request failed (network): %s", exc)
        return None, "network_error"

    if resp.status_code == 400:
        return None, "invalid_token"
    if resp.status_code != 200:
        return None, "provider_error"

    try:
        data = resp.json()
    except ValueError:
        return None, "malformed_response"

    if not isinstance(data, dict):
        return None, "malformed_response"

    if data.get("error") or data.get("error_description"):
        desc = (data.get("error_description") or data.get("error") or "").lower()
        if "expired" in desc:
            return None, "expired_token"
        return None, "invalid_token"

    exp = data.get("exp")
    if exp is not None:
        try:
            if int(exp) < int(time.time()):
                return None, "expired_token"
        except (TypeError, ValueError):
            return None, "malformed_response"

    return data, None
