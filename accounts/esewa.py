"""eSewa ePay V2 (Nepal). https://developer.esewa.com.np/pages/Epay-V2"""
import base64
import hashlib
import hmac
from decimal import Decimal

from django.conf import settings


def get_esewa_config():
    """Merchant code, secret key, and payment form URL (UAT or production)."""
    merchant_code = getattr(settings, 'ESEWA_MERCHANT_CODE', '') or ''
    secret = getattr(settings, 'ESEWA_SECRET_KEY', '') or ''
    use_uat = getattr(settings, 'ESEWA_USE_UAT', True)
    if use_uat:
        form_url = 'https://rc-epay.esewa.com.np/api/epay/main/v2/form'
    else:
        form_url = 'https://epay.esewa.com.np/api/epay/main/v2/form'
    return merchant_code, secret, form_url


def esewa_sign_message(message: str, secret: str) -> str:
    """Generate HMAC-SHA256 signature (base64) for eSewa."""
    signature = hmac.new(
        secret.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).digest()
    return base64.b64encode(signature).decode('ascii')


def esewa_build_form_data(
    total_amount,
    transaction_uuid: str,
    success_url: str,
    failure_url: str,
    product_code: str = None,
    secret: str = None,
    tax_amount: str = '0',
    product_service_charge: str = '0',
    product_delivery_charge: str = '0',
):
    """
    Build form parameters for eSewa ePay V2.
    total_amount: decimal or number (NPR). amount = total - tax - service - delivery (we use amount = total, others 0).
    transaction_uuid: unique ref (e.g. order-123 or cart-abc).
    """
    merchant_code, _secret, _ = get_esewa_config()
    product_code = product_code or merchant_code
    secret = secret or _secret
    if not product_code or not secret:
        return None

    total_amount = Decimal(str(total_amount))
    amount = total_amount - Decimal(tax_amount) - Decimal(product_service_charge) - Decimal(product_delivery_charge)
    if amount < 0:
        amount = total_amount
    # eSewa expects integer amount in NPR (round to avoid truncation)
    total_str = str(int(round(total_amount)))
    amount_str = str(int(round(amount)))
    signed_field_names = 'total_amount,transaction_uuid,product_code'
    message = f'total_amount={total_str},transaction_uuid={transaction_uuid},product_code={product_code}'
    signature = esewa_sign_message(message, secret)

    return {
        'amount': amount_str,
        'tax_amount': tax_amount,
        'total_amount': total_str,
        'transaction_uuid': transaction_uuid,
        'product_code': product_code,
        'product_service_charge': product_service_charge,
        'product_delivery_charge': product_delivery_charge,
        'success_url': success_url,
        'failure_url': failure_url,
        'signed_field_names': signed_field_names,
        'signature': signature,
    }


def _esewa_callback_value_str(val):
    """Stringify callback fields like eSewa/PHP (strings unchanged; 100.0 -> \"100\")."""
    if val is None:
        return None
    if isinstance(val, str):
        return val
    if isinstance(val, bool):
        return '1' if val else ''
    if isinstance(val, int):
        return str(val)
    if isinstance(val, float):
        if val == int(val):
            return str(int(val))
        return str(val)
    return str(val)


def esewa_verify_callback_signature(data: dict, secret: str) -> bool:
    """Verify HMAC on decoded callback JSON (signed_field_names order)."""
    signed_names_raw = data.get('signed_field_names', '')
    if not signed_names_raw or not data.get('signature'):
        return False
    received_sig = str(data.get('signature', '')).strip().replace('\n', '').replace('\r', '')
    parts = []
    for key in str(signed_names_raw).split(','):
        key = key.strip()
        if not key:
            continue
        if key not in data:
            return False
        val = _esewa_callback_value_str(data.get(key))
        if val is None:
            return False
        parts.append(f'{key}={val}')
    message = ','.join(parts)
    expected = esewa_sign_message(message, secret).strip()

    def _sig_bytes(s: str) -> bytes:
        s = (s or '').strip()
        pad = (-len(s)) % 4
        if pad:
            s += '=' * pad
        return base64.b64decode(s, validate=False)

    try:
        return hmac.compare_digest(_sig_bytes(expected), _sig_bytes(received_sig))
    except Exception:
        return False
