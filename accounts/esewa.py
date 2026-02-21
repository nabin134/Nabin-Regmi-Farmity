"""
eSewa ePay V2 integration (Nepal).
See: https://developer.esewa.com.np/pages/Epay-V2
"""
import base64
import hashlib
import hmac
from decimal import Decimal
from django.conf import settings
from django.urls import reverse


def get_esewa_config():
    """Return eSewa merchant code, secret, and form URL (UAT or production)."""
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


def esewa_verify_callback_signature(data: dict, secret: str) -> bool:
    """
    Verify eSewa success callback signature.
    data: decoded JSON from callback (status, signature, transaction_code, total_amount, transaction_uuid, product_code, signed_field_names).
    Use exact string representation of values to match eSewa's signature.
    """
    signed_names = data.get('signed_field_names', '')
    if not signed_names or not data.get('signature'):
        return False
    parts = []
    for key in signed_names.split(','):
        key = key.strip()
        val = data.get(key)
        if val is None:
            return False
        # Normalize so we match eSewa's signature (e.g. 230.0 -> "230")
        if isinstance(val, float) and val == int(val):
            val = int(val)
        parts.append(f'{key}={val}')
    message = ','.join(parts)
    expected = esewa_sign_message(message, secret)
    return hmac.compare_digest(expected, data.get('signature', ''))
