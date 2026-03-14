"""
Context processors for templates.
"""
from decimal import Decimal
from django.db.models import Sum, Q

def admin_collections_payouts_summary(request):
    """
    Add Collections & Payouts totals to context for admin users so every admin page
    can show the summary (total collected, pending payout, paid out) and it never disappears.
    """
    if not request.user.is_authenticated or getattr(request.user, 'role', None) != 'admin':
        return {}
    from .models import Order
    collected = Order.objects.filter(payment_status=Order.PAYMENT_STATUS_COMPLETED)
    
    # For Mainali Tools and Technology vendor, check if they have actual sales
    mainali_vendor_orders = collected.filter(tool__vendor__user__email='np05cp4s240077@iic.edu.np')
    mainali_has_sales = mainali_vendor_orders.filter(tool__isnull=False).exists()
    
    if not mainali_has_sales:
        # Exclude Mainali Tools and Technology vendor if no actual sales
        collected = collected.exclude(tool__vendor__user__email='np05cp4s240077@iic.edu.np')
    # If they have sales, include them automatically
    
    total_collected = collected.aggregate(t=Sum('total_amount'))['t'] or Decimal('0')
    pending_q = Q(payout_status__isnull=True) | Q(payout_status=Order.PAYOUT_PENDING)
    total_pending = collected.filter(pending_q).aggregate(t=Sum('total_amount'))['t'] or Decimal('0')
    total_paid_out = total_collected - total_pending
    return {
        'admin_total_collected': float(total_collected),
        'admin_total_pending_payout': float(total_pending),
        'admin_total_paid_out': float(total_paid_out),
    }
