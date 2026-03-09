# Backfill admin_commission and seller_amount for existing orders (20% / 80% split)
from decimal import Decimal
from django.db import migrations


def backfill_commission(apps, schema_editor):
    Order = apps.get_model('accounts', 'Order')
    for order in Order.objects.all():
        if order.admin_commission and order.admin_commission > 0:
            continue
        total = order.total_amount or Decimal('0')
        ship = order.shipping_cost or Decimal('0')
        product_sub = total - ship
        commission = (product_sub * Decimal('0.20')).quantize(Decimal('0.01'))
        seller_amt = (product_sub * Decimal('0.80') + ship).quantize(Decimal('0.01'))
        order.admin_commission = commission
        order.seller_amount = seller_amt
        order.save(update_fields=['admin_commission', 'seller_amount'])


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ('accounts', '0032_order_commission_and_expert_fee'),
    ]
    operations = [
        migrations.RunPython(backfill_commission, noop),
    ]
