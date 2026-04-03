# Generated manually to fix missing database fields

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0036_order_inventory_deducted_paymentgroup'),
    ]

    operations = [
        migrations.AddField(
            model_name='expertchatmessage',
            name='delivered_at',
            field=models.DateTimeField(null=True, blank=True, help_text="When message was delivered to recipient"),
        ),
        migrations.AddField(
            model_name='expertchatmessage',
            name='seen_at',
            field=models.DateTimeField(null=True, blank=True, help_text="When message was seen by recipient"),
        ),
        migrations.AddField(
            model_name='expertchatmessage',
            name='sender_profile_image',
            field=models.URLField(max_length=500, blank=True, null=True, help_text="Cached sender profile image URL"),
        ),
    ]
