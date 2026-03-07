# Add previous released amount for vendor earnings (e.g. 300 already released by admin)

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0029_landing_features_static_images'),
    ]

    operations = [
        migrations.AddField(
            model_name='vendorprofile',
            name='previous_released_amount',
            field=models.DecimalField(
                decimal_places=2,
                default=300,
                help_text='Earnings already released by admin before system tracking (e.g. 300)',
                max_digits=12,
                blank=True
            ),
        ),
    ]
