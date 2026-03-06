# Use project images for landing feature cards

from django.db import migrations

# Static paths (no leading slash) – served via {% static %}
STATIC_IMAGES = {
    'Marketplace': 'images/landing/marketplace.png',
    'Vendors': 'images/landing/vendor.png',
    'Experts': 'images/landing/experts.png',
    'Buyers': 'images/landing/buyers.png',
}


def set_static_images(apps, schema_editor):
    LandingFeature = apps.get_model('accounts', 'LandingFeature')
    for title, path in STATIC_IMAGES.items():
        LandingFeature.objects.filter(title=title).update(image_url=path)


def reverse_noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0028_default_landing_features'),
    ]

    operations = [
        migrations.RunPython(set_static_images, reverse_noop),
    ]
