# Generated manually

from django.db import migrations


def create_default_landing_features(apps, schema_editor):
    LandingFeature = apps.get_model('accounts', 'LandingFeature')
    defaults = [
        {
            'title': 'Marketplace',
            'label': 'Explore',
            'short_description': 'Fresh produce and crops directly from farms',
            'link_target': '#marketplace',
            'cta_text': 'View marketplace →',
            'image_url': 'https://images.unsplash.com/photo-1542838132-92c53300491e?w=600&h=320&fit=crop',
            'display_order': 0,
        },
        {
            'title': 'Vendors',
            'label': 'Suppliers',
            'short_description': 'Connect with trusted suppliers and buyers',
            'link_target': '#vendors',
            'cta_text': 'Meet vendors →',
            'image_url': 'https://images.unsplash.com/photo-1504328345606-18bbc8c9d7d1?w=600&h=320&fit=crop',
            'display_order': 1,
        },
        {
            'title': 'Experts',
            'label': 'Support',
            'short_description': 'Get timely advice and consultations',
            'link_target': '#experts',
            'cta_text': 'Talk to experts →',
            'image_url': 'https://images.unsplash.com/photo-1500387467463-ef581a3e2a31?w=600&h=320&fit=crop',
            'display_order': 2,
        },
        {
            'title': 'Buyers',
            'label': 'For you',
            'short_description': 'Get fresh produce directly from farms',
            'link_target': '#marketplace',
            'cta_text': 'Start shopping →',
            'image_url': 'https://images.unsplash.com/photo-1414235077428-338989a2e8c0?w=600&h=320&fit=crop',
            'display_order': 3,
        },
    ]
    for d in defaults:
        LandingFeature.objects.get_or_create(
            title=d['title'],
            defaults={**d, 'is_active': True},
        )


def reverse_noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0027_landing_feature'),
    ]

    operations = [
        migrations.RunPython(create_default_landing_features, reverse_noop),
    ]
