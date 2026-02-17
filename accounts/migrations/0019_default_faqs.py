# Generated data migration: default FAQs for customer support

from django.db import migrations


def create_default_faqs(apps, schema_editor):
    FAQ = apps.get_model('accounts', 'FAQ')
    defaults = [
        {
            'question': 'How do I reset my password?',
            'answer': 'Go to Login and click "Forgot password?". Enter your email and we will send you a link to reset your password. Check your spam folder if you do not see the email.',
            'category': 'Account',
            'order': 1,
        },
        {
            'question': 'How can I verify my account (KYC)?',
            'answer': 'Farmers, vendors, and agricultural experts need to complete KYC. Go to Profile or Dashboard and find the KYC section. Upload your ID document and a selfie. For vendors, a company document is required; for experts, a certificate. Our team will review within a few business days.',
            'category': 'Account',
            'order': 2,
        },
        {
            'question': 'How do I place an order for crops or tools?',
            'answer': 'Browse Crops or Tools from your dashboard (Buyer/User dashboard). Add items to cart and proceed to checkout. You can choose Cash on Delivery or eSewa. After placing an order, the farmer or vendor will confirm and update the status.',
            'category': 'Orders',
            'order': 3,
        },
        {
            'question': 'How do I track my order?',
            'answer': 'Go to Dashboard → Orders. You will see the status: Pending, Confirmed, Shipped, or Delivered. If a tracking number is added by the seller, it will appear there.',
            'category': 'Orders',
            'order': 4,
        },
        {
            'question': 'How do I book an appointment with an expert?',
            'answer': 'Go to the Appointments section and select "Request appointment". Choose an expert and a date from their available calendar. Add a message if needed. The expert will accept or reject and may suggest another date.',
            'category': 'Appointments',
            'order': 5,
        },
        {
            'question': 'How do I chat with an agricultural expert?',
            'answer': 'From your dashboard, open the Chat section. You can start a new chat with any listed expert. Only KYC-verified farmers can use expert chat. Buyers can chat with experts without KYC.',
            'category': 'Chat',
            'order': 6,
        },
        {
            'question': 'Who can I contact for direct support?',
            'answer': 'On the Support page you will see "Contact Support Staff" with available team members and their email. You can email them directly or open a support ticket for a tracked conversation.',
            'category': 'Support',
            'order': 7,
        },
    ]
    for faq in defaults:
        FAQ.objects.get_or_create(
            question=faq['question'],
            defaults={
                'answer': faq['answer'],
                'category': faq['category'],
                'order': faq['order'],
                'is_active': True,
            }
        )


def remove_default_faqs(apps, schema_editor):
    FAQ = apps.get_model('accounts', 'FAQ')
    questions = [
        'How do I reset my password?',
        'How can I verify my account (KYC)?',
        'How do I place an order for crops or tools?',
        'How do I track my order?',
        'How do I book an appointment with an expert?',
        'How do I chat with an agricultural expert?',
        'Who can I contact for direct support?',
    ]
    FAQ.objects.filter(question__in=questions).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0018_support_models'),
    ]

    operations = [
        migrations.RunPython(create_default_faqs, remove_default_faqs),
    ]
