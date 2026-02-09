"""
Management command to fix SocialAccount links that incorrectly point to admin
when the Google account's email belongs to a different user (e.g. vendor, farmer).

Run: python manage.py fix_google_social_links

This fixes the issue where Google sign-in always redirects to admin dashboard
because a SocialAccount was previously linked to admin instead of the user
who owns that email.
"""
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from allauth.socialaccount.models import SocialAccount

User = get_user_model()


class Command(BaseCommand):
    help = 'Fix SocialAccounts that wrongly link Google to admin when email belongs to another user'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be fixed without making changes',
        )

    def handle(self, *args, **options):
        dry_run = options.get('dry_run', False)

        # Find all Google SocialAccounts linked to admin users
        google_accounts = SocialAccount.objects.filter(provider='google').select_related('user')
        fixed = 0

        for sa in google_accounts:
            if sa.user.role != 'admin':
                continue

            # Get email from extra_data (Google puts it there)
            extra = sa.extra_data or {}
            if not isinstance(extra, dict):
                continue
            email = extra.get('email') or extra.get('Email') or extra.get('mail')
            if not email or not isinstance(email, str):
                continue
            email = email.strip().lower()

            # If admin's email matches this, the link is correct
            if sa.user.email and sa.user.email.lower() == email:
                continue

            # Find the user that actually owns this email
            correct_user = User.objects.filter(email__iexact=email).exclude(pk=sa.user_id).first()
            if not correct_user:
                continue

            self.stdout.write(
                f'Found wrong link: Google ({email}) -> admin (id={sa.user_id}), '
                f'should be -> {correct_user.role} (id={correct_user.id})'
            )
            fixed += 1
            if not dry_run:
                sa.user = correct_user
                sa.save()
                self.stdout.write(self.style.SUCCESS(f'  -> Re-linked to {correct_user.role} user'))

        if dry_run:
            self.stdout.write(self.style.WARNING(f'\nDry run: would fix {fixed} links. Run without --dry-run to apply.'))
        else:
            self.stdout.write(self.style.SUCCESS(f'\nFixed {fixed} SocialAccount link(s).'))
