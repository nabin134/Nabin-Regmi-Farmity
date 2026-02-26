"""
Management command to fix Google SocialAccount links that are incorrectly
linked to admin when the email belongs to another user.

Usage:
    python manage.py fix_google_social_links
    python manage.py fix_google_social_links --dry-run
"""

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from allauth.socialaccount.models import SocialAccount
from django.db import transaction

User = get_user_model()


class Command(BaseCommand):
    help = "Fix Google SocialAccounts wrongly linked to admin user"

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be fixed without applying changes",
        )

    @transaction.atomic
    def handle(self, *args, **options):
        dry_run = options.get("dry_run", False)
        fixed_count = 0

        google_accounts = (
            SocialAccount.objects
            .filter(provider="google")
            .select_related("user")
        )

        if not google_accounts.exists():
            self.stdout.write(self.style.WARNING("No Google SocialAccounts found."))
            return

        for social_account in google_accounts:

            user = social_account.user

            # Skip if user has no role attribute
            user_role = getattr(user, "role", None)
            if user_role != "admin":
                continue

            # Extract email safely from extra_data
            extra_data = social_account.extra_data or {}
            if not isinstance(extra_data, dict):
                continue

            email = (
                extra_data.get("email")
                or extra_data.get("Email")
                or extra_data.get("mail")
            )

            if not email or not isinstance(email, str):
                continue

            email = email.strip().lower()

            # If admin email matches, link is correct
            if user.email and user.email.lower() == email:
                continue

            # Find correct user by email
            correct_user = (
                User.objects
                .filter(email__iexact=email)
                .exclude(pk=user.pk)
                .first()
            )

            if not correct_user:
                continue

            self.stdout.write(
                f"Incorrect link found:"
                f" Google({email}) -> admin(id={user.id})"
                f" | Should link to {correct_user.role}(id={correct_user.id})"
            )

            fixed_count += 1

            if not dry_run:
                social_account.user = correct_user
                social_account.save(update_fields=["user"])
                self.stdout.write(
                    self.style.SUCCESS("  ✓ Re-linked successfully.")
                )

        if dry_run:
            self.stdout.write(
                self.style.WARNING(
                    f"\nDry run complete. {fixed_count} link(s) would be fixed."
                )
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(
                    f"\nCompleted. {fixed_count} SocialAccount link(s) fixed."
                )
            )