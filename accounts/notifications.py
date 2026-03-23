"""
Helper to create in-app notifications for users.

This file also supports sending email copies of important notifications.
"""

from __future__ import annotations

import logging
from typing import Iterable

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import send_mail

from .models import UserNotification

logger = logging.getLogger(__name__)


def _get_admin_emails() -> list[str]:
    """
    Admin recipients: all users with role='admin'.
    """
    User = get_user_model()
    try:
        return list(
            User.objects.filter(role='admin', is_active=True)
            .values_list('email', flat=True)
            .distinct()
        )
    except Exception:
        logger.exception("Failed to fetch admin emails")
        return []


def _send_notification_email(
    *,
    user,
    title: str,
    message: str,
    link: str,
    notification_type: str,
) -> None:
    """
    Best-effort email sending (never block in-app notification creation).
    """
    EMAIL_TYPES = {
        UserNotification.TYPE_ORDER,
        UserNotification.TYPE_KYC,
        UserNotification.TYPE_APPOINTMENT,
        UserNotification.TYPE_SUPPORT,
    }

    if notification_type not in EMAIL_TYPES:
        return

    recipient_list: list[str] = []
    user_email = getattr(user, "email", None)
    if user_email:
        recipient_list.append(user_email)

    # Also notify admins (requested by the user)
    for e in _get_admin_emails():
        if e and e not in recipient_list:
            recipient_list.append(e)

    if not recipient_list:
        return

    subject = f"Farmity: {title}"
    # Keep it plain-text for reliability across mail providers.
    body = (
        f"{title}\n\n"
        f"{message or ''}\n\n"
        f"Link: {link or '-'}\n"
    )

    try:
        send_mail(
            subject=subject,
            message=body,
            from_email=getattr(settings, "DEFAULT_FROM_EMAIL", None),
            recipient_list=recipient_list,
            fail_silently=False,
        )
    except Exception:
        # Never fail notification creation due to SMTP issues.
        logger.exception("Failed to send notification email")


def create_notification(
    user,
    title,
    message: str = "",
    link: str = "",
    notification_type: str = UserNotification.TYPE_INFO,
):
    """
    Create an in-app notification for the given user, and (optionally) send an email copy.
    """
    if not user or not title:
        return None

    notification = UserNotification.objects.create(
        user=user,
        title=title,
        message=message or "",
        link=link or "",
        notification_type=notification_type or UserNotification.TYPE_INFO,
    )

    # Best-effort: don't block normal app flow.
    try:
        _send_notification_email(
            user=user,
            title=title,
            message=message or "",
            link=link or "",
            notification_type=notification.notification_type,
        )
    except Exception:
        logger.exception("Notification email hook failed")

    return notification
