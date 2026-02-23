"""
Helper to create in-app notifications for users.
"""
from .models import UserNotification


def create_notification(user, title, message='', link='', notification_type=UserNotification.TYPE_INFO):
    """Create a notification for the given user."""
    if not user or not title:
        return None
    return UserNotification.objects.create(
        user=user,
        title=title,
        message=message or '',
        link=link or '',
        notification_type=notification_type or UserNotification.TYPE_INFO,
    )
