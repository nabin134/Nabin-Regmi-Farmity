"""
Helper to create in-app notifications for users.

This file also supports sending email copies of important notifications.
"""

from __future__ import annotations

import logging
from html import escape

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import EmailMultiAlternatives
from django.urls import reverse

from .models import UserNotification

logger = logging.getLogger(__name__)

ROLE_THEMES = {
    # Per request: unified green mail palette across all sections/roles.
    "buyer": {"primary": "#2E7D32", "secondary": "#E8F5E9", "label": "Buyer"},
    "farmer": {"primary": "#2E7D32", "secondary": "#E8F5E9", "label": "Farmer"},
    "vendor": {"primary": "#2E7D32", "secondary": "#E8F5E9", "label": "Vendor"},
    "agricultural_expert": {"primary": "#2E7D32", "secondary": "#E8F5E9", "label": "Agricultural Expert"},
    "admin": {"primary": "#2E7D32", "secondary": "#E8F5E9", "label": "Admin"},
}

EVENT_SUBJECTS = {
    "signup": "Welcome to Farmity",
    "kyc_Submitted": "KYC Submitted Successfully",
    "kyc_Approved": "KYC Approved - Full Access Unlocked",
    "kyc_Rejected": "KYC Update Required",
    "order_shipped": "Your Order Has Been Shipped",
    "order_on_the_way": "Your Order Is On The Way",
    "order_delivered": "Your Order Was Delivered",
    "order_cancelled": "Order Cancellation Update",
    "payment_completed": "Payment Confirmation",
    "payout_paid": "Payout Released",
    "appointment_booked": "Appointment Request Confirmed",
    "appointment_accepted": "Appointment Accepted",
    "appointment_rejected": "Appointment Update",
    "appointment_cancelled": "Appointment Cancelled",
    "appointment_visit_status": "Appointment Visit Status Updated",
    "support_created": "Support Ticket Created",
    "support_reply": "New Reply On Support Ticket",
}

RED_EVENT_TYPES = {
    "kyc_rejected",
    "order_cancelled",
    "appointment_rejected",
    "appointment_cancelled",
}


def _default_link_for_notification(user, notification_type: str, title: str, message: str) -> str:
    """Provide a consistent fallback link when caller does not pass one."""
    role = (getattr(user, "role", "") or "").strip().lower()
    ntype = (notification_type or UserNotification.TYPE_INFO).strip().lower()
    text = f"{title or ''} {message or ''}".lower()

    if ntype == UserNotification.TYPE_ORDER:
        if role == "farmer":
            return reverse("farmer_dashboard") + "?section=orders"
        if role == "vendor":
            return reverse("vendor_dashboard") + "?section=orders"
        if role == "admin":
            return reverse("admin_marketplace_oversight")
        return reverse("user_dashboard") + "?section=orders"

    if ntype == UserNotification.TYPE_KYC:
        if role == "admin":
            return reverse("admin_kyc_management")
        if role in {"farmer", "vendor", "agricultural_expert"}:
            return reverse("kyc")
        return reverse("profile")

    if ntype == UserNotification.TYPE_APPOINTMENT:
        if role == "agricultural_expert":
            return reverse("expert_dashboard") + "?section=appointments"
        if role == "farmer":
            return reverse("farmer_dashboard") + "?section=appointments"
        return reverse("appointment_request")

    if ntype == UserNotification.TYPE_SUPPORT:
        if role == "admin":
            return reverse("admin_support_desk")
        return reverse("support_hub")

    if ntype == UserNotification.TYPE_CHAT:
        if role == "agricultural_expert":
            return reverse("expert_dashboard") + "?section=chat"
        return reverse("chat_threads")

    # TYPE_INFO and unknowns: infer likely section from content for better context.
    if "profile" in text:
        return reverse("profile")
    if "booking" in text or "appointment" in text:
        if role == "agricultural_expert":
            return reverse("expert_dashboard") + "?section=appointments"
        if role == "farmer":
            return reverse("farmer_dashboard") + "?section=appointments"
        return reverse("appointment_request")
    if "order" in text or "payment" in text or "payout" in text:
        if role == "farmer":
            return reverse("farmer_dashboard") + "?section=orders"
        if role == "vendor":
            return reverse("vendor_dashboard") + "?section=orders"
        if role == "admin":
            return reverse("admin_marketplace_oversight")
        return reverse("user_dashboard") + "?section=orders"
    if "kyc" in text or "verification" in text:
        if role == "admin":
            return reverse("admin_kyc_management")
        if role in {"farmer", "vendor", "agricultural_expert"}:
            return reverse("kyc")
    if role == "admin":
        return reverse("admin_dashboard")
    if role == "agricultural_expert":
        return reverse("expert_dashboard")
    if role == "farmer":
        return reverse("farmer_dashboard")
    if role == "vendor":
        return reverse("vendor_dashboard")
    return reverse("user_dashboard")


def get_admin_email_recipients() -> list[str]:
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


def send_branded_email(
    *,
    subject: str,
    title: str,
    message: str,
    recipient_list: list[str],
    cta_link: str = "",
    cta_text: str = "Open Farmity",
    retry_attempts: int = 2,
    role: str = "",
    event_type: str = "",
) -> bool:
    """
    Send a professional Farmity email (HTML + text fallback) with retries.
    Returns True on success, False otherwise.
    """
    recipients = [r for r in (recipient_list or []) if r]
    if not recipients:
        return False

    from_email = getattr(settings, "DEFAULT_FROM_EMAIL", None) or getattr(settings, "EMAIL_HOST_USER", None)
    role_key = (role or "").strip().lower()
    theme = ROLE_THEMES.get(role_key, {"primary": "#2E7D32", "secondary": "#E8F5E9", "label": "Member"})
    is_rejection = event_type in RED_EVENT_TYPES
    if is_rejection:
        theme = {"primary": "#C62828", "secondary": "#FDECEC", "label": theme.get("label", "Member")}

    subject_line = EVENT_SUBJECTS.get(event_type, subject or "Farmity Update")
    subject_line = f"Farmity | {subject_line}"

    safe_title = escape(title or "Farmity Update")
    safe_message = escape(message or "").replace("\n", "<br>")
    safe_cta_text = escape(cta_text or "Open Farmity")
    safe_cta_link = escape(cta_link or "")
    safe_role = escape(theme["label"])
    primary = theme["primary"]
    secondary = theme["secondary"]

    text_body = (
        f"{title}\n\n"
        f"{message}\n\n"
        + (f"Action: {cta_link}\n" if cta_link else "")
        + "Visit Farmity: https://tinyurl.com/Farmity\n\n"
        + "Thank you,\nFarmity Team\n"
    )

    html_body = f"""
    <div style="background:#f5f7fb;padding:28px 12px;font-family:Segoe UI,Arial,sans-serif;color:#1f2937;">
      <div style="max-width:640px;margin:0 auto;background:#ffffff;border-radius:16px;overflow:hidden;border:1px solid #e5e7eb;">
        <div style="background:linear-gradient(135deg,{primary} 0%,{'#7f1d1d' if is_rejection else '#1B5E20'} 100%);padding:20px 24px;">
          <h1 style="margin:0;color:#ffffff;font-size:22px;font-weight:700;letter-spacing:.2px;">Farmity</h1>
          <p style="margin:6px 0 0 0;color:{'#FDECEC' if is_rejection else '#E8F5E9'};font-size:13px;">Smart agriculture platform</p>
        </div>
        <div style="padding:24px;">
          <div style="display:inline-block;background:{secondary};color:{primary};border:1px solid {secondary};padding:4px 10px;border-radius:999px;font-size:12px;font-weight:700;margin-bottom:12px;">
            {safe_role} Update
          </div>
          <h2 style="margin:0 0 12px 0;font-size:20px;line-height:1.3;color:#111827;">{safe_title}</h2>
          <div style="font-size:15px;line-height:1.7;color:#374151;">{safe_message}</div>
          {f'<div style="margin-top:22px;"><a href="{safe_cta_link}" style="display:inline-block;background:{primary};color:#ffffff;text-decoration:none;padding:10px 16px;border-radius:10px;font-weight:600;font-size:14px;">{safe_cta_text}</a></div>' if cta_link else ''}
        </div>
        <div style="padding:14px 24px;background:#f9fafb;border-top:1px solid #e5e7eb;color:#6b7280;font-size:12px;">
          This is an automated email from Farmity. Please do not reply directly.<br>
          Visit us: <a href="https://tinyurl.com/Farmity" style="color:#6b7280;text-decoration:underline;">https://tinyurl.com/Farmity</a>
        </div>
      </div>
    </div>
    """

    for attempt in range(1, max(1, retry_attempts) + 1):
        try:
            msg = EmailMultiAlternatives(
                subject=subject_line,
                body=text_body,
                from_email=from_email,
                to=recipients,
            )
            msg.attach_alternative(html_body, "text/html")
            msg.send(fail_silently=False)
            return True
        except Exception:
            logger.exception("Branded email send failed (attempt %s)", attempt)
    return False


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
    for e in get_admin_email_recipients():
        if e and e not in recipient_list:
            recipient_list.append(e)

    if not recipient_list:
        return

    role = getattr(user, "role", "") or ""
    lower_title = (title or "").lower()
    lower_message = (message or "").lower()
    event_type = ""
    if notification_type == UserNotification.TYPE_KYC:
        # IMPORTANT: "not approved" must be treated as rejected (red).
        if (
            "rejected" in lower_title
            or "rejected" in lower_message
            or "not approved" in lower_title
            or "not approved" in lower_message
        ):
            event_type = "kyc_rejected"
        elif "approved" in lower_title or "approved" in lower_message:
            event_type = "kyc_approved"
        else:
            event_type = "kyc_submitted"
    elif notification_type == UserNotification.TYPE_ORDER:
        if "payout" in lower_title or "payout" in lower_message:
            event_type = "payout_paid"
        elif "payment" in lower_title or "payment" in lower_message:
            event_type = "payment_completed"
        elif "delivered" in lower_title or "delivered" in lower_message:
            event_type = "order_delivered"
        elif "on the way" in lower_title or "on the way" in lower_message:
            event_type = "order_on_the_way"
        elif "shipped" in lower_title or "shipped" in lower_message:
            event_type = "order_shipped"
        elif "cancel" in lower_title or "cancel" in lower_message:
            event_type = "order_cancelled"
    elif notification_type == UserNotification.TYPE_APPOINTMENT:
        if "accepted" in lower_title:
            event_type = "appointment_accepted"
        elif "not accepted" in lower_title or "rejected" in lower_title:
            event_type = "appointment_rejected"
        elif "cancel" in lower_title:
            event_type = "appointment_cancelled"
        elif "visit status" in lower_title or "visit status" in lower_message:
            event_type = "appointment_visit_status"
        else:
            event_type = "appointment_booked"
    elif notification_type == UserNotification.TYPE_SUPPORT:
        if "reply" in lower_title:
            event_type = "support_reply"
        else:
            event_type = "support_created"

    ok = send_branded_email(
        subject=title,
        title=title,
        message=message or "You have a new update in your Farmity account.",
        recipient_list=recipient_list,
        cta_link=link or "",
        cta_text="View Update",
        retry_attempts=2,
        role=role,
        event_type=event_type,
    )
    if not ok:
        # Never fail notification creation due to SMTP issues.
        logger.error("Failed to send notification email")


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

    resolved_link = (link or "").strip() or _default_link_for_notification(
        user,
        notification_type or UserNotification.TYPE_INFO,
        title or "",
        message or "",
    )

    notification = UserNotification.objects.create(
        user=user,
        title=title,
        message=message or "",
        link=resolved_link,
        notification_type=notification_type or UserNotification.TYPE_INFO,
    )

    # Best-effort: don't block normal app flow.
    try:
        _send_notification_email(
            user=user,
            title=title,
            message=message or "",
            link=resolved_link,
            notification_type=notification.notification_type,
        )
    except Exception:
        logger.exception("Notification email hook failed")

    return notification
