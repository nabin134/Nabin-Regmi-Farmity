"""
WebSocket routing configuration for real-time features.
"""
from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    # Chat WebSocket routing
    re_path(r'ws/chat/(?P<thread_id>\w+)/$', consumers.ChatConsumer.as_asgi()),
    
    # Appointment WebSocket routing
    re_path(r'ws/appointments/$', consumers.AppointmentConsumer.as_asgi()),
    
    # Notifications WebSocket routing
    re_path(r'ws/notifications/$', consumers.NotificationConsumer.as_asgi()),

    # Support ticket real-time updates
    re_path(r'ws/support/(?P<ticket_id>\d+)/$', consumers.SupportTicketConsumer.as_asgi()),
]
