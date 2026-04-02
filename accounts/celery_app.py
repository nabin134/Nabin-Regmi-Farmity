"""
Celery configuration for Farmity background tasks.
"""
import os
from celery import Celery
from django.conf import settings

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Farmity.settings')

app = Celery('Farmity')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
# - namespace='CELERY' means all celery-related configuration keys
#   should have a `CELERY_` prefix.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django app configs.
app.autodiscover_tasks()

# Configure Celery to use Redis as broker
app.conf.broker_url = settings.REDIS_URL
app.conf.result_backend = settings.REDIS_URL
app.conf.accept_content = ['json']
app.conf.task_serializer = 'json'
app.conf.result_serializer = 'json'
app.conf.timezone = settings.TIME_ZONE


@app.task(bind=True)
def send_chat_notification(user_id, message_data):
    """Send real-time chat notification via WebSocket."""
    try:
        from channels.layers import get_channel_layer
        channel_layer = get_channel_layer()
        
        # Send to user's notification group
        from asgiref.sync import async_to_sync
        async_to_sync(channel_layer.group_send)(
            f'notifications_{user_id}',
            {
                'type': 'chat_notification',
                'data': message_data
            }
        )
        return {'status': 'success', 'message': 'Chat notification sent'}
    except Exception as e:
        return {'status': 'error', 'message': f'Failed to send chat notification: {str(e)}'}


@app.task(bind=True)
def send_appointment_notification(expert_id, appointment_data):
    """Send real-time appointment notification via WebSocket."""
    try:
        from channels.layers import get_channel_layer
        channel_layer = get_channel_layer()
        
        # Send to expert's appointment group
        from asgiref.sync import async_to_sync
        async_to_sync(channel_layer.group_send)(
            f'appointments_{expert_id}',
            {
                'type': 'appointment_update',
                'data': appointment_data
            }
        )
        return {'status': 'success', 'message': 'Appointment notification sent'}
    except Exception as e:
        return {'status': 'error', 'message': f'Failed to send appointment notification: {str(e)}'}


@app.task(bind=True)
def send_expert_availability_update(expert_id, availability_data):
    """Send real-time availability update via WebSocket."""
    try:
        from channels.layers import get_channel_layer
        channel_layer = get_channel_layer()
        
        # Send to expert's availability group
        from asgiref.sync import async_to_sync
        async_to_sync(channel_layer.group_send)(
            f'expert_{expert_id}_availability',
            {
                'type': 'availability_updated',
                'data': availability_data
            }
        )
        return {'status': 'success', 'message': 'Availability update sent'}
    except Exception as e:
        return {'status': 'error', 'message': f'Failed to send availability update: {str(e)}'}


@app.task(bind=True)
def send_notification_to_user(user_id, notification_data):
    """Send general notification to user via WebSocket."""
    try:
        from channels.layers import get_channel_layer
        channel_layer = get_channel_layer()
        
        # Send to user's notification group
        from asgiref.sync import async_to_sync
        async_to_sync(channel_layer.group_send)(
            f'notifications_{user_id}',
            {
                'type': 'general_notification',
                'data': notification_data
            }
        )
        return {'status': 'success', 'message': 'Notification sent'}
    except Exception as e:
        return {'status': 'error', 'message': f'Failed to send notification: {str(e)}'}
