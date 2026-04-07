"""
WebSocket consumers for real-time chat, appointments, and notifications.
"""
import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from channels.exceptions import StopConsumer
from django.contrib.auth.models import AnonymousUser
from channels.auth import login
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from accounts.models import ExpertChatThread, ExpertChatMessage, ExpertAppointment, SupportTicket
from django.utils import timezone
from datetime import timedelta


class ChatConsumer(AsyncWebsocketConsumer):
    """Real-time chat consumer."""
    
    async def connect(self):
        """Accept WebSocket connection and authenticate user."""
        self.user = self.scope["user"]
        if self.user == AnonymousUser():
            await self.close()
            return
        
        self.thread_id = self.scope['url_route']['kwargs']['thread_id']
        
        # Verify user has access to this chat thread
        try:
            thread = await database_sync_to_async(
                ExpertChatThread.objects.select_related('expert', 'created_by').get
            )(id=self.thread_id)
            
            # Check if user is expert in thread or thread creator
            if (thread.expert.user == self.user or 
                thread.created_by == self.user):
                
                # Accept connection
                await self.accept()
                
                # Add user to chat group
                self.chat_group_name = f'chat_{self.thread_id}'
                await self.channel_layer.group_add(
                    self.chat_group_name,
                    self.channel_name
                )
                
                # Send connection confirmation
                await self.send(text_data=json.dumps({
                    'type': 'connection',
                    'message': 'Connected to chat',
                    'user': self.user.email
                }))
            else:
                await self.close()
        except ExpertChatThread.DoesNotExist:
            await self.close()
    
    async def disconnect(self, close_code):
        """Handle WebSocket disconnection."""
        if hasattr(self, 'chat_group_name'):
            await self.channel_layer.group_discard(
                self.chat_group_name,
                self.channel_name
            )
    
    async def receive(self, text_data):
        """Handle incoming WebSocket messages."""
        try:
            data = json.loads(text_data)
            message_type = data.get('type')
            
            if message_type == 'chat_message':
                message_text = data.get('message', '').strip()
                
                if message_text:
                    # Save message to database
                    try:
                        thread = await database_sync_to_async(
                            ExpertChatThread.objects.get
                        )(id=self.thread_id)
                        
                        # Get sender profile image
                        sender_profile_image = await self.get_sender_profile_image()
                        
                        message = await database_sync_to_async(
                            ExpertChatMessage.objects.create
                        )(
                            thread=thread,
                            sender=self.user,
                            message=message_text,
                            sender_profile_image=sender_profile_image
                        )
                        
                        # Update thread timestamp
                        thread.updated_at = timezone.now()
                        await database_sync_to_async(thread.save)()
                        
                        # Broadcast message to all users in chat
                        await self.channel_layer.group_send(
                            self.chat_group_name,
                            {
                                'type': 'chat_message',
                                'message': message_text,
                                'sender': self.user.email,
                                'sender_id': self.user.id,
                                'sender_name': await self.get_sender_name(),
                                'sender_profile_image': sender_profile_image,
                                'timestamp': message.created_at.isoformat(),
                                'message_id': message.id,
                                'delivered_at': message.created_at.isoformat()
                            }
                        )
                        
                        # Mark message as delivered for other user
                        await self.mark_message_delivered(message.id)
                        
                    except Exception as e:
                        await self.send(text_data=json.dumps({
                            'type': 'error',
                            'message': f'Failed to send message: {str(e)}'
                        }))
                        
            elif message_type == 'typing':
                # Handle typing indicators
                await self.channel_layer.group_send(
                    self.chat_group_name,
                    {
                        'type': 'typing_indicator',
                        'user_id': self.user.id,
                        'user_email': self.user.email,
                        'is_typing': data.get('is_typing', False)
                    }
                )
                
            elif message_type == 'message_seen':
                # Handle message seen status
                message_id = data.get('message_id')
                if message_id:
                    await self.mark_message_seen(message_id)
                    
            else:
                await self.send(text_data=json.dumps({
                    'type': 'error',
                    'message': 'Invalid message type'
                }))
                
        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Invalid JSON format'
            }))
    
    async def get_sender_profile_image(self):
        """Get sender profile image URL."""
        try:
            if hasattr(self.user, 'expertprofile'):
                profile = await database_sync_to_async(lambda: self.user.expertprofile)()
                if profile and profile.photo:
                    return profile.photo.url
            elif hasattr(self.user, 'farmerprofile'):
                profile = await database_sync_to_async(lambda: self.user.farmerprofile)()
                if profile and profile.photo:
                    return profile.photo.url
            elif hasattr(self.user, 'userprofile'):
                profile = await database_sync_to_async(lambda: self.user.userprofile)()
                if profile and profile.photo:
                    return profile.photo.url
        except:
            pass
        return '/static/images/default-avatar.png'
    
    async def get_sender_name(self):
        """Get sender display name."""
        try:
            if hasattr(self.user, 'expertprofile'):
                profile = await database_sync_to_async(lambda: self.user.expertprofile)()
                return profile.name if profile and profile.name else self.user.email
            elif hasattr(self.user, 'farmerprofile'):
                profile = await database_sync_to_async(lambda: self.user.farmerprofile)()
                return profile.name if profile and profile.name else self.user.email
            elif hasattr(self.user, 'userprofile'):
                profile = await database_sync_to_async(lambda: self.user.userprofile)()
                return profile.name if profile and profile.name else self.user.email
        except:
            pass
        return self.user.email
    
    async def mark_message_delivered(self, message_id):
        """Mark message as delivered."""
        try:
            message = await database_sync_to_async(ExpertChatMessage.objects.get)(id=message_id)
            if not message.delivered_at:
                message.delivered_at = timezone.now()
                await database_sync_to_async(message.save)()
        except:
            pass
    
    async def mark_message_seen(self, message_id):
        """Mark message as seen and broadcast to sender."""
        try:
            message = await database_sync_to_async(ExpertChatMessage.objects.get)(id=message_id)
            if not message.seen_at:
                message.seen_at = timezone.now()
                await database_sync_to_async(message.save)()
                
                # Broadcast seen status to chat group
                await self.channel_layer.group_send(
                    self.chat_group_name,
                    {
                        'type': 'message_seen_status',
                        'message_id': message_id,
                        'seen_at': message.seen_at.isoformat(),
                        'seen_by': self.user.id
                    }
                )
        except:
            pass


class AppointmentConsumer(AsyncWebsocketConsumer):
    """Real-time appointment updates consumer."""
    
    async def connect(self):
        """Accept WebSocket connection and authenticate user."""
        self.user = self.scope["user"]
        if self.user == AnonymousUser():
            await self.close()
            return
        
        # Add user to their personal appointment group
        self.appointment_group = f'appointments_{self.user.id}'
        await self.channel_layer.group_add(
            self.appointment_group,
            self.channel_name
        )
        
        await self.accept()
        
        # Send initial appointment data
        await self.send_user_appointments()
    
    async def disconnect(self, close_code):
        """Handle WebSocket disconnection."""
        if hasattr(self, 'appointment_group'):
            await self.channel_layer.group_discard(
                self.appointment_group,
                self.channel_name
            )
    
    async def receive(self, text_data):
        """Handle incoming WebSocket messages for appointment updates."""
        try:
            data = json.loads(text_data)
            message_type = data.get('type')
            
            if message_type == 'get_appointments':
                await self.send_user_appointments()
            elif message_type == 'mark_available':
                # Expert marking themselves as available
                if self.user.role == 'agricultural_expert':
                    await self.update_expert_availability(data)
                    
        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Invalid JSON format'
            }))
    
    async def send_user_appointments(self):
        """Send user's current appointments."""
        try:
            if self.user.role == 'agricultural_expert':
                # Expert - get appointments where they are the expert
                appointments = await database_sync_to_async(
                    ExpertAppointment.objects.filter(
                        expert__user=self.user
                    ).select_related('requester').order_by('-created_at')
                )()
            else:
                # Other roles - get appointments they requested
                appointments = await database_sync_to_async(
                    ExpertAppointment.objects.filter(
                        requester=self.user
                    ).select_related('expert', 'expert__user').order_by('-created_at')
                )()
            
            appointments_data = []
            for appointment in appointments:
                appointments_data.append({
                    'id': appointment.id,
                    'requested_date': appointment.requested_date.isoformat(),
                    'requested_time': appointment.requested_time.isoformat() if appointment.requested_time else None,
                    'status': appointment.status,
                    'message': appointment.message,
                    'response_message': appointment.response_message,
                    'created_at': appointment.created_at.isoformat()
                })
            
            await self.send(text_data=json.dumps({
                'type': 'appointments_list',
                'appointments': appointments_data
            }))
            
        except Exception as e:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': f'Failed to load appointments: {str(e)}'
            }))
    
    async def update_expert_availability(self, data):
        """Update expert availability and notify clients."""
        try:
            from accounts.models import ExpertAvailability
            
            date_str = data.get('date')
            start_time = data.get('start_time')
            end_time = data.get('end_time')
            notes = data.get('notes', '')
            
            if date_str:
                # Create or update availability
                await database_sync_to_async(
                    ExpertAvailability.objects.update_or_create
                )(
                    expert__user=self.user,
                    date=date_str,
                    defaults={
                        'start_time': start_time,
                        'end_time': end_time,
                        'notes': notes
                    }
                )
                
                # Broadcast availability update
                await self.channel_layer.group_send(
                    f'expert_{self.user.id}_availability',
                    {
                        'type': 'availability_updated',
                        'expert_id': self.user.id,
                        'date': date_str,
                        'start_time': start_time,
                        'end_time': end_time,
                        'notes': notes
                    }
                )
                
        except Exception as e:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': f'Failed to update availability: {str(e)}'
            }))


class NotificationConsumer(AsyncWebsocketConsumer):
    """Real-time notifications consumer."""
    
    async def connect(self):
        """Accept WebSocket connection and authenticate user."""
        self.user = self.scope["user"]
        if self.user == AnonymousUser():
            await self.close()
            return
        
        # Add user to their personal notification group
        self.notification_group = f'notifications_{self.user.id}'
        await self.channel_layer.group_add(
            self.notification_group,
            self.channel_name
        )
        
        await self.accept()
        
        # Send connection confirmation
        await self.send(text_data=json.dumps({
            'type': 'connection',
            'message': 'Connected to notifications',
            'user': self.user.email
        }))
    
    async def disconnect(self, close_code):
        """Handle WebSocket disconnection."""
        if hasattr(self, 'notification_group'):
            await self.channel_layer.group_discard(
                self.notification_group,
                self.channel_name
            )
    
    async def receive(self, text_data):
        """Handle incoming WebSocket messages for notifications."""
        try:
            data = json.loads(text_data)
            message_type = data.get('type')
            
            if message_type == 'mark_read':
                # Mark notification as read
                notification_id = data.get('notification_id')
                if notification_id:
                    await self.mark_notification_read(notification_id)
                    
        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Invalid JSON format'
            }))
    
    async def mark_notification_read(self, notification_id):
        """Mark a notification as read."""
        try:
            from accounts.models import UserNotification
            
            await database_sync_to_async(
                UserNotification.objects.filter(
                    id=notification_id,
                    user=self.user
                ).update
            )(is_read=True)
            
            # Send confirmation
            await self.send(text_data=json.dumps({
                'type': 'notification_marked_read',
                'notification_id': notification_id
            }))
            
        except Exception as e:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': f'Failed to mark notification as read: {str(e)}'
            }))


class SupportTicketConsumer(AsyncWebsocketConsumer):
    """Real-time support ticket updates for owner/staff."""

    async def connect(self):
        self.user = self.scope["user"]
        if not self.user or getattr(self.user, "is_anonymous", True):
            await self.close()
            return

        self.ticket_id = self.scope["url_route"]["kwargs"]["ticket_id"]
        allowed = await self._can_access_ticket()
        if not allowed:
            await self.close()
            return

        self.group_name = f"support_ticket_{self.ticket_id}"
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        if hasattr(self, "group_name"):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data):
        # Keep-alive support for clients; no client-side command handling required.
        try:
            data = json.loads(text_data or "{}")
        except json.JSONDecodeError:
            return
        if data.get("type") == "ping":
            await self.send(text_data=json.dumps({"type": "pong"}))

    async def support_event(self, event):
        payload = event.get("payload") or {}
        await self.send(text_data=json.dumps(payload))

    @database_sync_to_async
    def _can_access_ticket(self):
        try:
            ticket = SupportTicket.objects.select_related("user").get(id=self.ticket_id)
        except SupportTicket.DoesNotExist:
            return False
        if ticket.user_id == self.user.id:
            return True
        # Same support-staff policy as views: admin role or support_staff_profile.
        role = getattr(self.user, "role", None)
        if role == "admin":
            return True
        return hasattr(self.user, "support_staff_profile")
