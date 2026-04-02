/**
 * Real-time WebSocket client for Farmity platform
 * Handles chat, appointments, and notifications via WebSockets
 */

// WebSocket connection management
class WebSocketManager {
    constructor() {
        this.connections = new Map();
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 3000;
    }

    // Chat WebSocket connection
    connectChat(threadId, callbacks = {}) {
        const wsUrl = this.getWebSocketUrl(`ws/chat/${threadId}/`);
        return this.createConnection(`chat_${threadId}`, wsUrl, {
            onMessage: (data) => {
                if (data.type === 'chat_message') {
                    callbacks.onMessage && callbacks.onMessage(data);
                } else if (data.type === 'connection') {
                    callbacks.onConnection && callbacks.onConnection(data);
                } else if (data.type === 'error') {
                    callbacks.onError && callbacks.onError(data);
                }
            },
            onConnect: () => {
                callbacks.onConnect && callbacks.onConnect();
            },
            onDisconnect: () => {
                callbacks.onDisconnect && callbacks.onDisconnect();
            }
        });
    }

    // Appointments WebSocket connection
    connectAppointments(callbacks = {}) {
        const wsUrl = this.getWebSocketUrl('ws/appointments/');
        return this.createConnection('appointments', wsUrl, {
            onMessage: (data) => {
                if (data.type === 'appointments_list') {
                    callbacks.onAppointmentsList && callbacks.onAppointmentsList(data);
                } else if (data.type === 'appointment_update') {
                    callbacks.onAppointmentUpdate && callbacks.onAppointmentUpdate(data);
                } else if (data.type === 'availability_updated') {
                    callbacks.onAvailabilityUpdate && callbacks.onAvailabilityUpdate(data);
                } else if (data.type === 'error') {
                    callbacks.onError && callbacks.onError(data);
                }
            },
            onConnect: () => {
                callbacks.onConnect && callbacks.onConnect();
            },
            onDisconnect: () => {
                callbacks.onDisconnect && callbacks.onDisconnect();
            }
        });
    }

    // Notifications WebSocket connection
    connectNotifications(callbacks = {}) {
        const wsUrl = this.getWebSocketUrl('ws/notifications/');
        return this.createConnection('notifications', wsUrl, {
            onMessage: (data) => {
                if (data.type === 'general_notification') {
                    callbacks.onNotification && callbacks.onNotification(data);
                } else if (data.type === 'chat_notification') {
                    callbacks.onChatNotification && callbacks.onChatNotification(data);
                } else if (data.type === 'connection') {
                    callbacks.onConnection && callbacks.onConnection(data);
                } else if (data.type === 'notification_marked_read') {
                    callbacks.onNotificationRead && callbacks.onNotificationRead(data);
                } else if (data.type === 'error') {
                    callbacks.onError && callbacks.onError(data);
                }
            },
            onConnect: () => {
                callbacks.onConnect && callbacks.onConnect();
            },
            onDisconnect: () => {
                callbacks.onDisconnect && callbacks.onDisconnect();
            }
        });
    }

    // Generic WebSocket connection method
    createConnection(name, url, callbacks) {
        // Close existing connection if any
        if (this.connections.has(name)) {
            this.connections.get(name).close();
        }

        const ws = new WebSocket(url);
        
        ws.onopen = () => {
            console.log(`WebSocket connected: ${name}`);
            this.connections.set(name, ws);
            this.reconnectAttempts = 0;
            callbacks.onConnect && callbacks.onConnect();
        };

        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                callbacks.onMessage && callbacks.onMessage(data);
            } catch (error) {
                console.error(`WebSocket message parse error: ${error}`);
            }
        };

        ws.onclose = (event) => {
            console.log(`WebSocket disconnected: ${name}, code: ${event.code}`);
            this.connections.delete(name);
            callbacks.onDisconnect && callbacks.onDisconnect();
            
            // Attempt reconnection
            if (this.reconnectAttempts < this.maxReconnectAttempts) {
                setTimeout(() => {
                    this.reconnectAttempts++;
                    console.log(`Attempting to reconnect ${name} (attempt ${this.reconnectAttempts})`);
                    this.createConnection(name, url, callbacks);
                }, this.reconnectDelay);
            }
        };

        ws.onerror = (error) => {
            console.error(`WebSocket error: ${name}`, error);
            callbacks.onError && callbacks.onError({ type: 'websocket_error', message: error.message });
        };

        return ws;
    }

    // Send message through WebSocket
    sendMessage(connectionName, message) {
        const ws = this.connections.get(connectionName);
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(message));
        } else {
            console.warn(`WebSocket ${connectionName} not connected`);
        }
    }

    // Close WebSocket connection
    closeConnection(name) {
        const ws = this.connections.get(name);
        if (ws) {
            ws.close();
            this.connections.delete(name);
        }
    }

    // Get WebSocket URL based on current protocol
    getWebSocketUrl(path) {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = window.location.host;
        return `${protocol}//${host}/${path}`;
    }

    // Close all connections
    closeAllConnections() {
        this.connections.forEach((ws, name) => {
            ws.close();
        });
        this.connections.clear();
    }
}

// Global WebSocket manager
window.wsManager = new WebSocketManager();

// Chat functionality for real-time messaging
class RealTimeChat {
    constructor(threadId) {
        this.threadId = threadId;
        this.callbacks = {};
        this.isConnected = false;
    }

    init(callbacks = {}) {
        this.callbacks = callbacks;
        
        wsManager.connectChat(this.threadId, {
            onConnect: () => {
                this.isConnected = true;
                callbacks.onConnect && callbacks.onConnect();
            },
            onMessage: (data) => {
                if (data.type === 'chat_message') {
                    this.displayMessage(data);
                    callbacks.onMessage && callbacks.onMessage(data);
                }
            },
            onDisconnect: () => {
                this.isConnected = false;
                callbacks.onDisconnect && callbacks.onDisconnect();
            },
            onError: (error) => {
                callbacks.onError && callbacks.onError(error);
            }
        });
    }

    sendMessage(message) {
        if (this.isConnected) {
            wsManager.sendMessage(`chat_${this.threadId}`, {
                type: 'chat_message',
                message: message
            });
        }
    }

    displayMessage(data) {
        const messagesContainer = document.getElementById('chat-messages');
        if (!messagesContainer) return;

        const messageElement = document.createElement('div');
        messageElement.className = `msg ${data.sender_id === window.currentUserId ? 'sent' : 'received'}`;
        
        const bubbleElement = document.createElement('div');
        bubbleElement.className = 'msg-bubble';
        bubbleElement.innerHTML = `
            ${this.escapeHtml(data.message)}
            <div class="msg-meta">${data.timestamp} • ${data.sender}</div>
        `;
        
        messageElement.appendChild(bubbleElement);
        messagesContainer.appendChild(messageElement);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    disconnect() {
        wsManager.closeConnection(`chat_${this.threadId}`);
    }
}

// Real-time appointments functionality
class RealTimeAppointments {
    constructor() {
        this.callbacks = {};
        this.isConnected = false;
    }

    init(callbacks = {}) {
        this.callbacks = callbacks;
        
        wsManager.connectAppointments({
            onConnect: () => {
                this.isConnected = true;
                callbacks.onConnect && callbacks.onConnect();
            },
            onMessage: (data) => {
                if (data.type === 'appointments_list') {
                    this.updateAppointmentsList(data.appointments);
                    callbacks.onAppointmentsList && callbacks.onAppointmentsList(data);
                } else if (data.type === 'appointment_update') {
                    this.updateAppointmentStatus(data.data);
                    callbacks.onAppointmentUpdate && callbacks.onAppointmentUpdate(data);
                } else if (data.type === 'availability_updated') {
                    this.updateExpertAvailability(data.data);
                    callbacks.onAvailabilityUpdate && callbacks.onAvailabilityUpdate(data);
                }
            },
            onDisconnect: () => {
                this.isConnected = false;
                callbacks.onDisconnect && callbacks.onDisconnect();
            },
            onError: (error) => {
                callbacks.onError && callbacks.onError(error);
            }
        });
    }

    requestAppointments() {
        if (this.isConnected) {
            wsManager.sendMessage('appointments', {
                type: 'get_appointments'
            });
        }
    }

    updateAppointmentsList(appointments) {
        // Update UI with new appointments list
        const appointmentsContainer = document.getElementById('appointments-list');
        if (appointmentsContainer) {
            appointmentsContainer.innerHTML = this.renderAppointmentsList(appointments);
        }
    }

    updateAppointmentStatus(appointmentData) {
        // Update specific appointment in UI
        const appointmentElement = document.getElementById(`appointment-${appointmentData.id}`);
        if (appointmentElement) {
            appointmentElement.innerHTML = this.renderAppointmentStatus(appointmentData);
        }
        
        // Show notification
        this.showNotification(`Appointment ${appointmentData.status}: ${appointmentData.message || 'Status updated'}`);
    }

    updateExpertAvailability(availabilityData) {
        // Update expert availability in calendar
        const calendarContainer = document.getElementById('availability-calendar');
        if (calendarContainer) {
            this.updateCalendarWithAvailability(availabilityData);
        }
    }

    renderAppointmentsList(appointments) {
        return appointments.map(apt => `
            <div class="appointment-item" id="appointment-${apt.id}">
                <div class="appointment-date">${apt.requested_date}</div>
                <div class="appointment-time">${apt.requested_time || 'All day'}</div>
                <div class="appointment-status status-${apt.status}">${apt.status}</div>
                <div class="appointment-message">${apt.message || ''}</div>
            </div>
        `).join('');
    }

    renderAppointmentStatus(appointment) {
        const statusColors = {
            'pending': '#ffc107',
            'accepted': '#28a745',
            'rejected': '#dc3545'
        };
        
        return `
            <div class="appointment-status" style="color: ${statusColors[appointment.status] || '#666'}">
                <strong>Status:</strong> ${appointment.status}
                ${appointment.response_message ? `<br><em>${appointment.response_message}</em>` : ''}
            </div>
        `;
    }

    updateCalendarWithAvailability(availability) {
        // Update calendar UI with new availability
        console.log('Updating calendar with availability:', availability);
        // Implementation depends on your calendar component
    }

    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `real-time-notification notification-${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <i class="fas fa-info-circle"></i>
                ${message}
            </div>
            <button class="notification-close" onclick="this.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        document.body.appendChild(notification);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 5000);
    }

    disconnect() {
        wsManager.closeConnection('appointments');
    }
}

// Real-time notifications functionality
class RealTimeNotifications {
    constructor() {
        this.callbacks = {};
        this.isConnected = false;
    }

    init(callbacks = {}) {
        this.callbacks = callbacks;
        
        wsManager.connectNotifications({
            onConnect: () => {
                this.isConnected = true;
                callbacks.onConnect && callbacks.onConnect();
            },
            onMessage: (data) => {
                if (data.type === 'general_notification') {
                    this.showNotification(data.data);
                    callbacks.onNotification && callbacks.onNotification(data);
                } else if (data.type === 'chat_notification') {
                    this.showChatNotification(data.data);
                    callbacks.onChatNotification && callbacks.onChatNotification(data);
                }
            },
            onDisconnect: () => {
                this.isConnected = false;
                callbacks.onDisconnect && callbacks.onDisconnect();
            },
            onError: (error) => {
                callbacks.onError && callbacks.onError(error);
            }
        });
    }

    markNotificationRead(notificationId) {
        if (this.isConnected) {
            wsManager.sendMessage('notifications', {
                type: 'mark_read',
                notification_id: notificationId
            });
        }
    }

    showNotification(notificationData) {
        const message = notificationData.message || notificationData.content;
        const type = notificationData.type || 'info';
        
        // Update notification bell
        const notificationBell = document.getElementById('notification-bell');
        if (notificationBell) {
            notificationBell.classList.add('has-new');
        }
        
        // Show notification popup
        this.showNotificationPopup(message, type);
    }

    showChatNotification(chatData) {
        const message = `New message from ${chatData.sender}: ${chatData.message}`;
        this.showNotification(message, 'chat');
        
        // Update notification count
        this.updateNotificationCount(1);
    }

    showNotificationPopup(message, type = 'info') {
        // Create popup notification
        const popup = document.createElement('div');
        popup.className = 'real-time-notification-popup';
        popup.innerHTML = `
            <div class="notification-content notification-${type}">
                <i class="fas fa-${type === 'error' ? 'exclamation-triangle' : 'info-circle'}"></i>
                ${message}
            </div>
        `;
        
        document.body.appendChild(popup);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (popup.parentElement) {
                popup.remove();
            }
        }, 5000);
    }

    updateNotificationCount(change) {
        const countElement = document.getElementById('notification-count');
        if (countElement) {
            const currentCount = parseInt(countElement.textContent) || 0;
            const newCount = Math.max(0, currentCount + change);
            countElement.textContent = newCount;
            countElement.style.display = newCount > 0 ? 'block' : 'none';
        }
    }

    disconnect() {
        wsManager.closeConnection('notifications');
    }
}

// Initialize real-time features when page loads
document.addEventListener('DOMContentLoaded', function() {
    // Set current user ID from template
    window.currentUserId = document.body.getAttribute('data-user-id') || null;
    
    // Auto-initialize based on page content
    const chatThreadElement = document.getElementById('chat-messages');
    if (chatThreadElement) {
        const threadId = chatThreadElement.getAttribute('data-thread-id');
        if (threadId) {
            window.realTimeChat = new RealTimeChat(threadId);
            window.realTimeChat.init({
                onMessage: (data) => {
                    console.log('New chat message:', data);
                }
            });
        }
    }
    
    const appointmentsElement = document.getElementById('appointments-list');
    if (appointmentsElement) {
        window.realTimeAppointments = new RealTimeAppointments();
        window.realTimeAppointments.init({
            onAppointmentUpdate: (data) => {
                console.log('Appointment updated:', data);
            }
        });
    }
    
    const notificationsElement = document.getElementById('notification-bell');
    if (notificationsElement) {
        window.realTimeNotifications = new RealTimeNotifications();
        window.realTimeNotifications.init({
            onNotification: (data) => {
                console.log('New notification:', data);
            }
        });
    }
});

// Add CSS for real-time notifications
const style = document.createElement('style');
style.textContent = `
.real-time-notification {
    position: fixed;
    top: 20px;
    right: 20px;
    background: #358D58;
    color: white;
    padding: 12px 16px;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    z-index: 1000;
    max-width: 300px;
    animation: slideInRight 0.3s ease-out;
}

.real-time-notification.notification-error {
    background: #dc3545;
}

.real-time-notification.notification-success {
    background: #28a745;
}

.notification-content {
    display: flex;
    align-items: center;
    gap: 8px;
}

.notification-close {
    background: none;
    border: none;
    color: white;
    cursor: pointer;
    font-size: 14px;
    padding: 4px;
    border-radius: 4px;
}

.notification-close:hover {
    background: rgba(255,255,255,0.1);
}

.real-time-notification-popup {
    position: fixed;
    top: 80px;
    right: 20px;
    background: #358D58;
    color: white;
    padding: 16px 20px;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    z-index: 1000;
    max-width: 350px;
    animation: slideInRight 0.3s ease-out;
}

@keyframes slideInRight {
    from {
        transform: translateX(100%);
        opacity: 0;
    }
    to {
        transform: translateX(0);
        opacity: 1;
    }
}

.appointment-item {
    background: white;
    padding: 16px;
    margin-bottom: 8px;
    border-radius: 8px;
    border-left: 4px solid #358D58;
}

.appointment-date {
    font-weight: bold;
    color: #358D58;
}

.appointment-time {
    color: #666;
    font-size: 14px;
}

.appointment-status {
    margin-top: 8px;
    padding: 8px 12px;
    border-radius: 4px;
    font-weight: bold;
}

.status-pending {
    background: #fff3cd;
    color: #856404;
}

.status-accepted {
    background: #d4edda;
    color: #155724;
}

.status-rejected {
    background: #f8d7da;
    color: #721c24;
}
`;
document.head.appendChild(style);
