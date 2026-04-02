"""
ASGI config for Farmity project with WebSocket support.
"""
import os
import django
from channels.routing import get_default_application
from channels.auth import AuthMiddlewareStack
from channels.security.websocket import AllowedHostsOriginValidator

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Farmity.settings')
django.setup()

# Get Channels-enabled application
application = get_default_application()

# Add WebSocket security middleware
application = AuthMiddlewareStack(
    application,
    AllowedHostsOriginValidator(['localhost', '127.0.0.1', '0.0.0.0'])
)
