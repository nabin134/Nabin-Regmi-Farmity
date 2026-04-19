from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.http import HttpResponse
from accounts.urls import api_urlpatterns, kyc_api_urlpatterns

urlpatterns = [
    # Admin URLs
    path('admin/', admin.site.urls),
    
    # App URLs
    path('', include('accounts.urls')),
    path('api/auth/', include(api_urlpatterns)),
    path('api/kyc/', include(kyc_api_urlpatterns)),
    path('accounts/', include('allauth.urls')),  # Allauth URLs for social login
]

# Serve static files and media in development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# Add WebSocket URL patterns for real-time features
if hasattr(settings, 'ASGI_APPLICATION'):
    from accounts.routing import websocket_urlpatterns
    urlpatterns += websocket_urlpatterns

# Custom handler for favicon
def favicon_view(request):
    return HttpResponse(status=204)