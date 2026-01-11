from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from accounts.urls import api_urlpatterns

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('accounts.urls')),
    path('api/auth/', include(api_urlpatterns)),
    path('accounts/', include('allauth.urls')),  # Allauth URLs for social login
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATICFILES_DIRS[0] if settings.STATICFILES_DIRS else None)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)