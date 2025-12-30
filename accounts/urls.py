from django.urls import path
from .views import (
    SignupView, LoginView,
    landing_page, role_selection, register_page, login_page, dashboard
)
urlpatterns = [
    path('', landing_page, name='landing'),
    path('role-selection/', role_selection, name='role-selection'),
    path('register/', register_page, name='register'),
    path('login/', login_page, name='login'),
    path('dashboard/', dashboard, name='dashboard'),
]

api_urlpatterns = [
    path('signup/', SignupView.as_view(), name='api-signup'),
    path('login/', LoginView.as_view(), name='api-login'),
]
