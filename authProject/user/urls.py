from django.urls import path, include
from rest_framework import routers
from .views_api import *
from .views import *


router = routers.DefaultRouter()
router.register(r'users', UserViewSet, basename='users')


urlpatterns = [
    # API Urls
    path('', include(router.urls)),
    path('login/', user_login),
    path('logout/', user_logout),
    path('forget-password/', forget_password),
    path('forget-password-confirm/', forget_password_confirm),
    path('resend-email-verification-otp/', re_send_email_verification_otp),
    path('verify-email/', verify_email, name='verify_email'),
    
    # used for backed server login as a admin only
    path('admin-login/', login_view, name="admin-login"),
    path('admin-logout/', logout_view, name="admin-logout"),
    
]