from django.urls import path
from .views import CheckPhoneView

urlpatterns = [
    path('check-phone', CheckPhoneView.as_view(), name='check-phone'),
]
