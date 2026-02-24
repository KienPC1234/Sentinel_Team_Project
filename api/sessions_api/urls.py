from django.urls import path
from .views import CheckSessionView

urlpatterns = [
    path('check-session', CheckSessionView.as_view(), name='check-session'),
]
