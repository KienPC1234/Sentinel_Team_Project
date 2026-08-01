from django.urls import path
from .views import ChatAIView, ChatAIStreamView

urlpatterns = [
    path('chat-ai', ChatAIView.as_view(), name='chat-ai'),
    path('chat-ai-stream', ChatAIStreamView.as_view(), name='chat-ai-stream'),
]
