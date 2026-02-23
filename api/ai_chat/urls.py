from django.urls import path
from .views import ChatAIStreamView, ChatSessionListView, ChatSessionDetailView, ChatSessionClearAllView

urlpatterns = [
    path('stream/', ChatAIStreamView.as_view(), name='chat-stream'),
    path('sessions/', ChatSessionListView.as_view(), name='chat-sessions'),
    path('sessions/<uuid:session_id>/', ChatSessionDetailView.as_view(), name='chat-session-detail'),
    path('sessions/clear_all/', ChatSessionClearAllView.as_view(), name='chat-sessions-clear-all'),
]
