from django.urls import path
from .views import (
    ChatAIStreamView, ChatSessionListView, ChatSessionDetailView, 
    ChatSessionClearAllView, ChatMessageDeleteAfterView,
    ChatFolderListView, ChatFolderDetailView,
    ChatSearchView, ChatbotConfigView, SavedMessageListView, SavedMessageDetailView
)

urlpatterns = [
    path('stream/', ChatAIStreamView.as_view(), name='chat-stream'),
    path('sessions/', ChatSessionListView.as_view(), name='chat-sessions'),
    path('sessions/<uuid:session_id>/', ChatSessionDetailView.as_view(), name='chat-session-detail'),
    path('sessions/clear_all/', ChatSessionClearAllView.as_view(), name='chat-sessions-clear-all'),
    path('folders/', ChatFolderListView.as_view(), name='chat-folders'),
    path('folders/<int:folder_id>/', ChatFolderDetailView.as_view(), name='chat-folder-detail'),
    path('messages/<int:message_id>/delete_after/', ChatMessageDeleteAfterView.as_view(), name='chat-message-delete-after'),
    path('search/', ChatSearchView.as_view(), name='chat-search'),
    path('config/', ChatbotConfigView.as_view(), name='chatbot-config'),
    path('saved/', SavedMessageListView.as_view(), name='saved-messages'),
    path('saved/<int:saved_id>/', SavedMessageDetailView.as_view(), name='saved-message-detail'),
]
