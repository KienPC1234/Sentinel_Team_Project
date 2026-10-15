from django.urls import path, re_path
from .views import (
    ChatAIStreamView, ChatSessionListView, ChatSessionDetailView, 
    ChatSessionClearAllView, ChatMessageDeleteAfterView, ChatMessageRatingView,
    ChatFolderListView, ChatFolderDetailView,
    ChatSearchView, ChatbotConfigView, SavedMessageListView, SavedMessageDetailView
)

urlpatterns = [
    path('stream/', ChatAIStreamView.as_view(), name='chat-stream'),
    path('sessions/', ChatSessionListView.as_view(), name='chat-sessions'),
    path('sessions/clear_all/', ChatSessionClearAllView.as_view(), name='chat-sessions-clear-all'),
    path('sessions/<uuid:session_id>/', ChatSessionDetailView.as_view(), name='chat-session-detail'),
    re_path(r'^sessions/(?P<session_id>[0-9a-fA-F-]{32,36})/?$', ChatSessionDetailView.as_view(), name='chat-session-detail-alias'),
    path('folders/', ChatFolderListView.as_view(), name='chat-folders'),
    path('folders/<int:folder_id>/', ChatFolderDetailView.as_view(), name='chat-folder-detail'),
    path('messages/<int:message_id>/delete_after/', ChatMessageDeleteAfterView.as_view(), name='chat-message-delete-after'),
    path('messages/<int:message_id>/rating/', ChatMessageRatingView.as_view(), name='chat-message-rating'),
    path('search/', ChatSearchView.as_view(), name='chat-search'),
    path('config/', ChatbotConfigView.as_view(), name='chatbot-config'),
    path('saved/', SavedMessageListView.as_view(), name='saved-messages'),
    path('saved/<int:saved_id>/', SavedMessageDetailView.as_view(), name='saved-message-detail'),
]
