from rest_framework import serializers
from .models import ChatFolder, ChatSession, ChatMessage

class ChatFolderSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChatFolder
        fields = ['id', 'name', 'created_at', 'updated_at']

class ChatSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChatSession
        fields = ['id', 'title', 'folder', 'created_at', 'updated_at']

class ChatAIRequestSerializer(serializers.Serializer):
    user_message = serializers.CharField(required=True)
    session_id = serializers.UUIDField(required=True)
    context = serializers.CharField(default='general')
    images = serializers.ListField(child=serializers.CharField(), required=False, default=[])

class ChatAIResponseSerializer(serializers.Serializer):
    ai_response = serializers.CharField()
    action_suggested = serializers.CharField(required=False, allow_null=True)
