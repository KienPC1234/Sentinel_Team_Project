from rest_framework import serializers
from .models import ChatFolder, ChatSession, ChatMessage, ChatbotConfig, SavedMessage

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

class ChatbotConfigSerializer(serializers.ModelSerializer):
    tone_display = serializers.CharField(source='get_tone_display', read_only=True)
    language_style_display = serializers.CharField(source='get_language_style_display', read_only=True)
    
    class Meta:
        model = ChatbotConfig
        fields = ['tone', 'tone_display', 'language_style', 'language_style_display', 
                  'custom_name', 'custom_instructions', 'updated_at']

class SavedMessageSerializer(serializers.ModelSerializer):
    message_text = serializers.CharField(source='message.message', read_only=True)
    message_role = serializers.CharField(source='message.role', read_only=True)
    session_id = serializers.UUIDField(source='message.session_id', read_only=True)
    session_title = serializers.CharField(source='message.session.title', read_only=True)
    
    class Meta:
        model = SavedMessage
        fields = ['id', 'message', 'message_text', 'message_role', 'session_id', 
                  'session_title', 'note', 'created_at']
