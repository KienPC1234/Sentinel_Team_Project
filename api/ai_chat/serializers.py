from rest_framework import serializers

class ChatAIRequestSerializer(serializers.Serializer):
    user_message = serializers.CharField(required=True)
    session_id = serializers.UUIDField(required=True)
    context = serializers.CharField(default='general')
    images = serializers.ListField(child=serializers.CharField(), required=False, default=[])

class ChatAIResponseSerializer(serializers.Serializer):
    ai_response = serializers.CharField()
    action_suggested = serializers.CharField(required=False, allow_null=True)
