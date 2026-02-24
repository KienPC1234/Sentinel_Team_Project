from rest_framework import serializers
from .models import UserSession

class UserSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserSession
        fields = ['session_id', 'created_at', 'last_accessed', 'is_active']
        read_only_fields = ['session_id', 'created_at', 'last_accessed']

class SessionCheckResponseSerializer(serializers.Serializer):
    is_valid = serializers.BooleanField()
    new_session_id = serializers.UUIDField(allow_null=True)
