from rest_framework import serializers

class PhoneCheckResponseSerializer(serializers.Serializer):
    risk_level = serializers.CharField()
    risk_label = serializers.CharField()
    recommendations = serializers.ListField(child=serializers.CharField())
