from rest_framework import serializers

class ImageRiskAnalysisSerializer(serializers.Serializer):
    is_safe = serializers.BooleanField()
    risk_level = serializers.CharField()
    details = serializers.CharField()

class ImageAnalysisResponseSerializer(serializers.Serializer):
    ocr_text = serializers.CharField()
    risk_analysis = ImageRiskAnalysisSerializer()

class AudioAnalysisResponseSerializer(serializers.Serializer):
    risk_score = serializers.IntegerField()
    is_scam = serializers.BooleanField()
    transcript = serializers.CharField()
    warning_message = serializers.CharField()

class ImageAnalysisRequestSerializer(serializers.Serializer):
    images = serializers.ListField(child=serializers.ImageField())
    session_id = serializers.UUIDField(required=False)

class AudioAnalysisRequestSerializer(serializers.Serializer):
    audio = serializers.FileField()
    phone_number = serializers.CharField()
    session_id = serializers.UUIDField(required=False)
