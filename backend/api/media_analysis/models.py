from django.db import models
import uuid


class ImageAnalysis(models.Model):
    """
    Stores image analysis results
    """
    analysis_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session_id = models.UUIDField(db_index=True, null=True, blank=True)
    ocr_text = models.TextField(blank=True)
    risk_level = models.CharField(
        max_length=20,
        choices=[
            ('SAFE', 'Safe'),
            ('GREEN', 'Low Risk'),
            ('YELLOW', 'Medium Risk'),
            ('RED', 'High Risk'),
        ],
        default='SAFE'
    )
    risk_details = models.TextField(blank=True)
    is_safe = models.BooleanField(default=True)
    image_file = models.ImageField(upload_to='analysis/images/', null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'image_analysis'
        indexes = [
            models.Index(fields=['session_id', 'created_at']),
            models.Index(fields=['risk_level']),
        ]


class AudioAnalysis(models.Model):
    """
    Stores audio analysis results
    """
    analysis_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session_id = models.UUIDField(db_index=True, null=True, blank=True)
    phone_number = models.CharField(max_length=20, db_index=True)
    transcript = models.TextField()
    risk_score = models.IntegerField(default=0, help_text="0-100 score")
    is_scam = models.BooleanField(default=False)
    warning_message = models.TextField(blank=True)
    audio_file = models.FileField(upload_to='analysis/audio/', null=True, blank=True)
    duration_seconds = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'audio_analysis'
        indexes = [
            models.Index(fields=['session_id', 'created_at']),
            models.Index(fields=['phone_number']),
            models.Index(fields=['is_scam']),
        ]
