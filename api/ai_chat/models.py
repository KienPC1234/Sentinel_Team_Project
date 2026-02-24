from django.db import models
import uuid


class ChatMessage(models.Model):
    """
    Stores chat messages between user and AI
    """
    ROLE_CHOICES = [
        ('user', 'User'),
        ('assistant', 'Assistant'),
    ]
    
    session_id = models.UUIDField(db_index=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    message = models.TextField()
    context = models.CharField(max_length=50, default='general', help_text="Context type: general, scam, etc")
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'chat_messages'
        indexes = [
            models.Index(fields=['session_id', 'created_at']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"{self.session_id} - {self.role}: {self.message[:50]}"


class ChatAction(models.Model):
    """
    Suggested actions from AI responses
    """
    ACTION_CHOICES = [
        ('NONE', 'No action'),
        ('BLOCK', 'Block number'),
        ('REPORT', 'Report to authorities'),
    ]
    
    chat_message = models.OneToOneField(ChatMessage, on_delete=models.CASCADE, related_name='action')
    action = models.CharField(max_length=20, choices=ACTION_CHOICES, default='NONE')
    confidence = models.FloatField(default=0.0, help_text="Confidence score 0-1")
    
    class Meta:
        db_table = 'chat_actions'
    
    def __str__(self):
        return f"{self.chat_message.session_id} - {self.action}"
