from django.db import models
from django.conf import settings
import uuid


class ChatFolder(models.Model):
    """
    User-defined folders to organize chat sessions.
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='chat_folders')
    name = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'chat_folders'
        ordering = ['-created_at']

    def __str__(self):
        return self.name


class ChatSession(models.Model):
    """
    Groups chat messages into a persistent session for history and titling.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='chat_sessions', null=True, blank=True)
    folder = models.ForeignKey(ChatFolder, on_delete=models.SET_NULL, related_name='sessions', null=True, blank=True)
    title = models.CharField(max_length=255, default="Cuộc trò chuyện mới")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'chat_sessions'
        ordering = ['-updated_at']

    def __str__(self):
        return f"{self.title} ({self.id})"


class ChatMessage(models.Model):
    """
    Stores individual messages within a context-aware chat session.
    """
    ROLE_CHOICES = [
        ('user', 'User'),
        ('assistant', 'Assistant'),
    ]
    
    session = models.ForeignKey(ChatSession, on_delete=models.CASCADE, related_name='messages')
    session_id_legacy = models.UUIDField(db_index=True, null=True, blank=True, help_text="Legacy field for migration")
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    message = models.TextField()
    metadata = models.JSONField(null=True, blank=True, help_text="Structured data like search results, tool outputs, etc")
    context = models.CharField(max_length=50, default='general', help_text="Context type: general, scam, etc")
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'chat_messages'
        indexes = [
            models.Index(fields=['session', 'created_at']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"{self.role}: {self.message[:50]}"


class ChatMessageImage(models.Model):
    """
    Stores images associated with a ChatMessage.
    """
    message = models.ForeignKey(ChatMessage, on_delete=models.CASCADE, related_name='images')
    image = models.ImageField(upload_to='chat_images/')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'chat_message_images'

    def __str__(self):
        return f"Image for Msg {self.message.id}"


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
        return f"{self.action} (Msg ID: {self.chat_message.id})"


class ChatbotConfig(models.Model):
    """
    Per-user chatbot personalization settings (tone, personality, etc.)
    """
    TONE_CHOICES = [
        ('professional', 'Chuyên nghiệp'),
        ('friendly', 'Thân thiện'),
        ('casual', 'Thoải mái'),
        ('formal', 'Trang trọng'),
        ('humorous', 'Hài hước'),
    ]
    LANGUAGE_STYLE_CHOICES = [
        ('simple', 'Đơn giản, dễ hiểu'),
        ('detailed', 'Chi tiết, chuyên sâu'),
        ('concise', 'Ngắn gọn, súc tích'),
    ]
    
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='chatbot_config')
    tone = models.CharField(max_length=30, choices=TONE_CHOICES, default='friendly')
    language_style = models.CharField(max_length=30, choices=LANGUAGE_STYLE_CHOICES, default='simple')
    custom_name = models.CharField(max_length=50, blank=True, default='', help_text="Custom name for the AI assistant")
    custom_instructions = models.TextField(blank=True, default='', help_text="Additional instructions for the AI")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'chatbot_configs'

    def __str__(self):
        return f"Config for {self.user.username} (tone={self.tone})"


class SavedMessage(models.Model):
    """
    User-bookmarked chat messages for quick access.
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='saved_messages')
    message = models.ForeignKey(ChatMessage, on_delete=models.CASCADE, related_name='saved_by')
    note = models.CharField(max_length=255, blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'saved_messages'
        ordering = ['-created_at']
        unique_together = ('user', 'message')

    def __str__(self):
        return f"Saved by {self.user.username}: Msg {self.message.id}"
