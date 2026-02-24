from django.db import models
import uuid
from datetime import timedelta
from django.utils import timezone


class UserSession(models.Model):
    """
    Stores user session information
    """
    session_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    last_accessed = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    # Session configuration
    session_timeout_hours = 24
    
    class Meta:
        db_table = 'user_sessions'
        indexes = [
            models.Index(fields=['last_accessed']),
            models.Index(fields=['is_active']),
        ]
    
    def is_expired(self):
        """Check if session has expired"""
        expiration_time = self.last_accessed + timedelta(hours=self.session_timeout_hours)
        return timezone.now() > expiration_time
    
    def refresh(self):
        """Refresh session access time"""
        self.last_accessed = timezone.now()
        self.save(update_fields=['last_accessed'])
    
    def __str__(self):
        return f"Session {self.session_id}"
