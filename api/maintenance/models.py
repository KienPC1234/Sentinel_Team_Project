from django.db import models
import uuid


class CrashReport(models.Model):
    """
    Stores crash reports from mobile devices
    """
    report_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device_info = models.CharField(max_length=255)
    stack_trace = models.TextField()
    timestamp = models.BigIntegerField(help_text="Unix timestamp in milliseconds")
    severity = models.CharField(
        max_length=20,
        choices=[
            ('CRITICAL', 'Critical'),
            ('ERROR', 'Error'),
            ('WARNING', 'Warning'),
        ],
        default='ERROR'
    )
    version = models.CharField(max_length=20, blank=True, help_text="App version")
    os_version = models.CharField(max_length=50, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    fixed = models.BooleanField(default=False)
    notes = models.TextField(blank=True)
    
    class Meta:
        db_table = 'crash_reports'
        indexes = [
            models.Index(fields=['created_at']),
            models.Index(fields=['severity']),
            models.Index(fields=['fixed']),
        ]
    
    def __str__(self):
        return f"Crash Report {self.report_id} - {self.severity}"


class ErrorLog(models.Model):
    """
    Stores general error logs
    """
    log_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    error_type = models.CharField(max_length=100)
    error_message = models.TextField()
    context = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    resolved = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'error_logs'
        indexes = [
            models.Index(fields=['error_type']),
            models.Index(fields=['created_at']),
        ]
