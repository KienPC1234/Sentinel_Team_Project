from django.db import models


class PhoneRiskLevel(models.TextChoices):
    SAFE = 'SAFE', 'Safe'
    GREEN = 'GREEN', 'Low Risk'
    YELLOW = 'YELLOW', 'Medium Risk'
    RED = 'RED', 'High Risk'


class PhoneNumber(models.Model):
    """
    Stores phone number risk information
    """
    phone_number = models.CharField(max_length=20, unique=True, db_index=True)
    risk_level = models.CharField(
        max_length=10,
        choices=PhoneRiskLevel.choices,
        default=PhoneRiskLevel.SAFE
    )
    risk_label = models.CharField(max_length=500, blank=True)
    recommendations = models.JSONField(default=list, help_text="List of recommendations")
    reports_count = models.IntegerField(default=0, help_text="Number of user reports")
    last_updated = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'phone_numbers'
        indexes = [
            models.Index(fields=['phone_number']),
            models.Index(fields=['risk_level']),
        ]
    
    def __str__(self):
        return f"{self.phone_number} - {self.risk_level}"


class PhoneReport(models.Model):
    """
    User reports about suspicious phone numbers
    """
    phone_number = models.ForeignKey(PhoneNumber, on_delete=models.CASCADE, related_name='reports')
    report_type = models.CharField(max_length=50, choices=[
        ('SPAM', 'Spam Call'),
        ('SCAM', 'Scam Call'),
        ('HARASSMENT', 'Harassment'),
        ('FRAUD', 'Fraud'),
    ])
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'phone_reports'
        indexes = [
            models.Index(fields=['created_at']),
            models.Index(fields=['report_type']),
        ]
