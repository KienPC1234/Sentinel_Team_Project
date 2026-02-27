"""
ShieldCall VN – Core Models
Implements MVP spec Section 4: Database Schema
"""
import hashlib
import uuid
import logging
from django.db import models
from django.conf import settings

logger = logging.getLogger(__name__)
from django.utils import timezone
from django.contrib.auth.models import User
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver

# ─── User Profile Model ──────────────────────────────────────────────────────

class UserProfile(models.Model):
    """Extended user data including avatar and preferences"""
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='profile')
    display_name = models.CharField(max_length=100, blank=True)
    avatar = models.ImageField(upload_to='profiles/avatars/', null=True, blank=True)
    rank_points = models.IntegerField(default=0)
    bio = models.TextField(max_length=500, blank=True)
    about = models.TextField(blank=True, help_text="Markdown supported bio/about section")
    messenger_link = models.URLField(max_length=500, blank=True, null=True, help_text="Link to Facebook Messenger, Zalo, etc.")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_super_admin = models.BooleanField(default=False)

    @property
    def rank_info(self):
        """Returns rank name and icon based on points"""
        p = self.rank_points
        if p >= 5000: return {'name': 'Kim Cương', 'level': 'diamond', 'icon': 'bi-gem', 'color': 'text-cyan-400'}
        if p >= 2000: return {'name': 'Bạch Kim', 'level': 'platinum', 'icon': 'bi-trophy-fill', 'color': 'text-purple-400'}
        if p >= 1000: return {'name': 'Vàng', 'level': 'gold', 'icon': 'bi-award-fill', 'color': 'text-yellow-400'}
        if p >= 300: return {'name': 'Bạc', 'level': 'silver', 'icon': 'bi-shield-shaded', 'color': 'text-slate-300'}
        return {'name': 'Đồng', 'level': 'bronze', 'icon': 'bi-shield-fill', 'color': 'text-orange-400'}

    def __str__(self):
        return f"Profile of {self.user.username}"

@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.get_or_create(user=instance)

@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def save_user_profile(sender, instance, **kwargs):
    if hasattr(instance, 'profile'):
        instance.profile.save()
    else:
        UserProfile.objects.get_or_create(user=instance)


# ─── Scam type & severity enums ─────────────────────────────────────────────

class ScamType(models.TextChoices):
    POLICE_IMPERSONATION = 'police_impersonation', 'Giả danh công an'
    BANK_IMPERSONATION = 'bank_impersonation', 'Giả mạo ngân hàng'
    RECRUITMENT_SCAM = 'recruitment_scam', 'Lừa tuyển dụng'
    INVESTMENT_SCAM = 'investment_scam', 'Lừa đầu tư'
    DELIVERY_SCAM = 'delivery_scam', 'Giả mạo giao hàng'
    LOAN_SCAM = 'loan_scam', 'Lừa vay tiền'
    OTP_STEAL = 'otp_steal', 'Chiêu trò OTP/2FA'
    PHISHING = 'phishing', 'Phishing link'
    ROMANCE_SCAM = 'romance_scam', 'Lừa tình cảm'
    OTHER = 'other', 'Khác'


class Severity(models.TextChoices):
    LOW = 'low', 'Thấp'
    MEDIUM = 'medium', 'Trung bình'
    HIGH = 'high', 'Cao'
    CRITICAL = 'critical', 'Khẩn cấp'


class RiskLevel(models.TextChoices):
    SAFE = 'SAFE', 'An toàn'
    GREEN = 'GREEN', 'Xanh'
    YELLOW = 'YELLOW', 'Cảnh báo'
    RED = 'RED', 'Nguy hiểm'


class ReportStatus(models.TextChoices):
    PENDING = 'pending', 'Chờ duyệt'
    APPROVED = 'approved', 'Đã duyệt'
    REJECTED = 'rejected', 'Từ chối'


class ScanStatus(models.TextChoices):
    PENDING = 'pending', 'Đang chờ'
    PROCESSING = 'processing', 'Đang xử lý'
    COMPLETED = 'completed', 'Hoàn thành'
    FAILED = 'failed', 'Lỗi'


class ScanType(models.TextChoices):
    PHONE = 'phone', 'Số điện thoại'
    MESSAGE = 'message', 'Tin nhắn'
    DOMAIN = 'domain', 'Website/URL'
    ACCOUNT = 'account', 'Tài khoản ngân hàng'
    QR = 'qr', 'QR / Ảnh'
    EMAIL = 'email', 'Email'


class TargetType(models.TextChoices):
    PHONE = 'phone', 'Số điện thoại'
    DOMAIN = 'domain', 'Website/URL'
    ACCOUNT = 'account', 'Tài khoản ngân hàng'
    MESSAGE = 'message', 'Tin nhắn'
    QR = 'qr', 'QR Code'
    EMAIL = 'email', 'Email'


# ─── Domain Model ───────────────────────────────────────────────────────────

class Domain(models.Model):
    """Tracked domains (phishing / scam websites)"""
    domain_name = models.CharField(max_length=255, unique=True, db_index=True)
    risk_score = models.IntegerField(default=0, db_index=True,
                                     help_text='0-100 risk score')
    domain_age_days = models.IntegerField(null=True, blank=True)
    ssl_valid = models.BooleanField(default=False)
    whois_snapshot = models.JSONField(default=dict, blank=True)
    report_count = models.IntegerField(default=0)
    scam_type = models.CharField(max_length=30, choices=ScamType.choices,
                                 default=ScamType.PHISHING)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-risk_score', '-created_at']
        verbose_name = 'Domain'
        verbose_name_plural = 'Domains'

    def __str__(self):
        return f"{self.domain_name} (risk={self.risk_score})"


# ─── Bank Account Model ─────────────────────────────────────────────────────

class BankAccount(models.Model):
    """Tracked bank accounts reported as scam"""
    BANK_CHOICES = [
        ('Vietcombank', 'Vietcombank'), ('Techcombank', 'Techcombank'),
        ('BIDV', 'BIDV'), ('VietinBank', 'VietinBank'),
        ('Agribank', 'Agribank'), ('MBBank', 'MBBank'),
        ('ACB', 'ACB'), ('VPBank', 'VPBank'), ('TPBank', 'TPBank'),
        ('Sacombank', 'Sacombank'), ('HDBank', 'HDBank'), ('SHB', 'SHB'),
        ('MSB', 'MSB'), ('VIB', 'VIB'), ('OCB', 'OCB'),
        ('Momo', 'Ví Momo'), ('ZaloPay', 'ZaloPay'), ('VNPay', 'VNPay'),
        ('Other', 'Khác'),
    ]

    bank_name = models.CharField(max_length=50, choices=BANK_CHOICES, db_index=True)
    account_number_hash = models.CharField(max_length=64, db_index=True,
                                           help_text='SHA-256 hash of account number')
    account_number_masked = models.CharField(max_length=20, blank=True,
                                             help_text='Masked display, e.g. ***456789')
    risk_score = models.IntegerField(default=0, db_index=True)
    report_count = models.IntegerField(default=0)
    scam_type = models.CharField(max_length=30, choices=ScamType.choices,
                                 default=ScamType.OTHER)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-risk_score', '-created_at']
        unique_together = ['bank_name', 'account_number_hash']
        verbose_name = 'Bank Account'
        verbose_name_plural = 'Bank Accounts'

    def __str__(self):
        return f"{self.bank_name} {self.account_number_masked} (risk={self.risk_score})"

    @staticmethod
    def hash_account(account_number: str) -> str:
        return hashlib.sha256(account_number.strip().encode()).hexdigest()

    @staticmethod
    def mask_account(account_number: str) -> str:
        s = account_number.strip()
        if len(s) <= 4:
            return '***' + s
        return '***' + s[-4:]


# ─── Report Model ───────────────────────────────────────────────────────────

class Report(models.Model):
    """Community scam reports submitted by users"""
    reporter = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
                                 null=True, blank=True, related_name='reports')
    target_type = models.CharField(max_length=20, choices=TargetType.choices)
    target_value = models.CharField(max_length=500,
                                    help_text='Normalized: phone number, domain, account info')
    scam_type = models.CharField(max_length=30, choices=ScamType.choices)
    severity = models.CharField(max_length=10, choices=Severity.choices,
                                default=Severity.MEDIUM)
    description = models.TextField()
    evidence_file = models.ImageField(upload_to='reports/evidence/%Y/%m/',
                                      null=True, blank=True)
    
    # New Scammer details fields
    scammer_phone = models.CharField(max_length=20, blank=True)
    scammer_bank_account = models.CharField(max_length=50, blank=True)
    scammer_bank_name = models.CharField(max_length=100, blank=True)
    scammer_name = models.CharField(max_length=200, blank=True)
    status = models.CharField(max_length=10, choices=ReportStatus.choices,
                              default=ReportStatus.PENDING, db_index=True)
    moderator = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
                                  null=True, blank=True, related_name='moderated_reports')
    moderation_note = models.TextField(blank=True)
    scan_event = models.ForeignKey('ScanEvent', on_delete=models.SET_NULL, 
                                 null=True, blank=True, related_name='linked_reports')
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Report'
        verbose_name_plural = 'Reports'

    def __str__(self):
        return f"Report #{self.pk} [{self.target_type}] {self.target_value[:30]} ({self.status})"


# ─── Scan Event Model ───────────────────────────────────────────────────────

class ScanEvent(models.Model):
    """Every scan performed by users (history + analytics)"""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
                             null=True, blank=True, related_name='scans')
    scan_type = models.CharField(max_length=20, choices=ScanType.choices)
    raw_input = models.TextField(help_text='Original user input')
    normalized_input = models.CharField(max_length=500, blank=True, db_index=True)
    result_json = models.JSONField(default=dict, blank=True)
    risk_score = models.IntegerField(default=0, db_index=True)
    risk_level = models.CharField(max_length=10, choices=RiskLevel.choices,
                                  default=RiskLevel.SAFE)
    status = models.CharField(max_length=20, choices=ScanStatus.choices,
                              default=ScanStatus.COMPLETED, db_index=True)
    job_id = models.CharField(max_length=100, blank=True, null=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    
    # Email Security Fields (Enterprise Grade)
    sender_domain = models.CharField(max_length=255, blank=True, null=True)
    spf_status = models.CharField(max_length=50, blank=True, null=True)
    dkim_status = models.CharField(max_length=50, blank=True, null=True)
    dmarc_status = models.CharField(max_length=50, blank=True, null=True)
    detected_urls = models.JSONField(default=list, blank=True, help_text="List of URLs found in email/message")

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Scan Event'
        verbose_name_plural = 'Scan Events'

    def __str__(self):
        return f"Scan #{self.pk} [{self.scan_type}] {self.risk_level} at {self.created_at:%Y-%m-%d %H:%M}"


# ─── Trend Daily Model ──────────────────────────────────────────────────────

class TrendDaily(models.Model):
    """Pre-computed daily scam trend stats (for Scam Radar)"""
    date = models.DateField(db_index=True)
    region = models.CharField(max_length=50, default='VN', blank=True)
    scam_type = models.CharField(max_length=30, choices=ScamType.choices)
    count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-date']
        unique_together = ['date', 'region', 'scam_type']
        verbose_name = 'Trend Daily'
        verbose_name_plural = 'Trend Daily'

    def __str__(self):
        return f"{self.date} | {self.scam_type}: {self.count}"


# ─── Entity Link Model (Fraud Graph) ────────────────────────────────────────

class EntityLink(models.Model):
    """Links between entities for fraud graph / scam ring detection"""
    ENTITY_TYPE_CHOICES = [
        ('phone', 'Phone'), ('domain', 'Domain'), ('account', 'Account'),
    ]
    LINK_REASON_CHOICES = [
        ('shared_text', 'Shared text'), ('shared_report', 'Shared report'),
        ('shared_url', 'Shared URL'), ('ocr_match', 'OCR match'),
        ('manual', 'Manual'),
    ]

    from_type = models.CharField(max_length=10, choices=ENTITY_TYPE_CHOICES)
    from_entity_id = models.IntegerField()
    to_type = models.CharField(max_length=10, choices=ENTITY_TYPE_CHOICES)
    to_entity_id = models.IntegerField()
    link_reason = models.CharField(max_length=20, choices=LINK_REASON_CHOICES)
    confidence = models.FloatField(default=0.5,
                                   help_text='0.0 to 1.0 confidence')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['from_type', 'from_entity_id']),
            models.Index(fields=['to_type', 'to_entity_id']),
        ]
        verbose_name = 'Entity Link'
        verbose_name_plural = 'Entity Links'

    def __str__(self):
        return f"{self.from_type}:{self.from_entity_id} -> {self.to_type}:{self.to_entity_id}"


# ─── User Alert (Saved warnings) ────────────────────────────────────────────

class UserAlert(models.Model):
    """Saved alerts/bookmarks by users"""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                             related_name='alerts')
    target_type = models.CharField(max_length=20, choices=TargetType.choices)
    target_value = models.CharField(max_length=500)
    risk_level = models.CharField(max_length=10, choices=RiskLevel.choices,
                                  default=RiskLevel.YELLOW)
    note = models.CharField(max_length=500, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Alert: {self.target_type} {self.target_value[:30]}"


# ─── Forum Models (Community Scam Discussion) ──────────────────────────────

class ForumCategory(models.TextChoices):
    WARNING = 'warning', 'Cảnh báo'
    DISCUSSION = 'discussion', 'Thảo luận'
    EXPERIENCE = 'experience', 'Kinh nghiệm'
    QUESTION = 'question', 'Hỏi đáp'


class ForumPost(models.Model):
    """Community forum posts for scam discussions"""
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                               related_name='forum_posts')
    title = models.CharField(max_length=300)
    content = models.TextField()
    category = models.CharField(max_length=20, choices=ForumCategory.choices,
                                default=ForumCategory.DISCUSSION)
    image = models.ImageField(upload_to='forum_images/', null=True, blank=True)
    views_count = models.IntegerField(default=0)
    likes_count = models.IntegerField(default=0)
    helpful_count = models.IntegerField(default=0)
    shares_count = models.IntegerField(default=0)
    dislikes_count = models.IntegerField(default=0)
    reports_count = models.IntegerField(default=0)
    comments_count = models.IntegerField(default=0)
    is_pinned = models.BooleanField(default=False)
    is_locked = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-is_pinned', '-created_at']
        verbose_name = 'Forum Post'
        verbose_name_plural = 'Forum Posts'

    def __str__(self):
        return f"[{self.category}] {self.title[:50]}"


class ForumComment(models.Model):
    """Comments on forum posts"""
    post = models.ForeignKey(ForumPost, on_delete=models.CASCADE,
                             related_name='comments')
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                               related_name='forum_comments')
    parent = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='replies')
    content = models.TextField()
    likes_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']
        verbose_name = 'Forum Comment'
        verbose_name_plural = 'Forum Comments'

    def __str__(self):
        return f"Comment by {self.author} on {self.post.title[:30]}"


class ForumLike(models.Model):
    """Track user likes on forum posts (prevent duplicates)"""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    post = models.ForeignKey(ForumPost, on_delete=models.CASCADE,
                             related_name='likes')

    class Meta:
        unique_together = ['user', 'post']

    def __str__(self):
        return f"{self.user.username} liked {self.post.id}"

class ForumCommentLike(models.Model):
    """Track user likes on forum comments"""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    comment = models.ForeignKey(ForumComment, on_delete=models.CASCADE,
                                related_name='likes')

    class Meta:
        unique_together = ['user', 'comment']

    def __str__(self):
        return f"{self.user.username} liked comment {self.comment.id}"

class ForumReactionType(models.TextChoices):
    HELPFUL = 'helpful', 'Hữu ích'
    SHARE = 'share', 'Chia sẻ'
    DISLIKE = 'dislike', 'Không thích'

class ForumPostReaction(models.Model):
    """Specific reactions like Helpful or Shared"""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    post = models.ForeignKey(ForumPost, on_delete=models.CASCADE, related_name='reactions')
    reaction_type = models.CharField(max_length=10, choices=ForumReactionType.choices)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['user', 'post', 'reaction_type']

class ForumPostReport(models.Model):
    """Community reports for harmful/scam content"""
    class ReportStatus(models.TextChoices):
        PENDING = 'pending', 'Chờ xử lý'
        APPROVED = 'approved', 'Đã duyệt (Vi phạm)'
        REJECTED = 'rejected', 'Từ chối (Không vi phạm)'
        AI_FLAGGED = 'ai_flagged', 'AI gắn cờ'

    reporter = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    post = models.ForeignKey(ForumPost, on_delete=models.CASCADE, related_name='post_reports')
    reason = models.TextField()
    status = models.CharField(max_length=20, choices=ReportStatus.choices, default=ReportStatus.PENDING)
    ai_analysis = models.JSONField(default=dict, blank=True)
    is_resolved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

class ForumCommentReport(models.Model):
    """Community reports for harmful comments"""
    reporter = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    comment = models.ForeignKey(ForumComment, on_delete=models.CASCADE, related_name='comment_reports')
    reason = models.TextField()
    status = models.CharField(max_length=20, choices=ForumPostReport.ReportStatus.choices, default=ForumPostReport.ReportStatus.PENDING)
    ai_analysis = models.JSONField(default=dict, blank=True)
    is_resolved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

# ─── Article & Learn Model (Admin CMS) ──────────────────────────────────────

class ArticleCategory(models.TextChoices):
    NEWS = 'news', 'Tin tức'
    GUIDE = 'guide', 'Hướng dẫn'
    ALERT = 'alert', 'Cảnh báo mới'
    STORY = 'story', 'Chuyện cảnh giác'


class Article(models.Model):
    """Admin articles for educating users (CMS)"""
    title = models.CharField(max_length=300)
    slug = models.SlugField(max_length=350, unique=True, blank=True)
    content = models.TextField()
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    category = models.CharField(max_length=20, choices=ArticleCategory.choices, default=ArticleCategory.GUIDE)
    cover_image = models.ImageField(upload_to='articles/covers/', null=True, blank=True)
    is_published = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Article'
        verbose_name_plural = 'Articles'

    def __str__(self):
        return self.title

    def save(self, *args, **kwargs):
        if not self.slug:
            from django.utils.text import slugify
            self.slug = slugify(self.title)
        super().save(*args, **kwargs)

class LearnLesson(models.Model):
    """Educational lessons for users"""
    title = models.CharField(max_length=300)
    slug = models.SlugField(max_length=350, unique=True, blank=True)
    content = models.TextField()
    category = models.CharField(max_length=20, choices=ArticleCategory.choices, default=ArticleCategory.GUIDE)
    cover_image = models.ImageField(upload_to='learn/covers/', null=True, blank=True)
    is_published = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def save(self, *args, **kwargs):
        if not self.slug:
            from django.utils.text import slugify
            self.slug = slugify(self.title)
        super().save(*args, **kwargs)

class LearnQuiz(models.Model):
    """Quizzes attached to lessons"""
    lesson = models.ForeignKey(LearnLesson, on_delete=models.CASCADE, related_name='quizzes', null=True, blank=True)
    article = models.ForeignKey(Article, on_delete=models.CASCADE, related_name='quizzes', null=True, blank=True)
    question = models.TextField()
    options = models.JSONField(help_text="List of choices")
    correct_answer = models.CharField(max_length=200)
    explanation = models.TextField(blank=True)

class LearnScenario(models.Model):
    """Interactive scam scenarios"""
    title = models.CharField(max_length=300)
    article = models.ForeignKey(Article, on_delete=models.CASCADE, related_name='scenarios', null=True, blank=True)
    description = models.TextField()
    content = models.JSONField(help_text="Scenario flow logic")
    created_at = models.DateTimeField(auto_now_add=True)

# ─── Prestige Calculation & Signals ────────────────────────────────────────

def update_user_prestige(user):
    """Recalculate user rank points based on activity"""
    try:
        profile = user.profile
        points = 0
        
        # 1. Activities by the user
        points += ForumPost.objects.filter(author=user).count() * 10
        points += ForumComment.objects.filter(author=user).count() * 5
        
        # 2. Reactions received on their posts
        post_likes = ForumLike.objects.filter(post__author=user).count()
        helpful_count = ForumPostReaction.objects.filter(post__author=user, reaction_type=ForumReactionType.HELPFUL).count()
        share_count = ForumPostReaction.objects.filter(post__author=user, reaction_type=ForumReactionType.SHARE).count()
        dislike_count = ForumPostReaction.objects.filter(post__author=user, reaction_type=ForumReactionType.DISLIKE).count()
        
        # 3. Likes received on comments
        comment_likes = ForumCommentLike.objects.filter(comment__author=user).count()
        
        # 4. Community contributions (Reporting valid scams - we give small points for reporting)
        reports_made = ForumPostReport.objects.filter(reporter=user).count()
        
        # 5. Post reports received (ONLY approved ones)
        report_count = ForumPostReport.objects.filter(post__author=user, status='approved').count()
        
        points += (post_likes * 2)
        points += (helpful_count * 2)
        points += (share_count * 2)
        points += (comment_likes * 2)
        points += (reports_made * 5) # Reward for reporting
        points += (dislike_count * -5)
        points += (report_count * -50) # Heavy penalty for approved violations

        profile.rank_points = max(0, points)
        profile.save(update_fields=['rank_points'])
    except Exception as e:
        print(f"Prestige update error: {e}")

@receiver([post_save, post_delete], sender=ForumPost)
@receiver([post_save, post_delete], sender=ForumComment)
@receiver([post_save, post_delete], sender=ForumLike)
@receiver([post_save, post_delete], sender=ForumCommentLike)
@receiver([post_save, post_delete], sender=ForumPostReaction)
@receiver([post_save, post_delete], sender=ForumPostReport)
def trigger_prestige_update(sender, instance, **kwargs):
    if hasattr(instance, 'author'):
        update_user_prestige(instance.author)
    elif hasattr(instance, 'post'): # For reactions and reports
        update_user_prestige(instance.post.author)
    elif hasattr(instance, 'reporter'): # For reports
        update_user_prestige(instance.reporter)
        if instance.post: update_user_prestige(instance.post.author)


@receiver([post_save, post_delete], sender=Article)
@receiver([post_save, post_delete], sender=LearnQuiz)
@receiver([post_save, post_delete], sender=LearnScenario)
@receiver([post_save, post_delete], sender=LearnLesson)
def sync_vector_db(sender, instance, **kwargs):
    """
    Automatically re-build the FAISS index when learning content changes via Celery.
    """
    from api.maintenance.tasks import rebuild_vector_index
    try:
        rebuild_vector_index.delay(trigger='AUTO')
        logger.info(f"Vector DB sync task queued by {sender.__name__} update.")
    except Exception as e:
        logger.error(f"Vector DB auto-sync error: {e}")
