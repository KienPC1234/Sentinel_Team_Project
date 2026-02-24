"""
ShieldCall VN – Core Serializers
DRF serializers for all MVP models + auth
"""
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from api.utils.normalization import normalize_phone_e164
from .models import (
    Domain, BankAccount, Report, ScanEvent, TrendDaily,
    EntityLink, UserAlert, ScamType, Severity, TargetType, ScanType,
    ForumPost, ForumComment, ForumLike, ForumPostReaction, ForumPostReport, 
    ForumCommentReport, ForumReactionType, UserProfile,
    LearnLesson, LearnQuiz, LearnScenario,
)

User = get_user_model()


# ─── Auth Serializers ────────────────────────────────────────────────────────

class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=8)
    first_name = serializers.CharField(max_length=150, required=False, default='')
    last_name = serializers.CharField(max_length=150, required=False, default='')

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError('Email đã được sử dụng.')
        return value.lower()

    def validate(self, attrs):
        validate_password(attrs['password'])
        return attrs

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['email'],
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
        )
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class UserProfileSerializer(serializers.ModelSerializer):
    rank_info = serializers.ReadOnlyField()
    messenger_link = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    
    class Meta:
        model = UserProfile
        fields = ['display_name', 'avatar', 'bio', 'about', 'messenger_link', 'rank_points', 'rank_info']
        read_only_fields = ['rank_points', 'rank_info']
        extra_kwargs = {
            'avatar': {'required': False, 'allow_null': True},
            'display_name': {'required': False, 'allow_blank': True},
        }

class UserSerializer(serializers.ModelSerializer):
    display_name = serializers.CharField(source='profile.display_name', read_only=True)
    avatar = serializers.ImageField(source='profile.avatar', read_only=True)
    rank_info = serializers.ReadOnlyField(source='profile.rank_info')
    about = serializers.CharField(source='profile.about', read_only=True)
    messenger_link = serializers.URLField(source='profile.messenger_link', read_only=True)
    
    class Meta:
        model = User
        fields = ['id', 'email', 'username', 'first_name', 'last_name', 'display_name', 'date_joined', 'is_staff', 'avatar', 'rank_info', 'about', 'messenger_link']
        read_only_fields = fields


# ─── Domain Serializer ──────────────────────────────────────────────────────

class DomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = Domain
        fields = '__all__'
        read_only_fields = ['created_at', 'updated_at']


# ─── Bank Account Serializer ────────────────────────────────────────────────

class BankAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = BankAccount
        fields = ['id', 'bank_name', 'account_number_masked', 'risk_score',
                  'report_count', 'scam_type', 'created_at']
        read_only_fields = fields


# ─── Report Serializers ─────────────────────────────────────────────────────

class ReportCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Report
        fields = ['target_type', 'target_value', 'scam_type', 'severity',
                  'description', 'evidence_file', 'scammer_phone', 
                  'scammer_bank_account', 'scammer_bank_name', 'scammer_name',
                  'ocr_text', 'ai_analysis']

    def validate(self, attrs):
        target_type = attrs.get('target_type')
        target_value = attrs.get('target_value')

        if target_type == 'phone':
            try:
                attrs['target_value'] = normalize_phone_e164(target_value, strict=True)
            except ValueError:
                raise serializers.ValidationError({
                    'target_value': 'Số điện thoại báo cáo phải có mã quốc gia, ví dụ +84xxxxxxxxx hoặc +1xxxxxxxxxx.'
                })

        return attrs

    def create(self, validated_data):
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            validated_data['reporter'] = request.user
        return super().create(validated_data)


class ReportListSerializer(serializers.ModelSerializer):
    reporter_email = serializers.SerializerMethodField()

    class Meta:
        model = Report
        fields = ['id', 'target_type', 'target_value', 'scam_type', 'severity',
                  'description', 'status', 'reporter_email', 'moderation_note',
                  'ocr_text', 'ai_analysis', 'created_at']

    def get_reporter_email(self, obj):
        if obj.reporter:
            # Mask reporter email for public list
            email = obj.reporter.email
            try:
                username, domain = email.split('@')
                return f"{username[:3]}***@{domain}"
            except:
                return "User"
        return 'Ẩn danh'

class ReportEvidenceSerializer(serializers.ModelSerializer):
    url = serializers.SerializerMethodField()
    class Meta:
        from api.core.models import ReportEvidence
        model = ReportEvidence
        fields = ['id', 'url', 'caption', 'created_at']
    def get_url(self, obj):
        return obj.image.url if obj.image else None


class ReportDetailSerializer(serializers.ModelSerializer):
    reporter_email = serializers.SerializerMethodField()
    scammer_info = serializers.SerializerMethodField()
    evidence_url = serializers.SerializerMethodField()
    evidence_images_data = ReportEvidenceSerializer(source='evidence_images', many=True, read_only=True)
    scam_type_display = serializers.CharField(source='get_scam_type_display', read_only=True)

    class Meta:
        model = Report
        fields = ['id', 'target_type', 'target_value', 'scam_type', 'scam_type_display', 'severity',
                  'description', 'status', 'created_at', 'reporter_email',
                  'scammer_name', 'scammer_phone', 'scammer_bank_account', 'scammer_bank_name',
                  'evidence_file', 'evidence_url', 'evidence_images_data', 'ocr_text', 'ai_analysis', 'moderation_note']

    def get_reporter_email(self, obj):
        if obj.reporter:
            email = obj.reporter.email
            try:
                username, domain = email.split('@')
                return f"{username[:3]}***@{domain}"
            except:
                return "User"
        return 'Ẩn danh'

    def get_scammer_info(self, obj):
        return {
            "name": obj.scammer_name,
            "phone": obj.scammer_phone,
            "bank_account": obj.scammer_bank_account, 
            "bank_name": obj.scammer_bank_name
        }

    def get_evidence_url(self, obj):
        if obj.evidence_file:
            return obj.evidence_file.url
        return None


class ReportModerateSerializer(serializers.Serializer):
    action = serializers.ChoiceField(choices=['approve', 'reject'])
    note = serializers.CharField(required=False, default='')


# ─── Scan Event Serializers ─────────────────────────────────────────────────

class ScanFileSerializer(serializers.Serializer):
    file = serializers.FileField()


class ScanAudioSerializer(serializers.Serializer):
    """Serializer for audio scan upload."""
    audio = serializers.FileField()


class ScanPhoneSerializer(serializers.Serializer):
    phone = serializers.CharField(max_length=20)

    def validate_phone(self, value):
        try:
            normalized = normalize_phone_e164(value, strict=False)
        except ValueError:
            raise serializers.ValidationError(
                'Số điện thoại không hợp lệ. '
                'Hỗ trợ: +84xxxxxxxxx, 0xxxxxxxxx (VN), +1xxxxxxxxxx...'
            )
        return normalized


class ScanMessageSerializer(serializers.Serializer):
    message = serializers.CharField(required=False, allow_blank=True)

    def validate(self, attrs):
        # We check request.FILES in the view for multi-image
        if not attrs.get('message') and not self.initial_data.get('image') and not self.initial_data.get('images'):
            raise serializers.ValidationError('Vui lòng nhập tin nhắn hoặc upload ảnh.')
        return attrs


class ScanDomainSerializer(serializers.Serializer):
    url = serializers.CharField(max_length=2000)
    deep_scan = serializers.BooleanField(default=False, required=False)


class ScanEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()
    content = serializers.CharField(required=False, allow_blank=True)


class ScanAccountSerializer(serializers.Serializer):
    bank = serializers.CharField(max_length=50)
    account = serializers.CharField(max_length=50)


class ScanImageSerializer(serializers.Serializer):
    # Empty because we handle FILES.getlist in view
    pass


class ScanEventListSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanEvent
        fields = ['id', 'scan_type', 'normalized_input', 'risk_score',
                  'risk_level', 'result_json', 'created_at']
        read_only_fields = fields


# ─── Trend Serializers ──────────────────────────────────────────────────────

class TrendDailySerializer(serializers.ModelSerializer):
    class Meta:
        model = TrendDaily
        fields = '__all__'


class TrendHotSerializer(serializers.Serializer):
    """Hot numbers / entities with rising risk"""
    target_type = serializers.CharField()
    target_value = serializers.CharField()
    report_count = serializers.IntegerField()
    risk_change = serializers.IntegerField()
    scam_type = serializers.CharField()


# ─── User Alert Serializer ──────────────────────────────────────────────────

class UserAlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserAlert
        fields = ['id', 'target_type', 'target_value', 'risk_level', 'note', 'created_at']
        read_only_fields = ['id', 'created_at']

    def create(self, validated_data):
        request = self.context.get('request')
        if request:
            validated_data['user'] = request.user
        return super().create(validated_data)
# ─── Forum Serializers ───────────────────────────────────────────────────────

class ForumCommentSerializer(serializers.ModelSerializer):
    author_name = serializers.SerializerMethodField()
    author_username = serializers.CharField(source='author.username', read_only=True)
    author_avatar = serializers.ImageField(source='author.profile.avatar', read_only=True)
    author_is_staff = serializers.BooleanField(source='author.is_staff', read_only=True)
    author_rank = serializers.SerializerMethodField()
    author_posts_count = serializers.SerializerMethodField()
    author_joined = serializers.SerializerMethodField()
    parent_author_name = serializers.SerializerMethodField()
    user_liked = serializers.SerializerMethodField()
    user_disliked = serializers.SerializerMethodField()
    user_helpful = serializers.SerializerMethodField()
    replies = serializers.SerializerMethodField()

    class Meta:
        model = ForumComment
        fields = ['id', 'author_name', 'author_username', 'author_avatar', 'author_is_staff', 'author_rank', 'author_posts_count', 'author_joined',
                  'content', 'parent', 'parent_author_name', 
                  'replies', 'likes_count', 'dislikes_count', 'helpful_count', 'user_liked', 'user_disliked', 'user_helpful', 'created_at']
        read_only_fields = ['id', 'author_name', 'author_username', 'author_avatar', 'author_is_staff', 'author_rank', 'author_posts_count', 'author_joined',
                            'created_at', 'parent_author_name', 'likes_count', 'dislikes_count', 'helpful_count']

    def get_author_name(self, obj):
        return obj.author.profile.display_name or obj.author.username

    def get_author_rank(self, obj):
        return obj.author.profile.rank_info

    def get_author_posts_count(self, obj):
        return obj.author.forum_posts.count()

    def get_author_joined(self, obj):
        return obj.author.date_joined.strftime('%d/%m/%Y')

    def get_parent_author_name(self, obj):
        if obj.parent:
            return obj.parent.author.profile.display_name or obj.parent.author.username
        return None

    def get_replies(self, obj):
        if obj.replies.exists():
            return ForumCommentSerializer(obj.replies.filter(parent=obj), many=True, context=self.context).data 
        return []

    def get_user_liked(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        return obj.likes.filter(user=request.user).exists()

    def get_user_disliked(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        from api.core.models import ForumCommentReaction
        return ForumCommentReaction.objects.filter(
            comment=obj, user=request.user, reaction_type='downvote'
        ).exists()

    def get_user_helpful(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        from api.core.models import ForumCommentReaction
        return ForumCommentReaction.objects.filter(
            comment=obj, user=request.user, reaction_type='helpful'
        ).exists()

class ForumPostSerializer(serializers.ModelSerializer):
    author_name = serializers.SerializerMethodField()
    author_username = serializers.CharField(source='author.username', read_only=True)
    author_is_staff = serializers.BooleanField(source='author.is_staff', read_only=True)
    author_avatar = serializers.ImageField(source='author.profile.avatar', read_only=True)
    author_rank = serializers.SerializerMethodField()
    author_posts_count = serializers.SerializerMethodField()
    author_comments_count = serializers.SerializerMethodField()
    author_joined = serializers.SerializerMethodField()
    comments = serializers.SerializerMethodField()
    user_liked = serializers.SerializerMethodField()
    user_helpful = serializers.SerializerMethodField()
    user_shared = serializers.SerializerMethodField()
    user_disliked = serializers.SerializerMethodField()
    unique_views_count = serializers.SerializerMethodField()
    last_comment_author = serializers.SerializerMethodField()
    last_comment_at = serializers.SerializerMethodField()

    class Meta:
        model = ForumPost
        fields = ['id', 'author_name', 'author_username', 'author_is_staff', 'author_avatar',
                  'author_rank', 'author_posts_count', 'author_comments_count', 'author_joined',
                  'title', 'content', 'category', 'image', 
                  'views_count', 'unique_views_count', 'likes_count', 'helpful_count', 'shares_count', 'dislikes_count', 'reports_count',
                  'comments_count', 'is_pinned', 'is_locked', 'user_liked', 'user_helpful', 'user_shared', 'user_disliked',
                  'comments', 'last_comment_author', 'last_comment_at', 'created_at']
        read_only_fields = ['id', 'author_name', 'author_username', 'author_is_staff', 'author_avatar',
                            'author_rank', 'author_posts_count', 'author_comments_count', 'author_joined',
                            'views_count', 'unique_views_count',
                            'likes_count', 'helpful_count', 'shares_count', 'dislikes_count', 'reports_count',
                            'comments_count', 'last_comment_author', 'last_comment_at', 'created_at']

    def get_comments(self, obj):
        # Only return top-level comments
        comments = obj.comments.filter(parent__isnull=True)
        return ForumCommentSerializer(comments, many=True, context=self.context).data

    def get_author_name(self, obj):
        return obj.author.profile.display_name or obj.author.username

    def get_author_rank(self, obj):
        return obj.author.profile.rank_info

    def get_author_posts_count(self, obj):
        return obj.author.forum_posts.count()

    def get_author_comments_count(self, obj):
        return obj.author.forum_comments.count()

    def get_author_joined(self, obj):
        return obj.author.date_joined.strftime('%d/%m/%Y')

    def get_last_comment_author(self, obj):
        last = obj.comments.order_by('-created_at').select_related('author', 'author__profile').first()
        if last:
            return {
                'name': last.author.profile.display_name or last.author.username,
                'username': last.author.username,
                'avatar': last.author.profile.avatar.url if last.author.profile.avatar else None,
            }
        return None

    def get_last_comment_at(self, obj):
        last = obj.comments.order_by('-created_at').first()
        return last.created_at.isoformat() if last else None

    def get_unique_views_count(self, obj):
        from api.core.models import ForumPostView
        return ForumPostView.objects.filter(post=obj).count()

    def get_user_liked(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        return ForumLike.objects.filter(post=obj, user=request.user).exists()

    def get_user_helpful(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        return ForumPostReaction.objects.filter(post=obj, user=request.user, reaction_type=ForumReactionType.HELPFUL).exists()

    def get_user_shared(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        return ForumPostReaction.objects.filter(post=obj, user=request.user, reaction_type=ForumReactionType.SHARE).exists()

    def get_user_disliked(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        return ForumPostReaction.objects.filter(post=obj, user=request.user, reaction_type=ForumReactionType.DISLIKE).exists()

class ForumPostReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = ForumPostReport
        fields = ['id', 'post', 'reason', 'status', 'ai_analysis', 'is_resolved', 'created_at']
        read_only_fields = ['id', 'status', 'ai_analysis', 'is_resolved', 'created_at']

class ForumCommentReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = ForumCommentReport
        fields = ['id', 'comment', 'reason', 'status', 'ai_analysis', 'is_resolved', 'created_at']
        read_only_fields = ['id', 'status', 'ai_analysis', 'is_resolved', 'created_at']

class LearnLessonSerializer(serializers.ModelSerializer):
    class Meta:
        model = LearnLesson
        fields = '__all__'

class LearnQuizSerializer(serializers.ModelSerializer):
    class Meta:
        model = LearnQuiz
        fields = '__all__'

class LearnScenarioSerializer(serializers.ModelSerializer):
    class Meta:
        model = LearnScenario
        fields = '__all__'
