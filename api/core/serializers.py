"""
ShieldCall VN – Core Serializers
DRF serializers for all MVP models + auth
"""
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from .models import (
    Domain, BankAccount, Report, ScanEvent, TrendDaily,
    EntityLink, UserAlert, ScamType, Severity, TargetType, ScanType,
    ForumPost, ForumComment, ForumLike, UserProfile,
)

User = get_user_model()


# ─── Auth Serializers ────────────────────────────────────────────────────────

class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=8)
    password2 = serializers.CharField(write_only=True, min_length=8)
    first_name = serializers.CharField(max_length=150, required=False, default='')
    last_name = serializers.CharField(max_length=150, required=False, default='')

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError('Email đã được sử dụng.')
        return value.lower()

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({'password2': 'Mật khẩu xác nhận không khớp.'})
        validate_password(attrs['password'])
        return attrs

    def create(self, validated_data):
        validated_data.pop('password2')
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
    class Meta:
        model = UserProfile
        fields = ['avatar', 'bio']

class UserSerializer(serializers.ModelSerializer):
    avatar = serializers.ImageField(source='profile.avatar', read_only=True)
    
    class Meta:
        model = User
        fields = ['id', 'email', 'username', 'first_name', 'last_name', 'date_joined', 'is_staff', 'avatar']
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
                  'description', 'evidence_file']

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
                  'created_at']

    def get_reporter_email(self, obj):
        if obj.reporter:
            return obj.reporter.email
        return 'Ẩn danh'


class ReportModerateSerializer(serializers.Serializer):
    action = serializers.ChoiceField(choices=['approve', 'reject'])
    note = serializers.CharField(required=False, default='')


# ─── Scan Event Serializers ─────────────────────────────────────────────────

class ScanPhoneSerializer(serializers.Serializer):
    phone = serializers.CharField(max_length=20)


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
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)
# ─── Forum Serializers ───────────────────────────────────────────────────────

class ForumCommentSerializer(serializers.ModelSerializer):
    author_name = serializers.CharField(source='author.username', read_only=True)
    replies = serializers.SerializerMethodField()

    class Meta:
        model = ForumComment
        fields = ['id', 'author_name', 'content', 'parent', 'replies', 'created_at']
        read_only_fields = ['id', 'author_name', 'created_at']

    def get_replies(self, obj):
        if obj.replies.exists():
            return ForumCommentSerializer(obj.replies.filter(parent=obj), many=True).data # parent=obj is redundant but safe
        return []

class ForumPostSerializer(serializers.ModelSerializer):
    author_name = serializers.CharField(source='author.username', read_only=True)
    comments = serializers.SerializerMethodField()
    user_liked = serializers.SerializerMethodField()

    class Meta:
        model = ForumPost
        fields = ['id', 'author_name', 'title', 'content', 'category', 'image', 
                  'views_count', 'likes_count', 'comments_count', 'is_pinned', 
                  'user_liked', 'comments', 'created_at']
        read_only_fields = ['id', 'author_name', 'views_count', 'likes_count', 
                            'comments_count', 'created_at']

    def get_comments(self, obj):
        # Only return top-level comments
        comments = obj.comments.filter(parent__isnull=True)
        return ForumCommentSerializer(comments, many=True).data

    def get_user_liked(self, obj):
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return obj.likes.filter(user=request.user).exists()
        return False
