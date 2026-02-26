"""ShieldCall VN – Forum Views"""
import re
import hashlib
import logging
import json
from urllib.parse import urlparse
from api.utils.security import verify_turnstile_token

from django.contrib.auth import authenticate, get_user_model
from django.db.models import Count, Sum, F, Q
from django.utils import timezone
from datetime import timedelta

from django.http import StreamingHttpResponse
from rest_framework import status, permissions, generics
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token

from api.utils.ollama_client import analyze_text_for_scam, generate_response, stream_response

from api.core.models import (
    Domain, BankAccount, Report, ScanEvent, TrendDaily,
    EntityLink, UserAlert, ScamType, RiskLevel, ReportStatus,
)
from api.core.serializers import (
    RegisterSerializer, LoginSerializer, UserSerializer,
    DomainSerializer, BankAccountSerializer,
    ReportCreateSerializer, ReportListSerializer, ReportModerateSerializer,
    ScanPhoneSerializer, ScanMessageSerializer, ScanDomainSerializer,
    ScanAccountSerializer, ScanImageSerializer, ScanEventListSerializer,
    TrendDailySerializer, TrendHotSerializer, UserAlertSerializer,
)

User = get_user_model()
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# FORUM APIs
# ═══════════════════════════════════════════════════════════════════════════

from api.core.models import ForumPost, ForumComment, ForumLike, ForumCommentLike, ForumPostReaction, ForumPostReport, ForumCommentReport, ForumReactionType
from api.core.serializers import ForumPostSerializer, ForumCommentSerializer, ForumPostReportSerializer, ForumCommentReportSerializer

class ForumPostListCreateView(APIView):
    """GET /api/forum/posts/ — list, POST — create"""

    def get_permissions(self):
        if self.request.method == 'POST':
            return [IsAuthenticated()]
        return [AllowAny()]

    def get(self, request):
        category = request.query_params.get('category')
        posts = ForumPost.objects.select_related('author').order_by('-is_pinned', '-created_at')
        if category:
            posts = posts.filter(category=category)
        
        posts = posts[:50]
        serializer = ForumPostSerializer(posts, many=True, context={'request': request})
        return Response(serializer.data)

    def post(self, request):
        # Turnstile Verification
        cf_token = request.data.get('cf-turnstile-response')
        if not verify_turnstile_token(cf_token):
             return Response({'error': 'Xác minh anti-spam không lệ. Vui lòng thử lại.'}, status=400)

        serializer = ForumPostSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        post = serializer.save(author=request.user)
        return Response(ForumPostSerializer(post, context={'request': request}).data, status=201)


class ForumPostDetailView(APIView):
    """GET /api/forum/posts/<id>/ — detail with comments"""
    permission_classes = [AllowAny]

    def get(self, request, post_id):
        try:
            post = ForumPost.objects.select_related('author').get(id=post_id)
        except ForumPost.DoesNotExist:
            return Response({'error': 'Bài viết không tồn tại'}, status=404)

        # Increment views
        ForumPost.objects.filter(id=post_id).update(views_count=F('views_count') + 1)
        post.refresh_from_db()

        serializer = ForumPostSerializer(post, context={'request': request})
        return Response(serializer.data)


class ForumPostCommentView(APIView):
    """POST /api/forum/posts/<id>/comment/"""
    permission_classes = [IsAuthenticated]

    def post(self, request, post_id):
        try:
            post = ForumPost.objects.get(id=post_id)
            if post.is_locked:
                return Response({'error': 'Bài viết này đã bị khóa, không thể bình luận.'}, status=403)
        except ForumPost.DoesNotExist:
            return Response({'error': 'Bài viết không tồn tại'}, status=404)

        # Turnstile Verification
        cf_token = request.data.get('cf-turnstile-response')
        if not verify_turnstile_token(cf_token):
             return Response({'error': 'Xác minh anti-spam không lệ. Vui lòng thử lại.'}, status=400)

        serializer = ForumCommentSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        comment = serializer.save(author=request.user, post=post)

        # Update post comment count
        ForumPost.objects.filter(id=post_id).update(comments_count=F('comments_count') + 1)

        return Response(ForumCommentSerializer(comment, context={'request': request}).data, status=201)

class ForumCommentLikeView(APIView):
    """POST /api/forum/comments/<id>/like/ — toggle like"""
    permission_classes = [IsAuthenticated]

    def post(self, request, comment_id):
        try:
            comment = ForumComment.objects.get(id=comment_id)
        except ForumComment.DoesNotExist:
            return Response({'error': 'Bình luận không tồn tại'}, status=404)

        like, created = ForumCommentLike.objects.get_or_create(user=request.user, comment=comment)
        if not created:
            like.delete()
            ForumComment.objects.filter(id=comment_id).update(likes_count=F('likes_count') - 1)
            action = 'unliked'
        else:
            ForumComment.objects.filter(id=comment_id).update(likes_count=F('likes_count') + 1)
            action = 'liked'
        
        comment.refresh_from_db()
        return Response({
            'action': action,
            'likes_count': comment.likes_count,
            'liked': created
        })


class ForumPostLikeView(APIView):
    """POST /api/forum/posts/<id>/like/ — toggle like"""
    permission_classes = [IsAuthenticated]

    def post(self, request, post_id):
        try:
            post = ForumPost.objects.get(id=post_id)
        except ForumPost.DoesNotExist:
            return Response({'error': 'Bài viết không tồn tại'}, status=404)

        like, created = ForumLike.objects.get_or_create(user=request.user, post=post)
        if not created:
            like.delete()
            ForumPost.objects.filter(id=post_id).update(likes_count=F('likes_count') - 1)
            action = 'unliked'
        else:
            ForumPost.objects.filter(id=post_id).update(likes_count=F('likes_count') + 1)
            action = 'liked'
        
        post.refresh_from_db()
        return Response({
            'action': action,
            'likes_count': post.likes_count,
            'liked': created
        })

class ForumPostReactionView(APIView):
    """POST /api/forum/posts/<id>/reaction/ — reaction_type: helpful, share"""
    permission_classes = [IsAuthenticated]

    def post(self, request, post_id):
        rtype = request.data.get('reaction_type')
        if rtype not in [ForumReactionType.HELPFUL, ForumReactionType.SHARE, ForumReactionType.DISLIKE]:
            return Response({'error': 'Loại tương tác không hợp lệ'}, status=400)

        try:
            post = ForumPost.objects.get(id=post_id)
        except ForumPost.DoesNotExist:
            return Response({'error': 'Bài viết không tồn tại'}, status=404)

        reaction, created = ForumPostReaction.objects.get_or_create(
            user=request.user, post=post, reaction_type=rtype
        )

        if not created:
            reaction.delete()
            if rtype == ForumReactionType.HELPFUL:
                ForumPost.objects.filter(id=post_id).update(helpful_count=F('helpful_count') - 1)
            elif rtype == ForumReactionType.SHARE:
                ForumPost.objects.filter(id=post_id).update(shares_count=F('shares_count') - 1)
            else:
                ForumPost.objects.filter(id=post_id).update(dislikes_count=F('dislikes_count') - 1)
            action = 'removed'
        else:
            if rtype == ForumReactionType.HELPFUL:
                ForumPost.objects.filter(id=post_id).update(helpful_count=F('helpful_count') + 1)
            elif rtype == ForumReactionType.SHARE:
                ForumPost.objects.filter(id=post_id).update(shares_count=F('shares_count') + 1)
            else:
                ForumPost.objects.filter(id=post_id).update(dislikes_count=F('dislikes_count') + 1)
            action = 'added'

        post.refresh_from_db()
        return Response({
            'action': action,
            'helpful_count': post.helpful_count,
            'shares_count': post.shares_count,
            'dislikes_count': post.dislikes_count,
            'reacted': created
        })

class ForumPostReportView(APIView):
    """POST /api/forum/posts/<id>/report/"""
    permission_classes = [IsAuthenticated]

    def post(self, request, post_id):
        reason = request.data.get('reason')
        if not reason:
            return Response({'error': 'Vui lòng cung cấp lý do báo cáo'}, status=400)

        try:
            post = ForumPost.objects.get(id=post_id)
        except ForumPost.DoesNotExist:
            return Response({'error': 'Bài viết không tồn tại'}, status=404)

        # Create report
        report = ForumPostReport.objects.create(
            reporter=request.user,
            post=post,
            reason=reason
        )

        # Increment report count
        ForumPost.objects.filter(id=post_id).update(reports_count=F('reports_count') + 1)

        # Trigger AI analysis task (Import here to avoid circulars)
        try:
            from api.core.tasks import process_forum_report
            process_forum_report.delay(report.id)
        except Exception as e:
            logger.error(f"Failed to trigger AI report task: {e}")

        return Response({'message': 'Báo cáo của bạn đã được gửi. AI đang tiến hành phân tích nội dung. Cảm ơn bạn!'}, status=201)

class ForumCommentReportView(APIView):
    """POST /api/forum/comments/<id>/report/"""
    permission_classes = [IsAuthenticated]

    def post(self, request, comment_id):
        reason = request.data.get('reason')
        if not reason:
            return Response({'error': 'Vui lòng cung cấp lý do báo cáo'}, status=400)

        try:
            comment = ForumComment.objects.select_related('post').get(id=comment_id)
        except ForumComment.DoesNotExist:
            return Response({'error': 'Bình luận không tồn tại'}, status=404)

        if comment.post.is_locked:
            return Response({'error': 'Không thể báo cáo bình luận trong bài viết đã bị khóa.'}, status=403)

        # Create report
        report = ForumCommentReport.objects.create(
            reporter=request.user,
            comment=comment,
            reason=reason
        )

        # Trigger AI analysis task
        try:
            from api.core.tasks import process_forum_comment_report
            process_forum_comment_report.delay(report.id)
        except Exception as e:
            logger.error(f"Failed to trigger AI comment report task: {e}")

        return Response({'message': 'Báo cáo bình luận đã được gửi. AI đang phân tích nội dung.'}, status=201)
