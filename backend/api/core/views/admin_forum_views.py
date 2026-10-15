"""ShieldCall VN – Admin Forum moderation API.

Các endpoint phục vụ trang Admin/forum_management.html:
    GET    /api/v1/admin/forum/reports/                    danh sách báo cáo bài viết
    POST   /api/v1/admin/forum/reports/<id>/action/        {action: approve|reject}
    GET    /api/v1/admin/forum/comment-reports/            danh sách báo cáo bình luận
    POST   /api/v1/admin/forum/comment-reports/<id>/action/
    GET    /api/v1/admin/forum/bans/                       danh sách cấm
    POST   /api/v1/admin/forum/ban/                        {user_id, reason, ban_type, days}
                                                           hoặc {ban_id, action: unban}
"""
from datetime import timedelta

from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_spectacular.utils import extend_schema

from api.core.models import (
    ForumPostReport,
    ForumCommentReport,
    ForumBan,
)


def _user_brief(user):
    if not user:
        return None
    return {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'is_staff': getattr(user, 'is_staff', False),
    }


def _post_report_row(r):
    return {
        'id': r.id,
        'post_id': r.post_id,
        'post_title': r.post.title,
        'post_author': r.post.author.username if r.post.author else '',
        'reporter': _user_brief(r.reporter),
        'reason': r.reason,
        'status': r.status,
        'is_resolved': r.is_resolved,
        'created_at': r.created_at.strftime('%d/%m/%Y %H:%M'),
    }


def _comment_report_row(r):
    return {
        'id': r.id,
        'comment_id': r.comment_id,
        'comment_content': r.comment.content,
        'comment_author': r.comment.author.username if r.comment.author else '',
        'post_id': r.comment.post_id,
        'post_title': r.comment.post.title,
        'reporter': _user_brief(r.reporter),
        'reason': r.reason,
        'status': r.status,
        'is_resolved': r.is_resolved,
        'created_at': r.created_at.strftime('%d/%m/%Y %H:%M'),
    }


class AdminForumReportsView(APIView):
    """GET /api/v1/admin/forum/reports/ — báo cáo bài viết (?status=pending|approved|rejected|all)"""
    permission_classes = [IsAdminUser]

    @extend_schema(responses={200: list})
    def get(self, request):
        status_f = request.query_params.get('status', 'pending')
        qs = ForumPostReport.objects.select_related('post', 'post__author', 'reporter')
        if status_f and status_f != 'all':
            qs = qs.filter(status=status_f)
        return Response([_post_report_row(r) for r in qs[:200]])


class AdminForumReportActionView(APIView):
    """POST /api/v1/admin/forum/reports/<int:report_id>/action/"""
    permission_classes = [IsAdminUser]

    def post(self, request, report_id):
        try:
            r = ForumPostReport.objects.select_related('post').get(id=report_id)
        except ForumPostReport.DoesNotExist:
            return Response({'error': 'Báo cáo không tồn tại.'}, status=status.HTTP_404_NOT_FOUND)

        action = request.data.get('action')
        if action == 'approve':
            r.status = ForumPostReport.ReportStatus.APPROVED
            r.is_resolved = True
            # Khóa bài viết bị duyệt vi phạm + đồng bộ số báo cáo.
            try:
                post = r.post
                post.is_locked = True
                # Chỉ đếm báo cáo chưa bị từ chối (không tính report đã rejected).
                post.reports_count = post.post_reports.exclude(status='rejected').count()
                post.save(update_fields=['is_locked', 'reports_count'])
            except Exception:
                pass
        elif action == 'reject':
            r.status = ForumPostReport.ReportStatus.REJECTED
            r.is_resolved = True
        elif action == 'analyze':
            from api.core.forum_moderation import moderate_forum_text

            verdict, reason = moderate_forum_text(r.post.content or '')
            r.ai_analysis = {'verdict': verdict, 'reason': reason}
            r.save(update_fields=['ai_analysis'])
            return Response({
                'status': 'ok',
                'message': f'Phân tích: {verdict}',
                'ai': {'verdict': verdict, 'reason': reason},
            })
        else:
            return Response({'error': 'Hành động không hợp lệ.'}, status=status.HTTP_400_BAD_REQUEST)

        r.save(update_fields=['status', 'is_resolved'])
        return Response({'status': 'ok', 'message': 'Đã xử lý báo cáo bài viết.'})


class AdminForumCommentReportsView(APIView):
    """GET /api/v1/admin/forum/comment-reports/ (?status=...)"""
    permission_classes = [IsAdminUser]

    @extend_schema(responses={200: list})
    def get(self, request):
        status_f = request.query_params.get('status', 'pending')
        qs = ForumCommentReport.objects.select_related(
            'comment', 'comment__author', 'comment__post', 'reporter'
        )
        if status_f and status_f != 'all':
            qs = qs.filter(status=status_f)
        return Response([_comment_report_row(r) for r in qs[:200]])


class AdminForumCommentReportActionView(APIView):
    """POST /api/v1/admin/forum/comment-reports/<int:report_id>/action/"""
    permission_classes = [IsAdminUser]

    def post(self, request, report_id):
        try:
            r = ForumCommentReport.objects.select_related('comment').get(id=report_id)
        except ForumCommentReport.DoesNotExist:
            return Response({'error': 'Báo cáo không tồn tại.'}, status=status.HTTP_404_NOT_FOUND)

        action = request.data.get('action')
        if action == 'approve':
            r.status = ForumPostReport.ReportStatus.APPROVED
            r.is_resolved = True
            try:
                r.comment.delete()
            except Exception:
                pass
        elif action == 'reject':
            r.status = ForumPostReport.ReportStatus.REJECTED
            r.is_resolved = True
        elif action == 'analyze':
            from api.core.forum_moderation import moderate_forum_text

            verdict, reason = moderate_forum_text(r.comment.content or '')
            r.ai_analysis = {'verdict': verdict, 'reason': reason}
            r.save(update_fields=['ai_analysis'])
            return Response({
                'status': 'ok',
                'message': f'Phân tích: {verdict}',
                'ai': {'verdict': verdict, 'reason': reason},
            })
        else:
            return Response({'error': 'Hành động không hợp lệ.'}, status=status.HTTP_400_BAD_REQUEST)

        r.save(update_fields=['status', 'is_resolved'])
        return Response({'status': 'ok', 'message': 'Đã xử lý báo cáo bình luận.'})


class AdminForumBansView(APIView):
    """GET /api/v1/admin/forum/bans/ (?active=1)"""
    permission_classes = [IsAdminUser]

    @extend_schema(responses={200: list})
    def get(self, request):
        qs = ForumBan.objects.select_related('user', 'banned_by')
        active_only = request.query_params.get('active')
        if active_only in ('1', 'true', 'yes'):
            qs = qs.filter(is_active=True)
        data = []
        for b in qs[:200]:
            data.append({
                'id': b.id,
                'user': _user_brief(b.user),
                'banned_by': _user_brief(b.banned_by),
                'reason': b.reason,
                'ban_type': b.ban_type,
                'expires_at': b.expires_at.strftime('%d/%m/%Y %H:%M') if b.expires_at else None,
                'is_active': b.is_active,
                'is_expired': b.is_expired,
                'created_at': b.created_at.strftime('%d/%m/%Y %H:%M'),
            })
        return Response(data)


class AdminForumBanActionView(APIView):
    """POST /api/v1/admin/forum/ban/

    Tạo cấm:  {user_id, reason, ban_type: 'temporary'|'permanent', days?}
    Gỡ cấm:   {ban_id, action: 'unban'}
    """
    permission_classes = [IsAdminUser]

    def post(self, request):
        action = request.data.get('action')

        if action == 'unban':
            ban_id = request.data.get('ban_id')
            try:
                ban = ForumBan.objects.get(id=ban_id)
            except ForumBan.DoesNotExist:
                return Response({'error': 'Bản ghi cấm không tồn tại.'}, status=status.HTTP_404_NOT_FOUND)
            ban.is_active = False
            ban.save(update_fields=['is_active'])
            return Response({'status': 'ok', 'message': f'Đã gỡ cấm {ban.user.username}.'})

        user_id = request.data.get('user_id')
        reason = (request.data.get('reason') or '').strip()
        ban_type = request.data.get('ban_type', ForumBan.BanType.TEMPORARY)
        days = request.data.get('days')

        if not user_id or not reason:
            return Response({'error': 'Thiếu người dùng hoặc lý do.'}, status=status.HTTP_400_BAD_REQUEST)

        from django.contrib.auth import get_user_model

        User = get_user_model()
        try:
            target = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'error': 'Người dùng không tồn tại.'}, status=status.HTTP_404_NOT_FOUND)

        if target.is_staff or target.is_superuser:
            return Response({'error': 'Không thể cấm quản trị viên.'}, status=status.HTTP_400_BAD_REQUEST)

        # Vô hiệu hóa các bản ghi cấm cũ còn hiệu lực.
        ForumBan.objects.filter(user=target, is_active=True).update(is_active=False)

        expires_at = None
        if ban_type != ForumBan.BanType.PERMANENT:
            try:
                expires_at = timezone.now() + timedelta(days=int(days or 7))
            except (TypeError, ValueError):
                expires_at = timezone.now() + timedelta(days=7)

        ban = ForumBan.objects.create(
            user=target,
            banned_by=request.user,
            reason=reason,
            ban_type=ban_type,
            expires_at=expires_at,
            is_active=True,
        )
        return Response({
            'status': 'ok',
            'id': ban.id,
            'message': f'Đã cấm {target.username} khỏi diễn đàn.',
        })


class AdminForumModeratorView(APIView):
    """POST /api/v1/admin/forum/moderator/ — {user_id, action: 'grant'|'revoke'}"""
    permission_classes = [IsAdminUser]

    def post(self, request):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        user_id = request.data.get('user_id')
        action = request.data.get('action')
        try:
            target = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'error': 'Người dùng không tồn tại.'}, status=status.HTTP_404_NOT_FOUND)

        if target.is_superuser:
            return Response({'error': 'Không thể thay đổi quyền Super Admin.'}, status=status.HTTP_400_BAD_REQUEST)

        if action == 'grant':
            target.is_staff = True
            target.save(update_fields=['is_staff'])
            return Response({'status': 'ok', 'message': f'Đã cấp quyền moderator cho {target.username}.'})
        if action == 'revoke':
            target.is_staff = False
            target.save(update_fields=['is_staff'])
            return Response({'status': 'ok', 'message': f'Đã thu hồi quyền moderator của {target.username}.'})
        return Response({'error': 'Hành động không hợp lệ.'}, status=status.HTTP_400_BAD_REQUEST)
