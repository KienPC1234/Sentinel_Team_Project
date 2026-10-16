"""ShieldCall VN – Admin Views"""
import re
import hashlib
import logging
import json
from urllib.parse import urlparse

from django.contrib.auth import authenticate, get_user_model
from django.db.models import Count, Sum, F, Q
from django.utils import timezone
from datetime import datetime, time, timedelta

from django.http import StreamingHttpResponse
from rest_framework import status, permissions, generics, serializers
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_spectacular.utils import extend_schema
from rest_framework.authtoken.models import Token

from api.utils.ollama_client import analyze_text_for_scam, generate_response, stream_response

from api.core.models import (
    Domain, BankAccount, Report, ScanEvent, TrendDaily,
    EntityLink, UserAlert, ScamType, RiskLevel, ReportStatus,
    Article, LearnLesson
)
from django.shortcuts import render
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


def _as_bool(value, default: bool = False) -> bool:
    """Ép bool an toàn cho cả JSON lẫn multipart ('false' không bị coi là True)."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().lower() in ('1', 'true', 'yes', 'on')
    return bool(value)


def _as_json(value, default):
    """Chấp nhận object/array sẵn có hoặc chuỗi JSON (khi client gửi FormData)."""
    if value is None:
        return default
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return default
    return value

# ═══════════════════════════════════════════════════════════════════════════
# ADMIN APIs
# ═══════════════════════════════════════════════════════════════════════════

class AdminReportsView(generics.ListAPIView):
    """GET /api/admin/reports — Moderation queue"""
    serializer_class = ReportListSerializer
    permission_classes = [IsAdminUser]

    def get_queryset(self):
        # select_related reporter: moi dong deu doc reporter.email (mask) nen
        # thieu dong nay la 1 query/dong o hang doi kiem duyet.
        qs = Report.objects.select_related('reporter').all()
        st = self.request.query_params.get('status', 'pending')
        if st:
            qs = qs.filter(status=st)
        return qs[:100]


class AdminReportActionView(APIView):
    """POST /api/admin/reports/{id}/action — Approve or reject a report"""
    permission_classes = [IsAdminUser]

    @extend_schema(request=ReportModerateSerializer, responses={200: serializers.DictField()})
    def post(self, request, report_id):
        serializer = ReportModerateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            report = Report.objects.get(pk=report_id)
        except Report.DoesNotExist:
            return Response({'error': 'Report không tồn tại.'},
                            status=status.HTTP_404_NOT_FOUND)

        action = serializer.validated_data['action']
        report.status = 'approved' if action == 'approve' else 'rejected'
        report.moderator = request.user
        report.moderation_note = serializer.validated_data.get('note', '')
        report.save()

        # Notify reporter via email + push notification. Boc het trong try rieng:
        # trang thai da luu o tren, loi gui mail/push khong duoc lam action 500.
        if report.reporter:
            try:
                from api.utils.email_utils import send_report_outcome_email
                send_report_outcome_email(report.reporter, report.target_type, report.target_value, report.status)
            except Exception:
                logger.exception('Failed to send report outcome email for report #%s', report_id)
            try:
                from api.utils.push_service import push_service
                if action == 'approve':
                    push_service.send_push(
                        report.reporter.id,
                        'Báo cáo đã được chấp thuận',
                        f'Báo cáo #{report_id} về {report.target_value} đã được chấp thuận.',
                        url='/my-reports/',
                        notification_type='success'
                    )
                else:
                    push_service.send_push(
                        report.reporter.id,
                        'Báo cáo đã bị từ chối',
                        f'Báo cáo #{report_id} về {report.target_value} đã bị từ chối.',
                        url='/my-reports/',
                        notification_type='warning'
                    )
            except Exception:
                logger.exception('Failed to push report outcome for report #%s', report_id)

        # If approved, update entity risk scores
        if action == 'approve':
            if report.target_type == 'phone':
                from api.core.tasks import recompute_phone_risk
                recompute_phone_risk.delay(report.target_value)
            elif report.target_type == 'domain':
                # Tran risk_score o 100 (truoc day +15 moi lan duyet co the vuot 100).
                for _domain in Domain.objects.filter(domain_name=report.target_value)[:1]:
                    _domain.report_count = (_domain.report_count or 0) + 1
                    _domain.risk_score = min(100, (_domain.risk_score or 0) + 15)
                    _domain.save(update_fields=['report_count', 'risk_score'])

        # So lieu public thay doi -> xoa cache stats
        try:
            from django.core.cache import cache as _cache
            _cache.delete('report_stats_v1')
        except Exception:
            pass

        return Response({
            'message': f'Report #{report_id} đã được {action}.',
            'status': report.status,
        })


class AdminStatsView(APIView):
    """GET /api/admin/stats — System overview stats"""
    permission_classes = [IsAdminUser]

    @extend_schema(responses={200: serializers.DictField()})
    def get(self, request):
        # Dashboard poll endpoint nay moi 5s (~25 count query/lan) nen cache 60s.
        # Truoc day moi tab admin mo la 12 lan/phut x 25 query vao DB.
        from django.core.cache import cache as _cache
        cached = _cache.get('admin_stats_v1')
        if cached is not None:
            return Response(cached)
        now = timezone.now()
        tz = timezone.get_current_timezone()
        today = now.astimezone(tz).date()
        today_start = timezone.make_aware(datetime.combine(today, time.min), tz)
        today_end = timezone.make_aware(datetime.combine(today, time.max), tz)
        week_ago_start = timezone.make_aware(datetime.combine(today - timedelta(days=7), time.min), tz)

        # Đếm thêm nội dung + diễn đàn cho trang Dashboard/Panel (bản gốc dùng context server).
        from api.core.models import ForumPost, ForumComment, ForumPostReport, ArticleComment
        try:
            forum_stats = {
                'total_posts': ForumPost.objects.count(),
                'total_comments': ForumComment.objects.count(),
                'pending_forum_reports': ForumPostReport.objects.filter(
                    status=ForumPostReport.ReportStatus.PENDING
                ).count(),
                'locked_posts': ForumPost.objects.filter(is_locked=True).count(),
                'pinned_posts': ForumPost.objects.filter(is_pinned=True).count(),
            }
        except Exception:
            forum_stats = {}

        # Chuỗi 7 ngày gần nhất cho biểu đồ Dashboard.
        # Sử dụng datetime range để không phụ thuộc vào CONVERT_TZ của MySQL/MariaDB.
        labels, scans_series, reports_series = [], [], []
        for i in range(6, -1, -1):
            day = today - timedelta(days=i)
            labels.append(day.strftime('%d/%m'))
            day_start = timezone.make_aware(datetime.combine(day, time.min), tz)
            day_end = timezone.make_aware(datetime.combine(day, time.max), tz)
            scans_series.append(ScanEvent.objects.filter(created_at__range=(day_start, day_end)).count())
            reports_series.append(Report.objects.filter(created_at__range=(day_start, day_end)).count())

        from api.core.models import WebPushSubscription, SupportTicket
        try:
            webpush_active = WebPushSubscription.objects.filter(is_active=True).count()
            webpush_total = WebPushSubscription.objects.count()
            open_tickets = SupportTicket.objects.filter(status='open').count()
        except Exception:
            webpush_active, webpush_total, open_tickets = 0, 0, 0

        payload = {
            'total_users': User.objects.count(),
            'total_scans': ScanEvent.objects.count(),
            'total_reports': Report.objects.count(),
            'pending_reports': Report.objects.filter(status='pending').count(),
            'scans_today': ScanEvent.objects.filter(created_at__range=(today_start, today_end)).count(),
            'scans_week': ScanEvent.objects.filter(created_at__gte=week_ago_start).count(),
            'reports_week': Report.objects.filter(created_at__gte=week_ago_start).count(),
            'domains_tracked': Domain.objects.count(),
            'accounts_tracked': BankAccount.objects.count(),
            'total_lessons': LearnLesson.objects.count(),
            'total_articles': Article.objects.count(),
            'total_article_comments': ArticleComment.objects.count(),
            'webpush_subscribers': webpush_active,
            'webpush_total': webpush_total,
            'pending_tickets': open_tickets,
            'active_today': User.objects.filter(last_login__range=(today_start, today_end)).count()
            if hasattr(User, 'last_login') else 0,
            # Đếm diễn đàn (vừa top-level cho Panel cũ, vừa nested cho Dashboard mới).
            'total_posts': forum_stats.get('total_posts', 0),
            'total_comments': forum_stats.get('total_comments', 0),
            'pending_forum_reports': forum_stats.get('pending_forum_reports', 0),
            'forum': forum_stats,
            'charts': {
                'labels': labels,
                'scans': scans_series,
                'reports': reports_series,
            },
        }
        _cache.set('admin_stats_v1', payload, timeout=60)
        return Response(payload)


class AdminRAGManagementView(APIView):
    """GET /api/admin/rag — Dashboard for RAG management"""
    permission_classes = [IsAdminUser]

    @extend_schema(
        parameters=[
            {'name': 'query', 'in': 'query', 'type': 'string', 'required': False},
            {'name': 'json', 'in': 'query', 'type': 'integer', 'required': False},
        ],
        responses={200: serializers.DictField()} # Simplified for now as it handles both HTML and JSON
    )
    def get(self, request):
        from api.maintenance.models import RAGIndexLog
        from api.utils.vector_db import vector_db
        from django.conf import settings
        from django.utils import timezone
        from datetime import timedelta
        
        # Auto-fail orphaned RUNNING logs older than 15 minutes to prevent perpetual stuck UI
        stale_cutoff = timezone.now() - timedelta(minutes=15)
        RAGIndexLog.objects.filter(status='RUNNING', started_at__lt=stale_cutoff).update(
            status='FAILED',
            completed_at=timezone.now(),
            error_message='Hệ thống tự động hủy do worker quá hạn (timeout >15 phút)'
        )

        query = request.query_params.get('query')
        test_results = []
        if query:
            try:
                test_results = vector_db.search(query, k=5)
            except Exception as search_err:
                logger.warning("RAG vector search test failed: %s", search_err)
                test_results = []
            
        logs = RAGIndexLog.objects.all()[:50]
        
        # Current stats
        from api.utils.vector_db import MODEL_NAME
        
        # Check if a sync is currently running
        running_log = RAGIndexLog.objects.filter(status='RUNNING').first()
        last_success = RAGIndexLog.objects.filter(status='SUCCESS').first()
        
        # Get beat schedule interval for news & vector synchronization
        beat_interval = 86400
        beat_schedule = getattr(settings, 'CELERY_BEAT_SCHEDULE', {})
        for key in ('sync-tinnhiemmang-news-daily', 'sync-tinnhiemmang-news-12h', 'daily-trend-aggregation'):
            if key in beat_schedule:
                sched = beat_schedule[key].get('schedule')
                if hasattr(sched, 'total_seconds'):
                    beat_interval = int(sched.total_seconds())
                elif isinstance(sched, (int, float)):
                    beat_interval = int(sched)
                break
        
        total_items = len(vector_db.metadata) if vector_db and getattr(vector_db, 'metadata', None) is not None else 0
        is_ready = bool(vector_db and getattr(vector_db, 'index', None) is not None)
        
        stats = {
            'total_items': total_items,
            'last_sync': last_success.completed_at if last_success else None,
            'is_ready': is_ready,
            'model_name': MODEL_NAME,
            'is_running': running_log is not None,
            'running_since': running_log.started_at if running_log else None,
            'beat_interval': beat_interval,
        }
        
        logs_data = [{
            'id': str(l.id),
            'status': l.status,
            'trigger': l.trigger,
            'documents_count': l.documents_count,
            'error_message': l.error_message or '',
            'started_at': l.started_at.strftime('%d/%m/%y %H:%M:%S') if l.started_at else '',
            'completed_at': l.completed_at.strftime('%d/%m/%y %H:%M:%S') if l.completed_at else '',
            'duration': str(l.completed_at - l.started_at) if l.completed_at and l.started_at else '',
        } for l in logs[:20]]
        
        return Response({
            'stats': stats,
            'logs': logs_data,
            'test_results': test_results
        })


class AdminRAGRebuildView(APIView):
    """POST /api/admin/rag/rebuild — Trigger vector index rebuild"""
    permission_classes = [IsAdminUser]

    @extend_schema(responses={200: serializers.DictField()})
    def post(self, request):
        from api.maintenance.tasks import rebuild_vector_index
        try:
            rebuild_vector_index.delay(trigger='MANUAL')
            return Response({'message': 'Đã lên lịch xây dựng lại chỉ mục Vector.'})
        except Exception as e:
            logger.error("Failed to queue rebuild_vector_index: %s", e)
            return Response({'error': f'Không thể kích hoạt Celery: {str(e)}'}, status=status.HTTP_503_SERVICE_UNAVAILABLE)

class AdminRAGClearLogsView(APIView):
    """POST /api/admin/rag/clear-logs — Clear sync history logs"""
    permission_classes = [IsAdminUser]

    @extend_schema(responses={200: serializers.DictField()})
    def post(self, request):
        from api.maintenance.models import RAGIndexLog
        count = RAGIndexLog.objects.exclude(status='RUNNING').count()
        RAGIndexLog.objects.exclude(status='RUNNING').delete()
        return Response({'message': f'Đã xóa {count} bản ghi lịch sử đồng bộ.', 'cleared': count})


# ═══════════════════════════════════════════════════════════════════════════
# CMS & USER MANAGEMENT APIs (Pure DRF / Next.js)
# ═══════════════════════════════════════════════════════════════════════════

from django.db import transaction
from api.core.models import LearnQuiz, LearnScenario


class AdminUsersView(APIView):
    """GET /api/v1/admin/users/ — List and search users"""
    permission_classes = [IsAdminUser]

    def get(self, request):
        q = (request.query_params.get('q') or '').strip()[:100]
        role = request.query_params.get('role', 'all')
        status_f = (request.query_params.get('status') or 'all').strip()

        users_qs = User.objects.select_related('profile').annotate(
            posts_count=Count('forum_posts', distinct=True),
            comments_count=Count('forum_comments', distinct=True),
        ).order_by('-is_active', '-is_staff', '-date_joined')

        if q:
            users_qs = users_qs.filter(
                Q(username__icontains=q) |
                Q(email__icontains=q) |
                Q(first_name__icontains=q) |
                Q(last_name__icontains=q)
            )

        if role == 'staff':
            users_qs = users_qs.filter(is_staff=True)
        elif role == 'super':
            users_qs = users_qs.filter(is_superuser=True)
        elif role == 'user':
            users_qs = users_qs.filter(is_staff=False, is_superuser=False)

        if status_f == 'active':
            users_qs = users_qs.filter(is_active=True)
        elif status_f == 'inactive':
            users_qs = users_qs.filter(is_active=False)

        count = users_qs.count()
        try:
            page = max(1, int(request.query_params.get('page', 1)))
        except (TypeError, ValueError):
            page = 1
        try:
            page_size = min(100, max(1, int(request.query_params.get('page_size', 30))))
        except (TypeError, ValueError):
            page_size = 30
        start = (page - 1) * page_size

        users_list = []
        for u in users_qs[start:start + page_size]:
            profile = getattr(u, 'profile', None)
            rank = profile.rank_points if profile else 0
            rank_info = getattr(profile, 'rank_info', None) or {}
            avatar = None
            try:
                if profile and profile.avatar:
                    avatar = profile.avatar.url
            except Exception:
                avatar = None
            is_super = u.is_superuser or bool(profile and profile.is_super_admin)
            users_list.append({
                'id': u.id,
                'username': u.username,
                'email': u.email or '',
                'full_name': u.get_full_name() or u.username,
                'is_staff': u.is_staff,
                'is_active': u.is_active,
                'is_superuser': is_super,
                'rank_points': rank,
                'rank_name': rank_info.get('name', ''),
                'rank_level': rank_info.get('level', ''),
                'rank_icon': rank_info.get('icon', ''),
                'avatar': avatar,
                'last_login': u.last_login.strftime('%d/%m/%Y %H:%M') if u.last_login else '',
                'posts_count': getattr(u, 'posts_count', 0),
                'comments_count': getattr(u, 'comments_count', 0),
                'date_joined': u.date_joined.strftime('%d/%m/%Y'),
            })

        return Response({
            'count': count,
            'page': page,
            'page_size': page_size,
            'has_next': start + page_size < count,
            'results': users_list,
        })


class AdminUserActionView(APIView):
    """POST /api/v1/admin/users/<int:user_id>/action/ — Moderate user"""
    permission_classes = [IsAdminUser]

    def post(self, request, user_id):
        try:
            target_user = User.objects.select_related('profile').get(id=user_id)
        except User.DoesNotExist:
            return Response({'error': 'Người dùng không tồn tại.'}, status=status.HTTP_404_NOT_FOUND)

        if target_user == request.user:
            return Response({'error': 'Không thể thao tác trên chính tài khoản của bạn.'}, status=status.HTTP_400_BAD_REQUEST)

        action = (request.data.get('action') or '').strip()

        if action == 'toggle_staff':
            if not request.user.is_superuser and not (hasattr(request.user, 'profile') and request.user.profile.is_super_admin):
                return Response({'error': 'Chỉ Super Admin mới có quyền phân quyền Admin.'}, status=status.HTTP_403_FORBIDDEN)
            if target_user.is_superuser:
                return Response({'error': 'Không thể thay đổi quyền của Superuser.'}, status=status.HTTP_400_BAD_REQUEST)
            target_user.is_staff = not target_user.is_staff
            target_user.save(update_fields=['is_staff'])
            return Response({
                'status': 'ok',
                'message': f"Đã {'thăng cấp' if target_user.is_staff else 'hạ cấp'} {target_user.username}.",
                'is_staff': target_user.is_staff,
            })

        elif action == 'toggle_active':
            if target_user.is_superuser:
                return Response({'error': 'Không thể khóa tài khoản Superuser.'}, status=status.HTTP_400_BAD_REQUEST)
            target_user.is_active = not target_user.is_active
            target_user.save(update_fields=['is_active'])
            return Response({
                'status': 'ok',
                'message': f"Đã {'mở khóa' if target_user.is_active else 'khóa'} {target_user.username}.",
                'is_active': target_user.is_active,
            })

        elif action == 'reset_rank':
            if hasattr(target_user, 'profile'):
                target_user.profile.rank_points = 0
                target_user.profile.save(update_fields=['rank_points'])
                return Response({'status': 'ok', 'message': f'Đã reset điểm uy tín cho {target_user.username}.'})
            return Response({'error': 'Chưa có hồ sơ profile.'}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'error': f'Hành động {action} không hợp lệ.'}, status=status.HTTP_400_BAD_REQUEST)


class AdminScenariosView(APIView):
    """GET/POST /api/v1/admin/scenarios/ — List and create scenarios"""
    permission_classes = [IsAdminUser]

    def get(self, request):
        scenarios = LearnScenario.objects.select_related('article', 'lesson').order_by('-created_at')[:100]
        data = [{
            'id': sc.id,
            'title': sc.title,
            'description': sc.description,
            'article_id': sc.article_id,
            'article_title': sc.article.title if sc.article else None,
            'lesson_id': sc.lesson_id,
            'lesson_title': sc.lesson.title if sc.lesson else None,
            'steps_count': len(sc.content.get('steps', [])) if isinstance(sc.content, dict) else 0,
            'created_at': sc.created_at.strftime('%d/%m/%Y'),
        } for sc in scenarios]
        return Response(data)

    def post(self, request):
        title = (request.data.get('title') or '').strip()
        description = (request.data.get('description') or '').strip()
        article_id = request.data.get('article_id')
        lesson_id = request.data.get('lesson_id')
        steps = request.data.get('steps', [])

        if not title:
            return Response({'error': 'Tiêu đề không được để trống.'}, status=status.HTTP_400_BAD_REQUEST)

        parsed_steps = []
        if isinstance(steps, list):
            for s in steps:
                if isinstance(s, dict) and str(s.get('text') or '').strip():
                    parsed_steps.append({
                        'speaker': s.get('speaker') if s.get('speaker') in ['scammer', 'victim', 'narrator'] else 'narrator',
                        'text': str(s.get('text')).strip(),
                        'note': str(s.get('note') or '').strip(),
                    })

        scenario = LearnScenario.objects.create(
            title=title,
            description=description,
            article_id=article_id or None,
            lesson_id=lesson_id or None,
            content={'steps': parsed_steps},
        )
        return Response({'status': 'ok', 'id': scenario.id, 'message': 'Đã tạo kịch bản thành công.'}, status=status.HTTP_201_CREATED)


class AdminScenarioDetailView(APIView):
    """GET/PUT/DELETE /api/v1/admin/scenarios/<int:scenario_id>/"""
    permission_classes = [IsAdminUser]

    def get(self, request, scenario_id):
        try:
            sc = LearnScenario.objects.select_related('article', 'lesson').get(id=scenario_id)
        except LearnScenario.DoesNotExist:
            return Response({'error': 'Kịch bản không tồn tại.'}, status=status.HTTP_404_NOT_FOUND)

        steps = sc.content.get('steps', []) if isinstance(sc.content, dict) else []
        return Response({
            'id': sc.id,
            'title': sc.title,
            'description': sc.description,
            'article_id': sc.article_id,
            'lesson_id': sc.lesson_id,
            'steps': steps,
            'created_at': sc.created_at.isoformat(),
        })

    def put(self, request, scenario_id):
        try:
            sc = LearnScenario.objects.get(id=scenario_id)
        except LearnScenario.DoesNotExist:
            return Response({'error': 'Kịch bản không tồn tại.'}, status=status.HTTP_404_NOT_FOUND)

        title = (request.data.get('title') or '').strip()
        description = (request.data.get('description') or '').strip()
        article_id = request.data.get('article_id')
        lesson_id = request.data.get('lesson_id')
        steps = request.data.get('steps', [])

        if not title:
            return Response({'error': 'Tiêu đề không được để trống.'}, status=status.HTTP_400_BAD_REQUEST)

        parsed_steps = []
        if isinstance(steps, list):
            for s in steps:
                if isinstance(s, dict) and str(s.get('text') or '').strip():
                    parsed_steps.append({
                        'speaker': s.get('speaker') if s.get('speaker') in ['scammer', 'victim', 'narrator'] else 'narrator',
                        'text': str(s.get('text')).strip(),
                        'note': str(s.get('note') or '').strip(),
                    })

        sc.title = title
        sc.description = description
        sc.article_id = article_id or None
        sc.lesson_id = lesson_id or None
        sc.content = {'steps': parsed_steps}
        sc.save()

        return Response({'status': 'ok', 'message': 'Đã cập nhật kịch bản thành công.'})

    def delete(self, request, scenario_id):
        try:
            sc = LearnScenario.objects.get(id=scenario_id)
            sc.delete()
            return Response({'status': 'ok', 'message': 'Đã xóa kịch bản.'})
        except LearnScenario.DoesNotExist:
            return Response({'error': 'Kịch bản không tồn tại.'}, status=status.HTTP_404_NOT_FOUND)


def _trigger_vector_rebuild():
    """Trigger background Vector DB rebuild and cache invalidation."""
    try:
        from api.utils.vector_db import vector_db
        vector_db.invalidate_cache()
    except Exception:
        pass
    try:
        from api.core.tasks import rebuild_scam_vector_index
        rebuild_scam_vector_index.delay()
    except Exception:
        try:
            import threading
            from api.utils.vector_db import vector_db
            threading.Thread(target=vector_db.rebuild_index, kwargs={'force_cpu': True}, daemon=True).start()
        except Exception:
            pass


class AdminLearnView(APIView):
    """GET/POST /api/v1/admin/learn/ — List and create lessons"""
    permission_classes = [IsAdminUser]

    def get(self, request):
        lessons = LearnLesson.objects.prefetch_related('quizzes', 'scenarios').order_by('-created_at')[:100]
        data = [{
            'id': l.id,
            'title': l.title,
            'slug': l.slug,
            'category': l.category,
            'summary': l.summary,
            'cover_image': l.cover_image.url if l.cover_image else None,
            'is_published': l.is_published,
            'quizzes_count': l.quizzes.count(),
            'scenarios_count': l.scenarios.count(),
            'created_at': l.created_at.strftime('%d/%m/%Y'),
        } for l in lessons]
        return Response(data)

    def post(self, request):
        title = (request.data.get('title') or '').strip()
        content = (request.data.get('content') or '').strip()
        summary = (request.data.get('summary') or '').strip()
        category = request.data.get('category', 'guide')
        is_published = _as_bool(request.data.get('is_published'), True)
        quizzes = _as_json(request.data.get('quizzes'), [])
        scenario_data = _as_json(request.data.get('scenario'), None)
        slug = (request.data.get('slug') or '').strip()
        cover_image = request.FILES.get('cover_image')

        if not title or not content:
            return Response({'error': 'Tiêu đề và nội dung không được để trống.'}, status=status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            create_kwargs = {
                'title': title,
                'summary': summary,
                'content': content,
                'category': category,
                'is_published': is_published,
            }
            if slug:
                create_kwargs['slug'] = slug
            if cover_image:
                create_kwargs['cover_image'] = cover_image
            lesson = LearnLesson.objects.create(**create_kwargs)

            if isinstance(quizzes, list):
                for q in quizzes:
                    if isinstance(q, dict) and str(q.get('question') or '').strip():
                        opts = q.get('options') if isinstance(q.get('options'), list) else []
                        corr = str(q.get('correct_answer') or '')
                        LearnQuiz.objects.create(
                            lesson=lesson,
                            question=str(q.get('question')).strip(),
                            question_type=q.get('question_type') or 'single_choice',
                            options=opts,
                            correct_answer=corr,
                            correct_answers=q.get('correct_answers') or ([corr] if corr else []),
                            explanation=str(q.get('explanation') or ''),
                        )

            if isinstance(scenario_data, dict) and str(scenario_data.get('title') or '').strip():
                steps = scenario_data.get('steps', [])
                parsed_steps = []
                if isinstance(steps, list):
                    for s in steps:
                        if isinstance(s, dict) and str(s.get('text') or '').strip():
                            parsed_steps.append({
                                'speaker': s.get('speaker') if s.get('speaker') in ['scammer', 'victim', 'narrator'] else 'narrator',
                                'text': str(s.get('text')).strip(),
                                'note': str(s.get('note') or '').strip(),
                            })
                LearnScenario.objects.create(
                    lesson=lesson,
                    title=str(scenario_data.get('title')).strip(),
                    description=str(scenario_data.get('description') or ''),
                    content={'steps': parsed_steps},
                )

        _trigger_vector_rebuild()
        return Response({'status': 'ok', 'id': lesson.id, 'slug': lesson.slug, 'message': 'Đã tạo bài học thành công.'}, status=status.HTTP_201_CREATED)


class AdminLearnDetailView(APIView):
    """GET/PUT/DELETE /api/v1/admin/learn/<int:lesson_id>/"""
    permission_classes = [IsAdminUser]

    def get(self, request, lesson_id):
        try:
            lesson = LearnLesson.objects.prefetch_related('quizzes', 'scenarios').get(id=lesson_id)
        except LearnLesson.DoesNotExist:
            return Response({'error': 'Bài học không tồn tại.'}, status=status.HTTP_404_NOT_FOUND)

        quizzes = [{
            'id': q.id,
            'question': q.question,
            'question_type': q.question_type,
            'options': q.options if isinstance(q.options, list) else [],
            'correct_answer': q.correct_answer,
            'correct_answers': q.correct_answers if isinstance(q.correct_answers, list) else ([q.correct_answer] if q.correct_answer else []),
            'explanation': q.explanation,
        } for q in lesson.quizzes.all()]

        scenario = lesson.scenarios.first()
        scenario_data = None
        if scenario:
            scenario_data = {
                'id': scenario.id,
                'title': scenario.title,
                'description': scenario.description,
                'steps': scenario.content.get('steps', []) if isinstance(scenario.content, dict) else [],
            }

        return Response({
            'id': lesson.id,
            'title': lesson.title,
            'slug': lesson.slug,
            'category': lesson.category,
            'summary': lesson.summary,
            'content': lesson.content,
            'is_published': lesson.is_published,
            'cover_image': lesson.cover_image.url if lesson.cover_image else None,
            'quizzes': quizzes,
            'scenario': scenario_data,
            'created_at': lesson.created_at.isoformat(),
        })

    def put(self, request, lesson_id):
        try:
            lesson = LearnLesson.objects.get(id=lesson_id)
        except LearnLesson.DoesNotExist:
            return Response({'error': 'Bài học không tồn tại.'}, status=status.HTTP_404_NOT_FOUND)

        title = (request.data.get('title') or '').strip()
        content = (request.data.get('content') or '').strip()
        summary = (request.data.get('summary') or '').strip()
        category = request.data.get('category', lesson.category)
        is_published = request.data.get('is_published', lesson.is_published)
        quizzes = _as_json(request.data.get('quizzes'), None)
        scenario_data = _as_json(request.data.get('scenario'), None)
        slug = (request.data.get('slug') or '').strip()
        cover_image = request.FILES.get('cover_image')

        if not title or not content:
            return Response({'error': 'Tiêu đề và nội dung không được để trống.'}, status=status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            lesson.title = title
            lesson.content = content
            lesson.summary = summary
            lesson.category = category
            lesson.is_published = _as_bool(is_published)
            update_fields = ['title', 'content', 'summary', 'category', 'is_published']
            if slug:
                lesson.slug = slug
                update_fields.append('slug')
            if cover_image:
                lesson.cover_image = cover_image
                update_fields.append('cover_image')
            lesson.save(update_fields=update_fields)

            if isinstance(quizzes, list):
                lesson.quizzes.all().delete()
                for q in quizzes:
                    if isinstance(q, dict) and str(q.get('question') or '').strip():
                        opts = q.get('options') if isinstance(q.get('options'), list) else []
                        corr = str(q.get('correct_answer') or '')
                        LearnQuiz.objects.create(
                            lesson=lesson,
                            question=str(q.get('question')).strip(),
                            question_type=q.get('question_type') or 'single_choice',
                            options=opts,
                            correct_answer=corr,
                            correct_answers=q.get('correct_answers') or ([corr] if corr else []),
                            explanation=str(q.get('explanation') or ''),
                        )

            if isinstance(scenario_data, dict):
                steps = scenario_data.get('steps', [])
                parsed_steps = []
                if isinstance(steps, list):
                    for s in steps:
                        if isinstance(s, dict) and str(s.get('text') or '').strip():
                            parsed_steps.append({
                                'speaker': s.get('speaker') if s.get('speaker') in ['scammer', 'victim', 'narrator'] else 'narrator',
                                'text': str(s.get('text')).strip(),
                                'note': str(s.get('note') or '').strip(),
                            })
                sc = lesson.scenarios.first()
                if sc:
                    sc.title = str(scenario_data.get('title') or lesson.title).strip()
                    sc.description = str(scenario_data.get('description') or '')
                    sc.content = {'steps': parsed_steps}
                    sc.save()
                elif parsed_steps:
                    LearnScenario.objects.create(
                        lesson=lesson,
                        title=str(scenario_data.get('title') or lesson.title).strip(),
                        description=str(scenario_data.get('description') or ''),
                        content={'steps': parsed_steps},
                    )

        _trigger_vector_rebuild()
        return Response({'status': 'ok', 'message': 'Đã cập nhật bài học thành công.'})

    def delete(self, request, lesson_id):
        try:
            lesson = LearnLesson.objects.get(id=lesson_id)
            lesson.delete()
            _trigger_vector_rebuild()
            return Response({'status': 'ok', 'message': 'Đã xóa bài học.'})
        except LearnLesson.DoesNotExist:
            return Response({'error': 'Bài học không tồn tại.'}, status=status.HTTP_404_NOT_FOUND)


class AdminLearnNotifyView(APIView):
    """POST /api/v1/admin/learn/<int:lesson_id>/notify/ — Broadcast new lesson"""
    permission_classes = [IsAdminUser]

    def post(self, request, lesson_id):
        try:
            lesson = LearnLesson.objects.get(id=lesson_id)
        except LearnLesson.DoesNotExist:
            return Response({'error': 'Bài học không tồn tại.'}, status=status.HTTP_404_NOT_FOUND)

        active_users = User.objects.filter(is_active=True)
        user_emails = list(active_users.exclude(email__isnull=True).exclude(email='').values_list('email', flat=True))
        user_emails = sorted(set(user_emails))

        from api.utils.email_utils import send_new_lesson_email
        lesson_url = f"/learn/lesson/{lesson.slug}/"
        sent_email_count = send_new_lesson_email(user_emails, lesson.title, lesson_url) if user_emails else 0

        push_count = 0
        from api.utils.push_service import PushNotificationService
        for user in active_users[:200]:
            try:
                PushNotificationService.send_push(
                    user_id=user.id,
                    title='Bài học mới trên ShieldCall',
                    message=f'{lesson.title}',
                    url=lesson_url,
                    notification_type='info'
                )
                push_count += 1
            except Exception:
                pass

        return Response({
            'status': 'ok',
            'sent_emails': sent_email_count,
            'push_count': push_count,
            'message': f'Đã gửi {sent_email_count} email và {push_count} thông báo push.',
        })


class AdminArticlesView(APIView):
    """GET/POST /api/v1/admin/articles/ — List all articles & create new article"""
    permission_classes = [IsAdminUser]

    def get(self, request):
        articles = Article.objects.all().order_by('-created_at')[:100]
        data = [{
            'id': a.id,
            'title': a.title,
            'slug': a.slug,
            'category': a.category,
            'category_display': a.get_category_display(),
            'source_type': getattr(a, 'source_type', 'internal'),
            'source_type_display': a.get_source_type_display() if hasattr(a, 'get_source_type_display') else 'ShieldCall VN',
            'source_url': getattr(a, 'source_url', None),
            'summary': a.summary,
            'is_published': a.is_published,
            'cover_image': a.cover_image.url if a.cover_image else None,
            'author_name': a.author.username if a.author else ('Tín nhiệm mạng (NCSC)' if a.source_type == 'tinnhiemmang' else 'Admin'),
            'created_at': a.created_at.strftime('%d/%m/%Y'),
        } for a in articles]
        return Response(data)

    def post(self, request):
        title = (request.data.get('title') or '').strip()
        content = (request.data.get('content') or '').strip()
        summary = (request.data.get('summary') or '').strip()
        category = request.data.get('category', 'news')
        source_type = request.data.get('source_type', 'internal')
        source_url = request.data.get('source_url', None)
        is_published = _as_bool(request.data.get('is_published'), True)
        cover_image = request.FILES.get('cover_image')

        if not title or not content:
            return Response({'error': 'Tiêu đề và nội dung không được để trống.'}, status=status.HTTP_400_BAD_REQUEST)

        article = Article.objects.create(
            title=title,
            content=content,
            summary=summary,
            category=category,
            source_type=source_type,
            source_url=source_url,
            is_published=is_published,
            author=request.user,
        )
        if cover_image:
            article.cover_image = cover_image
            article.save(update_fields=['cover_image'])

        _trigger_vector_rebuild()
        return Response({
            'status': 'ok',
            'id': article.id,
            'slug': article.slug,
            'message': 'Đã tạo bài viết thành công.'
        }, status=status.HTTP_201_CREATED)


class AdminArticleDetailView(APIView):
    """GET/PUT/DELETE /api/v1/admin/articles/<int:article_id>/"""
    permission_classes = [IsAdminUser]

    def get(self, request, article_id):
        try:
            a = Article.objects.get(id=article_id)
        except Article.DoesNotExist:
            return Response({'error': 'Bài viết không tồn tại.'}, status=status.HTTP_404_NOT_FOUND)

        return Response({
            'id': a.id,
            'title': a.title,
            'slug': a.slug,
            'category': a.category,
            'category_display': a.get_category_display(),
            'source_type': getattr(a, 'source_type', 'internal'),
            'source_type_display': a.get_source_type_display() if hasattr(a, 'get_source_type_display') else 'ShieldCall VN',
            'source_url': getattr(a, 'source_url', None),
            'summary': a.summary,
            'content': a.content,
            'is_published': a.is_published,
            'cover_image': a.cover_image.url if a.cover_image else None,
            'created_at': a.created_at.isoformat(),
        })

    def put(self, request, article_id):
        try:
            a = Article.objects.get(id=article_id)
        except Article.DoesNotExist:
            return Response({'error': 'Bài viết không tồn tại.'}, status=status.HTTP_404_NOT_FOUND)

        title = (request.data.get('title') or '').strip()
        content = (request.data.get('content') or '').strip()
        summary = (request.data.get('summary') or '').strip()
        category = request.data.get('category', a.category)
        source_type = request.data.get('source_type', a.source_type)
        source_url = request.data.get('source_url', a.source_url)
        is_published = request.data.get('is_published', a.is_published)
        cover_image = request.FILES.get('cover_image')

        if not title or not content:
            return Response({'error': 'Tiêu đề và nội dung không được để trống.'}, status=status.HTTP_400_BAD_REQUEST)

        a.title = title
        a.content = content
        a.summary = summary
        a.category = category
        a.source_type = source_type
        a.source_url = source_url
        a.is_published = _as_bool(is_published)
        update_fields = ['title', 'content', 'summary', 'category', 'source_type', 'source_url', 'is_published', 'updated_at']
        if cover_image:
            a.cover_image = cover_image
            update_fields.append('cover_image')
        a.save(update_fields=update_fields)
        _trigger_vector_rebuild()

        return Response({'status': 'ok', 'message': 'Đã cập nhật bài viết thành công.'})

    def delete(self, request, article_id):
        try:
            a = Article.objects.get(id=article_id)
            a.delete()
            _trigger_vector_rebuild()
            return Response({'status': 'ok', 'message': 'Đã xóa bài viết.'})
        except Article.DoesNotExist:
            return Response({'error': 'Bài viết không tồn tại.'}, status=status.HTTP_404_NOT_FOUND)



