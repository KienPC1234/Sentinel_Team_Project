"""ShieldCall VN – Admin Views"""
import re
import hashlib
import logging
import json
from urllib.parse import urlparse

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
    Article, LearnLesson
)
from api.utils.vector_db import vector_db
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

# ═══════════════════════════════════════════════════════════════════════════
# ADMIN APIs
# ═══════════════════════════════════════════════════════════════════════════

class AdminReportsView(generics.ListAPIView):
    """GET /api/admin/reports — Moderation queue"""
    serializer_class = ReportListSerializer
    permission_classes = [IsAdminUser]

    def get_queryset(self):
        qs = Report.objects.all()
        st = self.request.query_params.get('status', 'pending')
        if st:
            qs = qs.filter(status=st)
        return qs[:100]


class AdminReportActionView(APIView):
    """POST /api/admin/reports/{id}/action — Approve or reject a report"""
    permission_classes = [IsAdminUser]

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

        # If approved, update entity risk scores
        if action == 'approve':
            if report.target_type == 'phone':
                from .tasks import recompute_phone_risk
                recompute_phone_risk.delay(report.target_value)
            elif report.target_type == 'domain':
                Domain.objects.filter(domain_name=report.target_value).update(
                    risk_score=F('risk_score') + 15,
                    report_count=F('report_count') + 1,
                )

        return Response({
            'message': f'Report #{report_id} đã được {action}.',
            'status': report.status,
        })


class AdminStatsView(APIView):
    """GET /api/admin/stats — System overview stats"""
    permission_classes = [IsAdminUser]

    def get(self, request):
        today = timezone.now().date()
        week_ago = today - timedelta(days=7)

        return Response({
            'total_users': User.objects.count(),
            'total_scans': ScanEvent.objects.count(),
            'total_reports': Report.objects.count(),
            'pending_reports': Report.objects.filter(status='pending').count(),
            'scans_today': ScanEvent.objects.filter(created_at__date=today).count(),
            'scans_week': ScanEvent.objects.filter(created_at__date__gte=week_ago).count(),
            'reports_week': Report.objects.filter(created_at__date__gte=week_ago).count(),
            'domains_tracked': Domain.objects.count(),
            'accounts_tracked': BankAccount.objects.count(),
        })

class AdminRAGManagementView(APIView):
    """GET /api/admin/rag — Dashboard for RAG management"""
    permission_classes = [IsAdminUser]

    def get(self, request):
        from api.maintenance.models import RAGIndexLog
        from api.utils.vector_db import vector_db
        from django.conf import settings
        
        query = request.query_params.get('query')
        test_results = []
        if query:
            test_results = vector_db.search(query, k=5)
            
        logs = RAGIndexLog.objects.all()[:50]
        
        # Current stats
        from api.utils.vector_db import MODEL_NAME
        
        # Check if a sync is currently running
        running_log = RAGIndexLog.objects.filter(status='RUNNING').first()
        last_success = RAGIndexLog.objects.filter(status='SUCCESS').first()
        
        # Get beat schedule interval
        beat_interval = 3600
        beat_schedule = getattr(settings, 'CELERY_BEAT_SCHEDULE', {})
        for key, val in beat_schedule.items():
            if 'vector' in key.lower() or 'rag' in key.lower():
                sched = val.get('schedule', None)
                if hasattr(sched, 'total_seconds'):
                    beat_interval = int(sched.total_seconds())
                elif isinstance(sched, (int, float)):
                    beat_interval = int(sched)
                break
        
        stats = {
            'total_items': len(vector_db.metadata),
            'last_sync': last_success.completed_at if last_success else None,
            'is_ready': vector_db.index is not None,
            'model_name': MODEL_NAME,
            'is_running': running_log is not None,
            'running_since': running_log.started_at if running_log else None,
            'beat_interval': beat_interval,
        }
        
        # If it's a JSON request or has json=1 param
        if 'json' in request.query_params or request.headers.get('Accept') == 'application/json':
            # Also return latest logs for live table update
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

        return render(request, 'Admin/rag_management.html', {
            'logs': logs,
            'stats': stats,
            'test_results': test_results,
            'query': query,
            'title': 'Quản lý RAG / Kiến thức AI'
        })

class AdminRAGRebuildView(APIView):
    """POST /api/admin/rag/rebuild — Trigger vector index rebuild"""
    permission_classes = [IsAdminUser]

    def post(self, request):
        from api.maintenance.tasks import rebuild_vector_index
        rebuild_vector_index.delay(trigger='MANUAL')
        return Response({'message': 'Đã lên lịch xây dựng lại chỉ mục Vector.'})

class AdminRAGClearLogsView(APIView):
    """POST /api/admin/rag/clear-logs — Clear sync history logs"""
    permission_classes = [IsAdminUser]

    def post(self, request):
        from api.maintenance.models import RAGIndexLog
        count = RAGIndexLog.objects.count()
        RAGIndexLog.objects.all().delete()
        return Response({'message': f'Đã xóa {count} bản ghi lịch sử đồng bộ.', 'cleared': count})


