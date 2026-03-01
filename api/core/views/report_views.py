"""ShieldCall VN – Report Views"""
import re
import hashlib
import logging
import json
from urllib.parse import urlparse
from api.utils.security import verify_turnstile_token
from django.core.cache import cache

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
    Domain, BankAccount, Report, ReportEvidence, ScanEvent, TrendDaily,
    EntityLink, UserAlert, ScamType, RiskLevel, ReportStatus,
)
from api.utils.media_utils import extract_ocr_text
from api.core.serializers import (
    RegisterSerializer, LoginSerializer, UserSerializer,
    DomainSerializer, BankAccountSerializer,
    ReportCreateSerializer, ReportListSerializer, ReportModerateSerializer, ReportDetailSerializer,
    ScanPhoneSerializer, ScanMessageSerializer, ScanDomainSerializer,
    ScanAccountSerializer, ScanImageSerializer, ScanEventListSerializer,
    TrendDailySerializer, TrendHotSerializer, UserAlertSerializer,
)

User = get_user_model()
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# REPORT APIs
# ═══════════════════════════════════════════════════════════════════════════

class ReportCreateView(APIView):
    """POST /api/report — Submit a scam report"""
    permission_classes = [AllowAny]

    def post(self, request):
        # Basic anti-spam throttle: 8 report submits / 10 minutes / IP
        client_ip = (request.META.get('HTTP_X_FORWARDED_FOR') or '').split(',')[0].strip() or request.META.get('REMOTE_ADDR', 'unknown')
        throttle_key = f"report_submit_ip:{client_ip}"
        current_hits = int(cache.get(throttle_key, 0))
        if current_hits >= 8:
            return Response({'error': 'Bạn gửi quá nhanh. Vui lòng thử lại sau vài phút.'}, status=429)

        # Turnstile Verification
        cf_token = request.data.get('cf-turnstile-response')
        if not verify_turnstile_token(cf_token):
             return Response({'error': 'Xác minh anti-spam không hợp lệ. Vui lòng thử lại.'}, status=400)

        evidence_files = request.FILES.getlist('evidence_images')
        if len(evidence_files) > 4:
            return Response({'error': 'Tối đa 4 ảnh bổ sung.'}, status=400)
        allowed_types = {'image/jpeg', 'image/png', 'image/webp', 'image/jpg'}
        for ef in evidence_files:
            if getattr(ef, 'content_type', '') not in allowed_types:
                return Response({'error': 'Chỉ chấp nhận ảnh JPG/PNG/WEBP.'}, status=400)
            if getattr(ef, 'size', 0) > 6 * 1024 * 1024:
                return Response({'error': 'Mỗi ảnh bổ sung tối đa 6MB.'}, status=400)

        main_evidence = request.FILES.get('evidence_file')
        if main_evidence:
            if getattr(main_evidence, 'content_type', '') not in allowed_types:
                return Response({'error': 'Ảnh chính phải là JPG/PNG/WEBP.'}, status=400)
            if getattr(main_evidence, 'size', 0) > 8 * 1024 * 1024:
                return Response({'error': 'Ảnh chính tối đa 8MB.'}, status=400)

        serializer = ReportCreateSerializer(data=request.data,
                                            context={'request': request})
        if not serializer.is_valid():
            # Return field-level errors in a user-friendly format
            field_labels = {
                'target_type': 'Loại đối tượng',
                'target_value': 'Thông tin đối tượng',
                'scam_type': 'Phương thức lừa đảo',
                'description': 'Nội dung mô tả',
                'severity': 'Mức độ nghiêm trọng',
            }
            errors = []
            for field, msgs in serializer.errors.items():
                label = field_labels.get(field, field)
                for msg in msgs:
                    errors.append(f'{label}: {msg}')
            return Response({
                'error': ' | '.join(errors),
                'field_errors': serializer.errors,
            }, status=status.HTTP_400_BAD_REQUEST)
        report = serializer.save()

        # Save additional evidence images (multi-upload)
        evidence_files = request.FILES.getlist('evidence_images')
        for ef in evidence_files:
            ReportEvidence.objects.create(report=report, image=ef)

        cache.set(throttle_key, current_hits + 1, timeout=600)

        # Update report counts on related entities
        target = report.target_value
        if report.target_type == 'phone':
            from api.utils.normalization import normalize_phone_e164
            normalized = normalize_phone_e164(target, strict=False)
            if normalized != target:
                report.target_value = normalized
                report.save()
                target = normalized
                
            from api.phone_security.models import PhoneNumber
            PhoneNumber.objects.filter(phone_number=target).update(
                reports_count=F('reports_count') + 1
            )
        elif report.target_type == 'domain':
            Domain.objects.filter(domain_name=target).update(
                report_count=F('report_count') + 1
            )
        elif report.target_type == 'email':
            from api.utils.normalization import normalize_email
            normalized = normalize_email(target)
            if normalized != target:
                report.target_value = normalized
                report.save()
                target = normalized

        # Auto-link to the most recent ScanEvent for this user and target
        if request.user.is_authenticated:
            recent_scan = ScanEvent.objects.filter(
                Q(normalized_input=target) | Q(raw_input=target),
                user=request.user,
                scan_type=report.target_type
            ).order_by('-created_at').first()
            if recent_scan:
                report.scan_event = recent_scan
                report.save()

        # Background AI/OCR task (non-blocking for user submit flow)
        try:
            from api.core.tasks import process_report_ai_async
            process_report_ai_async.delay(report.id)
        except Exception as e:
            logger.error(f"[ReportAI] Failed to enqueue background task for report #{report.id}: {e}")

        # Notify admins right after report is created
        try:
            from api.utils.push_service import push_service
            target_preview = (str(report.target_value or '')[:64]).strip()
            push_service.broadcast_admin(
                title='Báo cáo mới từ cộng đồng',
                message=f'#{report.id} · {report.get_target_type_display()} · {target_preview}',
                url='/admin-cp/reports/',
                notification_type='warning',
            )
        except Exception as e:
            logger.error(f"[ReportNotify] Failed to notify admins for report #{report.id}: {e}")

        return Response({
            'message': 'Báo cáo đã được gửi thành công! Cảm ơn bạn đã giúp cộng đồng.',
            'report_id': report.pk,
            'status': report.status,
        }, status=status.HTTP_201_CREATED)



class ReportDetailView(generics.RetrieveAPIView):
    """GET /api/report/<pk>/ — Get detail of a report"""
    queryset = Report.objects.all()
    serializer_class = ReportDetailSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        instance = self.get_object()
        if not request.user.is_staff and instance.reporter_id != request.user.id:
            return Response({'error': 'Không có quyền truy cập báo cáo này.'}, status=403)
        serializer = self.get_serializer(instance)
        return Response(serializer.data)
