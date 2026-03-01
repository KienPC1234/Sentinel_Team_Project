"""ShieldCall VN – Report Views"""
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
        # Turnstile Verification
        cf_token = request.data.get('cf-turnstile-response')
        if not verify_turnstile_token(cf_token):
             return Response({'error': 'Xác minh anti-spam không hợp lệ. Vui lòng thử lại.'}, status=400)

        serializer = ReportCreateSerializer(data=request.data,
                                            context={'request': request})
        serializer.is_valid(raise_exception=True)
        report = serializer.save()

        # Save additional evidence images (multi-upload)
        evidence_files = request.FILES.getlist('evidence_images')
        for ef in evidence_files:
            ReportEvidence.objects.create(report=report, image=ef)

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

        # --- AI and OCR Integration ---
        # 1. OCR (if evidence exists)
        if report.evidence_file:
            try:
                ocr_text = extract_ocr_text(report.evidence_file)
                if ocr_text:
                    report.ocr_text = ocr_text
                    report.save()
            except Exception as e:
                logger.error(f"[ReportOCR] Error: {e}")

        # 2. AI Analysis
        try:
            full_context = f"Target Type: {report.target_type}\n"
            full_context += f"Target Value: {report.target_value}\n"
            full_context += f"Scam Type: {report.scam_type}\n"
            full_context += f"Description: {report.description}\n"
            if report.ocr_text:
                full_context += f"OCR Evidence Text: {report.ocr_text}\n"
            
            # Use general scam analysis
            analysis = analyze_text_for_scam(full_context)
            report.ai_analysis = analysis
            report.save()
        except Exception as e:
            logger.error(f"[ReportAI] Analysis error: {e}")

        return Response({
            'message': 'Báo cáo đã được gửi thành công! Cảm ơn bạn đã giúp cộng đồng.',
            'report_id': report.pk,
            'status': report.status,
        }, status=status.HTTP_201_CREATED)



class ReportDetailView(generics.RetrieveAPIView):
    """GET /api/report/<pk>/ — Get detail of a report"""
    queryset = Report.objects.all()
    serializer_class = ReportDetailSerializer
    permission_classes = [AllowAny]
