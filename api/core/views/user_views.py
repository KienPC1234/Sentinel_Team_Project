"""ShieldCall VN – User Views"""
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
from django.shortcuts import get_object_or_404
from rest_framework import status, permissions, generics, serializers
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from drf_spectacular.utils import extend_schema

from api.utils.ollama_client import analyze_text_for_scam, generate_response, stream_response

from api.core.models import (
    Domain, BankAccount, Report, ScanEvent, TrendDaily,
    EntityLink, UserAlert, ScamType, RiskLevel, ReportStatus, ForumPost,
)
from api.core.serializers import (
    RegisterSerializer, LoginSerializer, UserSerializer,
    DomainSerializer, BankAccountSerializer,
    ReportCreateSerializer, ReportListSerializer, ReportModerateSerializer,
    ScanPhoneSerializer, ScanMessageSerializer, ScanDomainSerializer,
    ScanAccountSerializer, ScanImageSerializer, ScanEventListSerializer,
    TrendDailySerializer, TrendHotSerializer, UserAlertSerializer,
    ForumPostSerializer,
)

User = get_user_model()
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# USER APIs
# ═══════════════════════════════════════════════════════════════════════════

class UserScansView(generics.ListAPIView):
    """GET /api/user/scans — User scan history"""
    serializer_class = ScanEventListSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        qs = ScanEvent.objects.filter(user=self.request.user)
        scan_type = self.request.query_params.get('type')
        if scan_type:
            qs = qs.filter(scan_type=scan_type)
        return qs[:50]


def _mask_scan_preview(scan: ScanEvent) -> str:
    raw = (scan.normalized_input or scan.raw_input or '').strip()
    if not raw:
        return f'Scan #{scan.id}'

    if scan.scan_type in ('message', 'file', 'audio'):
        compact = re.sub(r'\s+', ' ', raw)
        if len(compact) <= 12:
            return f'{compact[:2]}******'
        return f'{compact[:6]}******{compact[-3:]}'

    if scan.scan_type == 'phone' and len(raw) > 6:
        return f'{raw[:4]}****{raw[-2:]}'

    if scan.scan_type == 'account' and len(raw) > 6:
        return f'{raw[:3]}*****{raw[-3:]}'

    return raw[:140]


class UserScanPickerView(APIView):
    """GET /api/user/scan-picker — scans available for forum reference with filters."""
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: serializers.DictField()})
    def get(self, request):
        scope = (request.query_params.get('scope') or 'mine').strip().lower()
        scan_type = (request.query_params.get('type') or '').strip().lower()
        risk_level = (request.query_params.get('risk_level') or '').strip().upper()
        keyword = (request.query_params.get('q') or '').strip()
        scan_id_raw = (request.query_params.get('scan_id') or '').strip()
        min_risk_raw = (request.query_params.get('min_risk') or '').strip()

        base_qs = ScanEvent.objects.filter(
            Q(user=request.user) | Q(is_public_referable=True)
        )

        if scope == 'mine':
            base_qs = base_qs.filter(user=request.user)
        elif scope == 'public':
            base_qs = base_qs.filter(is_public_referable=True)

        if scan_type:
            base_qs = base_qs.filter(scan_type=scan_type)

        if risk_level:
            base_qs = base_qs.filter(risk_level=risk_level)

        if min_risk_raw.isdigit():
            base_qs = base_qs.filter(risk_score__gte=int(min_risk_raw))

        if keyword:
            base_qs = base_qs.filter(
                Q(normalized_input__icontains=keyword) | Q(raw_input__icontains=keyword)
            )

        if scan_id_raw:
            if not scan_id_raw.isdigit():
                return Response({'results': [], 'count': 0, 'error': 'scan_id không hợp lệ.'}, status=400)
            base_qs = base_qs.filter(id=int(scan_id_raw))

        scans = base_qs.order_by('-created_at')[:100]

        items = []
        for scan in scans:
            items.append({
                'id': scan.id,
                'scan_type': scan.scan_type,
                'status': scan.status,
                'risk_score': int(scan.risk_score or 0),
                'risk_level': scan.risk_level,
                'created_at': scan.created_at.isoformat() if scan.created_at else None,
                'preview': _mask_scan_preview(scan),
                'is_owner': scan.user_id == request.user.id,
                'is_public_referable': bool(scan.is_public_referable),
            })

        return Response({'results': items, 'count': len(items)})


class UserReportsView(generics.ListAPIView):
    """GET /api/user/reports — User report history"""
    serializer_class = ReportListSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Report.objects.filter(reporter=self.request.user)[:50]


class UserAlertsView(APIView):
    """GET/POST /api/user/alerts — User saved alerts"""
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: UserAlertSerializer(many=True)})
    def get(self, request):
        alerts = UserAlert.objects.filter(user=request.user)
        return Response(UserAlertSerializer(alerts, many=True).data)

    @extend_schema(request=UserAlertSerializer, responses={201: UserAlertSerializer})
    def post(self, request):
        serializer = UserAlertSerializer(data=request.data,
                                         context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @extend_schema(request={'application/json': {'type': 'object', 'properties': {'id': {'type': 'integer'}}}}, responses={200: serializers.DictField()})
    def delete(self, request):
        alert_id = request.data.get('id')
        if alert_id:
            UserAlert.objects.filter(user=request.user, id=alert_id).delete()
        return Response({'message': 'Đã xóa cảnh báo.'})


class PublicProfileView(APIView):
    """GET /api/user/profile/<username> — Public profile info"""
    permission_classes = [AllowAny]

    @extend_schema(responses={200: serializers.DictField()})
    def get(self, request, username):
        user = get_object_or_404(User.objects.select_related('profile'), username=username)
        posts = ForumPost.objects.filter(author=user).order_by('-created_at')[:10]
        
        return Response({
            'user': UserSerializer(user).data,
            'posts': ForumPostSerializer(posts, many=True, context={'request': request}).data,
            'stats': {
                'total_posts': ForumPost.objects.filter(author=user).count(),
                'total_reports': Report.objects.filter(reporter=user).count(),
            }
        })
