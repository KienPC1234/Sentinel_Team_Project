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


class UserReportsView(generics.ListAPIView):
    """GET /api/user/reports — User report history"""
    serializer_class = ReportListSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Report.objects.filter(reporter=self.request.user)[:50]


class UserAlertsView(APIView):
    """GET/POST /api/user/alerts — User saved alerts"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        alerts = UserAlert.objects.filter(user=request.user)
        return Response(UserAlertSerializer(alerts, many=True).data)

    def post(self, request):
        serializer = UserAlertSerializer(data=request.data,
                                         context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def delete(self, request):
        alert_id = request.data.get('id')
        if alert_id:
            UserAlert.objects.filter(user=request.user, id=alert_id).delete()
        return Response({'message': 'Đã xóa cảnh báo.'})


