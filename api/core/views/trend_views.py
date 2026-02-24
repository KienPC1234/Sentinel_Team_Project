"""ShieldCall VN – Trend Views"""
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
# TRENDS APIs
# ═══════════════════════════════════════════════════════════════════════════

class TrendDailyView(APIView):
    """GET /api/trends/daily — Scam Radar daily trends"""
    permission_classes = [AllowAny]

    def get(self, request):
        days = int(request.query_params.get('days', 7))
        scam_type = request.query_params.get('scam_type')
        since = timezone.now().date() - timedelta(days=days)

        qs = TrendDaily.objects.filter(date__gte=since)
        if scam_type:
            qs = qs.filter(scam_type=scam_type)

        # If no precomputed trends yet, compute from reports
        if not qs.exists():
            trends = (
                Report.objects.filter(created_at__date__gte=since)
                .values('created_at__date', 'scam_type')
                .annotate(count=Count('id'))
                .order_by('created_at__date')
            )
            return Response({
                'trends': [
                    {'date': str(t['created_at__date']),
                     'scam_type': t['scam_type'],
                     'count': t['count']}
                    for t in trends
                ],
                'source': 'computed',
            })

        return Response({
            'trends': TrendDailySerializer(qs, many=True).data,
            'source': 'precomputed',
        })


class TrendHotView(APIView):
    """GET /api/trends/hot — Hot/rising scam targets"""
    permission_classes = [AllowAny]

    def get(self, request):
        since = timezone.now() - timedelta(days=7)
        hot_phones = (
            Report.objects.filter(
                target_type='phone',
                created_at__gte=since,
            )
            .values('target_value', 'scam_type')
            .annotate(report_count=Count('id'))
            .order_by('-report_count')[:10]
        )

        hot_domains = (
            Report.objects.filter(
                target_type='domain',
                created_at__gte=since,
            )
            .values('target_value', 'scam_type')
            .annotate(report_count=Count('id'))
            .order_by('-report_count')[:10]
        )

        results = []
        for item in hot_phones:
            results.append({
                'target_type': 'phone',
                'target_value': item['target_value'],
                'report_count': item['report_count'],
                'risk_change': item['report_count'] * 10,
                'scam_type': item['scam_type'],
            })
        for item in hot_domains:
            results.append({
                'target_type': 'domain',
                'target_value': item['target_value'],
                'report_count': item['report_count'],
                'risk_change': item['report_count'] * 10,
                'scam_type': item['scam_type'],
            })

        results.sort(key=lambda x: x['report_count'], reverse=True)
        return Response({'hot': results[:15]})


