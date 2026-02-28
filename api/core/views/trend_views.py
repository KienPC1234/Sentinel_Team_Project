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


class ScamRadarStatsView(APIView):
    """GET /api/trends/radar-stats/ — Real-time stats for Scam Radar"""
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            filter_type = request.query_params.get('filter', 'all')
            time_range = request.query_params.get('timeRange', '7d')

            # Determine timeframe
            if time_range == '24h':
                days_delta = 1
            else:
                days_delta = 7
            
            end_date = timezone.now()
            start_date = end_date - timedelta(days=days_delta)
            prev_start_date = start_date - timedelta(days=days_delta)

            # Base query
            base_qs = Report.objects.all()
            if filter_type == 'phone':
                base_qs = base_qs.filter(target_type='phone')
            elif filter_type == 'bank':
                base_qs = base_qs.filter(target_type='bank')
            elif filter_type == 'phishing':
                base_qs = base_qs.filter(Q(target_type='domain') | Q(scam_type='phishing'))

            reports_this_period = base_qs.filter(created_at__gte=start_date).count()
            reports_prev_period = base_qs.filter(
                created_at__gte=prev_start_date, created_at__lt=start_date
            ).count()
            
            pct_change = 0
            if reports_prev_period > 0:
                pct_change = int(((reports_this_period - reports_prev_period) / reports_prev_period) * 100)

            # PhoneNumber created_at check
            from api.phone_security.models import PhoneNumber
            new_phones = PhoneNumber.objects.filter(created_at__gte=start_date).count() if hasattr(PhoneNumber, 'created_at') else 0
            phishing_domains = Domain.objects.filter(created_at__gte=start_date).count()

            # Hot phone numbers (always show phone for this card)
            hot_phones = (
                Report.objects.filter(created_at__gte=start_date, target_type='phone')
                .values('target_value', 'scam_type')
                .annotate(count=Count('id'))
                .order_by('-count')[:5]
            )
            scam_labels = dict(ScamType.choices)
            for hp in hot_phones:
                hp['label'] = scam_labels.get(hp['scam_type'], hp['scam_type'])
                v = hp['target_value']
                hp['masked'] = v[:4] + '****' + v[-2:] if len(v) > 6 else v

            # Recent reports (respect filter)
            recent_reports = []
            for r in base_qs.select_related('reporter').order_by('-created_at')[:5]:
                from django.template.defaultfilters import timesince
                recent_reports.append({
                    'id': r.id,
                    'created_at': r.created_at.isoformat(),
                    'created_at_display': f"{timesince(r.created_at)} trước",
                    'target_value': r.target_value,
                    'target_type_display': r.get_target_type_display(),
                    'scam_type_display': r.get_scam_type_display(),
                    'severity': r.severity,
                    'severity_display': r.get_severity_display(),
                    'scam_type': r.scam_type,
                })

            # Trend chart data
            days_count = 24 if time_range == '24h' else days_delta
            datasets = []
            colors = ['#ff1744', '#ffea00', '#00e5ff']
            
            # Use pre-determined scam types for the chart to keep it consistent
            chart_scam_types = (
                base_qs.filter(created_at__gte=start_date)
                .values('scam_type')
                .annotate(c=Count('id'))
                .order_by('-c')[:3]
            )
            
            labels = []
            if time_range == '24h':
                labels = [f"{(end_date - timedelta(hours=i)).hour}h" for i in range(23, -1, -1)]
            else:
                day_names = ['T2', 'T3', 'T4', 'T5', 'T6', 'T7', 'CN']
                labels = [day_names[(start_date + timedelta(days=i)).weekday()] for i in range(days_delta)]

            for i, tt in enumerate(chart_scam_types):
                st = tt['scam_type']
                data_points = []
                if time_range == '24h':
                    for h in range(23, -1, -1):
                        h_start = end_date - timedelta(hours=h+1)
                        h_end = end_date - timedelta(hours=h)
                        cnt = base_qs.filter(created_at__gte=h_start, created_at__lt=h_end, scam_type=st).count()
                        data_points.append(cnt)
                else:
                    for d in range(days_delta):
                        d_start = start_date + timedelta(days=d)
                        d_end = d_start + timedelta(days=1)
                        cnt = base_qs.filter(created_at__gte=d_start, created_at__lt=d_end, scam_type=st).count()
                        data_points.append(cnt)
                
                datasets.append({
                    'label': scam_labels.get(st, st),
                    'data': data_points,
                    'borderColor': colors[i % len(colors)],
                })

            return Response({
                'reports_this_week': reports_this_period,
                'pct_change': pct_change,
                'new_phones': new_phones,
                'phishing_domains': phishing_domains,
                'hot_phones': hot_phones,
                'recent_reports': recent_reports,
                'trend_data': {
                    'labels': labels,
                    'datasets': datasets
                }
            })
        except Exception as e:
            logger.error(f"Error in ScamRadarStatsView: {e}")
            return Response({'error': str(e)}, status=500)
