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
            now = timezone.now()

            # Determine timeframe
            if time_range == '24h':
                start_date = now - timedelta(hours=24)
                prev_start_date = now - timedelta(hours=48)
                steps = 24
                step_delta = timedelta(hours=1)
                date_fmt = '%H:%M'
            elif time_range == '30d':
                start_date = now - timedelta(days=30)
                prev_start_date = now - timedelta(days=60)
                steps = 30
                step_delta = timedelta(days=1)
                date_fmt = '%d/%m'
            elif time_range == '1y':
                start_date = now - timedelta(days=365)
                prev_start_date = now - timedelta(days=730)
                steps = 12
                # Special handling for month steps
                step_delta = None 
                date_fmt = '%m/%Y'
            else: # 7d
                start_date = now - timedelta(days=7)
                prev_start_date = now - timedelta(days=14)
                steps = 7
                step_delta = timedelta(days=1)
                date_fmt = '%d/%m'
            
            # Base query
            base_qs = Report.objects.all()
            if filter_type == 'phone':
                base_qs = base_qs.filter(target_type='phone')
            elif filter_type == 'bank':
                base_qs = base_qs.filter(target_type='account') # target_type is 'account' not 'bank'
            elif filter_type == 'phishing':
                base_qs = base_qs.filter(Q(target_type='domain') | Q(scam_type='phishing'))
            # Filter 'all' does not need additional filtering

            reports_this_period = base_qs.filter(created_at__gte=start_date).count()
            reports_prev_period = base_qs.filter(
                created_at__gte=prev_start_date, created_at__lt=start_date
            ).count()
            
            pct_change = 0
            if reports_prev_period > 0:
                pct_change = int(((reports_this_period - reports_prev_period) / reports_prev_period) * 100)

            # Metrics
            # For specific metrics, we might want global stats or filtered stats?
            # Let's keep them global for the top cards as they represent system health
            # OR make them respect the filter? 
            # The UI labels are "Báo cáo hôm nay/tuần này", "Số mới", "Domain". 
            # If we filter by 'bank', showing 'new phones' might be irrelevant but showing 'new bank accounts' would be better.
            # For simplicity, let's keep them global or semi-related.
            
            from api.phone_security.models import PhoneNumber
            new_phones = PhoneNumber.objects.filter(created_at__gte=start_date).count() if hasattr(PhoneNumber, 'created_at') else 0
            phishing_domains = Domain.objects.filter(created_at__gte=start_date).count()

            # Hot entities (respect filter)
            # If filter is 'bank', show hot bank accounts.
            target_filter = 'phone'
            if filter_type == 'bank': target_filter = 'account'
            if filter_type == 'phishing': target_filter = 'domain'
            
            # If filter is 'all', default to phone for hot list (or maybe mix?)
            # The UI expects "hot_phones".
            # Let's just stick to phone if 'all' or 'phone', else specific.
            
            hot_qs = Report.objects.filter(created_at__gte=start_date)
            if filter_type == 'all':
                hot_qs = hot_qs.filter(target_type='phone')
            else:
                hot_qs = hot_qs.filter(target_type=target_filter)

            hot_items = (
                hot_qs
                .values('target_value', 'scam_type')
                .annotate(count=Count('id'))
                .order_by('-count')[:5]
            )
            
            scam_labels = dict(ScamType.choices)
            processed_hot_items = []
            for item in hot_items:
                item['label'] = scam_labels.get(item['scam_type'], item['scam_type'])
                v = item['target_value']
                # Masking
                if target_filter == 'phone':
                     item['masked'] = v[:4] + '****' + v[-2:] if len(v) > 6 else v
                elif target_filter == 'account':
                     item['masked'] = v[:3] + '*****' + v[-3:] if len(v) > 6 else v
                else:
                     item['masked'] = v # Domains usually shown fully or truncated
                
                processed_hot_items.append(item)

            # Recent reports (respect filter)
            recent_data = []
            # Get latest 5 reports matching the filter
            recent_qs = base_qs.select_related('reporter').order_by('-created_at')[:5]
            
            for r in recent_qs:
                # Use timesince for "X minutes ago"
                from django.utils.timesince import timesince
                recent_data.append({
                    'id': r.id,
                    'created_at': r.created_at.isoformat(),
                    'created_at_display': f"{timesince(r.created_at, now).split(',')[0]} trước",
                    'target_value': r.target_value,
                    'target_type': r.target_type,
                    'target_type_display': r.get_target_type_display(),
                    'scam_type': r.scam_type,
                    'scam_type_display': r.get_scam_type_display(),
                    'severity': r.severity,
                    'severity_display': r.get_severity_display(),
                    'reporter_name': r.reporter.username if r.reporter else 'Ẩn danh'
                })

            # Trend chart data
            datasets = []
            colors = ['#ff1744', '#ffea00', '#00e5ff']
            
            # Top 3 scam types in this filtered view
            chart_scam_types = (
                base_qs.filter(created_at__gte=start_date)
                .values('scam_type')
                .annotate(c=Count('id'))
                .order_by('-c')[:3]
            )
            
            # Generate labels
            labels = []
            if time_range == '24h':
                # Use local time for display if possible, but server time is UTC usually.
                # Assuming simple string format is enough.
                labels = [(now - timedelta(hours=i)).strftime('%H:%M') for i in range(steps)][::-1]
            elif time_range == '30d':
                labels = [(now - timedelta(days=i)).strftime('%d/%m') for i in range(steps)][::-1]
            elif time_range == '1y':
                # Simplified 12 months
                labels = []
                for i in range(steps):
                    # Go to 1st of month for consistency
                    d = (now.replace(day=1) - timedelta(days=30*i)).replace(day=1)
                    labels.append(d.strftime('%m/%Y'))
                labels = labels[::-1]
            else: # 7d
                labels = [(now - timedelta(days=i)).strftime('%d/%m') for i in range(steps)][::-1]

            # Build datasets
            chart_data_map = {} # Cache for query optimization if needed
            
            for i, tt in enumerate(chart_scam_types):
                st = tt['scam_type']
                data_points = []
                
                if time_range == '1y':
                     for j in range(steps):
                         # Logic matches labels generation: steps-1-j is index from 0..11 (oldest..newest)
                         # But wait, label generation loop: i goes 0..11 (newest..oldest), then reversed.
                         # So labels[0] corresponds to i=11 (oldest).
                         # Here j goes 0..11.
                         # We want data_points[0] to match labels[0].
                         
                         # index backward from now
                         idx = steps - 1 - j
                         d_curr = (now.replace(day=1) - timedelta(days=30*idx))
                         
                         m_start = d_curr.replace(day=1, hour=0, minute=0, second=0)
                         # End of month
                         if m_start.month == 12:
                             m_end = m_start.replace(year=m_start.year+1, month=1)
                         else:
                             m_end = m_start.replace(month=m_start.month+1)
                         
                         cnt = base_qs.filter(created_at__gte=m_start, created_at__lt=m_end, scam_type=st).count()
                         data_points.append(cnt)
                elif time_range == '24h':
                     for j in range(steps):
                         # j=0 -> idx=23 (oldest hour)
                         idx = steps - 1 - j
                         h_end = now - timedelta(hours=idx) 
                         h_start = h_end - timedelta(hours=1)
                         cnt = base_qs.filter(created_at__gte=h_start, created_at__lt=h_end, scam_type=st).count()
                         data_points.append(cnt)
                else:
                     # Days (7d, 30d)
                     for j in range(steps):
                         idx = steps - 1 - j
                         # labels[j] is date for (now - idx days)
                         # We need to filter by that specific date
                         
                         target_date = (now - timedelta(days=idx)).date()
                         
                         # Note: SQLite date lookup can be tricky with timezones, but Django usually handles __date well
                         cnt = base_qs.filter(created_at__date=target_date, scam_type=st).count()
                         data_points.append(cnt)
                
                datasets.append({
                    'label': scam_labels.get(st, st),
                    'data': data_points,
                    'borderColor': colors[i % len(colors)],
                })

            return Response({
                'reports_this_week': reports_this_period, # Label says week but it is "this period"
                'pct_change': pct_change,
                'new_phones': new_phones,
                'phishing_domains': phishing_domains,
                'hot_phones': processed_hot_items,
                'recent_reports': recent_data,
                'trend_data': {
                    'labels': labels,
                    'datasets': datasets
                }
            })
        except Exception as e:
            logger.error(f"Error in ScamRadarStatsView: {e}")
            return Response({'error': str(e)}, status=500)
