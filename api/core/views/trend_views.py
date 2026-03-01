"""ShieldCall VN – Trend Views"""
import logging
from datetime import timedelta

from django.db.models import Count, Q
from django.utils import timezone
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from api.core.models import Domain, Report, ReportStatus, RiskLevel, ScamType, ScanEvent, ScanStatus, TrendDaily
from api.core.serializers import TrendDailySerializer

logger = logging.getLogger(__name__)


class TrendDailyView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        days = int(request.query_params.get('days', 7))
        scam_type = request.query_params.get('scam_type')
        since = timezone.now().date() - timedelta(days=days)

        qs = TrendDaily.objects.filter(date__gte=since)
        if scam_type:
            qs = qs.filter(scam_type=scam_type)

        if not qs.exists():
            trends = (
                Report.objects.filter(created_at__date__gte=since)
                .values('created_at__date', 'scam_type')
                .annotate(count=Count('id'))
                .order_by('created_at__date')
            )
            return Response({
                'trends': [
                    {
                        'date': str(t['created_at__date']),
                        'scam_type': t['scam_type'],
                        'count': t['count'],
                    }
                    for t in trends
                ],
                'source': 'computed',
            })

        return Response({'trends': TrendDailySerializer(qs, many=True).data, 'source': 'precomputed'})


class TrendHotView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        since = timezone.now() - timedelta(days=7)
        hot_phones = (
            Report.objects.filter(target_type='phone', created_at__gte=since)
            .values('target_value', 'scam_type')
            .annotate(report_count=Count('id'))
            .order_by('-report_count')[:10]
        )
        hot_domains = (
            Report.objects.filter(target_type='domain', created_at__gte=since)
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
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            filter_type = request.query_params.get('filter', 'all')
            time_range = request.query_params.get('timeRange', '7d')
            now = timezone.now()

            if time_range == '24h':
                start_date = now - timedelta(hours=24)
                prev_start_date = now - timedelta(hours=48)
                steps = 24
            elif time_range == '30d':
                start_date = now - timedelta(days=30)
                prev_start_date = now - timedelta(days=60)
                steps = 30
            elif time_range == '1y':
                start_date = now - timedelta(days=365)
                prev_start_date = now - timedelta(days=730)
                steps = 12
            else:
                start_date = now - timedelta(days=7)
                prev_start_date = now - timedelta(days=14)
                steps = 7

            reports_qs = Report.objects.filter(status=ReportStatus.APPROVED)
            scans_qs = ScanEvent.objects.filter(status=ScanStatus.COMPLETED, risk_level__in=[RiskLevel.RED, RiskLevel.YELLOW])

            if filter_type == 'phone':
                reports_qs = reports_qs.filter(target_type='phone')
                scans_qs = scans_qs.filter(scan_type='phone')
            elif filter_type == 'bank':
                reports_qs = reports_qs.filter(target_type='account')
                scans_qs = scans_qs.filter(scan_type='account')
            elif filter_type == 'phishing':
                reports_qs = reports_qs.filter(Q(target_type='domain') | Q(scam_type='phishing'))
                scans_qs = scans_qs.filter(scan_type__in=['domain', 'email', 'qr'])

            reports_this_period = reports_qs.filter(created_at__gte=start_date).count() + scans_qs.filter(created_at__gte=start_date).count()
            reports_prev_period = reports_qs.filter(created_at__gte=prev_start_date, created_at__lt=start_date).count() + scans_qs.filter(created_at__gte=prev_start_date, created_at__lt=start_date).count()

            pct_change = 0
            if reports_prev_period > 0:
                pct_change = int(((reports_this_period - reports_prev_period) / reports_prev_period) * 100)

            from api.phone_security.models import PhoneNumber
            new_phones = PhoneNumber.objects.filter(created_at__gte=start_date).count() if hasattr(PhoneNumber, 'created_at') else 0
            phishing_domains = Domain.objects.filter(created_at__gte=start_date).count()

            scam_labels = dict(ScamType.choices)
            hot_counter = {}

            def mask_target(target_type, value):
                if target_type == 'phone':
                    return value[:4] + '****' + value[-2:] if len(value) > 6 else value
                if target_type == 'account':
                    return value[:3] + '*****' + value[-3:] if len(value) > 6 else value
                return value

            for item in reports_qs.filter(created_at__gte=start_date).values('target_type', 'target_value', 'scam_type'):
                target_type = item.get('target_type') or 'unknown'
                target_value = (item.get('target_value') or '').strip()
                if not target_value:
                    continue
                key = f"report:{target_type}:{target_value}"
                if key not in hot_counter:
                    hot_counter[key] = {
                        'target_type': target_type,
                        'target_value': target_value,
                        'masked': mask_target(target_type, target_value),
                        'count': 0,
                        'label': scam_labels.get(item.get('scam_type'), item.get('scam_type') or 'Báo cáo xác nhận'),
                        'source': 'report',
                    }
                hot_counter[key]['count'] += 1

            for item in scans_qs.filter(created_at__gte=start_date).values('scan_type', 'normalized_input'):
                scan_type = item.get('scan_type') or 'unknown'
                normalized_input = (item.get('normalized_input') or '').strip()
                if not normalized_input:
                    continue
                mapped_type = 'phone' if scan_type == 'phone' else ('account' if scan_type == 'account' else 'domain')
                key = f"scan:{scan_type}:{normalized_input}"
                if key not in hot_counter:
                    hot_counter[key] = {
                        'target_type': mapped_type,
                        'target_value': normalized_input,
                        'masked': mask_target(mapped_type, normalized_input),
                        'count': 0,
                        'label': f"AI scan {scan_type}",
                        'source': 'scan_ai',
                    }
                hot_counter[key]['count'] += 1

            processed_hot_items = sorted(hot_counter.values(), key=lambda x: x['count'], reverse=True)[:8]

            from django.utils.timesince import timesince
            recent_data = []
            for report in reports_qs.select_related('reporter').order_by('-created_at')[:10]:
                recent_data.append({
                    'id': f"report-{report.id}",
                    'created_at': report.created_at,
                    'created_at_display': f"{timesince(report.created_at, now).split(',')[0]} trước",
                    'target_value': report.target_value,
                    'target_type': report.target_type,
                    'target_type_display': report.get_target_type_display(),
                    'scam_type': report.scam_type,
                    'scam_type_display': report.get_scam_type_display(),
                    'severity': report.severity,
                    'severity_display': report.get_severity_display(),
                    'reporter_name': report.reporter.username if report.reporter else 'Ẩn danh',
                    'source': 'report',
                    'source_display': 'Báo cáo đã duyệt',
                })

            scan_type_display = {
                'phone': 'Số điện thoại',
                'domain': 'Website/URL',
                'account': 'Tài khoản ngân hàng',
                'message': 'Tin nhắn',
                'qr': 'QR Code',
                'email': 'Email',
                'audio': 'Âm thanh',
                'file': 'Tệp tin',
            }
            for scan in scans_qs.select_related('user').order_by('-created_at')[:10]:
                recent_data.append({
                    'id': f"scan-{scan.id}",
                    'created_at': scan.created_at,
                    'created_at_display': f"{timesince(scan.created_at, now).split(',')[0]} trước",
                    'target_value': scan.normalized_input or scan.raw_input,
                    'target_type': scan.scan_type,
                    'target_type_display': scan_type_display.get(scan.scan_type, scan.scan_type),
                    'scam_type': 'ai_detected',
                    'scam_type_display': 'AI phát hiện rủi ro',
                    'severity': 'high' if scan.risk_level == RiskLevel.RED else 'medium',
                    'severity_display': 'Nguy hiểm' if scan.risk_level == RiskLevel.RED else 'Cảnh báo',
                    'reporter_name': scan.user.username if scan.user else 'Hệ thống',
                    'source': 'scan_ai',
                    'source_display': 'Kết quả quét AI',
                })

            recent_data = sorted(recent_data, key=lambda x: x['created_at'], reverse=True)[:8]
            for item in recent_data:
                item['created_at'] = item['created_at'].isoformat()

            if time_range == '24h':
                labels = [(now - timedelta(hours=i)).strftime('%H:%M') for i in range(steps)][::-1]
            elif time_range == '30d':
                labels = [(now - timedelta(days=i)).strftime('%d/%m') for i in range(steps)][::-1]
            elif time_range == '1y':
                labels = []
                for i in range(steps):
                    d = (now.replace(day=1) - timedelta(days=30 * i)).replace(day=1)
                    labels.append(d.strftime('%m/%Y'))
                labels = labels[::-1]
            else:
                labels = [(now - timedelta(days=i)).strftime('%d/%m') for i in range(steps)][::-1]

            def count_interval(qs, interval_idx):
                if time_range == '1y':
                    month_cursor = now.replace(day=1) - timedelta(days=30 * interval_idx)
                    month_start = month_cursor.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
                    if month_start.month == 12:
                        month_end = month_start.replace(year=month_start.year + 1, month=1)
                    else:
                        month_end = month_start.replace(month=month_start.month + 1)
                    return qs.filter(created_at__gte=month_start, created_at__lt=month_end).count()
                if time_range == '24h':
                    hour_end = now - timedelta(hours=interval_idx)
                    hour_start = hour_end - timedelta(hours=1)
                    return qs.filter(created_at__gte=hour_start, created_at__lt=hour_end).count()
                target_day = (now - timedelta(days=interval_idx)).date()
                return qs.filter(created_at__date=target_day).count()

            confirmed_series = []
            ai_series = []
            for j in range(steps):
                idx = steps - 1 - j
                confirmed_series.append(count_interval(reports_qs, idx))
                ai_series.append(count_interval(scans_qs, idx))

            return Response({
                'reports_this_week': reports_this_period,
                'pct_change': pct_change,
                'new_phones': new_phones,
                'phishing_domains': phishing_domains,
                'hot_phones': processed_hot_items,
                'recent_reports': recent_data,
                'trend_data': {
                    'labels': labels,
                    'datasets': [
                        {'label': 'Báo cáo đã xác nhận', 'data': confirmed_series, 'borderColor': '#ff1744'},
                        {'label': 'Kết quả quét AI rủi ro', 'data': ai_series, 'borderColor': '#00e5ff'},
                    ],
                },
            })
        except Exception as e:
            logger.error(f"Error in ScamRadarStatsView: {e}")
            return Response({'error': str(e)}, status=500)


class ScanLookupView(APIView):
    """
    GET /api/v1/scan/lookup/?q=...&type=all&risk=all&page=1
    Unified search across ScanEvent + Report for the lookup page.
    """
    permission_classes = [AllowAny]

    SCAN_TYPE_MAP = {
        'phone': ['phone'],
        'account': ['account'],
        'domain': ['domain'],
        'email': ['email'],
        'message': ['message'],
        'audio': ['audio'],
        'file': ['file'],
        'qr': ['qr'],
    }

    def get(self, request):
        from django.utils.timesince import timesince

        q = request.query_params.get('q', '').strip()
        type_filter = request.query_params.get('type', 'all')
        risk_filter = request.query_params.get('risk', 'all')
        page = max(1, int(request.query_params.get('page', 1)))
        per_page = 20

        now = timezone.now()
        results = []

        # --- ScanEvent search ---
        scan_qs = ScanEvent.objects.filter(status=ScanStatus.COMPLETED)
        if q:
            scan_qs = scan_qs.filter(
                Q(raw_input__icontains=q) | Q(normalized_input__icontains=q)
            )
        if type_filter != 'all' and type_filter in self.SCAN_TYPE_MAP:
            scan_qs = scan_qs.filter(scan_type__in=self.SCAN_TYPE_MAP[type_filter])
        if risk_filter == 'high':
            scan_qs = scan_qs.filter(risk_level=RiskLevel.RED)
        elif risk_filter == 'medium':
            scan_qs = scan_qs.filter(risk_level=RiskLevel.YELLOW)
        elif risk_filter == 'low':
            scan_qs = scan_qs.filter(risk_level__in=[RiskLevel.GREEN, RiskLevel.SAFE])

        scan_type_labels = {
            'phone': 'Số điện thoại', 'domain': 'Website/URL',
            'account': 'Tài khoản ngân hàng', 'message': 'Tin nhắn',
            'qr': 'QR / Ảnh', 'email': 'Email', 'audio': 'Âm thanh', 'file': 'Tệp tin',
        }

        for scan in scan_qs.order_by('-created_at')[:200]:
            risk_display = 'Nguy hiểm' if scan.risk_level == RiskLevel.RED else ('Cảnh báo' if scan.risk_level == RiskLevel.YELLOW else 'An toàn')
            results.append({
                'id': scan.id,
                'kind': 'scan',
                'type': scan.scan_type,
                'type_display': scan_type_labels.get(scan.scan_type, scan.scan_type),
                'target': scan.normalized_input or scan.raw_input,
                'risk_score': scan.risk_score,
                'risk_level': scan.risk_level,
                'risk_display': risk_display,
                'created_at': scan.created_at.isoformat(),
                'time_ago': f"{timesince(scan.created_at, now).split(',')[0]} trước",
                'url': f'/scan/status/{scan.id}/',
            })

        # --- Report search ---
        report_qs = Report.objects.filter(status=ReportStatus.APPROVED)
        if q:
            report_qs = report_qs.filter(
                Q(target_value__icontains=q) | Q(description__icontains=q) |
                Q(scammer_phone__icontains=q) | Q(scammer_bank_account__icontains=q)
            )
        if type_filter != 'all':
            mapped = type_filter
            if type_filter == 'domain':
                mapped = 'domain'
            report_qs = report_qs.filter(target_type=mapped)
        if risk_filter == 'high':
            report_qs = report_qs.filter(severity__in=['high', 'critical'])
        elif risk_filter == 'medium':
            report_qs = report_qs.filter(severity='medium')
        elif risk_filter == 'low':
            report_qs = report_qs.filter(severity='low')

        scam_labels = dict(ScamType.choices)
        target_labels = {
            'phone': 'Số điện thoại', 'domain': 'Website/URL',
            'account': 'Tài khoản ngân hàng', 'message': 'Tin nhắn',
            'qr': 'QR Code', 'email': 'Email',
        }
        type_to_page = {
            'phone': '/scan/phone/',
            'domain': '/scan/website/',
            'account': '/scan/bank/',
            'email': '/scan/email/',
            'message': '/scan/message/',
            'qr': '/scan/qr/',
        }

        for report in report_qs.order_by('-created_at')[:200]:
            risk_map = {'critical': 'RED', 'high': 'RED', 'medium': 'YELLOW', 'low': 'GREEN'}
            risk_level = risk_map.get(report.severity, 'YELLOW')
            risk_display = 'Nguy hiểm' if risk_level == 'RED' else ('Cảnh báo' if risk_level == 'YELLOW' else 'An toàn')
            results.append({
                'id': report.id,
                'kind': 'report',
                'type': report.target_type,
                'type_display': target_labels.get(report.target_type, report.target_type),
                'target': report.target_value,
                'risk_score': {'critical': 95, 'high': 80, 'medium': 50, 'low': 20}.get(report.severity, 50),
                'risk_level': risk_level,
                'risk_display': risk_display,
                'scam_type': scam_labels.get(report.scam_type, report.scam_type),
                'created_at': report.created_at.isoformat(),
                'time_ago': f"{timesince(report.created_at, now).split(',')[0]} trước",
                'url': type_to_page.get(report.target_type, '/scam-radar/'),
            })

        # Sort by time (newest first)
        results.sort(key=lambda x: x['created_at'], reverse=True)

        total = len(results)
        start = (page - 1) * per_page
        paginated = results[start:start + per_page]

        return Response({
            'results': paginated,
            'total': total,
            'page': page,
            'per_page': per_page,
            'has_next': start + per_page < total,
        })
