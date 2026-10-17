"""ShieldCall VN – Trend Views"""
import logging
import re
from datetime import datetime, time, timedelta

from django.db.models import Count, Max, Q
from django.utils import timezone
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from api.core.models import Domain, Report, ReportStatus, RiskLevel, ScamType, ScanEvent, ScanStatus, TrendDaily
from api.core.serializers import TrendDailySerializer
from api.utils.trust_guard import verdict_tone, verdict_display

logger = logging.getLogger(__name__)


class TrendDailyView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            days = int(request.query_params.get('days', 7))
        except (TypeError, ValueError):
            days = 7
        # Chặn biên trên để tránh truy vấn/khối lượng dữ liệu quá lớn.
        days = max(1, min(days, 365))
        scam_type = request.query_params.get('scam_type')
        since = timezone.now().date() - timedelta(days=days)

        qs = TrendDaily.objects.filter(date__gte=since)
        if scam_type:
            qs = qs.filter(scam_type=scam_type)

        if not qs.exists():
            cur_tz = timezone.get_current_timezone()
            since_start = timezone.make_aware(datetime.combine(since, time.min), cur_tz)
            trends = (
                Report.objects.filter(created_at__gte=since_start)
                .values('scam_type')
                .annotate(count=Count('id'))
            )
            return Response({
                'trends': [
                    {
                        'date': since.isoformat(),
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
        target_filter = request.query_params.get('type', '').strip()
        types = [target_filter] if target_filter in ['phone', 'domain', 'account', 'email'] else ['phone', 'domain', 'account', 'email']

        # Chi dem bao cao DA DUYET (truoc day ca pending/rejected deu len
        # "hot" public). Gom 1 query/nhom thay vi 1 query/item (N+1).
        results = []
        for t in types:
            hot_items = (
                Report.objects.filter(target_type=t, status=ReportStatus.APPROVED, created_at__gte=since)
                .values('target_value', 'scam_type')
                .annotate(report_count=Count('id'), last_at=Max('created_at'))
                .order_by('-report_count')[:50]
            )
            hot_list = list(hot_items)
            rep_map = {}
            if hot_list:
                _ors = Q()
                for _hi in hot_list:
                    _ors |= Q(target_type=t, target_value=_hi['target_value'], scam_type=_hi['scam_type'])
                for _rep in Report.objects.filter(
                    _ors, status=ReportStatus.APPROVED
                ).select_related('reporter').order_by('-created_at'):
                    _k = (_rep.target_value, _rep.scam_type)
                    if _k not in rep_map:
                        rep_map[_k] = _rep
            for item in hot_list:
                rep = rep_map.get((item['target_value'], item['scam_type']))
                results.append({
                    'id': rep.id if rep else None,
                    'target_type': t,
                    'target_value': item['target_value'],
                    'report_count': item['report_count'],
                    'risk_change': min(100, item['report_count'] * 10),
                    'scam_type': item['scam_type'],
                    'scam_type_display': rep.get_scam_type_display() if rep else item['scam_type'],
                    'severity': rep.severity if rep else '',
                    'source': 'user' if (rep and rep.reporter_id) else 'scan_ai',
                    'created_at': item['last_at'].isoformat() if item['last_at'] else '',
                    'created_at_display': item['last_at'].strftime('%d/%m/%Y') if item['last_at'] else '—',
                })

        results.sort(key=lambda x: x['report_count'], reverse=True)
        limit = 50 if target_filter else 20
        return Response({'hot': results[:limit]})


class ScamRadarStatsView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            filter_type = request.query_params.get('filter', 'all')
            time_range = request.query_params.get('timeRange', '7d')
            # Endpoint nang (~30-80 query + quet values toan cuc) ma frontend
            # poll lien tuc -> cache 120s theo (filter, timeRange).
            from django.core.cache import cache as _cache
            _ck = f'radar_stats_v1:{filter_type}:{time_range}'
            _hit = _cache.get(_ck)
            if _hit is not None:
                return Response(_hit)
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
            reports_base = reports_qs
            scans_base = scans_qs

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

            new_phones = (
                reports_base.filter(created_at__gte=start_date, target_type='phone').count() +
                scans_base.filter(created_at__gte=start_date, scan_type='phone').count()
            )
            phishing_domains = (
                reports_base.filter(created_at__gte=start_date).filter(Q(target_type='domain') | Q(scam_type='phishing')).count() +
                scans_base.filter(created_at__gte=start_date, scan_type__in=['domain', 'email', 'qr', 'message']).count()
            )

            scam_labels = dict(ScamType.choices)
            hot_counter = {}
            # Ẩn hoàn toàn mục tiêu nhạy cảm (nội dung tin nhắn, QR, ĐỊA CHỈ EMAIL,
            # tên tệp, âm thanh) khỏi radar công khai — tránh rò rỉ PII. Trước đây
            # 'email' bị lọt vì không nằm trong danh sách này.
            sensitive_scan_types = {'message', 'qr', 'email', 'file', 'audio'}
            sensitive_placeholder = '[Nội dung nhạy cảm đã được ẩn]'

            # Chi xet 10000 bao cao moi nhat de gioi han memory (DB lon dan
            # ma van dung cho hau het item nong).
            reported_risky_targets = {
                ((target_type or '').strip(), (target_value or '').strip())
                for target_type, target_value in Report.objects.filter(
                    status=ReportStatus.APPROVED,
                    target_type__in=['phone', 'account']
                ).order_by('-created_at').values_list('target_type', 'target_value')[:10000]
                if (target_type or '').strip() and (target_value or '').strip()
            }

            def mask_target(target_type, value):
                if target_type in sensitive_scan_types:
                    return sensitive_placeholder

                if (target_type in {'phone', 'account'} and
                    (target_type, value) in reported_risky_targets):
                    return value

                if target_type == 'phone':
                    return value[:4] + '****' + value[-2:] if len(value) > 6 else value
                if target_type == 'account':
                    return value[:3] + '*****' + value[-3:] if len(value) > 6 else value
                return value

            def map_scan_target_type(scan_type):
                if scan_type == 'phone':
                    return 'phone'
                if scan_type == 'account':
                    return 'account'
                if scan_type in {'domain', 'email', 'message', 'qr', 'audio', 'file'}:
                    return scan_type
                return 'domain'

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
                mapped_type = map_scan_target_type(scan_type)
                safe_value = (
                    sensitive_placeholder if mapped_type in sensitive_scan_types
                    else normalized_input
                )
                key = f"scan:{scan_type}:{normalized_input}"
                if key not in hot_counter:
                    hot_counter[key] = {
                        'target_type': mapped_type,
                        # Không trả raw target_value cho loại nhạy cảm (email/message/qr/file/audio).
                        'target_value': safe_value,
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
                report_target_value = (report.target_value or '').strip()
                recent_data.append({
                    'id': f"report-{report.id}",
                    'created_at': report.created_at,
                    'created_at_display': f"{timesince(report.created_at, now).split(',')[0]} trước",
                    'target_value': mask_target(report.target_type, report_target_value),
                    'target_type': report.target_type,
                    'target_type_display': report.get_target_type_display(),
                    'scam_type': report.scam_type,
                    'scam_type_display': report.get_scam_type_display(),
                    'severity': report.severity,
                    'severity_display': report.get_severity_display(),
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
                scan_target_type = map_scan_target_type(scan.scan_type)
                scan_target_value = (scan.normalized_input or scan.raw_input or '').strip()
                recent_data.append({
                    'id': f"scan-{scan.id}",
                    'created_at': scan.created_at,
                    'created_at_display': f"{timesince(scan.created_at, now).split(',')[0]} trước",
                    'target_value': mask_target(scan_target_type, scan_target_value),
                    'target_type': scan.scan_type,
                    'target_type_display': scan_type_display.get(scan.scan_type, scan.scan_type),
                    'scam_type': 'ai_detected',
                    'scam_type_display': 'AI phát hiện rủi ro',
                    'severity': 'high' if scan.risk_level == RiskLevel.RED else 'medium',
                    'severity_display': 'Nguy hiểm' if scan.risk_level == RiskLevel.RED else 'Cảnh báo',
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
                _base = now.replace(day=1)
                for i in range(steps):
                    _m = _base.month - i
                    _y = _base.year
                    while _m <= 0:
                        _m += 12
                        _y -= 1
                    labels.append(f'{_m:02d}/{_y}')
                labels = labels[::-1]
            else:
                labels = [(now - timedelta(days=i)).strftime('%d/%m') for i in range(steps)][::-1]

            def count_interval(qs, interval_idx):
                if time_range == '1y':
                    _m2 = now.month - interval_idx
                    _y2 = now.year
                    while _m2 <= 0:
                        _m2 += 12
                        _y2 -= 1
                    month_start = now.replace(year=_y2, month=_m2, day=1, hour=0, minute=0, second=0, microsecond=0)
                    if month_start.month == 12:
                        month_end = month_start.replace(year=month_start.year + 1, month=1)
                    else:
                        month_end = month_start.replace(month=month_start.month + 1)
                    return qs.filter(created_at__gte=month_start, created_at__lt=month_end).count()
                if time_range == '24h':
                    hour_end = now - timedelta(hours=interval_idx)
                    hour_start = hour_end - timedelta(hours=1)
                    return qs.filter(created_at__gte=hour_start, created_at__lt=hour_end).count()
                cur_tz = timezone.get_current_timezone()
                target_day = (now.astimezone(cur_tz) - timedelta(days=interval_idx)).date()
                day_start = timezone.make_aware(datetime.combine(target_day, time.min), cur_tz)
                day_end = timezone.make_aware(datetime.combine(target_day, time.max), cur_tz)
                return qs.filter(created_at__range=(day_start, day_end)).count()

            confirmed_series = []
            ai_series = []
            for j in range(steps):
                idx = steps - 1 - j
                confirmed_series.append(count_interval(reports_qs, idx))
                ai_series.append(count_interval(scans_qs, idx))

            payload = {
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
            }
            _cache.set(_ck, payload, timeout=120)
            return Response(payload)
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
        'social': ['social', 'message'],
        'crypto': ['crypto', 'message'],
    }

    def get(self, request):
        from django.utils.timesince import timesince

        q = request.query_params.get('q', '').strip()
        type_filter = request.query_params.get('type', 'all')
        risk_filter = request.query_params.get('risk', 'all')
        try:
            page = max(1, int(request.query_params.get('page', 1)))
        except (TypeError, ValueError):
            page = 1
        per_page = 20

        now = timezone.now()
        results = []

        # --- ScanEvent search ---
        if request.user.is_authenticated:
            scan_qs = ScanEvent.objects.filter(
                status=ScanStatus.COMPLETED
            ).filter(
                Q(user=request.user) | Q(is_public_referable=True)
            )
        else:
            scan_qs = ScanEvent.objects.filter(
                status=ScanStatus.COMPLETED,
                is_public_referable=True,
            )
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
            rj = scan.result_json if isinstance(scan.result_json, dict) else {}
            raw_target = scan.normalized_input or scan.raw_input
            if scan.scan_type in ('message', 'file', 'audio'):
                compact = re.sub(r'\s+', ' ', str(raw_target or '')).strip()
                if len(compact) <= 12:
                    safe_target = f'{compact[:2]}******' if len(compact) > 2 else '******'
                else:
                    safe_target = f'{compact[:6]}******{compact[-3:]}'
            elif scan.scan_type == 'phone' and len(str(raw_target or '')) > 6:
                t_str = str(raw_target or '')
                safe_target = f'{t_str[:4]}****{t_str[-2:]}'
            elif scan.scan_type == 'account' and len(str(raw_target or '')) > 6:
                t_str = str(raw_target or '')
                safe_target = f'{t_str[:3]}*****{t_str[-3:]}'
            else:
                safe_target = str(raw_target or '')[:500]

            results.append({
                'id': scan.id,
                'kind': 'scan',
                'type': scan.scan_type,
                'type_display': scan_type_labels.get(scan.scan_type, scan.scan_type),
                'target': safe_target,
                'risk_score': scan.risk_score,
                'risk_level': scan.risk_level,
                'risk_display': verdict_display(rj),
                'verdict_tone': verdict_tone(rj),
                'created_at': scan.created_at.isoformat(),
                'time_ago': f"{timesince(scan.created_at, now).split(',')[0]} trước",
                'url': f'/scan/status/{scan.id}/',
            })

        # --- Report search ---
        report_qs = Report.objects.filter(status=ReportStatus.APPROVED)
        if q:
            report_qs = report_qs.filter(
                Q(target_value__icontains=q) | Q(description__icontains=q) |
                Q(scammer_phone__icontains=q) | Q(scammer_bank_account__icontains=q) |
                Q(scammer_bank_name__icontains=q) | Q(scammer_name__icontains=q) |
                Q(scammer_social__icontains=q) | Q(ocr_text__icontains=q) |
                Q(ai_analysis__icontains=q) | Q(custom_fields__icontains=q)
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
            'file': 'Tệp tin / APK độc hại', 'audio': 'Audio / Deepfake',
            'social': 'Mạng xã hội', 'crypto': 'Ví Crypto / Web3',
        }
        type_to_page = {
            'phone': '/scan/phone/',
            'domain': '/scan/website/',
            'account': '/scan/bank/',
            'email': '/scan/email/',
            'message': '/scan/message/',
            'qr': '/scan/qr/',
            'file': '/scan/file/',
            'audio': '/scan/audio/',
            'social': '/scan/lookup/',
            'crypto': '/scan/lookup/',
        }

        for report in report_qs.select_related('reporter').order_by('-created_at')[:200]:
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
                'severity': report.severity,
                'scam_type': scam_labels.get(report.scam_type, report.scam_type),
                'scam_type_display': scam_labels.get(report.scam_type, report.scam_type),
                # Khong lo username nguoi bao cao tren endpoint public (truoc day
                # lo toan bo username; chi giu nhan an danh de dem so nguoi dong gop).
                'description': report.description or '',
                'scammer_name': report.scammer_name,
                'scammer_phone': report.scammer_phone,
                'scammer_bank_account': report.scammer_bank_account,
                'scammer_bank_name': report.scammer_bank_name,
                'scammer_social': getattr(report, 'scammer_social', ''),
                'custom_fields': getattr(report, 'custom_fields', {}) or {},
                'evidence_url': report.evidence_file.url if report.evidence_file else None,
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


class PublicStatsView(APIView):
    """GET /api/v1/stats/public/ — số liệu công khai cho trang chủ (không hardcode)."""
    permission_classes = [AllowAny]

    def get(self, request):
        from django.core.cache import cache
        cached = cache.get('public_stats_v1')
        if cached is not None:
            return Response(cached)
        total_scans = ScanEvent.objects.count()
        scam_detected = ScanEvent.objects.filter(
            risk_level__in=[RiskLevel.RED, RiskLevel.YELLOW]
        ).count()
        data = {
            'total_scans': total_scans,
            'scam_detected': scam_detected,
            'total_reports': Report.objects.filter(status='approved').count(),
        }
        cache.set('public_stats_v1', data, 300)
        return Response(data)
