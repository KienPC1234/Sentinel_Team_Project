"""
ShieldCall VN – Celery Tasks
MVP spec Section 9: Async tasks
"""
import logging
from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count, F

logger = logging.getLogger(__name__)


@shared_task(name='core.recompute_phone_risk')
def recompute_phone_risk(phone_number: str):
    """
    Recompute risk score for a phone number based on all reports.
    Called when a new report is approved.
    """
    from api.core.models import Report
    try:
        from api.phone_security.models import PhoneNumber
    except ImportError:
        logger.warning('PhoneNumber model not found')
        return

    reports = Report.objects.filter(target_type='phone', target_value=phone_number)
    approved = reports.filter(status='approved').count()
    pending = reports.filter(status='pending').count()
    recent = reports.filter(
        created_at__gte=timezone.now() - timedelta(days=7)
    ).count()

    score = min(100, (approved * 15) + (pending * 5) + (recent * 10))

    PhoneNumber.objects.filter(phone_number=phone_number).update(
        reports_count=approved + pending,
    )
    logger.info(f'Recomputed risk for {phone_number}: score={score}')


@shared_task(name='core.daily_trend_aggregation')
def daily_trend_aggregation(date_str: str = None):
    """
    Aggregate daily scam report counts by type.
    Run daily via celery beat.
    """
    from api.core.models import Report, TrendDaily

    if date_str:
        from datetime import date as dt
        target_date = dt.fromisoformat(date_str)
    else:
        target_date = (timezone.now() - timedelta(days=1)).date()

    # Aggregate reports by scam_type for the given date
    aggregated = (
        Report.objects.filter(created_at__date=target_date)
        .values('scam_type')
        .annotate(count=Count('id'))
    )

    for entry in aggregated:
        TrendDaily.objects.update_or_create(
            date=target_date,
            region='VN',
            scam_type=entry['scam_type'],
            defaults={'count': entry['count']},
        )

    logger.info(f'Trend aggregation for {target_date}: {len(aggregated)} types')


@shared_task(name='core.scan_domain_async')
def scan_domain_async(url: str, user_id: int = None):
    """
    Async domain scan for heavy analysis.
    """
    from api.core.views import _analyze_domain
    from api.core.models import ScanEvent

    result = _analyze_domain(url)

    ScanEvent.objects.create(
        user_id=user_id,
        scan_type='domain',
        raw_input=url,
        normalized_input=result['domain'],
        result_json=result,
        risk_score=result['risk_score'],
        risk_level=result['risk_level'],
    )

    return result


@shared_task(name='core.deduplicate_reports')
def deduplicate_reports():
    """
    Find and flag duplicate reports.
    """
    from api.core.models import Report

    pending = Report.objects.filter(status='pending').order_by('created_at')
    seen = {}
    duplicates = 0

    for report in pending:
        key = f"{report.target_type}:{report.target_value}"
        if key in seen:
            # Mark as duplicate in moderation note
            report.moderation_note = f'Possible duplicate of Report #{seen[key]}'
            report.save(update_fields=['moderation_note'])
            duplicates += 1
        else:
            seen[key] = report.pk

    logger.info(f'Found {duplicates} potential duplicate reports')
@shared_task(name='core.perform_scan_task', bind=True)
def perform_scan_task(self, scan_event_id):
    """
    Unified background task to perform scanning logic (phone, message, domain, email).
    """
    from api.core.models import ScanEvent, ScanStatus, RiskLevel
    from api.utils.vt_client import VTClient
    from api.utils.ollama_client import analyze_text_for_scam
    from api.core.views.scan_views import _phone_risk_score, _analyze_message_text, _analyze_domain
    
    try:
        scan_event = ScanEvent.objects.get(id=scan_event_id)
        scan_event.status = ScanStatus.PROCESSING
        scan_event.job_id = self.request.id
        scan_event.save()

        scan_type = scan_event.scan_type
        raw_input = scan_event.raw_input
        result = {}

        if scan_type == 'phone':
            result = _phone_risk_score(raw_input)
        elif scan_type == 'message':
            result = _analyze_message_text(raw_input)
        elif scan_type == 'domain':
            result = _analyze_domain(raw_input)
        elif scan_type == 'email':
            # Basic email reputation check logic
            from api.utils.normalization import normalize_domain
            email = raw_input.lower().strip()
            ai_res = analyze_text_for_scam(email)
            result = {
                'email': email,
                'risk_score': ai_res.get('risk_score', 0),
                'risk_level': ai_res.get('risk_level', 'SAFE'),
                'details': ['AI Analysis complete']
            }

        scan_event.result_json = result
        scan_event.risk_score = result.get('risk_score', 0)
        scan_event.risk_level = result.get('risk_level', RiskLevel.SAFE)
        scan_event.status = ScanStatus.COMPLETED
        scan_event.save()
        return result

    except Exception as e:
        logger.error(f"Scan task {scan_event_id} failed: {e}")
        ScanEvent.objects.filter(id=scan_event_id).update(
            status=ScanStatus.FAILED,
            result_json={'error': str(e)}
        )
        return {'error': str(e)}


@shared_task(name='core.perform_image_scan_task', bind=True)
def perform_image_scan_task(self, scan_event_id, images_data):
    """
    Background task for multi-image / OCR scans.
    Provides real-time progress updates via Channels.
    """
    from api.core.models import ScanEvent, ScanStatus, RiskLevel
    from api.utils.media_utils import extract_ocr_text
    from api.utils.ollama_client import analyze_text_for_scam
    import base64
    import io
    from asgiref.sync import async_to_sync
    from channels.layers import get_channel_layer

    channel_layer = get_channel_layer()
    group_name = f'scan_{scan_event_id}'
    
    logger.info(f"Task started for event {scan_event_id}. Group: {group_name}")

    def send_progress(message, step='processing', data=None):
        logger.info(f"Progress [{scan_event_id}]: {message} ({step})")
        if channel_layer:
            try:
                async_to_sync(channel_layer.group_send)(
                    group_name,
                    {
                        'type': 'scan_progress',
                        'message': message,
                        'status': 'processing',
                        'step': step,
                        'data': data
                    }
                )
            except Exception as e:
                logger.error(f"WS send error for event {scan_event_id}: {e}")
        else:
            logger.warning(f"No channel layer available for event {scan_event_id}")

    try:
        scan_event = ScanEvent.objects.get(id=scan_event_id)
        scan_event.status = ScanStatus.PROCESSING
        scan_event.job_id = self.request.id
        scan_event.save()

        num_images = len(images_data)
        send_progress(f"Bắt đầu xử lý {num_images} hình ảnh...", step="init")

        full_ocr = ""
        for i, img_b64 in enumerate(images_data):
            try:
                send_progress(f"Đang bóc tách chữ từ ảnh {i+1}/{num_images}...", step="ocr")
                if ',' in img_b64: img_b64 = img_b64.split(',')[1]
                img_bytes = base64.b64decode(img_b64)
                img_file = io.BytesIO(img_bytes)
                text = extract_ocr_text(img_file)
                if text: full_ocr += text + "\n---\n"
            except Exception as e:
                logger.error(f"OCR Error in task for event {scan_event_id}: {e}")
                send_progress(f"Cảnh báo: Lỗi xử lý ảnh {i+1}.", step="ocr_warning")

        if full_ocr:
            send_progress("Đang phân tích nội dung bằng Trí tuệ nhân tạo (AI)...", step="analyzing")
            
            # Retry mechanism for AI analysis
            ai_res = None
            for attempt in range(3):
                try:
                    ai_res = analyze_text_for_scam(full_ocr)
                    if ai_res and (ai_res.get('risk_score') is not None):
                        break
                except:
                    logger.warning(f"AI analysis attempt {attempt+1} failed for event {scan_event_id}")
            
            if not ai_res:
                 ai_res = {'risk_score': 0, 'risk_level': 'SAFE', 'explanation': 'Lỗi phân tích AI sau 3 lần thử.'}
            
            send_progress("AI đã hoàn tất phân tích logic.", step="analyzing")
        else:
            send_progress("Không tìm thấy ký tự khả dụng trong ảnh.", step="analyzing")
            ai_res = {'risk_score': 0, 'risk_level': 'SAFE', 'explanation': 'Không tìm thấy chữ trong ảnh để phân tích.'}

        # Determine level correctly
        score = ai_res.get('risk_score', 0)
        level = RiskLevel.SAFE
        if score >= 80: level = RiskLevel.RED
        elif score >= 50: level = RiskLevel.YELLOW
        elif score >= 20: level = RiskLevel.GREEN

        # Map reason to explanation if needed
        explanation = ai_res.get('explanation') or ai_res.get('reason') or ''

        result = {
            'ocr_text': full_ocr,
            'risk_score': score,
            'risk_level': level,
            'explanation': explanation
        }

        scan_event.result_json = result
        scan_event.risk_score = score
        scan_event.risk_level = level
        scan_event.status = ScanStatus.COMPLETED
        scan_event.save()
        
        send_progress("Hoàn tất quét hình ảnh!", step="completed", data=result)
        return result

    except Exception as e:
        logger.error(f"Image scan task {scan_event_id} failed: {e}")
        send_progress(f"Lỗi hệ thống: {str(e)}", step="error")
        ScanEvent.objects.filter(id=scan_event_id).update(
            status=ScanStatus.FAILED,
            result_json={'error': str(e)}
        )
        return {'error': str(e)}
@shared_task(name='core.perform_web_scrapping_task', bind=True)
def perform_web_scrapping_task(self, scan_event_id, url):
    """
    Task to scrape web content and analyze with AI for scam/phishing signs.
    Provides real-time progress updates via Channels.
    """
    from api.core.models import ScanEvent, ScanStatus, RiskLevel
    from api.utils.ollama_client import analyze_text_for_scam
    import requests
    from bs4 import BeautifulSoup
    from api.utils.normalization import normalize_domain
    from asgiref.sync import async_to_sync
    from channels.layers import get_channel_layer

    channel_layer = get_channel_layer()
    group_name = f'scan_{scan_event_id}'

    def send_progress(message, step='processing', data=None):
        async_to_sync(channel_layer.group_send)(
            group_name,
            {
                'type': 'scan_progress',
                'message': message,
                'status': 'processing',
                'step': step,
                'data': data
            }
        )

    try:
        scan_event = ScanEvent.objects.get(id=scan_event_id)
        scan_event.status = ScanStatus.PROCESSING
        scan_event.job_id = self.request.id
        scan_event.save()

        send_progress("Bắt đầu phân tích website...", step="init")
        
        domain = normalize_domain(url)
        content = ""
        
        # 1. Scrape Content with Retry (HTTPS -> HTTP)
        send_progress(f"Đang thu thập nội dung từ {domain}...", step="scraping")
        
        schemes = ['https://', 'http://']
        if '://' in url:
            # If user provided a scheme, try that first
            base_url = url.split('://', 1)[1]
            chosen_scheme = url.split('://', 1)[0] + '://'
            schemes = [chosen_scheme] + [s for s in schemes if s != chosen_scheme]
        else:
            base_url = url

        success = False
        last_error = ""

        for scheme in schemes:
            target_url = scheme + base_url
            try:
                send_progress(f"Đang thử kết nối qua {scheme.upper()}...", step="scraping")
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
                resp = requests.get(target_url, headers=headers, timeout=10, verify=False)
                if resp.status_code == 200:
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    for s in soup(['script', 'style']): s.decompose()
                    content = soup.get_text(separator=' ', strip=True)
                    success = True
                    send_progress(f"Đã lấy được nội dung qua {scheme.upper()}.", step="scraping")
                    break
                else:
                    last_error = f"Status {resp.status_code}"
            except Exception as e:
                last_error = str(e)
                logger.warning(f"Failed to scrape {target_url}: {e}")

        if not success:
            send_progress(f"Không thể truy cập website: {last_error}", step="error")
            content = f"Could not fetch content. Last error: {last_error}"

        # 2. AI Analysis
        send_progress("Đang phân tích nội dung bằng Trí tuệ nhân tạo (AI)...", step="analyzing")
        ai_input = f"Domain: {domain}\nURL: {url}\n\nPage Content Snapshot:\n{content[:5000]}"
        ai_res = analyze_text_for_scam(ai_input)
        send_progress("AI đã hoàn tất phân tích.", step="analyzing")

        result = {
            'domain': domain,
            'url': url,
            'risk_score': ai_res.get('risk_score', 0),
            'risk_level': ai_res.get('risk_level', 'SAFE'),
            'explanation': ai_res.get('explanation') or ai_res.get('reason') or '',
            'scam_type': ai_res.get('scam_type') or ai_res.get('type') or 'other',
            'content_length': len(content)
        }

        scan_event.result_json = result
        scan_event.risk_score = result['risk_score']
        scan_event.risk_level = result['risk_level']
        scan_event.status = ScanStatus.COMPLETED
        scan_event.save()
        
        send_progress("Hoàn tất quét website!", step="completed", data=result)
        return result

    except Exception as e:
        logger.error(f"Web scan task {scan_event_id} failed: {e}")
        send_progress(f"Lỗi hệ thống: {str(e)}", step="error")
        ScanEvent.objects.filter(id=scan_event_id).update(
            status=ScanStatus.FAILED,
            result_json={'error': str(e)}
        )
        return {'error': str(e)}
