"""
ShieldCall VN – Celery Tasks
MVP spec Section 9: Async tasks
"""
import logging
import re
import json
from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count, F

import logging
from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count, F

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
if not logger.handlers:
    fh = logging.FileHandler('llm_access.log')
    fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    logger.addHandler(fh)

@shared_task(name='core.rebuild_scam_vector_index')
def rebuild_scam_vector_index():
    """
    Rebuilds the FAISS vector index for RAG from Articles and LearnLessons.
    """
    try:
        from api.utils.vector_db import vector_db
        vector_db.rebuild_index(force_cpu=True)
        logger.info("Successfully rebuilt scam vector index.")
    except Exception as e:
        logger.error(f"Error rebuilding vector index: {e}")


@shared_task(name='core.recompute_phone_risk')
def recompute_phone_risk(phone_number: str):
    """
    Recompute risk score using the Hybrid Scoring Engine.
    Updates PhoneNumber model with new risk level, score, and trust metrics.
    """
    try:
        from api.phone_security.models import PhoneNumber, PhoneRiskLevel
        from api.core.views.scan_views import _phone_risk_score
    except ImportError:
        logger.warning('Dependencies not found for recompute_phone_risk')
        return

    # Calculate Score using the unified engine
    result = _phone_risk_score(phone_number)
    
    # Map API level string directly to Enum
    level_map = {
        'SAFE': PhoneRiskLevel.SAFE,
        'GREEN': PhoneRiskLevel.GREEN,
        'YELLOW': PhoneRiskLevel.YELLOW,
        'RED': PhoneRiskLevel.RED
    }
    risk_enum = level_map.get(result['risk_level'], PhoneRiskLevel.SAFE)

    # Update DB
    PhoneNumber.objects.update_or_create(
        phone_number=phone_number,
        defaults={
            'risk_level': risk_enum,
            'reports_count': result['report_count'],
            'trust_score': result.get('trust_score', 0),
            'risk_label': f"Score: {result['risk_score']}",
            # If carrier or other enriched data is available in result, save it here
        }
    )
    logger.info(f'Recomputed risk for {phone_number}: score={result["risk_score"]}')


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
    from api.core.views.scan_views import _analyze_domain
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


def _notify_scan_complete(scan_event, title_suffix=''):
    """
    Send push notification (OneSignal + WebSocket) when a scan completes.
    Only sends if the scan was initiated by an authenticated user.
    """
    try:
        if not scan_event.user_id:
            return  # Anonymous scan, no push target

        from api.utils.push_service import push_service

        risk_level = getattr(scan_event, 'risk_level', 'SAFE')
        risk_score = getattr(scan_event, 'risk_score', 0)

        level_labels = {
            'RED': '🔴 Nguy hiểm',
            'YELLOW': '🟡 Cẩn thận',
            'GREEN': '🟢 An toàn',
            'SAFE': '🟢 An toàn',
        }
        level_text = level_labels.get(risk_level, '🟢 An toàn')

        title = f"Kết quả quét: {level_text}"
        message = f"{title_suffix} — Điểm rủi ro: {risk_score}/100"
        url = f"/scan/status/{scan_event.id}/" if hasattr(scan_event, 'id') else None

        push_service.send_push(
            user_id=scan_event.user_id,
            title=title,
            message=message,
            url=url,
            notification_type='scan_result'
        )
        logger.info(f"[Push] Sent scan notification to user {scan_event.user_id} for event {scan_event.id}")
    except Exception as e:
        logger.warning(f"[Push] Failed to send scan notification: {e}")


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
            ai_res = None
            try:
                ai_res = analyze_text_for_scam(email)
            except Exception as _ai_exc:
                logger.warning(f"perform_scan_task: AI analysis failed for email ({_ai_exc}), using fallback.")
            if not ai_res:
                ai_res = {'risk_score': 0, 'risk_level': 'SAFE', 'explanation': 'AI không khả dụng.'}
            ai_notice = ai_res.get('ai_notice')
            details = [ai_res.get('explanation', 'Phân tích hoàn tất.')]
            if ai_notice and ai_notice not in details:
                details.insert(0, ai_notice)
            result = {
                'email': email,
                'risk_score': ai_res.get('risk_score', 0),
                'risk_level': ai_res.get('risk_level', 'SAFE'),
                'details': details,
                'ai_available': ai_res.get('explanation') != 'AI không khả dụng.',
                'ai_retry_used': ai_res.get('ai_retry_used', False),
                'ai_retry_count': ai_res.get('ai_retry_count', 0),
                'ai_notice': ai_notice,
            }

        scan_event.result_json = result
        scan_event.risk_score = result.get('risk_score', 0)
        scan_event.risk_level = result.get('risk_level', RiskLevel.SAFE)
        scan_event.status = ScanStatus.COMPLETED
        scan_event.save()

        type_labels = {'phone': 'số điện thoại', 'message': 'tin nhắn', 'domain': 'website', 'email': 'email'}
        _notify_scan_complete(scan_event, f"Quét {type_labels.get(scan_type, scan_type)} hoàn tất")
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
    Uses extract_ocr_with_boxes for annotated bounding-box images.
    """
    from api.core.models import ScanEvent, ScanStatus, RiskLevel
    from api.utils.media_utils import extract_ocr_with_boxes
    from api.utils.ollama_client import analyze_text_for_scam
    import base64
    import io
    import re
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
        all_qr_contents = []
        annotated_images = []
        all_phones = set()
        all_urls = set()
        all_emails = set()
        all_bank_accounts = set()

        for i, img_b64 in enumerate(images_data):
            try:
                send_progress(f"Đang phân tích ảnh {i+1}/{num_images} (OCR + QR)...", step="ocr")
                if ',' in img_b64: img_b64 = img_b64.split(',')[1]
                img_bytes = base64.b64decode(img_b64)
                img_file = io.BytesIO(img_bytes)
                img_file.name = f"image_{i}.png"
                img_file.size = len(img_bytes)
                
                ocr_result = extract_ocr_with_boxes(img_file)
                text = ocr_result.get("text", "")
                qr_contents = ocr_result.get("qr_contents", [])
                annotated_b64 = ocr_result.get("annotated_image_b64", "")
                
                if text:
                    full_ocr += text + "\n---\n"
                    send_progress(f"Ảnh {i+1}: Trích xuất {len(text)} ký tự", step="ocr_ok")
                else:
                    send_progress(f"Ảnh {i+1}: Không phát hiện text", step="ocr_ok")
                
                if qr_contents:
                    all_qr_contents.extend(qr_contents)
                    send_progress(f"Ảnh {i+1}: Phát hiện {len(qr_contents)} mã QR", step="qr_ok")
                
                if annotated_b64:
                    annotated_images.append(annotated_b64)
                
                # Extract entities from OCR text
                if text:
                    phones = re.findall(r'(?:\+84|0)\d[\d\s\-\.]{7,12}\d', text)
                    all_phones.update(p.replace(' ', '').replace('-', '').replace('.', '') for p in phones)
                    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text)
                    all_urls.update(urls)
                    emails = re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', text)
                    all_emails.update(emails)
                    bank_accs = re.findall(r'\b\d{8,19}\b', text)
                    # Filter out likely non-bank numbers (too short or phone-like)
                    for acc in bank_accs:
                        if len(acc) >= 8 and not any(acc == p for p in all_phones):
                            all_bank_accounts.add(acc)
                
            except Exception as e:
                logger.error(f"OCR Error in task for event {scan_event_id}: {e}")
                send_progress(f"Cảnh báo: Lỗi xử lý ảnh {i+1}.", step="ocr_warning")

        # Also extract entities from QR contents
        for qr in all_qr_contents:
            urls_in_qr = re.findall(r'https?://[^\s<>"]+', qr)
            all_urls.update(urls_in_qr)

        if full_ocr or all_qr_contents:
            # Build analysis text including QR contents
            analysis_text = full_ocr
            if all_qr_contents:
                analysis_text += "\n[QR CODE CONTENTS]:\n" + "\n".join(all_qr_contents) + "\n"
            
            send_progress("Đang phân tích nội dung bằng Trí tuệ nhân tạo (AI)...", step="analyzing")
            
            # Retry mechanism for AI analysis
            ai_res = None
            for attempt in range(3):
                try:
                    ai_res = analyze_text_for_scam(analysis_text, use_web_search=True)
                    if ai_res and (ai_res.get('risk_score') is not None):
                        break
                except:
                    logger.warning(f"AI analysis attempt {attempt+1} failed for event {scan_event_id}")
            
            if not ai_res:
                 ai_res = {'risk_score': 0, 'risk_level': 'SAFE', 'explanation': 'Lỗi phân tích AI sau 3 lần thử.'}

            ai_notice = ai_res.get('ai_notice')
            if ai_notice:
                send_progress(ai_notice, step="ai_retry_notice")
            
            send_progress("AI đã hoàn tất phân tích logic.", step="analyzing")
        else:
            send_progress("Không tìm thấy ký tự khả dụng trong ảnh.", step="analyzing")
            ai_res = {'risk_score': 0, 'risk_level': 'SAFE', 'explanation': 'Không tìm thấy chữ hoặc mã QR trong ảnh để phân tích.'}

        # Determine level correctly
        score = ai_res.get('risk_score', 0)
        level = RiskLevel.SAFE
        if score >= 80: level = RiskLevel.RED
        elif score >= 50: level = RiskLevel.YELLOW
        elif score >= 20: level = RiskLevel.GREEN

        # Map reason to explanation if needed
        explanation = ai_res.get('explanation') or ai_res.get('reason') or ''

        # Build entities dict
        entities = {}
        if all_phones:
            entities['phones'] = list(all_phones)[:20]
        if all_urls:
            entities['urls'] = list(all_urls)[:20]
        if all_emails:
            entities['emails'] = list(all_emails)[:10]
        if all_bank_accounts:
            entities['bank_accounts'] = list(all_bank_accounts)[:10]

        result = {
            'ocr_text': full_ocr,
            'risk_score': score,
            'risk_level': level,
            'explanation': explanation,
            'ai_notice': ai_res.get('ai_notice', ''),
            'ai_retry_used': ai_res.get('ai_retry_used', False),
            'ai_retry_count': ai_res.get('ai_retry_count', 0),
            'web_sources': ai_res.get('web_sources', []),
            'web_context': ai_res.get('web_context', ''),
            'qr_contents': list(set(all_qr_contents)),
            'entities': entities if entities else None,
            'annotated_images': annotated_images,
            'annotated_image': annotated_images[0] if annotated_images else '',
        }

        # Save to DB without large annotated images (they bloat the JSON field)
        scan_event.result_json = {k: v for k, v in result.items() if k not in ('annotated_images', 'annotated_image')}
        scan_event.risk_score = score
        scan_event.risk_level = level
        scan_event.status = ScanStatus.COMPLETED
        scan_event.save()
        
        send_progress("Hoàn tất quét hình ảnh!", step="completed", data=result)
        _notify_scan_complete(scan_event, 'Quét hình ảnh/QR hoàn tất')
        return result

    except Exception as e:
        logger.error(f"Image scan task {scan_event_id} failed: {e}")
        send_progress(f"Lỗi hệ thống: {str(e)}", step="error")
        ScanEvent.objects.filter(id=scan_event_id).update(
            status=ScanStatus.FAILED,
            result_json={'error': str(e)}
        )
        return {'error': str(e)}


@shared_task(name='core.perform_audio_scan_task', bind=True)
def perform_audio_scan_task(self, scan_event_id, audio_file_path):
    """
    Background task for audio transcription + AI scam analysis.
    Uses Faster-Whisper for speech-to-text, then Ollama for risk assessment.
    Provides real-time progress updates via Channels.
    """
    from api.core.models import ScanEvent, ScanStatus, RiskLevel
    from api.utils.media_utils import transcribe_audio, analyze_audio_risk
    from api.utils.ollama_client import analyze_text_for_scam
    from asgiref.sync import async_to_sync
    from channels.layers import get_channel_layer
    import os

    channel_layer = get_channel_layer()
    group_name = f'scan_{scan_event_id}'

    def send_progress(message, step='processing', data=None):
        logger.info(f"Audio [{scan_event_id}]: {message} ({step})")
        if channel_layer:
            try:
                async_to_sync(channel_layer.group_send)(
                    group_name,
                    {
                        'type': 'scan_progress',
                        'message': message,
                        'status': 'processing',
                        'step': step,
                        'data': data,
                    }
                )
            except Exception as e:
                logger.error(f"WS send error for audio event {scan_event_id}: {e}")

    try:
        scan_event = ScanEvent.objects.get(id=scan_event_id)
        scan_event.status = ScanStatus.PROCESSING
        scan_event.job_id = self.request.id
        scan_event.save()

        send_progress("Đang tải mô hình nhận diện giọng nói...", step="init")

        # ── Step 1: Transcribe audio ──
        send_progress("Đang chuyển đổi giọng nói thành văn bản...", step="transcribing")

        # Open the saved temp file for transcription
        with open(audio_file_path, 'rb') as audio_fp:
            from django.core.files.uploadedfile import InMemoryUploadedFile
            import io
            audio_bytes = audio_fp.read()
            audio_file_obj = io.BytesIO(audio_bytes)
            audio_file_obj.name = os.path.basename(audio_file_path)
            transcription_result = transcribe_audio(audio_file_obj)

        transcript = transcription_result.get('transcript', '')
        language = transcription_result.get('language', 'unknown')
        duration = transcription_result.get('duration', 0)
        segments = transcription_result.get('segments', [])

        if transcript:
            send_progress(
                f"Đã nhận diện {len(segments)} đoạn • {duration:.1f}s • Ngôn ngữ: {language}",
                step="transcribed",
                data={'transcript': transcript, 'language': language, 'duration': duration}
            )
        else:
            send_progress("Không nhận diện được giọng nói trong file âm thanh.", step="transcribed")

        # ── Step 2: AI Scam Analysis on transcript ──
        if transcript:
            send_progress("Đang phân tích dấu hiệu lừa đảo trong đoạn hội thoại bằng AI...", step="analyzing")

            ai_res = None
            for attempt in range(3):
                try:
                    ai_res = analyze_text_for_scam(transcript, use_web_search=True)
                    if ai_res and ai_res.get('risk_score') is not None:
                        break
                except Exception:
                    logger.warning(f"AI analysis attempt {attempt+1} failed for audio event {scan_event_id}")

            if not ai_res:
                ai_res = {
                    'risk_score': 0,
                    'risk_level': 'SAFE',
                    'explanation': 'Lỗi phân tích AI sau 3 lần thử.',
                }

            ai_notice = ai_res.get('ai_notice')
            if ai_notice:
                send_progress(ai_notice, step="ai_retry_notice")

            send_progress("AI đã hoàn tất phân tích dấu hiệu lừa đảo.", step="analyzed")
        else:
            ai_res = {
                'risk_score': 0,
                'risk_level': 'SAFE',
                'explanation': 'Không tìm thấy giọng nói để phân tích.',
            }

        # ── Step 3: Determine risk level and save ──
        score = ai_res.get('risk_score', 0)
        level = RiskLevel.SAFE
        if score >= 80:
            level = RiskLevel.RED
        elif score >= 50:
            level = RiskLevel.YELLOW
        elif score >= 20:
            level = RiskLevel.GREEN

        explanation = ai_res.get('explanation') or ai_res.get('reason') or ''

        result = {
            'transcript': transcript,
            'language': language,
            'duration': duration,
            'segments': segments,
            'risk_score': score,
            'risk_level': level,
            'explanation': explanation,
            'ai_notice': ai_res.get('ai_notice', ''),
            'ai_retry_used': ai_res.get('ai_retry_used', False),
            'ai_retry_count': ai_res.get('ai_retry_count', 0),
            'web_sources': ai_res.get('web_sources', []),
            'web_context': ai_res.get('web_context', ''),
        }

        scan_event.result_json = result
        scan_event.risk_score = score
        scan_event.risk_level = level
        scan_event.status = ScanStatus.COMPLETED
        scan_event.save()

        send_progress("Hoàn tất quét âm thanh!", step="completed", data=result)
        _notify_scan_complete(scan_event, 'Quét âm thanh hoàn tất')

        # Cleanup temp file
        try:
            if os.path.exists(audio_file_path):
                os.remove(audio_file_path)
        except Exception:
            pass

        return result

    except Exception as e:
        logger.error(f"Audio scan task {scan_event_id} failed: {e}")
        send_progress(f"Lỗi hệ thống: {str(e)}", step="error")
        ScanEvent.objects.filter(id=scan_event_id).update(
            status=ScanStatus.FAILED,
            result_json={'error': str(e)},
        )
        # Cleanup temp file
        try:
            if os.path.exists(audio_file_path):
                os.remove(audio_file_path)
        except Exception:
            pass
        return {'error': str(e)}


@shared_task(name='core.perform_web_scrapping_task', bind=True)
def perform_web_scrapping_task(self, scan_event_id, url):
    """
    Task to scrape web content and analyze with AI for scam/phishing signs.
    Provides real-time progress updates via Channels.
    """
    from api.core.models import ScanEvent, ScanStatus, RiskLevel
    from api.utils.ollama_client import analyze_text_for_scam
    import whois
    import dns.resolver
    from ipwhois import IPWhois, IPDefinedError
    from api.utils.normalization import normalize_domain
    from asgiref.sync import async_to_sync
    from channels.layers import get_channel_layer

    channel_layer = get_channel_layer()
    group_name = f'scan_{scan_event_id}'

    def send_progress(message, step='processing', data=None):
        if not channel_layer:
            logger.warning(f"[WebScan] Event {scan_event_id}: No channel layer; progress not sent")
            return
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
            logger.warning(f"[WebScan] Event {scan_event_id}: Progress send failed: {e}")

    def _decode_html_response(http_response):
        html_text = http_response.text or ''
        if any(marker in html_text for marker in ('Ã', 'Â', 'á»', '\ufffd')):
            try:
                encoding = http_response.apparent_encoding or 'utf-8'
                html_text = http_response.content.decode(encoding, errors='replace')
            except Exception:
                pass
        return html_text

    def _repair_mojibake(text: str) -> str:
        if not text:
            return ''
        repaired = text.strip()
        if any(marker in repaired for marker in ('Ã', 'Â', 'á»', 'Ä')):
            try:
                repaired_candidate = repaired.encode('latin-1', errors='ignore').decode('utf-8', errors='ignore').strip()
                if repaired_candidate:
                    repaired = repaired_candidate
            except Exception:
                pass
        return re.sub(r'\s+', ' ', repaired)

    try:
        scan_event = ScanEvent.objects.get(id=scan_event_id)
        scan_event.status = ScanStatus.PROCESSING
        scan_event.job_id = self.request.id
        scan_event.save()

        send_progress(f"Bắt đầu phân tích website...", step="init")
        
        domain = normalize_domain(url)
        logger.info(f"[WebScan] Event {scan_event_id}: Starting analysis for URL: {url};  Normalized: {domain}")
        send_progress(f"Tên miền: {domain}", step="init")

        content = ""
        network_risk_score = 0
        network_details = []

        # --- NETWORK ANALYSIS (Deep) ---
        send_progress("Đang kiểm tra thông tin tên miền (WHOIS, DNS)...", step="network_analysis")
        try:
            # 1. WHOIS Age
            try:
                send_progress("Đang tra cứu WHOIS (tuổi tên miền, chủ sở hữu)...", step="whois")
                w = whois.whois(domain)
                creation_date = w.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                if creation_date:
                    # Robust date conversion
                    if hasattr(creation_date, 'date'):
                         creation_dt = creation_date.date()
                    else:
                         creation_dt = creation_date # Assume it's already date or compatible

                    age_days = (timezone.now().date() - creation_dt).days
                    
                    if age_days < 14:
                        network_risk_score = max(network_risk_score, 75) # Very high risk if new
                        network_details.append(f"Tên miền quá mới (đăng ký {age_days} ngày trước)")
                        send_progress(f"⚠️ Tên miền rất mới: chỉ {age_days} ngày tuổi - dấu hiệu nghi ngờ!", step="whois_warning")
                        logger.info(f"[WebScan] Event {scan_event_id}: Domain too new ({age_days} days)")
                    elif age_days < 30:
                         network_risk_score += 10
                         network_details.append(f"Tên miền mới (đăng ký {age_days} ngày trước)")
                         send_progress(f"Tên miền khá mới: {age_days} ngày tuổi", step="whois_info")
                         logger.info(f"[WebScan] Event {scan_event_id}: Domain new ({age_days} days)")
                    else:
                         send_progress(f"WHOIS: Tên miền {age_days} ngày tuổi", step="whois_ok")
            except Exception as e:
                logger.warning(f"[WebScan] Event {scan_event_id}: WHOIS lookup failed: {e}")

            # 2. DNS Checks (Resolvers)
            try:
                send_progress("Đang kiểm tra DNS (MX records)...", step="dns")
                # Check for MX records (Phishing sites often lack email setup)
                try:
                    dns.resolver.resolve(domain, 'MX')
                    has_mx = True
                    logger.info(f"[WebScan] Event {scan_event_id}: MX records found")
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    has_mx = False
                    # Only penalize if it pretends to be a bank/corp
                    network_risk_score += 5
                    logger.info(f"[WebScan] Event {scan_event_id}: No MX records found")
                    
                if not has_mx:
                    network_risk_score += 7
            except Exception:
                pass

            # 3. ASN / IP Reputation
            try:
                send_progress("Đang kiểm tra ASN / IP Reputation...", step="asn")
                import socket
                ip = socket.gethostbyname(domain)
                obj = IPWhois(ip)
                try:
                    res = obj.lookup_rdap(depth=1)
                    asn_desc = res.get('asn_description', '') or res.get('asn_registry', '')
                    
                    # Check for known bad ASNs or cheap hosting
                    suspicious_keywords = ['Hetzner', 'DigitalOcean', 'Choopa', 'Namecheap', 'Vultr', 'Linode', 'Hostinger']
                    if any(k.lower() in asn_desc.lower() for k in suspicious_keywords):
                        # Cheap hosting itself isn't bad, but phishing often uses it
                        network_risk_score += 7
                        network_details.append(f"Hosting provider: {asn_desc}")
                        send_progress(f"Hosting: {asn_desc} (thường dùng cho phishing)", step="asn_warning")
                        logger.info(f"[WebScan] Event {scan_event_id}: Suspicious/Cheap hosting provider found: {asn_desc}")
                    else:
                        send_progress(f"IP/ASN: {asn_desc}", step="asn_ok")
                except IPDefinedError:
                     pass
            except Exception as e:
                logger.warning(f"[WebScan] Event {scan_event_id}: ASN lookup failed: {e}")

            send_progress(f"Đã hoàn tất kiểm tra mạng. Điểm rủi ro mạng: {network_risk_score}", step="network_analysis")
            logger.info(f"[WebScan] Event {scan_event_id}: Network scan complete. Score: {network_risk_score}")

        except Exception as e:
            logger.error(f"[WebScan] Event {scan_event_id}: Deep network scan failed: {e}")
            send_progress(f"Lỗi kiểm tra mạng: {str(e)}", step="network_warning")
        
        # 1. Fetch Content using requests + BeautifulSoup (replacing Ollama web_fetch)
        send_progress(f"Đang thu thập nội dung từ {domain}...", step="scraping")
        
        # Build full URL if scheme not provided
        if '://' not in url:
            target_url = f"https://{url}"
        else:
            target_url = url

        fetch_success = False
        page_title = ""
        
        try:
            import requests as http_requests
            from bs4 import BeautifulSoup

            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'vi-VN,vi;q=0.9,en;q=0.8',
            }
            resp = http_requests.get(target_url, headers=headers, timeout=15, verify=True, allow_redirects=True)
            resp.raise_for_status()

            html_text = _decode_html_response(resp)
            soup = BeautifulSoup(html_text, 'html.parser')

            # Extract title
            title_tag = soup.find('title')
            page_title = _repair_mojibake(title_tag.get_text(strip=True) if title_tag else '')

            # Remove script/style/nav/footer for cleaner content
            for tag in soup(['script', 'style', 'nav', 'footer', 'header', 'noscript', 'iframe']):
                tag.decompose()

            content = soup.get_text(separator='\n', strip=True)
            if content:
                fetch_success = True
                send_progress(f"Đã tải nội dung website ({len(content)} ký tự)", step="scraping_ok")
                logger.info(f"[WebScan] Event {scan_event_id}: Fetched content via requests+BS4 ({len(content)} chars)")

            # Try HTTP fallback if HTTPS failed and no content
            if not fetch_success and target_url.startswith('https://'):
                http_url = target_url.replace('https://', 'http://', 1)
                resp = http_requests.get(http_url, headers=headers, timeout=15, verify=False, allow_redirects=True)
                resp.raise_for_status()
                html_text = _decode_html_response(resp)
                soup = BeautifulSoup(html_text, 'html.parser')
                title_tag = soup.find('title')
                page_title = _repair_mojibake(title_tag.get_text(strip=True) if title_tag else '')
                for tag in soup(['script', 'style', 'nav', 'footer', 'header', 'noscript', 'iframe']):
                    tag.decompose()
                content = soup.get_text(separator='\n', strip=True)
                if content:
                    fetch_success = True
                    logger.info(f"[WebScan] Event {scan_event_id}: Fetched content via HTTP fallback ({len(content)} chars)")
        except Exception as e:
            logger.warning(f"[WebScan] Event {scan_event_id}: Web fetch failed: {e}")

        if not fetch_success:
            # ❌ Mark fetch failure but CONTINUE analysis
            send_progress(f"❌ Không thể thu thập nội dung website (tiếp tục phân tích...)", step="scraping_warning")
            content = ""
            network_details.append("❌ Không thể truy cập nội dung website")
            logger.warning(f"[WebScan] Event {scan_event_id}: Failed to fetch content, continuing with network analysis only")

        # 2. AI Analysis
        send_progress("Đang phân tích nội dung bằng Trí tuệ nhân tạo (AI)...", step="analyzing")
        # Keep the content snapshot short so the prompt stays within the local
        # model's context window.  Web-search enrichment is skipped here because
        # this task already performs dedicated network/WHOIS intelligence above.
        content_section = f"Page Content Snapshot:\n{content[:2500]}" if content else "(Không có nội dung - không thể truy cập website)"
        ai_input = (
            f"Domain: {domain}\nURL: {url}\n"
            f"Page Title: {page_title}\n" if page_title else f"Domain: {domain}\nURL: {url}\n"
        ) + (
            f"Network findings: {', '.join(network_details) if network_details else 'none'}\n\n"
            f"{content_section}"
        )
        logger.info(f"[WebScan] Event {scan_event_id}: Sending to AI ({len(ai_input)} chars)")

        try:
            import time
            from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

            ai_timeout_seconds = 600
            keepalive_every_seconds = 10
            executor = ThreadPoolExecutor(max_workers=1)
            future = executor.submit(analyze_text_for_scam, ai_input, None, True)
            start_time = time.time()
            last_keepalive = 0
            ai_res = None

            while True:
                try:
                    ai_res = future.result(timeout=5)
                    break
                except FutureTimeout:
                    elapsed = time.time() - start_time
                    if elapsed - last_keepalive >= keepalive_every_seconds:
                        send_progress("AI đang phân tích...", step="ping")
                        last_keepalive = elapsed
                    if elapsed >= ai_timeout_seconds:
                        ai_res = {
                            'is_scam': False,
                            'risk_score': 0,
                            'indicators': [],
                            'explanation': 'AI phân tích quá thời gian cho phép.'
                        }
                        future.cancel()
                        break
            executor.shutdown(wait=False, cancel_futures=True)
        except Exception as _ai_exc:
            import traceback
            logger.warning(traceback.format_exc())
            logger.warning(f"[WebScan] Event {scan_event_id}: AI analysis failed ({_ai_exc}), using fallback.")
            ai_res = {'is_scam': False, 'risk_score': 0, 'indicators': [], 'explanation': 'AI không khả dụng.'}

        logger.info(f"[WebScan] Event {scan_event_id}: AI Result: {ai_res}")
        ai_notice = ai_res.get('ai_notice')
        if ai_notice:
            send_progress(ai_notice, step="ai_retry_notice")
        send_progress("AI đã hoàn tất phân tích.", step="analyzing")

        final_risk_score = max(ai_res.get('risk_score', 0), network_risk_score)
        
        # Combine networks details
        explanation = ai_res.get('explanation') or ai_res.get('reason') or ''
        if network_details:
             explanation += f"\n\nPhát hiện từ mạng lưới: {', '.join(network_details)}"

        result = {
            'domain': domain,
            'url': url,
            'page_title': page_title,
            'fetch_success': fetch_success,
            'risk_score': final_risk_score,
            'risk_level': ai_res.get('risk_level', 'SAFE'),
            'explanation': explanation,
            'ai_notice': ai_notice,
            'ai_retry_used': ai_res.get('ai_retry_used', False),
            'ai_retry_count': ai_res.get('ai_retry_count', 0),
            'scam_type': ai_res.get('scam_type') or ai_res.get('type') or 'other',
            'content_length': len(content) if content else 0,
            'network_details': network_details,
            'web_sources': ai_res.get('web_sources', []),
            'web_context': ai_res.get('web_context', '')
        }
        
        # Adjust risk level based on network score
        if final_risk_score >= 80:
            result['risk_level'] = RiskLevel.RED
        elif final_risk_score >= 40:
             result['risk_level'] = RiskLevel.YELLOW
        elif final_risk_score >= 10:
             result['risk_level'] = RiskLevel.GREEN

        scan_event.result_json = result
        scan_event.risk_score = result['risk_score']
        scan_event.risk_level = result['risk_level']
        scan_event.status = ScanStatus.COMPLETED
        scan_event.save()
        
        send_progress("Hoàn tất quét website!", step="completed", data=result)
        _notify_scan_complete(scan_event, f"Quét website '{url}' hoàn tất")
        return result

    except Exception as e:
        logger.error(f"Web scan task {scan_event_id} failed: {e}")
        send_progress(f"Lỗi hệ thống: {str(e)}", step="error")
        ScanEvent.objects.filter(id=scan_event_id).update(
            status=ScanStatus.FAILED,
            result_json={'error': str(e)}
        )
        return {'error': str(e)}

@shared_task
def process_forum_report(report_id):
    """
    AI processes a forum report:
    1. Analyze the reported post content and reason using Ollama.
    2. If AI confirms a violation (confidence > 0.7), flag as AI_FLAGGED.
    3. If it's a clear violation, we can auto-approve it.
    """
    from api.core.models import ForumPostReport
    from api.utils.ollama_client import generate_response
    import json as _json
    try:
        report = ForumPostReport.objects.select_related('post', 'post__author').get(id=report_id)
        post = report.post
        
        # Analyze content using generate_response with structured JSON output
        prompt = f"""Phân tích bài viết diễn đàn sau đây xem có vi phạm tiêu chuẩn cộng đồng (lừa đảo, quấy rối, nội dung độc hại, spam, đe dọa) hay không.

Tiêu đề: {post.title}
Nội dung: {post.content[:2000]}
Lý do báo cáo từ người dùng: {report.reason}

Hãy phân tích khách quan và trả về kết quả dạng JSON với các trường:
- violation: true nếu vi phạm, false nếu không
- confidence: số từ 0 đến 1 thể hiện mức độ chắc chắn
- reason: giải thích ngắn gọn bằng tiếng Việt"""

        format_schema = {
            "type": "object",
            "properties": {
                "violation": {"type": "boolean"},
                "confidence": {"type": "number"},
                "reason": {"type": "string"}
            },
            "required": ["violation", "confidence", "reason"]
        }
        
        raw_result = generate_response(prompt, format_schema=format_schema)
        
        # Parse the JSON result
        try:
            analysis_res = _json.loads(raw_result) if isinstance(raw_result, str) else {}
        except (_json.JSONDecodeError, TypeError):
            analysis_res = {'violation': False, 'confidence': 0, 'reason': 'Không thể phân tích (lỗi format)'}
        
        report.ai_analysis = analysis_res
        
        from api.utils.email_utils import send_report_outcome_email
        from api.utils.push_service import PushNotificationService
        
        violation = analysis_res.get('violation')
        confidence = analysis_res.get('confidence', 0)
        ai_reason = analysis_res.get('reason', '')
        
        if violation is True and confidence > 0.8:
            report.status = ForumPostReport.ReportStatus.APPROVED
            report.is_resolved = True
            
            # Lock the post if it's a clear violation
            post.is_locked = True
            post.save(update_fields=['is_locked'])
            
            logger.info(f"Report #{report_id} auto-approved by AI. Post #{post.id} locked.")
            
            # Notify reporter via email
            send_report_outcome_email(report.reporter, "bài viết", post.title, 'approved', ai_reason)
            
            # Push notification to reporter
            PushNotificationService.send_push(
                report.reporter.id,
                'Báo cáo được chấp thuận',
                f'Báo cáo bài viết "{post.title[:50]}" đã được AI xác nhận vi phạm và bài viết đã bị khóa.',
                url=f'/forum/{post.id}/',
                notification_type='success'
            )
            # Notify admins
            PushNotificationService.broadcast_admin(
                'AI: Vi phạm phát hiện',
                f'Bài viết "{post.title[:50]}" bị AI phát hiện vi phạm (conf: {confidence}). Đã tự động khóa.',
                url='/admin-cp/forum/',
                notification_type='warning'
            )
        elif violation is True:
            report.status = ForumPostReport.ReportStatus.AI_FLAGGED
            logger.info(f"Report #{report_id} flagged by AI for manual review.")
            
            # Notify reporter 
            send_report_outcome_email(report.reporter, "bài viết", post.title, 'reviewing', ai_reason)
            PushNotificationService.send_push(
                report.reporter.id,
                'Báo cáo đang được xem xét',
                f'AI đã gắn cờ bài viết "{post.title[:50]}". Admin sẽ xem xét thêm.',
                url=f'/forum/{post.id}/',
                notification_type='info'
            )
            # Notify admins  
            PushNotificationService.broadcast_admin(
                'AI: Cần xem xét',
                f'Bài viết "{post.title[:50]}" bị AI gắn cờ (conf: {confidence}). Cần admin xem xét.',
                url='/admin-cp/forum/',
                notification_type='warning'
            )
        else:
            # AI says safe
            send_report_outcome_email(report.reporter, "bài viết", post.title, 'rejected', ai_reason)
            PushNotificationService.send_push(
                report.reporter.id,
                'Kết quả phân tích báo cáo',
                f'AI không phát hiện vi phạm trong bài viết "{post.title[:50]}". Cảm ơn bạn đã báo cáo!',
                url=f'/forum/{post.id}/',
                notification_type='info'
            )
            
        report.save()
        
    except ForumPostReport.DoesNotExist:
        logger.error(f"Report #{report_id} not found in process_forum_report task.")
    except Exception as e:
        logger.error(f"Error in process_forum_report task: {e}")

@shared_task
def process_forum_comment_report(report_id):
    """
    AI processes a forum comment report.
    """
    from api.core.models import ForumCommentReport
    from api.utils.ollama_client import generate_response
    from api.utils.email_utils import send_report_outcome_email
    import json as _json
    
    try:
        report = ForumCommentReport.objects.select_related('comment', 'comment__author', 'reporter').get(id=report_id)
        comment = report.comment
        
        prompt = f"""Phân tích bình luận diễn đàn sau đây xem có vi phạm tiêu chuẩn cộng đồng (lừa đảo, quấy rối, nội dung độc hại, spam, đe dọa) hay không.

Nội dung bình luận: {comment.content[:2000]}
Lý do báo cáo từ người dùng: {report.reason}

Hãy phân tích khách quan và trả về kết quả dạng JSON với các trường:
- violation: true nếu vi phạm, false nếu không
- confidence: số từ 0 đến 1 thể hiện mức độ chắc chắn
- reason: giải thích ngắn gọn bằng tiếng Việt"""

        format_schema = {
            "type": "object",
            "properties": {
                "violation": {"type": "boolean"},
                "confidence": {"type": "number"},
                "reason": {"type": "string"}
            },
            "required": ["violation", "confidence", "reason"]
        }
        
        raw_result = generate_response(prompt, format_schema=format_schema)
        
        try:
            analysis_res = _json.loads(raw_result) if isinstance(raw_result, str) else {}
        except (_json.JSONDecodeError, TypeError):
            analysis_res = {'violation': False, 'confidence': 0, 'reason': 'Không thể phân tích (lỗi format)'}
        
        report.ai_analysis = analysis_res
        
        from api.utils.email_utils import send_report_outcome_email
        from api.utils.push_service import PushNotificationService
        
        violation = analysis_res.get('violation')
        confidence = analysis_res.get('confidence', 0)
        ai_reason = analysis_res.get('reason', '')
        comment_preview = comment.content[:50] + '...' if len(comment.content) > 50 else comment.content
        
        if violation is True and confidence > 0.8:
            report.status = ForumCommentReport.ReportStatus.APPROVED
            report.is_resolved = True
            
            logger.info(f"Comment Report #{report_id} auto-approved by AI.")
            
            send_report_outcome_email(report.reporter, "bình luận", comment_preview, 'approved', ai_reason)
            PushNotificationService.send_push(
                report.reporter.id,
                'Báo cáo bình luận được chấp thuận',
                f'Bình luận bạn báo cáo đã được xác nhận vi phạm bởi AI.',
                notification_type='success'
            )
            PushNotificationService.broadcast_admin(
                'AI: Bình luận vi phạm',
                f'Bình luận "{comment_preview}" bị AI phát hiện vi phạm (conf: {confidence}).',
                url='/admin-cp/forum/',
                notification_type='warning'
            )
        elif violation is True:
            report.status = ForumCommentReport.ReportStatus.AI_FLAGGED
            logger.info(f"Comment Report #{report_id} flagged by AI for manual review.")
            
            send_report_outcome_email(report.reporter, "bình luận", comment_preview, 'reviewing', ai_reason)
            PushNotificationService.send_push(
                report.reporter.id,
                'Báo cáo đang được xem xét',
                f'AI đã gắn cờ bình luận bạn báo cáo. Admin sẽ xem xét thêm.',
                notification_type='info'
            )
            PushNotificationService.broadcast_admin(
                'AI: BL cần xem xét',
                f'Bình luận "{comment_preview}" bị AI gắn cờ (conf: {confidence}). Cần admin xem xét.',
                url='/admin-cp/forum/',
                notification_type='warning'
            )
        else:
            send_report_outcome_email(report.reporter, "bình luận", comment_preview, 'rejected', ai_reason)
            PushNotificationService.send_push(
                report.reporter.id,
                'Kết quả phân tích báo cáo',
                f'AI không phát hiện vi phạm trong bình luận bạn báo cáo. Cảm ơn!',
                notification_type='info'
            )
            
        report.save()
        
    except ForumCommentReport.DoesNotExist:
        logger.error(f"Comment Report #{report_id} not found.")
    except Exception as e:
        logger.error(f"Error in process_forum_comment_report: {e}")

@shared_task
def send_bulk_lesson_email(lesson_id):
    """
    Sends notification email to all users who have profiles.
    """
    from api.core.models import LearnLesson, UserProfile
    from api.utils.email_utils import send_new_lesson_email
    from django.conf import settings
    
    try:
        lesson = LearnLesson.objects.get(id=lesson_id)
        if not lesson.is_published: return
        
        emails = list(UserProfile.objects.filter(user__is_active=True).values_list('user__email', flat=True))
        emails = [e for e in emails if e] # Filter valid ones
        
        if not emails: return
        
        # Site URL fallback
        site_url = getattr(settings, 'SITE_URL', 'https://shieldcall.vn')
        lesson_url = f"{site_url}/learn/{lesson.slug}/"
        
        # Send in batches of 10 to avoid spam limits/timeouts
        for i in range(0, len(emails), 10):
            batch = emails[i:i+10]
            send_new_lesson_email(batch, lesson.title, lesson_url)
            
    except LearnLesson.DoesNotExist:
        pass
    except Exception as e:
        logger.error(f"Error in send_bulk_lesson_email: {e}")

@shared_task(name='core.analyze_content_task', bind=True)
def analyze_content_task(self, scan_event_id, content: str, urls: list = None):
    """
    Perform deep analysis on text content (Email/SMS) using LLM and URL checks.
    """
    from api.core.models import ScanEvent, ScanStatus, RiskLevel
    from api.utils.ollama_client import analyze_text_for_scam
    # from api.utils.vt_client import VTClient # Uncomment if VT is ready

    if urls is None: urls = []

    try:
        scan = ScanEvent.objects.get(id=scan_event_id)
        scan.status = ScanStatus.PROCESSING
        scan.job_id = self.request.id
        scan.save()
        
        logger.info(f"Analyzing content for ScanEvent #{scan_event_id}...")
        
        # 1. AI Analysis of Text Body
        # Summarize content if too long
        ai_input = content[:5000] 
        if urls:
            ai_input += f"\n\nContained URLs: {', '.join(urls)}"
            
        ai_res = analyze_text_for_scam(ai_input, use_web_search=True)
        
        current_risk_score = scan.risk_score
        current_details = scan.result_json or {}
        
        ai_score = ai_res.get('risk_score', 0)
        
        # Merge results - AI usually gives the comprehensive verdict
        final_score = max(current_risk_score, ai_score)
        
        if 'reasons' not in current_details:
             current_details['reasons'] = []
             
        # Add AI explanation
        ai_notice = ai_res.get('ai_notice')
        if ai_notice:
            current_details['ai_notice'] = ai_notice
            current_details['reasons'].append(ai_notice)
        explanation = ai_res.get('explanation') or ai_res.get('reason')
        if explanation:
            current_details['ai_explanation'] = explanation
        
        current_details['ai_full_response'] = ai_res
        # Include web sources and context at top level for frontend
        current_details['web_sources'] = ai_res.get('web_sources', [])
        current_details['web_context'] = ai_res.get('web_context', '')
        
        # 2. URL Analysis (Logic can be expanded here)
        if urls and final_score < 100:
             # Basic heuristic if not using VT
             suspicious_tlds = ['.xyz', '.top', '.club', '.info', '.ru', '.cn']
             for url in urls:
                 if any(tld in url for tld in suspicious_tlds):
                     final_score = max(final_score, 60)
                     current_details['reasons'].append(f"Suspicious URL TLD found: {url}")

        final_score = min(100, final_score)
        
        # Determine Level
        level = RiskLevel.SAFE
        if final_score >= 80: level = RiskLevel.RED
        elif final_score >= 40: level = RiskLevel.YELLOW
        elif final_score >= 15: level = RiskLevel.GREEN

        # Update ScanEvent
        scan.risk_score = final_score
        scan.risk_level = level
        scan.result_json = current_details
        scan.status = ScanStatus.COMPLETED
        scan.save()
        
        logger.info(f"ScanEvent #{scan_event_id} analysis complete. Score: {final_score}")
        
    except ScanEvent.DoesNotExist:
        logger.error(f"ScanEvent #{scan_event_id} not found.")
    except Exception as e:
        logger.error(f"analyze_content_task failed: {e}")
        if 'scan' in locals():
            scan.status = ScanStatus.FAILED
            scan.save()

@shared_task(name='core.perform_message_scan_task', bind=True)
def perform_message_scan_task(self, scan_event_id: int, message_text: str, images_b64: list):
    """
    Background task for message scan with real-time WS progress.
    Processes OCR per image, pattern analysis, then AI analysis.
    """
    from api.core.models import ScanEvent, ScanStatus, RiskLevel
    from api.utils.ollama_client import analyze_text_for_scam
    from api.utils.normalization import normalize_domain
    from api.utils.vt_client import VTClient
    from asgiref.sync import async_to_sync
    from channels.layers import get_channel_layer
    import base64
    import io

    channel_layer = get_channel_layer()
    group_name = f'scan_{scan_event_id}'

    def send_progress(message, step='processing', data=None):
        if not channel_layer:
            return
        try:
            payload = {
                'type': 'scan_progress',
                'message': message,
                'status': 'processing',
                'step': step,
            }
            if data is not None:
                payload['data'] = data
            async_to_sync(channel_layer.group_send)(group_name, payload)
        except Exception as e:
            logger.warning(f"[MsgScan] Event {scan_event_id}: Progress send failed: {e}")

    try:
        scan_event = ScanEvent.objects.get(id=scan_event_id)
        scan_event.status = ScanStatus.PROCESSING
        scan_event.job_id = self.request.id
        scan_event.save()

        send_progress("Bắt đầu phân tích tin nhắn...", step="init")

        # 1. OCR Processing
        combined_ocr_text = []
        annotated_images = []

        if images_b64:
            send_progress(f"Đang xử lý {len(images_b64)} ảnh bằng OCR...", step="ocr")
            from api.utils.media_utils import extract_ocr_with_boxes
            from django.core.files.uploadedfile import InMemoryUploadedFile

            for idx, img_b64 in enumerate(images_b64):
                send_progress(f"Đang nhận dạng text từ ảnh {idx+1}/{len(images_b64)}...", step="ocr")
                try:
                    img_bytes = base64.b64decode(img_b64)
                    img_file = io.BytesIO(img_bytes)
                    img_file.name = f"image_{idx}.png"
                    img_file.size = len(img_bytes)

                    ocr_result = extract_ocr_with_boxes(img_file)
                    if ocr_result.get("text"):
                        combined_ocr_text.append(ocr_result["text"])
                        send_progress(f"Ảnh {idx+1}: Trích xuất {len(ocr_result['text'])} ký tự", step="ocr_ok")
                    else:
                        send_progress(f"Ảnh {idx+1}: Không phát hiện text", step="ocr_ok")
                    if ocr_result.get("annotated_image_b64"):
                        annotated_images.append(ocr_result["annotated_image_b64"])
                except Exception as e:
                    logger.error(f"[MsgScan] OCR Error for image {idx}: {e}")
                    send_progress(f"Ảnh {idx+1}: Lỗi OCR - {str(e)[:50]}", step="ocr_warning")

        # 2. Combine text
        full_text = message_text or ''
        if combined_ocr_text:
            full_text = (full_text + '\n' + '\n'.join(combined_ocr_text)).strip()

        if not full_text:
            send_progress("Không có nội dung để phân tích.", step="error")
            scan_event.status = ScanStatus.FAILED
            scan_event.result_json = {'error': 'Không có nội dung để phân tích.'}
            scan_event.save()
            return

        # 3. Pattern Analysis + Domain scan
        send_progress("Đang phát hiện dấu hiệu scam (từ khóa, URL)...", step="pattern_analysis")

        patterns_found = []
        scam_keywords = {
            r'otp|mã xác': 'Yêu cầu OTP',
            r'chuyển khoản|chuyển tiền': 'Giao dịch tài chính',
            r'công an|viện kiểm sát': 'Mạo danh cơ quan chức năng',
            r'trúng thưởng|quà tặng': 'Dụ dỗ trúng thưởng',
            r'khóa tài khoản|phong tỏa': 'Đe dọa tài khoản',
        }
        for pattern, label in scam_keywords.items():
            if re.search(pattern, full_text.lower()):
                patterns_found.append(label)

        found_urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', full_text)
        domain_risks = []
        max_domain_score = 0
        vt = VTClient()
        for url in found_urls:
            domain = normalize_domain(url)
            if domain:
                send_progress(f"Đang kiểm tra domain: {domain}...", step="domain_check")
                vt_res = vt.scan_url(url)
                score = vt_res.get('risk_score', 0)
                max_domain_score = max(max_domain_score, score)
                if score > 0:
                    domain_risks.append(f"Domain {domain} rủi ro cao ({score}/100)")

        if patterns_found or domain_risks:
            send_progress(f"Phát hiện {len(patterns_found) + len(domain_risks)} dấu hiệu đáng ngờ", step="pattern_done")
        else:
            send_progress("Không phát hiện dấu hiệu rõ ràng, đang chuyển sang AI...", step="pattern_done")

        # 4. AI Analysis
        send_progress("AI đang phân tích nội dung tin nhắn...", step="ai_analysis")
        ai_score = 0
        ai_explanation = ''
        ai_available = True
        ai_result_data = None
        try:
            import time
            from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
            ai_timeout_seconds = 90
            keepalive_every_seconds = 8
            executor = ThreadPoolExecutor(max_workers=1)
            future = executor.submit(analyze_text_for_scam, full_text)
            start_time = time.time()
            last_keepalive = 0
            ai_result_data = None

            while True:
                try:
                    ai_result_data = future.result(timeout=3)
                    break
                except FutureTimeout:
                    elapsed = time.time() - start_time
                    if elapsed - last_keepalive >= keepalive_every_seconds:
                        send_progress("AI đang phân tích...", step="ping")
                        last_keepalive = elapsed
                    if elapsed >= ai_timeout_seconds:
                        ai_result_data = None
                        ai_available = False
                        future.cancel()
                        break
            executor.shutdown(wait=False, cancel_futures=True)

            if ai_result_data:
                ai_score = ai_result_data.get('risk_score', 0) or 0
                ai_explanation = ai_result_data.get('explanation') or ''
                ai_notice = ai_result_data.get('ai_notice')
                if ai_notice:
                    send_progress(ai_notice, step="ai_retry_notice")
                send_progress("AI đã hoàn tất phân tích.", step="ai_done")
            else:
                ai_available = False
                send_progress("AI không khả dụng, sử dụng phân tích quy tắc.", step="ai_warning")
        except Exception as exc:
            ai_available = False
            logger.warning(f"[MsgScan] AI error: {exc}")
            send_progress("AI gặp lỗi, sử dụng phân tích quy tắc.", step="ai_warning")

        # 5. Final scoring
        send_progress("Đang tổng hợp kết quả...", step="finalizing")
        rule_score = min(100, len(patterns_found) * 15 + max_domain_score)
        final_score = max(ai_score, max_domain_score) if ai_available else rule_score
        final_score = max(0, min(100, final_score))

        if final_score >= 70:
            level = 'RED'
        elif final_score >= 40:
            level = 'YELLOW'
        elif final_score >= 10:
            level = 'GREEN'
        else:
            level = 'SAFE'

        scam_type = 'other'
        if any('công an' in p for p in patterns_found):
            scam_type = 'police_impersonation'
        elif any('OTP' in p for p in patterns_found):
            scam_type = 'otp_steal'
        elif any('chuyển khoản' in p for p in patterns_found):
            scam_type = 'investment_scam'
        elif domain_risks:
            scam_type = 'phishing'

        if ai_available and ai_explanation:
            explanation = ai_explanation
        elif patterns_found or domain_risks:
            explanation = f'Phát hiện {len(patterns_found + domain_risks)} dấu hiệu đáng ngờ (phân tích quy tắc).'
        else:
            explanation = 'Không phát hiện dấu hiệu lừa đảo rõ ràng.'

        result = {
            'risk_score': final_score,
            'risk_level': level,
            'scam_type': scam_type,
            'patterns_found': list(set(patterns_found + domain_risks)),
            'explanation': explanation,
            'ai_insight': ai_explanation,
            'ai_available': ai_available,
            'ocr_text': '\n'.join(combined_ocr_text) if combined_ocr_text else '',
            'annotated_images': annotated_images,
            'annotated_image': annotated_images[0] if annotated_images else '',
            'web_sources': (ai_result_data or {}).get('web_sources', []),
            'web_context': (ai_result_data or {}).get('web_context', ''),
        }

        scan_event.result_json = {k: v for k, v in result.items() if k not in ('annotated_images', 'annotated_image')}
        scan_event.risk_score = final_score
        scan_event.risk_level = level
        scan_event.status = ScanStatus.COMPLETED
        scan_event.save()

        send_progress("Hoàn tất phân tích tin nhắn!", step="completed", data=result)
        _notify_scan_complete(scan_event, 'Quét tin nhắn hoàn tất')
        return result

    except ScanEvent.DoesNotExist:
        logger.error(f"[MsgScan] ScanEvent #{scan_event_id} not found.")
    except Exception as e:
        logger.error(f"[MsgScan] perform_message_scan_task failed: {e}", exc_info=True)
        try:
            send_progress(f"Lỗi hệ thống: {str(e)[:100]}", step="error")
            scan_event = ScanEvent.objects.get(id=scan_event_id)
            scan_event.status = ScanStatus.FAILED
            scan_event.save()
        except:
            pass


@shared_task(name='core.perform_email_deep_scan')
def perform_email_deep_scan(scan_event_id: int, email_data: dict):
    """
    Async deep analysis for emails using weighted EML signals + AI enrichment.
    """
    from api.core.models import ScanEvent, RiskLevel, ScanStatus
    from api.utils.ollama_client import analyze_text_for_scam
    from api.utils.email_utils import compute_eml_weighted_risk
    from asgiref.sync import async_to_sync
    from channels.layers import get_channel_layer

    channel_layer = get_channel_layer()
    group_name = f'scan_{scan_event_id}'

    def send_progress(message, step='processing', data=None):
        if not channel_layer:
            return
        try:
            payload = {
                'type': 'scan_progress',
                'message': message,
                'status': 'processing',
                'step': step,
            }
            if data is not None:
                payload['data'] = data
            async_to_sync(channel_layer.group_send)(group_name, payload)
        except Exception as e:
            logger.warning(f"[EmailScan] Event {scan_event_id}: Progress send failed: {e}")
    
    logger.info(f"[EmailScan] Event {scan_event_id}: Starting deep scan")
    
    try:
        scan_event = ScanEvent.objects.get(id=scan_event_id)
        current_score = int(scan_event.risk_score or 0)
        analysis_type = (email_data.get('analysis_type') or 'text').lower()
        is_basic_mode = analysis_type != 'eml'

        send_progress("Bắt đầu phân tích chuyên sâu email...", step="init")
        send_progress(f"Chế độ: {'Phân tích cơ bản (text)' if is_basic_mode else 'Phân tích file .eml đầy đủ'}", step="init")
        if email_data.get('from'):
            send_progress(f"Người gửi: {email_data['from']}", step="init")
        if email_data.get('subject'):
            send_progress(f"Tiêu đề: {email_data['subject'][:120]}", step="init")

        # Use result_json instead of details
        result_json = scan_event.result_json or {}
        security_checks = list(result_json.get('security_checks', []))
        details = list(security_checks)

        # 1) Scoring engine
        send_progress("Đang tính điểm rủi ro email...", step="scoring")
        if is_basic_mode:
            eml_res = {
                'risk_score': current_score,
                'components': {},
                'auth_results': {},
                'details': [
                    'Chế độ phân tích cơ bản: chỉ dùng email và nội dung do người dùng cung cấp (không có header/metadata .eml).'
                ],
            }
            eml_score = current_score
            logger.info(f"[EmailScan] Event {scan_event_id}: BASIC mode score={eml_score}")
            send_progress(f"Điểm rủi ro cơ bản: {eml_score}/100", step="scoring")
        else:
            eml_res = compute_eml_weighted_risk(email_data)
            eml_score = int(eml_res.get('risk_score', 0) or 0)
            details.extend(eml_res.get('details', []))
            logger.info(f"[EmailScan] Event {scan_event_id}: EML weighted score={eml_score}")
            send_progress(f"Điểm EML weighted: {eml_score}/100", step="scoring")
            # Show auth results
            auth = eml_res.get('auth_results', {})
            if auth:
                auth_parts = []
                for k, v in auth.items():
                    status = '✅' if v in ('pass', True) else '❌'
                    auth_parts.append(f"{k.upper()}: {status} {v}")
                if auth_parts:
                    send_progress(f"Xác thực: {' | '.join(auth_parts)}", step="auth_check")
            # Show component breakdown
            components = eml_res.get('components', {})
            if components:
                comp_parts = [f"{k}: {v}" for k, v in components.items() if v]
                if comp_parts:
                    send_progress(f"Thành phần: {', '.join(comp_parts[:6])}", step="scoring_detail")

        # 2) Content Analysis (LLM)
        body_text = email_data.get('body', '')
        subject = email_data.get('subject', '')
        sender = email_data.get('from', '')
        analysis = None
        ai_bonus = 0

        if body_text and len(body_text) > 20:
            send_progress(f"Đang phân tích nội dung email bằng AI ({len(body_text)} ký tự)...", step="ai_analysis")
            # Show detected URLs
            detected_urls = email_data.get('urls', [])
            if detected_urls:
                send_progress(f"Phát hiện {len(detected_urls)} URL trong email", step="url_detect")
            # Show detected attachments
            detected_attachments = email_data.get('attachments', [])
            if detected_attachments:
                send_progress(f"Phát hiện {len(detected_attachments)} file đính kèm", step="attachment_detect")
            security_lines = '\n'.join(f"- {item}" for item in security_checks[:20]) if security_checks else '- Không có dữ liệu kiểm tra bảo mật domain.'
            security_context = (
                "Kết quả kiểm tra bảo mật domain (hệ thống backend đã xác thực, có thể dùng trực tiếp):\n"
                f"{security_lines}"
            )

            # Build a Vietnamese-context enriched text block for the AI
            if is_basic_mode:
                analysis_input = (
                    "CHẾ ĐỘ PHÂN TÍCH CƠ BẢN (TEXT-ONLY):\n"
                    "- Chỉ sử dụng dữ liệu được cung cấp bên dưới.\n"
                    "- ĐƯỢC PHÉP dùng kết quả SPF/DKIM/DMARC/MX từ phần 'Kết quả kiểm tra bảo mật domain' bên dưới.\n"
                    "- KHÔNG suy diễn hoặc kết luận về header email/metadata SMTP, "
                    "độ uy tín domain qua ScamAdviser/Trustpilot/Sitejabber nếu không có dữ liệu xác thực tương ứng.\n"
                    "- Không đưa nhận định về WHOIS/Tranco/ESP nếu không có bằng chứng trực tiếp trong input.\n\n"
                    f"Địa chỉ gửi: {sender}\n"
                    f"Tiêu đề: {subject}\n"
                    f"{security_context}\n\n"
                    f"Nội dung:\n{body_text[:4000]}"
                )
            else:
                eml_components = json.dumps(eml_res.get('components', {}), ensure_ascii=False)
                eml_auth = json.dumps(eml_res.get('auth_results', {}), ensure_ascii=False)
                eml_detail_lines = '\n'.join(f"- {item}" for item in (eml_res.get('details') or [])[:20])
                analysis_input = (
                    "CHẾ ĐỘ PHÂN TÍCH .EML (FULL):\n"
                    f"Địa chỉ gửi: {sender}\n"
                    f"Tiêu đề: {subject}\n"
                    f"{security_context}\n\n"
                    "Kết quả phân tích EML weighted (hệ thống backend đã tính sẵn, có thể dùng trực tiếp):\n"
                    f"- EML Weighted Risk Score: {eml_score}/100\n"
                    f"- Components: {eml_components}\n"
                    f"- Auth Results: {eml_auth}\n"
                    f"- EML Details:\n{eml_detail_lines if eml_detail_lines else '- Không có chi tiết EML bổ sung.'}\n\n"
                    f"Nội dung:\n{body_text[:4000]}"
                )
            logger.info(f"[EmailScan] Event {scan_event_id}: Analyzing body text ({len(body_text)} chars)")
            if not is_basic_mode:
                send_progress("Đang tra cứu cơ sở dữ liệu lừa đảo + tìm kiếm web...", step="web_search")
            analysis = analyze_text_for_scam(analysis_input, use_web_search=(not is_basic_mode))
            logger.info(f"[EmailScan] Event {scan_event_id}: AI Result: {analysis}")
            ai_notice = analysis.get('ai_notice') if analysis else None
            if ai_notice:
                send_progress(ai_notice, step="ai_retry_notice")
            # Show web sources found
            if analysis and analysis.get('web_sources'):
                src_list = ', '.join(str(s) for s in analysis['web_sources'][:5])
                send_progress(f"Nguồn tình báo: {src_list}", step="web_sources_ok")
            send_progress("AI đã hoàn tất phân tích nội dung.", step="ai_done")
            
            if analysis:
                if analysis.get('is_scam'):
                    ai_bonus = min(35, int((analysis.get('risk_score', 0) or 0) * 0.45))
                else:
                    ai_bonus = -10 if int(analysis.get('risk_score', 0) or 0) <= 20 else 0
                details.extend(analysis.get('indicators', []))
                ai_explain = analysis.get('explanation', '')
                if ai_explain:
                    details.append(f"AI nhận định: {ai_explain}")
        else:
            logger.info(f"[EmailScan] Event {scan_event_id}: Body text too short, skipping AI")
            send_progress("Nội dung email quá ngắn, bỏ qua phân tích AI.", step="ai_skipped")

        # 3) Finalize - combine preliminary score, weighted EML score, and AI adjustment
        send_progress("Đang tổng hợp kết quả phân tích...", step="finalizing")
        combined_base = max(current_score, eml_score)
        final_score = max(0, min(100, combined_base + ai_bonus))
        logger.info(f"[EmailScan] Event {scan_event_id}: Final Score: {final_score}")
        send_progress(f"Điểm tổng kết: {final_score}/100 (base={combined_base}, AI adj={ai_bonus:+d})", step="score_final")

        # Remove duplicated analysis lines (e.g., DMARC/SPF repeated by multiple analyzers)
        deduped_details = []
        seen_detail_keys = set()
        for item in details:
            text = str(item).strip()
            if not text:
                continue
            normalized_key = re.sub(r'\s+', ' ', text).lower()
            if normalized_key in seen_detail_keys:
                continue
            seen_detail_keys.add(normalized_key)
            deduped_details.append(text)
        
        # Determine Risk Level
        if final_score >= 80:
            scan_event.risk_level = RiskLevel.RED
        elif final_score >= 40:
            scan_event.risk_level = RiskLevel.YELLOW
        else:
            scan_event.risk_level = RiskLevel.GREEN
            
        scan_event.risk_score = final_score
        result_json['analysis_result'] = deduped_details[:40]
        result_json['eml_weighted_score'] = eml_score
        result_json['eml_score_components'] = eml_res.get('components', {})
        result_json['email_auth_results'] = eml_res.get('auth_results', {})
        result_json['analysis_type'] = analysis_type
        result_json['detected_urls'] = email_data.get('urls', [])
        result_json['detected_attachments'] = email_data.get('attachments', [])
        # Include grounded intelligence from AI analysis
        if analysis:
            result_json['web_sources'] = analysis.get('web_sources', [])
            result_json['web_context'] = analysis.get('web_context', '')
            result_json['searched_urls'] = analysis.get('searched_urls', [])
        scan_event.result_json = result_json
        scan_event.status = ScanStatus.COMPLETED
        scan_event.save()
        
        send_progress("Hoàn tất phân tích chuyên sâu email!", step="completed", data={
            'risk_score': final_score,
            'risk_level': str(scan_event.risk_level),
            'result': result_json
        })
        logger.info(f"[EmailScan] Event {scan_event_id}: Completed Successfully. Level: {scan_event.risk_level}")
        _notify_scan_complete(scan_event, 'Quét email chuyên sâu hoàn tất')
        
    except ScanEvent.DoesNotExist:
        logger.error(f"[EmailScan] ScanEvent #{scan_event_id} not found.")
    except Exception as e:
        logger.error(f"[EmailScan] perform_email_deep_scan failed: {e}", exc_info=True)
        try:
                        scan_event = ScanEvent.objects.get(id=scan_event_id)
                        scan_event.status = ScanStatus.FAILED
                        scan_event.save()
        except: pass


@shared_task(name='core.perform_file_scan_task', bind=True)
def perform_file_scan_task(self, scan_event_id, file_path):
    """
    Background task to scan an uploaded file using VirusTotal.
    Called from ScanFileView after saving the file to a temp location.
    """
    import os
    import time
    from api.core.models import ScanEvent, ScanStatus, RiskLevel
    from api.utils.vt_client import VTClient

    start_time = time.time()

    try:
        scan_event = ScanEvent.objects.get(id=scan_event_id)
        scan_event.status = ScanStatus.PROCESSING
        scan_event.job_id = self.request.id
        scan_event.save()

        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
        logger.info(f"[FileScan] Event {scan_event_id}: START — file='{file_name}', size={file_size} bytes")

        # Scan with VirusTotal (timeout 5 min)
        logger.info(f"[FileScan] Event {scan_event_id}: Uploading to VirusTotal...")
        vt = VTClient()
        vt_result = vt.scan_file(file_path, timeout=300)
        elapsed = time.time() - start_time
        logger.info(f"[FileScan] Event {scan_event_id}: VT scan returned after {elapsed:.1f}s — result={'OK' if vt_result else 'None'}")

        if vt_result:
            malicious = vt_result.get('malicious', 0)
            suspicious = vt_result.get('suspicious', 0)
            harmless = vt_result.get('harmless', 0)
            undetected = vt_result.get('undetected', 0)
            total = vt_result.get('total', 0) or (malicious + suspicious + harmless + undetected)

            # Calculate risk score (0-100)
            if total > 0:
                risk_score = min(100, int(((malicious * 1.0 + suspicious * 0.5) / total) * 100))
            else:
                risk_score = 0

            # Determine risk level
            if malicious >= 5 or risk_score >= 70:
                risk_level = RiskLevel.RED
            elif malicious >= 1 or suspicious >= 3 or risk_score >= 30:
                risk_level = RiskLevel.YELLOW
            else:
                risk_level = RiskLevel.GREEN

            details = []
            if malicious > 0:
                details.append(f"⚠️ {malicious}/{total} engine phát hiện mã độc.")
            if suspicious > 0:
                details.append(f"🔍 {suspicious}/{total} engine đánh giá đáng ngờ.")
            if harmless > 0:
                details.append(f"✅ {harmless}/{total} engine đánh giá an toàn.")
            if undetected > 0:
                details.append(f"❔ {undetected}/{total} engine không phát hiện gì.")

            scan_event.result_json = {
                'file_name': file_name,
                'file_size': file_size,
                'malicious': malicious,
                'suspicious': suspicious,
                'harmless': harmless,
                'undetected': undetected,
                'total': total,
                'risk_score': risk_score,
                'risk_level': risk_level,
                'details': details,
                'summary': f"Kết quả quét: {malicious} mã độc, {suspicious} đáng ngờ trên tổng {total} engine.",
            }
            scan_event.risk_score = risk_score
            scan_event.risk_level = risk_level
        else:
            # VT scan failed or returned None
            logger.warning(f"[FileScan] Event {scan_event_id}: VirusTotal returned no result after {elapsed:.1f}s")
            scan_event.result_json = {
                'file_name': file_name,
                'file_size': file_size,
                'risk_score': 0,
                'risk_level': RiskLevel.GREEN,
                'details': ['Không thể quét file qua VirusTotal. Vui lòng thử lại sau.'],
                'summary': 'Quét file thất bại. Không có kết quả từ VirusTotal.',
            }
            scan_event.risk_score = 0
            scan_event.risk_level = RiskLevel.GREEN

        scan_event.status = ScanStatus.COMPLETED
        scan_event.save()
        total_time = time.time() - start_time
        logger.info(f"[FileScan] Event {scan_event_id}: COMPLETED in {total_time:.1f}s. Risk: {scan_event.risk_level}, Score: {scan_event.risk_score}")

        # Send push notification to user
        _notify_scan_complete(scan_event, f"Quét file '{file_name}' hoàn tất")

    except ScanEvent.DoesNotExist:
        logger.error(f"[FileScan] ScanEvent #{scan_event_id} not found.")
    except Exception as e:
        logger.error(f"[FileScan] perform_file_scan_task failed after {time.time() - start_time:.1f}s: {e}", exc_info=True)
        try:
            scan_event = ScanEvent.objects.get(id=scan_event_id)
            scan_event.status = ScanStatus.FAILED
            scan_event.result_json = {'error': str(e)}
            scan_event.save()
        except Exception:
            pass
    finally:
        # Cleanup temp file
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                logger.info(f"[FileScan] Cleaned up temp file: {file_path}")
        except Exception as cleanup_err:
            logger.warning(f"[FileScan] Failed to clean up temp file: {cleanup_err}")


# ---------------------------------------------------------------------------
# Magic Create Lesson — runs AI generation in Celery with WS progress
# ---------------------------------------------------------------------------

def _send_task_progress(task_id, status, message, step=None, data=None):
    """Helper to send progress over WebSocket for a generic task."""
    from channels.layers import get_channel_layer
    from asgiref.sync import async_to_sync
    channel_layer = get_channel_layer()
    if channel_layer:
        async_to_sync(channel_layer.group_send)(f'task_{task_id}', {
            'type': 'task_progress',
            'status': status,
            'message': message,
            'step': step,
            'data': data,
        })


@shared_task(name='core.magic_create_lesson_task', bind=True, max_retries=1)
def magic_create_lesson_task(self, task_id, raw_text):
    """
    AI-powered lesson generation via Celery.
    Generates: lesson content (HTML), 5 quizzes, rich scenario (10+ steps with AI roleplay).
    Sends PARTIAL progress updates via WebSocket at each stage.
    """
    import re as _re
    import time as _time_mod
    import markdown as md
    from api.utils.ollama_client import generate_response, stream_response

    def _md_to_html(text):
        """Convert markdown to clean HTML for CKEditor."""
        if not text:
            return ''
        # If it already looks like HTML, return as-is
        if '<h2' in text or '<h3' in text or '<p>' in text:
            return text
        try:
            html = md.markdown(text, extensions=['extra', 'nl2br', 'sane_lists'])
        except Exception:
            # Fallback manual conversion
            html = text
            html = _re.sub(r'^### (.+)$', r'<h3>\1</h3>', html, flags=_re.MULTILINE)
            html = _re.sub(r'^## (.+)$', r'<h2>\1</h2>', html, flags=_re.MULTILINE)
            html = _re.sub(r'^# (.+)$', r'<h1>\1</h1>', html, flags=_re.MULTILINE)
            html = _re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html)
            html = _re.sub(r'\*(.+?)\*', r'<em>\1</em>', html)
            html = _re.sub(r'^- (.+)$', r'<li>\1</li>', html, flags=_re.MULTILINE)
            html = _re.sub(r'(<li>.*?</li>\n?)+', r'<ul>\g<0></ul>', html)
            html = _re.sub(r'\n{2,}', '</p><p>', html)
            html = '<p>' + html + '</p>'
            html = html.replace('<p></p>', '')
        return html

    # ──── STAGE 1: Analyze ────
    _send_task_progress(task_id, 'processing', 'Đang phân tích văn bản nguồn...', step=1)

    # ──── STAGE 2: Generate lesson content (streamed) ────
    _send_task_progress(task_id, 'processing', 'AI đang phân tích và tạo nội dung...', step=2)

    TITLE_SCHEMA = {
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "category": {"type": "string", "enum": ["news", "guide", "alert", "story"]}
        },
        "required": ["title", "category"]
    }

    try:
        # ── Step 2a: Extract title + category via structured JSON (fast) ──
        title_prompt = f"""Phân tích văn bản sau và đặt tiêu đề bài học giáo dục an ninh mạng.
---
{raw_text[:1500]}
---
Trả về JSON: {{"title": "Tiêu đề hấp dẫn, giáo dục", "category": "news|guide|alert|story"}}"""

        logger.info(f"[MagicCreate] Task {task_id}: Calling generate_response for title (text_len={len(raw_text)})")
        title_resp = generate_response(
            prompt=title_prompt,
            system_prompt="Trả về JSON thuần, không markdown code block.",
            format_schema=TITLE_SCHEMA,
            max_tokens=6000,  # Extra room for thinking tokens
        )
        title_data = _parse_json_safe(title_resp)
        if not title_data or not title_data.get('title'):
            # Fallback: use first 80 chars of raw text as title
            title_data = {'title': raw_text[:80].strip().split('\n')[0], 'category': 'guide'}
            logger.warning(f"[MagicCreate] Task {task_id}: Title extraction failed, using fallback")

        logger.info(f"[MagicCreate] Task {task_id}: Title: {title_data['title']}")

        # Send title immediately
        _send_task_progress(task_id, 'processing', 'AI đang viết nội dung bài học...', step=2, data={
            'title': title_data['title'],
            'category': title_data.get('category', 'guide'),
        })

        # ── Step 2b: Generate lesson content (non-streaming for reliability) ──
        content_prompt = f"""Văn bản nguồn:
---
{raw_text}
---

Viết bài học giáo dục về an ninh mạng bằng Markdown từ văn bản trên.

YÊU CẦU:
- Bao gồm các phần: ## Tổng quan, ## Thủ đoạn lừa đảo, ## Dấu hiệu nhận biết, ## Cách phòng tránh, ## Kết luận
- Mỗi phần phải có ít nhất 3 bullet points hoặc 2 đoạn văn
- Dùng ví dụ thực tế minh họa, ngôn ngữ dễ hiểu cho mọi lứa tuổi
- Tổng ít nhất 500 từ trở lên
- Viết Markdown thuần (## heading, ### sub, **bold**, - bullet, > blockquote)
- KHÔNG bọc trong code block, KHÔNG trả về JSON"""

        logger.info(f"[MagicCreate] Task {task_id}: Generating content (non-streaming), prompt_len={len(content_prompt)}")
        _send_task_progress(task_id, 'processing', 'AI đang viết nội dung bài học...', step=2)

        _accumulated_md = ''
        try:
            _accumulated_md = generate_response(
                prompt=content_prompt,
                system_prompt="Bạn là chuyên gia an ninh mạng Việt Nam. Viết bài học Markdown chi tiết, dễ hiểu. Chỉ viết nội dung Markdown, không JSON, không code block.",
                max_tokens=12000,   # High limit: ~3k thinking + ~9k content tokens for 500+ word lesson
                tools=[],           # Disable tools — model should write content, not search
                skip_filter=True,   # Don't strip CJK from content
            ) or ''
            logger.info(f"[MagicCreate] Task {task_id}: generate_response returned {len(_accumulated_md)} chars")
            if _accumulated_md:
                logger.info(f"[MagicCreate] Task {task_id}: Content preview (first 300): {_accumulated_md[:300]!r}")
                logger.info(f"[MagicCreate] Task {task_id}: Content preview (last 200): {_accumulated_md[-200:]!r}")
        except Exception as gen_err:
            logger.error(f"[MagicCreate] Task {task_id}: Content generation error: {gen_err}", exc_info=True)

        # Final content
        _content_html = _md_to_html(_accumulated_md) if _accumulated_md.strip() else ''
        logger.info(f"[MagicCreate] Task {task_id}: md_len={len(_accumulated_md)}, html_len={len(_content_html)}")
        if not _content_html:
            logger.error(f"[MagicCreate] Task {task_id}: Content generation produced empty result")
            _send_task_progress(task_id, 'error', 'AI không tạo được nội dung bài học. Thử lại.')
            return

        content_data = {
            'title': title_data['title'],
            'category': title_data.get('category', 'guide'),
            'content': _content_html,
        }

        # Send complete content at once
        _send_task_progress(task_id, 'processing', 'Nội dung bài học đã tạo xong!', step=2, data={
            'title': content_data['title'],
            'category': content_data.get('category', 'guide'),
            'content': content_data['content']
        })
        logger.info(f"[MagicCreate] Task {task_id}: Content generated - {content_data['title']} "
                    f"({len(_accumulated_md)} chars md, {len(_content_html)} chars html)")

    except Exception as e:
        logger.error(f"[MagicCreate] Task {task_id} content failed: {e}", exc_info=True)
        _send_task_progress(task_id, 'error', f'Lỗi tạo nội dung: {str(e)}')
        return

    # ──── STAGE 4: Finalize ────
    final_data = {
        'title': content_data['title'],
        'content': content_data['content'],
        'category': content_data.get('category', 'news'),
        
    }
    _send_task_progress(task_id, 'done', 'Tạo bài viết thành công!', step=4, data=final_data)
    logger.info(f"[MagicArticle] Task {task_id} completed: {content_data['title']} ")

    try:
        from api.utils.push_service import PushNotificationService
        PushNotificationService.broadcast_admin(
            title='✨ Magic Create Article hoàn thành',
            message=f'Bài viết "{content_data["title"]}" đã được AI tạo xong .',
            url='/admin-cp/articles/magic-create/',
            notification_type='success',
        )
    except Exception as push_err:
        logger.warning(f"[MagicArticle] Push notification failed: {push_err}")


def _parse_json_safe(text):
    """Safely parse JSON from AI response, with multiple repair attempts."""
    if not text:
        return None

    # 1. Try direct parse
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError) as e:
        logger.debug(f"[_parse_json_safe] direct parse failed: {e}")

    # 2. Strip markdown code fences
    stripped = re.sub(r'^```(?:json)?\s*', '', text.strip())
    stripped = re.sub(r'\s*```$', '', stripped.strip())
    try:
        return json.loads(stripped)
    except (json.JSONDecodeError, TypeError):
        pass

    # 3. Extract outermost { ... }
    match = re.search(r'\{[\s\S]*\}', text)
    if match:
        candidate = match.group()
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass
        # 4. Fix trailing commas
        fixed = re.sub(r',\s*([}\]])', r'\1', candidate)
        try:
            return json.loads(fixed)
        except json.JSONDecodeError:
            pass
        # 5. Remove CJK chars that may have been injected by the model
        cleaned = re.sub(r'[\u4e00-\u9fff]+', '', candidate)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass
        # 6. Strip control characters
        ctrl_clean = re.sub(r'[\x00-\x1f\x7f]', ' ', candidate)
        try:
            return json.loads(ctrl_clean)
        except json.JSONDecodeError as e:
            logger.warning(f"[_parse_json_safe] all parse attempts failed, last error: {e}, "
                           f"text[:300]={text[:300]!r}")

    return None
