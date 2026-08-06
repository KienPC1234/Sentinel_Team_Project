"""
ShieldCall VN – Celery Tasks
MVP spec Section 9: Async tasks
"""
import logging
import re
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
            ai_res = None
            try:
                ai_res = analyze_text_for_scam(email)
            except Exception as _ai_exc:
                logger.warning(f"perform_scan_task: AI analysis failed for email ({_ai_exc}), using fallback.")
            if not ai_res:
                ai_res = {'risk_score': 0, 'risk_level': 'SAFE', 'explanation': 'AI không khả dụng.'}
            result = {
                'email': email,
                'risk_score': ai_res.get('risk_score', 0),
                'risk_level': ai_res.get('risk_level', 'SAFE'),
                'details': [ai_res.get('explanation', 'Phân tích hoàn tất.')],
                'ai_available': ai_res.get('explanation') != 'AI không khả dụng.',
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
                    ai_res = analyze_text_for_scam(full_ocr, use_web_search=True)
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
            'explanation': explanation,
            'web_sources': ai_res.get('web_sources', []),
            'web_context': ai_res.get('web_context', '')
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
    from api.utils.ollama_client import analyze_text_for_scam, web_fetch_url
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

    try:
        scan_event = ScanEvent.objects.get(id=scan_event_id)
        scan_event.status = ScanStatus.PROCESSING
        scan_event.job_id = self.request.id
        scan_event.save()

        send_progress(f"Bắt đầu phân tích website...", step="init")
        
        domain = normalize_domain(url)
        logger.info(f"[WebScan] Event {scan_event_id}: Starting analysis for URL: {url};  Normalized: {domain}")

        content = ""
        network_risk_score = 0
        network_details = []

        # --- NETWORK ANALYSIS (Deep) ---
        send_progress("Đang kiểm tra thông tin tên miền (WHOIS, DNS)...", step="network_analysis")
        try:
            # 1. WHOIS Age
            try:
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
                        logger.info(f"[WebScan] Event {scan_event_id}: Domain too new ({age_days} days)")
                    elif age_days < 30:
                         network_risk_score += 10
                         network_details.append(f"Tên miền mới (đăng ký {age_days} ngày trước)")
                         logger.info(f"[WebScan] Event {scan_event_id}: Domain new ({age_days} days)")
            except Exception as e:
                logger.warning(f"[WebScan] Event {scan_event_id}: WHOIS lookup failed: {e}")

            # 2. DNS Checks (Resolvers)
            try:
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
                        logger.info(f"[WebScan] Event {scan_event_id}: Suspicious/Cheap hosting provider found: {asn_desc}")
                except IPDefinedError:
                     pass
            except Exception as e:
                logger.warning(f"[WebScan] Event {scan_event_id}: ASN lookup failed: {e}")

            send_progress(f"Đã hoàn tất kiểm tra mạng. Điểm rủi ro mạng: {network_risk_score}", step="network_analysis")
            logger.info(f"[WebScan] Event {scan_event_id}: Network scan complete. Score: {network_risk_score}")

        except Exception as e:
            logger.error(f"[WebScan] Event {scan_event_id}: Deep network scan failed: {e}")
            send_progress(f"Lỗi kiểm tra mạng: {str(e)}", step="network_warning")
        
        # 1. Fetch Content using Ollama Web Fetch API
        send_progress(f"Đang thu thập nội dung từ {domain}...", step="scraping")
        
        # Build full URL if scheme not provided
        if '://' not in url:
            target_url = f"https://{url}"
        else:
            target_url = url

        fetch_success = False
        page_title = ""
        
        try:
            fetch_result = web_fetch_url(target_url)
            if fetch_result and fetch_result.get('content'):
                content = fetch_result.get('content', '')
                page_title = fetch_result.get('title', '')
                fetch_success = True
                logger.info(f"[WebScan] Event {scan_event_id}: Fetched content via Ollama API ({len(content)} chars)")
            else:
                # Try HTTP fallback if HTTPS failed
                if target_url.startswith('https://'):
                    http_url = target_url.replace('https://', 'http://', 1)
                    fetch_result = web_fetch_url(http_url)
                    if fetch_result and fetch_result.get('content'):
                        content = fetch_result.get('content', '')
                        page_title = fetch_result.get('title', '')
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

            ai_timeout_seconds = 120
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
    from api.utils.ollama_client import analyze_text_for_scam
    try:
        report = ForumPostReport.objects.select_related('post', 'post__author').get(id=report_id)
        post = report.post
        
        # Analyze content
        prompt = f"""
        Phân tích bài viết diễn đàn sau đây xem có vi phạm tiêu chuẩn cộng đồng (lừa đảo, quấy rối, nội dung độc hại) hay không.
        Tiêu đề: {post.title}
        Nội dung: {post.content}
        Lý do báo cáo: {report.reason}
        
        Trả về JSON: {{"violation": true/false, "confidence": 0-1, "reason": "giải thích ngắn gọn"}}
        """
        
        analysis_res = analyze_text_for_scam(prompt)
        report.ai_analysis = analysis_res
        
        from api.utils.email_utils import send_report_outcome_email
        
        if analysis_res.get('violation') is True and analysis_res.get('confidence', 0) > 0.8:
            report.status = ForumPostReport.ReportStatus.APPROVED
            report.is_resolved = True
            
            # Lock the post if it's a clear violation
            post.is_locked = True
            post.save(update_fields=['is_locked'])
            
            logger.info(f"Report #{report_id} auto-approved by AI. Post #{post.id} locked.")
            
            # Notify reporter
            send_report_outcome_email(
                report.reporter, 
                "bài viết", 
                post.title, 
                'approved', 
                analysis_res.get('reason')
            )
        elif analysis_res.get('violation') is True:
            report.status = ForumPostReport.ReportStatus.AI_FLAGGED
            logger.info(f"Report #{report_id} flagged by AI for manual review.")
        else:
            # Mark as safe for now, could auto-reject if confidence is very high
            pass
            
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
    from api.utils.ollama_client import analyze_text_for_scam
    from api.utils.email_utils import send_report_outcome_email
    
    try:
        report = ForumCommentReport.objects.select_related('comment', 'comment__author', 'reporter').get(id=report_id)
        comment = report.comment
        
        prompt = f"""
        Phân tích bình luận diễn đàn sau đây xem có vi phạm tiêu chuẩn cộng đồng (lừa đảo, quấy rối, nội dung độc hại) hay không.
        Nội dung bình luận: {comment.content}
        Lý do báo cáo: {report.reason}
        
        Trả về JSON: {{"violation": true/false, "confidence": 0-1, "reason": "giải thích ngắn gọn"}}
        """
        
        analysis_res = analyze_text_for_scam(prompt)
        report.ai_analysis = analysis_res
        
        if analysis_res.get('violation') is True and analysis_res.get('confidence', 0) > 0.8:
            report.status = ForumCommentReport.ReportStatus.APPROVED
            report.is_resolved = True
            
            # In a real app, we might hide/delete the comment here
            logger.info(f"Comment Report #{report_id} auto-approved by AI.")
            
            send_report_outcome_email(
                report.reporter,
                "bình luận",
                comment.content[:50] + "...",
                'approved',
                analysis_res.get('reason')
            )
        elif analysis_res.get('violation') is True:
            report.status = ForumCommentReport.ReportStatus.AI_FLAGGED
            logger.info(f"Comment Report #{report_id} flagged by AI for manual review.")
            
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

@shared_task(name='core.perform_email_deep_scan')
def perform_email_deep_scan(scan_event_id: int, email_data: dict):
    """
    Async deep analysis for emails using weighted EML signals + AI enrichment.
    """
    from api.core.models import ScanEvent, RiskLevel, ScanStatus
    from api.utils.ollama_client import analyze_text_for_scam
    from api.utils.email_utils import compute_eml_weighted_risk
    
    logger.info(f"[EmailScan] Event {scan_event_id}: Starting deep scan")
    
    try:
        scan_event = ScanEvent.objects.get(id=scan_event_id)
        current_score = int(scan_event.risk_score or 0)
        analysis_type = (email_data.get('analysis_type') or 'text').lower()
        is_basic_mode = analysis_type != 'eml'

        # Use result_json instead of details
        result_json = scan_event.result_json or {}
        details = [] if is_basic_mode else list(result_json.get('security_checks', []))

        # 1) Scoring engine
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
        else:
            eml_res = compute_eml_weighted_risk(email_data)
            eml_score = int(eml_res.get('risk_score', 0) or 0)
            details.extend(eml_res.get('details', []))
            logger.info(f"[EmailScan] Event {scan_event_id}: EML weighted score={eml_score}")

        # 2) Content Analysis (LLM)
        body_text = email_data.get('body', '')
        subject = email_data.get('subject', '')
        sender = email_data.get('from', '')
        analysis = None
        ai_bonus = 0

        if body_text and len(body_text) > 20:
            # Build a Vietnamese-context enriched text block for the AI
            if is_basic_mode:
                analysis_input = (
                    "CHẾ ĐỘ PHÂN TÍCH CƠ BẢN (TEXT-ONLY):\n"
                    "- Chỉ sử dụng dữ liệu được cung cấp bên dưới.\n"
                    "- KHÔNG suy diễn hoặc kết luận về SPF/DKIM/DMARC, header email, metadata SMTP, "
                    "độ uy tín domain qua ScamAdviser/Trustpilot/Sitejabber nếu không có dữ liệu xác thực tương ứng.\n"
                    "- Không đưa nhận định về WHOIS/Tranco/ESP nếu không có bằng chứng trực tiếp trong input.\n\n"
                    f"Địa chỉ gửi: {sender}\n"
                    f"Tiêu đề: {subject}\n"
                    f"Nội dung:\n{body_text[:4000]}"
                )
            else:
                analysis_input = (
                    f"Địa chỉ gửi: {sender}\n"
                    f"Tiêu đề: {subject}\n"
                    f"Nội dung:\n{body_text[:4000]}"
                )
            logger.info(f"[EmailScan] Event {scan_event_id}: Analyzing body text ({len(body_text)} chars)")
            analysis = analyze_text_for_scam(analysis_input, use_web_search=(not is_basic_mode))
            logger.info(f"[EmailScan] Event {scan_event_id}: AI Result: {analysis}")
            
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

        # For basic mode, keep result concise and avoid metadata-heavy indicators.
        if is_basic_mode:
            details = [
                item for item in details
                if not re.search(r'(SPF|DKIM|DMARC|WHOIS|ScamAdviser|Trustpilot|Sitejabber|Tranco)', str(item), re.IGNORECASE)
            ]

        # 3) Finalize - combine preliminary score, weighted EML score, and AI adjustment
        combined_base = max(current_score, eml_score)
        final_score = max(0, min(100, combined_base + ai_bonus))
        logger.info(f"[EmailScan] Event {scan_event_id}: Final Score: {final_score}")
        
        # Determine Risk Level
        if final_score >= 80:
            scan_event.risk_level = RiskLevel.RED
        elif final_score >= 40:
            scan_event.risk_level = RiskLevel.YELLOW
        else:
            scan_event.risk_level = RiskLevel.GREEN
            
        scan_event.risk_score = final_score
        result_json['analysis_result'] = details[:40]
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
        scan_event.result_json = result_json
        scan_event.status = ScanStatus.COMPLETED
        scan_event.save()
        
        logger.info(f"[EmailScan] Event {scan_event_id}: Completed Successfully. Level: {scan_event.risk_level}")
        
    except ScanEvent.DoesNotExist:
        logger.error(f"[EmailScan] ScanEvent #{scan_event_id} not found.")
    except Exception as e:
        logger.error(f"[EmailScan] perform_email_deep_scan failed: {e}", exc_info=True)
        try:
                        scan_event = ScanEvent.objects.get(id=scan_event_id)
                        scan_event.status = ScanStatus.FAILED
                        scan_event.save()
        except: pass
