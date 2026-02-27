"""ShieldCall VN – Scan Views"""
import re
import hashlib
import logging
import json
import socket
import ssl
import requests
from urllib.parse import urlparse
from django.core.cache import cache
from api.utils.security import verify_turnstile_token

from django.contrib.auth import authenticate, get_user_model
from django.db.models import Count, Sum, F, Q
from django.utils import timezone
from datetime import timedelta

from django.http import StreamingHttpResponse
from rest_framework import status, permissions, generics
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
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
    ScanAccountSerializer, ScanImageSerializer, ScanEmailSerializer,
    ScanEventListSerializer, TrendDailySerializer, TrendHotSerializer, UserAlertSerializer,
)

User = get_user_model()
logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# SCAN APIs — Real business logic
# ═══════════════════════════════════════════════════════════════════════════

from api.utils.normalization import normalize_phone, normalize_domain
from api.utils.vt_client import VTClient

import math
from api.utils.trust_score import calculate_reporter_trust

def _phone_risk_score(phone_number: str) -> dict:
    """
    Production-Grade Phone Risk Engine.
    Hybrid Scoring = (Weighted Reports) + (Network Signals) + (Behavioral Patterns)
    """
    from api.phone_security.models import PhoneNumber
    # Normalize input for lookup
    phone_number = normalize_phone(phone_number)
    
    # 1. Fetch Reports & Apply Trust/Time Decay
    reports = Report.objects.filter(target_type='phone', target_value=phone_number).select_related('reporter', 'reporter__profile')
    
    report_score = 0.0
    verified_count = 0
    pending_count = 0
    
    # Decay factor lambda: e^(-0.15 * days)
    # 1 day old = 0.86
    # 7 days old = 0.35
    # 30 days old = 0.01
    DECAY_LAMBDA = 0.15
    
    now = timezone.now()
    
    for r in reports:
        age_days = (now - r.created_at).days
        time_weight = math.exp(-DECAY_LAMBDA * age_days)
        
        # trust score logic
        trust = calculate_reporter_trust(r.reporter)
        
        # Base weight by status
        status_weight = 0
        if r.status == 'approved':
            status_weight = 1.0
            verified_count += 1
        elif r.status == 'pending':
            status_weight = 0.2
            pending_count += 1
        elif r.status == 'rejected':
            continue # Skip rejected reports
            
        # Impact: Trust * Time * Status
        # Max impact per report = 1.0 * 1.0 * 1.0 = 1.0 (High trust reporter, today, approved)
        impact = trust * time_weight * status_weight * 25 # Scale factor
        report_score += impact

    # 2. Network Intelligence (Mock / DB)
    network_score = 0.0
    carrier_info = "Unknown"
    is_virtual = False
    
    try:
        phone_obj = PhoneNumber.objects.get(phone_number=phone_number)
        carrier_info = phone_obj.carrier or "Unknown"
        is_virtual = phone_obj.is_virtual
        
        # Risk from database
        if phone_obj.risk_level == RiskLevel.RED:
            network_score += 60
        elif phone_obj.risk_level == RiskLevel.YELLOW:
            network_score += 30
            
        # Virtual number penalty
        if is_virtual:
            network_score += 25
            
        # Carrier risk (Example)
        if carrier_info == 'VirtualProvider':
             network_score += 15

    except PhoneNumber.DoesNotExist:
        # Create empty record for tracking
        pass

    # 3. Behavioral Features (Velocity)
    # Check if number of reports in last 24h is high
    recent_velocity = reports.filter(created_at__gte=now - timedelta(hours=24)).count()
    velocity_score = 0
    if recent_velocity > 10:
        velocity_score = 40
    elif recent_velocity > 3:
        velocity_score = 15

    # --- FINAL AGGREGATION ---
    final_score = report_score + network_score + velocity_score
    final_score = min(100, final_score)
    
    # Determine Level
    level = RiskLevel.SAFE
    if final_score >= 80: level = RiskLevel.RED
    elif final_score >= 40: level = RiskLevel.YELLOW
    elif final_score >= 15: level = RiskLevel.GREEN

    # Reasons
    reasons = []
    if verified_count > 0:
        reasons.append(f'{verified_count} báo cáo uy tín đã xác minh')
    if is_virtual:
        reasons.append('Số điện thoại ảo (Virtual Number)')
    if velocity_score > 0:
        reasons.append(f'Tăng đột biến: {recent_velocity} báo cáo trong 24h')
    if report_score > 20 and not verified_count:
        reasons.append('Nhiều báo cáo từ cộng đồng (đang chờ duyệt)')

    # Update PhoneNumber DB using update_or_create to avoid race conditions roughly
    # In async task we do this more carefully
    
    return {
        'phone': phone_number,
        'risk_score': round(final_score),
        'risk_level': level,
        'scam_type': 'other', # TODO: Detect most common scam type from reports
        'report_count': verified_count + pending_count,
        'reports_verified': verified_count,
        'carrier': carrier_info,
        'is_virtual': is_virtual,
        'trust_score': round(report_score, 2),
        'reasons': reasons[:3],
    }


class ScanPhoneView(APIView):
    """POST /api/scan/phone — Scan phone number risk"""
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ScanPhoneSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        phone = normalize_phone(serializer.validated_data['phone'])
        if not re.match(r'^0\d{9,10}$', phone):
            return Response({'error': 'Số điện thoại không hợp lệ.'},
                            status=status.HTTP_400_BAD_REQUEST)

        result = _phone_risk_score(phone)

        # Turnstile Verification
        cf_token = request.data.get('cf-turnstile-response')
        if not verify_turnstile_token(cf_token):
            return Response({'error': 'Xác minh anti-spam không lệ. Vui lòng thử lại.'}, status=400)

        # Log scan event
        from api.core.models import ScanStatus
        scan_event = ScanEvent.objects.create(
            user=request.user if request.user.is_authenticated else None,
            scan_type='phone',
            raw_input=serializer.validated_data['phone'],
            normalized_input=phone,
            result_json=result,
            risk_score=result['risk_score'],
            risk_level=result['risk_level'],
            status=ScanStatus.COMPLETED
        )

        return Response(result)


class ScanEmailView(APIView):
    """POST /api/scan/email — Analyze email sender and content (.eml upload)"""
    permission_classes = [AllowAny]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def post(self, request):
        file_obj = request.FILES.get('file')
        content_text = request.data.get('content', '')
        sender_input = request.data.get('email', '')
        
        email_data = {
            'subject': '',
            'from': sender_input,
            'body': content_text,
            'urls': [],
            'attachments': [],
            'analysis_type': 'text'
        }

        # 1. Parse Input Source (.eml takes precedence)
        if file_obj:
            try:
                # Limit size to 10MB
                if file_obj.size > 10 * 1024 * 1024:
                    return Response({'error': 'File quá lớn (Max 10MB).'}, status=400)

                # Use updated util
                from api.utils.email_utils import parse_eml_content
                parsed = parse_eml_content(file_obj.read())
                
                if not parsed:
                    return Response({'error': 'Không thể đọc file .eml.'}, status=400)

                email_data = {
                    'subject': parsed['subject'],
                    'from': parsed['from'],
                    'body': parsed['body_text'],
                    'urls': parsed['extracted_urls'],
                    'attachments': parsed['attachments'],
                    'analysis_type': 'eml'
                }
            except Exception as e:
                logger.error(f"EML Upload Error: {e}")
                return Response({'error': 'Lỗi xử lý file.'}, status=500)

        # 2. Basic Validation
        sender = email_data['from']
        # Extract pure email from "Name <email@domain.com>"
        email_match = re.search(r'[\w\.-]+@[\w\.-]+', sender)
        clean_email = email_match.group(0) if email_match else sender
        
        if not clean_email or '@' not in clean_email:
             # Allow analysis if we have body content even without valid sender (sometimes)
             # But for security scan, sender is crucial.
             if not email_data['body']:
                return Response({'error': 'Cần cung cấp file .eml hoặc email/nội dung.'}, status=400)
             clean_email = "unknown@unknown.com" # Fallback

        # 3. Synchronous Security Checks (DNS/SPF/DMARC)
        from api.utils.email_utils import check_email_security
        domain = clean_email.split('@')[-1]
        
        # Initial Score Base
        security_result = check_email_security(domain)
        base_risk_score = security_result['penalty']
        security_details = security_result['details']

        # 4. Check Database Reports
        report_count = Report.objects.filter(
            target_type='email', 
            target_value=clean_email, 
            status='approved'
        ).count()
        
        if report_count > 0:
            base_risk_score += 50
            security_details.append(f"Đã có {report_count} báo cáo lừa đảo xác thực")

        # 5. Create Scan Event
        scan_event = ScanEvent.objects.create(
            scan_type='email',
            raw_input=clean_email,
            normalized_input=clean_email,
            status='pending',
            risk_score=base_risk_score,
            result_json={
                'security_checks': security_details,
                'content_snippet': email_data['body'][:5000]
            },
            user=request.user if request.user.is_authenticated else None,
            detected_urls=email_data['urls']
        )
        
        # 6. Trigger Deep Analysis Task (Async)
        from api.core.tasks import perform_email_deep_scan
        perform_email_deep_scan.delay(scan_event.id, email_data)

        # 7. Return Preliminary Result
        return Response({
            'scan_id': scan_event.id,
            'status': 'processing',
            'message': 'Đang phân tích chuyên sâu...',
            'preliminary_score': base_risk_score,
            'security_checks': security_details,
            'extracted_info': {
                'subject': email_data['subject'],
                'from': email_data['from'],
                'url_count': len(email_data['urls']),
                'attachment_count': len(email_data['attachments'])
            }
        })





class ScanBanksView(APIView):
    """
    GET /api/scan/banks — Fetch list of banks from VietQR API.
    Cached for 24 hours to ensure local performance.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        import requests
        from django.core.cache import cache

        cached_banks = cache.get('vietqr_banks')
        if cached_banks:
            return Response(cached_banks)

        try:
            resp = requests.get('https://api.vietqr.io/v2/banks', timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('code') == '00':
                    banks = data.get('data', [])
                    # Cache for 24 hours
                    cache.set('vietqr_banks', banks, 86400)
                    return Response(banks)
            return Response({'error': 'Không thể lấy danh sách ngân hàng.'}, status=500)
        except Exception as e:
            logger.error(f"Error fetching banks from VietQR: {str(e)}")
            return Response({'error': 'Lỗi kết nối đến dịch vụ ngân hàng.'}, status=500)


def _analyze_message_text(text: str) -> dict:
    """
    Enhanced AI Text Analyzer.
    Prioritizes AI analysis and incorporates domain risk checks.
    Falls back gracefully to rule-based scoring when AI (Ollama) is unavailable.
    """
    # 1. AI Analysis (Ollama) — with graceful fallback
    ai_score = 0
    ai_explanation = ''
    ai_available = True
    try:
        ai_result = analyze_text_for_scam(text)
        if ai_result:
            ai_score = ai_result.get('risk_score', 0) or 0
            ai_explanation = ai_result.get('explanation') or ai_result.get('reason') or ''
        else:
            ai_available = False
            logger.warning("_analyze_message_text: AI returned None, falling back to rule-based scoring.")
    except Exception as exc:
        ai_available = False
        logger.warning(f"_analyze_message_text: AI error ({exc}), falling back to rule-based scoring.")

    # 2. Extract and Scan Domains
    found_urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text)
    domain_risks = []
    max_domain_score = 0

    vt = VTClient()
    for url in found_urls:
        domain = normalize_domain(url)
        if domain:
            vt_res = vt.scan_url(url)
            score = vt_res.get('risk_score', 0)
            max_domain_score = max(max_domain_score, score)
            if score > 0:
                domain_risks.append(f"Domain {domain} rủi ro cao ({score}/100)")

    # 3. Heuristic Patterns
    patterns_found = []
    scam_keywords = {
        r'otp|mã xác': 'Yêu cầu OTP',
        r'chuyển khoản|chuyển tiền': 'Giao dịch tài chính',
        r'công an|viện kiểm sát': 'Mạo danh cơ quan chức năng',
        r'trúng thưởng|quà tặng': 'Dụ dỗ trúng thưởng',
        r'khóa tài khoản|phong tỏa': 'Đe dọa tài khoản',
    }
    for pattern, label in scam_keywords.items():
        if re.search(pattern, text.lower()):
            patterns_found.append(label)

    # Rule-based score (used as sole score when AI is unavailable)
    rule_score = min(100, len(patterns_found) * 15 + max_domain_score)

    # 4. Final Ensemble
    if ai_available:
        # Combine AI judgement with domain signals; AI takes precedence
        final_score = max(ai_score, max_domain_score)
    else:
        # AI offline — fall back entirely to heuristics + domain risk
        final_score = rule_score

    level = RiskLevel.SAFE
    if final_score >= 70: level = RiskLevel.RED
    elif final_score >= 40: level = RiskLevel.YELLOW
    elif final_score >= 10: level = RiskLevel.GREEN

    # Determine scam type from detected patterns
    scam_type = 'other'
    if any('công an' in p for p in patterns_found):
        scam_type = 'police_impersonation'
    elif any('OTP' in p for p in patterns_found):
        scam_type = 'otp_steal'
    elif any('chuyển khoản' in p for p in patterns_found):
        scam_type = 'investment_scam'
    elif any('trúng thưởng' in p.lower() for p in patterns_found):
        scam_type = 'prize_scam'
    elif domain_risks:
        scam_type = 'phishing'

    # Actionable advice based on risk level
    if final_score >= 70:
        actions = ['🚫 KHÔNG chuyển tiền', '🚫 KHÔNG cung cấp OTP',
                   '📞 Gọi 113 báo công an', '📸 Lưu bằng chứng']
    elif final_score >= 40:
        actions = ['⚠️ Kiểm tra lại nguồn gửi', '🔍 Tìm kiếm số/link trên ShieldCall',
                   '📝 Báo cáo nếu nghi ngờ']
    else:
        actions = ['✅ Tin nhắn có vẻ an toàn', '🔍 Vẫn nên cẩn thận với link lạ']

    # Build explanation — prefer AI's if available, else use rule summary
    if ai_available and ai_explanation:
        explanation = ai_explanation
    elif patterns_found or domain_risks:
        explanation = f'Phát hiện {len(patterns_found + domain_risks)} dấu hiệu đáng ngờ (phân tích quy tắc).'
    else:
        explanation = 'Không phát hiện dấu hiệu lừa đảo rõ ràng.'

    return {
        'risk_score': final_score,
        'risk_level': level,
        'scam_type': scam_type,
        'patterns_found': list(set(patterns_found + domain_risks)),
        'explanation': explanation,
        'ai_insight': ai_explanation,
        'ai_available': ai_available,
        'actions': actions,
        'rule_score': rule_score,
        'ai_score': ai_score,
    }


class ScanMessageView(APIView):
    """POST /api/scan/message — Analyze text message for scams (Multi-image support)"""
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ScanMessageSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        text = serializer.validated_data.get('message', '')
        
        # Multiple images support
        images = request.FILES.getlist('image') or request.FILES.getlist('images')
        combined_ocr_text = []
        ocr_regions = []
        annotated_image = ""
        
        from api.utils.media_utils import extract_ocr_with_boxes
        
        for img in images:
            try:
                ocr_result = extract_ocr_with_boxes(img)
                if ocr_result.get("text"):
                    combined_ocr_text.append(ocr_result["text"])
                if ocr_result.get("regions"):
                    ocr_regions.extend(ocr_result["regions"])
                if not annotated_image and ocr_result.get("annotated_image_b64"):
                    annotated_image = ocr_result["annotated_image_b64"]
            except Exception as e:
                logger.error(f"OCR Error for image: {str(e)}")

        full_text = text
        if combined_ocr_text:
            full_text = (text + '\n' + '\n'.join(combined_ocr_text)).strip()

        if not full_text:
            return Response({'error': 'Không có nội dung để phân tích.'},
                            status=status.HTTP_400_BAD_REQUEST)

        result = _analyze_message_text(full_text)
        if combined_ocr_text:
            result['ocr_text'] = '\n'.join(combined_ocr_text)
        result['ocr_regions'] = ocr_regions
        result['annotated_image'] = annotated_image

        # Turnstile Verification
        cf_token = request.data.get('cf-turnstile-response')
        if not verify_turnstile_token(cf_token):
            return Response({'error': 'Xác minh anti-spam không lệ. Vui lòng thử lại.'}, status=400)

        # Log scan event
        log_result = {k: v for k, v in result.items() if k != 'annotated_image'}
        ScanEvent.objects.create(
            user=request.user if request.user.is_authenticated else None,
            scan_type='message',
            raw_input=full_text[:2000],
            normalized_input=full_text[:500],
            result_json=log_result,
            risk_score=result['risk_score'],
            risk_level=result['risk_level'],
        )

        return Response(result)


def _analyze_network(url: str, domain: str) -> dict:
    """Perform network analysis: SSL validation, redirects, and headers."""
    network_info = {
        'ssl_valid': False,
        'redirects': 0,
        'final_url': url,
        'server': '',
        'error': None,
        'ip_address': None,
        'cert_issuer': None,
        'cert_age_days': 0,
        'cert_details': {}
    }
    
    # 0. Basic DNS resolution (Sync)
    try:
        network_info['ip_address'] = socket.gethostbyname(domain)
    except socket.gaierror:
        network_info['error'] = 'DNS resolution failed'
        return network_info

    # 1. SSL Validation
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                network_info['ssl_valid'] = True
                
                # Extract cert details
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])
                network_info['cert_issuer'] = issuer.get('organizationName') or issuer.get('commonName')
                
                # Check multiple formats for cert date
                from datetime import datetime
                not_before = None
                formats = [r'%b %d %H:%M:%S %Y %Z', r'%Y-%m-%d %H:%M:%S', r'%Y%m%d%H%M%SZ']
                
                for fmt in formats:
                    try:
                        not_before = datetime.strptime(cert['notBefore'], fmt)
                        break
                    except ValueError:
                        continue
                
                if not_before:
                     network_info['cert_age_days'] = (datetime.utcnow() - not_before).days
                     network_info['cert_details']['valid_from'] = str(cert['notBefore'])
                     network_info['cert_details']['valid_to'] = str(cert['notAfter'])
                else:
                    network_info['cert_age_days'] = 0 # Default safe

    except Exception as e:
        network_info['ssl_valid'] = False
        network_info['ssl_error'] = str(e)

    # 2. HTTP Analysis (Redirects, Headers)
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        req_url = url if url.startswith('http') else f'https://{domain}'
        
        response = requests.get(req_url, headers=headers, timeout=5, allow_redirects=True)
        
        network_info['redirects'] = len(response.history)
        network_info['final_url'] = response.url
        network_info['server'] = response.headers.get('Server', '')
        network_info['status_code'] = response.status_code
        network_info['security_headers'] = {
            'HSTS': 'Strict-Transport-Security' in response.headers,
            'CSP': 'Content-Security-Policy' in response.headers,
            'X-Frame-Options': 'X-Frame-Options' in response.headers,
        }
        
    except requests.RequestException as e:
        if not network_info['error']: # prioritize DNS error
             network_info['error'] = str(e)
        
    return network_info


def _get_trusted_domains() -> dict:
    """Get trusted domains, caching the result."""
    trusted = cache.get('trusted_domains_list')
    if trusted:
        return trusted
        
    # Default comprehensive list of Vietnamese banks and popular services
    default_trusted = {
        'vietcombank.com.vn': 'Vietcombank',
        'techcombank.com.vn': 'Techcombank',
        'bidv.com.vn': 'BIDV',
        'vietinbank.vn': 'VietinBank',
        'mbbank.com.vn': 'MBBank',
        'agribank.com.vn': 'Agribank',
        'tpbank.vn': 'TPBank',
        'vpbank.com.vn': 'VPBank',
        'acb.com.vn': 'ACB',
        'vib.com.vn': 'VIB',
        'shb.com.vn': 'SHB',
        'sacombank.com.vn': 'Sacombank',
        'hdbank.com.vn': 'HDBank',
        'momo.vn': 'Momo',
        'zalopay.vn': 'ZaloPay',
        'vnpay.vn': 'VNPay',
        'facebook.com': 'Facebook',
        'google.com': 'Google',
        'youtube.com': 'YouTube',
        'zalo.me': 'Zalo',
        'tiktok.com': 'TikTok',
        'shopee.vn': 'Shopee',
        'lazada.vn': 'Lazada',
        'tiki.vn': 'Tiki',
        'chotot.com': 'ChoTot',
        'gov.vn': 'Chính phủ VN',
        'chinhphu.vn': 'Chính phủ VN',
    }
    
    # In a real scenario, we could fetch from an external API here
    # e.g., requests.get('https://raw.githubusercontent.com/.../whitelist.json')
    
    cache.set('trusted_domains_list', default_trusted, 86400) # Cache for 24 hours
    return default_trusted


def _analyze_domain(url: str) -> dict:
    """Domain/URL Risk Engine with VirusTotal integration and Network Analysis."""
    domain = normalize_domain(url)
    
    # Ensure URL has a scheme for VT scan
    if not re.match(r'^[a-z0-9]+://', url):
        full_url = 'https://' + url
    else:
        full_url = url

    score = 0
    details = []

    # 1. Network Analysis (SSL, Redirects, Headers)
    network_info = _analyze_network(full_url, domain)
    
    if not network_info['ssl_valid']:
        score += 15
        details.append('Chứng chỉ SSL không hợp lệ hoặc không có HTTPS')
    elif network_info.get('cert_age_days', 0) < 3:
        score += 20
        details.append(f"Chứng chỉ SSL mới tạo ({network_info['cert_age_days']} ngày) - Rủi ro cao")
        
    issuer = str(network_info.get('cert_issuer', '')).lower()
    if 'let\'s encrypt' in issuer or 'cloudflare' in issuer:
        # Flag free certs ONLY if domain tries to look like a bank/big brand
        is_lookalike = any(_is_lookalike(domain, trusted) for trusted in _get_trusted_domains())
        if is_lookalike:
            score += 10
            details.append('Sử dụng chứng chỉ miễn phí (Let\'s Encrypt/Cloudflare) cho tên miền giống ngân hàng')

    if network_info.get('redirects', 0) > 2:
        score += 15
        details.append(f"Chuyển hướng quá nhiều lần ({network_info['redirects']} lần)")
        
    if network_info.get('error'):
        score += 10
        details.append('Không thể kết nối đến trang web (có thể đã sập hoặc chặn bot)')

    # Check for missing security headers (only if we got a response)
    sec_headers = network_info.get('security_headers', {})
    if network_info['ssl_valid'] and not any(sec_headers.values()):
         score += 5
         # details.append('Thiếu các header bảo mật cơ bản') # Maybe too technical for user?

    # 2. VirusTotal Scan
    with VTClient() as vt:
        vt_results = vt.scan_url(full_url)
        if vt_results:
            malicious = vt_results.get('malicious', 0)
            suspicious = vt_results.get('suspicious', 0)
            if malicious > 0:
                score += min(60, malicious * 20)
                details.append(f"VirusTotal: {malicious} engine(s) gắn cờ ĐỘC HẠI")
            elif suspicious > 0:
                score += min(30, suspicious * 10)
                details.append(f"VirusTotal: {suspicious} engine(s) gắn cờ NGHI NGỜ")
            else:
                details.append("VirusTotal: Sạch (không phát hiện mã độc)")

    # Suspicious patterns
    if len(domain) > 30:
        score += 10
        details.append('Domain name dài bất thường')
    if domain.count('.') > 3:
        score += 15
        details.append('Quá nhiều subdomain')
    if domain.count('-') > 2:
        score += 10
        details.append('Nhiều dấu gạch ngang')
    if re.search(r'\d{3,}', domain):
        score += 10
        details.append('Chứa nhiều số liên tiếp')

    # Lookalike detection (Vietnamese banks + common targets)
    trusted_domains = _get_trusted_domains()

    similarity_warning = None
    for trusted, name in trusted_domains.items():
        # Simple Levenshtein-like check
        if trusted != domain and _is_lookalike(domain, trusted):
            score += 30
            details.append(f'Giống domain chính thức: {name} ({trusted})')
            similarity_warning = f'Có thể bạn muốn vào {trusted}'
            break

    # Check existing database
    try:
        db_domain = Domain.objects.get(domain_name=domain)
        score = max(score, db_domain.risk_score)
        if db_domain.report_count > 0:
            details.append(f'{db_domain.report_count} báo cáo từ cộng đồng')
    except Domain.DoesNotExist:
        pass

    # IP-based URL
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
        score += 20
        details.append('Sử dụng địa chỉ IP thay vì domain')

    score = min(100, score)

    if score >= 70:
        level = RiskLevel.RED
    elif score >= 40:
        level = RiskLevel.YELLOW
    elif score >= 10:
        level = RiskLevel.GREEN
    else:
        level = RiskLevel.SAFE

    result = {
        'url': url,
        'domain': domain,
        'risk_score': score,
        'risk_level': level,
        'details': details if details else ['Không phát hiện dấu hiệu phishing'],
        'ssl': network_info['ssl_valid'],
        'network_info': network_info,
    }

    if similarity_warning:
        result['similarity_warning'] = similarity_warning

    # Save/update domain in DB
    Domain.objects.update_or_create(
        domain_name=domain,
        defaults={
            'risk_score': score,
            'ssl_valid': network_info['ssl_valid'],
        }
    )

    return result


def _is_lookalike(domain: str, trusted: str) -> bool:
    """Simple lookalike detection using character substitution patterns"""
    # Remove TLD for comparison
    d1 = domain.split('.')[0]
    t1 = trusted.split('.')[0]

    if d1 == t1:
        return False  # exactly same, not lookalike

    # Common substitutions
    subs = {'0': 'o', '1': 'l', 'l': 'i', 'rn': 'm', 'vv': 'w'}
    normalized = d1
    for k, v in subs.items():
        normalized = normalized.replace(k, v)

    if normalized == t1:
        return True

    # Levenshtein distance <= 2
    if len(d1) > 3 and len(t1) > 3:
        dist = _levenshtein(d1, t1)
        if dist <= 2:
            return True

    return False


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein distance between two strings"""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


class ScanDomainView(APIView):
    """POST /api/scan/domain — Analyze URL/domain for phishing"""
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ScanDomainSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        url = serializer.validated_data['url'].strip()
        deep_scan = serializer.validated_data.get('deep_scan', False)

        if deep_scan:
            from api.core.models import ScanStatus
            from api.core.tasks import perform_web_scrapping_task
            
            scan_event = ScanEvent.objects.create(
                user=request.user if request.user.is_authenticated else None,
                scan_type='domain',
                raw_input=url,
                status=ScanStatus.PENDING
            )
            
            perform_web_scrapping_task.delay(scan_event.id, url)
            
            return Response({
                'scan_id': scan_event.id,
                'status': scan_event.status,
                'message': 'Đang tiến hành quét sâu nội dung website...'
            })

        # Standard scan
        result = _analyze_domain(url)

        # Turnstile Verification
        cf_token = request.data.get('cf-turnstile-response')
        if not verify_turnstile_token(cf_token):
            return Response({'error': 'Xác minh anti-spam không lệ. Vui lòng thử lại.'}, status=400)

        ScanEvent.objects.create(
            user=request.user if request.user.is_authenticated else None,
            scan_type='domain',
            raw_input=url,
            normalized_input=result['domain'],
            result_json=result,
            risk_score=result['risk_score'],
            risk_level=result['risk_level'],
        )

        return Response(result)


class ScanAccountView(APIView):
    """POST /api/scan/account — Look up bank account risk"""
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ScanAccountSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        bank = serializer.validated_data['bank'].strip()
        account = serializer.validated_data['account'].strip()
        account_hash = BankAccount.hash_account(account)
        account_masked = BankAccount.mask_account(account)

        # Look up database
        score = 0
        scam_type = 'other'
        report_count = 0
        details = []

        try:
            ba = BankAccount.objects.get(bank_name=bank, account_number_hash=account_hash)
            score = ba.risk_score
            scam_type = ba.scam_type
            report_count = ba.report_count
            if report_count > 0:
                details.append(f'{report_count} báo cáo từ cộng đồng')
        except BankAccount.DoesNotExist:
            pass

        # Check reports too
        reports_for_account = Report.objects.filter(
            target_type='account',
            target_value__icontains=account[-4:]
        ).count()
        if reports_for_account > 0:
            score = max(score, reports_for_account * 15)
            details.append(f'{reports_for_account} báo cáo liên quan')

        score = min(100, score)
        if score >= 70:
            level = RiskLevel.RED
        elif score >= 40:
            level = RiskLevel.YELLOW
        elif score >= 10:
            level = RiskLevel.GREEN
        else:
            level = RiskLevel.SAFE

        if not details:
            details.append('Không tìm thấy cảnh báo nào cho tài khoản này')

        result = {
            'bank': bank,
            'account_masked': account_masked,
            'risk_score': score,
            'risk_level': level,
            'scam_type': scam_type,
            'report_count': report_count,
            'details': details,
        }

        # Save/update in DB
        BankAccount.objects.update_or_create(
            bank_name=bank,
            account_number_hash=account_hash,
            defaults={
                'account_number_masked': account_masked,
                'risk_score': score,
            }
        )

        # Turnstile Verification
        cf_token = request.data.get('cf-turnstile-response')
        if not verify_turnstile_token(cf_token):
            return Response({'error': 'Xác minh anti-spam không lệ. Vui lòng thử lại.'}, status=400)

        ScanEvent.objects.create(
            user=request.user if request.user.is_authenticated else None,
            scan_type='account',
            raw_input=f'{bank}:{account_masked}',
            normalized_input=f'{bank}:{account_hash[:16]}',
            result_json=result,
            risk_score=score,
            risk_level=level,
        )

        return Response(result)


import logging
import base64
from rest_framework import status

logger = logging.getLogger(__name__)
from api.core.tasks import perform_image_scan_task
from api.core.models import ScanStatus

class ScanImageView(APIView):
    """
    POST /api/scan/image — OCR & Scam Analysis (Multi-image)
    Offloaded to Celery because OCR and AI are heavy.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ScanImageSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        # Try multiple keys for images to be robust
        images = request.FILES.getlist('images') or \
                 request.FILES.getlist('image') or \
                 request.FILES.getlist('file') or \
                 request.FILES.getlist('files')

        if not images:
            return Response({'error': 'Vui lòng cung cấp ít nhất một hình ảnh.'},
                            status=status.HTTP_400_BAD_REQUEST)

        # Turnstile Verification
        cf_token = request.data.get('cf-turnstile-response')
        if not verify_turnstile_token(cf_token):
            return Response({'error': 'Xác minh anti-spam không lệ. Vui lòng thử lại.'}, status=400)

        # Create PENDING event
        scan_event = ScanEvent.objects.create(
            user=request.user if request.user.is_authenticated else None,
            scan_type='qr', # We use 'qr' type for general image/OCR scans
            raw_input=f"Scan {len(images)} images",
            status=ScanStatus.PENDING
        )

        # Convert images to b64 for task
        images_data = []
        for img in images:
            logger.info(f"Processing image: {img.name} ({img.size} bytes)")
            img.seek(0)
            images_data.append(base64.b64encode(img.read()).decode('utf-8'))

        # Start task
        from api.core.tasks import perform_image_scan_task
        try:
            logger.info(f"Dispatching perform_image_scan_task for event {scan_event.id}")
            perform_image_scan_task.delay(scan_event.id, images_data)
            logger.info(f"Task successfully dispatched for event {scan_event.id}")
        except Exception as e:
            logger.error(f"Failed to dispatch task: {e}")
            scan_event.status = ScanStatus.FAILED
            scan_event.result_json = {'error': f'Task dispatch failed: {str(e)}'}
            scan_event.save()
            return Response({'error': 'Lỗi hệ thống khi bắt đầu quét.'}, status=500)

        return Response({
            'scan_id': scan_event.id,
            'status': scan_event.status,
            'message': 'Đang xử lý hình ảnh...'
        })


class ScanFileView(APIView):
    """
    POST /api/scan/file — File upload scan using VirusTotal
    """
    permission_classes = [AllowAny]

    def post(self, request):
        from api.core.serializers import ScanFileSerializer
        serializer = ScanFileSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        uploaded_file = request.FILES['file']
        
        # Turnstile Verification
        cf_token = request.data.get('cf-turnstile-response')
        if not verify_turnstile_token(cf_token):
            return Response({'error': 'Xác minh anti-spam không lệ. Vui lòng thử lại.'}, status=400)

        # Create PENDING event
        scan_event = ScanEvent.objects.create(
            user=request.user if request.user.is_authenticated else None,
            scan_type='message', # Reusing scan_type enums or extending them? spec said TargetType.QR for image. 
                                # Let's use 'message' or add FILE to ScanType maybe.
            raw_input=f"File: {uploaded_file.name}",
            status=ScanStatus.PENDING
        )

        # Save file to temp location
        import tempfile
        import os
        temp_dir = tempfile.gettempdir()
        file_path = os.path.join(temp_dir, f"{scan_event.id}_{uploaded_file.name}")
        
        with open(file_path, 'wb+') as destination:
            for chunk in uploaded_file.chunks():
                destination.write(chunk)

        # Offload to Celery
        from api.core.tasks import perform_file_scan_task
        try:
            perform_file_scan_task.delay(scan_event.id, file_path)
            return Response({
                'scan_id': scan_event.id,
                'status': scan_event.status,
                'message': 'Đang tải lên và phân tích file...'
            })
        except Exception as e:
            logger.error(f"Failed to dispatch file scan task: {e}")
            scan_event.status = ScanStatus.FAILED
            scan_event.save()
            if os.path.exists(file_path):
                os.remove(file_path)
            return Response({'error': 'Lỗi hệ thống khi bắt đầu quét file.'}, status=500)

class ScanStatusView(APIView):
    """
    GET /api/scan/status/<id> — Check status of a scan job
    """
    permission_classes = [AllowAny]

    def get(self, request, scan_id):
        from api.core.models import ScanEvent, ScanStatus
        try:
            event = ScanEvent.objects.get(id=scan_id)
            return Response({
                'id': event.id,
                'status': event.status,
                'scan_type': event.scan_type,
                'risk_score': event.risk_score,
                'risk_level': event.risk_level,
                'result': event.result_json if event.status == ScanStatus.COMPLETED else None
            })
        except ScanEvent.DoesNotExist:
            return Response({'error': 'Scan không tồn tại.'}, status=404)


def _extract_entities_from_text(text: str) -> dict:
    """Extract phone numbers, URLs, bank accounts from OCR text"""
    entities = {'phones': [], 'urls': [], 'accounts': [], 'otp_codes': []}
    if not text:
        return entities

    # Phone numbers (Vietnamese format)
    phones = re.findall(r'(?:\+84|0)\d{9,10}', text)
    entities['phones'] = list(set(phones))

    # URLs
    urls = re.findall(r'https?://[^\s<>"]+', text)
    entities['urls'] = list(set(urls))

    # Bank account patterns (6-19 digits)
    accounts = re.findall(r'\b\d{6,19}\b', text)
    entities['accounts'] = list(set(accounts))[:5]

    # OTP codes (4-8 digit codes)
    otp = re.findall(r'\b\d{4,8}\b', text)
    entities['otp_codes'] = list(set(otp))[:3]

    return entities


