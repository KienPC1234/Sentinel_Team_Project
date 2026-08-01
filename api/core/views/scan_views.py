"""ShieldCall VN – Scan Views"""
import re
import hashlib
import logging
import json
from urllib.parse import urlparse
from api.utils.security import verify_turnstile_token

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

def _phone_risk_score(phone_number: str) -> dict:
    """
    Phone Risk Engine (MVP spec 6.2).
    Risk = weighted sum of: reports_verified, reports_pending, recency
    """
    from api.phone_security.models import PhoneNumber
    # Normalize input for lookup
    phone_number = normalize_phone(phone_number)
    
    reports = Report.objects.filter(target_type='phone', target_value=phone_number)
    approved = reports.filter(status='approved').count()
    pending = reports.filter(status='pending').count()

    # Recency boost — reports in last 7 days count more
    recent = reports.filter(created_at__gte=timezone.now() - timedelta(days=7)).count()

    # Check if phone exists in phone_security database
    db_risk = 0
    scam_type = 'other'
    try:
        phone_obj = PhoneNumber.objects.get(phone_number=phone_number)
        # PhoneNumber uses risk_level (SAFE/GREEN/YELLOW/RED) not numeric score
        risk_map = {'SAFE': 0, 'GREEN': 10, 'YELLOW': 40, 'RED': 70}
        db_risk = risk_map.get(getattr(phone_obj, 'risk_level', 'SAFE'), 0)
        scam_type = getattr(phone_obj, 'scam_type', 'other') or 'other'
    except Exception:
        pass

    # Weighted formula
    w_approved = 15
    w_pending = 5
    w_recent = 10
    w_db = 1

    score = min(100, (approved * w_approved) + (pending * w_pending)
                + (recent * w_recent) + (db_risk * w_db))

    if score >= 70:
        level = RiskLevel.RED
    elif score >= 40:
        level = RiskLevel.YELLOW
    elif score >= 10:
        level = RiskLevel.GREEN
    else:
        level = RiskLevel.SAFE

    # Top reasons
    reasons = []
    if approved > 0:
        reasons.append(f'{approved} báo cáo đã xác minh')
    if pending > 0:
        reasons.append(f'{pending} báo cáo đang chờ duyệt')
    if recent > 0:
        reasons.append(f'{recent} báo cáo trong 7 ngày gần đây')
    if db_risk > 30:
        reasons.append('Có trong database cảnh báo')
    if not reasons:
        reasons.append('Không tìm thấy cảnh báo nào')

    return {
        'phone': phone_number,
        'risk_score': score,
        'risk_level': level,
        'scam_type': scam_type,
        'report_count': approved + pending,
        'reports_verified': approved,
        'last_seen': reports.order_by('-created_at').first().created_at.isoformat() if reports.exists() else None,
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
    """POST /api/scan/email — Analyze email sender and content"""
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ScanEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email'].lower().strip()
        content = serializer.validated_data.get('content', '').strip()

        # Robust domain extraction
        domain = email
        if '@' in email:
            domain = email.split('@')[-1]

        # 1. Reputation Check
        reports = Report.objects.filter(target_type='email', target_value=email)
        approved = reports.filter(status='approved').count()
        
        score = min(70, approved * 35) # High weight for confirmed reports
        
        # 2. Domain Check
        temp_domains = [
            'tempmail.com', '10minutemail.com', 'guerrillamail.com', 
            'mailinator.com', 'yopmail.com', 'dispostable.com'
        ]
        if domain in temp_domains:
            score += 40
            
        # 3. Content Analysis (Heuristic if content provided)
        if content:
            # We add context for AI but use the ensemble logic
            ai_res = analyze_text_for_scam(content)
            score = max(score, ai_res.get('risk_score', 0))

        score = min(100, score)
        level = RiskLevel.SAFE
        if score >= 70: level = RiskLevel.RED
        elif score >= 40: level = RiskLevel.YELLOW
        elif score >= 10: level = RiskLevel.GREEN

        result = {
            'email': email,
            'risk_score': score,
            'risk_level': level,
            'report_count': reports.count(),
            'details': [f'{approved} báo cáo cộng đồng xác thực'] if approved > 0 else ['Chưa có tiền sử lừa đảo']
        }

        # Turnstile Verification
        cf_token = request.data.get('cf-turnstile-response')
        if not verify_turnstile_token(cf_token):
            return Response({'error': 'Xác minh anti-spam không lệ. Vui lòng thử lại.'}, status=400)

        # Log event
        ScanEvent.objects.create(
            user=request.user if request.user.is_authenticated else None,
            scan_type='email',
            raw_input=email,
            normalized_input=email,
            result_json=result,
            risk_score=score,
            risk_level=level,
        )

        return Response(result)


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
    """
    # 1. AI Analysis (Ollama)
    ai_result = analyze_text_for_scam(text)
    ai_score = ai_result.get('risk_score', 0)
    ai_explanation = ai_result.get('explanation') or ai_result.get('reason') or ''
    
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

    # 3. Final Ensemble (AI + Domain Risk)
    final_score = max(ai_score, max_domain_score)
    
    # 4. Patterns (Heuristic)
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

    level = RiskLevel.SAFE
    if final_score >= 70: level = RiskLevel.RED
    elif final_score >= 40: level = RiskLevel.YELLOW
    elif final_score >= 10: level = RiskLevel.GREEN

    return {
        'risk_score': final_score,
        'risk_level': level,
        'explanation': ai_explanation,
        'patterns_found': list(set(patterns_found + domain_risks)),
        'ai_insight': ai_explanation
    }

    # Determine scam type
    scam_type = 'other'
    if any('công an' in p for p in patterns_found):
        scam_type = 'police_impersonation'
    elif any('ngân hàng' in p for p in patterns_found):
        scam_type = 'bank_impersonation'
    elif any('OTP' in p for p in patterns_found):
        scam_type = 'otp_steal'
    elif any('chuyển khoản' in p for p in patterns_found):
        scam_type = 'investment_scam'
    elif any('trúng thưởng' in p.lower() for p in patterns_found):
        scam_type = 'other'
    elif any('link' in p.lower() for p in patterns_found):
        scam_type = 'phishing'

    # Action checklist
    actions = []
    if final_score >= 70:
        actions = ['🚫 KHÔNG chuyển tiền', '🚫 KHÔNG cung cấp OTP',
                   '📞 Gọi 113 báo công an', '📸 Lưu bằng chứng']
    elif final_score >= 40:
        actions = ['⚠️ Kiểm tra lại nguồn gửi', '🔍 Tìm kiếm số/link trên ShieldCall',
                   '📝 Báo cáo nếu nghi ngờ']
    else:
        actions = ['✅ Tin nhắn có vẻ an toàn', '🔍 Vẫn nên cẩn thận với link lạ']

    return {
        'risk_score': final_score,
        'risk_level': level,
        'scam_type': scam_type,
        'patterns_found': patterns_found,
        'ai_analysis': ai_result.get('reason', ''),
        'explanation': f'Phát hiện {len(patterns_found)} dấu hiệu đáng ngờ.' if patterns_found
                       else 'Không phát hiện dấu hiệu lừa đảo rõ ràng.',
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


def _analyze_domain(url: str) -> dict:
    """Domain/URL Risk Engine with VirusTotal integration."""
    domain = normalize_domain(url)
    
    # Ensure URL has a scheme for VT scan
    if not re.match(r'^[a-z0-9]+://', url):
        full_url = 'https://' + url
    else:
        full_url = url

    score = 0
    details = []

    # 1. VirusTotal Scan
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

    # 2. Heuristic checks
    # Re-initialize score and details for heuristic part, as VT score is separate
    heuristic_score = 0
    heuristic_details = []

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
    trusted_domains = {
        'vietcombank.com.vn': 'Vietcombank',
        'techcombank.com.vn': 'Techcombank',
        'bidv.com.vn': 'BIDV',
        'vietinbank.vn': 'VietinBank',
        'mbbank.com.vn': 'MBBank',
        'agribank.com.vn': 'Agribank',
        'tpbank.vn': 'TPBank',
        'vpbank.com.vn': 'VPBank',
        'acb.com.vn': 'ACB',
        'momo.vn': 'Momo',
        'zalopay.vn': 'ZaloPay',
        'facebook.com': 'Facebook',
        'google.com': 'Google',
    }

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
        'ssl': url.startswith('https'),
    }

    if similarity_warning:
        result['similarity_warning'] = similarity_warning

    # Save/update domain in DB
    Domain.objects.update_or_create(
        domain_name=domain,
        defaults={
            'risk_score': score,
            'ssl_valid': url.startswith('https'),
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


