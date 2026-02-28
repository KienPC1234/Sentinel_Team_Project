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

from api.utils.ollama_client import analyze_text_for_scam, generate_response, stream_response, lookup_tranco

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

from api.utils.normalization import normalize_phone, normalize_phone_e164, normalize_domain
from api.utils.vt_client import VTClient

import math
import phonenumbers
from phonenumbers import carrier, geocoder, PhoneNumberType
from api.utils.trust_score import calculate_reporter_trust

def _phone_risk_score(phone_number: str) -> dict:
    """
    Production-grade phone risk engine.

    Hybrid scoring (0-100):
    - Reputation/complaints component (0-45)
    - Number metadata component (0-25)
    - Behavioral velocity component (0-30)
    """
    from api.phone_security.models import PhoneNumber
    # Normalize input for lookup (prefer E.164, fallback for internal legacy callers)
    try:
        phone_number = normalize_phone_e164(phone_number, strict=False)
    except ValueError:
        phone_number = normalize_phone(phone_number)

    # 1) Fetch reports (exclude rejected) and compute trust/recency-weighted reputation
    reports = Report.objects.filter(
        target_type='phone',
        target_value=phone_number,
    ).exclude(status='rejected').select_related('reporter', 'reporter__profile')

    reputation_raw = 0.0
    approved_count = 0
    pending_count = 0

    # Decay: still meaningful after 7-30 days, but prioritizes recent waves.
    DECAY_LAMBDA = 0.12
    now = timezone.now()

    severity_weight = {
        'low': 0.8,
        'medium': 1.0,
        'high': 1.25,
        'critical': 1.5,
    }

    for r in reports:
        age_days = max(0, (now - r.created_at).days)
        time_weight = math.exp(-DECAY_LAMBDA * age_days)

        trust = calculate_reporter_trust(r.reporter)

        status_weight = 0.0
        if r.status == 'approved':
            status_weight = 1.0
            approved_count += 1
        elif r.status == 'pending':
            status_weight = 0.25
            pending_count += 1
        else:
            continue

        sev = severity_weight.get((r.severity or 'medium').lower(), 1.0)
        # Max per approved critical recent report is intentionally capped by final component bound.
        impact = 12.0 * trust * time_weight * status_weight * sev
        reputation_raw += impact

    reputation_score = min(45.0, reputation_raw)

    # 2) Number metadata / provenance component
    metadata_score = 0.0
    carrier_info = "Unknown"
    is_virtual = False
    is_valid = True # Default to True unless explicitly proven invalid by library
    line_type = "Unknown"
    # Sensible defaults for country (not strictly defaulting to VN)
    country_code = "UNKNOWN"
    country_name = "Không xác định"
    
    # Analyze prefix/international metadata via phonenumbers library first
    try:
        # Import directly to ensure availability of helper
        from phonenumbers import region_code_for_country_code, is_valid_number
        parsed = phonenumbers.parse(phone_number)
        
        # 1. Detect ISO Country Code
        detected_region = phonenumbers.region_code_for_number(parsed)
        if not detected_region and parsed.country_code:
            # Full fallback across all known library country codes
            detected_region = region_code_for_country_code(parsed.country_code)
        
        country_code = detected_region or "VN"
        
        # 2. Get Country Name in Vietnamese
        vi_name = geocoder._region_display_name(detected_region, "vi")
        
        country_name = vi_name
        
        # Try to get carrier name using the detected region and fallback to 'en'
        # This will query phonenumbers with the specific country region (e.g. 'CN' for China) 
        # for better provider identification.
        carrier_info = (
            carrier.name_for_number(parsed, country_code) or 
            carrier.name_for_number(parsed, 'en') or 
            "Unknown Provider"
        )
        
        # 3. Validation & Line Type
        is_valid = is_valid_number(parsed)
        ntype = phonenumbers.number_type(parsed)
        line_type_map = {
            PhoneNumberType.MOBILE: "Mobile",
            PhoneNumberType.FIXED_LINE: "Fixed Line",
            PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed or Mobile",
            PhoneNumberType.VOIP: "VoIP (Virtual/Net)",
            PhoneNumberType.PAGER: "Pager",
            PhoneNumberType.PERSONAL_NUMBER: "Personal",
            PhoneNumberType.PREMIUM_RATE: "Premium",
            PhoneNumberType.TOLL_FREE: "Toll-free",
            PhoneNumberType.UAN: "UAN",
            PhoneNumberType.SHARED_COST: "Shared Cost",
            PhoneNumberType.VOICEMAIL: "Voicemail",
        }
        line_type = line_type_map.get(ntype, "Unknown")
        is_virtual = (ntype == PhoneNumberType.VOIP)

        # Baseline risks for invalid/anonymous types
        if not is_valid:
            metadata_score += 10 # Potential spoofed or fake number pattern
        if is_virtual:
            metadata_score += 15
        if ntype == PhoneNumberType.PREMIUM_RATE:
            metadata_score += 10

    except Exception:
        pass

    # Enrich from internal DB (reputation memory) if exists
    try:
        phone_obj = PhoneNumber.objects.get(phone_number=phone_number)
        # Prefer DB carrier/type if explicit, otherwise fallback to analyzed
        carrier_info = phone_obj.carrier or carrier_info
        is_virtual = phone_obj.is_virtual or is_virtual
        line_type = phone_obj.line_type or line_type
        country_code = phone_obj.country_code or country_code

        # Historical risk memory (heavy penalty if blacklisted)
        if phone_obj.risk_level == RiskLevel.RED:
            metadata_score += 20
        elif phone_obj.risk_level == RiskLevel.YELLOW:
            metadata_score += 10
        elif phone_obj.risk_level == RiskLevel.GREEN:
            metadata_score += 3
        
        # Override virtual if explicitly set in DB
        if phone_obj.is_virtual:
            metadata_score += 5 # Additional flag for known-bad virtual providers

    except PhoneNumber.DoesNotExist:
        # If it's a new number, we keep the analyzed metadata but may add subtle risk flags
        # for suspicious patterns (e.g. unknown carriers in specific regions)
        if carrier_info == "Unknown" and country_code != "VN":
            metadata_score += 5

    line_type_l = line_type.lower()
    if 'voip' in line_type_l:
        metadata_score += 15
    elif 'toll' in line_type_l:
        metadata_score += 8

    carrier_l = carrier_info.lower()
    if any(k in carrier_l for k in ['virtual', 'cloud', 'internet', 'twilio', 'skype']):
        metadata_score += 8

    if country_code and country_code.upper() != 'VN':
        metadata_score += 4

    metadata_score = min(25.0, metadata_score)

    # 3) Behavioral component (velocity / burst / diversity)
    reports_1h = reports.filter(created_at__gte=now - timedelta(hours=1)).count()
    reports_24h = reports.filter(created_at__gte=now - timedelta(hours=24)).count()
    reports_7d = reports.filter(created_at__gte=now - timedelta(days=7)).count()

    unique_reporters_24h = reports.filter(
        created_at__gte=now - timedelta(hours=24),
        reporter__isnull=False,
    ).values('reporter_id').distinct().count()

    velocity_norm = min(1.0, reports_24h / 12.0)
    burst_norm = min(1.0, reports_1h / 4.0)
    diversity_norm = min(1.0, unique_reporters_24h / 6.0)
    recency_ratio = (reports_24h + 1.0) / (reports_7d + 1.0)
    recency_norm = min(1.0, recency_ratio * 2.0)

    behavior_norm = (
        0.45 * velocity_norm +
        0.25 * burst_norm +
        0.20 * diversity_norm +
        0.10 * recency_norm
    )
    behavior_score = min(30.0, 30.0 * behavior_norm)

    # --- FINAL AGGREGATION ---
    final_score = min(100.0, reputation_score + metadata_score + behavior_score)
    final_score_int = int(round(final_score))
    
    # Determine level (operational thresholds)
    level = RiskLevel.SAFE
    if final_score_int > 80:
        level = RiskLevel.RED
    elif final_score_int > 50:
        level = RiskLevel.YELLOW
    elif final_score_int > 20:
        level = RiskLevel.GREEN

    # Action map aligned with thresholds
    suggested_action = 'ALLOW'
    if final_score_int > 80:
        suggested_action = 'BLOCK'
    elif final_score_int > 50:
        suggested_action = 'VOICEMAIL_OR_WARN'
    elif final_score_int > 20:
        suggested_action = 'WARN'

    # Reasons (top explainers)
    reasons = []
    if approved_count > 0:
        reasons.append(f'{approved_count} báo cáo đã duyệt (độ tin cậy cao)')
    if pending_count > 0:
        reasons.append(f'{pending_count} báo cáo đang chờ duyệt')
    if is_virtual:
        reasons.append('Số điện thoại ảo (Virtual Number)')
    if not is_valid:
        reasons.append('Định dạng số không hợp lệ (Có thể là số giả/spoofed)')
    if reports_24h > 0:
        reasons.append(f'Tần suất tăng: {reports_24h} báo cáo trong 24h')
    if unique_reporters_24h >= 3:
        reasons.append(f'Nhiều nguồn độc lập: {unique_reporters_24h} người báo cáo trong 24h')
    if 'voip' in str(line_type).lower():
        reasons.append('Line type VoIP - nguy cơ spoofing cao hơn')
    if metadata_score >= 18 and not approved_count:
        reasons.append('Tín hiệu metadata rủi ro dù chưa có nhiều báo cáo duyệt')

    if not reasons:
        reasons.append('Chưa thấy tín hiệu rủi ro mạnh từ dữ liệu hiện có')

    # Synthesize analysis result text for the frontend summary block
    status_label = "AN TOÀN"
    if level == RiskLevel.RED: status_label = "NGUY HIỂM / LỪA ĐẢO"
    elif level == RiskLevel.YELLOW: status_label = "CẢNH GIÁC CAO"
    elif level == RiskLevel.GREEN: status_label = "CÓ RỦI RO THẤP"

    analysis_result = f"Số điện thoại {phone_number} (`{country_name}`) hiện đang ở mức `{status_label}`. "
    analysis_result += f"Đây là một thuê bao thuộc nhà mạng **{carrier_info}** ({line_type}). "
    analysis_result += f"Hệ thống ghi nhận tổng cộng {approved_count + pending_count} báo cáo từ cộng đồng. "
    if is_virtual:
        analysis_result += "Đây là một số điện thoại ảo (Virtual/VoIP), thường được dùng để che giấu danh tính. "
    analysis_result += f"Hành động khuyến nghị: **{suggested_action}**."

    return {
        'phone': phone_number,
        'risk_score': final_score_int,
        'risk_level': level,
        'suggested_action': suggested_action,
        'scam_type': 'other',
        'report_count': approved_count + pending_count,
        'reports_verified': approved_count,
        'carrier': carrier_info,
        'line_type': line_type,
        'country_code': country_code,
        'country_name': country_name,
        'is_virtual': is_virtual,
        'trust_score': round(reputation_score, 2),
        'analysis_result': analysis_result,
        'component_scores': {
            'reputation': round(reputation_score, 2),
            'metadata': round(metadata_score, 2),
            'behavior': round(behavior_score, 2),
        },
        'check_descriptions': {
            'reputation': (
                f"Uy tín cộng đồng: {approved_count} báo cáo đã duyệt, {pending_count} báo cáo chờ duyệt; "
                f"điểm thành phần {round(reputation_score, 2)}/45."
            ),
            'metadata': (
                f"Tín hiệu metadata: carrier={carrier_info}, line_type={line_type}, "
                f"virtual={'có' if is_virtual else 'không'}, country={country_code}; "
                f"điểm thành phần {round(metadata_score, 2)}/25."
            ),
            'behavior': (
                f"Hành vi gần đây: {reports_1h} báo cáo/1h, {reports_24h} báo cáo/24h, "
                f"{unique_reporters_24h} nguồn độc lập; điểm thành phần {round(behavior_score, 2)}/30."
            ),
        },
        'metrics': {
            'reports_1h': reports_1h,
            'reports_24h': reports_24h,
            'reports_7d': reports_7d,
            'unique_reporters_24h': unique_reporters_24h,
        },
        'reasons': reasons[:5],
    }


class ScanPhoneView(APIView):
    """POST /api/scan/phone — Scan phone number risk"""
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ScanPhoneSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Turnstile Verification (before expensive work)
        cf_token = request.data.get('cf-turnstile-response')
        if not verify_turnstile_token(cf_token):
            return Response({'error': 'Xác minh anti-spam không hợp lệ. Vui lòng thử lại.'}, status=400)

        # Already validated as E.164 by serializer (requires country flag).
        phone = serializer.validated_data['phone']

        result = _phone_risk_score(phone)

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
        # Turnstile Verification
        cf_token = request.data.get('cf-turnstile-response')
        if not verify_turnstile_token(cf_token):
            return Response({'error': 'Xác minh anti-spam không hợp lệ. Vui lòng thử lại.'}, status=400)

        file_obj = request.FILES.get('file')
        content_text = request.data.get('content', '')
        sender_input = request.data.get('email', '')
        
        email_data = {
            'subject': '',
            'from': sender_input,
            'body': content_text,
            'urls': [],
            'attachments': [],
            'to': '',
            'reply_to': '',
            'delivered_to': '',
            'received_chain': [],
            'return_path': '',
            'authentication_results': '',
            'content_type': 'text/plain',
            'analysis_type': 'text'
        }

        # 1. Parse Input Source (.eml takes precedence)
        if file_obj:
            try:
                # Limit size to 10MB
                if file_obj.size > 15 * 1024 * 1024:
                    return Response({'error': 'File quá lớn (Max 15MB).'}, status=400)

                # Use updated util
                from api.utils.email_utils import parse_eml_content
                parsed = parse_eml_content(file_obj.read())
                
                if not parsed:
                    return Response({'error': 'Không thể đọc file .eml.'}, status=400)

                email_data = {
                    'subject': parsed['subject'],
                    'from': parsed['from'],
                    'to': parsed.get('to', ''),
                    'reply_to': parsed.get('reply_to', ''),
                    'delivered_to': parsed.get('delivered_to', ''),
                    'received_chain': parsed.get('received_chain', []),
                    'return_path': parsed.get('return_path', ''),
                    'authentication_results': parsed.get('authentication_results', ''),
                    'content_type': parsed.get('content_type', ''),
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

        # Turnstile Verification (before any processing)
        cf_token = request.data.get('cf-turnstile-response')
        if not verify_turnstile_token(cf_token):
            return Response({'error': 'Xác minh anti-spam không hợp lệ. Vui lòng thử lại.'}, status=400)

        # Multiple images support
        images = request.FILES.getlist('image') or request.FILES.getlist('images')

        if not text.strip() and not images:
            return Response({'error': 'Vui lòng nhập tin nhắn hoặc tải ảnh.'},
                            status=status.HTTP_400_BAD_REQUEST)

        # Create PENDING scan event
        from api.core.models import ScanStatus
        scan_event = ScanEvent.objects.create(
            user=request.user if request.user.is_authenticated else None,
            scan_type='message',
            raw_input=(text or '')[:2000],
            status=ScanStatus.PENDING
        )

        # Convert images to base64 for Celery task
        import base64
        images_b64 = []
        for img in images:
            try:
                img.seek(0)
                images_b64.append(base64.b64encode(img.read()).decode('utf-8'))
            except Exception as e:
                logger.error(f"Image encode error: {e}")

        # Dispatch to Celery
        from api.core.tasks import perform_message_scan_task
        try:
            perform_message_scan_task.delay(scan_event.id, text.strip(), images_b64)
        except Exception as e:
            logger.error(f"Failed to dispatch message scan task: {e}")
            scan_event.status = ScanStatus.FAILED
            scan_event.save()
            return Response({'error': 'Lỗi hệ thống khi bắt đầu quét.'}, status=500)

        return Response({
            'scan_id': scan_event.id,
            'status': 'pending',
            'message': 'Đang phân tích tin nhắn...'
        })


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

    # 0. Fetch page content using requests + BeautifulSoup
    fetch_success = False
    page_title = ""
    content_length = 0
    try:
        from api.utils.ollama_client import web_fetch_url
        fetch_result = web_fetch_url(full_url)
        if fetch_result and fetch_result.get('content'):
            fetch_success = True
            page_title = fetch_result.get('title', '') or ''
            content_length = len(fetch_result.get('content', ''))
    except Exception as e:
        logger.warning(f"[ScanDomain] content fetch failed for {url}: {e}")

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

    # 3. Tranco Rank (Pro-active Popularity Check)
    tranco_data = lookup_tranco(domain)
    if tranco_data and tranco_data.get('content') and "Popularity Rank" in tranco_data['content']:
        try:
            rank_part = tranco_data['content'].split('Popularity Rank: ')[1].split('\n')[0]
            if rank_part.isdigit():
                rank = int(rank_part)
                # If rank is high (number is low), it's a very popular site
                if rank < 10000:
                    score = max(0, score - 60) # Massive trust boost
                    details.append(f"Quy mô lớn (Tranco Top {rank}) - Rất uy tín")
                elif rank < 100000:
                    score = max(0, score - 30)
                    details.append(f"Website phổ biến (Tranco Top {rank})")
                elif rank < 1000000:
                    score = max(0, score - 10)
                    details.append(f"Website đã index (Top {rank})")
            else: 
                # Rank is N/A or text
                pass
        except Exception as e:
            logger.warning(f"Tranco parse error: {e}")

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
        'fetch_success': fetch_success,
        'page_title': page_title,
        'content_length': content_length,
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

        # Turnstile Verification (before any processing)
        cf_token = request.data.get('cf-turnstile-response')
        if not verify_turnstile_token(cf_token):
            return Response({'error': 'Xác minh anti-spam không hợp lệ. Vui lòng thử lại.'}, status=400)

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

        # Standard scan with error handling
        try:
            result = _analyze_domain(url)
        except Exception as e:
            logger.error(f"[ScanDomain] _analyze_domain failed for {url}: {e}")
            return Response({
                'error': 'Không thể phân tích tên miền. Vui lòng thử lại sau.',
                'url': url,
            }, status=502)

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
            return Response({'error': 'Xác minh anti-spam không hợp lệ. Vui lòng thử lại.'}, status=400)

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
            return Response({'error': 'Xác minh anti-spam không hợp lệ. Vui lòng thử lại.'}, status=400)

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
            return Response({'error': 'Xác minh anti-spam không hợp lệ. Vui lòng thử lại.'}, status=400)

        # Create PENDING event
        scan_event = ScanEvent.objects.create(
            user=request.user if request.user.is_authenticated else None,
            scan_type='file',
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


class ScanAudioView(APIView):
    """
    POST /api/scan/audio — Audio transcription + AI scam analysis.
    Accepts audio file upload, offloads to Celery for Faster-Whisper + AI.
    """
    permission_classes = [AllowAny]
    parser_classes = [MultiPartParser, FormParser]

    ALLOWED_EXTENSIONS = ('.mp3', '.m4a', '.wav', '.ogg', '.webm', '.flac', '.aac')
    MAX_SIZE = 50 * 1024 * 1024  # 50 MB

    def post(self, request):
        audio_file = request.FILES.get('audio')
        if not audio_file:
            return Response(
                {'error': 'Vui lòng cung cấp file âm thanh.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Validate extension
        ext = '.' + audio_file.name.rsplit('.', 1)[-1].lower() if '.' in audio_file.name else ''
        if ext not in self.ALLOWED_EXTENSIONS:
            return Response(
                {'error': f'Định dạng không hỗ trợ. Chấp nhận: {", ".join(self.ALLOWED_EXTENSIONS)}'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Validate size
        if audio_file.size > self.MAX_SIZE:
            return Response(
                {'error': 'File quá lớn. Tối đa 50 MB.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Turnstile verification
        cf_token = request.data.get('cf-turnstile-response')
        if not verify_turnstile_token(cf_token):
            return Response(
                {'error': 'Xác minh anti-spam không hợp lệ. Vui lòng thử lại.'},
                status=400,
            )

        # Create PENDING scan event
        from api.core.models import ScanEvent, ScanStatus
        scan_event = ScanEvent.objects.create(
            user=request.user if request.user.is_authenticated else None,
            scan_type='audio',
            raw_input=f"Audio: {audio_file.name} ({audio_file.size} bytes)",
            status=ScanStatus.PENDING,
        )

        # Save audio to temp path for Celery worker
        import tempfile, os
        temp_dir = tempfile.gettempdir()
        file_path = os.path.join(temp_dir, f"audio_{scan_event.id}_{audio_file.name}")
        with open(file_path, 'wb+') as dest:
            for chunk in audio_file.chunks():
                dest.write(chunk)

        # Dispatch Celery task
        from api.core.tasks import perform_audio_scan_task
        try:
            perform_audio_scan_task.delay(scan_event.id, file_path)
        except Exception as e:
            logger.error(f"Failed to dispatch audio scan task: {e}")
            scan_event.status = ScanStatus.FAILED
            scan_event.result_json = {'error': f'Task dispatch failed: {str(e)}'}
            scan_event.save()
            if os.path.exists(file_path):
                os.remove(file_path)
            return Response({'error': 'Lỗi hệ thống khi bắt đầu quét.'}, status=500)

        return Response({
            'scan_id': scan_event.id,
            'status': scan_event.status,
            'message': 'Đang xử lý âm thanh...',
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


