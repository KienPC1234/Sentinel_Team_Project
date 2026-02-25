"""ShieldCall VN – Centralized Security Scanning Utilities"""
import re
import math
import logging
import json
import socket
import ssl
import requests
from datetime import datetime, timedelta
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings

from api.core.models import Report, Domain, BankAccount, RiskLevel
from api.utils.normalization import normalize_phone, normalize_domain
from api.utils.vt_client import VTClient
from api.utils.trust_score import calculate_reporter_trust

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# PHONE SCAN LOGIC
# ---------------------------------------------------------------------------

def get_phone_risk(phone_number: str) -> dict:
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
    DECAY_LAMBDA = 0.15
    now = timezone.now()
    
    for r in reports:
        age_days = (now - r.created_at).days
        time_weight = math.exp(-DECAY_LAMBDA * age_days)
        
        trust = calculate_reporter_trust(r.reporter)
        
        status_weight = 0
        if r.status == 'approved':
            status_weight = 1.0
            verified_count += 1
        elif r.status == 'pending':
            status_weight = 0.2
            pending_count += 1
        elif r.status == 'rejected':
            continue
            
        impact = trust * time_weight * status_weight * 25 # Scale factor
        report_score += impact

    # 2. Network Intelligence
    network_score = 0.0
    carrier_info = "Unknown"
    is_virtual = False
    
    try:
        phone_obj = PhoneNumber.objects.get(phone_number=phone_number)
        carrier_info = phone_obj.carrier or "Unknown"
        is_virtual = phone_obj.is_virtual
        
        if phone_obj.risk_level == RiskLevel.RED:
            network_score += 60
        elif phone_obj.risk_level == RiskLevel.YELLOW:
            network_score += 30
            
        if is_virtual:
            network_score += 25
            
        if carrier_info == 'VirtualProvider':
             network_score += 15

    except PhoneNumber.DoesNotExist:
        pass

    # 3. Behavioral Features (Velocity)
    recent_velocity = reports.filter(created_at__gte=now - timedelta(hours=24)).count()
    velocity_score = 0
    if recent_velocity > 10:
        velocity_score = 40
    elif recent_velocity > 3:
        velocity_score = 15

    # --- FINAL AGGREGATION ---
    final_score = report_score + network_score + velocity_score
    final_score = min(100, final_score)
    
    level = RiskLevel.SAFE
    if final_score >= 80: level = RiskLevel.RED
    elif final_score >= 40: level = RiskLevel.YELLOW
    elif final_score >= 15: level = RiskLevel.GREEN

    reasons = []
    if verified_count > 0:
        reasons.append(f'{verified_count} báo cáo uy tín đã xác minh')
    if is_virtual:
        reasons.append('Số điện thoại ảo (Virtual Number)')
    if velocity_score > 0:
        reasons.append(f'Tăng đột biến: {recent_velocity} báo cáo trong 24h')
    if report_score > 20 and not verified_count:
        reasons.append('Nhiều báo cáo từ cộng đồng (đang chờ duyệt)')

    return {
        'phone': phone_number,
        'risk_score': round(final_score),
        'risk_level': level,
        'scam_type': 'other', 
        'report_count': verified_count + pending_count,
        'reports_verified': verified_count,
        'carrier': carrier_info,
        'is_virtual': is_virtual,
        'trust_score': round(report_score, 2),
        'reasons': reasons[:3],
    }

# ---------------------------------------------------------------------------
# DOMAIN / URL SCAN LOGIC
# ---------------------------------------------------------------------------

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
    
    try:
        network_info['ip_address'] = socket.gethostbyname(domain)
    except socket.gaierror:
        network_info['error'] = 'DNS resolution failed'
        return network_info

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                network_info['ssl_valid'] = True
                issuer = dict(x[0] for x in cert['issuer'])
                network_info['cert_issuer'] = issuer.get('organizationName') or issuer.get('commonName')
                
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
    except Exception as e:
        network_info['ssl_valid'] = False
        network_info['ssl_error'] = str(e)

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
        if not network_info['error']:
             network_info['error'] = str(e)
    return network_info

def _get_trusted_domains() -> dict:
    trusted = cache.get('trusted_domains_list')
    if trusted:
        return trusted
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
    cache.set('trusted_domains_list', default_trusted, 86400)
    return default_trusted

def _levenshtein(s1: str, s2: str) -> int:
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

def _is_lookalike(domain: str, trusted: str) -> bool:
    d1 = domain.split('.')[0]
    t1 = trusted.split('.')[0]
    if d1 == t1:
        return False
    subs = {'0': 'o', '1': 'l', 'l': 'i', 'rn': 'm', 'vv': 'w'}
    normalized = d1
    for k, v in subs.items():
        normalized = normalized.replace(k, v)
    if normalized == t1:
        return True
    if len(d1) > 3 and len(t1) > 3:
        if _levenshtein(d1, t1) <= 2:
            return True
    return False

def get_domain_risk(url: str) -> dict:
    """Domain/URL Risk Engine with VirusTotal integration and Network Analysis."""
    from api.utils.ollama_client import lookup_tranco
    domain = normalize_domain(url)
    if not re.match(r'^[a-z0-9]+://', url):
        full_url = 'https://' + url
    else:
        full_url = url

    score = 0
    details = []
    network_info = _analyze_network(full_url, domain)
    
    if not network_info['ssl_valid']:
        score += 15
        details.append('Chứng chỉ SSL không hợp lệ hoặc không có HTTPS')
    elif network_info.get('cert_age_days', 0) < 3:
        score += 20
        details.append(f"Chứng chỉ SSL mới tạo ({network_info['cert_age_days']} ngày) - Rủi ro cao")
        
    issuer = str(network_info.get('cert_issuer', '')).lower()
    if 'let\'s encrypt' in issuer or 'cloudflare' in issuer:
        is_lookalike = any(_is_lookalike(domain, trusted) for trusted in _get_trusted_domains())
        if is_lookalike:
            score += 10
            details.append('Sử dụng chứng chỉ miễn phí cho tên miền giống ngân hàng')

    if network_info.get('redirects', 0) > 2:
        score += 15
        details.append(f"Chuyển hướng quá nhiều lần ({network_info['redirects']} lần)")
        
    if network_info.get('error'):
        score += 10
        details.append('Không thể kết nối đến trang web')

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

    tranco_data = lookup_tranco(domain)
    if tranco_data and tranco_data.get('content') and "Popularity Rank" in tranco_data['content']:
        try:
            rank_part = tranco_data['content'].split('Popularity Rank: ')[1].split('\n')[0]
            if rank_part.isdigit():
                rank = int(rank_part)
                if rank < 10000:
                    score = max(0, score - 60)
                    details.append(f"Quy mô lớn (Tranco Top {rank}) - Rất uy tín")
                elif rank < 100000:
                    score = max(0, score - 30)
                    details.append(f"Website phổ biến (Tranco Top {rank})")
                elif rank < 1000000:
                    score = max(0, score - 10)
                    details.append(f"Website đã index (Top {rank})")
        except Exception as e:
            logger.warning(f"Tranco parse error: {e}")

    if len(domain) > 30: score += 10; details.append('Domain name dài bất thường')
    if domain.count('.') > 3: score += 15; details.append('Quá nhiều subdomain')
    if domain.count('-') > 2: score += 10; details.append('Nhiều dấu gạch ngang')
    if re.search(r'\d{3,}', domain): score += 10; details.append('Chứa nhiều số liên tiếp')

    trusted_domains = _get_trusted_domains()
    similarity_warning = None
    for trusted, name in trusted_domains.items():
        if trusted != domain and _is_lookalike(domain, trusted):
            score += 30
            details.append(f'Giống domain chính thức: {name} ({trusted})')
            similarity_warning = f'Có thể bạn muốn vào {trusted}'
            break

    try:
        db_domain = Domain.objects.get(domain_name=domain)
        score = max(score, db_domain.risk_score)
        if db_domain.report_count > 0:
            details.append(f'{db_domain.report_count} báo cáo từ cộng đồng')
    except Domain.DoesNotExist:
        pass

    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
        score += 20
        details.append('Sử dụng địa chỉ IP thay vì domain')

    score = min(100, score)
    level = RiskLevel.SAFE
    if score >= 70: level = RiskLevel.RED
    elif score >= 40: level = RiskLevel.YELLOW
    elif score >= 10: level = RiskLevel.GREEN

    result = {
        'url': url,
        'domain': domain,
        'risk_score': score,
        'risk_level': level,
        'details': details if details else ['Không phát hiện dấu hiệu phishing'],
        'ssl': network_info['ssl_valid'],
        'network_info': network_info,
    }
    if similarity_warning: result['similarity_warning'] = similarity_warning

    Domain.objects.update_or_create(
        domain_name=domain,
        defaults={'risk_score': score, 'ssl_valid': network_info['ssl_valid']}
    )
    return result

# ---------------------------------------------------------------------------
# BANK ACCOUNT SCAN LOGIC
# ---------------------------------------------------------------------------

def get_bank_risk(bank_name: str, account_number: str) -> dict:
    """Look up bank account risk."""
    bank = bank_name.strip()
    account = account_number.strip()
    account_hash = BankAccount.hash_account(account)
    account_masked = BankAccount.mask_account(account)

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

    reports_for_account = Report.objects.filter(
        target_type='account',
        target_value__icontains=account[-4:]
    ).count()
    if reports_for_account > 0:
        score = max(score, reports_for_account * 15)
        details.append(f'{reports_for_account} báo cáo liên quan')

    score = min(100, score)
    level = RiskLevel.SAFE
    if score >= 70: level = RiskLevel.RED
    elif score >= 40: level = RiskLevel.YELLOW
    elif score >= 10: level = RiskLevel.GREEN

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

    BankAccount.objects.update_or_create(
        bank_name=bank,
        account_number_hash=account_hash,
        defaults={'account_number_masked': account_masked, 'risk_score': score}
    )
    return result

# ---------------------------------------------------------------------------
# ENTITY EXTRACTION
# ---------------------------------------------------------------------------

def extract_entities_from_text(text: str) -> dict:
    """Extract phone numbers, URLs, bank accounts from OCR text"""
    entities = {'phones': [], 'urls': [], 'accounts': [], 'otp_codes': []}
    if not text:
        return entities

    phones = re.findall(r'(?:\+84|0)\d{9,10}', text)
    entities['phones'] = list(set(phones))

    urls = re.findall(r'https?://[^\s<>"]+', text)
    entities['urls'] = list(set(urls))

    accounts = re.findall(r'\b\d{6,19}\b', text)
    entities['accounts'] = list(set(accounts))[:5]

    otp = re.findall(r'\b\d{4,8}\b', text)
    entities['otp_codes'] = list(set(otp))[:3]

    return entities
