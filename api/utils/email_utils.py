"""ShieldCall VN – Email Utilities"""
import logging
import email
import re
import ipaddress
from typing import Dict, Any, List
from urllib.parse import urlparse
from email.policy import default
from bs4 import BeautifulSoup
import dns.resolver

from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags

logger = logging.getLogger(__name__)


def _extract_sender_domain(sender_text: str) -> str:
    match = re.search(r'([\w\.-]+@[\w\.-]+)', sender_text or '')
    if not match:
        return ''
    return match.group(1).split('@')[-1].lower().strip()


def _parse_authentication_results(auth_text: str) -> Dict[str, str]:
    auth_raw = (auth_text or '').lower()

    def _pick(pattern: str) -> str:
        m = re.search(pattern, auth_raw)
        return m.group(1) if m else 'unknown'

    return {
        'spf': _pick(r'spf=(pass|fail|softfail|permerror|temperror|neutral|none)'),
        'dkim': _pick(r'dkim=(pass|fail|permerror|temperror|neutral|none)'),
        'dmarc': _pick(r'dmarc=(pass|fail|bestguesspass|none|quarantine|reject)'),
        'arc': 'present' if 'arc-' in auth_raw else 'absent',
    }


def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address((host or '').strip())
        return True
    except ValueError:
        return False


def compute_eml_weighted_risk(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute weighted risk score (0-100) for parsed EML data.

    Components (A..F):
    - A Authentication & trust (40%)
    - B Delivery path & envelope (10%)
    - C Sender reputation & DNS (15%)
    - D Message content (20%)
    - E Attachments (10%)
    - F Technical anomalies / header oddities (5%)
    """
    details: List[str] = []

    subject = (email_data.get('subject') or '').strip()
    sender = (email_data.get('from') or '').strip()
    body = (email_data.get('body') or '').strip()
    urls = email_data.get('urls') or []
    attachments = email_data.get('attachments') or []
    received_chain = email_data.get('received_chain') or []
    auth_results = _parse_authentication_results(email_data.get('authentication_results', ''))
    return_path = (email_data.get('return_path') or '').strip()
    reply_to = (email_data.get('reply_to') or '').strip()
    delivered_to = (email_data.get('delivered_to') or '').strip()
    content_type = (email_data.get('content_type') or '').lower()

    sender_domain = _extract_sender_domain(sender)
    return_domain = _extract_sender_domain(return_path)
    reply_domain = _extract_sender_domain(reply_to)

    # A) Authentication & trust
    A = 0.0
    spf = auth_results.get('spf', 'unknown')
    dkim = auth_results.get('dkim', 'unknown')
    dmarc = auth_results.get('dmarc', 'unknown')

    if spf == 'fail':
        A += 1.0
        details.append('SPF fail')
    elif spf in {'softfail', 'permerror', 'temperror'}:
        A += 0.7
        details.append(f'SPF {spf}')
    elif spf in {'neutral', 'none', 'unknown'}:
        A += 0.4
        details.append('SPF không chắc chắn')

    if dkim == 'fail':
        A += 1.0
        details.append('DKIM fail')
    elif dkim in {'permerror', 'temperror'}:
        A += 0.8
        details.append(f'DKIM {dkim}')
    elif dkim in {'none', 'unknown'}:
        A += 0.5
        details.append('DKIM thiếu hoặc không rõ')

    if dmarc == 'fail':
        A += 1.0
        details.append('DMARC fail')
    elif dmarc in {'quarantine', 'reject'}:
        A += 0.7
        details.append(f'DMARC policy={dmarc}')
    elif dmarc in {'none', 'unknown'}:
        A += 0.4
        details.append('DMARC không rõ')

    A = min(1.0, A)

    # B) Delivery path & envelope
    B = 0.0
    hops = len(received_chain)
    if hops >= 8:
        B += 0.8
        details.append(f'Chuỗi Received dài bất thường ({hops} hops)')
    elif hops >= 5:
        B += 0.4

    if sender_domain and return_domain and sender_domain != return_domain:
        B += 0.5
        details.append('Return-Path khác domain người gửi')

    if not delivered_to:
        B += 0.2

    B = min(1.0, B)

    # C) Sender reputation & DNS
    C = 0.0
    if sender_domain:
        try:
            txt_records = dns.resolver.resolve(sender_domain, 'TXT')
            has_spf = any('v=spf1' in str(r).lower() for r in txt_records)
            if not has_spf:
                C += 0.5
                details.append('Tên miền gửi thiếu SPF record')
        except Exception:
            C += 0.5
            details.append('Không truy vấn được SPF record của domain gửi')

        try:
            dmarc_records = dns.resolver.resolve(f'_dmarc.{sender_domain}', 'TXT')
            dmarc_ok = any('v=dmarc1' in str(r).lower() for r in dmarc_records)
            if not dmarc_ok:
                C += 0.3
        except Exception:
            C += 0.3

    # Reputable ESP indicators reduce this component slightly
    sender_lower = sender.lower()
    if any(esp in sender_lower or esp in (email_data.get('authentication_results', '').lower())
           for esp in ['mailgun', 'sendgrid', 'amazonses', 'sparkpost', 'postmark']):
        C = max(0.0, C - 0.2)

    C = min(1.0, C)

    # D) Content risk
    D = 0.0
    combined_text = f"{subject}\n{body}".lower()
    phishing_kw = [
        'verify', 'urgent', 'immediately', 'suspended', 'click', 'confirm', 'password',
        'otp', 'mã xác thực', 'khẩn cấp', 'xác minh', 'đăng nhập', 'tài khoản'
    ]
    hits = sum(1 for kw in phishing_kw if kw in combined_text)
    if hits >= 4:
        D += 0.5
        details.append('Nội dung có nhiều từ khóa phishing/khẩn cấp')
    elif hits >= 2:
        D += 0.3

    url_hosts = []
    for u in urls:
        parsed = urlparse(u if '://' in u else f'http://{u}')
        host = (parsed.hostname or '').lower()
        if host:
            url_hosts.append(host)
            if _is_ip_host(host):
                D += 0.6
                details.append(f'URL dùng địa chỉ IP: {host}')
        if any(short in (host or '') for short in ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl']):
            D += 0.6
            details.append('Có URL rút gọn trong email')

    # Link-host mismatch versus sender domain (when sender domain known)
    if sender_domain and url_hosts:
        mismatch_count = sum(1 for host in url_hosts if sender_domain not in host)
        if mismatch_count >= max(1, len(url_hosts) // 2):
            D += 0.4
            details.append('Domain link không khớp domain người gửi')

    D = min(1.0, D)

    # E) Attachment risk
    E = 0.0
    risky_ext = {'.exe', '.scr', '.js', '.vbs', '.bat', '.cmd', '.ps1', '.msi'}
    risky_office = {'.docm', '.xlsm', '.pptm'}
    for att in attachments:
        filename = (att.get('filename') or '').lower()
        ctype = (att.get('content_type') or '').lower()

        if any(filename.endswith(ext) for ext in risky_ext):
            E = max(E, 1.0)
            details.append(f'Tệp đính kèm nguy hiểm: {filename}')
            continue

        if any(filename.endswith(ext) for ext in risky_office):
            E = max(E, 1.0)
            details.append(f'Tệp Office có macro tiềm ẩn: {filename}')
            continue

        if filename.endswith('.zip') or 'zip' in ctype:
            E = max(E, 0.9)
            details.append(f'Tệp nén cần kiểm tra thêm: {filename or "zip"}')
            continue

        if filename.endswith('.pdf') and ('javascript' in ctype or 'octet-stream' in ctype):
            E = max(E, 0.6)

    E = min(1.0, E)

    # F) Technical/header anomalies
    F = 0.0
    if reply_domain and sender_domain and reply_domain != sender_domain:
        F += 0.4
        details.append('Reply-To khác domain người gửi')

    brand_words = ['apple', 'google', 'microsoft', 'paypal', 'amazon', 'facebook', 'bank', 'vietcombank', 'mbbank']
    if any(word in sender.lower() for word in brand_words) and sender_domain:
        if not any(word in sender_domain for word in brand_words):
            F += 0.5
            details.append('Dấu hiệu mạo danh thương hiệu ở tên hiển thị')

    if 'multipart' in content_type and not body:
        F += 0.6
        details.append('Multipart bất thường: thiếu nội dung body đọc được')

    F = min(1.0, F)

    score = round(40 * A + 10 * B + 15 * C + 20 * D + 10 * E + 5 * F)
    score = max(0, min(100, score))

    return {
        'risk_score': score,
        'components': {
            'auth_trust': round(A, 3),
            'delivery_path': round(B, 3),
            'sender_reputation': round(C, 3),
            'content_risk': round(D, 3),
            'attachment_risk': round(E, 3),
            'technical_anomaly': round(F, 3),
        },
        'auth_results': auth_results,
        'details': details[:20],
    }

def parse_eml_content(file_bytes) -> dict:
    """
    Parses .eml file content and returns headers, body text, and attachments metadata.
    Robust handling for malformed emails.
    """
    try:
        msg = email.message_from_bytes(file_bytes, policy=default)
        
        extracted_data = {
            'subject': msg.get('Subject', ''),
            'from': msg.get('From', ''),
            'to': msg.get('To', ''),
            'reply_to': msg.get('Reply-To', ''),
            'delivered_to': msg.get('Delivered-To', ''),
            'received_chain': msg.get_all('Received', []),
            'return_path': msg.get('Return-Path', ''),
            'message_id': msg.get('Message-ID', ''),
            'authentication_results': msg.get('Authentication-Results', ''),
            'dkim_signature': msg.get('DKIM-Signature', ''),
            'content_type': msg.get_content_type(),
            'body_text': '',
            'attachments': [],
            'extracted_urls': []
        }

        # Body Extraction
        body_content = ""
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                cdispo = str(part.get('Content-Disposition'))

                if 'attachment' in cdispo:
                    fname = part.get_filename()
                    if fname:
                        extracted_data['attachments'].append({
                            'filename': fname,
                            'content_type': ctype,
                            'size': len(part.get_payload(decode=True) or b'')
                        })
                    continue

                if ctype == 'text/plain':
                    try:
                        body_content += part.get_content()
                    except: pass
                elif ctype == 'text/html':
                    try:
                        html_content = part.get_content()
                        soup = BeautifulSoup(html_content, 'html.parser')
                        for link in soup.find_all('a', href=True):
                            extracted_data['extracted_urls'].append(link['href'])
                        body_content += soup.get_text(separator=' ', strip=True)
                    except: pass
        else:
            try:
                payload = msg.get_content()
                if msg.get_content_type() == 'text/html':
                    soup = BeautifulSoup(payload, 'html.parser')
                    for link in soup.find_all('a', href=True):
                        extracted_data['extracted_urls'].append(link['href'])
                    body_content = soup.get_text(separator=' ', strip=True)
                else:
                    body_content = payload
            except: pass

        extracted_data['body_text'] = body_content.strip()
        
        # URL Regex fallback for plain text
        text_urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', extracted_data['body_text'])
        extracted_data['extracted_urls'] = list(set(extracted_data['extracted_urls'] + text_urls))

        # Parse auth summary for downstream scoring
        extracted_data['auth_parsed'] = _parse_authentication_results(extracted_data['authentication_results'])
        
        return extracted_data

    except Exception as e:
        logger.error(f"Error parsing EML: {e}")
        return None

def check_email_security(domain: str) -> dict:
    """
    Synchronous Security Checks: MX, DMARC, SPF record existence.
    Returns score (0-100 penalty) and details.
    """
    score_penalty = 0
    details = []
    
    # 1. MX Check
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_hosts = [str(r.exchange).lower() for r in mx_records]
        if not mx_hosts:
             score_penalty += 50
             details.append("Tên miền không có máy chủ email (MX record)")
    except Exception:
        score_penalty += 50
        details.append("Tên miền không hợp lệ hoặc không có MX record")

    # 2. DMARC Check
    try:
        dmarc = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        dmarc_txt = str(dmarc[0]).lower()
        if 'p=reject' in dmarc_txt or 'p=quarantine' in dmarc_txt:
            details.append("DMARC Policy: Strict (An toàn)")
        elif 'p=none' in dmarc_txt:
            score_penalty += 10
            details.append("DMARC Policy: None (Yếu)")
        else:
            score_penalty += 10
            details.append("DMARC Policy: Không rõ ràng")
    except Exception:
        score_penalty += 20 
        details.append("Không tìm thấy bản ghi DMARC")

    # 3. SPF Check existence
    try:
        spf = dns.resolver.resolve(domain, 'TXT')
        has_spf = False
        for r in spf:
            if 'v=spf1' in str(r):
                has_spf = True
                break
        if not has_spf:
            score_penalty += 15
            details.append("Không tìm thấy bản ghi SPF")
    except Exception:
        pass
        
    return {
        'penalty': min(100, score_penalty),
        'details': details
    }

def send_html_otp_email(to_email, token):
    """
    Sends an HTML email with the OTP token.
    """
    subject = "[ShieldCall VN] Mã xác thực (OTP) của bạn"
    context = {'token': token, 'site_name': 'ShieldCall VN'}
    
    try:
        html_message = render_to_string('Emails/otp_email.html', context)
        plain_message = f"Mã xác thực của bạn là: {token}"
    except Exception:
        plain_message = f"Mã xác thực của bạn là: {token}"
        html_message = f"<p>Mã xác thực của bạn là: <strong>{token}</strong></p>"

    try:
        send_mail(
            subject,
            plain_message,
            settings.DEFAULT_FROM_EMAIL,
            [to_email],
            html_message=html_message,
            fail_silently=True
        )
        logger.info(f"OTP email sent to {to_email}")
    except Exception as e:
        logger.error(f"Failed to send OTP email: {e}")

def send_report_outcome_email(user, report_type, target, status, reason=None):
    """
    Sends an email to the reporter about the outcome of their report.
    """
    if not user.email:
        return

    subject = f"[ShieldCall VN] Kết quả xử lý báo cáo {report_type}"
    
    context = {
        'user': user,
        'report_type': report_type,
        'target': target,
        'status': status,
        'reason': reason,
        'site_name': 'ShieldCall VN'
    }
    
    # Try to use a template, fallback to plain text if template missing
    try:
        html_message = render_to_string('Emails/report_outcome.html', context)
        plain_message = render_to_string('Emails/report_outcome.txt', context)
    except Exception:
        status_text = "đã được chấp thuận" if status == 'approved' else "đã bị từ chối"
        plain_message = f"Chào {user.username},\n\nBáo cáo của bạn về {target} {status_text}.\n"
        if reason:
            plain_message += f"Lý do: {reason}\n"
        plain_message += "\nCảm ơn bạn đã góp phần xây dựng cộng đồng an toàn!\n\nShieldCall VN Team"
        html_message = None

    try:
        send_mail(
            subject,
            plain_message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            html_message=html_message,
            fail_silently=True
        )
        logger.info(f"Report outcome email sent to {user.email}")
    except Exception as e:
        logger.error(f"Failed to send report outcome email: {e}")

def send_new_lesson_email(user_emails, lesson_title, lesson_url):
    """
    Sends notification to users about a new lesson.
    """
    subject = f"[ShieldCall VN] Bài học mới: {lesson_title}"
    
    plain_message = f"Chào bạn,\n\nChúng tôi vừa xuất bản bài học mới: {lesson_title}.\nXem ngay tại: {lesson_url}\n\nShieldCall VN Team"
    
    try:
        send_mail(
            subject,
            plain_message,
            settings.DEFAULT_FROM_EMAIL,
            user_emails,
            fail_silently=True
        )
        logger.info(f"New lesson email sent to {len(user_emails)} users")
    except Exception as e:
        logger.error(f"Failed to send bulk lesson email: {e}")
