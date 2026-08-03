"""ShieldCall VN – Email Utilities"""
import logging
import email
import re
from email.policy import default
from bs4 import BeautifulSoup
import dns.resolver

from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags

logger = logging.getLogger(__name__)

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
