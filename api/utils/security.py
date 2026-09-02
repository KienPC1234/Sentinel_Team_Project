import logging
import ipaddress
import socket
import os
import re
from urllib.parse import urlparse
import requests
from django.conf import settings

from turnstile.settings import SECRET, VERIFY_URL, TIMEOUT

logger = logging.getLogger(__name__)

def is_safe_url(url: str) -> bool:
    """
    Validates URL to prevent Server-Side Request Forgery (SSRF).
    Blocks loopback, link-local, private, broadcast, and reserved networks.
    """
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        hostname = hostname.lower()
        if hostname in ('localhost', '127.0.0.1', '::1', '0.0.0.0', '169.254.169.254'):
            return False
        
        # Resolve all DNS IP addresses
        addr_info = socket.getaddrinfo(hostname, None)
        for entry in addr_info:
            ip_str = entry[4][0]
            ip_obj = ipaddress.ip_address(ip_str)
            if (ip_obj.is_private or ip_obj.is_loopback or 
                ip_obj.is_link_local or ip_obj.is_multicast or 
                ip_obj.is_reserved or ip_obj.is_unspecified):
                return False
        return True
    except Exception:
        return False


def sanitize_filename(filename: str, default_ext: str = '') -> str:
    """
    Sanitize filename against path traversal, null bytes, and malicious characters.
    """
    if not filename:
        return 'unnamed_file'
    clean = os.path.basename(filename)
    clean = re.sub(r'[\x00-\x1f\x7f/\\]', '', clean)
    clean = re.sub(r'[^\w\.\-_]', '_', clean).strip('._')
    if not clean:
        clean = 'file'
    if default_ext and not os.path.splitext(clean)[1]:
        clean += default_ext
    return clean


def verify_turnstile_token(token: str, remote_ip: str = None) -> bool:
    """
    Verify Cloudflare Turnstile token using centralized settings.
    """
    if not token:
        logger.warning("[Turnstile] Empty token provided")
        return False
        
    try:
        response = requests.post(
            VERIFY_URL,
            data={
                'secret': SECRET,
                'response': token,
                'remoteip': remote_ip
            },
            timeout=TIMEOUT
        )
        result = response.json()
        success = result.get('success', False)
        if not success:
            logger.warning(f"[Turnstile] Verification failed: {result.get('error-codes', [])}")
        return success
    except Exception as e:
        logger.error(f"[Turnstile] Error connecting to verification endpoint: {e}")
        return False
