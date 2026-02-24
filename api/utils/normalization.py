import re

def normalize_phone(phone: str) -> str:
    """Normalize Vietnamese phone number to 0xxx format"""
    if not phone:
        return ""
    phone = re.sub(r'[^\d+]', '', phone.strip())
    if phone.startswith('+84'):
        phone = '0' + phone[3:]
    elif phone.startswith('84') and len(phone) > 9:
        phone = '0' + phone[2:]
    return phone

def normalize_domain(url: str) -> str:
    """Normalize domain/URL to extract only the hostname"""
    from urllib.parse import urlparse
    if not url:
        return ""
    # Remove any whitespaces
    url = url.strip().lower()
    # Check if it looks like a URL or just a domain
    if not re.match(r'^[a-z0-9]+://', url):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        # Remove port if present
        domain = domain.split(':')[0]
        # Remove www.
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain
    except Exception:
        return url
