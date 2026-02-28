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


def normalize_phone_e164(phone: str, default_country_code: str = '84', strict: bool = False) -> str:
    """
    Normalize a phone number to E.164 format: +<country><national_number>.

    Examples:
    - '+84 379-456-789' -> '+84379456789'
    - '003793456789' -> '+3793456789'
    - '0379456789' -> '+84379456789' (only when strict=False)

    Args:
        phone: Input phone text.
        default_country_code: Used when converting local numbers in non-strict mode.
        strict: If True, requires explicit country flag (+xx) and raises ValueError otherwise.
    """
    if not phone:
        raise ValueError('Phone number is empty')

    cleaned = re.sub(r'[^\d+]', '', phone.strip())
    if not cleaned:
        raise ValueError('Phone number is invalid')

    # International prefix 00xxxx -> +xxxx
    if cleaned.startswith('00'):
        cleaned = '+' + cleaned[2:]

    if cleaned.startswith('+'):
        digits = cleaned[1:]
        if not digits.isdigit() or len(digits) < 8 or len(digits) > 15:
            raise ValueError('Phone number must be E.164 (+ followed by 8-15 digits)')
        return '+' + digits

    if strict:
        raise ValueError('Phone number must include country flag, e.g. +84 or +1')

    # Non-strict fallback for internal compatibility paths.
    digits_only = re.sub(r'\D', '', cleaned)
    if digits_only.startswith(default_country_code):
        return '+' + digits_only
    if digits_only.startswith('0'):
        return '+' + default_country_code + digits_only[1:]
    return '+' + digits_only

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
