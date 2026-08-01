import requests
from django.conf import settings

from turnstile.settings import SECRET, VERIFY_URL, TIMEOUT

def verify_turnstile_token(token: str, remote_ip: str = None) -> bool:
    """
    Verify Cloudflare Turnstile token using centralized settings.
    """
    if not token:
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
        return result.get('success', False)
    except Exception:
        return False
