import os
import re
from typing import Any, Dict

import requests
from django.conf import settings


def _safe_text(value: Any, limit: int = 50000) -> str:
    text = str(value or '')
    text = re.sub(r'\s+', ' ', text).strip()
    return text[:limit]


def fetch_with_puppeteer_host(url: str, timeout_ms: int = 20000) -> Dict[str, Any]:
    """
    Fetch rendered page content from a local Node Puppeteer host.

    Returns a normalized payload to keep Celery tasks resilient.
    """
    endpoint = getattr(
        settings,
        'PUPPETEER_HOST_URL',
        os.getenv('PUPPETEER_HOST_URL', 'http://127.0.0.1:3010/render'),
    )

    payload = {
        'url': url,
        'timeoutMs': int(timeout_ms),
        'waitUntil': 'networkidle2',
    }

    request_timeout_seconds = max(10, int(timeout_ms / 1000) + 8)

    try:
        response = requests.post(endpoint, json=payload, timeout=request_timeout_seconds)
        response.raise_for_status()
        data = response.json() if response.content else {}

        return {
            'ok': bool(data.get('ok')),
            'title': _safe_text(data.get('title', ''), 300),
            'content': _safe_text(data.get('content', ''), 70000),
            'captcha_detected': bool(data.get('captcha_detected')),
            'status_code': data.get('status_code'),
            'final_url': data.get('final_url') or url,
            'error': _safe_text(data.get('error', ''), 500),
        }
    except Exception as exc:
        return {
            'ok': False,
            'title': '',
            'content': '',
            'captcha_detected': False,
            'status_code': None,
            'final_url': url,
            'error': f'Puppeteer host unavailable: {exc}',
        }
