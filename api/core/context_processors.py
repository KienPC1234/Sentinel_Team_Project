from django.conf import settings

def turnstile_context(request):
    """
    Expose Turnstile Site Key to all templates for the frontend widget.
    """
    return {
        'TURNSTILE_SITEKEY': getattr(settings, 'TURNSTILE_SITEKEY', '')
    }
