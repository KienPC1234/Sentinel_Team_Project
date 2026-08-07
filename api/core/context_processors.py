from django.conf import settings

def turnstile_context(request):
    """
    Expose shared frontend keys to all templates.
    """
    return {
        'TURNSTILE_SITEKEY': getattr(settings, 'TURNSTILE_SITEKEY', ''),
        'CKEDITOR_LICENSE_KEY': getattr(settings, 'CKEDITOR_LICENSE_KEY', ''),
        'ONESIGNAL_APP_ID': getattr(settings, 'ONESIGNAL_APP_ID', ''),
        'ONESIGNAL_SAFARI_WEB_ID': getattr(settings, 'ONESIGNAL_SAFARI_WEB_ID', ''),
    }
