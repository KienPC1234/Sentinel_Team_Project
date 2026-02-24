from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings

def send_html_otp_email(to_email, token):
    """
    Send OTP email using a beautiful HTML template.
    """
    try:
        subject = f'[ShieldCall VN] Mã xác thực của bạn: {token}'
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'ShieldCall VN <noreply@fptoj.com>')
        
        context = {'token': token}
        html_content = render_to_string('Email/otp_email.html', context)
        text_content = strip_tags(html_content)
        
        msg = EmailMultiAlternatives(subject, text_content, from_email, [to_email])
        msg.attach_alternative(html_content, "text/html")
        msg.send()
        return True
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Failed to send OTP email: {str(e)}")
        # Fallback for dev: print to console if SMTP fails
        print(f"DEBUG OTP EMAIL TO {to_email}: {token}")
        return False
