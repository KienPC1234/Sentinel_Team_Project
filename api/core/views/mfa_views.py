"""ShieldCall VN – MFA Views"""
import pyotp
import qrcode
import io
import base64
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.plugins.otp_email.models import EmailDevice
from django.contrib.auth import get_user_model, login as auth_login
from rest_framework.authtoken.models import Token
from api.core.serializers import UserSerializer

User = get_user_model()

class MFAStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        totp_devices = TOTPDevice.objects.filter(user=user, confirmed=True)
        email_devices = EmailDevice.objects.filter(user=user, confirmed=True)
        
        has_totp = totp_devices.exists()
        has_email = email_devices.exists()
        
        return Response({
            'has_2fa': has_totp or has_email,
            'methods': {
                'totp': has_totp,
                'email': has_email
            },
            'details': {
                'totp_count': totp_devices.count(),
                'email_count': email_devices.count()
            }
        })

class MFASetupTOTPView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        device, created = TOTPDevice.objects.get_or_create(user=user, name='default', defaults={'confirmed': False})
        
        # In case an unconfirmed device already existed but was confirmed=True due to django-otp defaults
        if created and device.confirmed:
            device.confirmed = False
            device.save()
            
        if not device.confirmed:
            # Construct a standard and robust OTP URI for better app compatibility
            import base64 as b64
            secret_b32 = b64.b32encode(bytes.fromhex(device.key)).decode().replace('=', '')
            
            # Label format: Issuer:Account
            account_name = user.email if user.email else user.username
            issuer_name = "ShieldCall"
            
            # Constructing the "Gold Standard" URI manually to ensure perfect formatting
            # Note: We keep the label readable (no encoding for @) as many apps prefer it
            otp_uri = (
                f"otpauth://totp/{issuer_name}:{account_name}?"
                f"secret={secret_b32}&"
                f"issuer={issuer_name}&"
                f"algorithm=SHA1&"
                f"digits=6&"
                f"period=30"
            )
            
            # Generate QR Code image
            qr = qrcode.QRCode(version=None, box_size=10, border=5)
            qr.add_data(otp_uri)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            
            buffered = io.BytesIO()
            img.save(buffered, format="PNG")
            img_base64 = base64.b64encode(buffered.getvalue()).decode()

            return Response({
                'otp_uri': otp_uri,
                'qr_code': f"data:image/png;base64,{img_base64}",
                'secret': secret_b32
            })
        return Response({'error': 'TOTP is already enabled for this account.'}, status=400)

    def post(self, request):
        user = request.user
        token = request.data.get('token')
        device = TOTPDevice.objects.filter(user=user, name='default').first()
        if device and device.verify_token(token):
            device.confirmed = True
            device.save()
            return Response({'message': 'TOTP confirmed successfully.'})
        return Response({'error': 'Invalid token. Please try again.'}, status=400)

class MFASetupEmailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        if not request.user.is_authenticated:
            user_id = request.session.get('mfa_user_id')
            if not user_id:
                return Response({'error': 'Authentication required.'}, status=401)
            user = User.objects.get(id=user_id)
        else:
            user = request.user

        device, created = EmailDevice.objects.get_or_create(user=user, name='default', email=user.email)
        
        # Instead of device.generate_challenge(), we manually send HTML email
        from django_otp.util import random_hex
        token = str(random_hex(3)).upper() # Generate a 6-char hex/numeric-like token
        # Or simpler for users: 6 random digits
        import random
        token = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        
        from django.utils import timezone
        from datetime import timedelta
        device.token = token
        device.valid_until = timezone.now() + timedelta(minutes=2)
        device.save()
        request.session.modified = True
        
        from api.utils.email_utils import send_html_otp_email
        send_html_otp_email(user.email, token)
        
        return Response({'message': 'Mã OTP đã được gửi đến email của bạn.'})

    def post(self, request):
        user = request.user
        token = request.data.get('token')
        device = EmailDevice.objects.filter(user=user, name='default').first()
        if device and device.verify_token(token):
            device.confirmed = True
            device.save()
            return Response({'message': 'Email 2FA confirmed successfully.'})
        return Response({'error': 'Invalid token.'}, status=400)

class MFAVerifyView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        user_id = request.session.get('mfa_user_id')
        if not user_id:
            return Response({'error': 'Session expired or invalid.'}, status=401)
        
        user = User.objects.get(id=user_id)
        token = request.data.get('token')
        method = request.data.get('method', 'totp')

        verified = False
        if method == 'totp':
            device = TOTPDevice.objects.filter(user=user, confirmed=True).first()
            if device and device.verify_token(token):
                verified = True
        elif method == 'email':
            device = EmailDevice.objects.filter(user=user, confirmed=True).first()
            if device and device.verify_token(token):
                verified = True

        if verified:
            # Fix: Manually specify the backend to avoid ValueError when multiple backends are configured
            user.backend = 'django.contrib.auth.backends.ModelBackend'
            auth_login(request, user)
            if 'mfa_user_id' in request.session:
                del request.session['mfa_user_id']
            auth_token, _ = Token.objects.get_or_create(user=user)
            return Response({
                'token': auth_token.key,
                'user': UserSerializer(user).data
            })
        
        return Response({'error': 'Invalid 2FA token.'}, status=400)

class MFADeactivateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        password = request.data.get('password')
        otp_token = request.data.get('token')

        # 1. Verify password
        if not user.check_password(password):
            return Response({'error': 'Mật khẩu không chính xác.'}, status=400)

        # 2. Verify Email OTP (required for deactivation as per user request)
        device = EmailDevice.objects.filter(user=user, name='default').first()
        if not device or not device.verify_token(otp_token):
            return Response({'error': 'Mã OTP Email không hợp lệ hoặc đã hết hạn.'}, status=400)

        # 3. Disable all MFA methods
        TOTPDevice.objects.filter(user=user).delete()
        EmailDevice.objects.filter(user=user).delete()
        
        # In case the user had an unconfirmed device that caused the "already enabled" error
        # we explicitly delete any device associated with the user.

        return Response({'message': 'Đã vô hiệu hóa bảo mật 2 lớp thành công.'})
