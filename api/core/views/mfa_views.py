"""ShieldCall VN – MFA Views"""
import pyotp
import qrcode
import io
import base64
import hashlib
import secrets
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, serializers
from rest_framework.permissions import IsAuthenticated, AllowAny
from drf_spectacular.utils import extend_schema
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.plugins.otp_email.models import EmailDevice
from django.contrib.auth import get_user_model, login as auth_login
from rest_framework.authtoken.models import Token
from api.core.serializers import UserSerializer
from api.core.models import UserProfile, MFARecoveryCode

User = get_user_model()


def _normalize_recovery_code(raw_code: str) -> str:
    return (raw_code or '').upper().replace('-', '').replace(' ', '').strip()


def _hash_recovery_code(user_id: int, normalized_code: str) -> str:
    material = f"{user_id}:{settings.SECRET_KEY}:{normalized_code}"
    return hashlib.sha256(material.encode('utf-8')).hexdigest()


def _generate_recovery_codes(user, total: int = 10):
    alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    plain_codes = []
    rows = []

    for _ in range(total):
        chunk = ''.join(secrets.choice(alphabet) for _ in range(4))
        chunk2 = ''.join(secrets.choice(alphabet) for _ in range(4))
        display = f"{chunk}-{chunk2}"
        normalized = _normalize_recovery_code(display)
        plain_codes.append(display)
        rows.append(MFARecoveryCode(
            user=user,
            code_hash=_hash_recovery_code(user.id, normalized),
            hint=display[-4:],
        ))

    with transaction.atomic():
        MFARecoveryCode.objects.filter(user=user).delete()
        MFARecoveryCode.objects.bulk_create(rows)

    return plain_codes

class MFAStatusView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: serializers.DictField()})
    def get(self, request):
        user = request.user
        totp_devices = TOTPDevice.objects.filter(user=user, confirmed=True)
        email_devices = EmailDevice.objects.filter(user=user, confirmed=True)
        
        has_totp = totp_devices.exists()
        has_email = email_devices.exists()
        profile, _ = UserProfile.objects.get_or_create(user=user)
        preferred = profile.mfa_preferred_method
        recovery_remaining = MFARecoveryCode.objects.filter(user=user, is_used=False).count()

        if preferred not in {'totp', 'email'}:
            if has_totp:
                preferred = 'totp'
            elif has_email:
                preferred = 'email'

        if preferred == 'totp' and has_totp:
            methods = {'totp': True, 'email': False}
        elif preferred == 'email' and has_email:
            methods = {'totp': False, 'email': True}
        else:
            methods = {'totp': has_totp, 'email': has_email}
        
        return Response({
            'has_2fa': has_totp or has_email,
            'methods': methods,
            'preferred_method': preferred,
            'recovery_codes': {
                'remaining': recovery_remaining,
                'total': MFARecoveryCode.objects.filter(user=user).count(),
            },
            'details': {
                'totp_count': totp_devices.count(),
                'email_count': email_devices.count()
            }
        })

class MFASetupTOTPView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: serializers.DictField()})
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
            qr = qrcode.QRCode(
                version=None,
                box_size=14,
                border=6,
                error_correction=qrcode.constants.ERROR_CORRECT_H,
            )
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

    @extend_schema(request={'application/json': {'type': 'object', 'properties': {'token': {'type': 'string'}}, 'required': ['token']}}, responses={200: serializers.DictField()})
    def post(self, request):
        user = request.user
        token = request.data.get('token')
        device = TOTPDevice.objects.filter(user=user, name='default').first()
        if device and device.verify_token(token):
            device.confirmed = True
            device.save()
            EmailDevice.objects.filter(user=user).delete()
            profile, _ = UserProfile.objects.get_or_create(user=user)
            profile.mfa_preferred_method = 'totp'
            profile.save(update_fields=['mfa_preferred_method'])
            recovery_codes = _generate_recovery_codes(user, total=10)
            return Response({
                'message': 'TOTP confirmed successfully.',
                'recovery_codes': recovery_codes,
                'recovery_note': 'Đây là 10 mã dự phòng, hãy lưu ở nơi an toàn. Mỗi mã chỉ dùng được 1 lần.',
            })
        return Response({'error': 'Invalid token. Please try again.'}, status=400)

class MFASetupEmailView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(responses={200: serializers.DictField()})
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

    @extend_schema(request={'application/json': {'type': 'object', 'properties': {'token': {'type': 'string'}}, 'required': ['token']}}, responses={200: serializers.DictField()})
    def post(self, request):
        user = request.user
        token = request.data.get('token')
        device = EmailDevice.objects.filter(user=user, name='default').first()
        if device and device.verify_token(token):
            device.confirmed = True
            device.save()
            TOTPDevice.objects.filter(user=user).delete()
            MFARecoveryCode.objects.filter(user=user).delete()
            profile, _ = UserProfile.objects.get_or_create(user=user)
            profile.mfa_preferred_method = 'email'
            profile.save(update_fields=['mfa_preferred_method'])
            return Response({'message': 'Email 2FA confirmed successfully.'})
        return Response({'error': 'Invalid token.'}, status=400)

class MFAVerifyView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(request={'application/json': {'type': 'object', 'properties': {'token': {'type': 'string'}, 'method': {'type': 'string'}}, 'required': ['token']}}, responses={200: serializers.DictField()})
    def post(self, request):
        user_id = request.session.get('mfa_user_id')
        if not user_id:
            return Response({'error': 'Session expired or invalid.'}, status=401)
        
        user = User.objects.get(id=user_id)
        token = request.data.get('token')
        method = request.data.get('method', 'totp')

        has_totp = TOTPDevice.objects.filter(user=user, confirmed=True).exists()
        has_email = EmailDevice.objects.filter(user=user, confirmed=True).exists()
        profile, _ = UserProfile.objects.get_or_create(user=user)
        preferred = profile.mfa_preferred_method
        if preferred not in {'totp', 'email'}:
            preferred = 'totp' if has_totp else ('email' if has_email else None)

        if method != 'recovery':
            if preferred == 'totp' and method != 'totp':
                return Response({'error': 'Tài khoản này chỉ chấp nhận mã từ ứng dụng Authenticator.'}, status=400)
            if preferred == 'email' and method != 'email':
                return Response({'error': 'Tài khoản này chỉ chấp nhận mã OTP Email.'}, status=400)

        verified = False
        if method == 'totp':
            device = TOTPDevice.objects.filter(user=user, confirmed=True).first()
            if device and device.verify_token(token):
                verified = True
        elif method == 'email':
            device = EmailDevice.objects.filter(user=user, confirmed=True).first()
            if device and device.verify_token(token):
                verified = True
        elif method == 'recovery':
            normalized = _normalize_recovery_code(token)
            if len(normalized) >= 8:
                code_hash = _hash_recovery_code(user.id, normalized)
                recovery = MFARecoveryCode.objects.filter(user=user, code_hash=code_hash, is_used=False).first()
                if recovery and (preferred == 'totp' or has_totp):
                    recovery.is_used = True
                    recovery.used_at = timezone.now()
                    recovery.save(update_fields=['is_used', 'used_at'])
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

    @extend_schema(request={'application/json': {'type': 'object', 'properties': {'password': {'type': 'string'}, 'token': {'type': 'string'}, 'method': {'type': 'string'}}, 'required': ['password', 'token']}}, responses={200: serializers.DictField()})
    def post(self, request):
        user = request.user
        password = request.data.get('password')
        otp_token = request.data.get('token')
        method = request.data.get('method')

        # 1. Verify password
        if not user.check_password(password):
            return Response({'error': 'Mật khẩu không chính xác.'}, status=400)

        profile, _ = UserProfile.objects.get_or_create(user=user)
        preferred = method or profile.mfa_preferred_method
        if preferred not in {'totp', 'email'}:
            preferred = 'totp' if TOTPDevice.objects.filter(user=user, confirmed=True).exists() else 'email'

        if preferred == 'totp':
            verified = False
            totp_device = TOTPDevice.objects.filter(user=user, confirmed=True).first()
            if totp_device and totp_device.verify_token(otp_token):
                verified = True
            if not verified:
                normalized = _normalize_recovery_code(otp_token)
                if len(normalized) >= 8:
                    code_hash = _hash_recovery_code(user.id, normalized)
                    recovery = MFARecoveryCode.objects.filter(user=user, code_hash=code_hash, is_used=False).first()
                    if recovery:
                        recovery.is_used = True
                        recovery.used_at = timezone.now()
                        recovery.save(update_fields=['is_used', 'used_at'])
                        verified = True
            if not verified:
                return Response({'error': 'Mã TOTP hoặc recovery code không hợp lệ.'}, status=400)
        else:
            device = EmailDevice.objects.filter(user=user, name='default').first()
            if not device or not device.verify_token(otp_token):
                return Response({'error': 'Mã OTP Email không hợp lệ hoặc đã hết hạn.'}, status=400)

        # 3. Disable all MFA methods
        TOTPDevice.objects.filter(user=user).delete()
        EmailDevice.objects.filter(user=user).delete()
        MFARecoveryCode.objects.filter(user=user).delete()
        profile.mfa_preferred_method = None
        profile.save(update_fields=['mfa_preferred_method'])
        
        # In case the user had an unconfirmed device that caused the "already enabled" error
        # we explicitly delete any device associated with the user.

        return Response({'message': 'Đã vô hiệu hóa bảo mật 2 lớp thành công.'})


class MFARecoveryCodesView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: serializers.DictField()})
    def get(self, request):
        user = request.user
        total = MFARecoveryCode.objects.filter(user=user).count()
        remaining = MFARecoveryCode.objects.filter(user=user, is_used=False).count()
        hints = list(MFARecoveryCode.objects.filter(user=user, is_used=False).values_list('hint', flat=True))
        return Response({
            'total': total,
            'remaining': remaining,
            'hints': hints,
        })

    @extend_schema(responses={200: serializers.DictField()})
    def post(self, request):
        user = request.user
        has_totp = TOTPDevice.objects.filter(user=user, confirmed=True).exists()
        if not has_totp:
            return Response({'error': 'Recovery codes chỉ khả dụng khi bạn dùng TOTP.'}, status=400)
        codes = _generate_recovery_codes(user, total=10)
        return Response({
            'message': 'Đã tạo mới 10 recovery codes.',
            'codes': codes,
            'note': 'Lưu các mã này ở nơi bảo mật. Mỗi mã chỉ dùng một lần.',
        })
