"""ShieldCall VN – Auth Views"""
import re
import hashlib
import logging
import json
import random
import hmac
from urllib.parse import urlparse

from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.core.exceptions import ValidationError
from django.core.cache import cache
from django.conf import settings
from django.core.validators import validate_email
from django.db.models import Count, Sum, F, Q
from django.utils import timezone
from datetime import timedelta

from django.http import StreamingHttpResponse
from rest_framework import status, permissions, generics
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token

from api.utils.ollama_client import analyze_text_for_scam, generate_response, stream_response
from api.utils.security import verify_turnstile_token

from api.core.models import (
    Domain, BankAccount, Report, ScanEvent, TrendDaily,
    EntityLink, UserAlert, ScamType, RiskLevel, ReportStatus, UserProfile, MFARecoveryCode,
)
from api.core.serializers import (
    RegisterSerializer, LoginSerializer, UserSerializer,
    DomainSerializer, BankAccountSerializer,
    ReportCreateSerializer, ReportListSerializer, ReportModerateSerializer,
    ScanPhoneSerializer, ScanMessageSerializer, ScanDomainSerializer,
    ScanAccountSerializer, ScanImageSerializer, ScanEventListSerializer,
    TrendDailySerializer, TrendHotSerializer, UserAlertSerializer,
    UserProfileSerializer,
)

User = get_user_model()
logger = logging.getLogger(__name__)
EMAIL_CHANGE_CACHE_PREFIX = 'email_change_otp:'
REGISTER_OTP_CACHE_PREFIX = 'register_otp:'


def _email_change_cache_key(user_id: int, email: str) -> str:
    return f"{EMAIL_CHANGE_CACHE_PREFIX}{user_id}:{email.lower()}"


def _email_change_otp_hash(user_id: int, email: str, otp: str) -> str:
    material = f"{user_id}:{email.lower()}:{otp}:{settings.SECRET_KEY}"
    return hashlib.sha256(material.encode('utf-8')).hexdigest()


def _register_otp_cache_key(email: str) -> str:
    return f"{REGISTER_OTP_CACHE_PREFIX}{(email or '').strip().lower()}"


def _register_otp_hash(email: str, otp: str) -> str:
    material = f"{(email or '').strip().lower()}:{otp}:{settings.SECRET_KEY}"
    return hashlib.sha256(material.encode('utf-8')).hexdigest()

# ═══════════════════════════════════════════════════════════════════════════
# AUTH APIs
# ═══════════════════════════════════════════════════════════════════════════

class RegisterRequestOTPView(APIView):
    """POST /api/auth/register/request-otp — validate input then send OTP to email"""
    permission_classes = [AllowAny]

    def post(self, request):
        cf_token = request.data.get('cf-turnstile-response')
        forwarded = (request.META.get('HTTP_X_FORWARDED_FOR') or '').split(',')[0].strip()
        remote_ip = forwarded or request.META.get('REMOTE_ADDR')
        if not verify_turnstile_token(cf_token, remote_ip=remote_ip):
            return Response({'error': 'Xác thực bảo mật thất bại. Vui lòng thử lại.'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        cache_key = _register_otp_cache_key(email)
        cache.set(
            cache_key,
            {
                'otp_hash': _register_otp_hash(email, otp),
                'requested_at': timezone.now().isoformat(),
            },
            timeout=600,
        )

        from api.utils.email_utils import send_html_otp_email
        send_html_otp_email(email, otp)

        return Response({
            'message': 'Đã gửi mã OTP đến email của bạn.',
            'expires_in': 600,
        }, status=status.HTTP_200_OK)


class RegisterView(APIView):
    """POST /api/auth/register — create account after OTP verification"""
    permission_classes = [AllowAny]

    def post(self, request):
        otp = (request.data.get('otp') or '').strip()
        email = (request.data.get('email') or '').strip().lower()
        if len(otp) != 6 or not otp.isdigit():
            return Response({'error': 'Vui lòng nhập mã OTP 6 chữ số.'}, status=status.HTTP_400_BAD_REQUEST)

        pending = cache.get(_register_otp_cache_key(email))
        if not pending:
            return Response({'error': 'OTP đã hết hạn hoặc chưa được yêu cầu.'}, status=status.HTTP_400_BAD_REQUEST)

        expected_hash = pending.get('otp_hash', '')
        actual_hash = _register_otp_hash(email, otp)
        if not hmac.compare_digest(expected_hash, actual_hash):
            return Response({'error': 'Mã OTP không chính xác.'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        cache.delete(_register_otp_cache_key(email))

        try:
            from api.utils.push_service import push_service
            push_service.send_push(
                user_id=user.id,
                title='Chào mừng đến với ShieldCall VN',
                message='Tài khoản đã tạo thành công. Hãy mở Dashboard để bắt đầu và theo dõi cảnh báo mới trong Hộp thư.',
                url='/dashboard/',
                notification_type='success',
            )
        except Exception:
            logger.exception('Failed to create welcome inbox notification for user_id=%s', user.id)

        try:
            from api.utils.email_utils import send_welcome_email
            send_welcome_email(user)
        except Exception:
            logger.exception('Failed to trigger welcome email for user_id=%s', user.id)

        token, _ = Token.objects.get_or_create(user=user)
        return Response({
            'message': 'Đăng ký thành công!',
            'welcome_message': f'Xin chào {user.email}! Tài khoản của bạn đã được tạo thành công.',
            'token': token.key,
            'user': UserSerializer(user).data,
        }, status=status.HTTP_201_CREATED)


from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout, get_user_model

class LoginView(APIView):
    """POST /api/auth/login"""
    permission_classes = [AllowAny]

    def post(self, request):
        cf_token = request.data.get('cf-turnstile-response')
        forwarded = (request.META.get('HTTP_X_FORWARDED_FOR') or '').split(',')[0].strip()
        remote_ip = forwarded or request.META.get('REMOTE_ADDR')
        if not verify_turnstile_token(cf_token, remote_ip=remote_ip):
            return Response({'error': 'Xác thực bảo mật thất bại. Vui lòng thử lại.'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']

        try:
            user_obj = User.objects.get(email=email.lower())
            user = authenticate(request, username=user_obj.username, password=password)
        except User.DoesNotExist:
            user = None

        if user is None:
            return Response({'error': 'Email hoặc mật khẩu không đúng.'},
                            status=status.HTTP_401_UNAUTHORIZED)

        # Check for confirmed 2FA devices
        from django_otp import user_has_device
        from django_otp.plugins.otp_totp.models import TOTPDevice
        from django_otp.plugins.otp_email.models import EmailDevice
        if user_has_device(user, confirmed=True):
            request.session['mfa_user_id'] = user.id
            request.session.modified = True # Ensure session is saved
            has_totp = TOTPDevice.objects.filter(user=user, confirmed=True).exists()
            has_email = EmailDevice.objects.filter(user=user, confirmed=True).exists()
            profile, _ = UserProfile.objects.get_or_create(user=user)
            preferred = profile.mfa_preferred_method
            if preferred not in {'totp', 'email'}:
                preferred = 'totp' if has_totp else ('email' if has_email else None)

            methods = {'totp': False, 'email': False, 'recovery': False}
            if preferred == 'totp' and has_totp:
                methods['totp'] = True
                methods['recovery'] = MFARecoveryCode.objects.filter(user=user, is_used=False).exists()
            elif preferred == 'email' and has_email:
                methods['email'] = True
            else:
                methods['totp'] = has_totp
                methods['email'] = has_email
                methods['recovery'] = has_totp and MFARecoveryCode.objects.filter(user=user, is_used=False).exists()

            return Response({
                'mfa_required': True,
                'methods': methods,
                'preferred_method': preferred,
                'message': 'Hành động yêu cầu xác thực 2 lớp (2FA).'
            })

        # IMPORTANT: Create session for MPA navigation
        auth_login(request, user)
        
        token, _ = Token.objects.get_or_create(user=user)
        return Response({
            'message': 'Đăng nhập thành công!',
            'token': token.key,
            'user': UserSerializer(user).data,
        })


class LogoutView(APIView):
    """POST /api/auth/logout — revoke token"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            request.user.auth_token.delete()
        except Exception:
            pass
        return Response({'message': 'Đã đăng xuất.'})


class MeView(APIView):
    """GET /api/me — current user info"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        scan_count = ScanEvent.objects.filter(user=request.user).count()
        report_count = Report.objects.filter(reporter=request.user).count()
        alert_count = UserAlert.objects.filter(user=request.user).count()
        return Response({
            'user': UserSerializer(request.user).data,
            'stats': {
                'total_scans': scan_count,
                'total_reports': report_count,
                'saved_alerts': alert_count,
            }
        })

    def patch(self, request):
        """Update profile (avatar, bio, etc.)"""
        user = request.user
        profile, created = UserProfile.objects.get_or_create(user=user)

        # Username update
        if 'username' in request.data:
            new_username = (request.data.get('username') or '').strip()

            if not new_username:
                return Response({
                    'error': 'Lỗi dữ liệu hồ sơ',
                    'details': {'username': ['Username không được để trống.']}
                }, status=status.HTTP_400_BAD_REQUEST)

            if len(new_username) < 3:
                return Response({
                    'error': 'Lỗi dữ liệu hồ sơ',
                    'details': {'username': ['Username phải có ít nhất 3 ký tự.']}
                }, status=status.HTTP_400_BAD_REQUEST)

            if User.objects.filter(username__iexact=new_username).exclude(pk=user.pk).exists():
                return Response({
                    'error': 'Lỗi dữ liệu hồ sơ',
                    'details': {'username': ['Username đã tồn tại.']}
                }, status=status.HTTP_400_BAD_REQUEST)

            validator = UnicodeUsernameValidator()
            try:
                validator(new_username)
            except ValidationError:
                return Response({
                    'error': 'Lỗi dữ liệu hồ sơ',
                    'details': {
                        'username': ['Username chỉ được chứa chữ cái, số và các ký tự @/./+/-/_.']
                    }
                }, status=status.HTTP_400_BAD_REQUEST)

            if user.username != new_username:
                user.username = new_username
        
        # Profile data (avatar, bio, display_name, about, messenger_link)
        profile_fields = ['avatar', 'bio', 'display_name', 'about', 'messenger_link']
        if any(k in request.data for k in profile_fields):
            # If avatar is a string (URL), remove it from data to avoid ImageField validation error
            patch_data = request.data.copy() if hasattr(request.data, 'copy') else request.data
            if 'messenger_link' in patch_data:
                raw_link = patch_data.get('messenger_link')
                normalized_link = '' if raw_link is None else str(raw_link).strip()
                if normalized_link.lower() in {'none', 'null', 'undefined', 'nan', 'false', '0'}:
                    normalized_link = ''
                patch_data['messenger_link'] = normalized_link
            if 'avatar' in patch_data and isinstance(patch_data['avatar'], str):
                if hasattr(patch_data, 'pop'):
                    patch_data.pop('avatar')
                else:
                    del patch_data['avatar']
                
            serializer = UserProfileSerializer(profile, data=patch_data, partial=True)
            if not serializer.is_valid():
                return Response({
                    'error': 'Lỗi dữ liệu hồ sơ',
                    'details': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
            serializer.save()
            
        # Basic user data (username, names)
        if any(k in request.data for k in ['username', 'first_name', 'last_name']):
            user.first_name = request.data.get('first_name', user.first_name)
            user.last_name = request.data.get('last_name', user.last_name)
            user.save()
            
        return Response({
            'message': 'Cập nhật thông tin thành công!',
            'user': UserSerializer(user).data
        })


class DeleteAccountView(APIView):
    """POST /api/v1/auth/account/delete/ — permanently delete user account"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        password = (request.data.get('password') or '').strip()
        confirmation_text = (request.data.get('confirmation_text') or '').strip().upper()
        required_text = 'XOA TAI KHOAN'

        if not password:
            return Response({'error': 'Vui lòng nhập mật khẩu hiện tại.'}, status=status.HTTP_400_BAD_REQUEST)
        if confirmation_text != required_text:
            return Response({'error': f'Bạn cần nhập chính xác cụm từ "{required_text}" để xác nhận.'}, status=status.HTTP_400_BAD_REQUEST)
        if not user.check_password(password):
            return Response({'error': 'Mật khẩu hiện tại không chính xác.'}, status=status.HTTP_400_BAD_REQUEST)

        user_id = user.id
        try:
            try:
                user.auth_token.delete()
            except Exception:
                pass
            auth_logout(request)
            user.delete()
        except Exception:
            logger.exception('Delete account failed for user_id=%s', user_id)
            return Response({'error': 'Không thể xóa tài khoản lúc này. Vui lòng thử lại sau.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({'message': 'Tài khoản đã được xóa vĩnh viễn.'}, status=status.HTTP_200_OK)


class EmailChangeRequestOTPView(APIView):
    """POST /api/v1/auth/email-change/request/ — verify password and send OTP to new email"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        password = (request.data.get('password') or '').strip()
        new_email = (request.data.get('new_email') or '').strip().lower()

        if not password:
            return Response({'error': 'Vui lòng nhập mật khẩu hiện tại.'}, status=status.HTTP_400_BAD_REQUEST)
        if not new_email:
            return Response({'error': 'Vui lòng nhập email mới.'}, status=status.HTTP_400_BAD_REQUEST)
        if not user.check_password(password):
            return Response({'error': 'Mật khẩu hiện tại không chính xác.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            validate_email(new_email)
        except ValidationError:
            return Response({'error': 'Email mới không hợp lệ.'}, status=status.HTTP_400_BAD_REQUEST)

        if new_email == (user.email or '').strip().lower():
            return Response({'error': 'Email mới phải khác email hiện tại.'}, status=status.HTTP_400_BAD_REQUEST)
        if User.objects.filter(email__iexact=new_email).exclude(pk=user.pk).exists():
            return Response({'error': 'Email này đã được sử dụng.'}, status=status.HTTP_400_BAD_REQUEST)

        otp = ''.join(str(random.randint(0, 9)) for _ in range(6))
        cache_key = _email_change_cache_key(user.id, new_email)
        cache.set(
            cache_key,
            {
                'otp_hash': _email_change_otp_hash(user.id, new_email, otp),
                'requested_at': timezone.now().isoformat(),
            },
            timeout=600,
        )

        from api.utils.email_utils import send_html_otp_email
        send_html_otp_email(new_email, otp)

        return Response({
            'message': 'Đã gửi OTP xác nhận đến email mới của bạn.',
            'expires_in': 600,
        })


class EmailChangeVerifyOTPView(APIView):
    """POST /api/v1/auth/email-change/verify/ — verify OTP sent to new email and update account email"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        new_email = (request.data.get('new_email') or '').strip().lower()
        otp = (request.data.get('otp') or '').strip()

        if not new_email:
            return Response({'error': 'Thiếu email mới để xác thực.'}, status=status.HTTP_400_BAD_REQUEST)
        if len(otp) != 6 or not otp.isdigit():
            return Response({'error': 'Mã OTP gồm 6 chữ số.'}, status=status.HTTP_400_BAD_REQUEST)

        cache_key = _email_change_cache_key(user.id, new_email)
        pending = cache.get(cache_key)
        if not pending:
            return Response({'error': 'OTP đã hết hạn hoặc chưa được yêu cầu.'}, status=status.HTTP_400_BAD_REQUEST)

        expected_hash = pending.get('otp_hash', '')
        actual_hash = _email_change_otp_hash(user.id, new_email, otp)
        if not hmac.compare_digest(expected_hash, actual_hash):
            return Response({'error': 'Mã OTP không hợp lệ.'}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email__iexact=new_email).exclude(pk=user.pk).exists():
            return Response({'error': 'Email này đã được sử dụng bởi tài khoản khác.'}, status=status.HTTP_400_BAD_REQUEST)

        user.email = new_email
        user.save(update_fields=['email'])

        try:
            from django_otp.plugins.otp_email.models import EmailDevice
            EmailDevice.objects.filter(user=user).update(email=new_email)
        except Exception:
            logger.exception('Failed updating EmailDevice for user_id=%s', user.id)

        cache.delete(cache_key)

        return Response({
            'message': 'Đổi email thành công.',
            'user': UserSerializer(user).data,
        }, status=status.HTTP_200_OK)


class PasswordChangeView(APIView):
    """POST /api/v1/auth/password/change/ — change password with OTP"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')
        otp_token = request.data.get('token')

        if not user.check_password(old_password):
            return Response({'error': 'Mật khẩu cũ không chính xác.'}, status=400)

        if len(new_password) < 8:
            return Response({'error': 'Mật khẩu mới phải có ít nhất 8 ký tự.'}, status=400)

        from django_otp.plugins.otp_email.models import EmailDevice
        device = EmailDevice.objects.filter(user=user, name='default').first()
        if not device or not device.verify_token(otp_token):
            return Response({'error': 'Mã OTP Email không hợp lệ hoặc đã hết hạn.'}, status=400)

        user.set_password(new_password)
        user.save()

        # Re-login to keep the session
        from django.contrib.auth import update_session_auth_hash
        update_session_auth_hash(request, user)

        return Response({'message': 'Đã đổi mật khẩu thành công.'})

