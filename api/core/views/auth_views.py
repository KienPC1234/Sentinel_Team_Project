"""ShieldCall VN – Auth Views"""
import re
import hashlib
import logging
import json
from urllib.parse import urlparse

from django.contrib.auth import authenticate, get_user_model
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

from api.core.models import (
    Domain, BankAccount, Report, ScanEvent, TrendDaily,
    EntityLink, UserAlert, ScamType, RiskLevel, ReportStatus,
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

# ═══════════════════════════════════════════════════════════════════════════
# AUTH APIs
# ═══════════════════════════════════════════════════════════════════════════

class RegisterView(APIView):
    """POST /api/auth/register"""
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token, _ = Token.objects.get_or_create(user=user)
        return Response({
            'message': 'Đăng ký thành công!',
            'token': token.key,
            'user': UserSerializer(user).data,
        }, status=status.HTTP_201_CREATED)


from django.contrib.auth import authenticate, login as auth_login, get_user_model

class LoginView(APIView):
    """POST /api/auth/login"""
    permission_classes = [AllowAny]

    def post(self, request):
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
            return Response({
                'mfa_required': True,
                'methods': {
                    'totp': has_totp,
                    'email': has_email
                },
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
        # We handle both User and UserProfile updates here for simplicity
        profile = user.profile
        
        # Profile data (avatar, bio)
        if 'avatar' in request.FILES or 'bio' in request.data:
            serializer = UserProfileSerializer(profile, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            
        # Basic user data (names)
        if any(k in request.data for k in ['first_name', 'last_name']):
            user.first_name = request.data.get('first_name', user.first_name)
            user.last_name = request.data.get('last_name', user.last_name)
            user.save()
            
        return Response({
            'message': 'Cập nhật thông tin thành công!',
            'user': UserSerializer(user).data
        })


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

