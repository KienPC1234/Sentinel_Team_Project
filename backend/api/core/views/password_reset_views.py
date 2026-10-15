"""ShieldCall VN – Native password reset API (React) dùng cơ chế token của django-allauth.

Trước đây frontend gọi `POST /auth/password/reset/` và `/auth/password/reset/confirm/`
nhưng backend chưa có route → 404. Module này bổ sung 2 endpoint tương thích đúng
với luồng allauth (ResetPasswordForm / UserTokenForm / ResetPasswordKeyForm) để:
- sinh & gửi email chứa liên kết đặt lại (token uidb36-key),
- đổi mật khẩu từ uid + token.
"""
import logging

from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from api.core.views.scan_views import _verify_turnstile_or_api_key

logger = logging.getLogger(__name__)


class PasswordResetRequestView(APIView):
    """POST /api/v1/auth/password/reset/ {email, cf-turnstile-response}.

    Luôn trả 200 để không tiết lộ email có tồn tại hay không.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        ts_err = _verify_turnstile_or_api_key(request)
        if ts_err:
            return ts_err

        email = str(request.data.get('email', '') or '').strip()
        if not email:
            return Response({'error': 'Vui lòng nhập địa chỉ email.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            from allauth.account.forms import ResetPasswordForm
            form = ResetPasswordForm(data={'email': email})
            if form.is_valid():
                form.save(request=request)
            else:
                logger.info('[PasswordReset] Bỏ qua email không hợp lệ/không tồn tại (chống dò email).')
        except Exception as exc:  # không để lộ chi tiết ra ngoài
            logger.warning(f'[PasswordReset] request flow error: {exc}')

        return Response({'message': 'Nếu email tồn tại trong hệ thống, liên kết đặt lại mật khẩu đã được gửi.'})


class PasswordResetConfirmView(APIView):
    """POST /api/v1/auth/password/reset/confirm/ {uid, token, password1, password2}.

    `uid` = uidb36, `token` = key trong liên kết allauth (/accounts/password/reset/key/<uid>-<key>/).
    """
    permission_classes = [AllowAny]

    def post(self, request):
        uid = str(request.data.get('uid', '') or request.data.get('uidb36', '') or '').strip()
        token = str(request.data.get('token', '') or request.data.get('key', '') or '').strip()
        pw1 = request.data.get('password1', '') or ''
        pw2 = request.data.get('password2', '') or ''

        if not uid or not token:
            return Response(
                {'token_fail': True, 'error': 'Liên kết đặt lại mật khẩu không hợp lệ.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if pw1 != pw2:
            return Response({'error': 'Mật khẩu xác nhận không khớp.'}, status=status.HTTP_400_BAD_REQUEST)
        if not pw1:
            return Response({'error': 'Vui lòng nhập mật khẩu mới.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            from allauth.account.forms import ResetPasswordKeyForm, UserTokenForm

            token_form = UserTokenForm(data={'uidb36': uid, 'key': token})
            if not token_form.is_valid() or token_form.reset_user is None:
                return Response(
                    {'token_fail': True, 'error': 'Liên kết đặt lại mật khẩu không hợp lệ hoặc đã hết hạn.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user = token_form.reset_user
            form = ResetPasswordKeyForm(data={'password1': pw1, 'password2': pw2}, user=user, temp_key=token)
            if not form.is_valid():
                msgs = []
                for field in ('password1', 'password2'):
                    msgs.extend([str(e) for e in form.errors.get(field, [])])
                return Response(
                    {'error': ' '.join(msgs) or 'Mật khẩu không hợp lệ.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            form.save()
            try:
                from allauth.account.internal.flows.password_reset import finalize_password_reset
                finalize_password_reset(request, user)
            except Exception as exc:
                logger.warning(f'[PasswordReset] finalize error: {exc}')

            return Response({'message': 'Đặt lại mật khẩu thành công.'})
        except Exception as exc:
            logger.exception(f'[PasswordReset] confirm error: {exc}')
            return Response(
                {'token_fail': True, 'error': 'Không thể đặt lại mật khẩu. Vui lòng thử lại.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
