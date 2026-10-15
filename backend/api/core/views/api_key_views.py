"""
ShieldCall VN – User API Key Management Views
Handles CRUD operations, quota monitoring, and key regeneration for users.
"""
import logging
from rest_framework import status, serializers
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from drf_spectacular.utils import extend_schema, inline_serializer
from api.core.models import APIKey

logger = logging.getLogger(__name__)

MAX_KEYS_PER_USER = 5
MAX_KEYS_PER_STAFF = 20


def _serialize_api_key(key: APIKey) -> dict:
    return {
        'id': key.id,
        'name': key.name,
        'prefix': key.prefix,
        'tier': key.tier,
        'tier_display': key.get_tier_display(),
        'rate_limit_per_minute': key.rate_limit_per_minute,
        'daily_quota': key.daily_quota,
        'monthly_quota': key.monthly_quota,
        'requests_today': key.requests_today,
        'requests_this_month': key.requests_this_month,
        'total_requests': key.total_requests,
        'last_used_at': key.last_used_at.isoformat() if key.last_used_at else None,
        'is_active': key.is_active,
        'created_at': key.created_at.isoformat(),
    }


class UserAPIKeyListCreateView(APIView):
    """
    GET  /api/v1/user/api-keys/  — List all API keys of authenticated user
    POST /api/v1/user/api-keys/  — Create a new API key (returns raw key once)
    """
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Danh sách API Key của người dùng",
        responses={200: inline_serializer(
            name='UserAPIKeyListResponse',
            fields={
                'api_keys': serializers.ListField(child=serializers.DictField()),
                'limits_summary': serializers.DictField(),
            }
        )}
    )
    def get(self, request):
        keys = APIKey.objects.filter(user=request.user).order_by('-created_at')
        max_allowed = MAX_KEYS_PER_STAFF if request.user.is_staff else MAX_KEYS_PER_USER
        
        return Response({
            'api_keys': [_serialize_api_key(k) for k in keys],
            'limits_summary': {
                'total_keys': keys.count(),
                'max_allowed_keys': max_allowed,
            }
        })

    @extend_schema(
        summary="Tạo API Key mới",
        request=inline_serializer(
            name='UserAPIKeyCreateRequest',
            fields={
                'name': serializers.CharField(required=False, default=""),
                'tier': serializers.CharField(required=False, default="free"),
            }
        ),
        responses={201: inline_serializer(
            name='UserAPIKeyCreateResponse',
            fields={
                'id': serializers.IntegerField(),
                'name': serializers.CharField(),
                'prefix': serializers.CharField(),
                'tier': serializers.CharField(),
                'tier_display': serializers.CharField(),
                'rate_limit_per_minute': serializers.IntegerField(),
                'daily_quota': serializers.IntegerField(),
                'monthly_quota': serializers.IntegerField(),
                'requests_today': serializers.IntegerField(),
                'requests_this_month': serializers.IntegerField(),
                'total_requests': serializers.IntegerField(),
                'last_used_at': serializers.DateTimeField(allow_null=True),
                'is_active': serializers.BooleanField(),
                'created_at': serializers.DateTimeField(),
                'raw_key': serializers.CharField(),
                'warning': serializers.CharField(),
            }
        )}
    )
    def post(self, request):
        max_allowed = MAX_KEYS_PER_STAFF if request.user.is_staff else MAX_KEYS_PER_USER
        current_count = APIKey.objects.filter(user=request.user).count()
        if current_count >= max_allowed:
            return Response(
                {'error': f'Bạn đã đạt giới hạn tối đa {max_allowed} API Keys. Vui lòng xóa bớt khóa cũ trước khi tạo mới.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        name = (request.data.get('name') or '').strip()
        if not name:
            name = f"Key #{current_count + 1}"

        tier_requested = request.data.get('tier', APIKey.Tier.FREE)
        # Only staff or admins can create developer or unlimited tier keys directly
        if tier_requested in (APIKey.Tier.DEVELOPER, APIKey.Tier.UNLIMITED) and not (request.user.is_staff or getattr(request.user.profile, 'is_super_admin', False)):
            tier_requested = APIKey.Tier.FREE

        api_key, raw_token = APIKey.generate(
            user=request.user,
            name=name[:120],
            tier=tier_requested,
        )

        response_data = _serialize_api_key(api_key)
        response_data['raw_key'] = raw_token
        response_data['warning'] = (
            'Vui lòng lưu lại API Key này ngay bây giờ! '
            'Vì lý do an toàn, mã bí mật đầy đủ này sẽ không được hiển thị lại.'
        )

        return Response(response_data, status=status.HTTP_201_CREATED)


class UserAPIKeyDetailView(APIView):
    """
    DELETE /api/v1/user/api-keys/<id>/ — Revoke/delete an API key
    """
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Thu hồi và xóa vĩnh viễn API Key",
        responses={200: inline_serializer(
            name='UserAPIKeyDeleteResponse',
            fields={'message': serializers.CharField()}
        )}
    )
    def delete(self, request, pk: int):
        api_key = get_object_or_404(APIKey, pk=pk, user=request.user)
        api_key.delete()
        return Response({'message': f'Đã xóa API Key "{api_key.name}" thành công.'})


class UserAPIKeyToggleView(APIView):
    """
    POST /api/v1/user/api-keys/<id>/toggle/ — Enable/Disable an API key
    """
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Bật hoặc vô hiệu hóa trạng thái API Key",
        request=None,
        responses={200: inline_serializer(
            name='UserAPIKeyToggleResponse',
            fields={
                'id': serializers.IntegerField(),
                'is_active': serializers.BooleanField(),
                'message': serializers.CharField(),
            }
        )}
    )
    def post(self, request, pk: int):
        api_key = get_object_or_404(APIKey, pk=pk, user=request.user)
        api_key.is_active = not api_key.is_active
        api_key.save(update_fields=['is_active', 'updated_at'])
        state = 'kích hoạt' if api_key.is_active else 'vô hiệu hóa'
        return Response({
            'id': api_key.id,
            'is_active': api_key.is_active,
            'message': f'Đã {state} API Key thành công.'
        })


class UserAPIKeyRegenerateView(APIView):
    """
    POST /api/v1/user/api-keys/<id>/regenerate/ — Generate new secret for existing key
    """
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Tái tạo token bí mật mới cho API Key",
        request=None,
        responses={200: inline_serializer(
            name='UserAPIKeyRegenerateResponse',
            fields={
                'id': serializers.IntegerField(),
                'name': serializers.CharField(),
                'prefix': serializers.CharField(),
                'tier': serializers.CharField(),
                'tier_display': serializers.CharField(),
                'rate_limit_per_minute': serializers.IntegerField(),
                'daily_quota': serializers.IntegerField(),
                'monthly_quota': serializers.IntegerField(),
                'requests_today': serializers.IntegerField(),
                'requests_this_month': serializers.IntegerField(),
                'total_requests': serializers.IntegerField(),
                'last_used_at': serializers.DateTimeField(allow_null=True),
                'is_active': serializers.BooleanField(),
                'created_at': serializers.DateTimeField(),
                'raw_key': serializers.CharField(),
                'warning': serializers.CharField(),
            }
        )}
    )
    def post(self, request, pk: int):
        api_key = get_object_or_404(APIKey, pk=pk, user=request.user)
        raw_token = api_key.regenerate()

        response_data = _serialize_api_key(api_key)
        response_data['raw_key'] = raw_token
        response_data['warning'] = (
            'Khóa bí mật mới đã được tạo thành công! Khóa cũ đã bị vô hiệu hóa ngay lập tức. '
            'Vui lòng cập nhật cấu hình trên ứng dụng hoặc chatbot của bạn.'
        )
        return Response(response_data)


