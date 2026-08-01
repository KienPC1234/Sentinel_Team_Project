from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.core.cache import cache
from drf_spectacular.utils import extend_schema, OpenApiParameter
from .models import PhoneNumber, PhoneRiskLevel
from .serializers import PhoneCheckResponseSerializer

class CheckPhoneView(APIView):
    """
    Check the risk level of a phone number.
    """
    @extend_schema(
        parameters=[
            OpenApiParameter(name='phone', description='Phone number to check', required=True, type=str)
        ],
        responses={200: PhoneCheckResponseSerializer}
    )
    def get(self, request):
        phone = request.query_params.get('phone', '').strip()
        
        if not phone:
            return Response({
                'error': 'phone parameter is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        normalized_phone = ''.join(c for c in phone if c.isdigit() or c.startswith('+'))
        
        cache_key = f'phone_risk:{normalized_phone}'
        cached_result = cache.get(cache_key)
        if cached_result:
            return Response(cached_result)
        
        try:
            phone_record = PhoneNumber.objects.get(phone_number=normalized_phone)
            response_data = {
                'risk_level': phone_record.risk_level,
                'risk_label': phone_record.risk_label,
                'recommendations': phone_record.recommendations
            }
        except PhoneNumber.DoesNotExist:
            response_data = {
                'risk_level': PhoneRiskLevel.SAFE,
                'risk_label': 'Số điện thoại chưa được báo cáo',
                'recommendations': []
            }
        
        cache.set(cache_key, response_data, 60 * 60)
        
        return Response(response_data)
