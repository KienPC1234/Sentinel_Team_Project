from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from drf_spectacular.utils import extend_schema, OpenApiParameter
import uuid
from .models import UserSession
from .serializers import SessionCheckResponseSerializer

class CheckSessionView(APIView):
    """
    Check if a session is valid and return a new one if expired.
    """
    @extend_schema(
        parameters=[
            OpenApiParameter(name='session_id', description='UUID of the session to check', required=True, type=str)
        ],
        responses={200: SessionCheckResponseSerializer}
    )
    def get(self, request):
        session_id = request.query_params.get('session_id')
        
        if not session_id:
            return Response({
                'error': 'session_id is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            session_uuid = uuid.UUID(session_id)
        except (ValueError, AttributeError):
            return Response({
                'error': 'Invalid session_id format'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            session = UserSession.objects.get(session_id=session_uuid)
            
            # Check if expired
            if session.is_expired():
                session.is_active = False
                session.save(update_fields=['is_active'])
                
                # Create new session
                new_session = UserSession.objects.create()
                
                return Response({
                    'is_valid': False,
                    'new_session_id': str(new_session.session_id)
                })
            
            # Session is valid, refresh it
            session.refresh()
            
            return Response({
                'is_valid': True,
                'new_session_id': None
            })
        
        except UserSession.DoesNotExist:
            # Create new session for unknown session_id
            new_session = UserSession.objects.create()
            
            return Response({
                'is_valid': False,
                'new_session_id': str(new_session.session_id)
            })
