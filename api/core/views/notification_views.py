import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from api.utils.push_service import push_service
import os
from django.conf import settings
from api.maintenance.tasks import rebuild_vector_index

logger = logging.getLogger(__name__)

class TestPushView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        message = request.data.get('message', 'Đây là tin nhắn thử nghiệm từ ShieldCall!')
        title = request.data.get('title', 'Thông báo thử nghiệm')
        
        success = push_service.send_push(
            user_id=request.user.id,
            title=title,
            message=message,
            notification_type='success'
        )
        
        if success:
            return Response({'status': 'success', 'message': 'Đã gửi yêu cầu push tới websocket.'})
        return Response({'status': 'error', 'message': 'Không thể gửi push.'}, status=500)

class ResetRAGView(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request):
        """
        Deletes the vector index files and triggers a fresh rebuild.
        """
        index_dir = os.path.join(settings.BASE_DIR, 'media', 'vector_index')
        try:
            if os.path.exists(index_dir):
                for f in os.listdir(index_dir):
                    os.remove(os.path.join(index_dir, f))
            
            # Trigger task
            rebuild_vector_index.delay(trigger='FORCE_RESET')
            
            return Response({
                'status': 'success', 
                'message': 'Đã xóa dữ liệu cũ và bắt đầu rebuild index từ đầu (chế độ nền).'
            })
        except Exception as e:
            return Response({'status': 'error', 'message': str(e)}, status=500)

class OneSignalRegistrationView(APIView):
    """
    Registers or updates the OneSignal Player ID for the authenticated user.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        player_id = request.data.get('player_id')
        if not player_id:
            return Response({'status': 'error', 'message': 'player_id is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            profile = request.user.profile
            profile.onesignal_player_id = player_id
            profile.save()
            logger.info(f"Registered OneSignal Player ID for user {request.user.username}: {player_id}")
            return Response({'status': 'success', 'message': 'OneSignal ID registered'})
        except Exception as e:
            logger.error(f"Error saving OneSignal ID for {request.user.username}: {e}")
            return Response({'status': 'error', 'message': str(e)}, status=500)
