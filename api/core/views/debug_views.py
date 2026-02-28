from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAdminUser
from django.core.mail import send_mail
from django.conf import settings
from api.utils.ollama_client import client, DEFAULT_MODEL, is_ollama_available
import logging

logger = logging.getLogger(__name__)

class DebugSystemView(APIView):
    """
    Debug view to test system connectivity.
    """
    permission_classes = [IsAdminUser]

    def get(self, request):
        action = request.query_params.get('action')
        
        if action == 'test_email':
            return self.test_email(request)
        elif action == 'test_ai':
            return self.test_ai(request)
        
        return Response({
            "status": "ok",
            "message": "ShieldCall Debug API",
            "capabilities": ["test_email", "test_ai"]
        })

    def test_email(self, request):
        target_email = request.query_params.get('email', settings.DEFAULT_FROM_EMAIL)
        try:
            send_mail(
                "ShieldCall Debug Test",
                "This is a test email from ShieldCall Debug API.",
                settings.DEFAULT_FROM_EMAIL,
                [target_email],
                fail_silently=False
            )
            return Response({"status": "success", "message": f"Test email sent to {target_email}"})
        except Exception as e:
            logger.exception("Debug email test failed")
            return Response({"status": "error", "message": str(e)}, status=500)

    def test_ai(self, request):
        try:
            if not is_ollama_available():
                return Response({"status": "error", "message": "Ollama service not available"}, status=503)
            
            models = client.list()
            return Response({
                "status": "success",
                "ollama_available": True,
                "default_model": DEFAULT_MODEL,
                "available_models": [m['name'] for m in models['models']]
            })
        except Exception as e:
            logger.exception("Debug AI test failed")
            return Response({"status": "error", "message": str(e)}, status=500)
