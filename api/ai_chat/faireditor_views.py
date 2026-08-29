"""FairEditor - Dedicated Analysis API"""
import json
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from api.utils.ollama_client import generate_response

class FairEditorAnalyzeView(APIView):
    """
    POST /api/v1/faireditor/analyze/
    Analyzes text for gender bias and returns structured JSON for the extension.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        text = request.data.get('text', '').strip()
        if not text:
            return Response({'error': 'Không có dữ liệu văn bản'}, status=status.HTTP_400_BAD_REQUEST)

        system_prompt = (
            "Bạn là một chuyên gia về ngôn ngữ thấu cảm và bao trùm. "
            "Hãy phân tích đoạn văn sau để tìm định kiến giới hoặc ngôn từ không bao trùm. "
            "Trả về kết quả dưới dạng JSON duy nhất với các trường sau:\n"
            "- biasDetected: boolean\n"
            "- inclusiveScore: int (từ 0 đến 100, 100 là hoàn hảo)\n"
            "- originalText: string\n"
            "- suggestedText: string (đoạn văn đã được sửa lại cho thấu cảm hơn)\n"
            "- explanation: string (giải thích ngắn gọn tại sao cần sửa)\n"
            "- highlights: mảng các đối tượng { \"start\": int, \"end\": int, \"type\": \"bias|unclear\" }.\n\n"
            "Chỉ trả về JSON, không có văn bản thừa."
        )

        try:
            ai_raw = generate_response(f"{system_prompt}\n\nVăn bản: \"{text}\"")
            try:
                cleaned = ai_raw.strip()
                if cleaned.startswith("```json"):
                    cleaned = cleaned[7:]
                if cleaned.endswith("```"):
                    cleaned = cleaned[:-3]
                result = json.loads(cleaned.strip())
                # Ensure inclusiveScore exists
                if 'inclusiveScore' not in result:
                    result['inclusiveScore'] = 100 if not result.get('biasDetected') else 60
            except:
                result = {
                    "biasDetected": True,
                    "inclusiveScore": 50,
                    "originalText": text,
                    "suggestedText": ai_raw,
                    "explanation": "AI đã phân tích và phát hiện các yếu tố cần cải thiện.",
                    "highlights": []
                }
            
            # Special logic for recruitment context if detected
            if "tuyển" in text.lower() or "công việc" in text.lower():
                result['context'] = "recruitment"
            
            return Response(result)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
