from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.parsers import MultiPartParser, FormParser
from drf_spectacular.utils import extend_schema
import uuid
from .models import ImageAnalysis, AudioAnalysis
from .serializers import (
    ImageAnalysisRequestSerializer, 
    ImageAnalysisResponseSerializer,
    AudioAnalysisRequestSerializer,
    AudioAnalysisResponseSerializer
)
from api.utils.media_utils import (
    extract_ocr_text, 
    extract_ocr_with_boxes,
    analyze_image_risk, 
    transcribe_audio, 
    analyze_audio_risk
)
from api.utils.ollama_client import generate_response
from django.conf import settings

class AnalyzeImagesView(APIView):
    """
    Analyze multiple images for OCR and risk detection.
    """
    parser_classes = (MultiPartParser, FormParser)
    
    @extend_schema(
        request=ImageAnalysisRequestSerializer,
        responses={200: ImageAnalysisResponseSerializer}
    )
    def post(self, request):
        session_id = request.data.get('session_id')
        images = request.FILES.getlist('images')
        
        if not images:
            return Response({'error': 'At least one image is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            session_uuid = uuid.UUID(session_id) if session_id else None
        except (ValueError, AttributeError):
            return Response({'error': 'Invalid session_id format'}, status=status.HTTP_400_BAD_REQUEST)
        
        all_ocr_text = []
        all_qr_data = []
        annotated_images = []
        max_risk_level = 'SAFE'
        risk_details_list = []
        
        small_model = getattr(settings, 'SMALL_MODEL', 'ministral-3:14b-cloud')

        for image_file in images:
            if not image_file.name.lower().endswith(('.jpg', '.jpeg', '.png', '.gif')):
                continue
            
            # Use improved OCR with Boxes and QR extraction
            ocr_result = extract_ocr_with_boxes(image_file)
            ocr_text = ocr_result.get('text', '')
            qr_contents = ocr_result.get('qr_contents', [])
            annotated_img = ocr_result.get('annotated_image_b64', '')

            all_ocr_text.append(ocr_text)
            all_qr_data.extend(qr_contents)
            if annotated_img:
                annotated_images.append(annotated_img)
            
            risk_analysis = analyze_image_risk(ocr_text, image_file)
            
            risk_levels = {'SAFE': 0, 'GREEN': 1, 'YELLOW': 2, 'RED': 3}
            if risk_levels.get(risk_analysis['risk_level'], 0) > risk_levels.get(max_risk_level, 0):
                max_risk_level = risk_analysis['risk_level']
            
            risk_details_list.append(risk_analysis['details'])
            
            ImageAnalysis.objects.create(
                session_id=session_uuid,
                ocr_text=ocr_text,
                risk_level=risk_analysis['risk_level'],
                risk_details=risk_analysis['details'],
                is_safe=risk_analysis['is_safe'],
                image_file=image_file if hasattr(image_file, 'file') else None
            )
        
        combined_ocr = '\n\n'.join(all_ocr_text)
        combined_qr = '\n'.join(all_qr_data)
        combined_details = '\n'.join(risk_details_list)

        # AI Small LLM Reformatting/Summary
        ai_summary = combined_ocr
        if combined_ocr or combined_qr:
            prompt = f"""Hãy tóm tắt và định dạng lại nội dung văn bản (OCR) và mã QR thu thập được từ hình ảnh bằng chứng lừa đảo dưới đây.
Mục tiêu: Làm cho thông tin dễ hiểu, mạch lạc nhưng KHÔNG LÀM MẤT bất kỳ dữ liệu quan trọng nào (số tiền, tên người, STK, SĐT, link...).
Văn bản OCR:
{combined_ocr}
Dữ liệu QR:
{combined_qr}
Hãy trình bày theo dạng danh sách hoặc đoạn văn ngắn gọn, chuyên nghiệp nhất."""
            
            summary_response = generate_response(
                prompt=prompt,
                model=small_model,
                system_prompt="Bạn là trợ lý an ninh mạng chuyên trích xuất và tóm tắt thông tin từ bằng chứng lừa đảo."
            )
            if summary_response:
                ai_summary = summary_response
        
        return Response({
            'ocr_text': ai_summary,
            'raw_ocr': combined_ocr,
            'qr_data': all_qr_data,
            'annotated_images': annotated_images,
            'risk_analysis': {
                'is_safe': max_risk_level in ['SAFE', 'GREEN'],
                'risk_level': max_risk_level,
                'details': combined_details
            }
        })

class AnalyzeAudioView(APIView):
    """
    Analyze recorded audio for speech-to-text and scam detection.
    """
    parser_classes = (MultiPartParser, FormParser)
    
    @extend_schema(
        request=AudioAnalysisRequestSerializer,
        responses={200: AudioAnalysisResponseSerializer}
    )
    def post(self, request):
        session_id = request.data.get('session_id')
        phone_number = request.data.get('phone_number', '')
        audio_file = request.FILES.get('audio')
        
        if not audio_file or not phone_number:
            return Response({'error': 'audio and phone_number are required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            session_uuid = uuid.UUID(session_id) if session_id else None
        except (ValueError, AttributeError):
            return Response({'error': 'Invalid session_id format'}, status=status.HTTP_400_BAD_REQUEST)
        
        if not audio_file.name.lower().endswith(('.mp3', '.m4a', '.wav', '.ogg')):
            return Response({'error': 'Unsupported audio format'}, status=status.HTTP_400_BAD_REQUEST)
        
        transcript_result = transcribe_audio(audio_file)
        transcript = transcript_result.get('transcript', '') if isinstance(transcript_result, dict) else str(transcript_result)
        audio_risk = analyze_audio_risk(transcript, phone_number)
        
        AudioAnalysis.objects.create(
            session_id=session_uuid,
            phone_number=phone_number,
            transcript=transcript,
            risk_score=audio_risk['risk_score'],
            is_scam=audio_risk['is_scam'],
            warning_message=audio_risk['warning_message'],
            audio_file=audio_file if hasattr(audio_file, 'file') else None
        )
        
        return Response({
            'risk_score': audio_risk['risk_score'],
            'is_scam': audio_risk['is_scam'],
            'transcript': transcript,
            'warning_message': audio_risk['warning_message']
        })
