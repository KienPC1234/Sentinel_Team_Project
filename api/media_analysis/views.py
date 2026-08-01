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
    analyze_image_risk, 
    transcribe_audio, 
    analyze_audio_risk
)

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
        max_risk_level = 'SAFE'
        risk_details_list = []
        
        for image_file in images:
            if not image_file.name.lower().endswith(('.jpg', '.jpeg', '.png', '.gif')):
                continue
            
            ocr_text = extract_ocr_text(image_file)
            all_ocr_text.append(ocr_text)
            
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
        combined_details = '\n'.join(risk_details_list)
        
        return Response({
            'ocr_text': combined_ocr,
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
        
        transcript = transcribe_audio(audio_file)
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
