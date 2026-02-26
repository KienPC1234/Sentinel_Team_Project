"""
Media utilities for OCR, image analysis, and audio transcription.

This module provides implementations for:
- OCR text extraction from images using Tesseract (Vietnamese + English)
- Image risk analysis using Ollama
- Audio transcription (placeholder)
- Audio scam pattern detection using Ollama
"""

import io
import json
import logging
from PIL import Image, ImageFilter, ImageEnhance
from api.utils.ollama_client import analyze_text_for_scam, generate_response

logger = logging.getLogger(__name__)

# ─── EasyOCR Configuration ──────────────────────────────────────────
try:
    import easyocr
    EASYOCR_AVAILABLE = True
except ImportError:
    EASYOCR_AVAILABLE = False
    logger.warning("easyocr not installed. OCR will be disabled.")

_EASYOCR_READER = None

def get_easyocr_reader():
    """
    Singleton EasyOCR reader instance for English and Vietnamese.
    Loads the model into memory only once.
    """
    global _EASYOCR_READER
    if not EASYOCR_AVAILABLE:
        return None
        
    if _EASYOCR_READER is None:
        from django.conf import settings
        gpu = getattr(settings, 'EASYOCR_GPU', False)
        logger.info(f"Initializing EasyOCR reader (GPU={gpu})...")
        try:
            # English is compatible with Vietnamese.
            _EASYOCR_READER = easyocr.Reader(['vi', 'en'], gpu=gpu)
            logger.info("EasyOCR reader initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize EasyOCR reader: {e}")
            return None
    return _EASYOCR_READER


def extract_ocr_text(image_file) -> str:
    """
    Extract text from image using EasyOCR.
    Supports Vietnamese (vi) and English (en) languages.

    Args:
        image_file: Django UploadedFile, file-like object, or numpy array
    
    Returns:
        Extracted text string
    """
    reader = get_easyocr_reader()
    if not reader:
        logger.warning("EasyOCR not available, returning empty OCR result")
        return ""

    try:
        if hasattr(image_file, 'read'):
            image_data = image_file.read()
            image_file.seek(0)
        else:
            image_data = image_file

        results = reader.readtext(image_data, detail=0)
        text = '\n'.join(results).strip()

        logger.info(f"EasyOCR extracted {len(text)} characters from image")
        return text

    except Exception as e:
        logger.error(f"EasyOCR extraction error: {e}")
        return ""


def extract_ocr_with_boxes(image_file):
    """
    Extract OCR text AND QR codes WITH bounding box coordinates.
    Generates an annotated image showing both text regions and QR codes.
    
    Returns:
        dict with keys:
            - text: full extracted OCR text
            - qr_contents: list of decoded QR data strings
            - regions: list of {bbox, text, confidence, type: 'text'|'qr'}
            - annotated_image_b64: base64-encoded annotated image
    """
    import base64
    import numpy as np
    from PIL import ImageDraw, ImageFont
    try:
        from pyzbar import pyzbar
        PYZBAR_AVAILABLE = True
    except ImportError:
        PYZBAR_AVAILABLE = False

    reader = get_easyocr_reader()
    
    try:
        if hasattr(image_file, 'read'):
            image_data = image_file.read()
            image_file.seek(0)
        else:
            image_data = image_file

        pil_img = Image.open(io.BytesIO(image_data)).convert("RGB")
        draw = ImageDraw.Draw(pil_img)
        
        # Build regions list
        regions = []
        text_parts = []
        qr_contents = []

        # 1. Detect QR Codes first (cyan boxes)
        if PYZBAR_AVAILABLE:
            decoded = pyzbar.decode(pil_img)
            for d in decoded:
                content = d.data.decode('utf-8', errors='replace')
                qr_contents.append(content)
                # pyzbar provides rect (left, top, width, height) and polygon
                # and polygon is a list of Points
                poly = d.polygon
                bbox = [[p.x, p.y] for p in poly]
                regions.append({
                    "bbox": bbox,
                    "text": content,
                    "confidence": 1.0,
                    "type": "qr"
                })

        # 2. Detect OCR Text (green/yellow/red boxes)
        if reader:
            ocr_results = reader.readtext(image_data, detail=1)
            for item in ocr_results:
                bbox, text, conf = item
                text_parts.append(text)
                regions.append({
                    "bbox": [[int(p[0]), int(p[1])] for p in bbox],
                    "text": text,
                    "confidence": round(float(conf), 3),
                    "type": "text"
                })

        full_text = '\n'.join(text_parts).strip()

        # 3. Draw Bounding Boxes
        try:
            font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 14)
        except Exception:
            font = ImageFont.load_default()

        for region in regions:
            bbox = region["bbox"]
            conf = region["confidence"]
            rtype = region["type"]
            
            points = [(p[0], p[1]) for p in bbox]
            
            if rtype == "qr":
                color = (0, 229, 255)  # cyan
            else: # text
                if conf >= 0.8:
                    color = (0, 230, 118)  # green
                elif conf >= 0.5:
                    color = (255, 234, 0)  # yellow
                else:
                    color = (255, 23, 68)  # red
            
            # Draw outline
            draw.polygon(points, outline=color)
            for offset in [(1, 0), (-1, 0), (0, 1), (0, -1)]:
                shifted = [(p[0] + offset[0], p[1] + offset[1]) for p in points]
                draw.polygon(shifted, outline=color)
            
            # Label
            label = "QR" if rtype == "qr" else f"{conf:.0%}"
            label_pos = (min(p[0] for p in points), min(p[1] for p in points) - 16)
            draw.text(label_pos, label, fill=color, font=font)

        # Encode annotated image to base64
        buf = io.BytesIO()
        pil_img.save(buf, format="PNG", optimize=True)
        annotated_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

        return {
            "text": full_text,
            "qr_contents": qr_contents,
            "regions": regions,
            "annotated_image_b64": f"data:image/png;base64,{annotated_b64}"
        }

    except Exception as e:
        logger.error(f"OCR with boxes error: {e}")
        return {"text": "", "qr_contents": [], "regions": [], "annotated_image_b64": ""}


def extract_qr_data(image_file) -> list:
    """
    Extract QR code data from an image.

    Returns:
        List of decoded QR strings
    """
    try:
        from pyzbar import pyzbar
        image = Image.open(image_file)
        decoded = pyzbar.decode(image)
        return [d.data.decode('utf-8', errors='replace') for d in decoded]
    except ImportError:
        logger.warning("pyzbar not installed, QR decoding disabled")
        return []
    except Exception as e:
        logger.error(f"QR decode error: {e}")
        return []


def analyze_image_risk(ocr_text, image_file=None):
    """
    Analyze image for scam/phishing indicators using Ollama.

    Returns:
    {
        "is_safe": bool,
        "risk_level": "SAFE" | "GREEN" | "YELLOW" | "RED",
        "details": "Description of risk"
    }
    """
    if not ocr_text:
        return {
            'is_safe': True,
            'risk_level': 'SAFE',
            'details': 'Ảnh trống hoặc không chứa văn bản'
        }

    # Use Ollama to analyze the text
    try:
        analysis = analyze_text_for_scam(ocr_text)

        is_scam = analysis.get('is_scam', False)
        risk_score = analysis.get('risk_score', 0)

        # Map risk score to risk level
        if risk_score >= 80:
            risk_level = 'RED'
        elif risk_score >= 60:
            risk_level = 'YELLOW'
        elif risk_score >= 40:
            risk_level = 'GREEN'
        else:
            risk_level = 'SAFE'

        details = analysis.get('reason', 'Không thể xác định')

        return {
            'is_safe': not is_scam and risk_level != 'RED',
            'risk_level': risk_level,
            'details': details
        }

    except Exception as e:
        logger.error(f"Error analyzing image with Ollama: {e}")

        # Fallback to keyword-based analysis
        risk_keywords = {
            'RED': [
                'chuyển khoản', 'cung cấp thông tin', 'xác minh tài khoản',
                'update ngân hàng', 'tài khoản bị khóa', 'không hoạt động',
                'nhập mã otp', 'cảnh sát', 'công an yêu cầu',
            ],
            'YELLOW': [
                'xác minh', 'kiểm tra', 'tiền', 'tài khoản',
                'thanh toán', 'chuyển tiền', 'mã xác nhận',
            ]
        }

        text_lower = ocr_text.lower()

        # Check for RED risk indicators
        for keyword in risk_keywords['RED']:
            if keyword in text_lower:
                return {
                    'is_safe': False,
                    'risk_level': 'RED',
                    'details': f"Phát hiện từ khóa nguy hiểm: '{keyword}'"
                }

        # Check for YELLOW risk indicators
        for keyword in risk_keywords['YELLOW']:
            if keyword in text_lower:
                return {
                    'is_safe': False,
                    'risk_level': 'YELLOW',
                    'details': f"Phát hiện từ khóa cảnh báo: '{keyword}'"
                }

        return {
            'is_safe': True,
            'risk_level': 'SAFE',
            'details': 'Ảnh an toàn'
        }


def transcribe_audio(audio_file):
    """
    Transcribe audio to text using speech-to-text service.

    Production implementation: Use Google Cloud Speech-to-Text or OpenAI Whisper
    """
    try:
        # PRODUCTION NOTE: This requires a speech-to-text engine like OpenAI Whisper or Google Speech-to-Text.
        # For the local prototype, we return an empty string or a note if the engine is not configured.
        logger.warning("Audio transcription engine not configured. Audio analysis will be limited.")
        return "" 
    except Exception as e:
        logger.error(f"Audio transcription error: {e}")
        return ""


def analyze_audio_risk(transcript, phone_number):
    """
    Analyze audio transcript for scam patterns using Ollama.

    Returns:
    {
        "risk_score": 0-100,
        "is_scam": bool,
        "warning_message": "...",
        "duration": seconds
    }
    """
    if not transcript:
        return {
            'risk_score': 0,
            'is_scam': False,
            'warning_message': 'Không thể phân tích âm thanh trống',
            'duration': 0
        }

    try:
        # Use Ollama to analyze transcript
        analysis = analyze_text_for_scam(transcript)

        risk_score = analysis.get('risk_score', 0)
        is_scam = analysis.get('is_scam', False)
        indicators = analysis.get('indicators', [])
        reason = analysis.get('reason', '')

        warning_message = reason if reason else 'Cuộc gọi bình thường'

        return {
            'risk_score': min(risk_score, 100),
            'is_scam': is_scam or risk_score >= 75,
            'warning_message': warning_message,
            'duration': 0
        }

    except Exception as e:
        logger.error(f"Error analyzing audio with Ollama: {e}")

        # Fallback to keyword-based analysis
        scam_patterns = {
            'police_impersonation': ['công an', 'cảnh sát', 'nhân viên công an'],
            'financial_fraud': ['chuyển tiền', 'tài khoản ngân hàng', 'cung cấp thông tin'],
            'account_verification': ['xác minh tài khoản', 'kiểm tra tài khoản', 'tài khoản bị khóa'],
            'urgency': ['khẩn cấp', 'gấp', 'ngay lập tức'],
        }

        transcript_lower = transcript.lower()
        found_patterns = []

        for pattern_type, keywords in scam_patterns.items():
            for keyword in keywords:
                if keyword in transcript_lower:
                    found_patterns.append(pattern_type)
                    break

        # Calculate risk score
        risk_score = len(found_patterns) * 25
        is_scam = risk_score >= 50

        warning_message = ""
        if found_patterns:
            warning_message = f"Phát hiện kịch bản lừa đảo: {', '.join(found_patterns).replace('_', ' ')}"

        return {
            'risk_score': min(risk_score, 100),
            'is_scam': is_scam,
            'warning_message': warning_message if warning_message else 'Cuộc gọi bình thường',
            'duration': 0
        }
