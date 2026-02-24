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
    Handles CUDA fork errors in Celery prefork workers by falling back to CPU.
    """
    global _EASYOCR_READER
    if not EASYOCR_AVAILABLE:
        return None
        
    if _EASYOCR_READER is None:
        import os
        import multiprocessing
        from django.conf import settings

        gpu = getattr(settings, 'EASYOCR_GPU', False)

        # Detect forked subprocess (Celery prefork) — CUDA cannot reinitialize after fork
        is_forked = multiprocessing.current_process().daemon or multiprocessing.parent_process() is not None
        if is_forked and gpu:
            logger.info("Forked subprocess detected — forcing EasyOCR to CPU mode.")
            gpu = False
            # Prevent PyTorch from touching CUDA at all in forked process
            os.environ['CUDA_VISIBLE_DEVICES'] = ''
            try:
                import torch
                if hasattr(torch.cuda, 'is_available'):
                    # Disable CUDA in torch before EasyOCR loads models
                    torch.cuda.is_available = lambda: False
            except ImportError:
                pass

        logger.info(f"Initializing EasyOCR reader (GPU={gpu})...")
        try:
            _EASYOCR_READER = easyocr.Reader(['vi', 'en'], gpu=gpu)
            logger.info("EasyOCR reader initialized successfully.")
        except RuntimeError as e:
            if 'CUDA' in str(e) or 'forked' in str(e):
                logger.warning(f"CUDA error detected, retrying with gpu=False: {e}")
                os.environ['CUDA_VISIBLE_DEVICES'] = ''
                try:
                    import torch
                    torch.cuda.is_available = lambda: False
                except ImportError:
                    pass
                try:
                    _EASYOCR_READER = easyocr.Reader(['vi', 'en'], gpu=False)
                    logger.info("EasyOCR reader initialized successfully (CPU fallback).")
                except Exception as e2:
                    logger.error(f"Failed to initialize EasyOCR reader (CPU fallback): {e2}")
                    return None
            else:
                logger.error(f"Failed to initialize EasyOCR reader: {e}")
                return None
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

    except RuntimeError as e:
        if 'CUDA' in str(e):
            logger.warning(f"CUDA error during readtext, resetting reader to CPU: {e}")
            global _EASYOCR_READER
            _EASYOCR_READER = None
            import os
            os.environ['CUDA_VISIBLE_DEVICES'] = ''
            try:
                import torch
                torch.cuda.is_available = lambda: False
            except ImportError:
                pass
            reader = get_easyocr_reader()
            if reader:
                try:
                    if hasattr(image_file, 'seek'):
                        image_file.seek(0)
                    results = reader.readtext(image_data, detail=0)
                    return '\n'.join(results).strip()
                except Exception as e2:
                    logger.error(f"EasyOCR retry failed: {e2}")
        else:
            logger.error(f"EasyOCR extraction error: {e}")
        return ""
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
        global _EASYOCR_READER
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
            try:
                ocr_results = reader.readtext(image_data, detail=1)
            except RuntimeError as cuda_err:
                if 'CUDA' in str(cuda_err):
                    logger.warning(f"CUDA error during readtext in extract_ocr_with_boxes, resetting reader: {cuda_err}")
                    _EASYOCR_READER = None
                    import os as _os
                    _os.environ['CUDA_VISIBLE_DEVICES'] = ''
                    try:
                        import torch
                        torch.cuda.is_available = lambda: False
                    except ImportError:
                        pass
                    reader = get_easyocr_reader()
                    ocr_results = reader.readtext(image_data, detail=1) if reader else []
                else:
                    raise
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


# ─── Faster-Whisper Configuration ─────────────────────────────────────
try:
    from faster_whisper import WhisperModel
    FASTER_WHISPER_AVAILABLE = True
except ImportError:
    FASTER_WHISPER_AVAILABLE = False
    logger.warning("faster-whisper not installed. Audio transcription will be disabled.")

_WHISPER_MODEL = None

def get_whisper_model():
    """
    Singleton Faster-Whisper model.  Loads once into memory.
    Uses ``small`` by default (good accuracy / speed balance for Vietnamese).
    Falls back to CPU in forked Celery workers just like the OCR reader.
    """
    global _WHISPER_MODEL
    if not FASTER_WHISPER_AVAILABLE:
        return None

    if _WHISPER_MODEL is None:
        import multiprocessing
        from django.conf import settings

        model_size = getattr(settings, 'WHISPER_MODEL_SIZE', 'small')
        device = getattr(settings, 'WHISPER_DEVICE', 'auto')

        is_forked = (
            multiprocessing.current_process().daemon
            or multiprocessing.parent_process() is not None
        )
        if is_forked and device != 'cpu':
            logger.info("Forked subprocess detected — forcing Whisper to CPU mode.")
            device = 'cpu'

        compute_type = 'int8' if device == 'cpu' else 'float16'
        logger.info(
            f"Loading Faster-Whisper model '{model_size}' on device='{device}', "
            f"compute_type='{compute_type}' …"
        )
        try:
            _WHISPER_MODEL = WhisperModel(
                model_size, device=device, compute_type=compute_type
            )
            logger.info("Faster-Whisper model loaded successfully.")
        except Exception as exc:
            logger.error(f"Failed to load Faster-Whisper on {device}: {exc}")
            if device != 'cpu':
                logger.info("Retrying Faster-Whisper on CPU …")
                _WHISPER_MODEL = WhisperModel(
                    model_size, device='cpu', compute_type='int8'
                )
                logger.info("Faster-Whisper model loaded on CPU fallback.")
    return _WHISPER_MODEL


def transcribe_audio(audio_file, language=None):
    """
    Transcribe an audio file to text using Faster-Whisper.

    Args:
        audio_file: A file-like object (Django ``UploadedFile``) or a path string.
        language: ISO-639-1 code (e.g. ``'vi'``).  ``None`` = auto-detect.

    Returns:
        A ``dict`` with keys ``transcript`` (str), ``language`` (str),
        ``duration`` (float, seconds) and ``segments`` (list of dicts with
        ``start``, ``end``, ``text``).
    """
    empty_result = {'transcript': '', 'language': '', 'duration': 0.0, 'segments': []}

    model = get_whisper_model()
    if model is None:
        logger.warning("Whisper model unavailable — returning empty transcript.")
        return empty_result

    import tempfile, os, shutil

    tmp_path = None
    wav_converted_path = None
    try:
        # Persist the uploaded file to a temp path that faster-whisper can read
        if hasattr(audio_file, 'read'):
            suffix = ''
            name = getattr(audio_file, 'name', '') or ''
            if '.' in name:
                suffix = '.' + name.rsplit('.', 1)[-1]
            fd, tmp_path = tempfile.mkstemp(suffix=suffix)
            with os.fdopen(fd, 'wb') as tmp:
                if hasattr(audio_file, 'seek'):
                    audio_file.seek(0)
                shutil.copyfileobj(audio_file, tmp)
            file_for_model = tmp_path
        else:
            file_for_model = str(audio_file)

        # Convert webm/ogg to wav for better whisper compatibility
        ext_lower = os.path.splitext(file_for_model)[1].lower()
        if ext_lower in ('.webm', '.ogg'):
            try:
                import subprocess
                fd_wav, wav_converted_path = tempfile.mkstemp(suffix='.wav')
                os.close(fd_wav)
                result = subprocess.run(
                    ['ffmpeg', '-y', '-i', file_for_model, '-ar', '16000', '-ac', '1', '-f', 'wav', wav_converted_path],
                    capture_output=True, timeout=60
                )
                if result.returncode == 0 and os.path.getsize(wav_converted_path) > 0:
                    logger.info(f"Converted {ext_lower} to wav for transcription")
                    file_for_model = wav_converted_path
                else:
                    logger.warning(f"ffmpeg conversion failed (rc={result.returncode}), using original file")
                    if wav_converted_path and os.path.exists(wav_converted_path):
                        os.remove(wav_converted_path)
                    wav_converted_path = None
            except (FileNotFoundError, subprocess.TimeoutExpired) as conv_err:
                logger.warning(f"ffmpeg not available or timed out ({conv_err}), using original file")
                wav_converted_path = None

        transcribe_kwargs = {'beam_size': 5, 'vad_filter': True}
        if language:
            transcribe_kwargs['language'] = language

        segments_iter, info = model.transcribe(file_for_model, **transcribe_kwargs)

        segments = []
        full_text_parts = []
        for seg in segments_iter:
            segments.append({
                'start': round(seg.start, 2),
                'end':   round(seg.end, 2),
                'text':  seg.text.strip(),
            })
            full_text_parts.append(seg.text.strip())

        transcript = ' '.join(full_text_parts)
        detected_lang = getattr(info, 'language', language or '')
        duration = getattr(info, 'duration', 0.0)

        logger.info(
            f"Transcription complete: lang={detected_lang}, "
            f"duration={duration:.1f}s, chars={len(transcript)}"
        )
        return {
            'transcript': transcript,
            'language': detected_lang,
            'duration': round(duration, 2),
            'segments': segments,
        }

    except Exception as e:
        logger.error(f"Audio transcription error: {e}", exc_info=True)
        return empty_result
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        if wav_converted_path and os.path.exists(wav_converted_path):
            try:
                os.remove(wav_converted_path)
            except OSError:
                pass


def analyze_audio_risk(transcript, phone_number=''):
    """
    Analyze audio transcript for scam patterns using Ollama.

    Args:
        transcript: Plain text string (the speech-to-text output).
        phone_number: Optional associated phone number for context.

    Returns:
        dict with ``risk_score``, ``is_scam``, ``warning_message``, ``duration``.
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
