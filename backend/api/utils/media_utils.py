"""
Media utilities for OCR, image analysis, and audio transcription.

This module provides implementations for:
- OCR text extraction from images using Tesseract (Vietnamese + English)
- Image risk analysis using Ollama
- Audio transcription (placeholder)
- Audio scam pattern detection using Ollama
"""

import io
import os
import base64
import json
import logging
import re
import unicodedata
import numpy as np
from PIL import Image, ImageFilter, ImageEnhance
from api.utils.ollama_client import analyze_text_for_scam, generate_response

logger = logging.getLogger(__name__)

# ─── OCR engine: VietOCR (chạy trong venv riêng qua bridge) ──────────
# Đã gỡ EasyOCR/PaddleOCR. Engine nhận dạng tiếng Việt = VietOCR (xem ocr_bridge.py).
import importlib.util


def preprocess_image_for_ocr(image_bytes: bytes) -> bytes:
    """
    Enhance screenshot quality for OCR:
    - Upscale low-res/compressed text to optimal OCR scale (~1800-2400px).
    - Apply adaptive histogram equalization (CLAHE) on lightness channel to sharpen text.
    """
    try:
        import cv2
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            return image_bytes

        h, w = img.shape[:2]
        max_dim = max(h, w)
        if max_dim < 1800:
            scale = min(2.0, 1800.0 / max(max_dim, 1))
            img = cv2.resize(img, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)

        lab = cv2.cvtColor(img, cv2.COLOR_BGR2LAB)
        l_channel, a_channel, b_channel = cv2.split(lab)
        clahe = cv2.createCLAHE(clipLimit=1.5, tileGridSize=(8, 8))
        cl = clahe.apply(l_channel)
        enhanced_lab = cv2.merge((cl, a_channel, b_channel))
        enhanced_bgr = cv2.cvtColor(enhanced_lab, cv2.COLOR_LAB2BGR)

        is_success, buffer = cv2.imencode('.png', enhanced_bgr)
        return buffer.tobytes() if is_success else image_bytes
    except Exception as e:
        logger.warning(f"Image preprocessing for OCR failed, using original: {e}")
        return image_bytes


def clean_ocr_text(text: str) -> str:
    """
    Post-process OCR output:
    - Unicode NFC normalization.
    - Spacing cleanups for punctuation and URLs.
    - Fix common Vietnamese OCR confusion (e.g. 'Iàm'/'Zàm' -> 'làm', 'nình' -> 'mình').
    """
    if not text:
        return ""
    text = unicodedata.normalize('NFC', text)
    # Fix spacing around punctuation
    text = re.sub(r'\s+([,.:;?!])', r'\1', text)
    # Fix broken URL schemes like https:/ / or https: //
    text = re.sub(r'https?\s*:\s*/+\s*', 'https://', text, flags=re.IGNORECASE)
    # Fix broken domain extensions like .top/ or .com/
    text = re.sub(r'([a-zA-Z0-9_-]+)\s+(top|com|vn|net|org|xyz|vip)\b', r'\1.\2', text, flags=re.IGNORECASE)
    # Fix numbers with spaces before dots: 800 .000 -> 800.000
    text = re.sub(r'(\d+)\s*\.\s*(\d+)', r'\1.\2', text)
    # Fix common Vietnamese OCR character confusion (dấu thanh)
    text = re.sub(r'(?i)\b[I|]àm\b', 'làm', text)
    text = re.sub(r'(?i)\bZàm\b', 'làm', text)
    text = re.sub(r'(?i)\bnình\b', 'mình', text)
    text = re.sub(r'(?i)\bsôluợng\b', 'số lượng', text)
    text = re.sub(r'(?i)\bsõ lượng\b', 'số lượng', text)
    text = re.sub(r'(?i)\bnhan tiền\b', 'nhận tiền', text)
    text = re.sub(r'(?i)\bđon hàng\b', 'đơn hàng', text)
    # Normalize multiple whitespace characters
    text = re.sub(r'[ \t]+', ' ', text)
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()


def extract_ocr_text(image_file) -> str:
    """
    Extract text từ ảnh. Engine chính: **VietOCR** (tiếng Việt), chạy trong venv riêng qua
    bridge (`backend/scripts/ocr_bridge.py`). Nếu VietOCR không khả dụng → Tesseract (vie+eng).

    Chọn engine qua setting `OCR_ENGINE` (env `OCR_ENGINE`): vietocr | tesseract (mặc định vietocr).
    """
    if hasattr(image_file, 'read'):
        image_data = image_file.read()
        try:
            image_file.seek(0)
        except Exception:
            pass
    else:
        image_data = image_file
    if not image_data:
        return ""

    engine = _ocr_engine_choice()
    if engine == 'vietocr':
        # VietOCR bridge tự nhị phân hoá + phân đoạn dòng; upscale/CLAHE dễ phá phân đoạn.
        processed_data = image_data
    else:
        try:
            processed_data = preprocess_image_for_ocr(image_data)
        except Exception:
            processed_data = image_data

    funcs = {
        'vietocr': _ocr_vietocr_bytes,
        'tesseract': _ocr_tesseract_bytes,
    }
    func = funcs.get(engine, _ocr_vietocr_bytes)
    text = func(processed_data) or ""
    if not text.strip() and func is not _ocr_tesseract_bytes:
        text = _ocr_tesseract_bytes(processed_data) or ""
    cleaned = clean_ocr_text(text)
    logger.info(f"OCR[{engine}] extracted {len(cleaned)} characters from image")
    return cleaned


# ─── Pluggable OCR engines ───────────────────────────────────────────
def _module_available(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except Exception:
        return False


def _backend_dir() -> str:
    # .../backend/api/utils/media_utils.py -> .../backend
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _ocr_bridge_python() -> str:
    """Trả về interpreter của venv OCR riêng (nếu có) để chạy engine ngoài .venv chính."""
    try:
        from django.conf import settings
        p = getattr(settings, 'OCR_BRIDGE_PY', None) or os.getenv('OCR_BRIDGE_PY', '')
    except Exception:
        p = os.getenv('OCR_BRIDGE_PY', '')
    if p and os.path.exists(p):
        return p
    cand = os.path.join(os.path.dirname(_backend_dir()), '.venv-ocr', 'bin', 'python')
    return cand if os.path.exists(cand) else ''


def _run_bridge(engine: str, image_bytes: bytes, boxes: bool = False) -> dict:
    """Chạy engine OCR trong venv riêng qua subprocess. Trả dict {text, regions, error}."""
    import subprocess
    import tempfile
    py = _ocr_bridge_python()
    script = os.path.join(_backend_dir(), 'scripts', 'ocr_bridge.py')
    if not py or not os.path.exists(script):
        return {}
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as fh:
            fh.write(image_bytes)
            tmp = fh.name
        cmd = [py, script, engine, tmp]
        if boxes:
            cmd.append('--boxes')
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        out = (res.stdout or '').strip()
        if not out:
            logger.warning(f"OCR bridge[{engine}] rỗng. stderr: {(res.stderr or '')[:200]}")
            return {}
        data = json.loads(out.splitlines()[-1])
        if data.get('error'):
            logger.warning(f"OCR bridge[{engine}] error: {data['error']}")
        return data
    except Exception as e:
        logger.error(f"OCR bridge[{engine}] failed: {e}")
        return {}
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except Exception:
                pass


def _ocr_service_url() -> str:
    try:
        from django.conf import settings
        u = getattr(settings, 'OCR_SERVICE_URL', '') or os.getenv('OCR_SERVICE_URL', '')
    except Exception:
        u = os.getenv('OCR_SERVICE_URL', '')
    return str(u or '').rstrip('/')


def _run_ocr_service(url: str, image_bytes: bytes, boxes: bool = False) -> dict:
    """Gọi OCR service thường trú qua HTTP (tránh nạp lại model mỗi ảnh)."""
    import urllib.request
    try:
        payload = json.dumps({
            "image_b64": base64.b64encode(image_bytes).decode('ascii'),
            "boxes": boxes,
        }).encode('utf-8')
        req = urllib.request.Request(url + '/ocr', data=payload,
                                     headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=180) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except Exception as e:
        logger.warning(f"OCR service không dùng được ({url}): {e}")
        return {}


def _run_engine(engine: str, image_bytes: bytes, boxes: bool = False) -> dict:
    """Ưu tiên OCR service (model thường trú); nếu không có → bridge subprocess."""
    url = _ocr_service_url()
    if url:
        data = _run_ocr_service(url, image_bytes, boxes)
        if data:
            return data
    return _run_bridge(engine, image_bytes, boxes)


def _ocr_text_boxes(image_bytes: bytes) -> list:
    """Bounding boxes + text bằng VietOCR (service hoặc bridge)."""
    return (_run_engine('vietocr', image_bytes, boxes=True) or {}).get('regions') or []


def _ocr_engine_choice() -> str:
    engine = 'vietocr'
    try:
        from django.conf import settings
        engine = str(getattr(settings, 'OCR_ENGINE', None) or os.getenv('OCR_ENGINE', '') or 'vietocr')
    except Exception:
        engine = str(os.getenv('OCR_ENGINE', '') or 'vietocr')
    engine = engine.strip().lower()
    if engine in ('', 'auto'):
        engine = 'vietocr'
    return engine


_VIETOCR_PREDICTOR = None


def _ocr_vietocr_bytes(image_bytes: bytes) -> str:
    """VietOCR — nhận dạng tiếng Việt (Transformer). Ưu tiên OCR service, fallback bridge."""
    return (_run_engine('vietocr', image_bytes) or {}).get('text', '')


def _ocr_tesseract_bytes(image_bytes: bytes) -> str:
    """Tesseract (vie+eng) — cần cài hệ thống + `pip install pytesseract`."""
    try:
        import pytesseract
    except Exception:
        return ""
    try:
        img = Image.open(io.BytesIO(image_bytes))
        return pytesseract.image_to_string(img, lang='vie+eng').strip()
    except Exception as e:
        logger.error(f"Tesseract error: {e}")
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

        # 2. Detect OCR Text (green/yellow/red boxes) — VietOCR (bridge)
        for region in _ocr_text_boxes(image_data):
            text = region.get("text", "")
            if not text:
                continue
            text_parts.append(text)
            regions.append({
                "bbox": region.get("bbox") or [],
                "text": text,
                "confidence": round(float(region.get("confidence", 0.0)), 3),
                "type": "text"
            })

        full_text = clean_ocr_text('\n'.join(text_parts).strip())
        if not full_text:
            try:
                fallback = extract_ocr_text(image_data)
                if fallback:
                    full_text = fallback
            except Exception as fe:
                logger.warning(f"Fallback OCR text extraction failed: {fe}")

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
            'details': 'Không phát hiện từ khóa rủi ro trong ảnh (kết luận cuối căn theo guardrail)'
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
        if device != 'cpu':
            try:
                import ctypes
                import nvidia.cublas.lib
                _cublas_dir = nvidia.cublas.lib.__path__[0]
                _lt = os.path.join(_cublas_dir, 'libcublasLt.so.12')
                _cub = os.path.join(_cublas_dir, 'libcublas.so.12')
                if os.path.exists(_lt):
                    ctypes.CDLL(_lt, mode=ctypes.RTLD_GLOBAL)
                if os.path.exists(_cub):
                    ctypes.CDLL(_cub, mode=ctypes.RTLD_GLOBAL)
            except Exception as _ce:
                logger.debug(f"Preloading cublas12 skipped: {_ce}")

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

        segments = []
        full_text_parts = []
        try:
            segments_iter, info = model.transcribe(file_for_model, **transcribe_kwargs)
            for seg in segments_iter:
                segments.append({
                    'start': round(seg.start, 2),
                    'end':   round(seg.end, 2),
                    'text':  seg.text.strip(),
                })
                full_text_parts.append(seg.text.strip())
        except Exception as te:
            err_msg = str(te).lower()
            if any(k in err_msg for k in ('cublas', 'cuda', 'cudnn', 'device', 'library')):
                logger.warning(f"Whisper GPU execution failed ({te}), falling back to CPU model...")
                from faster_whisper import WhisperModel
                from django.conf import settings
                cpu_model = WhisperModel(getattr(settings, 'WHISPER_MODEL_SIZE', 'small'), device='cpu', compute_type='int8')
                global _WHISPER_MODEL
                _WHISPER_MODEL = cpu_model
                segments_iter, info = cpu_model.transcribe(file_for_model, **transcribe_kwargs)
                segments = []
                full_text_parts = []
                for seg in segments_iter:
                    segments.append({
                        'start': round(seg.start, 2),
                        'end':   round(seg.end, 2),
                        'text':  seg.text.strip(),
                    })
                    full_text_parts.append(seg.text.strip())
            else:
                raise

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
