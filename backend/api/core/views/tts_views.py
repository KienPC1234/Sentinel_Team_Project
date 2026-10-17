"""API TTS cho chế độ người cao tuổi.

- ``GET  /api/v1/tts/?text=...`` → trả audio (MP3 mặc định, sinh + cache nếu chưa có).
- ``POST /api/v1/tts/warm/ {texts:[...]}`` → build trước hàng loạt (frontend gọi
  khi mở trang để "tự động build ở backend", lần bấm "Đọc to" sau đó là tức thì).

Nếu TTS chưa sẵn sàng (thiếu model/thư viện/tắt) → trả 503 để frontend fallback
sang giọng trình duyệt.
"""
from __future__ import annotations

import logging
import os

from django.http import FileResponse, HttpResponseNotModified
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from api.core import tts_service
from api.core.throttling import TtsThrottle, TtsWarmThrottle

logger = logging.getLogger(__name__)

_WARM_MAX_ITEMS = 120
_WARM_MAX_CHARS = 24000  # tổng ký tự tối đa mỗi lần warm


class TtsView(APIView):
    """Trả về audio (MP3/WAV/OGG) cho một đoạn văn bản tiếng Việt."""

    permission_classes = [AllowAny]
    # Endpoint công khai, không cần định danh. Bỏ authentication để KHÔNG dính
    # CSRF của SessionAuthentication (nếu người dùng đã đăng nhập, POST warm sẽ
    # bị 403 CSRF nếu dùng session auth).
    authentication_classes: list = []
    throttle_classes = [TtsThrottle]

    def get(self, request):
        if not tts_service.enabled():
            return Response(
                {'error': 'TTS chưa được bật trên máy chủ.', 'code': 'tts_disabled'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        text = (request.query_params.get('text') or '').strip()
        if not text:
            return Response({'error': 'Thiếu tham số "text".'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            path, key, _generated = tts_service.ensure_audio(text)
        except tts_service.TtsUnavailable as exc:
            logger.warning('TTS unavailable: %s', exc)
            return Response(
                {'error': 'Máy chủ chưa sẵn sàng đọc tiếng Việt.', 'code': 'tts_unavailable'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        try:
            size = os.path.getsize(path)
        except OSError:
            size = None

        etag = f'"{key}"'
        cache_control = 'private, no-cache'  # lưu được nhưng PHẢI hỏi lại (ETag) → đổi giọng là nhận ngay

        # Conditional GET: trình duyệt còn bản cũ thì trả 304, khỏi tải lại.
        if request.headers.get('If-None-Match', '').find(etag) != -1:
            not_modified = HttpResponseNotModified()
            not_modified['ETag'] = etag
            not_modified['Cache-Control'] = cache_control
            return not_modified

        resp = FileResponse(open(path, 'rb'), content_type=tts_service.content_type())
        resp['Cache-Control'] = cache_control
        resp['ETag'] = etag
        if size is not None:
            resp['Content-Length'] = str(size)
        return resp


class TtsWarmView(APIView):
    """Build trước (cache) audio cho một danh sách văn bản."""

    permission_classes = [AllowAny]
    authentication_classes: list = []  # tránh CSRF 403 với người dùng đã đăng nhập
    throttle_classes = [TtsWarmThrottle]

    def post(self, request):
        if not tts_service.enabled():
            return Response(
                {'ready': False, 'code': 'tts_disabled'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        texts = request.data.get('texts')
        if not isinstance(texts, list):
            return Response({'error': 'Cần "texts" là một mảng chuỗi.'}, status=status.HTTP_400_BAD_REQUEST)

        built = 0
        cached = 0
        errors = 0
        processed = 0
        total_chars = 0
        for item in texts[:_WARM_MAX_ITEMS]:
            raw = str(item or '').strip()
            if not raw:
                continue
            if total_chars + len(raw) > _WARM_MAX_CHARS:
                break
            total_chars += len(raw)
            processed += 1
            try:
                _path, _key, generated = tts_service.ensure_audio(raw)
                if generated:
                    built += 1
                else:
                    cached += 1
            except tts_service.TtsUnavailable:
                errors += 1
            except Exception:  # pragma: no cover - phòng lỗi bất ngờ
                logger.exception('Lỗi build TTS cho một đoạn văn bản')
                errors += 1

        return Response({
            'ready': errors == 0,
            'built': built,
            'cached': cached,
            'errors': errors,
            'total': processed,
        })
