"""Tests cho server-side TTS (chế độ người cao tuổi)."""
import tempfile
from pathlib import Path

from django.core.cache import cache
from django.test import Client, TestCase, override_settings

from api.core import tts_service

# Cache cục bộ cho test — KHÔNG đụng Redis/hệ thống đang chạy.
_LOCMEM_CACHE = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'tts-tests',
    }
}


def _reset_budget():
    cache.delete('tts:synth:min')
    cache.delete('tts:synth:hour')


@override_settings(CACHES=_LOCMEM_CACHE, TTS_FORMAT='wav')
class TtsEndpointTest(TestCase):
    def setUp(self):
        _reset_budget()
        if not tts_service.is_available():
            self.skipTest('TTS chưa sẵn sàng (thiếu piper-tts/model) — bỏ qua.')
        self.client = Client(SERVER_NAME='localhost')

    def test_get_returns_wav(self):
        resp = self.client.get('/api/v1/tts/', {'text': 'Xin chào bác, đây là kiểm thử.'})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get('Content-Type'), 'audio/wav')
        self.assertTrue(resp.headers.get('ETag'))
        first = next(resp.streaming_content)
        self.assertEqual(first[:4], b'RIFF')  # header WAV

    def test_mp3_when_configured(self):
        import soundfile as sf
        if 'MP3' not in sf.available_formats():
            self.skipTest('libsndfile không hỗ trợ ghi MP3.')
        with override_settings(TTS_FORMAT='mp3'):
            resp = self.client.get('/api/v1/tts/', {'text': 'Câu kiểm thử định dạng MP3 nén sẵn.'})
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.headers.get('Content-Type'), 'audio/mpeg')
            first = next(resp.streaming_content)
            self.assertNotEqual(first[:4], b'RIFF')  # MP3, không phải WAV

    def test_missing_text_is_400(self):
        resp = self.client.get('/api/v1/tts/')
        self.assertEqual(resp.status_code, 400)

    def test_warm_builds_and_caches(self):
        payload = {'texts': ['Câu kiểm thử số một.', 'Câu kiểm thử số hai.']}
        resp = self.client.post('/api/v1/tts/warm/', data=payload, content_type='application/json')
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(body['ready'])
        self.assertEqual(body['errors'], 0)

        # Gọi lại → tất cả đã có trong cache (không build lại).
        resp2 = self.client.post('/api/v1/tts/warm/', data=payload, content_type='application/json')
        self.assertEqual(resp2.json()['built'], 0)

    def test_warm_rejects_non_list(self):
        resp = self.client.post('/api/v1/tts/warm/', data={'texts': 'khong-phai-mang'}, content_type='application/json')
        self.assertEqual(resp.status_code, 400)

    def test_normalize_text_strips_html(self):
        self.assertEqual(
            tts_service.normalize_text('<b>Chào</b>  bác   nhé'),
            'Chào bác nhé.',
        )


@override_settings(CACHES=_LOCMEM_CACHE)
class TtsAbuseGuardTest(TestCase):
    """Chống lạm dụng: hạn mức tổng hợp toàn cục + giới hạn cache."""

    def setUp(self):
        _reset_budget()

    def test_synth_budget_unit(self):
        with override_settings(TTS_MAX_SYNTH_PER_MIN=2, TTS_MAX_SYNTH_PER_HOUR=1000):
            self.assertTrue(tts_service.consume_synth_budget())
            self.assertTrue(tts_service.consume_synth_budget())
            self.assertFalse(tts_service.consume_synth_budget())

    def test_budget_exhausted_get_returns_503(self):
        if not tts_service.is_available():
            self.skipTest('TTS chưa sẵn sàng.')
        client = Client(SERVER_NAME='localhost')
        with tempfile.TemporaryDirectory() as tmp:
            with override_settings(TTS_CACHE_DIR=tmp, TTS_MAX_SYNTH_PER_MIN=1,
                                   TTS_MAX_SYNTH_PER_HOUR=1000):
                first = client.get('/api/v1/tts/', {'text': 'Câu độc nhất kiểm thử một về hạn mức.'})
                self.assertEqual(first.status_code, 200)
                # Câu khác (cache-miss) nhưng đã hết hạn mức sinh → 503 để fallback.
                second = client.get('/api/v1/tts/', {'text': 'Câu độc nhất kiểm thử hai về hạn mức.'})
                self.assertEqual(second.status_code, 503)

    def test_cache_limit_evicts_old_files(self):
        if not tts_service.is_available():
            self.skipTest('TTS chưa sẵn sàng.')
        with tempfile.TemporaryDirectory() as tmp:
            with override_settings(TTS_CACHE_DIR=tmp, TTS_CACHE_MAX_FILES=1,
                                   TTS_MAX_SYNTH_PER_MIN=1000):
                tts_service.ensure_audio('Câu kiểm thử eviction thứ nhất.')
                tts_service.ensure_audio('Câu kiểm thử eviction thứ hai.')
                files = [p for p in Path(tmp).iterdir() if p.is_file() and not p.name.endswith('.tmp')]
                self.assertEqual(len(files), 1)

    def test_single_flight_no_duplicate(self):
        """Hai 'request' cùng câu: cái sau phải là cache hit (không tổng hợp lại)."""
        if not tts_service.is_available():
            self.skipTest('TTS chưa sẵn sàng.')
        with tempfile.TemporaryDirectory() as tmp:
            with override_settings(TTS_CACHE_DIR=tmp, TTS_MAX_SYNTH_PER_MIN=1000):
                _p1, _k1, gen1 = tts_service.ensure_audio('Câu kiểm thử single-flight.')
                _p2, _k2, gen2 = tts_service.ensure_audio('Câu kiểm thử single-flight.')
                self.assertTrue(gen1)
                self.assertFalse(gen2)
