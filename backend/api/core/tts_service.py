"""Text-to-Speech tiếng Việt chạy ở server (Piper ONNX) — phục vụ chế độ người cao tuổi.

Lý do tồn tại: giọng đọc của trình duyệt (Web Speech API) không đáng tin —
không phải máy nào cũng cài giọng tiếng Việt, chất lượng thay đổi theo thiết bị,
có khi đọc sai dấu. Thay vào đó, server sinh audio bằng model Piper
``vi_VN-vais1000-medium`` (ONNX, 22.05kHz) và CACHE theo nội dung, để lần sau
phát tức thì.

Tối ưu:
- Đầu ra nén sẵn: MP3 mặc định (nhỏ ~6× so với WAV, tương thích mọi trình duyệt).
- Single-flight: nhiều request cùng một câu chỉ tổng hợp MỘT lần.
- Cache file theo ``sha1(voice + format + text)``, dọn LRU theo dung lượng/số file.
- Có thể nạp sẵn giọng lúc khởi động (``preload()``) để giảm trễ lần đọc đầu.
- Thiếu model/thư viện → ném ``TtsUnavailable`` để view trả 503; frontend tự
  fallback sang giọng trình duyệt (không chặn người dùng).

Module này CHỈ được import trong tiến trình Django; phần nạp ``piper`` nằm trong
hàm để môi trường không có ``piper-tts`` vẫn import được Django bình thường.
"""
from __future__ import annotations

import hashlib
import html
import io
import logging
import os
import re
import threading
import time
from pathlib import Path

from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
# Ký tự điều khiển (trừ \t \n \r) — loại để không phá câu/không sinh audio rác.
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class TtsUnavailable(RuntimeError):
    """Không thể tổng hợp audio (thiếu model / thư viện / bị tắt bằng cấu hình)."""


# ── Trạng thái voz dùng chung ────────────────────────────────────────────────
_voice = None
_engine_loaded: str | None = None
_voice_lock = threading.Lock()          # bảo vệ khi nạp / dùng engine
_synth_lock = threading.Lock()          # engine không thread-safe → tuần tự hoá synth

# Lưu ý: backend/PKV/settings.py KHÔNG được commit (file môi trường), nên mọi
# mặc định phải nằm ngay trong module này để chạy được trên máy mới. Có thể
# override qua settings HOẶC biến môi trường (TTS_*).
_TRUTHY = {'true', '1', 'yes', 'on'}


def _cfg(name: str, default: str) -> str:
    """Ưu tiên settings.<name>, rồi env <name>, cuối cùng là mặc định."""
    val = getattr(settings, name, None)
    if val is None:
        val = os.getenv(name)
    if val is None or val == '':
        return default
    return str(val)


def voice_id() -> str:
    return _cfg('TTS_VOICE_ID', 'vi_VN-vais1000-medium')


# ── Định dạng đầu ra (nén sẵn để nhẹ băng thông/ổ đĩa) ───────────────────────
_VALID_FORMATS = ('wav', 'mp3', 'ogg')
_CONTENT_TYPES = {'wav': 'audio/wav', 'mp3': 'audio/mpeg', 'ogg': 'audio/ogg'}


def output_format() -> str:
    """Định dạng audio: ``TTS_FORMAT=auto|wav|mp3|ogg`` (auto ưu tiên MP3)."""
    fmt = _cfg('TTS_FORMAT', 'auto').lower()
    if fmt in _VALID_FORMATS:
        return fmt
    try:
        import soundfile as sf
        available = sf.available_formats()
        if 'MP3' in available:
            return 'mp3'
        if 'OGG' in available:
            return 'ogg'
    except Exception:
        pass
    return 'wav'


def content_type() -> str:
    return _CONTENT_TYPES.get(output_format(), 'audio/wav')


def file_ext() -> str:
    return output_format()


def _model_path() -> Path:
    default = str(Path(settings.BASE_DIR) / 'models' / 'piper' / f'{voice_id()}.onnx')
    return Path(_cfg('TTS_VOICE_MODEL', default))


def cache_dir() -> Path:
    default = str(Path(settings.MEDIA_ROOT) / 'tts')
    d = Path(_cfg('TTS_CACHE_DIR', default))
    d.mkdir(parents=True, exist_ok=True)
    return d


def max_chars() -> int:
    try:
        return int(_cfg('TTS_MAX_CHARS', '1200'))
    except (TypeError, ValueError):
        return 1200


def use_cuda() -> bool:
    return _cfg('TTS_USE_CUDA', 'false').lower() in _TRUTHY


def enabled() -> bool:
    return _cfg('TTS_ENABLED', 'true').lower() in _TRUTHY


# ── Chọn engine: VieNeu-TTS (giọng tự nhiên, 48kHz) hoặc Piper ──────────────
_engine_cache: str | None = None
_vieneu_voice_resolved: str = ""


def engine() -> str:
    """``TTS_ENGINE=auto|vieneu|piper`` — auto ưu tiên VieNeu nếu cài được."""
    global _engine_cache
    if _engine_cache is not None:
        return _engine_cache
    want = _cfg('TTS_ENGINE', 'auto').lower()
    if want in ('vieneu', 'piper'):
        _engine_cache = want
        return _engine_cache
    try:
        import vieneu  # noqa: F401
        _engine_cache = 'vieneu'
    except Exception:
        _engine_cache = 'piper'
    return _engine_cache


def vieneu_voice() -> str:
    """Tên giọng dựng sẵn của VieNeu (xem ``vieneu.list_preset_voices()``)."""
    return _cfg('TTS_VIENEU_VOICE', 'Ngọc Huyền')


def _int_cfg(name: str, default: int) -> int:
    try:
        return int(_cfg(name, str(default)))
    except (TypeError, ValueError):
        return default


def cache_max_bytes() -> int:
    """Giới hạn dung lượng cache audio (MB) — chống làm đầy ổ đĩa."""
    return max(0, _int_cfg('TTS_CACHE_MAX_MB', 300)) * 1024 * 1024


def cache_max_files() -> int:
    return max(0, _int_cfg('TTS_CACHE_MAX_FILES', 20000))


# ── Hạn mức SINH toàn cục (chống lạm dụng, kể cả botnet nhiều IP) ───────────
def _bump_within(key: str, limit: int, window: int) -> bool:
    """Đếm 1 lượt vào cửa sổ ``window`` giây; trả True nếu còn trong hạn mức.

    Cache gặp sự cố → cho qua (fail-open) để không chặn nhầm người dùng thật.
    """
    if limit <= 0:
        return True
    try:
        if cache.add(key, 1, window):
            return 1 <= limit
        try:
            cur = cache.incr(key)
        except ValueError:
            cache.set(key, 1, window)
            return 1 <= limit
        return cur <= limit
    except Exception:  # pragma: no cover - cache backend lỗi
        return True


def consume_synth_budget() -> bool:
    """Cấp phép cho MỘT lượt tổng hợp mới (cache-miss) trên toàn máy chủ."""
    per_min = _int_cfg('TTS_MAX_SYNTH_PER_MIN', 120)
    per_hour = _int_cfg('TTS_MAX_SYNTH_PER_HOUR', 2000)
    if not _bump_within('tts:synth:min', per_min, 60):
        return False
    if not _bump_within('tts:synth:hour', per_hour, 3600):
        return False
    return True


# ── Chuẩn hoá văn bản ────────────────────────────────────────────────────────
def normalize_text(text: str) -> str:
    """Bỏ thẻ HTML, giải mã thực thể, gộp khoảng trắng; đảm bảo có dấu câu cuối."""
    t = str(text or "")
    t = _TAG_RE.sub(" ", t)
    t = html.unescape(t)
    t = t.replace("\u00a0", " ")
    t = _CTRL_RE.sub(" ", t)
    t = _WS_RE.sub(" ", t).strip()
    if t and t[-1] not in ".!?…:;,":
        t += "."
    return t


def cache_key(text: str) -> str:
    eng = engine()
    voice = vieneu_voice() if eng == 'vieneu' else voice_id()
    body = f"{eng}\n{voice}\n{output_format()}\n{text}".encode("utf-8")
    return hashlib.sha1(body).hexdigest()[:32]


def cache_path(key: str) -> Path:
    return cache_dir() / f"{key}.{file_ext()}"


def is_available() -> bool:
    """Model + thư viện đã sẵn sàng chưa (không nạp model)."""
    if not enabled():
        return False
    try:
        import soundfile  # noqa: F401
    except Exception:  # pragma: no cover - phụ thuộc môi trường
        return False
    eng = engine()
    if eng == 'vieneu':
        try:
            import vieneu  # noqa: F401
            return True
        except Exception:
            pass  # rơi xuống kiểm tra Piper
    try:
        import piper  # noqa: F401
    except Exception:
        return False
    return _model_path().is_file()


# ── Nạp / tổng hợp ───────────────────────────────────────────────────────────
def _force_hf_no_symlinks() -> None:
    """Bắt ``huggingface_hub`` tải mỗi tệp thành BẢN SAO thật trong thư mục snapshot.

    Mặc định hub tạo symlink snapshot → blob, nên ``vieneu_prefill.onnx`` và
    ``vieneu_backbone_shared.data`` trỏ về hai thư mục blob khác nhau. ONNX Runtime
    từ chối external-data nằm ngoài thư mục model:
        "External data path escapes model directory".
    Đặt biến môi trường KHÔNG đủ nếu ``huggingface_hub`` đã được import (nó đọc env
    lúc import), nên phải ghi thẳng vào hằng số đã nạp.
    """
    os.environ.setdefault("HF_HUB_DISABLE_SYMLINKS", "1")
    os.environ.setdefault("HF_HUB_DISABLE_SYMLINKS_WARNING", "1")
    try:
        import huggingface_hub.constants as hf_constants
        hf_constants.HF_HUB_DISABLE_SYMLINKS = True
    except Exception:  # pragma: no cover - không cài huggingface_hub
        pass


# Áp dụng càng sớm càng tốt, trước mọi lần tải model từ HuggingFace.
_force_hf_no_symlinks()


def _preload_cuda_libs() -> None:
    """Nạp trước cuDNN/cuBLAS của các wheel ``nvidia-*`` (torch kéo về) để
    CUDAExecutionProvider của onnxruntime tìm thấy.

    Vì sao cần: glibc KHÔNG đọc lại ``LD_LIBRARY_PATH`` sau khi tiến trình đã
    khởi động, nên không thể set env trong code. Nạp bằng ``ctypes`` với
    ``RTLD_GLOBAL`` đăng ký sẵn soname → ``dlopen`` của onnxruntime khớp được.
    """
    import ctypes
    import glob
    import sys

    dirs: list[str] = []
    for base in sys.path:
        for sub in ('cudnn', 'cublas', 'cuda_runtime', 'cufft', 'curand'):
            d = os.path.join(base, 'nvidia', sub, 'lib')
            if os.path.isdir(d):
                dirs.append(d)
    for d in dirs:
        for f in sorted(glob.glob(os.path.join(d, '*.so*'))):
            try:
                ctypes.CDLL(f, mode=ctypes.RTLD_GLOBAL)
            except OSError:
                pass


def _load_piper():
    """Nạp PiperVoice (GPU nếu bật; tự fallback CPU)."""
    model = _model_path()
    if not model.is_file():
        raise TtsUnavailable(f"Thiếu model TTS (Piper): {model}")
    from piper import PiperVoice

    wants_cuda = use_cuda()
    if wants_cuda:
        _preload_cuda_libs()
        try:
            import onnxruntime as ort
            try:
                ort.preload_dlls()  # no-op nếu không có wheel nvidia-* phù hợp
            except Exception:
                pass
        except Exception:
            pass

    attempts = [True, False] if wants_cuda else [False]
    last_exc: Exception | None = None
    for cuda in attempts:
        t0 = time.time()
        try:
            voice = PiperVoice.load(str(model), use_cuda=cuda)
            for _ in voice.synthesize("Kiểm tra."):
                break
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            logger.warning(
                "Piper %s lỗi (%s)%s", "GPU" if cuda else "CPU", exc,
                " — thử CPU." if cuda else "",
            )
            continue
        try:
            providers = list(voice.session.get_providers())
        except Exception:
            providers = ["?"]
        logger.info(
            "Piper '%s' trên %s trong %.2fs (providers=%s)",
            voice_id(), "GPU" if cuda else "CPU", time.time() - t0, providers,
        )
        return "piper", voice

    raise TtsUnavailable(f"Không nạp được Piper: {last_exc}")


def _load_vieneu():
    """Nạp VieNeu-TTS (48kHz) + xác thực giọng cấu hình.

    Việc nạp có thể ĐUA với luồng khởi động Django đang import ``transformers``
    (preload chạy nền) → module import dở → ``cannot import name ...``. Vì vậy
    thử lại vài lần cho qua giai đoạn khởi động.
    """
    global _vieneu_voice_resolved
    _force_hf_no_symlinks()

    t0 = time.time()
    model = None
    last_exc: Exception | None = None
    for attempt in range(4):
        try:
            from vieneu import Vieneu
            model = Vieneu()
            break
        except ImportError as exc:
            # Lỗi import do ĐUA với luồng khởi động Django đang import transformers
            # (module import dở) → thử lại. Các lỗi khác (thiếu/không nạp được model,
            # ONNX Runtime...) là lỗi thật, thử lại chỉ tốn thời gian vô ích.
            last_exc = exc
            logger.info("Nạp VieNeu lỗi import (thử %d/4): %s", attempt + 1, exc)
            time.sleep(3)
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            logger.info("Nạp VieNeu lỗi: %s", exc)
            break
    if model is None:
        raise TtsUnavailable(f"VieNeu không nạp được: {last_exc}")

    voice = vieneu_voice()
    try:
        model.infer("Kiểm tra.", voice=voice)
        _vieneu_voice_resolved = voice
    except Exception as exc:  # noqa: BLE001
        logger.warning("Giọng VieNeu '%s' lỗi (%s) — dùng giọng mặc định.", voice, exc)
        _vieneu_voice_resolved = ""
    logger.info(
        "VieNeu-TTS sẵn sàng trong %.2fs (giọng=%s)",
        time.time() - t0, _vieneu_voice_resolved or "(mặc định)",
    )
    return "vieneu", model


def _load_voice():
    """Nạp engine TTS một lần (double-checked locking), có fallback engine."""
    global _voice, _engine_loaded
    if _voice is not None:
        return _voice
    with _voice_lock:
        if _voice is not None:
            return _voice
        if not enabled():
            raise TtsUnavailable("TTS đang tắt (TTS_ENABLED=False).")

        primary = engine()
        order = [primary]
        for alt in ('vieneu', 'piper'):
            if alt not in order:
                order.append(alt)

        last_exc: Exception | None = None
        for name in order:
            try:
                eng, obj = _load_vieneu() if name == 'vieneu' else _load_piper()
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                logger.warning("Engine TTS '%s' không dùng được: %s", name, exc)
                continue
            _voice = obj
            _engine_loaded = eng
            return _voice

        raise TtsUnavailable(f"Không nạp được engine TTS nào: {last_exc}")


def preload() -> None:
    """Nạp sẵn giọng (best-effort) để giảm độ trễ lần đọc đầu tiên.

    Hoãn một chút để Django import xong ``transformers`` trước, tránh đua import
    (xem ``_load_vieneu``).
    """
    try:
        if not (enabled() and is_available()):
            return
        try:
            time.sleep(max(0.0, float(_cfg('TTS_PRELOAD_DELAY', '6'))))
        except (TypeError, ValueError):
            time.sleep(6)
        _load_voice()
    except Exception as exc:  # noqa: BLE001
        logger.info("TTS preload bỏ qua: %s", exc)


def _synthesize_pcm(text: str):
    """Tổng hợp ``text`` (đã chuẩn hoá) thành PCM int16 + sample_rate.

    KHÔNG tự lấy khoá — caller (``ensure_audio``) đã giữ ``_synth_lock``.
    """
    import numpy as np

    _load_voice()
    eng = _engine_loaded or engine()

    if eng == 'vieneu':
        kwargs = {'voice': _vieneu_voice_resolved} if _vieneu_voice_resolved else {}
        audio = _voice.infer(text, **kwargs)
        wav = np.asarray(audio, dtype=np.float32)
        sr = int(getattr(_voice, 'sample_rate', 48000) or 48000)
        return (np.clip(wav, -1.0, 1.0) * 32767.0).astype(np.int16), sr

    chunks = []
    for chunk in _voice.synthesize(text):
        data = getattr(chunk, "audio_int16_bytes", None)
        if data:
            chunks.append(np.frombuffer(data, dtype=np.int16))
    if not chunks:
        raise TtsUnavailable("TTS không sinh được mẫu âm thanh.")
    sample_rate = int(getattr(_voice.config, "sample_rate", 22050))
    return np.concatenate(chunks), sample_rate


def _encode_audio(pcm, sample_rate: int) -> bytes:
    """Mã hoá PCM → bytes theo định dạng cấu hình (MP3 nhỏ ~6× so với WAV)."""
    import soundfile as sf

    fmt = output_format()
    buf = io.BytesIO()
    if fmt == 'mp3':
        sf.write(buf, pcm, sample_rate, format='MP3')
    elif fmt == 'ogg':
        sf.write(buf, pcm, sample_rate, format='OGG', subtype='VORBIS')
    else:
        sf.write(buf, pcm, sample_rate, format='WAV', subtype='PCM_16')
    return buf.getvalue()


def _enforce_cache_limit(adding_bytes: int) -> None:
    """Dọn cache cũ (LRU ~ mtime) để không vượt dung lượng/số file tối đa."""
    limit = cache_max_bytes()
    max_files = cache_max_files()
    if limit <= 0 and max_files <= 0:
        return
    try:
        entries: list[tuple[float, int, Path]] = []
        for f in cache_dir().iterdir():
            if not f.is_file() or f.name.endswith('.tmp'):
                continue
            try:
                st = f.stat()
            except OSError:
                continue
            entries.append((st.st_mtime, st.st_size, f))
    except OSError:
        return

    total = sum(size for _, size, _ in entries)
    count = len(entries)
    entries.sort(key=lambda e: e[0])  # cũ nhất trước
    for _, size, f in entries:
        over_size = limit > 0 and total + adding_bytes > limit
        over_files = max_files > 0 and count + 1 > max_files
        if not over_size and not over_files:
            break
        try:
            f.unlink()
            total -= size
            count -= 1
        except OSError:
            pass


def ensure_audio(raw_text: str) -> tuple[Path, str, bool]:
    """Đảm bảo có file audio cho ``raw_text`` (định dạng theo cấu hình).

    Trả về ``(path, key, generated)``; ``generated=True`` nếu vừa tổng hợp mới.
    Single-flight: nhiều request đồng thời cho CÙNG một câu chỉ tổng hợp một lần
    (kiểm tra lại bên trong khoá). Chỉ tổng hợp khi còn hạn mức toàn cục;
    cache-miss vượt hạn mức → ném ``TtsUnavailable`` để frontend fallback.
    """
    text = normalize_text(raw_text)
    if not text:
        raise TtsUnavailable("Văn bản trống.")
    limit = max_chars()
    if len(text) > limit:
        text = text[:limit].rstrip()
        if text and text[-1] not in ".!?…":
            text += "…"

    key = cache_key(text)
    path = cache_path(key)

    def _hit() -> bool:
        try:
            return path.is_file() and path.stat().st_size > 0
        except OSError:
            return False

    if _hit():
        try:
            os.utime(path, None)  # đánh dấu vừa dùng (xấp xỉ LRU)
        except OSError:
            pass
        return path, key, False

    with _synth_lock:
        # Already có ai đó vừa tổng hợp xong trong lúc ta chờ khoá → dùng luôn.
        if _hit():
            try:
                os.utime(path, None)
            except OSError:
                pass
            return path, key, False

        if not consume_synth_budget():
            raise TtsUnavailable("TTS đang quá tải (hết hạn mức tổng hợp). Vui lòng thử lại sau.")

        try:
            pcm, sample_rate = _synthesize_pcm(text)
            data = _encode_audio(pcm, sample_rate)
        except TtsUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.exception("TTS tổng hợp lỗi")
            raise TtsUnavailable(f"TTS lỗi tổng hợp: {exc}") from exc
        _enforce_cache_limit(len(data))
        tmp = path.with_name(path.name + '.tmp')
        tmp.write_bytes(data)
        os.replace(tmp, path)  # ghi nguyên tử

    return path, key, True
