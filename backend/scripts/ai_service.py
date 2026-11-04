#!/usr/bin/env python3
"""ShieldCall VN — Unified local AI service.

Một tiến trình duy nhất giữ các model local để **chia sẻ một CUDA context**
(thay vì mỗi model nằm trong một process/venv riêng):

  - OCR (VietOCR)               -> POST /ocr
  - Embedding RAG (nomic)       -> POST /embed      (mặc định CPU để tiết kiệm VRAM)
  - Speech-to-text (Whisper)    -> POST /transcribe (lazy-load, tự unload khi rảnh)

Chạy (venv chính đã có torch + sentence-transformers + faster-whisper + vietocr):
  .venv/bin/python backend/scripts/ai_service.py
  # hoặc qua PM2: pm2 start ecosystem.config.js --only pkv-ai

Biến môi trường:
  AI_SERVICE_PORT / OCR_SERVICE_PORT   cổng HTTP (mặc định 5010)
  VIETOCR_DEVICE                       auto | cpu | cuda:0
  AI_EMBED_DEVICE                      cpu (mặc định) | cuda | auto
  AI_EMBED_PRELOAD                     true (mặc định) | false
  AI_EMBED_MODEL                       mặc định nomic-ai/nomic-embed-text-v1
  WHISPER_MODEL_SIZE                   mặc định small
  WHISPER_DEVICE                       cuda (mặc định) | cpu
  AI_WHISPER_IDLE_UNLOAD_SEC           mặc định 900 (0 = không unload)

Thiết kế an toàn: mỗi model có lock riêng; VietOCR vốn không thread-safe nên
request OCR được xếp hàng. Whisper được unload sau khi rảnh để trả VRAM.
"""
from __future__ import annotations

import base64
import gc
import json
import os
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# OCR dùng lại toàn bộ logic + cache của ocr_service (import không chạy server).
import ocr_service as ocr_svc  # noqa: E402

PORT = int(os.getenv("AI_SERVICE_PORT") or os.getenv("OCR_SERVICE_PORT") or "5010")
MAX_BODY = int(os.getenv("AI_MAX_BODY_MB", "200")) * 1024 * 1024

EMBED_MODEL = os.getenv("AI_EMBED_MODEL", "nomic-ai/nomic-embed-text-v1")
EMBED_DEVICE = (os.getenv("AI_EMBED_DEVICE", "cpu") or "cpu").strip().lower()
EMBED_PRELOAD = os.getenv("AI_EMBED_PRELOAD", "true").strip().lower() in ("1", "true", "yes", "on")
EMBED_BATCH = int(os.getenv("AI_EMBED_BATCH", "32"))

WHISPER_MODEL_SIZE = os.getenv("WHISPER_MODEL_SIZE", "small")
WHISPER_DEVICE = (os.getenv("WHISPER_DEVICE", "cuda") or "cuda").strip().lower()
WHISPER_IDLE_UNLOAD_SEC = int(os.getenv("AI_WHISPER_IDLE_UNLOAD_SEC", "900") or "0")
WHISPER_COMPUTE = (os.getenv("AI_WHISPER_COMPUTE", "") or "").strip().lower()
WHISPER_LANGUAGE = (os.getenv("AI_WHISPER_LANGUAGE", "auto") or "auto").strip()
WHISPER_INITIAL_PROMPT = os.getenv(
    "AI_WHISPER_INITIAL_PROMPT", "Đây là cuộc hội thoại tiếng Việt."
).strip()
WHISPER_CPU_MODEL_SIZE = os.getenv("AI_WHISPER_CPU_MODEL_SIZE", "small")
WHISPER_PRELOAD = os.getenv("AI_WHISPER_PRELOAD", "false").strip().lower() in ("1", "true", "yes", "on")

_EMBED = None
_EMBED_LOCK = threading.RLock()
_WHISPER = None
_WHISPER_LOCK = threading.RLock()
_WHISPER_LAST_USE = 0.0
_WHISPER_DEVICE_USED = ""
_WHISPER_COMPUTE_USED = ""
_WHISPER_MODEL_USED = ""


# ────────────────────────────────────────────────────────────── embedding
def _torch_cuda_available() -> bool:
    try:
        import torch
        return bool(torch.cuda.is_available())
    except Exception:
        return False


def _embed_device() -> str:
    if EMBED_DEVICE in ("", "auto"):
        return "cuda" if _torch_cuda_available() else "cpu"
    return EMBED_DEVICE


def _get_embedder():
    global _EMBED
    if _EMBED is not None:
        return _EMBED
    with _EMBED_LOCK:
        if _EMBED is not None:
            return _EMBED
        from sentence_transformers import SentenceTransformer
        device = _embed_device()
        print(f"[sentinel-ai] loading embedding '{EMBED_MODEL}' on {device} ...", flush=True)
        t0 = time.time()
        _EMBED = SentenceTransformer(EMBED_MODEL, device=device, trust_remote_code=True)
        print(f"[sentinel-ai] embedding ready on {device} in {time.time() - t0:.1f}s", flush=True)
        return _EMBED


def _embed(texts):
    model = _get_embedder()
    with _EMBED_LOCK:
        vecs = model.encode(
            texts,
            convert_to_numpy=True,
            normalize_embeddings=True,
            batch_size=EMBED_BATCH,
            show_progress_bar=False,
        )
    return vecs.astype("float32").tolist()


# ─────────────────────────────────────────────────────────────── whisper
def _get_whisper():
    global _WHISPER, _WHISPER_DEVICE_USED, _WHISPER_COMPUTE_USED, _WHISPER_MODEL_USED
    if _WHISPER is not None:
        return _WHISPER
    with _WHISPER_LOCK:
        if _WHISPER is not None:
            return _WHISPER
        from faster_whisper import WhisperModel
        device = WHISPER_DEVICE
        if device == "auto":
            device = "cuda" if _torch_cuda_available() else "cpu"
        size = WHISPER_CPU_MODEL_SIZE if device == "cpu" else WHISPER_MODEL_SIZE
        compute = WHISPER_COMPUTE or ("int8" if device == "cpu" else "float16")
        print(f"[sentinel-ai] loading whisper '{size}' on {device}/{compute} ...", flush=True)
        t0 = time.time()
        try:
            _WHISPER = WhisperModel(size, device=device, compute_type=compute)
        except Exception as exc:
            if device == "cpu":
                raise
            print(f"[sentinel-ai] whisper GPU lỗi ({exc}); fallback CPU '{WHISPER_CPU_MODEL_SIZE}'", flush=True)
            device, size, compute = "cpu", WHISPER_CPU_MODEL_SIZE, "int8"
            _WHISPER = WhisperModel(size, device="cpu", compute_type="int8")
        _WHISPER_DEVICE_USED = device
        _WHISPER_COMPUTE_USED = compute
        _WHISPER_MODEL_USED = size
        print(f"[sentinel-ai] whisper ready on {device}/{compute} in {time.time() - t0:.1f}s", flush=True)
        return _WHISPER


def _unload_whisper() -> bool:
    global _WHISPER
    with _WHISPER_LOCK:
        if _WHISPER is None:
            return False
        _WHISPER = None
        gc.collect()
        try:
            import torch
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
        except Exception:
            pass
        return True


def _whisper_idle_watcher():
    if WHISPER_IDLE_UNLOAD_SEC <= 0:
        return
    while True:
        time.sleep(min(60, max(5, WHISPER_IDLE_UNLOAD_SEC // 4)))
        try:
            with _WHISPER_LOCK:
                if _WHISPER is not None and (time.time() - _WHISPER_LAST_USE) >= WHISPER_IDLE_UNLOAD_SEC:
                    if _unload_whisper():
                        print("[sentinel-ai] whisper unloaded (idle)", flush=True)
        except Exception:
            pass


def _transcribe(path: str, language: str | None, beam_size: int):
    global _WHISPER_LAST_USE
    lang = (language or WHISPER_LANGUAGE or "").strip()
    if lang.lower() in ("auto", "none"):
        lang = ""
    kwargs = {"beam_size": max(1, min(int(beam_size or 5), 10)), "vad_filter": True}
    if lang:
        kwargs["language"] = lang
    if WHISPER_INITIAL_PROMPT:
        kwargs["initial_prompt"] = WHISPER_INITIAL_PROMPT
    with _WHISPER_LOCK:
        model = _get_whisper()
        _WHISPER_LAST_USE = time.time()
        segments_iter, info = model.transcribe(path, **kwargs)
        segments = []
        parts = []
        for seg in segments_iter:
            text = (seg.text or "").strip()
            segments.append({"start": round(seg.start, 2), "end": round(seg.end, 2), "text": text})
            if text:
                parts.append(text)
        _WHISPER_LAST_USE = time.time()
    return {
        "transcript": " ".join(parts),
        "language": getattr(info, "language", lang or ""),
        "duration": round(float(getattr(info, "duration", 0.0) or 0.0), 2),
        "segments": segments,
    }


# ──────────────────────────────────────────────────────────────── HTTP
def _health() -> dict:
    try:
        _pred, ocr_dev = ocr_svc.bridge._get_predictor()
    except Exception as exc:
        ocr_dev = f"error:{type(exc).__name__}: {exc}"
    return {
        "status": "healthy",
        "service": "sentinel-ai",
        "port": PORT,
        "ocr": {"device": ocr_dev, "cached": len(ocr_svc._CACHE)},
        "embed": {
            "loaded": _EMBED is not None,
            "device": _embed_device(),
            "model": EMBED_MODEL,
        },
        "whisper": {
            "loaded": _WHISPER is not None,
            "device": _WHISPER_DEVICE_USED or WHISPER_DEVICE,
            "compute_type": _WHISPER_COMPUTE_USED,
            "model": _WHISPER_MODEL_USED or WHISPER_MODEL_SIZE,
            "language": WHISPER_LANGUAGE,
            "preload": WHISPER_PRELOAD,
            "idle_unload_sec": WHISPER_IDLE_UNLOAD_SEC,
        },
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code: int, obj: dict):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > MAX_BODY:
            raise ValueError(f"body quá lớn ({length} > {MAX_BODY})")
        return self.rfile.read(length) if length else b""

    def do_GET(self):
        if self.path.startswith("/health"):
            self._send(200, _health())
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        try:
            if path == "/ocr":
                self._handle_ocr()
            elif path == "/embed":
                self._handle_embed()
            elif path == "/transcribe":
                self._handle_transcribe()
            elif path == "/unload":
                self._handle_unload()
            else:
                self._send(404, {"error": "not found"})
        except Exception as exc:
            self._send(500, {"error": f"{type(exc).__name__}: {exc}"})

    # -- OCR ---------------------------------------------------------
    def _handle_ocr(self):
        payload = json.loads(self._read_body() or b"{}")
        data = base64.b64decode(payload.get("image_b64", ""))
        if not data:
            self._send(400, {"error": "image_b64 rỗng"})
            return
        self._send(200, ocr_svc._ocr_bytes(data, bool(payload.get("boxes"))))

    # -- Embedding ---------------------------------------------------
    def _handle_embed(self):
        payload = json.loads(self._read_body() or b"{}")
        texts = payload.get("texts") or []
        if isinstance(texts, str):
            texts = [texts]
        texts = [str(t) for t in texts]
        if not texts:
            self._send(400, {"error": "texts rỗng"})
            return
        vectors = _embed(texts)
        self._send(200, {"vectors": vectors, "dim": len(vectors[0]), "model": EMBED_MODEL})

    # -- Whisper -----------------------------------------------------
    def _handle_transcribe(self):
        body = self._read_body()
        if not body:
            self._send(400, {"error": "audio rỗng"})
            return
        name = self.headers.get("X-Audio-Filename", "audio.wav")
        suffix = os.path.splitext(os.path.basename(name))[1] or ".wav"
        language = (self.headers.get("X-Language") or "").strip() or None
        try:
            beam = int(self.headers.get("X-Beam-Size", "5") or 5)
        except ValueError:
            beam = 5
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(suffix=suffix)
            with os.fdopen(fd, "wb") as fh:
                fh.write(body)
            self._send(200, _transcribe(tmp, language, beam))
        finally:
            if tmp and os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    def _handle_unload(self):
        """POST /unload — giải phóng Whisper khỏi VRAM (ví dụ trước khi chạy LLM local)."""
        with _WHISPER_LOCK:
            loaded = _WHISPER is not None
            _unload_whisper()
        self._send(200, {
            "status": "unloaded" if loaded else "already_unloaded",
            "whisper_loaded": _WHISPER is not None,
        })

    def log_message(self, fmt, *args):
        pass


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64
    allow_reuse_address = True


def main():
    print(f"[sentinel-ai] warming up OCR (device={os.getenv('VIETOCR_DEVICE', 'auto')}) ...", flush=True)
    try:
        _pred, dev = ocr_svc.bridge._get_predictor()
        print(f"[sentinel-ai] OCR ready on {dev}", flush=True)
    except Exception as exc:
        print(f"[sentinel-ai] OCR warmup failed: {exc}", flush=True)

    if EMBED_PRELOAD:
        # Nạp nền: server vẫn phục vụ OCR/transcribe trong lúc embedding load.
        def _warm_embed():
            try:
                _get_embedder()
            except Exception as exc:
                print(f"[sentinel-ai] embedding warmup failed: {exc}", flush=True)

        threading.Thread(target=_warm_embed, name="embed-warmup", daemon=True).start()

    if WHISPER_PRELOAD:
        def _warm_whisper():
            try:
                _get_whisper()
            except Exception as exc:
                print(f"[sentinel-ai] whisper preload failed: {exc}", flush=True)

        threading.Thread(target=_warm_whisper, name="whisper-warmup", daemon=True).start()

    threading.Thread(target=_whisper_idle_watcher, name="whisper-idle", daemon=True).start()

    srv = Server(("127.0.0.1", PORT), Handler)
    print(f"[sentinel-ai] listening on 127.0.0.1:{PORT}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
