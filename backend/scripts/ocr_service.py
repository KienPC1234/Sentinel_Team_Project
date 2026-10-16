#!/usr/bin/env python3
"""
ShieldCall VN — OCR Service thường trú (VietOCR) để TRÁNH NGHẼN.

Vấn đề: gọi bridge qua subprocess mỗi ảnh → nạp lại torch + model (~8-9s/ảnh).
Giải pháp: tiến trình chạy nền giữ model trong RAM; Django gọi qua HTTP (nhanh ~vài chục ms/ảnh sau warmup).

Chạy (trong venv OCR):
  .venv-ocr/bin/python backend/scripts/ocr_service.py
  # hoặc qua PM2: pm2 start ecosystem.config.js --only pkv-ocr

Endpoints:
  GET  /health           → {"status","device"}
  POST /ocr              → body {"image_b64","boxes":bool} → {"text","regions","error"}

Cấu hình: OCR_SERVICE_PORT (mặc định 5010), VIETOCR_DEVICE (auto|cpu|cuda:0).
An toàn luồng: dùng lock (VietOCR không thread-safe) → request xếp hàng, tránh nghẽn GPU.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import tempfile
import threading
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ocr_bridge as bridge  # noqa: E402

PORT = int(os.getenv("OCR_SERVICE_PORT", "5010"))
_LOCK = threading.Lock()          # serialize suy luận (VietOCR không thread-safe)
_CACHE: "OrderedDict[str, dict]" = OrderedDict()
_CACHE_MAX = int(os.getenv("OCR_CACHE_SIZE", "128"))


def _cache_get(key: str):
    v = _CACHE.get(key)
    if v is not None:
        _CACHE.move_to_end(key)
    return v


def _cache_put(key: str, val: dict):
    _CACHE[key] = val
    _CACHE.move_to_end(key)
    while len(_CACHE) > _CACHE_MAX:
        _CACHE.popitem(last=False)


def _ocr_bytes(image_bytes: bytes, want_boxes: bool) -> dict:
    key = hashlib.sha256(image_bytes).hexdigest() + (":boxes" if want_boxes else "")
    hit = _cache_get(key)
    if hit is not None:
        return hit
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as fh:
            fh.write(image_bytes)
            tmp = fh.name
        with _LOCK:
            text, regions = bridge.run_vietocr(tmp, want_boxes)
        out = {"text": text, "regions": regions, "error": None}
    except Exception as exc:
        out = {"text": "", "regions": [], "error": f"{type(exc).__name__}: {exc}"}
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except Exception:
                pass
    if not out.get("error"):
        _cache_put(key, out)
    return out


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code: int, obj: dict):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/health"):
            try:
                _pred, dev = bridge._get_predictor()
            except Exception as exc:
                dev = f"error:{exc}"
            self._send(200, {"status": "healthy", "service": "sentinel-ocr", "device": dev, "cached": len(_CACHE)})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self.path.startswith("/ocr"):
            self._send(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length) or b"{}")
            data = base64.b64decode(payload.get("image_b64", ""))
            if not data:
                self._send(400, {"error": "image_b64 rỗng"})
                return
            self._send(200, _ocr_bytes(data, bool(payload.get("boxes"))))
        except Exception as exc:
            self._send(500, {"text": "", "regions": [], "error": f"{type(exc).__name__}: {exc}"})

    def log_message(self, fmt, *args):  # giảm log ồn
        pass


def main():
    print(f"[sentinel-ocr] warming up VietOCR (device={os.getenv('VIETOCR_DEVICE','auto')}) ...", flush=True)
    try:
        _pred, dev = bridge._get_predictor()
        print(f"[sentinel-ocr] ready on {dev}", flush=True)
    except Exception as exc:
        print(f"[sentinel-ocr] warmup failed: {exc}", flush=True)
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"[sentinel-ocr] listening on 127.0.0.1:{PORT}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
