#!/usr/bin/env python3
"""
ShieldCall VN — OCR bridge: chạy VietOCR trong VENV RIÊNG (tránh xung đột deps).

Dùng:  <venv-ocr>/bin/python backend/scripts/ocr_bridge.py <engine> <image_path> [--boxes]
In ra 1 dòng JSON:
  - thường:      {"engine","text","regions":[],"error"}
  - có --boxes:  {"engine","text","regions":[{"bbox":[[x,y]x4],"text","confidence"}],"error"}

Engine: vietocr (chính). (EasyOCR/PaddleOCR đã gỡ.)
"""
from __future__ import annotations

import json
import sys


_PREDICTOR = None
_DEVICE = None


def _get_predictor():
    """Nạp VietOCR predictor 1 lần/tiến trình (cache toàn cục) — tránh nạp lại mỗi request."""
    global _PREDICTOR, _DEVICE
    if _PREDICTOR is None:
        import os
        import torch
        from vietocr.tool.predictor import Predictor
        from vietocr.tool.config import Cfg
        dev = (os.getenv("VIETOCR_DEVICE") or "auto").strip().lower()
        if dev in ("", "auto"):
            dev = "cuda:0" if torch.cuda.is_available() else "cpu"
        cfg = Cfg.load_config_from_name("vgg_transformer")
        cfg["device"] = dev
        try:
            cfg["cnn"]["pretrained"] = False  # không tải lại VGG pretrained
        except Exception:
            pass
        _PREDICTOR = Predictor(cfg)
        _DEVICE = dev
    return _PREDICTOR, _DEVICE


_CRAFT = None
_CRAFT_FAILED = False


def _get_craft():
    """Craft detector (nếu đã cài craft-text-detector) — cache toàn cục."""
    global _CRAFT
    if _CRAFT is None:
        import os
        import torch
        import torchvision.models.vgg as vgg
        if not hasattr(vgg, "model_urls"):
            vgg.model_urls = {"vgg16_bn": "https://download.pytorch.org/models/vgg16_bn-6c64b313.pth"}
        from craft_text_detector import Craft
        dev = (os.getenv("VIETOCR_DEVICE") or "auto").strip().lower()
        use_cuda = torch.cuda.is_available() and dev != "cpu"
        _CRAFT = Craft(
            output_dir=None, rectify=True, export_extra=False, cuda=use_cuda,
            text_threshold=0.7, link_threshold=0.4, low_text=0.4,
        )
    return _CRAFT


def _detect_boxes(path: str, img):
    """Phát hiện vùng chữ: CRAFT (nếu cài & tương thích) → fallback projection."""
    global _CRAFT_FAILED
    det = (__import__("os").getenv("OCR_DETECTOR") or "auto").strip().lower()
    if det in ("auto", "craft") and not _CRAFT_FAILED:
        try:
            craft = _get_craft()
            pred = craft.detect_text(path)
            out = []
            for b in (pred.get("boxes") or []):
                xs = [float(p[0]) for p in b]
                ys = [float(p[1]) for p in b]
                out.append((int(min(xs)), int(min(ys)), int(max(xs)), int(max(ys))))
            if out:
                return out
        except Exception as exc:  # không cài/không tương thích → dùng projection (chỉ cảnh báo 1 lần)
            _CRAFT_FAILED = True
            print(f"[ocr] CRAFT không dùng được ({type(exc).__name__}: {exc}); chuyển projection", file=sys.stderr)
            if det == "craft":
                raise
    return _detect_boxes_projection(img)


def _detect_boxes_projection(img):
    import cv2
    import numpy as np
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    H, W = gray.shape

    def extract_from_binary(bw_img):
        kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (15, 3))
        dil = cv2.dilate(bw_img, kernel, iterations=1)
        contours, _ = cv2.findContours(dil, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        found = []
        for c in contours:
            x, y, w, h = cv2.boundingRect(c)
            if w < 10 or h < 8:
                continue
            if w * h > 0.9 * W * H:
                continue
            found.append((x, y, x + w, y + h))
        return found

    # 1. Otsu thresholding
    bw = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)[1]
    if float(bw.mean()) > 127.0:
        bw = cv2.bitwise_not(bw)
    boxes = extract_from_binary(bw)

    # 2. Adaptive threshold fallback (for complex backgrounds, dark mode, gradient chat bubbles)
    if not boxes:
        bw_adapt = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY_INV, 25, 10)
        boxes = extract_from_binary(bw_adapt)

    # 3. Horizontal line slicing fallback if image has gradient content
    if not boxes:
        edges = cv2.Canny(gray, 50, 150)
        row_sums = np.sum(edges, axis=1)
        active_rows = np.where(row_sums > 0)[0]
        if len(active_rows) > 0:
            band_h = 32
            for y in range(0, H, band_h):
                boxes.append((0, y, W, min(H, y + band_h)))

    # 4. Final safety net: full image crop
    if not boxes:
        boxes.append((0, 0, W, H))

    return boxes


def run_vietocr(path: str, want_boxes: bool):
    """VietOCR: detect vùng chữ (CRAFT/projection) → nhận dạng theo LÔ (predict_batch, GPU)."""
    import cv2
    from PIL import Image

    predictor, _dev = _get_predictor()
    img = cv2.imread(path)
    if img is None:
        return "", []
    H, W = img.shape[:2]

    boxes = _detect_boxes(path, img)
    pad = 2
    crops_pil, metas = [], []
    for (x1, y1, x2, y2) in boxes:
        X1, Y1 = max(0, x1 - pad), max(0, y1 - pad)
        X2, Y2 = min(W, x2 + pad), min(H, y2 + pad)
        if X2 <= X1 or Y2 <= Y1:
            continue
        crop = img[Y1:Y2, X1:X2]
        if crop.size == 0:
            continue
        crops_pil.append(Image.fromarray(cv2.cvtColor(crop, cv2.COLOR_BGR2RGB)))
        metas.append((X1, Y1, X2, Y2))

    if not crops_pil:
        return "", []

    # Sắp theo thứ tự đọc (trên→dưới, trái→phải) trước khi nhận dạng
    order = sorted(range(len(metas)), key=lambda i: (round(metas[i][1] / 12), metas[i][0]))
    crops_sorted = [crops_pil[i] for i in order]
    metas_sorted = [metas[i] for i in order]

    try:
        texts = predictor.predict_batch(crops_sorted)   # batch trên GPU (nhanh hơn nhiều)
    except Exception:
        texts = [predictor.predict(p) for p in crops_sorted]

    out_texts, regions = [], []
    for t, (X1, Y1, X2, Y2) in zip(texts, metas_sorted):
        t = (t or "").strip()
        if not t:
            continue
        out_texts.append(t)
        if want_boxes:
            regions.append({"bbox": [[X1, Y1], [X2, Y1], [X2, Y2], [X1, Y2]], "text": t, "confidence": 1.0})
    return "\n".join(out_texts).strip(), regions


def run_tesseract(path: str, want_boxes: bool):
    import pytesseract
    from PIL import Image
    return pytesseract.image_to_string(Image.open(path), lang="vie+eng").strip(), []


def main() -> None:
    args = [a for a in sys.argv[1:] if a != "--boxes"]
    want_boxes = "--boxes" in sys.argv
    engine = args[0] if args else "vietocr"
    path = args[1] if len(args) > 1 else ""
    out = {"engine": engine, "text": "", "regions": [], "error": None}
    try:
        if engine == "vietocr":
            text, regions = run_vietocr(path, want_boxes)
        elif engine == "tesseract":
            text, regions = run_tesseract(path, want_boxes)
        else:
            text, regions = "", []
            out["error"] = f"engine không hỗ trợ: {engine}"
        out["text"] = text
        out["regions"] = regions
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    print(json.dumps(out, ensure_ascii=False))


if __name__ == "__main__":
    main()
