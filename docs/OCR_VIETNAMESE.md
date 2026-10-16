# OCR tiếng Việt — chuyển sang VietOCR

> Trạng thái: **đã gỡ EasyOCR và PaddleOCR**. OCR hiện dùng **VietOCR** (Transformer tiếng Việt),
> chạy trong **venv riêng** (`.venv-ocr`) và kết nối qua **bridge** (`backend/scripts/ocr_bridge.py`).

## 1. Vì sao (đo được, không phải cảm tính)

Tập test nội bộ (5 dòng tin nhắn lừa đảo tiếng Việt; ảnh sạch + ảnh khó nền tối/chữ nhỏ/JPEG nén).
Chỉ số: **CER** (Character Error Rate, càng thấp càng tốt).

| Engine | CER ảnh sạch | CER ảnh khó (dark/JPEG) | Ghi chú |
|---|---|---|---|
| EasyOCR (đã gỡ) | 0.020 | 0.024 | tốt, nhưng gộp dòng |
| PaddleOCR (vi, đã gỡ) | 0.089 | 0.089 | **rớt dấu** nặng |
| **VietOCR (đang dùng)** | **0.020** | **0.012** | **đúng dấu, giữ dòng** |

VietOCR tốt nhất cho tiếng Việt (đặc biệt dấu thanh). Lưu ý: tập test nhỏ — **hãy benchmark lại trên
ảnh thật của bạn** (`backend/scripts/ocr_compare.py`).

## 2. Kiến trúc (vì sao tách venv)

- Engine OCR = **VietOCR** + phân đoạn dòng (projection, OpenCV) → nhận dạng từng dòng.
- VietOCR kéo `albumentations/imgaug/opencv/torch` dễ **xung đột** với `.venv` chính
  (numpy 2.4 / opencv-python-headless / torch cu130) → **cách ly vào `.venv-ocr`**.
- `.venv` chính **không còn EasyOCR** (đã `pip uninstall easyocr` + gỡ khỏi `requirements.txt`).
- Gọi qua subprocess: `media_utils._ocr_vietocr_bytes` → `_run_bridge('vietocr', …)` → `ocr_bridge.py`.

```
[Django/Celery .venv]  --HTTP-->  [.venv-ocr] OCR service: giữ VietOCR trong RAM  (khuyến nghị)
                       --subprocess(JSON)--> [.venv-ocr] ocr_bridge.py  (fallback nếu không dùng service)
```

### 2.1 OCR service thường trú (tránh nghẽn)

**Nút nghẽn trước đây:** gọi bridge qua **subprocess mỗi ảnh** → nạp lại torch + model ≈ **8–9s/ảnh**.
**Giải pháp:** chạy **service thường trú** giữ model trong RAM (`backend/scripts/ocr_service.py`),
Django gọi qua HTTP (`OCR_SERVICE_URL`). Endpoint: `GET /health`, `POST /ocr`.

```bash
# chạy tay
.venv-ocr/bin/python backend/scripts/ocr_service.py
# hoặc qua PM2 (khuyến nghị)
pm2 start ecosystem.config.js --only pkv-ocr
```

Đặc điểm chống nghẽn:
- **Model nạp 1 lần** (warmup khi khởi động) — không nạp lại mỗi ảnh.
- **Lock** quanh suy luận (VietOCR không thread-safe) → request xếp hàng, không thrash GPU/crash.
- **Cache LRU** theo hash ảnh (`OCR_CACHE_SIZE`, mặc định 128) → ảnh trùng gần như tức thời.
- **Nhận dạng theo LÔ** (`predict_batch`, GPU) — gom mọi dòng rồi chạy 1 lượt, nhanh hơn từng dòng.

**Kết quả đo** (RTX 4070 SUPER, `VIETOCR_DEVICE=auto`):

| Cách gọi | Ảnh mới (cache miss) | Ảnh trùng (cache hit) |
|---|---|---|
| Bridge subprocess (cũ) | ~8.9s | ~8.9s |
| OCR service | ~1.8–2.2s | ~0.002s |
| **OCR service + batch (mới)** | **~0.7–1.4s** | **~0.002s** |

Nếu không đặt `OCR_SERVICE_URL` → tự fallback về bridge subprocess (vẫn đúng, chỉ chậm hơn).

## 3. Cài đặt (từ đầu)

```bash
cd /data/Sentinel_Team_Project
.venv/bin/python -m venv .venv-ocr
.venv-ocr/bin/pip install -U pip
.venv-ocr/bin/pip install torch torchvision --index-url https://download.pytorch.org/whl/cpu
.venv-ocr/bin/pip install -r backend/requirements-ocr.txt     # = vietocr
```
- `.venv-ocr/` đã nằm trong `.gitignore`.
- Lần chạy đầu tải weights VietOCR (`vgg_transformer`) — cần mạng.

## 4. Cấu hình

`backend/.env`:
```bash
OCR_ENGINE=vietocr       # vietocr | tesseract  (mặc định vietocr)
VIETOCR_DEVICE=auto      # auto (GPU nếu có) | cpu | cuda:0
# OCR_BRIDGE_PY=/abs/path/.venv-ocr/bin/python   # tùy chọn (mặc định tự dò ../.venv-ocr)
```
`auto` → bridge tự dùng `cuda:0` nếu torch trong `.venv-ocr` thấy GPU, ngược lại `cpu`.
Để có GPU: cài torch CUDA trong `.venv-ocr`:
```bash
.venv-ocr/bin/pip install --force-reinstall torch torchvision \
    --index-url https://download.pytorch.org/whl/cu130   # khớp driver (main venv đang cu130)
```
Setting tương ứng trong `PKV/settings.py`.

## 5. Dọn dẹp deps đã làm

- `requirements.txt`: **đã xóa `easyocr`**; thêm chú thích trỏ `requirements-ocr.txt`.
- `requirements-ocr.txt` (**mới**): chỉ `vietocr` (+ hướng dẫn cài `torch` CPU tường minh —
  vì vietocr KHÔNG khai báo torch trong deps).
- `.venv` chính: `pip uninstall easyocr` (đã làm). Các deps dùng chung khác giữ nguyên.
- `media_utils.py`: xóa `get_easyocr_reader`, `_ocr_easyocr_bytes`, `_ocr_paddleocr_bytes`
  (chỉ còn `_ocr_vietocr_bytes`, `_ocr_tesseract_bytes`).

## 6. Kiểm thử / so sánh

```bash
# VietOCR vs Tesseract trên ảnh thật (+ CER nếu có ground truth)
.venv/bin/python backend/scripts/ocr_compare.py --image shot.png --truth shot.txt
```

Đo qua đường app thật (`extract_ocr_text`): CER **0.020** (ảnh sạch) / **0.012** (ảnh khó).

## 7. Hạn chế & việc tiếp theo

- **Phát hiện dòng:** mặc định dùng **projection (OpenCV)** — nhanh, tốt cho ảnh chat/screenshot thường.
  Với ảnh nhiều cột/bảng/biên lai phức tạp có thể kém. Hỗ trợ sẵn detector **CRAFT**
  (`OCR_DETECTOR=craft|auto`) nhưng bản `craft-text-detector 0.4.3` **chưa tương thích torchvision mới**
  (`model_urls`) và cần tải VGG16_bn (~530MB). Muốn bật: cài `torchvision` cũ, hoặc patch
  `torchvision.models.vgg.model_urls`, hoặc thay bằng detector khác (DBNet) — chưa bật mặc định.
- **Hiệu năng:** đã xử lý nút nghẽn bằng **OCR service thường trú** (`pkv-ocr`) + **batch recognition**:
  ~0.7–1.4s/ảnh mới, ~0.002s/ảnh trùng (cache). GPU đã bật (`VIETOCR_DEVICE=auto`, `cuda:0`).
  Nếu tải cao: chạy thêm instance service hoặc batching lớn hơn.
- Chưa có số liệu CER trên tập ảnh VN lớn — xem `docs/EVAL_GUIDE.md` để thu thập & gán nhãn.
- VLM (Ollama `qwen2.5vl`) có thể bổ sung cho ảnh phức tạp, nhưng có thể "bịa" — không dùng làm nguồn duy nhất.
