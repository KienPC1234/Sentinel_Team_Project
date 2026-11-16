# HỒ SƠ NỘP BÀI CHẶNG 1 & KHAI BÁO MINH BẠCH - SHIELDCALL VN

> **Trạng thái:** hồ sơ nộp · **Cập nhật:** 2026-11-16 · **Đối tượng:** hội đồng giám khảo, người nộp bài

Tài liệu tổng hợp đầy đủ các mục bắt buộc theo biểu mẫu **Nộp / cập nhật bài - Chặng 1 (Vòng Chung kết)**.

---

## 1. Bảng điền biểu mẫu nộp bài

| Mục trên cổng nộp bài | Giá trị nộp / Hướng dẫn đối chiếu |
|---|---|
| **Liên kết mã nguồn (HTTPS)** | `https://github.com/KienPC1234/Sentinel_Team_Project` |
| **Liên kết sản phẩm chạy thử (HTTPS)** | `https://sc.fptoj.com` |
| **Liên kết báo cáo cải tiến PDF/Word (HTTPS)** | `https://github.com/KienPC1234/Sentinel_Team_Project/blob/master/docs/BAO_CAO_CAI_TIEN_CHUNG_KET.pdf` (sau khi push commit mới nhất lên GitHub) |
| **Commit / tag / phiên bản mã nguồn** | Kiểm tra bằng `git rev-parse --short HEAD` và `git tag` sau khi commit & push bản Chung kết (base commit hiện tại trên remote: `de5c44f`, tag gần nhất: `1.0b`). |
| **Tài khoản dùng thử sản phẩm** | Đã tạo sẵn tài khoản người dùng chuẩn (`is_staff=False, is_superuser=False`, email đã xác thực) dành riêng cho Hội đồng giám khảo: `bgk_demo` (hoặc BGK có thể tự đăng ký mới tại `https://sc.fptoj.com/register/`). *Không lưu mật khẩu thật trong repository git công khai; mật khẩu dùng thử được gửi riêng qua ô biểu mẫu nộp bài / kênh trao đổi trực tiếp.* |
| **Mật khẩu dùng thử** | *Không nhúng mật khẩu thật vào tài liệu công khai trong repo git; lấy giá trị mật khẩu dùng thử tương ứng cho tài khoản `bgk_demo` từ bảng hướng dẫn nộp bài riêng của đội thi.* |

---

## 2. Hướng dẫn cài đặt và chạy sản phẩm

### 2.1. Yêu cầu môi trường

- Hệ điều hành: Linux (khuyến nghị Ubuntu 22.04/24.04)
- Python 3.11+ (virtualenv tại `.venv/` ở thư mục gốc)
- Node.js 20+ và `npm`
- Redis Server (cho Django Channels, Celery worker & beat)
- Dịch vụ phụ trợ tùy chọn: ClamAV (`clamdscan`/`clamscan`), `exiftool`, ZBar (`libzbar0`), Tesseract OCR, Chromium (cho `puppeteer_host`)

### 2.2. Cài đặt và khởi chạy nhanh (Development / Self-host)

1. **Sao chép mã nguồn và cài đặt môi trường Python (3.11+)**:

```bash
git clone https://github.com/KienPC1234/Sentinel_Team_Project.git
cd Sentinel_Team_Project
python3.11 -m venv .venv
.venv/bin/pip install -U pip
.venv/bin/pip install -r backend/requirements.txt
# Tùy chọn OCR tiếng Việt dùng chung trong venv chính:
.venv/bin/pip install gdown && .venv/bin/pip install --no-deps vietocr==0.3.13
```

2. **Khởi tạo cấu hình từ tệp mẫu**:

```bash
cp backend/PKV/settings.py.example backend/PKV/settings.py
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env.local
```

> Mặc định `backend/.env.example` dùng `DB_ENGINE=sqlite3` để chạy ngay không cần cài MariaDB; khi triển khai thật có thể đổi sang `DB_ENGINE=mysql` kèm `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT` và cấu hình `REDIS_URL`, `OLLAMA_BASE_URL` / `OLLAMA_API_KEY`.

3. **Khởi chạy Backend Django + Celery**:

```bash
cd backend
../.venv/bin/python manage.py migrate
../.venv/bin/python manage.py collectstatic --noinput
../.venv/bin/python manage.py runserver 0.0.0.0:8001
# Terminal khác (nếu chạy tác vụ quét bất đồng bộ):
../.venv/bin/celery -A PKV worker -l info
```

4. **Cài đặt & khởi chạy Frontend Next.js (và dịch vụ Puppeteer tùy chọn)**:

```bash
cd frontend
npm ci
npm run build
API_TARGET=http://127.0.0.1:8001 npm run start -- -p 3000
# Tùy chọn chạy trình duyệt quét URL (cổng 3010):
cd ../puppeteer_host && npm ci && npm run build && npm run start
```

5. **Hoặc chạy đồng bộ toàn bộ dịch vụ qua PM2 (`ecosystem.config.js`)**: khởi động các tiến trình `pkv-web` (Django `:8001`), `pkv-frontend` (Next.js `:3000`), `pkv-celery`, `pkv-celery-beat`, `pkv-puppeteer` (`:3010`), `pkv-ai` (`:5010`).
6. **Kiểm tra nhanh sau cài đặt**:

```bash
cd backend
../.venv/bin/python manage.py check
../.venv/bin/python manage.py test api.core.tests.test_trust_privacy api.core.tests.test_scam_rules api.core.tests.test_scan_audit --noinput
../.venv/bin/python scripts/eval/evaluate_vn_final.py
```

---

## 3. Khai báo sử dụng AI, mã nguồn và dữ liệu bên ngoài

### 3.1. Mô hình AI và API suy luận

| Thành phần | Mục đích sử dụng | Chế độ vận hành & kiểm soát dữ liệu |
|---|---|---|
| Mô hình ngôn ngữ LLM qua Ollama Cloud / Local (`Ollama` API: `qwen`, `deepseek`, `gemma` theo cấu hình `OLLAMA_MODEL` / `OLLAMA_BASE_URL`) | Diễn giải ngữ nghĩa tin nhắn/trang web/ảnh sang tiếng Việt tự nhiên, tổng hợp khuyến nghị hành động an toàn và kịch bản từ chối giao dịch; **không** thay thế bằng chứng gốc. | Tuân thủ nút gạt che PII trên từng lượt quét (`ScanPrivacyToggle`, mặc định BẬT `mask_pii=True`): khi bật, `redact_for_external_llm` ẩn SĐT/CCCD/Email/STK trước khi gửi Cloud LLM (kèm quy tắc prompt giữ khả năng phân tích ngữ cảnh trên nhãn đã che); chỉ gửi nguyên văn khi chạy local hoặc người dùng chủ động tắt `mask_pii=False`. Log hệ thống (`PIIRedactionFilter`) luôn ẩn PII bất biến. |
| `faster-whisper` / Whisper (chạy cục bộ) | Chuyển giọng nói thành văn bản (Speech-to-Text) cho tệp âm thanh/cuộc gọi tải lên. | Chạy cục bộ trên máy chủ, không gửi file âm thanh ra dịch vụ bên ngoài. |
| Embedding / RAG (`sentence-transformers`, `faiss-cpu`, `torch`) | Vector hóa và truy xuất 279 mục tài liệu phòng chống lừa đảo tiếng Việt tại máy chủ. | Chạy cục bộ hoàn toàn với chỉ mục `backend/vector_store`. |
| OCR / QR (`pyzbar`, VietOCR + CRAFT, fallback Tesseract) | Trích xuất nội dung chữ tiếng Việt và mã QR từ ảnh chụp màn hình/biên lai. | Xử lý cục bộ trên máy chủ (`pkv-ai` / `ocr_bridge`). |

### 3.2. Mã nguồn và thư viện bên thứ ba (Giấy phép dự án: `AGPL-3.0-or-later`)

Toàn bộ mã nguồn do nhóm tự phát triển được cấp phép **`AGPL-3.0-or-later`** (tệp `LICENSE`). Bảng dưới đây tổng hợp đầy đủ các thành phần bên thứ ba theo `docs/LEGAL_AND_LICENSE.md`:

| Nhóm thành phần | Thành phần tiêu biểu | Giấy phép | Cách tích hợp & tương thích |
|---|---|---|---|
| Web Framework & API | Django, Django REST Framework, Channels, Celery, `drf-spectacular` | BSD-3-Clause / MIT | Phụ thuộc chuẩn Python, tương thích AGPL-3.0. |
| Trình soạn thảo nội dung | `martor` 1.8.2; CKEditor 5 Community | GPL-3.0 (`martor`); GPL-2.0-or-later (CKEditor 5) | Kết hợp hợp lệ vào tác phẩm `AGPL-3.0-or-later` theo Điều 13 AGPLv3. |
| Phân tích mã độc & Tệp tin | ClamAV, `exiftool` (gọi qua CLI/subprocess); `yara-python`, `pefile`, `oletools`, `pyzbar` / `libzbar` | GPL-2.0 / GPL-1.0-or-later (tiến trình độc lập); Apache-2.0 / MIT / LGPL-2.1 | Tiến trình độc lập (mere aggregation) và thư viện permissive/LGPL tương thích AGPL-3.0. |
| Frontend & Trình duyệt kiểm tra | Next.js 16, React, Tailwind CSS, Lucide/Bootstrap Icons, Puppeteer | MIT / ISC / Apache-2.0 | Permissive, tương thích AGPL-3.0. |

### 3.3. Dữ liệu và dịch vụ tra cứu bên ngoài

| Nguồn dữ liệu / Dịch vụ | Cách sử dụng trong hệ thống | Ngày đối soát / cập nhật |
|---|---|---|
| **Tín nhiệm mạng Việt Nam (`tinnhiemmang.vn` - NCSC/VNCERT)** | Snapshot danh bạ tên miền tín nhiệm (`5,873` mục) và tên miền lừa đảo (`21,293` mục) lưu tại `backend/api/core/data/tinnhiemmang/`. | `04/11/2026` |
| **Danh bạ kênh chính thức & báo chí Việt Nam** | Thông tin tổng đài 113, 156, cổng `khonggianmang.vn`, Bộ Công an, NHNN, 20 hotline/website ngân hàng VN và bài cảnh báo báo chí trong `backend/api/utils/vn_sources.py`. | `2026-11-15` |
| **VirusTotal API v3** | Đối chiếu hash/URL với 70+ engine AV; file tải lên chỉ tra cứu theo mã băm (`upload_if_unknown=False`). | Truy vấn trực tiếp khi bật API key |
| **Tranco List, WHOIS / RDAP, Google Safe Browsing / Feed công khai** | Đánh giá độ phổ biến tên miền, tuổi đăng ký tên miền và thông tin kỹ thuật công khai. | Truy vấn trực tiếp / theo cấu hình |
| **Dữ liệu kiểm thử đánh giá** | Bộ 80 tin nhắn Việt Nam (`independent_test_set_vn.jsonl`) và 20 tình huống guardrail (`vn_final_suite.jsonl`) do nhóm biên soạn phục vụ đo FP/FN và ca thiếu/mâu thuẫn bằng chứng. | `2026-11-15` |
