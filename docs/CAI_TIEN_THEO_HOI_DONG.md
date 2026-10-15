# Cải tiến theo góp ý Hội đồng giám khảo — ShieldCall VN

> Tài liệu này ghi lại **kết quả cải tiến** đáp ứng 5 góp ý của hội đồng đánh giá.
> Mọi mục đều ghi rõ **trạng thái thực tế** (đã triển khai & kiểm thử / đang triển khai),
> kèm **file đối chứng** và **lệnh kiểm chứng**. Không claim vượt quá những gì đã đo được.

- **Đội:** AI26B0025 — Bảng B · Miền Bắc
- **Ngày cập nhật:** 2026-10-15
- **Phạm vi thay đổi:** Backend Django (`api/`, `PKV/`) — lớp *Trust & Safety*; API mới; cấu hình logging.

---

## 0. Tóm tắt góp ý → giải pháp → trạng thái

| # | Góp ý của hội đồng | Giải pháp đã triển khai | Trạng thái | File chính |
|---|---|---|---|---|
| 1 | **Bổ sung Guardrail**: AI nhận diện sai; chưa đủ cơ sở thì **không kết luận cụ thể**, phải cảnh báo | Lớp *uncertainty guardrail*: vùng xám 10–39 điểm → nhãn **“CHƯA ĐỦ CƠ SỞ XÁC MINH”**, cảnh báo + kênh xác minh; không bao giờ khẳng định “an toàn” khi thiếu bằng chứng | ✅ Đã triển khai & kiểm thử | `backend/api/utils/trust_guard.py` |
| 2 | **Bổ sung dữ liệu nguồn Việt Nam** | Danh mục kênh/đầu mối chính thức VN (NCSC 156, Bộ Công an 113, VNCERT, tổng đài ngân hàng), từ điển dấu hiệu lừa đảo tiếng Việt, tên miền tin cậy VN | ✅ Đã triển khai | `backend/api/utils/vn_sources.py` |
| 3 | **Độ tin cậy dữ liệu nguồn**: làm rõ giới hạn công cụ | Danh mục **14 nguồn** với độ tin cậy (high/medium/low), mô tả và **giới hạn cụ thể** (VirusTotal, ClamAV, YARA, sandbox, heuristic, RAG, cộng đồng, LLM…) | ✅ Đã triển khai | `backend/api/utils/trust_guard.py` (`SOURCE_CATALOG`) |
| 4 | **Đưa bằng chứng cho nhận định** | Chuẩn hoá mọi phát hiện thành `evidence[]` (nguồn, độ tin cậy, mức độ, liên kết tham chiếu); gắn vào kết quả quét | ✅ Đã triển khai (scan tin nhắn/URL/file) | `backend/api/utils/trust_guard.py` (`build_evidence`) |
| 5 | **Độ bảo mật dữ liệu**: tránh lộ PII qua LLM/logs | Module `privacy` ẩn SĐT/email/STK/CCCD/thẻ/khoá; **logging filter toàn cục**; làm sạch `llm_access.log` | ✅ Đã triển khai & kiểm thử | `backend/api/utils/privacy.py`, `backend/PKV/settings.py` |

---

## 1. Guardrail độ bất định (góp ý #1)

**Vấn đề hội đồng nêu:** *“Cần bổ sung guardrail… nếu chưa đủ cơ sở xác minh thì không nên đưa ra một quyết định cụ thể.”*

### Giải pháp
Hàm `assess()` trong `backend/api/utils/trust_guard.py` phân loại mỗi kết quả quét thành 5 mức, dựa trên
**điểm rủi ro + bằng chứng thực tế + độ tin cậy nguồn**:

| Mức (tier) | Điều kiện | Ý nghĩa |
|---|---|---|
| `CONFIRMED_RISK` | Có bằng chứng “malicious” độ tin cậy cao (VD VirusTotal/ClamAV gắn cờ) | Nguy hiểm, có xác thực |
| `HIGH_RISK` | Điểm ≥ 70 | Nguy cơ cao |
| `SUSPICIOUS` | 40 ≤ điểm < 70 | Đáng ngờ, cần thận trọng |
| **`INSUFFICIENT`** | **10 ≤ điểm < 40 mà không có bằng chứng kết luận** | **Chưa đủ cơ sở — KHÔNG kết luận** |
| `LIKELY_SAFE` | Điểm < 10 **và có bằng chứng sạch độ tin cậy cao** | Có khả năng an toàn (không bảo đảm 100%) |

Điểm mấu chốt: **điểm thấp KHÔNG tự động = “an toàn”.** Chỉ khi có bằng chứng sạch từ nguồn
tin cậy cao (VD VirusTotal sạch trên nhiều engine) hệ thống mới dùng nhãn `LIKELY_SAFE`, và nhãn
này vẫn kèm cảnh báo “không bảo đảm 100%”.

Mỗi kết quả kèm khối `guardrail`:
```json
{
  "tier": "INSUFFICIENT",
  "label": "CHƯA ĐỦ CƠ SỞ XÁC MINH",
  "confidence": 0.3,
  "is_conclusive": false,
  "requires_verification": true,
  "cautions": ["Hệ thống chưa thu thập đủ bằng chứng để kết luận. KHÔNG xem đây là 'an toàn'…"],
  "disclaimer": "Kết quả phân tích tự động chỉ mang tính tham khảo…",
  "official_channels": [ { "name": "Tổng đài Quốc gia phòng chống lừa đảo (NCSC)", "phone": "156", "url": "https://khonggianmang.vn" }, … ],
  "refusal_script": "Cảm ơn, nhưng tôi chưa đủ cơ sở để xác nhận điều này…"
}
```

### Siết prompt LLM
`backend/api/utils/prompts.py` — `PROMPT_GUARD` bổ sung quy tắc 4–5 (áp cho mọi prompt phân tích):
> *4. Nếu dữ liệu rỗng/không đọc được HOẶC bằng chứng không đủ để kết luận, PHẢI nêu rõ “chưa đủ cơ sở để kết luận”… TUYỆT ĐỐI không khẳng định “an toàn”.*
> *5. Mọi nhận định phải kèm bằng chứng/nguồn cụ thể khi có.*

### Nối vào luồng quét
- Tin nhắn: `backend/api/core/views/scan_views.py::_analyze_message_text` → `apply_guardrail(result, kind='message')`.
- URL/Website: `backend/api/core/views/scan_views.py::_analyze_domain` → gắn dữ liệu VirusTotal + `apply_guardrail(..., kind='url')`.
- Tệp tin: `backend/api/core/tasks.py` (task quét file) → `apply_guardrail(result_json, kind='file')`.

### Đồng bộ lời khuyên & nhánh fallback (bổ sung 2026-10-15)
- **Lời khuyên hành động** của quét tin nhắn nay sinh theo `guardrail.tier` qua `_actions_for_guardrail()`
  (`backend/api/core/views/scan_views.py`) — vùng `INSUFFICIENT/SUSPICIOUS` **không còn** câu
  "✅ Tin nhắn có vẻ an toàn" mà hướng xác minh qua kênh chính thức.
- **Nhánh fallback** khi LLM trả JSON lỗi/hết thời gian (`backend/api/utils/ollama_client.py`)
  không còn nói "tạm trả kết quả an toàn"; thay bằng câu trung tính + cờ `insufficient_input=True`.
- **Nhãn ảnh** (`media_utils.py`) đổi "Ảnh an toàn" → "Không phát hiện từ khóa rủi ro trong ảnh".

### Kiểm chứng
```bash
# Tin nhắn giả mạo công an
risk=100 RED → guardrail.tier = HIGH_RISK  (evidence=3, kèm kênh chính thức)
# URL sạch (google.com, VT sạch)
risk=0 → guardrail.tier = LIKELY_SAFE  (kèm cảnh báo "không bảo đảm 100%")
# Vùng xám (điểm 25, không bằng chứng)
guardrail.tier = INSUFFICIENT  ("CHƯA ĐỦ CƠ SỞ XÁC MINH")
```

---

## 2. Dữ liệu nguồn Việt Nam (góp ý #2)

`backend/api/utils/vn_sources.py` bổ sung:

- **Kênh chính thức VN:** Tổng đài 156 (NCSC), Cục ATTT (`canhbao.ncsc.gov.vn`), Công an 113,
  Cảnh sát hình sự `069.2342609`, VNCERT/CC.
- **Tổng đài ngân hàng/ví (18 đơn vị):** BIDV, Vietcombank, VietinBank, Agribank, Techcombank,
  VPBank, MB, ACB, Sacombank, TPBank, VIB, HDBank, SHB, MSB, OCB, MoMo, ZaloPay, VNPay.
- **Từ điển dấu hiệu lừa đảo tiếng Việt** (có dấu & không dấu): OTP, mạo danh công an, trúng thưởng,
  việc nhẹ lương cao, đầu tư/tiền ảo, dụ cài app, giả mạo giao hàng…
- **Tên miền tin cậy VN** (ngân hàng, cơ quan nhà nước) để phát hiện giả mạo.
- **Nguồn tham chiếu VN** để trích dẫn bằng chứng: NCSC, Không gian mạng VN, Bộ Công an, Chính phủ.

> Khi phát hiện ngân hàng liên quan, `guardrail.official_channels` tự chèn tổng đài ngân hàng tương ứng.

**Kho tri thức báo đài:** thêm 9 nguồn báo chí chính thống (VnExpress, Tuổi Trẻ, Thanh Niên, Dân Trí, VietnamNet, VTV, VietnamPlus, Báo Chính phủ, CAND) và lệnh `python manage.py seed_vn_knowledge` tạo 8 bài viết chuyên đề (cảnh báo/hướng dẫn/tin tức/chuyện cảnh giác) **kèm nguồn tham khảo**, được nạp vào chỉ mục RAG (29 → 45 tài liệu) cùng tên miền tin cậy VN đã hợp nhất.

### Mở rộng danh mục nguồn VN (bổ sung 2026-10-15)
Rà soát lại thấy danh mục còn mỏng, đã mở rộng (`backend/api/utils/vn_sources.py`):
- **Kênh chính thức: 10** (thêm Bảo vệ trẻ em 111, BHXH 1900 9068, NHNN, Dịch vụ công Quốc gia, Bộ TT&TT).
- **Ngân hàng/ví: 39** (18 có tổng đài + 21 thêm website chính thức; guardrail tự chèn website khi chưa có tổng đài).
- **Từ điển dấu hiệu lừa đảo: 31 nhóm** (thêm VNeID/dịch vụ công, deepfake, hoàn thuế, BHXH, đăng kiểm, romance, hack nick, tín dụng đen, shipper, xuất khẩu lao động…) — và **đã nối vào bộ quét tin nhắn** (`_analyze_message_text`, trước đây từ điển chưa được dùng).
- **Tên miền tin cậy: 78** (bank + gov + viễn thông + tiện ích + TMĐT).
- **Báo chí: 15**, **nguồn nhà nước: 8**.
- **Kho tri thức RAG: +10 bài VN** (VNeID giả, romance, sàn ảo/forex, BHXH/hoàn thuế, shipper, hack nick, tín dụng đen, bảo vệ trẻ em & người cao tuổi, quy trình xử lý khi đã bị lừa, kiểm tra doanh nghiệp) → chỉ mục RAG **51 tài liệu** (kèm trích dẫn nguồn chính thức).

> Danh mục biên soạn thủ công từ nguồn công khai; cần định kỳ đối chiếu lại URL/SĐT với website chính thức.

---

## 3. Độ tin cậy nguồn & giới hạn công cụ (góp ý #3)

`SOURCE_CATALOG` mô tả **14 nguồn**; mỗi nguồn có `reliability` và `limits` minh bạch:

| Nguồn | Độ tin cậy | Giới hạn đã nêu rõ |
|---|---|---|
| VirusTotal (70+ engine) | high | Phụ thuộc dữ liệu cộng đồng; mẫu mới có thể chưa có báo cáo; bản free giới hạn lượt/phút |
| ClamAV | high | Chỉ nhận diện chữ ký đã biết; có thể sót zero-day |
| YARA | high | Phụ thuộc bộ luật |
| Zero-Trust Sandbox | high | Mẫu cần mạng/kích hoạt trễ có thể không bộc lộ |
| PEFile / OLEtools | medium | Chỉ cung cấp dấu hiệu, không kết luận độc hại |
| Phân tích mạng/SSL | medium | Phụ thuộc khả năng kết nối |
| Tranco | medium | Chỉ là chỉ báo phổ biến, **không đồng nghĩa an toàn** |
| Heuristic tiếng Việt | medium | Có thể dương tính giả |
| RAG (kho tri thức) | medium | Có thể chưa cập nhật hết |
| Báo cáo cộng đồng | medium | Chưa xác minh đầy đủ |
| **Mô hình LLM** | **low (AI)** | **Có thể nhận diện sai/bịa; không phải bằng chứng gốc** |

API công khai: `GET /api/v1/trust/sources/` và `GET /api/v1/trust/policy/`.

---

## 4. Bằng chứng cho nhận định (góp ý #4)

`build_evidence()` chuẩn hoá mọi phát hiện — từ `virustotal`, `forensic_evidence`, `details`,
`network_details`, `patterns_found`, `sources` — thành danh sách thống nhất:

```json
{
  "source": "virustotal",
  "source_name": "VirusTotal (70+ engine AV)",
  "reliability": "high",
  "severity": "CRITICAL",
  "detail": "5 engine gắn cờ ĐỘC HẠI trên 70 engine.",
  "supports": "malicious",
  "url": "https://www.virustotal.com/...",
  "limits": "Phụ thuộc dữ liệu cộng đồng..."
}
```

Mỗi nhận định của hệ thống nay đi kèm nguồn + độ tin cậy + (nếu có) liên kết tham chiếu, đáp ứng
yêu cầu “nhận định phải có bằng chứng hoặc nguồn tham khảo cụ thể”.

---

## 5. Bảo mật dữ liệu — chống lộ PII (góp ý #5)

**Vấn đề:** *“Tránh lỗi/lộ thông tin người dùng qua mô hình ngôn ngữ, tránh ghi thông tin vào logs.”*

`backend/api/utils/privacy.py`:
- `redact_pii(text)` ẩn **SĐT, email, số tài khoản, CCCD/CMND, số thẻ, khoá bí mật/API key/JWT**.
- `PIIRedactionFilter` — filter logging làm sạch **mọi bản ghi log**.
- `redact_for_external_llm()` — dùng trước khi gửi dữ liệu tới mô hình cloud.
- `privacy_notice()` — công bố chính sách xử lý dữ liệu.

Áp dụng:
- `backend/PKV/settings.py` — cấu hình `LOGGING` gắn `pii_redaction` vào handler console (mọi log `api`/`django`).
- `backend/api/utils/ollama_client.py::_log_llm` — ẩn PII trong `prompt_preview`/`response_preview`; gắn filter vào handler file `llm_access.log`.
- `backend/api/core/tasks.py` — gắn filter vào handler file.

Ví dụ (`POST /api/v1/trust/redact/`):
```
input : "Goi 0912345678 hoac a@b.com, STK 123456789012"
output: "Goi [SĐT đã ẩn] hoac [email đã ẩn], STK [số tài khoản đã ẩn]"
```

> Nguyên tắc: redaction áp cho **log & lời gọi mô hình cloud**, KHÔNG dùng để che bằng chứng khi
> phân tích cục bộ (tránh kẻ lừa đảo lợi dụng).

---

## 6. API mới

| Method | Endpoint | Mô tả |
|---|---|---|
| GET | `/api/v1/trust/sources/` | Danh mục nguồn + độ tin cậy + giới hạn |
| GET | `/api/v1/trust/policy/` | Chính sách tin cậy & ngưỡng guardrail |
| GET | `/api/v1/trust/channels/` | Kênh chính thức + tổng đài ngân hàng VN |
| GET | `/api/v1/trust/privacy/` | Chính sách xử lý dữ liệu (điểm #5) |
| POST | `/api/v1/trust/redact/` | Thử nghiệm ẩn PII (không lưu) |

Đăng ký tại `backend/api/core/urls.py`; view ở `backend/api/core/views/trust_views.py`.

---

## 7. Kiểm chứng (đã chạy)

```bash
cd /data/Sentinel_Team_Project
.venv/bin/python manage.py check                 # → System check identified no issues
pm2 reload pkv-web
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8001/api/v1/trust/sources/   # → 200
curl -s -X POST http://127.0.0.1:8001/api/v1/trust/redact/ \
  -H "Content-Type: application/json" \
  -d '{"text":"Goi 0912345678 hoac a@b.com, STK 123456789012"}'
```

Bằng chứng VirusTotal (chạy live, xác nhận công cụ hoạt động):
- URL `google.com`: **93 engine**, 62 sạch / 0 độc hại.
- Hash EICAR: **61/75 engine** gắn cờ độc hại.
- Quét tệp EICAR cục bộ: `verdict=MALICIOUS`, `sources=['local','virustotal']`.

---

## 8. Trạng thái & việc tiếp theo

**Đã hoàn thành (đã kiểm thử):**
- Backend: guardrail bất định, bằng chứng hoá, danh mục nguồn, dữ liệu VN, chống lộ PII qua log/LLM.
- **UI**: component `TrustGuardrailPanel` hiển thị **kết luận + bằng chứng + kênh xác minh chính thức**
  ngay trên các trang kết quả quét (Website, Tin nhắn, Email, QR, Số điện thoại, Tài khoản, Tệp, Âm thanh, Trạng thái).
  Banner “CHƯA ĐỦ CƠ SỞ XÁC MINH” + cảnh báo “mô hình AI có thể sai” + kịch bản từ chối an toàn.
- Bằng chứng được nối cho **mọi loại quét** (phone/account/email/url/message/file + async image/audio qua `/scan/status/`).
- **Trang AI Assistant**: tối ưu streaming (memo hoá hàng tin nhắn), auto-scroll thông minh, composer đo chiều cao động, backdrop sidebar mobile.
- **Bảo mật quiz**: đáp án/giải thích không còn trả qua API công khai; chấm phía server qua `POST /learn/quizzes/<id>/check/`.
- **Tái cấu trúc**: gom toàn bộ backend Django vào `backend/` (repo còn `backend/` + `frontend/` rõ ràng).
- **Object storage S3**: media lưu lên S3 (`django-storages`), bật bằng `USE_S3_MEDIA`; endpoint API qua Tailscale, URL công khai `s3.fptoj.com`; quản trị bằng `rclone`.
- **100% object storage**: cả **media & static** trên S3 (`USE_S3_MEDIA`/`USE_S3_STATIC`); upload mới **không lưu máy**; chỉ mục RAG tách sang `backend/vector_store/`; đồng bộ định kỳ (`sync_media_to_s3`, Celery Beat).
- **Trang Nguồn & độ tin cậy** `/trust/`: công khai nguồn + độ tin cậy/giới hạn, kênh chính thức, báo chí, bảo mật dữ liệu, trạng thái S3.
- **RAG tối ưu**: query cache (LRU), embedding tăng dần, thread-safe; **backup chỉ mục lên S3** (tự backup sau rebuild + Celery Beat 6h, tự khôi phục khi thiếu).

**Việc dài hạn (ghi nhận, chưa làm):**
- Trang “Nguồn & độ tin cậy” riêng (hiện đã có API `/trust/sources/`, và giới hạn nguồn hiển thị trong panel).
- ~~Tuning ngưỡng trên tập chuẩn (ROC) và công bố mẫu/baseline.~~ → **Đã làm cho tầng heuristic tin nhắn**
  (xem `docs/EVAL_THRESHOLDS.md`, AUC 0.950 vs baseline 0.655); còn **phone/domain** và cần tập nhãn do
  người độc lập gán.
- Mở rộng kho tri thức RAG bằng dữ liệu VN có kiểm chứng (có trích dẫn nguồn) — đã thêm 10 bài VN (2026-10-15).

---

## 9. Sửa lỗi liên quan đến độ tin cậy (song song với cải tiến)

Trong quá trình rà soát, đã phát hiện & sửa một số lỗi ảnh hưởng trực tiếp đến độ tin cậy/kết quả:

| Lỗi | Ảnh hưởng | Sửa |
|---|---|---|
| `admin_views.py:129` import sai `from .tasks` | Duyệt báo cáo **số điện thoại** → **500** sau khi đã đổi trạng thái | Đổi sang `from api.core.tasks import recompute_phone_risk` |
| `scan_views.py::normalize_bank_name` khớp substring `'mb'` | `"Vietcombank"`/`"Techcombank"` bị nhận nhầm thành **MBBank** | Khớp theo **ranh giới từ** trên chuỗi gốc (ưu tiên key dài) |
| `VTClient()` không đóng (3 chỗ) | Rò rỉ kết nối/session khi quét tin nhắn & file | Bọc `with VTClient() as vt:` / `try…finally: vt.close()` |
| `Report.tsx` đọc sai field phản hồi | Không hiển thị “Mã hồ sơ #id” sau khi gửi báo cáo | Đọc `report_id` (khớp `ReportCreateView`) |
| `ForumDetail.tsx` gọi `/admin-cp/forum/ban/` | Nút **Cấm người dùng** trên diễn đàn 404 | Đổi sang API `/api/v1/admin/forum/ban/` |

**Sự cố vận hành đã khắc phục:**
- `pkv-celery-beat` **crash-loop** (file `celerybeat-schedule` hỏng → `EOFError`) → đã xoá file lịch hỏng, beat chạy lại bình thường.
- Frontend đang phục vụ **build cũ** so với mã đã sửa → cần `npm run build` + `pm2 reload pkv-frontend` (hoặc chạy `next dev`) để các cải tiến lên bản chạy.

**Đã sửa thêm trong cùng phiên:**
- **Reset mật khẩu** (`PasswordReset*`) trước gọi endpoint 404 → nay có `/api/v1/auth/password/reset/` + `/confirm/` dùng đúng form allauth (kiểm thử: token sai → 400, khớp → 200, đăng nhập lại bằng mật khẩu mới OK).
- **Admin Reports**: duyệt/từ chối/AI analyze/ghi chú trỏ URL Django không proxy → nay proxy qua rewrite (approve/reject/analyze/note).
- **Django Admin `/admin/`**: không truy cập được (bị loop 301) → nay proxy bằng route handler `app/admin/[[...path]]/route.ts`.
- **`/user/reports/`** thiếu `scam_type_display`; **`/auth/me/`** thiếu `is_superuser`/`profile` → đã bổ sung ở serializer.
- **ReportCreateSerializer**: `ocr_text`/`ai_analysis` chuyển read-only (chống giả mạo phân tích AI).
- **Trang chủ**: số “Tổng lượt scan / Mối nguy hiểm” bỏ hardcode → lấy từ `GET /api/v1/stats/public/`.
- **Nav/Footer**: thêm Scam IQ Exam, Admin Control Panel, Django Admin cho staff; mobile thêm Trang chủ/Khẩn cấp/Đăng nhập/Đăng xuất.
- **Web Push**: chống ghi đè chủ sở hữu endpoint của người khác; **MCP**: sửa `target_type` mô tả sai.

**Còn tồn (đã ghi nhận, chưa sửa):**
- Tuning ngưỡng trên tập chuẩn (ROC) và công bố số mẫu/baseline.

---

## Phụ lục A — Bản đồ góp ý ↔ mã nguồn

| Góp ý | Mã nguồn |
|---|---|
| #1 Guardrail | `backend/api/utils/trust_guard.py` (`assess`, `apply_guardrail`); `backend/api/utils/prompts.py` (`PROMPT_GUARD`) |
| #2 Dữ liệu VN | `backend/api/utils/vn_sources.py` |
| #3 Độ tin cậy nguồn | `backend/api/utils/trust_guard.py` (`SOURCE_CATALOG`, `source_catalog`) |
| #4 Bằng chứng | `backend/api/utils/trust_guard.py` (`build_evidence`) |
| #5 Bảo mật dữ liệu | `backend/api/utils/privacy.py`; `backend/PKV/settings.py` (`LOGGING`); `backend/api/utils/ollama_client.py`; `backend/api/core/tasks.py` |
| Nối vào quét | `backend/api/core/views/scan_views.py`; `backend/api/core/tasks.py` |
| API | `backend/api/core/views/trust_views.py`; `backend/api/core/urls.py` |
