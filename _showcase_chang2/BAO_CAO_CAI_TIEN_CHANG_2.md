# Báo cáo Cải tiến Chặng 2 · Phiên bản 1: Kiểm thử Đầu-Cuối

**Ngày:** 28/11/2026  
**Chủ đề:** Ngăn lỗi OCR / tra cứu lan truyền sang giải thích & khuyến nghị; đo chất lượng khuyến nghị theo từng bước.

## 1. Vấn đề đặt ra
Trong kiến trúc đa công cụ (OCR, trích xuất thực thể, VirusTotal, Tín nhiệm mạng NCSC, tra cứu web OSINT, mô hình AI), lỗi ở một mắt xích đầu vào (OCR đọc sai/nhiễu, trang tra cứu trả về 404/reCAPTCHA/Cloudflare, dữ liệu nguồn lỗi thời hoặc công cụ AI/VT gián đoạn) có thể lan sang phần giải thích và khuyến nghị cuối cùng.

## 2. Các điểm cải tiến đã thực hiện
1. **Lọc trang lỗi & nguồn nhiễu OSINT (`backend/api/utils/ollama_client.py`):**
   - Bổ sung `_NOISE_PAGE_MARKERS` và `_is_noise_or_error_page()` trong `lookup_trustpilot`, `lookup_sitejabber`, `lookup_scamadviser` để chặn nội dung 404, reCAPTCHA, Cloudflare lọt vào `threat_intel`.
2. **Bảo vệ luồng ảnh/OCR và đồng bộ khuyến nghị (`backend/api/core/tasks.py`):**
   - Ghi nhận `ocr_errors` trong `perform_image_scan_task`; khi OCR gặp lỗi và không trích xuất được nội dung, gán `insufficient_input=True` kèm giải thích rõ nguyên nhân lỗi nhận dạng chữ.
   - Đồng bộ `result['actions']` theo `guardrail.tier` qua `_actions_for_guardrail()` ngay sau khi gắn guardrail.
3. **Mở rộng giải thích AI & chuẩn hóa giao diện tiếng Việt (`scan_views.py`, `Message.tsx`, `ScanWidgets.tsx`, `trust_guard.py`):**
   - Truyền `advice` và `prevention_measures` từ AI ra kết quả `/scan/message` và hiển thị mục **Khuyến nghị xử lý**.
   - Việt hóa `WsBadge` (`Trực tiếp`, `Hoàn tất`, ...) và `SOURCE_CATALOG` (`Bộ lọc mẫu dấu hiệu lừa đảo`, `Trợ lý phân tích AI`, `Đối chiếu nguồn công khai trên web`).
   - Tắt log nhiễu `faiss.loader` (`ModuleNotFoundError` AVX512/AVX2) trong `backend/api/utils/vector_db.py`.

## 3. Bộ ca thử đầu-cuối & Thang đo chất lượng theo từng bước
Tệp kiểm thử: `backend/api/core/tests/test_e2e_scan_resilience.py`  
Hàm đo: `measure_recommendation_quality(result, expected_tiers)` kiểm tra 5 tiêu chí trên 3 tầng:
- **Bước 1 (Đầu vào & Tra cứu):** `stage1_no_noise_leak` (không lọt chuỗi `reCAPTCHA`, `Cloudflare`, `Whoops!`, `404`, `_tool_`).
- **Bước 2 (Guardrail):** `stage2_guardrail_aligned` (`guardrail.tier` khớp mức độ rủi ro thực tế).
- **Bước 3 (Giải thích & Khuyến nghị):** `stage3_actions_present` (đủ >= 2 hành động cụ thể), `stage3_cautions_present` (có cảnh báo giới hạn bằng chứng), `stage3_no_false_safe_claim` (không khẳng định an toàn tuyệt đối khi thiếu cơ sở).

## 4. Kết quả Trước / Sau cải tiến

| Ca thử | Trước cải tiến | Sau cải tiến | Điểm chất lượng |
| :--- | :--- | :--- | :--- |
| **Ca 1: OCR sai / lỗi / nhiễu** | Luồng ảnh không trả `actions`; lỗi OCR gộp chung thông báo thiếu chữ. | Gán `insufficient_input=True`, giải thích rõ lỗi nhận dạng chữ, `tier=INSUFFICIENT`, đủ 3 bước xác minh `156`/`113`. | 100.0% (5/5) |
| **Ca 2: URL nguy hiểm** | Nếu AI gián đoạn, dễ thiếu đồng bộ phần khuyến nghị hành động khẩn cấp. | NCSC + VT + rule giữ `risk_score >= 85`, `tier=CONFIRMED_RISK`/`HIGH_RISK`, trả đủ `actions` chặn chuyển tiền/OTP và gọi `113`. | 100.0% (5/5) |
| **Ca 3: Nguồn lỗi thời / trang lỗi** | Trang 404/reCAPTCHA từ Trustpilot lọt vào `Tình báo đe dọa toàn cầu`. | `_is_noise_or_error_page()` lọc sạch trang lỗi; nguồn tin cậy cũ mâu thuẫn VT mới tự hạ về `INSUFFICIENT` (`has_contradiction=True`). | 100.0% (5/5) |
| **Ca 4: Công cụ không hoạt động** | AI lỗi cả 3 lần thử ở quét ảnh thiếu `actions` kèm theo trong payload. | Thoái lui an toàn về `INSUFFICIENT` hoặc bằng chứng độc lập, vẫn trả đủ `actions` và cảnh báo trung thực. | 100.0% (5/5) |

**Tổng hợp chạy kiểm thử:** `manage.py test api.core.tests.test_e2e_scan_resilience api.core.tests.test_trust_privacy --noinput` đạt **62/62 test OK**.
