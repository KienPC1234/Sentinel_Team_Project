# Báo cáo Cải tiến Phiên bản 1: Kiểm thử Đầu-Cuối & Đo Chất lượng Khuyến nghị

**Ngày lập:** 28/11/2026  
**Phạm vi:** Hệ thống quét đa kênh ShieldCall VN (`backend/api/core/tasks.py`, `backend/api/core/views/scan_views.py`, `backend/api/utils/ollama_client.py`, `backend/api/utils/trust_guard.py`, `frontend/src/components/ScanWidgets.tsx`, `frontend/src/views/Scan/Message.tsx`).

## 1. Vấn đề & Mục tiêu
Khi kết hợp nhiều công cụ (OCR, trích xuất thực thể, VirusTotal, Tín nhiệm mạng NCSC, tra cứu OSINT web, mô hình AI), lỗi ở bước đầu vào (OCR nhận dạng sai/nhiễu, trang tra cứu trả về 404/reCAPTCHA/Cloudflare, dữ liệu nguồn lỗi thời hoặc công cụ AI/VT gián đoạn) có thể lan truyền sang phần giải thích và khuyến nghị cuối cùng, gây kết luận sai lệch hoặc thiếu hướng dẫn hành động an toàn.

Mục tiêu của Phiên bản 1:
1. Ngăn lỗi OCR, trang lỗi OSINT và sự cố công cụ làm sai lệch kết luận/khuyến nghị.
2. Xây dựng bộ ca thử đầu-cuối (`test_e2e_scan_resilience.py`) bao phủ 4 nhóm tình huống: **OCR sai**, **URL nguy hiểm**, **Nguồn lỗi thời/nhiễu**, **Công cụ không hoạt động**.
3. Đo lường chất lượng khuyến nghị theo từng bước (`measure_recommendation_quality`) qua 3 tầng: Bằng chứng/Đầu vào -> Guardrail -> Giải thích & Khuyến nghị.

## 2. Các cải tiến đã triển khai
1. **Lọc nhiễu OSINT / nguồn lỗi thời (commit `5db6f1b`):**
   - Bổ sung `_NOISE_PAGE_MARKERS` và `_is_noise_or_error_page()` trong `backend/api/utils/ollama_client.py` cho `lookup_trustpilot`, `lookup_sitejabber`, `lookup_scamadviser` để loại bỏ nội dung 404, reCAPTCHA, Cloudflare interstitial khỏi `threat_intel`.
2. **Đồng bộ khuyến nghị hành động ở luồng ảnh/OCR và cải thiện thông báo lỗi OCR (`backend/api/core/tasks.py`):**
   - Theo dõi `ocr_errors` trong `perform_image_scan_task`; khi OCR gặp lỗi và không có dữ liệu đọc được, trả `insufficient_input=True` với giải thích rõ nguyên nhân lỗi nhận dạng chữ.
   - Đồng bộ `result['actions']` qua `_actions_for_guardrail()` sau khi gắn `guardrail`, đảm bảo mọi kết quả quét ảnh/QR (kể cả khi OCR lỗi hoặc AI lỗi 3 lần) đều có danh sách khuyến nghị khớp `guardrail.tier`.
3. **Mở rộng giải thích AI & Việt hóa giao diện (`f3af2c5`, `b3bc695`, `eef1b8b`):**
   - Hiển thị `advice` và `prevention_measures`/`actions` trong `Message.tsx`.
   - Đổi `WsBadge` sang nhãn tiếng Việt (`Trực tiếp`, `Hoàn tất`, `Đang kết nối`...) và đổi nhãn `SOURCE_CATALOG` (`Heuristic tiếng Việt` -> `Bộ lọc mẫu dấu hiệu lừa đảo`, `LLM` -> `Trợ lý phân tích AI`, `OSINT` -> `Đối chiếu nguồn công khai trên web`).

## 3. Thang đo Chất lượng Khuyến nghị Theo Từng Bước
Hàm `measure_recommendation_quality(result, expected_tiers)` đánh giá 5 tiêu chí (tổng 100%):

| Bước | Tiêu chí kiểm tra | Ý nghĩa |
| :--- | :--- | :--- |
| Bước 1 (Đầu vào/Tra cứu) | `stage1_no_noise_leak` | Không lọt chuỗi `reCAPTCHA`, `Cloudflare`, `Whoops!`, `404`, `_tool_` vào giải thích |
| Bước 2 (Guardrail) | `stage2_guardrail_aligned` | `guardrail.tier` khớp mức độ rủi ro thực tế (`INSUFFICIENT`, `HIGH_RISK`, `CONFIRMED_RISK`, ...) |
| Bước 3 (Khuyến nghị) | `stage3_actions_present` | Có tối thiểu 2 bước khuyến nghị hành động cụ thể |
| Bước 3 (Cảnh báo) | `stage3_cautions_present` | Có cảnh báo giới hạn bằng chứng (`guardrail.cautions`) |
| Bước 3 (An toàn ngôn từ) | `stage3_no_false_safe_claim` | Không khẳng định "chắc chắn an toàn" / "an toàn tuyệt đối" khi chưa đủ căn cứ |

## 4. Ví dụ Kết quả Trước / Sau Cải tiến

| Nhóm ca thử | Trước cải tiến | Sau cải tiến |
| :--- | :--- | :--- |
| **Ca OCR sai / nhiễu** | `perform_image_scan_task` không trả `actions`; khi OCR lỗi chỉ báo chung chung "Không tìm thấy chữ hoặc mã QR". | Trả `insufficient_input=True`, giải thích rõ lỗi nhận dạng chữ, `guardrail.tier = INSUFFICIENT`, tự động gắn 3 bước `actions` yêu cầu xác minh kênh chính thức `156`/`113`. Điểm chất lượng: **100%**. |
| **URL nguy hiểm** | Nếu AI timeout/offline, một số luồng phụ thuộc phần giải thích ngắn của AI và thiếu đồng bộ khuyến nghị khẩn cấp. | Bằng chứng NCSC + VirusTotal + rule vẫn giữ `risk_score >= 85`, `tier = CONFIRMED_RISK`/`HIGH_RISK`, trả đủ `actions` chặn chuyển tiền/OTP và gọi `113`. Điểm chất lượng: **100%**. |
| **Nguồn lỗi thời / trang lỗi** | `lookup_trustpilot` chèn nguyên văn `"Whoops! The page you're looking for could not be found... protected by reCAPTCHA"` vào `Tình báo đe dọa toàn cầu`. | `_is_noise_or_error_page()` lọc sạch 404/reCAPTCHA/Cloudflare; nếu nguồn tin cậy cũ mâu thuẫn VT mới thì hạ về `INSUFFICIENT` (`has_contradiction=True`). Điểm chất lượng: **100%**. |
| **Công cụ không hoạt động** | Khi AI lỗi cả 3 lần thử ở quét ảnh hoặc mất kết nối Ollama, thiếu `actions` kèm theo trên payload ảnh. | Thoái lui an toàn về `INSUFFICIENT` (khi thiếu dữ liệu) hoặc rule/evidence (khi có cờ độc hại), trả `actions` đầy đủ, không bịa đặt. Điểm chất lượng: **100%**. |

## 5. Kết quả Kiểm thử & Thư mục Minh chứng
- **Lệnh kiểm thử:** `manage.py test api.core.tests.test_e2e_scan_resilience api.core.tests.test_trust_privacy --noinput`
- **Kết quả:** **62/62 test đạt** (7 ca mới trong `test_e2e_scan_resilience.py` + 55 ca trong `test_trust_privacy.py`), toàn bộ đạt `quality_score = 100.0%`.
- **Thư mục minh chứng:** `docs/minh_chung_v1_20261128/` gồm:
  - `BAO_CAO_CAI_TIEN_PHIEN_BAN_1.md` (báo cáo này)
  - `test_results_e2e_v1.txt` (log chạy 62 test)
  - `git_commits_20261128.txt` và `git_commits_since_0730.txt` (lịch sử git commit)
  - `ai_brain_history/` (`transcript.jsonl` và ảnh chụp màn hình từ phiên AI trong brain `1f1a8250-320b-47cc-b401-fd0b37dbd03c`)
