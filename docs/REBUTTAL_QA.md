# Tài liệu Phản biện — Câu hỏi BGK & Câu trả lời chuẩn bị sẵn

> Mục đích: mọi câu hỏi khó đều có **câu trả lời trung thực + file đối chứng + trạng thái
> khắc phục**. Không claim tuyệt đối ở những chỗ chưa đo được.

## Nhóm A — Tính mới & AI

**Q1. Điểm mới khoa học ở đâu, hay chỉ lắp ráp thư viện?**
Điểm mới là **pipeline hybrid nhiều vector + scoring hợp nhất** cho lừa đảo tiếng Việt
(`get_phone_risk` trong `backend/api/utils/scan_utils.py`, `_phone_risk_score` / `_analyze_domain`
trong `backend/api/core/views/scan_views.py`, entropy + homoglyph tự triển khai), không phải model
mới. Nói rõ điều này; lộ trình fine-tune SLM là kế hoạch phát triển,
không phải kết quả đã đạt.

**Q2. Công thức Risk Score 0–100, trọng số, ngưỡng?**
Phone: reputation (≤45) + metadata (≤25) + behavior (≤30), ngưỡng RED >80 / YELLOW >50 /
GREEN >20 (`scan_views.py:_phone_risk_score`). Domain: cộng điểm theo SSL/redirect/VT/feed,
trừ điểm theo Tranco (`_analyze_domain`). Thừa nhận: trọng số là heuristic chuyên gia.
**Đã bắt đầu tuning ngưỡng trên tập chuẩn (ROC) cho tầng heuristic tin nhắn** — xem Q6 và
`docs/EVAL_THRESHOLDS.md`; **chưa** tuning cho phone/domain (còn là việc tiếp theo), không claim "tối ưu".

**Q3. "Triệt tiêu hoàn toàn hallucination"?**
Cách diễn đạt cũ là quá tay. Thực tế: RAG (FAISS, `backend/api/utils/vector_db.py`) **giảm**
bịa đặt bằng grounding + web-search enrichment, không triệt tiêu. Chưa có eval
faithfulness — ghi rõ là hạn chế.

**Q4. "On-premise / Zero Cloud Leakage" trong khi dùng DeepSeek cloud?**
Kiến trúc thực tế là **hybrid**: sandbox/ClamAV/OCR/Whisper/FAISS chạy local; LLM
cloud là **optional fallback** theo `LLM_PROVIDER` (`backend/PKV/settings.py`). Dữ liệu nhạy cảm
(file upload) mặc định chỉ qua local engine; khi bật cloud phải có consent và ghi log.
Không claim "tuyệt đối on-premise" nữa.

**Q5. Chống prompt-injection thế nào?**
Snippet script tách riêng, strip control-chars, giới hạn 150 dòng/500KB
(`sandbox_analyzer.py:_extract_script_snippet`); moderation prompt coi user-content là
DATA (`tasks.py:MODERATION_SYSTEM_PROMPT`). Thừa nhận: chưa có bộ test jailbreak cho
file/PDF đính kèm — đang bổ sung.

## Nhóm B — Đo kiểm & số liệu

**Q6. Các con số 96.8% / 94.5% / 99.2% / 100% đo trên tập nào?**
Trả lời trung thực: đó là **kết quả nội bộ sơ bộ**, chưa có dataset công bố + baseline.
Mọi claim "100%" đã hạ tone. Điều kiện công nhận: công bố số mẫu, môi trường đo, script
đánh giá và baseline (Tesseract/VirusTotal) — đang thực hiện.

**Cập nhật (2026-10-15) — đã có đánh giá tái lập cho tầng heuristic tin nhắn:**
`docs/EVAL_THRESHOLDS.md` (sinh bởi `backend/scripts/eval/evaluate_thresholds.py`, tái lập được):
- Tập chuẩn **88 mẫu** (45 lừa đảo / 43 hợp lệ) — nhỏ, nội bộ.
- **AUC = 0.950** (heuristic VN mở rộng) vs **baseline 6 từ khoá = 0.655**.
- Ngưỡng F1 tốt nhất = **10** (P 0.90 / R 0.96 / F1 0.92); Youden-J = 20.
- **Cảnh báo thiên lệch:** cùng đội viết từ điển lẫn tập nhãn → có thể lạc quan; cần người gán
  độc lập + mẫu từ dữ liệu thật. Đây là lý do chưa nâng các con số marketing.

**Q7. Stress test "0% error" có đáng tin?**
CSV hiện tại mẫu nhỏ (APK 50 req), thiếu Locust script, p99, fail-point (Redis/Ollama
sập). Trình bày đúng mức "smoke test", không gọi là kiểm thử tải đầy đủ.

**Q8. GPU 8–16GB thì trường học chạy thế nào?**
Thừa nhận yêu cầu phần cứng là rào cản; lộ trình: API cloud cho client nhẹ + bản local
rút gọn (tắt Whisper/OCR nặng). `WHISPER_MODEL_SIZE` / `EASYOCR_GPU` đã cấu hình được
qua env.

## Nhóm C — Bảo mật & pháp lý dữ liệu

**Q9. SĐT/STK theo NĐ 13/2023: consent, lưu trữ, xóa, khiếu nại?**
Hiện có: hash STK (`BankAccount.hash_account`), che số hiển thị (`mask_account`),
phân quyền xem scan (`ScanStatusView`: staff/chủ sở hữu/session/referable). Còn thiếu:
chính sách lưu trữ/xóa, DPIA, quy trình khiếu nại false-positive có SLA — đã liệt kê
là việc phải làm, không né.

**Q10. Upload 100MB + Puppeteer + MCP public có phải lỗ hổng?**
Giới hạn upload đã thống nhất **một nguồn duy nhất 100MB** trong `settings.py` (xóa
block trùng 500MB). SSRF có `is_safe_url` chặn dải private + kiểm tra sau redirect;
Puppeteer chỉ render, không dùng để vượt CAPTCHA. MCP chấp nhận API-key qua header,
rate-limit/quota qua Redis (`backend/api/core/authentication.py`).

**Q11. Kết luận sai thì ai chịu trách nhiệm?**
Mọi kết quả AI đều kèm `risk_level` + diễn giải, không tự động chặn tài khoản người
dùng; luồng `report-admin` + moderation queue cho admin duyệt lại
(`_document_scan_for_admin`, ngưỡng 85). Cam kết bổ sung hiển thị "AI có thể sai" trên UI.

## Nhóm D — Liêm chính hồ sơ

**Q12. Ảnh placehold, Drive placeholder, 180+ commits?**
Nhận lỗi trực diện: ảnh minh họa đang là placeholder (cần thay screenshot thật),
link Drive chưa mở, số commit thực tế kiểm bằng `git rev-list --count` (hiện ~51,
không phải 180+). Đã sửa `.gitignore` để **toàn bộ thư mục minh chứng được track**
lên remote cho BGK verify (chỉ loại trừ video thô + secrets + DB + media upload).
Số liệu "150 học sinh" chỉ được giữ lại khi có file đối chứng.

**Q13. Giấy phép?**
Xem `docs/LEGAL_AND_LICENSE.md`: dự án **AGPL-3.0-or-later**, martor thực tế là
**GPL-3.0** (đã kiểm chứng, hồ sơ cũ ghi nhầm AGPL đã sửa), combine hợp lệ theo
điều 13 AGPL; không còn chữ "Proprietary".
