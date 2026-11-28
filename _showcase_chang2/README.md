# Showcase & Minh chứng Chặng 2 (28/11/2026)

Thư mục này phục vụ trình diễn trực tiếp tại bàn thi cho Ban Giám Khảo (BGK), tách biệt hoàn toàn với `docs/` chính của dự án.

## Cấu trúc thư mục

| Tệp / Thư mục | Mục đích |
| :--- | :--- |
| `README.md` | Hướng dẫn demo nhanh 3 phút tại bàn thi |
| `BAO_CAO_CAI_TIEN_CHANG_2.md` | Báo cáo cải tiến Phiên bản 1 (Kiểm thử đầu-cuối & đo chất lượng khuyến nghị) |
| `demo_scenarios.json` | 4 kịch bản mẫu (OCR sai, URL nguy hiểm, Nguồn lỗi thời/nhiễu, Công cụ lỗi) để demo trực tiếp |
| `01_ket_qua_kiem_thu_dau_cuoi.txt` | Kết quả chạy 62 ca kiểm thử tự động (`test_e2e_scan_resilience` + `test_trust_privacy`) |
| `02_git_commits_tu_0730.txt` | Lịch sử Git commit từ 07:30 ngày 28/11/2026 |
| `02b_git_commits_hom_nay.txt` | Toàn bộ Git commit trong ngày 28/11/2026 |
| `03_lich_su_ai_brain/` | Lịch sử phiên làm việc AI (`transcript.jsonl`) và ảnh chụp minh chứng |

## Kịch bản Demo nhanh cho BGK (3 phút)

1. **Demo trên giao diện Web (`/scan/message/` và `/scan/qr/`):**
   - Dán mẫu `URL nguy hiểm` từ `demo_scenarios.json` vào `/scan/message/`.
   - Chỉ cho BGK thấy tiến trình thời gian thực (`Trực tiếp` -> `Hoàn tất`), badge che thông tin nhạy cảm dạng thu gọn, giải thích AI chi tiết kèm mục **Khuyến nghị xử lý**, và nguồn đối chiếu tiếng Việt thân thiện (`Bộ lọc mẫu dấu hiệu lừa đảo`, `Trợ lý phân tích AI`).
2. **Demo kiểm thử đầu-cuối & đo chất lượng khuyến nghị (Terminal):**
   ```bash
   cd /data/Sentinel_Team_Project/backend
   /data/Sentinel_Team_Project/.venv/bin/python manage.py test api.core.tests.test_e2e_scan_resilience --noinput
   ```
   - Chạy 7 ca kiểm thử đầu-cuối trong < 1 giây, kiểm chứng đủ 4 tình huống lỗi/rủi ro và đạt 100% điểm chất lượng khuyến nghị qua 3 bước.
3. **Đối chiếu minh chứng Git & Lịch sử AI:**
   - Mở `02_git_commits_tu_0730.txt` và `03_lich_su_ai_brain/transcript.jsonl`.
