# Ma trận Giấy phép & Tính tương thích — ShieldCall VN

Dự án dùng giấy phép **`AGPL-3.0-or-later`** (xem `LICENSE`). Tài liệu này là câu trả lời
cho câu hỏi phản biện: "MIT + Proprietary + martor AGPL có tương thích không?".

> Nguyên tắc chọn AGPL-3.0: dự án là **web service** (chạy trên server, người dùng
> tương tác qua mạng). Chỉ AGPL mới buộc bên vận hành bản sửa đổi phải mở source
> (điều 13). MIT/GPL thường không làm được điều này — đó chính là lỗ hổng mà
> martor-thời-MIT từng tạo ra.

## 1. Kết luận trước (để BGK đọc 30 giây)

| # | Câu hỏi | Trả lời |
|---|---------|----------|
| 1 | Dự án license gì? | AGPL-3.0-or-later, toàn bộ code tự viết. `LICENSE` là toàn văn AGPL-3.0. |
| 2 | Còn chữ "Proprietary and Confidential"? | Đã xóa khỏi `README.md`. Không còn mâu thuẫn MIT/Proprietary. |
| 3 | martor ghi nhầm AGPL trong bản kê khai cũ? | **Đã đính chính.** Bản martor đang cài thực tế là **1.8.2, GPL-3.0** (kiểm chứng metadata trong `.venv`). GPL-3.0 được phép link/combine vào tác phẩm AGPL theo **điều 13 AGPL**. Bản kê khai nộp kèm hồ sơ phải ghi đúng GPL-3.0. |
| 4 | CKEditor GPL, ClamAV GPL, exiftool GPL? | CKEditor 5 Community (`GPL-2.0-or-later`, vendored JS) được quyền nâng lên GPL-3.0 và combine vào AGPL theo điều 13. ClamAV/exiftool chạy **tiến trình độc lập** (gọi qua CLI/subprocess), không link vào code → **mere aggregation**, không lây copyleft. |
| 5 | Nghĩa vụ khi deploy công khai? | Mọi bản sửa đổi chạy public phải cung cấp Corresponding Source cho người dùng mạng (AGPL §13). Source chuẩn là repo này. |
| 6 | Thư viện MIT/Apache/BSD/LGPL? | Tương thích mặc định với AGPL-3.0 (permissive + LGPL cho phép link). |

## 2. Ma trận chi tiết (nhóm copyleft cần chứng minh)

| Thành phần | License thực tế | Cách dùng | Vì sao tương thích với AGPL-3.0 |
|------------|----------------|-----------|----------------------------------|
| Code tự viết (`api/`, `PKV/`, `scripts/`, `mcp_server/`) | AGPL-3.0-or-later | Toàn bộ | Gốc của combined work |
| `martor` 1.8.2 | **GPL-3.0** (metadata `.venv`, đã kiểm chứng; hồ sơ cũ ghi nhầm AGPL) | Import Python (link) | AGPL §13 cho phép combine với GPLv3, whole work → AGPL-3.0 |
| CKEditor 5 Community (vendored `PKV/static/vendor/ckeditor5/`) | GPL-2.0-or-later | JS chạy browser, giữ nguyên header license | "or-later" → được phân phối dưới GPL-3.0 → combine vào AGPL theo §13 |
| ClamAV / clamd | GPL-2.0 | Gọi binary độc lập (`_scan_with_clamav`, subprocess) | Tiến trình riêng, giao tiếp qua file/CLI = aggregation, không phải derivative |
| `exiftool` | GPL-1.0-or-later | Gọi binary độc lập | Như trên |
| `pyzbar` 0.1.9 (wrapper) + ZBar (system lib) | MIT (wrapper, đã kiểm chứng) / LGPL-2.1 (ZBar) | Import + dynamic lib hệ thống | Permissive + LGPL cho phép link vào AGPL |
| `faiss-cpu`, `transformers`, `sentence-transformers`, `torch` | MIT / Apache-2.0 / BSD | Import | Permissive, tương thích |
| Model LLM (DeepSeek/Qwen/Gemma qua API, Whisper, embedding) | Theo điều khoản provider / MIT / Apache-2.0 | Gọi API hoặc load weights, không phân phối lại | Không tạo derivative của code; tuân ToS provider |

## 3. Việc cần làm định kỳ (cam kết trước BGK)

1. `pip-licenses --format=markdown` mỗi release để tái kiểm chứng ma trận (tránh ghi nhầm như vụ martor).
2. Giữ nguyên header `@license CKSource` trên mọi file vendored CKEditor.
3. Không commit code patch đè lên thư viện copyleft mà không ghi chú nguồn.
4. Mọi deploy public của bản fork phải giữ link "Mã nguồn (AGPL)" tới repo (đáp ứng §13 + §5d Appropriate Legal Notices).
