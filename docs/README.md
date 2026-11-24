# Tài liệu ShieldCall VN

> **Trạng thái:** đang dùng · **Cập nhật:** 2026-11-15 · **Đối tượng:** toàn bộ thành viên, hội đồng giám khảo
>
> Mục lục tài liệu kỹ thuật, đánh giá và hồ sơ nộp bài của dự án.
> **Phạm vi:** `docs/` và các tài liệu gốc ở thư mục repository.

---

## 1. Đọc gì trước

| Bạn là | Lộ trình |
| :--- | :--- |
| Người mới vào dự án | [`../README.md`](../README.md) → [`SETUP.md`](SETUP.md) → [`ARCHITECTURE.md`](ARCHITECTURE.md) → [`API_REFERENCE.md`](API_REFERENCE.md) |
| Kỹ sư backend / DevOps | [`../AGENTS.md`](../AGENTS.md) → [`ARCHITECTURE.md`](ARCHITECTURE.md) → [`SETUP.md`](SETUP.md) → [`TESTING.md`](TESTING.md) |
| Người làm đánh giá / nghiên cứu | [`EVAL_GUIDE.md`](EVAL_GUIDE.md) → [`EVAL_THRESHOLDS.md`](EVAL_THRESHOLDS.md) → các báo cáo benchmark bên dưới |
| Hội đồng giám khảo | [`../PROJECT_OVERVIEW.md`](../PROJECT_OVERVIEW.md) → [`BAO_CAO_CAI_TIEN_CHUNG_KET.md`](BAO_CAO_CAI_TIEN_CHUNG_KET.md) → [`CHECKLIST_TINH_NANG.md`](CHECKLIST_TINH_NANG.md) → [`REBUTTAL_QA.md`](REBUTTAL_QA.md) (và `_chungket/KHAI_BAO_VA_NOP_BAI_CHUNG_KET.md` ngoài git) |

---

## 2. Danh mục tài liệu

### 2.1. Kiến trúc, vận hành và API

| Tài liệu | Nội dung | Trạng thái | Cập nhật |
| :--- | :--- | :--- | :--- |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Topology, pipeline 6 vector, sandbox, Puppeteer, MCP | Đang dùng · EN | 2026-11-15 |
| [`SETUP.md`](SETUP.md) | Cài đặt, biến môi trường, S3, build, PM2 | Đang dùng · EN | 2026-11-15 |
| [`API_REFERENCE.md`](API_REFERENCE.md) | Bảng endpoint chính, xác thực, Swagger/ReDoc | Đang dùng · EN | 2026-11-15 |
| [`TESTING.md`](TESTING.md) | Lệnh kiểm thử backend, sandbox, frontend, Puppeteer, đánh giá | Đang dùng · EN | 2026-11-15 |

### 2.2. Nguồn dữ liệu và engine chuyên biệt

| Tài liệu | Nội dung | Trạng thái | Cập nhật |
| :--- | :--- | :--- | :--- |
| [`TINNHIEM.md`](TINNHIEM.md) | Thư viện, crawler và threat feed Tín nhiệm mạng | Đang dùng · VI | 2026-10-16 |
| [`OCR_VIETNAMESE.md`](OCR_VIETNAMESE.md) | Pipeline VietOCR, CER và giới hạn | Đang dùng · VI | 2026-11-04 |
| [`DATASET_CONTRACT_V1.md`](DATASET_CONTRACT_V1.md) | Hợp đồng dữ liệu sự kiện cuộc gọi/SMS v1 | Nháp (development) · EN | 2026-11-04 |

### 2.3. Đánh giá và benchmark

| Tài liệu | Nội dung | Trạng thái | Cập nhật |
| :--- | :--- | :--- | :--- |
| [`EVAL_GUIDE.md`](EVAL_GUIDE.md) | Hướng dẫn gán nhãn, chạy ROC và kiểm định | Đang dùng · VI | 2026-11-15 |
| [`EVAL_THRESHOLDS.md`](EVAL_THRESHOLDS.md) | Ngưỡng heuristic tin nhắn (sinh tự động) | Số liệu chụp · VI | 2026-10-15 |
| [`EVAL_DOMAIN.md`](EVAL_DOMAIN.md) | Ngưỡng scorer domain (sinh tự động) | Số liệu chụp · VI | 2026-10-16 |
| [`BENCHMARK_MESSAGES_INDEPENDENT.md`](BENCHMARK_MESSAGES_INDEPENDENT.md) | Benchmark 80 tin nhắn độc lập | Số liệu chụp · VI | 2026-11-04 |
| [`BENCHMARK_MESSAGES_DEV.md`](BENCHMARK_MESSAGES_DEV.md) | Benchmark tập phát triển 80 mẫu | Số liệu chụp · VI | 2026-11-04 |
| [`BENCHMARK_MESSAGES_HOLDOUT_B.md`](BENCHMARK_MESSAGES_HOLDOUT_B.md) | Benchmark holdout B 40 mẫu | Số liệu chụp · VI | 2026-11-04 |
| [`ADVERSARIAL_STRESS_TEST_REPORT.md`](ADVERSARIAL_STRESS_TEST_REPORT.md) | Kiểm thử đối kháng, jailbreak và fallback LLM | Số liệu chụp · VI | 2026-11-04 |

> Các tài liệu "Số liệu chụp" phản ánh đúng tập dữ liệu, ngày chạy và cấu hình ghi trong từng file.
> Không sửa số liệu tại chỗ; khi chạy lại, tạo báo cáo mới và cập nhật bảng này.

### 2.4. Trust & Safety, phản biện và pháp lý

| Tài liệu | Nội dung | Trạng thái | Cập nhật |
| :--- | :--- | :--- | :--- |
| [`CAI_TIEN_THEO_HOI_DONG.md`](CAI_TIEN_THEO_HOI_DONG.md) | Kết quả cải tiến theo 5 góp ý hội đồng (vòng trước) | Báo cáo vòng trước · VI | 2026-10-15 |
| [`CHECKLIST_TINH_NANG.md`](CHECKLIST_TINH_NANG.md) | Checklist kiểm chứng tính năng theo điểm mạnh / cần cải tiến | Ảnh chụp rà soát · VI | 2026-10-16 |
| [`REBUTTAL_QA.md`](REBUTTAL_QA.md) | Câu hỏi phản biện thường gặp và câu trả lời | Đang dùng · VI | 2026-10-16 |
| [`LEGAL_AND_LICENSE.md`](LEGAL_AND_LICENSE.md) | Ma trận giấy phép và tương thích AGPL-3.0 | Đang dùng · VI | 2026-10-15 |

> `CAI_TIEN_THEO_HOI_DONG.md` là báo cáo của vòng trước. Bản tổng hợp mới nhất cho Vòng Chung kết
> là [`BAO_CAO_CAI_TIEN_CHUNG_KET.md`](BAO_CAO_CAI_TIEN_CHUNG_KET.md).

### 2.5. Hồ sơ nộp bài Vòng Chung kết

| Tài liệu | Nội dung | Trạng thái | Cập nhật |
| :--- | :--- | :--- | :--- |
| [`BAO_CAO_CAI_TIEN_CHUNG_KET.md`](BAO_CAO_CAI_TIEN_CHUNG_KET.md) | Báo cáo cải tiến (bản Markdown nguồn) | Hồ sơ nộp · VI | 2026-11-15 |
| [`BAO_CAO_CAI_TIEN_CHUNG_KET.pdf`](BAO_CAO_CAI_TIEN_CHUNG_KET.pdf) | Bản PDF nộp Chặng 1 | Hồ sơ nộp · VI | 2026-11-15 |
| `_chungket/KHAI_BAO_VA_NOP_BAI_CHUNG_KET.md` | Biểu mẫu nộp bài, khai báo AI/mã nguồn/dữ liệu (tách khỏi git) | Hồ sơ nộp ngoài git · VI | 2026-11-24 |
| [`BAO_CAO_CAI_TIEN_CHUNG_KET.tex`](BAO_CAO_CAI_TIEN_CHUNG_KET.tex) | Mã nguồn LaTeX dựng PDF báo cáo | Nguồn dựng · VI | 2026-11-15 |
| [`so_do_luong_du_lieu.pdf`](so_do_luong_du_lieu.pdf) | Sơ đồ luồng dữ liệu Local / Cloud | Nguồn dựng · VI | 2026-11-15 |

> Bản sao phục vụ trình bày nằm trong `_chungket/` (được `.gitignore`, không đẩy lên GitHub).
> Khi cập nhật báo cáo, sửa tại `docs/` rồi mới đồng bộ sang `_chungket/`.

### 2.6. Tài liệu gốc ngoài `docs/`

| Tài liệu | Nội dung | Trạng thái | Cập nhật |
| :--- | :--- | :--- | :--- |
| [`../README.md`](../README.md) | Giới thiệu, quick start, stack, license | Đang dùng · EN | 2026-11-15 |
| [`../PROJECT_OVERVIEW.md`](../PROJECT_OVERVIEW.md) | Tổng quan tính năng và màn hình | Đang dùng · VI | 2026-11-15 |
| [`../AGENTS.md`](../AGENTS.md) | Quy tắc bắt buộc cho AI agent và người sửa code | Đang dùng · EN | 2026-11-15 |
| [`../frontend/README.md`](../frontend/README.md) | Chạy dev, proxy API và cấu trúc frontend Next.js | Đang dùng · VI | — |
| [`../frontend/AGENTS.md`](../frontend/AGENTS.md) | Quy ước riêng cho Next.js (file được `next dev` tạo lại) | Đang dùng · EN | — |
| [`../puppeteer_host/README.md`](../puppeteer_host/README.md) | Cấu trúc, build và vận hành cụm trình duyệt headless | Đang dùng · VI | — |
| [`../backend/helps/index.md`](../backend/helps/index.md) | Nội dung Trung tâm Hỗ trợ (người dùng cuối) | Đang dùng · VI | — |

---

## 3. Quy ước viết tài liệu

### 3.1. Đặt tên

- Dùng `UPPER_SNAKE_CASE.md`, không dấu cách, không dấu tiếng Việt trong tên file.
- Hậu tố ngày chỉ dùng cho ảnh chụp không sửa lại (`*_YYYYMMDD.md`); tài liệu sống không gắn ngày vào tên.
- Tài liệu nộp bài giữ tên tiếng Việt không dấu đã dùng trong biểu mẫu; **không đổi tên** vì link nộp bài trỏ trực tiếp.

### 3.2. Khung đầu tài liệu

Mọi tài liệu mới bắt đầu bằng H1 và một dòng metadata theo đúng thứ tự:

```markdown
# ShieldCall VN — <Chủ đề>

> **Trạng thái:** đang dùng · **Cập nhật:** YYYY-MM-DD · **Đối tượng:** <người đọc>
```

- Tài liệu tiếng Anh dùng nhãn `Status / Updated / Audience`.
- Trạng thái hợp lệ: `đang dùng` (current), `nháp` (draft), `số liệu chụp` (snapshot), `hồ sơ nộp` (submission), `báo cáo vòng trước` (superseded).
- Chỉ một H1 mỗi file; mục lớn dùng `##`, mục con dùng `###`, không nhảy cấp.

### 3.3. Nội dung và bằng chứng

- Số liệu benchmark phải nêu **tập dữ liệu, ngày chạy, lệnh tái lập**; không suy diễn hoặc làm tròn thành claim tuyệt đối.
- Tài liệu sinh tự động phải ghi rõ script sinh ra nó; sửa tay sẽ bị ghi đè ở lần chạy sau.
- Không đưa mật khẩu, token, PII thật hoặc đường dẫn nội bộ của máy cá nhân vào tài liệu. Dùng placeholder `<...>`.
- Link nội bộ dùng đường dẫn tương đối tới file trong repository; không link tới `_chungket/` hoặc `_minhchung/` (đã gitignore).

### 3.4. Khi thêm hoặc xoá tài liệu

1. Thêm/xoá dòng tương ứng trong mục 2 của file này.
2. Nếu là tài liệu điểm vào, cập nhật bảng Documentation trong [`../README.md`](../README.md).
3. Nếu thay đổi quy trình bắt buộc, cập nhật [`../AGENTS.md`](../AGENTS.md).
4. Chạy kiểm tra link nội bộ trước khi commit.

---

## 4. Tài liệu đã ngừng sử dụng

Các file dưới đây đã bị xoá trong đợt chuẩn hoá 2026-11-15. Lịch sử vẫn còn trong Git.

| Tài liệu cũ | Thay thế bằng |
| :--- | :--- |
| `API.md` (spec Android, port 3000, endpoint cũ) | [`API_REFERENCE.md`](API_REFERENCE.md) + `/api/docs/` |
| `IMPLEMENTATION_SUMMARY.md` (báo cáo tháng 8/2026) | [`ARCHITECTURE.md`](ARCHITECTURE.md), [`TESTING.md`](TESTING.md) |
| `OLLAMA_COMPLETE.md` (báo cáo tháng 8/2026, file không còn tồn tại) | [`SETUP.md`](SETUP.md) mục AI & LLM |
| `IDEAS.md` (brainstorm) | [`../PROJECT_OVERVIEW.md`](../PROJECT_OVERVIEW.md) |
| `PHONE_NUMBER_RISK_20261101.md` (ghi chú một lần) | [`ARCHITECTURE.md`](ARCHITECTURE.md) §2.1, [`REBUTTAL_QA.md`](REBUTTAL_QA.md) Q2 |
