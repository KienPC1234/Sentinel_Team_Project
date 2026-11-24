# Đánh giá & tinh chỉnh ngưỡng — Tầng heuristic phát hiện lừa đảo (VN)

> Sinh tự động bởi `backend/scripts/eval/evaluate_thresholds.py`.

> **Phạm vi:** chỉ tầng LUẬT heuristic (`api/utils/scam_rules.py`), tách khỏi AI/network để tái lập.
> Đây là **tập chuẩn nhỏ, nội bộ** (không phải benchmark công khai).


## 1. Tập dữ liệu
- Tổng mẫu: **88** (45 lừa đảo / 43 hợp lệ).
- Nguồn nhãn: đội dự án gán thủ công theo chiến thuật; file `backend/scripts/eval/scam_messages_vn.jsonl`.
- Hạn chế: mẫu nhỏ; một người gán nhãn (chưa có inter-annotator agreement).
- **Cảnh báo thiên lệch (liêm chính):** cùng đội dự án vừa biên soạn từ điển dấu hiệu vừa tạo tập nhãn,
  nên điểm số **có thể lạc quan hơn** thực tế. Tập nhãn cần được bổ sung bởi người độc lập và
  mẫu thu thập từ dữ liệu thật trước khi coi là benchmark.

## 2. Kết quả tổng hợp
- **AUC (heuristic mở rộng): 0.959**
- AUC (baseline khoá cơ sở — 6 từ khoá): 0.655
- Ngưỡng tốt nhất theo F1: **10** (precision 0.88, recall 0.96, F1 0.91)
- Ngưỡng Youden-J: **20**

## 3. Precision / Recall / F1 theo ngưỡng (dự đoán 'lừa đảo' nếu điểm ≥ ngưỡng)

| Ngưỡng | Precision | Recall | F1 | Accuracy | FPR | TP | FP | TN | FN |
|---|---|---|---|---|---|---|---|---|---|
| 0 | 0.51 | 1.00 | 0.68 | 0.51 | 1.00 | 45 | 43 | 0 | 0 |
| 10 ⭐ | 0.88 | 0.96 | 0.91 | 0.91 | 0.14 | 43 | 6 | 37 | 2 |
| 20 | 0.88 | 0.96 | 0.91 | 0.91 | 0.14 | 43 | 6 | 37 | 2 |
| 30 | 1.00 | 0.73 | 0.85 | 0.86 | 0.00 | 33 | 0 | 43 | 12 |
| 40 | 1.00 | 0.73 | 0.85 | 0.86 | 0.00 | 33 | 0 | 43 | 12 |
| 50 | 1.00 | 0.31 | 0.47 | 0.65 | 0.00 | 14 | 0 | 43 | 31 |
| 60 | 1.00 | 0.31 | 0.47 | 0.65 | 0.00 | 14 | 0 | 43 | 31 |
| 70 | 1.00 | 0.02 | 0.04 | 0.50 | 0.00 | 1 | 0 | 43 | 44 |
| 80 | 1.00 | 0.02 | 0.04 | 0.50 | 0.00 | 1 | 0 | 43 | 44 |
| 90 | 1.00 | 0.02 | 0.04 | 0.50 | 0.00 | 1 | 0 | 43 | 44 |
| 100 | 1.00 | 0.02 | 0.04 | 0.50 | 0.00 | 1 | 0 | 43 | 44 |

## 4. Điểm vận hành hiện tại của hệ thống (ngưỡng vùng xám 10 / đáng ngờ 40 / cao 70)

| Ngưỡng | Precision | Recall | F1 | Accuracy | FPR |
|---|---|---|---|---|---|
| 10 | 0.88 | 0.96 | 0.91 | 0.91 | 0.14 |
| 40 | 1.00 | 0.73 | 0.85 | 0.86 | 0.00 |
| 70 | 1.00 | 0.02 | 0.04 | 0.50 | 0.00 |

## 5. Lỗi minh bạch (ngưỡng 40)
- **Dương tính giả (FP)** — tin hợp lệ bị gắn cờ (0):
- **Âm tính giả (FN)** — tin lừa đảo bị bỏ sót (12):
  - “Thông báo: tài khoản quý khách có giao dịch bất thường, cung cấp mã OTP để hủy giao dịch.”
  - “Chị ơi em là shipper, đơn của chị cần thanh toán thêm phí giao hàng, chuyển vào STK này.”
  - “Tài khoản Facebook của em bị hack và đang nhắn vay tiền mọi người, mọi người đừng chuyển nhé.”
  - “Mã OTP của bạn là 123456, vui lòng đọc lại cho nhân viên ngân hàng để xác minh.”
  - “Số điện thoại của bạn chưa định danh SIM chính chủ, sẽ bị khóa sau 24h, bấm link xác nhận.”
  - “Quý khách được mời tham gia nhóm đầu tư chứng khoán quốc tế, lợi nhuận khủng, rút tiền dễ.”
  - “Link nhận thưởng trúng thưởng iPhone, nhập thông tin thẻ để nhận quà.”
  - “Tài khoản của bạn sẽ bị phong tỏa, nộp tiền để mở khóa ngay lập tức.”
  - “Chị ơi em bị kẹt tiền, cho em vay ít tiền, em hứa trả trong tuần này.”
  - “Anh có thể giúp em một khoản nhỏ không, em đang rất cần, lát em trả.”
  - “Nạp thẻ game giúp em nhé, em gửi mệnh giá sau.”
  - “Chúc mừng quý khách đã may mắn nhận giải đặc biệt, liên hệ ngay để nhận thưởng.”

## 6. Khuyến nghị
- Giữ **3 ngưỡng guardrail (10/40/70)** cho phân loại đa mức (vùng xám 10–39 vẫn cần xác minh).
- Với **chế độ cảnh báo nhị phân**, ngưỡng 10 cho F1 cao nhất trên tập này (0.91);
  ngưỡng Youden-J là 20. Không đủ cơ sở để thay đổi ngưỡng production từ tập nhỏ này.
- Dương tính giả chủ yếu là **tin thật chứa từ khoá** (VD OTP thật, nhờ chuyển khoản) — hệ thống
  xử lý bằng nhãn 'cần xác minh' thay vì khẳng định lừa đảo, giảm hệ quả FP.
- Việc mở rộng từ điển VN (6 khoá → 39 mẫu) đưa AUC từ **0.655 → 0.959**
  — đây là kết quả chính, có thể tái lập bằng script này.
- Việc tiếp theo: mở rộng tập nhãn (nhiều người gán, có kiểm định), thêm trọng số theo mức độ dấu hiệu,
  và đánh giá cả tầng AI (faithfulness/hallucination) — hiện **chưa** công bố vì chưa đủ dữ liệu.
