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
- **AUC (heuristic mở rộng): 0.950**
- AUC (baseline khoá cơ sở — 6 từ khoá): 0.655
- Ngưỡng tốt nhất theo F1: **10** (precision 0.90, recall 0.96, F1 0.92)
- Ngưỡng Youden-J: **20**

## 3. Precision / Recall / F1 theo ngưỡng (dự đoán 'lừa đảo' nếu điểm ≥ ngưỡng)

| Ngưỡng | Precision | Recall | F1 | Accuracy | FPR | TP | FP | TN | FN |
|---|---|---|---|---|---|---|---|---|---|
| 0 | 0.51 | 1.00 | 0.68 | 0.51 | 1.00 | 45 | 43 | 0 | 0 |
| 10 ⭐ | 0.90 | 0.96 | 0.92 | 0.92 | 0.12 | 43 | 5 | 38 | 2 |
| 20 | 0.90 | 0.96 | 0.92 | 0.92 | 0.12 | 43 | 5 | 38 | 2 |
| 30 | 0.94 | 0.76 | 0.84 | 0.85 | 0.05 | 34 | 2 | 41 | 11 |
| 40 | 0.94 | 0.76 | 0.84 | 0.85 | 0.05 | 34 | 2 | 41 | 11 |
| 50 | 1.00 | 0.38 | 0.55 | 0.68 | 0.00 | 17 | 0 | 43 | 28 |
| 60 | 1.00 | 0.38 | 0.55 | 0.68 | 0.00 | 17 | 0 | 43 | 28 |
| 70 | 1.00 | 0.09 | 0.16 | 0.53 | 0.00 | 4 | 0 | 43 | 41 |
| 80 | 1.00 | 0.09 | 0.16 | 0.53 | 0.00 | 4 | 0 | 43 | 41 |
| 90 | 1.00 | 0.04 | 0.09 | 0.51 | 0.00 | 2 | 0 | 43 | 43 |
| 100 | 1.00 | 0.04 | 0.09 | 0.51 | 0.00 | 2 | 0 | 43 | 43 |

## 4. Điểm vận hành hiện tại của hệ thống (ngưỡng vùng xám 10 / đáng ngờ 40 / cao 70)

| Ngưỡng | Precision | Recall | F1 | Accuracy | FPR |
|---|---|---|---|---|---|
| 10 | 0.90 | 0.96 | 0.92 | 0.92 | 0.12 |
| 40 | 0.94 | 0.76 | 0.84 | 0.85 | 0.05 |
| 70 | 1.00 | 0.09 | 0.16 | 0.53 | 0.00 |

## 5. Lỗi minh bạch (ngưỡng 40)
- **Dương tính giả (FP)** — tin hợp lệ bị gắn cờ (2):
  - “Mã xác thực đăng nhập của bạn là 482913, không chia sẻ cho bất kỳ ai.”
  - “Chị chuyển khoản tiền điện giúp em với, em gửi stk sau nhé.”
- **Âm tính giả (FN)** — tin lừa đảo bị bỏ sót (11):
  - “Tài khoản ngân hàng của bạn bị khóa, vui lòng bấm vào link xác minh lại: vcb-xacminh.top”
  - “Chị ơi em là shipper, đơn của chị cần thanh toán thêm phí giao hàng, chuyển vào STK này.”
  - “Tài khoản Facebook của em bị hack và đang nhắn vay tiền mọi người, mọi người đừng chuyển nhé.”
  - “Cơ quan điều tra thông báo bạn liên quan đường dây rửa tiền, nộp tiền bảo lãnh để tại ngoại.”
  - “Số điện thoại của bạn chưa định danh SIM chính chủ, sẽ bị khóa sau 24h, bấm link xác nhận.”
  - “Quý khách được mời tham gia nhóm đầu tư chứng khoán quốc tế, lợi nhuận khủng, rút tiền dễ.”
  - “Tôi là cán bộ thuế, yêu cầu cung cấp CCCD để hoàn thuế online cho bạn.”
  - “Chị ơi em bị kẹt tiền, cho em vay ít tiền, em hứa trả trong tuần này.”
  - “Anh có thể giúp em một khoản nhỏ không, em đang rất cần, lát em trả.”
  - “Nạp thẻ game giúp em nhé, em gửi mệnh giá sau.”
  - “Chúc mừng quý khách đã may mắn nhận giải đặc biệt, liên hệ ngay để nhận thưởng.”

## 6. Khuyến nghị
- Giữ **3 ngưỡng guardrail (10/40/70)** cho phân loại đa mức (vùng xám 10–39 vẫn cần xác minh).
- Với **chế độ cảnh báo nhị phân**, ngưỡng 10 cho F1 cao nhất trên tập này (0.92);
  ngưỡng Youden-J là 20. Không đủ cơ sở để thay đổi ngưỡng production từ tập nhỏ này.
- Dương tính giả chủ yếu là **tin thật chứa từ khoá** (VD OTP thật, nhờ chuyển khoản) — hệ thống
  xử lý bằng nhãn 'cần xác minh' thay vì khẳng định lừa đảo, giảm hệ quả FP.
- Việc mở rộng từ điển VN (6 khoá → 37 mẫu) đưa AUC từ **0.655 → 0.950**
  — đây là kết quả chính, có thể tái lập bằng script này.
- Việc tiếp theo: mở rộng tập nhãn (nhiều người gán, có kiểm định), thêm trọng số theo mức độ dấu hiệu,
  và đánh giá cả tầng AI (faithfulness/hallucination) — hiện **chưa** công bố vì chưa đủ dữ liệu.
