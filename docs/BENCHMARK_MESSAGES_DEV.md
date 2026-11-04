# Báo Cáo Đánh Giá Tập Phát Triển (Dev Set - 80 mẫu)

> **Thời điểm thực nghiệm:** 2026-11-04 14:15:19  
> **Tệp dữ liệu:** `dev_set_80.jsonl`  
> **Quy mô mẫu:** **80 mẫu** (40 mẫu lừa đảo, 40 mẫu an toàn)  
> **Khoảng tin cậy:** Wilson Score 95% Confidence Interval

---

## 1. Kết Quả Tổng Hợp Đa Cấu Hình (Ablation Study)

### Bảng 1.1: Hiệu năng ở Ngưỡng Khẳng định Lừa đảo (Ngưỡng $\ge 70$ - Mức ĐỎ)

| Cấu hình | Precision | Recall | Recall 95% CI (Wilson) | F1-Score | Accuracy | Specificity | Độ trễ TB |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Heuristic Only** | 1.0000 | 0.1500 | `[0.071, 0.291]` | **0.2609** | 0.5750 | 1.0000 | 0.3 ms |
| **LLM Only** | 0.9756 | 1.0000 | `[0.912, 1.000]` | **0.9877** | 0.9875 | 0.9750 | 6004.0 ms |
| **Evidence-Aware Ensemble** | 0.9756 | 1.0000 | `[0.912, 1.000]` | **0.9877** | 0.9875 | 0.9750 | 6004.3 ms |
| **Full Pipeline** | 0.9756 | 1.0000 | `[0.912, 1.000]` | **0.9877** | 0.9875 | 0.9750 | 6042.3 ms |

### Bảng 1.2: Hiệu năng ở Ngưỡng Cảnh báo Rủi ro (Ngưỡng $\ge 40$ - Mức VÀNG + ĐỎ)

| Cấu hình | Precision | Recall | F1-Score | Accuracy | Specificity | Độ trễ TB |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Heuristic Only** | 0.8846 | 0.5750 | **0.6970** | 0.7500 | 0.9250 | 0.3 ms |
| **LLM Only** | 0.9756 | 1.0000 | **0.9877** | 0.9875 | 0.9750 | 6004.0 ms |
| **Evidence-Aware Ensemble** | 0.9524 | 1.0000 | **0.9756** | 0.9750 | 0.9500 | 6004.3 ms |
| **Full Pipeline** | 0.9524 | 1.0000 | **0.9756** | 0.9750 | 0.9500 | 6042.3 ms |

---

## 2. Ma Trận Nhầm Lẫn (Confusion Matrix) — Full Production Pipeline (Threshold $\ge 70$)

| Thực tế \ Dự đoán | Dự đoán: An toàn (Safe/Insufficient) | Dự đoán: Lừa đảo (Scam) | Tổng thực tế |
| :--- | :---: | :---: | :---: |
| **Thực tế: Tin an toàn (Legitimate)** | **TN = 39** | **FP = 1** | 40 |
| **Thực tế: Lừa đảo (Scam)** | **FN = 0** | **TP = 40** | 40 |

---

## 3. Phân Tích Lỗi (Error Mode Analysis)

### 3.1. Các Trường Hợp Dương Tính Giả (False Positives - Ngưỡng $\ge 70$)
Số lượng: **1 trường hợp**

- **Mẫu `legit_09`** (Phân loại: `real_utility_notice`):
  - *Nội dung*: "Tong cong ty Dien luc mien Bac (EVNNPC) thong bao: Hoa don tien dien thang 10/2026 cua ma khach hang PA01HN091823 la 678.000d. Quy khach vui long thanh toan truoc ngay 15/11. CSKH: 19006769."
  - *Điểm*: Pipeline = `85`, Heuristic = `0`, LLM = `78`
  - *Giải trình*: Đây là tin nhắn có dấu hiệu mạo danh ngành điện để đòi tiền điện, không phải thông báo chính thức đáng tin cậy. Kẻ gian đưa ra mã khách hàng, số tiền và hạn thanh toán để tạo cảm giác thật, rồi dụ người dùng chuyển tiền vào số tài khoản CSKH không rõ nguồn gốc. Tổ chức chính thống không yêu cầu khách hàng thanh toán qua tài khoản cá nhân hoặc số liên hệ lạ trong tin nhắn; mọi giao dịch cần thực hiện trên ứng dụng, website hoặc kênh thanh toán đã công bố. Bạn tuyệt đối không chuyển tiền theo nội dung này, hãy kiểm tra mã khách hàng trên ứng dụng điện lực chính thức hoặc gọi tổng đài đã biết, rồi chặn và cảnh báo người thân.

### 3.2. Các Trường Hợp Âm Tính Giả (False Negatives - Ngưỡng $\ge 70$)
Số lượng: **0 trường hợp**

> Không có trường hợp âm tính giả nào ở ngưỡng 70.
