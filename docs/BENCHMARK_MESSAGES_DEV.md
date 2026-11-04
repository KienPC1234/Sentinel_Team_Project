# Báo Cáo Đánh Giá Tập Phát Triển (Dev Set - 80 mẫu)

> **Thời điểm thực nghiệm:** 2026-11-04 11:25:49  
> **Tệp dữ liệu:** `dev_set_80.jsonl`  
> **Quy mô mẫu:** **80 mẫu** (40 mẫu lừa đảo, 40 mẫu an toàn)  
> **Khoảng tin cậy:** Wilson Score 95% Confidence Interval

---

## 1. Kết Quả Tổng Hợp Đa Cấu Hình (Ablation Study)

### Bảng 1.1: Hiệu năng ở Ngưỡng Khẳng định Lừa đảo (Ngưỡng $\ge 70$ - Mức ĐỎ)

| Cấu hình | Precision | Recall | Recall 95% CI (Wilson) | F1-Score | Accuracy | Specificity | Độ trễ TB |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Heuristic Only** | 1.0000 | 0.1500 | `[0.071, 0.291]` | **0.2609** | 0.5750 | 1.0000 | 0.3 ms |
| **LLM Only** | 1.0000 | 1.0000 | `[0.912, 1.000]` | **1.0000** | 1.0000 | 1.0000 | 5556.8 ms |
| **Calibrated Ensemble** | 1.0000 | 1.0000 | `[0.912, 1.000]` | **1.0000** | 1.0000 | 1.0000 | 5557.1 ms |
| **Full Pipeline** | 1.0000 | 1.0000 | `[0.912, 1.000]` | **1.0000** | 1.0000 | 1.0000 | 5155.7 ms |

### Bảng 1.2: Hiệu năng ở Ngưỡng Cảnh báo Rủi ro (Ngưỡng $\ge 40$ - Mức VÀNG + ĐỎ)

| Cấu hình | Precision | Recall | F1-Score | Accuracy | Specificity | Độ trễ TB |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Heuristic Only** | 0.8846 | 0.5750 | **0.6970** | 0.7500 | 0.9250 | 0.3 ms |
| **LLM Only** | 1.0000 | 1.0000 | **1.0000** | 1.0000 | 1.0000 | 5556.8 ms |
| **Calibrated Ensemble** | 1.0000 | 1.0000 | **1.0000** | 1.0000 | 1.0000 | 5557.1 ms |
| **Full Pipeline** | 1.0000 | 1.0000 | **1.0000** | 1.0000 | 1.0000 | 5155.7 ms |

---

## 2. Ma Trận Nhầm Lẫn (Confusion Matrix) — Full Production Pipeline (Threshold $\ge 70$)

| Thực tế \ Dự đoán | Dự đoán: An toàn (Safe/Insufficient) | Dự đoán: Lừa đảo (Scam) | Tổng thực tế |
| :--- | :---: | :---: | :---: |
| **Thực tế: Tin an toàn (Legitimate)** | **TN = 40** | **FP = 0** | 40 |
| **Thực tế: Lừa đảo (Scam)** | **FN = 0** | **TP = 40** | 40 |

---

## 3. Phân Tích Lỗi (Error Mode Analysis)

### 3.1. Các Trường Hợp Dương Tính Giả (False Positives - Ngưỡng $\ge 70$)
Số lượng: **0 trường hợp**

> Không có trường hợp dương tính giả nào ở ngưỡng 70. Hệ thống đạt độ đặc hiệu (Specificity) 100%.

### 3.2. Các Trường Hợp Âm Tính Giả (False Negatives - Ngưỡng $\ge 70$)
Số lượng: **0 trường hợp**

> Không có trường hợp âm tính giả nào ở ngưỡng 70.
