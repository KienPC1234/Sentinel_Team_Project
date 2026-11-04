# Báo Cáo Đánh Giá Tập Kiểm Thử Độc Lập Thứ Hai (Holdout Set B - 40 mẫu)

> **Thời điểm thực nghiệm:** 2026-11-04 14:07:17  
> **Tệp dữ liệu:** `holdout_test_set_b.jsonl`  
> **Quy mô mẫu:** **40 mẫu** (20 mẫu lừa đảo, 20 mẫu an toàn)  
> **Khoảng tin cậy:** Wilson Score 95% Confidence Interval

---

## 1. Kết Quả Tổng Hợp Đa Cấu Hình (Ablation Study)

### Bảng 1.1: Hiệu năng ở Ngưỡng Khẳng định Lừa đảo (Ngưỡng $\ge 70$ - Mức ĐỎ)

| Cấu hình | Precision | Recall | Recall 95% CI (Wilson) | F1-Score | Accuracy | Specificity | Độ trễ TB |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Heuristic Only** | 0.7500 | 0.1500 | `[0.052, 0.360]` | **0.2500** | 0.5500 | 0.9500 | 0.4 ms |
| **LLM Only** | 1.0000 | 1.0000 | `[0.839, 1.000]` | **1.0000** | 1.0000 | 1.0000 | 5915.0 ms |
| **Evidence-Aware Ensemble** | 1.0000 | 1.0000 | `[0.839, 1.000]` | **1.0000** | 1.0000 | 1.0000 | 5915.3 ms |
| **Full Pipeline** | 1.0000 | 1.0000 | `[0.839, 1.000]` | **1.0000** | 1.0000 | 1.0000 | 6479.9 ms |

### Bảng 1.2: Hiệu năng ở Ngưỡng Cảnh báo Rủi ro (Ngưỡng $\ge 40$ - Mức VÀNG + ĐỎ)

| Cấu hình | Precision | Recall | F1-Score | Accuracy | Specificity | Độ trễ TB |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Heuristic Only** | 0.8182 | 0.4500 | **0.5806** | 0.6750 | 0.9000 | 0.4 ms |
| **LLM Only** | 1.0000 | 1.0000 | **1.0000** | 1.0000 | 1.0000 | 5915.0 ms |
| **Evidence-Aware Ensemble** | 1.0000 | 1.0000 | **1.0000** | 1.0000 | 1.0000 | 5915.3 ms |
| **Full Pipeline** | 1.0000 | 1.0000 | **1.0000** | 1.0000 | 1.0000 | 6479.9 ms |

---

## 2. Ma Trận Nhầm Lẫn (Confusion Matrix) — Full Production Pipeline (Threshold $\ge 70$)

| Thực tế \ Dự đoán | Dự đoán: An toàn (Safe/Insufficient) | Dự đoán: Lừa đảo (Scam) | Tổng thực tế |
| :--- | :---: | :---: | :---: |
| **Thực tế: Tin an toàn (Legitimate)** | **TN = 20** | **FP = 0** | 20 |
| **Thực tế: Lừa đảo (Scam)** | **FN = 0** | **TP = 20** | 20 |

---

## 3. Phân Tích Lỗi (Error Mode Analysis)

### 3.1. Các Trường Hợp Dương Tính Giả (False Positives - Ngưỡng $\ge 70$)
Số lượng: **0 trường hợp**

> Không có trường hợp dương tính giả nào ở ngưỡng 70. Hệ thống đạt độ đặc hiệu (Specificity) 100%.

### 3.2. Các Trường Hợp Âm Tính Giả (False Negatives - Ngưỡng $\ge 70$)
Số lượng: **0 trường hợp**

> Không có trường hợp âm tính giả nào ở ngưỡng 70.
