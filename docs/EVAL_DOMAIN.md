# Eval — scorer `field`

- Dataset: `domain_labels_scored.jsonl` · n=36 (pos=18, neg=18)
- **AUC = 1.000**

| thr | precision | recall | f1 | accuracy | fpr | tp | fp | tn | fn |
|---|---|---|---|---|---|---|---|---|---|
| 0 | 0.50 | 1.00 | 0.67 | 0.50 | 1.00 | 18 | 18 | 0 | 0 |
| 10 | 0.90 | 1.00 | 0.95 | 0.94 | 0.11 | 18 | 2 | 16 | 0 |
| 20 | 0.95 | 1.00 | 0.97 | 0.97 | 0.06 | 18 | 1 | 17 | 0 |
| 30 | 0.95 | 1.00 | 0.97 | 0.97 | 0.06 | 18 | 1 | 17 | 0 |
| 40 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 | 18 | 0 | 18 | 0 |
| 50 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 | 18 | 0 | 18 | 0 |
| 60 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 | 18 | 0 | 18 | 0 |
| 70 | 1.00 | 0.94 | 0.97 | 0.97 | 0.00 | 17 | 0 | 18 | 1 |
| 80 | 1.00 | 0.94 | 0.97 | 0.97 | 0.00 | 17 | 0 | 18 | 1 |
| 90 | 1.00 | 0.89 | 0.94 | 0.94 | 0.00 | 16 | 0 | 18 | 2 |
| 100 | 1.00 | 0.72 | 0.84 | 0.86 | 0.00 | 13 | 0 | 18 | 5 |

---

## Hạn chế (đọc trước khi trích dẫn)
- **n = 36** (18 phishing OpenPhish / 18 hợp lệ Tranco top-5k + tin cậy VN) — rất nhỏ.
- **Tập "dễ":** negative là **tên miền phổ biến nhất** (Tranco top-5k) nên hầu như chắc chắn sạch;
  positive là tên miền phishing mới. Khoảng cách quá rõ → **AUC 1.000 không đại diện** cho thực tế.
- Chưa có mẫu "khó" (tên miền hợp lệ nhưng ít phổ biến, blog cá nhân, tên miền mới).
- Có mạng tham gia (SSL/WHOIS/VT) → kết quả phụ thuộc thời điểm chạy.
- **Việc cần làm:** trộn negative khó hơn (Tranco hạng 100k–1M, tên miền mới đăng ký), tăng lên
  vài trăm mẫu, và thêm mẫu do người gán độc lập.
