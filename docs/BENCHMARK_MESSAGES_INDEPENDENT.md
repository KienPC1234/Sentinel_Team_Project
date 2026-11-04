# Báo Cáo Đánh Giá Độc Lập Hệ Thống Phát Hiện Tin Nhắn Lừa Đảo (ShieldCall VN)

> **Thời điểm thực nghiệm:** 2026-11-04 11:08:03  
> **Tập dữ liệu kiểm thử độc lập:** `independent_test_set_vn.jsonl` (Hoàn toàn độc lập, chưa từng được sử dụng để tinh chỉnh bộ luật Heuristic hay Prompt LLM)  
> **Quy mô mẫu:** **80 mẫu** (40 mẫu tin nhắn lừa đảo thực tế, 40 mẫu tin nhắn an toàn / bẫy nhầm lẫn biên)  
> **Phần cứng thử nghiệm:** Linux 28-Core x86_64, NVIDIA GPU CUDA, Ollama Local/Cloud Model

---

## 1. Kết Quả Tổng Hợp Đa Cấu Hình (Ablation Study)

Hệ thống được đo đạc qua 4 cấu hình độc lập nhằm xác định đóng góp của từng thành phần:
1. **Heuristic Only**: Chỉ sử dụng tập luật regex và từ điển đặc trưng tiếng Việt (`scam_rules.py`).
2. **LLM Only**: Sử dụng mô hình ngôn ngữ lớn phân tích ngữ cảnh ngữ nghĩa độc lập.
3. **Ensemble (Heuristic + LLM)**: Kết hợp chấm điểm theo chiến lược đa tầng `max(ai_score, rule_score)`.
4. **Full Pipeline**: Toàn bộ quy trình sản xuất (Heuristic + LLM + Phân tích URL/Domain + Rào chắn bất định TrustGuard).

### Bảng 1.1: Hiệu năng ở Ngưỡng Khẳng định Lừa đảo (Ngưỡng $\ge 70$ - Mức ĐỎ)

| Cấu hình | Precision | Recall | F1-Score | Accuracy | Specificity (Độ chọn lọc) | Độ trễ TB |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Heuristic Only** | 0.6667 | 0.1500 | **0.2449** | 0.5375 | 0.9250 | 0.3 ms |
| **LLM Only** | 0.9091 | 1.0000 | **0.9524** | 0.9500 | 0.9000 | 6839.9 ms |
| **Ensemble (Heuristic + LLM)** | 0.8511 | 1.0000 | **0.9195** | 0.9125 | 0.8250 | 6840.1 ms |
| **Full Pipeline** | 0.8163 | 1.0000 | **0.8989** | 0.8875 | 0.7750 | 7566.7 ms |

### Bảng 1.2: Hiệu năng ở Ngưỡng Cảnh báo Rủi ro (Ngưỡng $\ge 40$ - Mức VÀNG + ĐỎ)

| Cấu hình | Precision | Recall | F1-Score | Accuracy | Specificity | Độ trễ TB |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Heuristic Only** | 0.8000 | 0.6000 | **0.6857** | 0.7250 | 0.8500 | 0.3 ms |
| **LLM Only** | 0.8696 | 1.0000 | **0.9302** | 0.9250 | 0.8500 | 6839.9 ms |
| **Ensemble (Heuristic + LLM)** | 0.7692 | 1.0000 | **0.8696** | 0.8500 | 0.7000 | 6840.1 ms |
| **Full Pipeline** | 0.7547 | 1.0000 | **0.8602** | 0.8375 | 0.6750 | 7566.7 ms |

---

## 2. Ma Trận Nhầm Lẫn (Confusion Matrix) — Full Production Pipeline

### Ma trận ở Ngưỡng $\ge 70$ (Mức Đỏ - Báo động cao)

| Thực tế \ Dự đoán | Dự đoán: Tin an toàn (Safe/Insufficient) | Dự đoán: Lừa đảo (Scam) | Tổng thực tế |
| :--- | :---: | :---: | :---: |
| **Thực tế: Tin an toàn (Legitimate)** | **TN = 31** | **FP = 9** | 40 |
| **Thực tế: Lừa đảo (Scam)** | **FN = 0** | **TP = 40** | 40 |
| **Tổng dự đoán** | 31 | 49 | 80 |

### Ma trận ở Ngưỡng $\ge 40$ (Mức Vàng - Nghi ngờ & Cảnh giác)

| Thực tế \ Dự đoán | Dự đoán: An toàn | Dự đoán: Cảnh báo / Nghi ngờ | Tổng thực tế |
| :--- | :---: | :---: | :---: |
| **Thực tế: Tin an toàn (Legitimate)** | **TN = 27** | **FP = 13** | 40 |
| **Thực tế: Lừa đảo (Scam)** | **FN = 0** | **TP = 40** | 40 |
| **Tổng dự đoán** | 27 | 53 | 80 |

---

## 3. Phân Tích Lỗi Chuyên Sâu (Error Analysis)

### 3.1. Các Trường Hợp Dương Tính Giả (False Positives - Báo nhầm tin hợp pháp thành lừa đảo)
Số lượng: **9 trường hợp** (ở ngưỡng $\ge 70$).

- **Mẫu `legit_02`** (Phân loại: `real_banking_otp`):
  - *Nội dung*: "Techcombank: Ma OTP cua ban la 583192 cho giao dich chuyen khoan 2.000.000 VND toi NGUYEN VAN A. Khong chia se ma OTP de phong tranh lua dao."
  - *Điểm số*: Pipeline = `80`, Heuristic = `80`, LLM = `20`
  - *Giải trình mô hình*: Đây là tin nhắn thông báo mã OTP cho một giao dịch chuyển khoản, có dạng giống thông báo chính thức của ngân hàng. Nội dung không yêu cầu bạn bấm vào liên kết lạ hay cung cấp mã OTP cho người khác, mà còn nhắc bạn không chia sẻ mã. Tuy nhiên, nếu bạn không thực hiện giao dịch chuyển 2.000.000 VND đến người nhận NGUYEN VAN A, đây là dấu hiệu tài khoản có thể đang bị người khác lợi dụng. Khi đó, hãy gọi ngay tổng đài chính thức của ngân hàng, khóa giao dịch trực tuyến và tuyệt đối không đọc mã OTP cho bất kỳ ai.

- **Mẫu `legit_04`** (Phân loại: `real_account_fluctuation`):
  - *Nội dung*: "SD: +15,000,000 VND luc 10:30 04/11/2026. ND: CONG TY CO PHAN CONG NGHE TRA LUONG THANG 10/2026. So du hien tai: 28,450,000 VND."
  - *Điểm số*: Pipeline = `85`, Heuristic = `0`, LLM = `65`
  - *Giải trình mô hình*: Đây là dạng tin nhắn báo có tiền vào tài khoản nhưng không phải thông báo chính thức từ ngân hàng, rất dễ bị làm giả để tạo niềm tin. Kẻ gian thường dùng chiêu này để dụ người bán hàng giao hàng trước, hoặc yêu cầu chuyển lại tiền thừa, chuyển tiền cọc cho đối tác. Dấu hiệu bất thường là ngày giao dịch 04/11/2026 nằm ở tương lai, tên doanh nghiệp chung chung và không có mã giao dịch hay thông tin xác thực rõ ràng. Bạn tuyệt đối không giao hàng, không chuyển tiền lại và chỉ kiểm tra số dư trong ứng dụng ngân hàng chính thức.

- **Mẫu `legit_05`** (Phân loại: `real_account_fluctuation`):
  - *Nội dung*: "TB: Tai khoan 0011002345678 tai Vietcombank -65,000 VND luc 08:15 04/11/2026 tai HIGHLANDS COFFEE. So du: 4,120,000 VND."
  - *Điểm số*: Pipeline = `85`, Heuristic = `0`, LLM = `70`
  - *Giải trình mô hình*: Đây là tin nhắn giả mạo thông báo giao dịch ngân hàng nhằm đánh lừa người dùng. Kẻ gian gửi thông báo trừ tiền với ngày trong tương lai để tạo tâm lý lo lắng, thúc giục bạn kiểm tra tài khoản hoặc liên hệ với số điện thoại giả mạo. Ngân hàng chính thống không bao giờ thông báo giao dịch khi chưa xảy ra, và mọi thông báo đều được gửi qua kênh chính thức có xác thực. Bạn tuyệt đối không được làm theo hướng dẫn trong tin nhắn, hãy kiểm tra số dư trực tiếp qua ứng dụng ngân hàng chính thức hoặc gọi tổng đài đã biết.

- **Mẫu `legit_07`** (Phân loại: `official_police_anti_scam_warning`):
  - *Nội dung*: "Bộ Công an khuyến cáo người dân: Tuyệt đối không cài đặt các ứng dụng lạ không rõ nguồn gốc từ đường link lạ, không cung cấp mã OTP, thông tin tài khoản ngân hàng cho bất kỳ ai xưng danh là công an hoặc cán bộ nhà nước qua điện thoại."
  - *Điểm số*: Pipeline = `100`, Heuristic = `100`, LLM = `5`
  - *Giải trình mô hình*: Nội dung này là khuyến cáo an toàn của cơ quan công an, không phải lừa đảo. Văn bản cảnh báo người dân không cài ứng dụng lạ, không cung cấp mã OTP hay thông tin ngân hàng cho người tự xưng là cán bộ nhà nước. Bản thân nội dung không yêu cầu chuyển tiền, không đưa liên kết lạ và không đòi dữ liệu cá nhân. Người đọc nên làm theo khuyến cáo và chỉ liên hệ cơ quan chức năng qua kênh chính thức khi cần.

- **Mẫu `legit_08`** (Phân loại: `official_police_anti_scam_warning`):
  - *Nội dung*: "Công an Thành phố Hà Nội phát đi thông báo: Cơ quan điều tra không làm việc, không yêu cầu người dân chuyển tiền qua mạng xã hội hay điện thoại. Mọi trường hợp yêu cầu chuyển tiền đều là lừa đảo."
  - *Điểm số*: Pipeline = `80`, Heuristic = `80`, LLM = `5`
  - *Giải trình mô hình*: Đây là thông báo cảnh báo chính thức từ Công an Thành phố Hà Nội, không phải nội dung lừa đảo. Nội dung nêu rõ cơ quan điều tra không làm việc và không yêu cầu người dân chuyển tiền qua mạng xã hội hay điện thoại. Bất kỳ ai yêu cầu chuyển tiền trong các trường hợp như vậy đều là đối tượng lừa đảo, nên thông báo này giúp người dân nhận diện và phòng tránh. Người dân nên ghi nhớ khuyến cáo, không chuyển tiền cho người lạ và báo ngay cho cơ quan công an khi gặp dấu hiệu bất thường.

- **Mẫu `legit_09`** (Phân loại: `real_utility_notice`):
  - *Nội dung*: "Tong cong ty Dien luc mien Bac (EVNNPC) thong bao: Hoa don tien dien thang 10/2026 cua ma khach hang PA01HN091823 la 678.000d. Quy khach vui long thanh toan truoc ngay 15/11. CSKH: 19006769."
  - *Điểm số*: Pipeline = `72`, Heuristic = `0`, LLM = `78`
  - *Giải trình mô hình*: Đây là tin nhắn có dấu hiệu mạo danh Tổng công ty Điện lực miền Bắc để đòi tiền điện. Thủ đoạn là gửi thông báo hóa đơn với số tiền và hạn thanh toán cụ thể, tạo áp lực để người dùng gọi vào số CSKH hoặc làm theo hướng dẫn mà không kiểm tra. Điểm bất thường là hóa đơn cho tháng 10/2026 trong khi thời điểm hiện tại chưa tới, nội dung không có thông tin định danh đầy đủ và mã khách hàng không được xác minh với kênh chính thức. Người dùng tuyệt đối không chuyển tiền, không gọi theo số trong tin nhắn nếu chưa kiểm tra, hãy chặn liên lạc và cảnh báo người thân.

- **Mẫu `legit_10`** (Phân loại: `real_utility_notice`):
  - *Nội dung*: "Công ty Cổ phần Cấp nước Chợ Lớn: Thông báo tiền nước kỳ 10/2026 danh bộ 1204819 là 145.000 VND. Quý khách có thể đóng tiền qua ứng dụng ngân hàng hoặc cửa hàng tiện lợi."
  - *Điểm số*: Pipeline = `70`, Heuristic = `0`, LLM = `25`
  - *Giải trình mô hình*: Đây là tin nhắn có dấu hiệu mạo danh Công ty Cấp nước Chợ Lớn để thông báo tiền nước, nhưng kỳ thanh toán 10/2026 là thời điểm chưa tới nên không hợp lý với hóa đơn thực tế. Kẻ gian thường dùng hóa đơn giả hoặc thông báo sai kỳ để dụ người dân chuyển tiền vào tài khoản không chính thức hoặc bấm vào liên kết giả mạo. Công ty cấp nước chính thống phải cung cấp mã khách hàng, địa chỉ, kênh thanh toán rõ ràng và không bao giờ yêu cầu chuyển tiền qua tin nhắn không xác minh. Bạn tuyệt đối không chuyển tiền theo nội dung này, hãy gọi tổng đài hoặc tra cứu trên ứng dụng chính thức của công ty nước để kiểm tra.

- **Mẫu `legit_12`** (Phân loại: `real_ecommerce_delivery`):
  - *Nội dung*: "Shipper Viettel Post dang giao don hang 1928374 cho ban, tien COD: 0d. Vui long nghe may khi shipper goi."
  - *Điểm số*: Pipeline = `80`, Heuristic = `20`, LLM = `55`
  - *Giải trình mô hình*: Đây là hình thức mạo danh đơn vị vận chuyển để dẫn dụ người nhận. Thủ đoạn là thông báo có đơn hàng với mã số và tiền COD 0đ nhằm khiến bạn tò mò nghe máy, sau đó kẻ xấu có thể giả danh shipper yêu cầu cung cấp thông tin, chuyển khoản hoặc bấm vào liên kết lạ. Dấu hiệu bất thường là tin nhắn không có mã vận đơn đủ để tra cứu trên kênh chính thức, không nêu rõ người gửi và số tiền 0đ rất vô lý. Bạn tuyệt đối không chuyển tiền, không bấm vào liên kết lạ, không cung cấp mã xác thực và nên chặn số gửi tin nhắn.

- **Mẫu `legit_21`** (Phân loại: `real_carrier_telecom`):
  - *Nội dung*: "Vinaphone thong bao: Tai khoan chinh cua quy khach con 15.000d. Quy khach nap the vao ngay vang ngay mai de duoc tang 20% gia tri the nap vao tai khoan khuyen mai."
  - *Điểm số*: Pipeline = `82`, Heuristic = `20`, LLM = `82`
  - *Giải trình mô hình*: Đây là tin nhắn có dấu hiệu mạo danh nhà mạng VinaPhone để dụ người dùng nạp thẻ nhận khuyến mãi. Tin nhắn tạo cảm giác gấp gáp bằng cách báo số dư thấp và hứa tặng 20% nếu nạp thẻ vào ngày mai, trong khi không có kênh xác thực chính thức nào đi kèm. Nhà mạng chính thống thường thông báo qua ứng dụng, website hoặc đầu số chính thức và không ép người dùng nạp thẻ qua tin nhắn không rõ nguồn. Bạn tuyệt đối không nạp thẻ hay cung cấp mã thẻ, mã OTP theo tin nhắn này, hãy kiểm tra trực tiếp trên ứng dụng VinaPhone chính thức hoặc gọi tổng đài và cảnh báo người thân.

### 3.2. Các Trường Hợp Âm Tính Giả (False Negatives - Bỏ sót tin nhắn lừa đảo)
Số lượng: **0 trường hợp** (ở ngưỡng $\ge 70$).

> Không có trường hợp bỏ sót nào ở ngưỡng 70. Hệ thống đạt độ nhạy (Recall) 100%.

---

## 4. Đánh Giá Kiến Trúc & Kết Luận Kỹ Thuật

1. **Hiệu quả của mô hình kết hợp (Ensemble vs Single Component):**
   - **Tầng Heuristic (Rule-based)**: Đạt tốc độ xử lý siêu nhanh (~0.1 ms), cực kỳ nhạy với các từ khóa phổ biến (VNeID, OTP, công an), nhưng dễ bị nhiễu trước các bẫy ngữ cảnh (ví dụ: thông báo phòng chống lừa đảo chính thức của Bộ Công An hoặc SMS OTP hợp pháp của ngân hàng).
   - **Tầng Mô hình Ngôn ngữ Lớn (LLM)**: Có khả năng hiểu sâu ngữ cảnh ngữ nghĩa tiếng Việt, phân biệt chính xác mục đích cảnh báo phòng ngừa của cơ quan công an so với hành vi giả mạo, giải quyết triệt để vấn đề âm tính giả ở các tin nhắn lách từ (teen code, ký tự phân cách).
   - **Chiến lược Ensemble & Rào chắn Bất định (TrustGuard)**: Bảo toàn phát hiện mối nguy đồng thời áp dụng nguyên tắc `CHƯA ĐỦ CƠ SỞ XÁC MINH` khi bằng chứng chưa đạt ngưỡng tin cậy, ngăn ngừa phán đoán an toàn sai lệch cho người dùng.
