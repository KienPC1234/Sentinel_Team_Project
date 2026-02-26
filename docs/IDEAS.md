# ShieldCall VN – Ý tưởng phát triển sản phẩm (brainstorm)

Tài liệu này chỉ mang tính chất brainstorm, giúp team có kho ý tưởng để chọn lọc cho các phase tiếp theo.

---

## 1. Trải nghiệm người dùng & UI/UX

1. **Onboarding tương tác cho user mới**  
   - Hướng dẫn từng bước cách sử dụng 5 chế độ scan (số điện thoại, tin nhắn, website, tài khoản ngân hàng, QR/file).  
   - Kèm ví dụ thực tế và cảnh báo phổ biến.

2. **Dashboard cá nhân hoá**  
   - Hiển thị lịch sử scan, cảnh báo gần đây, các "thói quen rủi ro" (vd: thường xuyên click link không rõ nguồn gốc).  
   - Gợi ý hành động tiếp theo (bật cảnh báo, học thêm bài trong Learn Hub...).

3. **Notification center trên web**  
   - Trung tâm thông báo: kết quả scan chậm, cập nhật xu hướng lừa đảo mới, cảnh báo theo khu vực.  
   - Hỗ trợ in-browser notification (Web Push) cho user opt-in.

4. **Dark mode + chế độ chống mỏi mắt**  
   - Thêm theme tối, font to hơn cho người cao tuổi.  
   - Chế độ "focus" khi scan khẩn cấp (giảm distraction, chỉ hiển thị bước quan trọng).

5. **Hỗ trợ đa ngôn ngữ (VN/EN, ưu tiên VN)**  
   - Giúp mở rộng đối tượng user và partner quốc tế.  
   - Cấu trúc i18n sẵn trong Django templates + API response.

---

## 2. Tính năng Scan & Phân tích nâng cao

1. **Scan realtime cho cuộc gọi đang diễn ra (Call Guardian)**  
   - User nhập số hoặc chọn contact khi đang nghe máy; hệ thống trả kết quả rủi ro gần realtime.  
   - Kết hợp pattern từ nội dung cuộc gọi (nếu mobile app gửi transcript) và dữ liệu cộng đồng.

2. **Scan lịch sử SMS/OTT (Zalo, Messenger) dạng batch**  
   - Cho phép upload export tin nhắn hoặc kết nối API từ mobile app → backend phân tích toàn bộ lịch sử.  
   - Trả ra danh sách thread/tin nhắn có nguy cơ cao, kèm lý do.

3. **Phân tích combo nhiều thực thể**  
   - Một phiên scan có thể chứa: số điện thoại + link + số tài khoản + ảnh chụp màn hình.  
   - Engine phân tích mối liên hệ giữa các thực thể để đánh giá rủi ro tổng thể (risk profile).

4. **Watchlist cá nhân hoá**  
   - User lưu các số/tài khoản/web muốn "theo dõi" (vd: số tổng đài ngân hàng, tài khoản người thân).  
   - Khi các thực thể này xuất hiện trong cảnh báo cộng đồng, hệ thống gửi notification.

5. **Scan định kỳ (scheduled scans)**  
   - User đăng ký job định kỳ: kiểm tra lại blacklist, domain hoặc danh sách tài khoản quan trọng.  
   - Kết quả được gửi qua email hoặc notification trên web/app.

---

## 3. AI & Phân tích thông minh

1. **AI giải thích kết quả scan cho người không rành công nghệ**  
   - Sau khi scan, AI tóm tắt theo dạng "ngôn ngữ đời thường", giải thích tại sao nguy hiểm, nên làm gì tiếp.  
   - Có thể chọn mức độ chi tiết: cơ bản / nâng cao.

2. **AI mô phỏng kịch bản lừa đảo (Scam Simulator)**  
   - User có thể mô tả tình huống đang gặp, AI dựng lại kịch bản của scammer, chỉ ra các "red flag".  
   - Dùng để đào tạo nội bộ doanh nghiệp hoặc giáo dục người thân.

3. **AI gợi ý mẫu tin nhắn / phản hồi an toàn**  
   - Khi nhận tin nhắn nghi ngờ, user có thể nhờ hệ thống gợi ý cách trả lời an toàn (hoặc không trả lời).  
   - Gợi ý nội dung báo cáo cho công an/ngân hàng.

4. **Phân tích hành vi (behavioural insights)**  
   - Trên dashboard admin: thống kê các mẫu hành vi thường gặp của nạn nhân (từ dữ liệu ẩn danh).  
   - Hỗ trợ team product điều chỉnh UX, nội dung cảnh báo.

5. **AI hỗ trợ người cao tuổi**  
   - Giao diện "Senior Mode" với trợ lý ảo nói tiếng Việt đơn giản, hướng dẫn từng bước.  
   - Có thể kết hợp TTS (text-to-speech) để đọc to cảnh báo.

---

## 4. Cộng đồng & Giáo dục

1. **Hệ thống huy hiệu (badge) cho cộng đồng**  
   - Người dùng báo cáo scam hữu ích được gắn badge (vd: Người gác cổng, Thợ săn scam…).  
   - Xây dựng động lực đóng góp dữ liệu chất lượng.

2. **Leaderboard đóng góp**  
   - Bảng xếp hạng theo số báo cáo hợp lệ, số comment hữu ích, số scam được ngăn chặn.  
   - Có thể dùng cho chiến dịch truyền thông.

3. **Learn Hub theo lộ trình (learning path)**  
   - Chia bài học thành các lộ trình: người cao tuổi, sinh viên, nhân viên ngân hàng, nhân viên chăm sóc KH…  
   - Mỗi lộ trình có bài quiz nhỏ để kiểm tra kiến thức.

4. **Kho tình huống thực tế (case library)**  
   - Tập hợp các case study lừa đảo thật (ẩn danh thông tin nhạy cảm), phân tích chi tiết.  
   - Cho phép search theo từ khoá: "mạo danh công an", "đầu tư đa cấp", "mã OTP"…

5. **Q&A cộng đồng có kiểm duyệt**  
   - Khu vực user đặt câu hỏi về các tình huống đang gặp; mod hoặc các member uy tín trả lời.  
   - Tích hợp hệ thống gắn nhãn chất lượng câu trả lời.

---

## 5. Niềm tin & Danh tiếng (Trust Layer)

1. **Hồ sơ uy tín (Reputation Profile) cho số/đơn vị**  
   - Với những số/bên được nhiều người xác nhận là uy tín (ngân hàng, doanh nghiệp), hiển thị dấu xác minh rõ ràng.  
   - Ngược lại, số/bên bị báo cáo scam nhiều sẽ bị đánh dấu nổi bật.

2. **Verification cho doanh nghiệp/tổ chức**  
   - Doanh nghiệp có thể đăng ký tài khoản "Verified" và cung cấp danh sách số/tài khoản/channels chính thức.  
   - Hệ thống check chéo với dữ liệu người dùng báo cáo.

3. **"Trust Score" cá nhân hóa cho user**  
   - Không phải điểm uy tín của user, mà là mức độ an toàn của bối cảnh họ thường xuyên tương tác (số liên hệ, kênh giao dịch...).  
   - Gợi ý hành động để "nâng trust" (vd: xác thực lại số hotline ngân hàng, cập nhật danh sách whitelist...).

4. **Báo cáo tổng hợp cho cơ quan quản lý**  
   - Export report (ẩn danh) về xu hướng scam theo tỉnh/thành, loại hình, kênh.  
   - Có thể là sản phẩm B2G ở phase sau.

---

## 6. B2B & Tích hợp

1. **API / SDK cho đối tác (Bank/Telco/Fintech)**  
   - Cung cấp endpoint check-risk theo thời gian thực để tích hợp vào app/web của đối tác.  
   - Plan: giới hạn rate, cấp API key, dashboard cho partner.

2. **Browser Extension (Chrome/Edge) cho người dùng cuối**  
   - Tự động highlight link/nghi ngờ scam trên web/email.  
   - Gửi dữ liệu về backend scan domain theo thời gian thực.

3. **Webhook cho doanh nghiệp**  
   - Khi hệ thống phát hiện scam liên quan đến thương hiệu của doanh nghiệp, gửi webhook để họ phản ứng nhanh (chặn số, cảnh báo khách hàng...).

4. **Plugin cho helpdesk/CRM**  
   - Tích hợp với Zendesk/Freshdesk hoặc hệ thống nội bộ để agent có thể scan nhanh số điện thoại/tài khoản ngay trong màn hình chăm sóc khách hàng.

---

## 7. Vận hành & Công cụ nội bộ

1. **Admin dashboard nâng cao**  
   - Thống kê theo ngày/tuần/tháng: số lượt scan, loại scam nhiều nhất, nguồn báo cáo (web/app/partner).  
   - Bộ lọc nâng cao theo khu vực, thiết bị, kênh liên lạc.

2. **Hệ thống gắn nhãn & review báo cáo**  
   - Moderator có flow duyệt/chỉnh sửa báo cáo trước khi public vào cơ sở dữ liệu cộng đồng.  
   - Cho phép merge các thực thể trùng/na ná nhau (ví dụ nhiều số giống nhau khác 1–2 ký tự do nhập sai).

3. **Playbook xử lý khủng hoảng**  
   - Khi phát hiện chiến dịch scam lớn (surge bất thường), hệ thống gợi ý playbook: thông báo gì trên web, push gì cho user, contact cơ quan nào.  
   - Có giao diện cấu hình kịch bản trước.

4. **Stress test & chaos mode (dev tool)**  
   - Công cụ nội bộ giả lập hàng loạt request scan để test hiệu năng, scaling, Celery queue.  
   - Kết hợp metric/alert để tuning hệ thống.

---

## 8. Hướng phát triển xa hơn

1. **Hồ sơ bảo vệ gia đình (Family Safety)**  
   - Quản lý nhiều account (ông bà, bố mẹ, con cái) trong một "family group".  
   - Chủ nhóm nhận cảnh báo khi thành viên có hành vi rủi ro (vd: sắp chuyển tiền lớn tới tài khoản lạ).

2. **Bản đồ realtime các chiến dịch scam**  
   - Map Việt Nam hiển thị các "điểm nóng" theo thời gian thực dựa trên dữ liệu báo cáo.  
   - Cho phép zoom theo quận/huyện, loại hình, kênh liên lạc.

3. **Trung tâm dữ liệu mở (Open Data, có kiểm soát)**  
   - Cung cấp dataset ẩn danh cho nghiên cứu/đồ án, theo chuẩn bảo vệ dữ liệu cá nhân.  
   - Xây cộng đồng researcher xung quanh vấn đề scam.

4. **Gamification phòng chống lừa đảo**  
   - Mini game mô phỏng "bắt lỗi" trong các tin nhắn/cuộc gọi.  
   - Dùng để tổ chức campaign trong trường học, doanh nghiệp.

---

> Gợi ý: team có thể dùng file này như backlog ý tưởng. Khi chọn làm một tính năng, nên chuyển sang issue/ticket riêng, bổ sung spec và gắn nhãn (MVP / Nice-to-have / Experiment).