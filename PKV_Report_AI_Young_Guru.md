
**THÔNG TIN ĐỘI THI:**
* **Tên đội thi:** SENTINEL TEAM
* **Họ tên các thành viên đội thi:** [Điền họ tên các thành viên]
* **Tên sản phẩm:** ShieldCall VN - Nền tảng Phòng chống và Giáo dục Lừa đảo Không gian mạng Toàn diện bằng AI
* **Số điện thoại liên hệ (đại diện):** [Điền số điện thoại]
* **Email (đại diện):** kienhtfhl31796@gmail.com

---

**THÔNG TIN BÀI DỰ THI:**

### 2. Cấu trúc tài liệu nộp

#### Phần 1: Mô tả vấn đề
Trong thực tế, tình trạng lừa đảo mạng ở Việt Nam đang diễn biến ngày càng phức tạp và tinh vi, với hàng chục nghìn vụ việc được ghi nhận trong những năm gần đây. Theo thống kê của Bộ Công an, từ năm 2020 đến cuối năm 2025 đã xảy ra hơn 24.000 vụ lừa đảo trực tuyến, gây thiệt hại gần 40.000 tỷ đồng (khoảng 1,6 tỷ USD). Đặc biệt, riêng năm 2024 có trên 6.000 vụ với số tiền bị chiếm đoạt ước tính từ 12.000 đến 18.900 tỷ đồng, cho thấy mức độ nghiêm trọng và xu hướng gia tăng rõ rệt.

Tại địa phương của chúng em, nhiều người dân vẫn còn thiếu kỹ năng nhận diện các thủ đoạn lừa đảo mới như giả danh cơ quan chức năng, ngân hàng, lừa đảo đầu tư tài chính hoặc sử dụng công nghệ AI, deepfake để tạo lòng tin. Không ít trường hợp vì thiếu thông tin hoặc tâm lý chủ quan đã cung cấp dữ liệu cá nhân và chuyển tiền cho đối tượng xấu. Bên cạnh đó, không phải ai cũng chủ động trình báo khi bị lừa, khiến việc xử lý gặp nhiều khó khăn.

Vì vậy, cần tăng cường tuyên truyền, giáo dục kỹ năng an toàn số và ứng dụng công nghệ trong việc cảnh báo sớm các nguy cơ lừa đảo, giúp người dân nâng cao cảnh giác, bảo vệ thông tin cá nhân và hạn chế thiệt hại do lừa đảo mạng gây ra.

#### Phần 2: Cách thức tiếp cận
* **Ý tưởng của giải pháp:** Xây dựng một hệ sinh thái "All-in-one" kết hợp trí tuệ nhân tạo (AI) và sức mạnh cộng đồng (Crowdsourcing). Chuyển hướng phòng chống lừa đảo từ "bị động khắc phục" sang "chủ động quét, nhận diện và tự đào tạo giáo dục".
* **Sử dụng công nghệ/công cụ AI nào:**
  * Mô hình AI Ngôn ngữ (LLMs) linh hoạt qua giao thức Ollama để phân tích ngữ nghĩa, phân loại mức độ rủi ro.
  * **RAG (Retrieval-Augmented Generation) & FAISS Vector DB:** Giúp AI luôn cập nhật các kịch bản lừa đảo mới nhất ở Việt Nam mà không cần huấn luyện lại toàn bộ mô hình.
  * **AI OCR & Xử lý Hình ảnh:** Nhận diện ký tự quang học để trích xuất văn bản từ biên lai chuyển tiền giả mạo, mã độc ẩn trong Web/Mã QR.
  * **Công nghệ cốt lõi:** Web Framework Django (Python), hệ thống message broker Celery & Redis xử lý tác vụ nặng, WebSockets (Channels) truyền dữ liệu thời gian thực, Frontend siêu mượt với Alpine.js + Tailwind CSS.
* **Quy trình thực hiện & Độ phức tạp của dự án (Vượt xa "những Prompt cơ bản"):** 
  1. **Quy mô Hệ thống Lớn:** Dự án không phải chỉ là một giao diện bọc ngoài API AI. Đây là một nền tảng phức tạp với hơn **13.477 dòng code Python**, **12.677 dòng code HTML**, và **7.529 dòng CSS/JS**. 
  2. **Multi-Agent Collaboration (Đa đặc vụ AI hợp tác):** Để tạo ra hệ thống này, dự án áp dụng mô hình nhiều đặc vụ AI cùng làm việc, chéo nghiệm thu và đóng góp liên tục. Quá trình sinh mã (coding), gỡ lỗi (debugging) được phối hợp nhịp nhàng giữa các Agent chuyên biệt (UI/UX Agent, Backend Agent, Database Agent).
  3. **Kiến trúc Prompt Engineering Chuyên sâu:** Ứng dụng ShieldCall không dùng các câu lệnh AI đơn giản. Chúng tôi thiết kế hệ thống *Prompt Chaining* (chuỗi hướng dẫn lệnh đan xen), *Few-shot Prompting* với các file schema JSON phức tạp ràng buộc AI phải trả về kết quả cấu trúc chuẩn xác để backend có thể tự động parse dữ liệu (ví dụ: bộ engine đánh giá rủi ro Email EML, hay AI Magic Create sinh giáo án).
  4. **Quy trình Phát triển MVP Chặt chẽ:** Mọi tính năng đều trải qua quá trình định nghĩa Minimum Viable Product (MVP) rõ ràng để AI không đi lệch hướng. Sau khi hoàn thành MVP, hệ thống trải qua hàng chục vòng lặp kiểm thử (Iterative Testing) và cải tiến mã nguồn để đạt đến trạng thái ổn định, chống lỗi (fault-tolerance) như hiện tại.
  5. **Băng chuyền xử lý (Pipeline):** Người dùng nhập dữ liệu -> Thu thập metadata song song (WHOIS, DNS, Hash) -> Đẩy vào RAG Vector DB -> AI Reasoning Engine tổng hợp -> Trả kết quả thời gian thực qua WebSockets/SSE.

#### Phần 3: Mô tả sản phẩm
* **Hình thức thể hiện:** Giao diện Web Application linh hoạt, tương thích đa nền tảng (PC/Mobile) với phong cách thiết kế UI/UX "Liquid Glass" (kính mờ, nền đen gradient) hiện đại, tạo cảm giác của một trung tâm an ninh mạng chuyên nghiệp.
* **Nội dung & Công năng chính:**
  * **Cỗ máy quét đa nguyên (Multi-vector Scan Engine):** Cung cấp 7 công cụ quét độc lập: Quét SĐT, Tin nhắn/Chat, Website (phân tích mã nguồn và độ tin cậy), Tài khoản Ngân hàng (Hash checking), Quét Email chuyên sâu (.EML parsing kiểm định giả mạo), Quét mã QR và Quét File/Hình ảnh.
  * **Scam Radar & Cộng đồng (Crowdsourcing):** Nơi người dùng tố cáo kẻ lừa đảo. Radar thống kê theo thời gian thực các "hot trends" lừa đảo hiện hành. Tính năng Forum giúp thảo luận và tích luỹ điểm "Prestige" (Danh tiếng tín nhiệm).
  * **Learn Hub & AI Magic Create (Hệ thống giáo dục số tự động):** 
    * Cung cấp các bài học, kịch bản tương tác (Interactive Scenarios) để huấn luyện người dùng.
    * **Đột phá "AI Magic Create":** Quản trị viên chỉ cần dán một đoạn tin tức/văn bản thô, AI sẽ tự động phân tích và sinh ra cấu trúc 1 bài học chuẩn hóa bằng Markdown, tạo ra 1 câu hỏi Trắc nghiệm (Quiz), và sinh ra cả 1 Kịch bản hội thoại để người dùng thực hành.
  * **Trợ lý Ảo AI Chat (AI Assistant):** Giải đáp thắc mắc 24/7 với trí nhớ ngữ cảnh đầy đủ.
* **Cách thức sử dụng/Vận hành:** 
  * Khi người dùng nghi ngờ 1 tin nhắn trúng thưởng, họ dán vào hệ thống. Màn hình sẽ hiển thị từng bước xử lý thời gian thực ("Đang trích xuất liên kết...", "Web này mới lập 2 ngày...", "AI kết luận: 95% lừa đảo đầu tư").
  * Người dùng có thể click làm "Báo cáo" để đóng góp vào Database chung, giúp những người sau cảnh giác. Đồng thời, họ vào Learn Hub chơi các minigame mô phỏng để tăng cường kỹ năng.

#### Phần 4: Hiệu quả mang lại
* **Giá trị thực tế:** Trực tiếp ngặn chặn dòng tiền chuyển đi sai mục đích thông qua cảnh báo "Sát sườn" điểm yếu của các kịch bản lừa đảo. Giảm tải gánh nặng xác minh cho cơ quan công an bằng công cụ AI tự gán nhãn chứng cứ.
* **Đẳng cấp Kỹ thuật & Sự Tỉ mỉ:** Bằng việc code "từ con số không" với khối lượng hơn 33.000 dòng code (Python, C, JS, HTML), làm chủ hoàn toàn Backend tới Luồng xử lý Socket AI, sản phẩm thể hiện trình độ kỹ thuật vững vàng chứ không đơn thuần chỉ gọi API có sẵn.
* **Phạm vi ảnh hưởng:** Mọi công dân sử dụng điện thoại và mạng internet. Đặc biệt là nhóm người cao tuổi, sinh viên và công nhân – những nhóm dễ bị tổn thương nhất trên không gian mạng hiện nay.
* **Tính mới so với các giải pháp cũ:**
  * Các ứng dụng cũ chỉ là "Danh sách đen" (Blacklist) số điện thoại chặn thụ động. ShieldCall VN là một "Bộ não phân tích" (Analysis Engine). Cho dù kẻ gian dùng SĐT mới, Website mới, AI vẫn đọc vị được văn phong lừa đảo (Thao túng tâm lý, giục giã, dọa nạt) để khóa mục tiêu.
  * Hệ thống giáo dục không khô khan mà được **Gamification (Trò chơi hóa)** qua chức năng *Interactive Scenarios*. Đặc biệt tính năng "AI Magic Create" giúp nền tảng mở rộng nội dung tự động không giới hạn nhờ sức mạnh của AI sinh tạo. Lừa đảo mới xuất hiện buổi sáng, buổi chiều hệ thống đã có bài giảng và kịch bản thực tập cho người dùng nhờ AI tạo ra.

---

### Thông tin Trải nghiệm Hệ thống (Dành cho Ban Giám Khảo)
Để Ban Giám khảo có thể trực tiếp trải nghiệm toàn bộ tính năng của hệ thống (bao gồm cả Trang Quản trị Admin và các tính năng AI), nhóm đã khởi tạo một tài khoản đặc quyền Super Admin:

* **Tên đăng nhập (Username):** `BanGiamKhao`
* **Mật khẩu (Password):** `AIYoungGuru2026!`

*(Lưu ý: Tài khoản này có toàn quyền quản trị, xin mời Ban Giám khảo đăng nhập và truy cập vào mục "Bảng Điều Khiển Admin" để kiểm thử tính năng của trang web)*
