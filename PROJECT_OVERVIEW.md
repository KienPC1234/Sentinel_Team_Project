# 🛡️ ShieldCall VN: Project Overview & AI Ecosystem

**ShieldCall VN** là một nền tảng an ninh mạng toàn diện, được thiết kế chuyên biệt để bảo vệ người dùng số tại Việt Nam thông qua sức mạnh của Trí tuệ Nhân tạo (AI). Dự án không chỉ dừng lại ở việc phát hiện lừa đảo mà còn xây dựng một hệ sinh thái giáo dục và cộng đồng vững chắc.

---

## 🛠️ Stack Công nghệ (Advanced Tech Stack)

Dự án được xây dựng trên một nền tảng hiện đại, tối ưu hóa cho hiệu suất và khả năng mở rộng AI.

| Thành phần | Công nghệ sử dụng | Chi tiết |
| :--- | :--- | :--- |
| **Backend Core** | **Django 5.x** + **Django REST Framework** | Cấu trúc Monolith-First bền vững, API chuẩn RESTful. |
| **Frontend UI** | **Tailwind CSS v4** + **Alpine.js** | Giao diện **Liquid Glass Aesthetic** (Kính lỏng) sang trọng và mượt mà. |
| **AI Engine (Local)** | **Ollama** (**GPT-OSS:120b**) | Phân tích Reasoning Engine bằng mô hình ngôn ngữ lớn chạy local hoặc remote. |
| **AI Vision & Audio** | **EasyOCR** & **Faster-Whisper** | Trích xuất văn bản từ hình ảnh và chuyển đổi âm thanh cuộc gọi thời gian thực. |
| **Vector DB (RAG)** | **FAISS** + **Sentence-Transformers** | Hệ thống nhúng (embeddings) thông minh để tra cứu kiến thức bảo mật. |
| **Async Tasks** | **Celery** + **Redis** | Xử lý các tác vụ quét nặng và lịch trình định kỳ (Celery Beat). |
| **Real-time** | **Django Channels** (WebSockets) | Thông báo và phản hồi AI trực tiếp ngay lập tức. |
| **Infrastructure** | **Nginx** + **MySQL 8.0** + **Daphne** | Hệ thống máy chủ production mạnh mẽ, bảo mật. |

---

## 🗺️ Danh mục các Trang & Chức năng (Page Directory)

Hệ thống bao gồm các phân khu chức năng được liên kết chặt chẽ:

### 1. Trung tâm Quét Đa hướng (Scan Hub)
*   **Quét Số điện thoại & Tài khoản ngân hàng**: Tra cứu mức độ rủi ro từ cơ sở dữ liệu cộng đồng và AI.
*   **Quét Website (URL Scan)**: Phân tích WHOIS, DNS, Hosting và đánh giá uy tín bằng AI.
*   **Quét Email (.eml)**: Vạch trần các kịch bản lừa đảo qua email và xác thực nguồn gửi.
*   **Quét Tin nhắn (Sms/Message)**: Phân tích nội dung tin nhắn giả mạo.
*   **Quét QR Code**: Phát hiện các mã QR độc hại dẫn đến trang phishing.
*   **Quét Hình ảnh (OCR Scan)**: Phân tích ảnh chụp màn hình cuộc trò chuyện lừa đảo.
*   **Quét Audio**: Chuyển giọng nói cuộc gọi thành văn bản để AI phân tích kịch bản.

### 2. Hệ sinh thái Cộng đồng & Giáo dục
*   **Scam Radar (Bản đồ lừa đảo)**: Theo dõi xu hướng và địa điểm lừa đảo theo thời gian thực.
*   **Learn Hub (Trung tâm học tập)**: Kho bài học, bài viết chuyên sâu về an toàn thông tin.
*   **Scam IQ Exam**: Hệ thống bài thi đánh giá năng lực phòng chống lừa đảo.
*   **Forum (Diễn đàn)**: Nơi cộng đồng chia sẻ kinh nghiệm và cảnh báo lẫn nhau.
*   **Emergency (Khẩn cấp)**: Hướng dẫn xử lý nhanh khi đã bị lừa đảo.

### 3. Trợ lý AI & Cá nhân hóa
*   **AI Assistant (ShieldCall AI)**: Chatbot thông minh hỗ trợ 24/7 với khả năng hiểu ngữ cảnh sâu.
*   **Custom Personas**: Người dùng có thể tùy chỉnh giọng điệu (Friendly, Professional, etc.) của AI.
*   **Profile Management**: Quản lý thông tin cá nhân, lịch sử báo cáo và thành tích học tập.

### 4. Quản trị Đẳng cấp (Admin CP)
*   **Magic Create**: Quy trình tự động tạo nội dung giáo dục từ tin tức thô bằng AI.
*   **Dashboard Thông minh**: Giám sát toàn bộ hoạt động hệ thống và thống kê lừa đảo.

---

## 🤖 Tính năng AI Đột phá (The AI "X-Factor")

Hệ thống tích hợp hàng loạt công nghệ AI tiên phong để đảm bảo độ chính xác cao nhất:

### 🔥 Multi-Agent Orchestration (Đặc vụ Đa tầng)
Khi bạn đặt câu hỏi hoặc gửi dữ liệu quét, AI không chỉ trả lời đơn thuần. Nó kích hoạt một quy trình cộng tác giữa các đặc vụ:
- **Search Agent**: Tự động tra cứu Google/Bing/DuckDuckGo để tìm thông tin mới nhất về các vụ lừa đảo.
- **Lookup Agent**: Truy cập vào các nguồn uy tín như VirusTotal, ScamAdviser, Trustpilot.
- **Analysis Agent**: Tổng hợp dữ liệu từ mọi nguồn, đối chiếu chéo và đưa ra kết luận cuối cùng cho người dùng.

### 📚 RAG (Retrieval-Augmented Generation)
Hệ thống sử dụng **FAISS Vector Database** để "học" toàn bộ kho bài giảng và bài viết trong Learn Hub. Khi người dùng hỏi, AI sẽ tìm kiếm thông tin chính xác nhất từ cơ sở dữ liệu này (RAG context) thay vì chỉ dựa vào tri thức có sẵn, giúp giảm thiểu tối đa hiện tượng "ảo giác AI".

### 🪄 AI Magic Create Workflow
Quy trình 5 giai đoạn dành cho Admin giúp biến một mẩu tin lừa đảo thô thành bài học hoàn chỉnh chỉ trong vài giây:
1.  **Analyze**: Phân tích nội dung thô bằng AI.
2.  **Generate Lesson**: Tự động soạn thảo bài giảng.
3.  **Create Quiz**: Tạo bài kiểm tra trắc nghiệm tương ứng.
4.  **Design Scenario**: Xây dựng kịch bản tương tác (chat-based player).
5.  **Push Notification**: Gửi thông báo đến người dùng ngay lập tức.

### 👁️ AI OCR Magic (Mắt thần)
Sử dụng **EasyOCR** kết hợp với mô hình LLM để không chỉ đọc chữ trong ảnh mà còn hiểu được ý đồ của kẻ lừa đảo. AI có khả năng trích xuất tên người, số tài khoản, số điện thoại từ ảnh chụp màn hình một cách thông minh.

### 🔊 Audio Scam Analysis
Tích hợp **Faster-Whisper** để xử lý âm thanh cuộc gọi. AI phân tích kịch bản giọng nói (voice scripts), nhận diện các dấu hiệu tâm lý (thúc ép, đe dọa) thường thấy trong các vụ giả danh công an hoặc ngân hàng.

---

## 🛡️ Bảo mật & Tin cậy
-   **VirusTotal Integration**: Kiểm tra mã độc và link phishing qua API VirusTotal.
-   **WHOIS/DNS Analysis**: Thuật toán tự phát triển để đánh giá độ tuổi và độ tin cậy của tên miền.
-   **2FA & Cloudflare Turnstile**: Bảo vệ tài khoản và ngăn chặn bot tấn công hệ thống.

---
*Tài liệu được cập nhật tự động bởi **ShieldCall AI Agent Engine**.*
