# BÁO CÁO KÊ KHAI CÔNG CỤ AI, DỮ LIỆU, API, THƯ VIỆN VÀ MÃ NGUỒN MỞ

- Dự án: **ShieldCall VN (Sentinel Team Project)**
- Phiên bản: **1.0.0**
- Ngày thẩm định và cập nhật: **16/09/2026**
- Phạm vi: Toàn bộ hệ thống mã nguồn Backend (Django/Daphne/Celery), AI Engine (LLM/Ollama/Vision/Audio/RAG), Container Sandbox (ClamAV/YARA/Capa), Trình duyệt ẩn danh (Node.js/Puppeteer) và Giao diện người dùng (Tailwind/Alpine.js).
- Mục tiêu: Kê khai minh bạch, trung thực 100% không bỏ sót bất kỳ thành phần nào, phục vụ đánh giá liêm chính học thuật, hồ sơ kỹ thuật cuộc thi khoa học công nghệ và kiểm định an toàn thông tin.

---

## 1. TỔNG QUAN HỆ THỐNG & TRIẾT LÝ BẢO MẬT

ShieldCall VN là nền tảng an toàn số toàn diện dành cho người dùng và tổ chức tại Việt Nam, tập trung giải quyết bài toán phát hiện, cảnh báo sớm và phân tích pháp chứng các hình thức lừa đảo trực tuyến đa phương thức:
- **Số điện thoại**: Mạo danh cơ quan công an, viện kiểm sát, tòa án, nhân viên ngân hàng, lừa đảo tuyển dụng, phát hiện số ảo VoIP qua nhà mạng ảo (Virtual Providers).
- **Tài khoản ngân hàng**: Đối soát danh sách đen gian lận tài chính, tài khoản rác/thuê mượn, chuẩn hóa theo chuẩn ngân hàng quốc gia VietQR.
- **Tên miền & Website**: Phát hiện website phishing giả mạo ngân hàng/cổng thanh toán, kiểm tra chứng chỉ SSL/TLS thời gian thực, DNS, WHOIS, thuật toán phát hiện tên miền mạo danh (Levenshtein lookalike và Homoglyph substitution).
- **Email & Tin nhắn**: Phân tích nội dung lừa đảo (.eml, SMS, mạng xã hội), kiểm tra tính toàn vẹn email qua bản ghi SPF, DKIM, DMARC, DNS MX; phát hiện kịch bản thao túng tâm lý (social engineering).
- **Hình ảnh & Mã QR**: Trích xuất ký tự quang học (OCR) tiếng Việt từ ảnh chụp màn hình, phát hiện và giải mã mã QR độc hại (Quishing).
- **Tệp tin mã độc**: Phân tích tĩnh chuyên sâu trong môi trường Docker Sandbox Zero-Trust cô lập hoàn toàn mạng, tính toán Shannon Entropy, kiểm tra chữ ký ClamAV và luật YARA.
- **Ghi âm cuộc gọi**: Phiên âm âm thanh tiếng Việt và nhận diện bẫy kịch bản cuộc gọi mạo danh có timestamps.

**Triết lý kiến trúc**: Ưu tiên **On-Premise / Zero Cloud Leakage**. Toàn bộ các tác vụ xử lý tệp tin, OCR, phiên âm âm thanh và tra cứu vector RAG đều vận hành nội bộ trên hạ tầng máy chủ của hệ thống, không chuyển tiếp dữ liệu nhạy cảm của người dùng ra dịch vụ đám mây bên thứ ba trái phép.

---

## 2. KÊ KHAI CÔNG CỤ TRÍ TUỆ NHÂN TẠO (AI ENGINES & MODELS)

| Nhóm công cụ | Tên mô hình / Công cụ | Nhà phát triển / Nguồn gốc | Cơ chế vận hành & Vị trí trong mã nguồn | Mục đích sử dụng cụ thể |
| :--- | :--- | :--- | :--- | :--- |
| **Mô hình Ngôn ngữ Lớn (Primary Cloud LLM)** | DeepSeek (`deepseek-chat`, `deepseek-reasoner`) / OpenAI (`gpt-4o`) | DeepSeek-AI / OpenAI | Giao thức HTTP OpenAI-compatible client, streaming SSE tại `api/utils/ollama_client.py`, cấu hình qua biến môi trường `OPENAI_BASE_URL` và `OPENAI_API_KEY`. | Đánh giá ngữ cảnh lừa đảo, phân tích kịch bản thao túng tâm lý, phát hiện yêu cầu OTP/chuyển tiền trái phép, giải thích kỹ thuật cho người dùng bằng tiếng Việt tự nhiên và hỗ trợ tính năng stream quá trình suy luận (Reasoning/Thinking block). |
| **Mô hình Ngôn ngữ Nội bộ (Local LLM Fallback)** | Ollama (`qwen2.5:7b`, `llama3.1:8b`, `deepseek-r1:7b`) | Alibaba Cloud / Meta / DeepSeek (qua Ollama Runtime) | Chạy cục bộ trên GPU/CPU nội bộ (`http://localhost:11434`), tích hợp tại `api/utils/ollama_client.py`. Tự động fallback khi mất mạng ngoài hoặc ở chế độ Zero-Cloud. | Phân tích nội dung khi không có kết nối Internet hoặc xử lý các báo cáo yêu cầu bảo mật dữ liệu tuyệt đối không đẩy ra ngoài. |
| **Nhận dạng Ký tự Quang học (Vision OCR)** | EasyOCR (CRAFT + ResNet + BiLSTM + CTC) | JaidedAI (Giấy phép Apache-2.0) | Khởi tạo Singleton tại `api/utils/media_utils.py`, nạp mô hình ngôn ngữ tiếng Việt (`vi`) và tiếng Anh (`en`), tối ưu hoá trên PyTorch CUDA với cơ chế fallback sang CPU khi chạy tiến trình con Celery. | Trích xuất toàn bộ văn bản từ ảnh chụp màn hình tin nhắn, biên lai chuyển khoản giả, bài đăng mạng xã hội; tính toán bounding box và tạo ảnh minh chứng trực quan (annotated image). |
| **Giải mã Mã phản hồi nhanh (QR Code)** | PyZbar (ZBar Barcode Reader Library) | Natural History Museum / Jeff Brown (LGPL-2.1) | Tích hợp tại `api/utils/media_utils.py` kết hợp xử lý hình ảnh PIL/Pillow. | Định vị vùng toạ độ và giải mã dữ liệu mã QR (URL, chuỗi thanh toán VietQR) ẩn trong hình ảnh tải lên trước khi đưa vào pipeline quét tên miền. |
| **Nhận dạng Giọng nói & Phiên âm (Audio AI)** | Faster-Whisper (mô hình `small`) | OpenAI / SYSTRAN (CTranslate2, MIT) | Quản lý tại `api/utils/media_utils.py`, sử dụng định dạng 8-bit int/float16, kết hợp tiện ích `ffmpeg` chuẩn hoá âm thanh về 16kHz WAV mono. | Phiên âm các tệp ghi âm cuộc gọi mạo danh (định dạng mp3, wav, m4a, webm, ogg) thành văn bản tiếng Việt có mốc thời gian (timestamps) để chuyển giao cho LLM phân tích bẫy lừa đảo. |
| **Mô hình Nhúng Vector (Embedding Vector)** | `nomic-ai/nomic-embed-text-v1` | Nomic AI (Giấy phép Apache-2.0, Hugging Face) | Sử dụng qua `sentence-transformers` và `transformers` tại `api/utils/vector_db.py`, chiều vector $D=768$, hỗ trợ cự ly ngữ cảnh dài với rotary embedding (yêu cầu thư viện `einops`). | Chuyển đổi toàn bộ tri thức an toàn thông tin, cẩm nang phòng thủ và tình huống lừa đảo thành vector phục vụ cơ chế RAG. |
| **Cơ sở dữ liệu Vector (Vector DB)** | FAISS (`faiss-cpu`) | Meta AI Research (Giấy phép MIT) | Quản lý chỉ mục vector tại `api/utils/vector_db.py` với tệp index nhị phân `scam_index.faiss` và metadata tương ứng. | Tìm kiếm tương đồng ngữ nghĩa (Cosine / Inner Product similarity) siêu tốc, đưa ngữ cảnh chính xác vào prompt của AI để loại bỏ hiện tượng ảo giác (hallucination). |
| **AI Multi-Agent & Tool Calling Engine** | ReAct Pattern Agent (`ShieldCallAgent`) | Tự thiết kế và hiện thực trong `api/utils/ai_agent.py` | Mô hình tự động điều phối công cụ (tool calling loop) cho phép AI Assistant tự động gọi các tool: tìm kiếm web (SearXNG), tra cứu thực thể DB nội bộ, tra cứu ScamAdviser/Tranco, tính toán thiệt hại tài chính. | Tự động hóa quá trình điều tra đa nguồn tin tức và tổng hợp kết quả điều tra độc lập. |
| **Scam IQ AI Scoring Engine** | Hệ thống chấm điểm tương tác tự động | Hiện thực tại `api/core/views/scam_iq_views.py` | Đánh giá câu trả lời tự luận và trắc nghiệm tình huống của thí sinh, tạo phản hồi sư phạm (AI Feedback) chi tiết dựa trên ma trận rủi ro. | Tự động hóa quá trình đào tạo và kiểm tra năng lực tự vệ số của người dùng trên toàn hệ thống. |
| **Magic Create Content Engine** | Pipeline sinh tài liệu giáo dục 5 bước | Hiện thực tại `api/core/views/admin_views.py` | Tự động bóc tách tin tức thô từ báo chí, trích xuất thực thể IOC, tóm tắt nội dung, sinh bộ câu hỏi trắc nghiệm (Quizzes) và kịch bản thực tế (Scenarios). | Giúp quản trị viên tạo nội dung giáo dục chất lượng cao trên Learn Hub chỉ từ liên kết báo chí hoặc văn bản thô. |

---

## 3. KÊ KHAI NGUỒN DỮ LIỆU (DATASETS & THREAT FEEDS)

| Tên tập dữ liệu / Nguồn dữ liệu | Đơn vị chủ quản / Nguồn cung cấp | Định dạng & Chu kỳ cập nhật | Mục đích sử dụng |
| :--- | :--- | :--- | :--- |
| **URLhaus Malicious Feed** | abuse.ch (Thụy Sĩ) | Tệp CSV cập nhật định kỳ (`https://urlhaus.abuse.ch/downloads/csv_recent/`), đồng bộ hàng ngày qua Celery Beat. | Danh mục URL/tên miền trực tiếp phát tán mã độc, spyware, ransomware và trojan ngân hàng. |
| **OpenPhish Phishing Feed** | OpenPhish | Tệp văn bản (`https://openphish.com/feed.txt`), cập nhật theo thời gian thực. | Nhận diện các liên kết tấn công giả mạo (phishing) zero-day mới xuất hiện trên toàn cầu. |
| **Phishing.Database** | Mitchell Krogza (Cộng đồng quốc tế) | Tệp danh sách domain thô từ GitHub (`phishing-domains-ACTIVE.txt`), đồng bộ định kỳ. | Bổ sung kho dữ liệu tên miền lừa đảo, tên miền cờ bạc, mạo danh thương hiệu. |
| **Tranco Research List** | Tranco Project (Đại học TU Delft / Radboud) | API JSON (`tranco-list.eu/api/ranks/domain/`). | Bảng xếp hạng 1 triệu website uy tín nhất thế giới, làm căn cứ xác định tên miền mới lập, độ phổ biến thấp và có nguy cơ mạo danh cao. |
| **Danh mục Ngân hàng Việt Nam** | Casso / VietQR Open API | JSON API (`https://api.vietqr.io/v2/banks`), cache Redis 24 giờ. | Chuẩn hoá tên ngân hàng, mã BIN, mã viết tắt của toàn bộ hệ sinh thái ngân hàng tại Việt Nam để kiểm tra số tài khoản. |
| **Danh mục 27+ Tên miền Quốc gia Tin cậy** | Sentinel Team biên soạn nội bộ | Lưu trữ trong bộ nhớ đệm Redis (`api/utils/scan_utils.py`). | Danh sách tên miền gốc của các ngân hàng thương mại Việt Nam (Vietcombank, Techcombank, BIDV...), ví điện tử (MoMo, ZaloPay), mạng xã hội và cổng cơ quan nhà nước (`chinhphu.vn`, `gov.vn`) làm cơ sở đối chiếu thuật toán phát hiện tên miền mạo danh (Lookalike / Typo-squatting). |
| **Bộ Quy tắc Pháp chứng YARA (Signature-Base)** | Florian Roth (Neo23x0) | Hơn 734 tập luật YARA mã nguồn mở, được biên dịch trước trong Docker Sandbox (`/sandbox/rules/signature_base/`). | Nhận diện chữ ký mã độc, backdoor, webshell, mã nhị phân độc hại, tệp Office chứa macro VBA khai thác lỗ hổng. |
| **Bộ Quy tắc Hành vi Mandiant Capa** | Mandiant / Google Cloud | Bộ luật Capa Rules tại `/sandbox/capa-rules`. | Phân tích hành vi nhị phân độc hại (anti-analysis, stealth persistence, process hollowing, privilege escalation). |
| **Cơ sở Dữ liệu Chữ ký ClamAV** | Cisco Talos / ClamAV Community | Tệp cơ sở dữ liệu `main.cvd`, `daily.cvd`, `bytecode.cvd` cập nhật tự động bằng `freshclam`. | Quét nhận diện virus, trojan, worm, ransomware chuẩn quốc tế. |
| **Dữ liệu Tri thức Nội bộ & Báo cáo Cộng đồng** | Cơ sở dữ liệu ShieldCall VN (`db.sqlite3` / MySQL `shieldcall_db`) | Bảng `Report`, `Domain`, `PhoneNumber`, `BankAccount`, `Article`, `LearnLesson`, `LearnQuiz`. | Kho dữ liệu do cộng đồng người dùng gửi báo cáo, được kiểm duyệt và tính điểm uy tín (Reporter Trust Score) theo thời gian. |

---

## 4. KÊ KHAI GIAO DIỆN LẬP TRÌNH ỨNG DỤNG BÊN THỨ BA (EXTERNAL APIS)

| Tên API / Dịch vụ | Nhà cung cấp | Endpoint / Phương thức kết nối | Mục đích trong hệ thống | Ghi chú về an toàn & Bảo mật |
| :--- | :--- | :--- | :--- | :--- |
| **OpenAI / DeepSeek API** | DeepSeek / OpenAI | HTTPS `POST /chat/completions` (SSE Streaming) | Tạo câu trả lời AI, phân tích sâu bằng mô hình lý luận (reasoning). | Khóa API đọc từ biến môi trường `.env`, không lộ ra phía client. |
| **SearXNG Meta Search Engine** | Tự vận hành nội bộ (`https://search.fptoj.com`) | HTTPS `GET /search?format=json` | Tìm kiếm dữ liệu web phục vụ AI Agent kiểm chứng số điện thoại, đơn vị chủ quản, tin tức cảnh báo. | Tự host, không lưu log tìm kiếm người dùng, ẩn danh hóa yêu cầu. |
| **VietQR Banks API** | VietQR / Napas | HTTPS `GET https://api.vietqr.io/v2/banks` | Lấy danh mục tên ngân hàng, mã chuyển khoản nhanh tại Việt Nam. | Dữ liệu công khai, lưu cache Redis 86400 giây để tối ưu băng thông. |
| **Cloudflare Turnstile** | Cloudflare | HTTPS `POST https://challenges.cloudflare.com/turnstile/v0/siteverify` | Xác thực chống bot vô hình (Invisible CAPTCHA) trên các form quét, đăng nhập và báo cáo. | Token xác thực chỉ sử dụng một lần (single-use), hỗ trợ bảo vệ chống tấn công DDoS và cào dữ liệu. |
| **W3C WebPush Service** | Mozilla / Google FCM / Apple APNs | HTTPS Web Push Protocol (RFC 8291/8292) | Gửi thông báo đẩy về trình duyệt khi có báo cáo được duyệt hoặc có cảnh báo khẩn cấp. | Xác thực bất đối xứng qua cặp khóa VAPID (ECDSA P-256), không cần đăng ký tài khoản bên thứ ba. |
| **Google OAuth 2.0** | Google Identity Services | HTTPS OAuth 2.0 Authorization Flow | Đăng nhập tài khoản nhanh qua Google cho người dùng web. | Tích hợp qua `django-allauth`, chỉ yêu cầu quyền đọc `profile` và `email`. |
| **Tranco List API** | Tranco Project | `tranco-list.eu/api/ranks/` | Truy vấn xếp hạng độ phổ biến của domain trong top 1M. | Read-only HTTPS JSON. |
| **ScamAdviser / Trustpilot / Sitejabber** | Các nền tảng đánh giá website | HTTPS Web Request (với user-agent mô phỏng an toàn) | Tra cứu điểm tin cậy (Trust Score) và phản ánh từ cộng đồng người dùng quốc tế. | Thực hiện qua các hàm tra cứu tại `api/utils/ollama_client.py`. |
| **Tra Cứu Mã Số Thuế / Tratencongty** | Hệ thống tra cứu thông tin doanh nghiệp | HTTPS Web Request | Đối soát tên doanh nghiệp, mã số thuế của đơn vị bị mạo danh lừa đảo. | Thực hiện qua hàm `lookup_business_tax` tại `api/utils/ollama_client.py`. |

*Ghi chú quan trọng về VirusTotal*: Dự án **không phụ thuộc** vào API VirusTotal bên ngoài. Toàn bộ tính năng kiểm tra file và URL được chuyển giao sang động cơ nội bộ `LocalSandboxAnalyzer` kết hợp Docker Zero-Trust Container và ClamAV để đảm bảo triết lý không lộ lọt dữ liệu người dùng ra bên ngoài (Zero Cloud Leakage).

---

## 5. KÊ KHAI TOÀN BỘ THƯ VIỆN PHẦN MỀM (SOFTWARE LIBRARIES)

### 5.1. Thư viện Backend Python (`requirements.txt`)

Tất cả 42 thư viện dưới đây đều có mặt và tham gia trực tiếp vào luồng xử lý của mã nguồn:

| Tên thư viện | Phiên bản | Giấy phép | Vai trò & Mục đích kỹ thuật trong mã nguồn |
| :--- | :--- | :--- | :--- |
| **django** | >= 5.0 | BSD-3-Clause | Khung web cốt lõi (Core Web Framework), quản lý ORM, MVC routing, session và bảo mật ứng dụng. |
| **djangorestframework** | Mới nhất | Encode OSS | Cung cấp chuẩn kiến trúc RESTful API, Serializers, APIView và xác thực API Key / Token. |
| **drf-spectacular** | Mới nhất | BSD-3-Clause | Tự động tạo tài liệu đặc tả OpenAPI 3.0, Swagger UI và Redoc tại `/api/docs/`. |
| **django-cors-headers** | Mới nhất | MIT | Cấu hình Cross-Origin Resource Sharing cho phép các client/mobile gọi API hợp lệ. |
| **pymysql** | Mới nhất | MIT | Trình điều khiển kết nối cơ sở dữ liệu MySQL 8.0 trong môi trường triển khai Production. |
| **cryptography** | Mới nhất | Apache-2.0 / BSD | Sinh và quản lý cặp khóa mã hóa VAPID cho dịch vụ thông báo đẩy WebPush. |
| **django-redis** | Mới nhất | BSD-3-Clause | Bộ điều hợp bộ nhớ đệm (Cache Backend) và lưu trữ Session phân tán trên Redis. |
| **celery** | Mới nhất | BSD-3-Clause | Hàng đợi tác vụ bất đồng bộ (Task Queue) xử lý scan ngầm, phân tích tệp tin, lập chỉ mục RAG. |
| **redis** | Mới nhất | MIT | Client giao tiếp với Redis Server cho Celery Broker, Result Backend và WebSockets. |
| **pillow** | Mới nhất | HPND | Thư viện xử lý ảnh (cắt, nén, vẽ bounding box phát hiện OCR và QR code). |
| **requests** | >= 2.31.0 | Apache-2.0 | Thực hiện các yêu cầu HTTP đồng bộ tới các Threat Feeds, SearXNG và dịch vụ bên ngoài. |
| **django-tailwind** | Mới nhất | MIT | Cầu nối tích hợp trình biên dịch giao diện Tailwind CSS vào vòng đời quản lý của Django. |
| **python-dotenv** | Mới nhất | BSD-3-Clause | Nạp an toàn các biến môi trường cấu hình từ tệp `.env` vào `settings.py`. |
| **easyocr** | Mới nhất | Apache-2.0 | Động cơ OCR mã nguồn mở trích xuất chữ tiếng Việt và tiếng Anh từ hình ảnh. |
| **pyzbar** | Mới nhất | MIT | Giải mã mã vạch và mã QR từ tệp ảnh người dùng cung cấp. |
| **opencv-python-headless**| Mới nhất | Apache-2.0 | Phụ thuộc gián tiếp của EasyOCR để xử lý ma trận ảnh nhị phân trên môi trường máy chủ không có GUI. |
| **ollama** | Mới nhất | MIT | Thư viện client chính thức giao tiếp với runtime máy chủ Ollama cục bộ. |
| **django-allauth[socialaccount]** | Mới nhất | MIT | Xác thực đăng nhập tài khoản người dùng, tích hợp cơ chế Google OAuth 2.0 Social Login. |
| **channels** | >= 4.0.0 | BSD-3-Clause | Mở rộng Django hỗ trợ giao thức thời gian thực WebSockets và luồng dữ liệu bất đồng bộ. |
| **channels-redis** | >= 4.2.0 | BSD-3-Clause | Lớp lưu trữ kênh (Channel Layer) dựa trên Redis điều phối tin nhắn giữa các tiến trình Daphne. |
| **daphne** | Mới nhất | BSD-3-Clause | Máy chủ ứng dụng ASGI chuẩn chịu tải cho các kết nối HTTP, SSE và WebSockets thời gian thực. |
| **beautifulsoup4** | >= 4.12.0 | MIT | Bóc tách cú pháp HTML, lọc văn bản từ các trang tin tức và phân tích web lừa đảo. |
| **django-otp** | Mới nhất | BSD-3-Clause | Hạ tầng xác thực hai yếu tố (2FA / MFA) cho người dùng và tài khoản quản trị viên. |
| **pyotp** | Mới nhất | MIT | Tạo và kiểm tra mã xác thực một lần theo thời gian (TOTP - RFC 6238). |
| **qrcode** | Mới nhất | BSD | Sinh mã QR hiển thị trên giao diện giúp người dùng quét và kích hoạt ứng dụng xác thực 2FA. |
| **django-turnstile** | Mới nhất | MIT | Tích hợp widget Cloudflare Turnstile vào Django form để chống spam và lạm dụng API. |
| **python-whois** | Mới nhất | MIT | Truy vấn thông tin đăng ký tên miền WHOIS (ngày tạo, đơn vị đăng ký, ngày hết hạn). |
| **dnspython** | >= 2.4.2 | ISC | Truy vấn các bản ghi DNS (A, AAAA, MX, TXT, SPF, DMARC) để kiểm tra độ an toàn của email và domain. |
| **ipwhois** | Mới nhất | BSD-2-Clause | Tra cứu thông tin địa chỉ IP, số hiệu mạng tự trị (ASN) và nhà cung cấp dịch vụ Internet (ISP). |
| **phonenumbers** | Mới nhất | Apache-2.0 | Phân tích cú pháp, kiểm tra tính hợp lệ và định dạng số điện thoại Việt Nam (+84). |
| **einops** | Mới nhất | MIT | Xử lý phép toán ma trận tensor cần thiết cho mô hình embedding `nomic-ai/nomic-embed-text-v1`. |
| **markdown** | Mới nhất | BSD-3-Clause | Biên dịch nội dung định dạng Markdown thành HTML hiển thị trên giao diện forum và cẩm nang hỗ trợ. |
| **faster-whisper** | Mới nhất | MIT | Nhận dạng giọng nói tự động, chuyển đổi tệp âm thanh cuộc gọi thành văn bản. |
| **whitenoise** | Mới nhất | MIT | Phục vụ tệp tĩnh (CSS, JS, Fonts) trực tiếp, hiệu năng cao và có nén Gzip/Brotli trong môi trường sản phẩm. |
| **faiss-cpu** | Mới nhất | MIT | Động cơ tìm kiếm tương đồng vector hiệu năng cao do Meta AI Research phát triển cho RAG. |
| **pywebpush** | >= 2.0.3 | MPL-2.0 | Gửi tin nhắn thông báo đẩy Web Push tuân thủ đặc tả mã hóa chuẩn W3C. |
| **sentence-transformers** | Mới nhất | Apache-2.0 | Nạp và tính toán vector nhúng ngữ nghĩa câu từ các mô hình học sâu. |
| **transformers** | Mới nhất | Apache-2.0 | Khung làm việc mô hình ngôn ngữ Hugging Face quản lý logging và cấu hình mô hình nhúng. |
| **torch** | Mới nhất | BSD-3-Clause | Khung tính toán học sâu (PyTorch) cung cấp nền tảng xử lý tensor cho EasyOCR và Embeddings. |
| **martor** | Mới nhất | AGPL-3.0 | Trình soạn thảo văn bản Markdown trực quan cho bài viết diễn đàn và quản trị nội dung. |
| **mcp** | >= 2.2.0 | MIT | Thư viện triển khai giao thức Model Context Protocol (Anthropic standard) cho phép các LLM ngoài tích hợp công cụ của ShieldCall VN. |

---

### 5.2. Thư viện Node.js & Trình duyệt Tự động (`scripts/puppeteer_host/package.json`)

Mô-đun máy chủ trình duyệt ẩn danh (`puppeteer_host`) phục vụ kiểm tra sâu nội dung các website lừa đảo có sử dụng kỹ thuật che giấu mã (Cloaking, dynamic JavaScript):

| Gói thư viện | Phiên bản | Giấy phép | Vai trò & Mục đích |
| :--- | :--- | :--- | :--- |
| **express** | ^5.2.1 | MIT | Cung cấp HTTP API nội bộ tại cổng 3010 để Django gọi lệnh điều khiển trình duyệt. |
| **puppeteer** | ^24.38.0 | Apache-2.0 | Tự động hóa trình duyệt Chromium không giao diện (Headless Chrome). |
| **puppeteer-extra** | ^3.3.6 | MIT | Khung mở rộng plugin cho Puppeteer. |
| **puppeteer-extra-plugin-stealth** | ^2.11.2 | MIT | Vượt qua các cơ chế phát hiện bot của website lừa đảo (giả lập thuộc tính `navigator.webdriver`, canvas fingerprint, plugins). |
| **random-useragent** | ^0.5.0 | MIT | Tự động xoay vòng danh tính trình duyệt (User-Agent) phổ biến nhằm tránh bị chặn IP. |
| **ws** | ^8.19.0 | MIT | Quản lý kết nối WebSocket cho các phiên tương tác trực tiếp với trang web. |

---

### 5.3. Thư viện trong Container Docker Sandbox (`sandbox/Dockerfile`)

Môi trường Zero-Trust Sandbox vận hành trong container Docker hoàn toàn cô lập, không có mạng ngoài (`network_mode: none`), quyền root bị loại bỏ (`cap-drop: ALL`), hệ thống tệp chỉ đọc (`read_only: true`):

| Công cụ / Thư viện | Nhà phát triển | Vai trò kỹ thuật trong phân tích mã độc |
| :--- | :--- | :--- |
| **ClamAV & ClamAV Daemon** | Cisco Talos (GPL-2.0) | Quét nhận dạng chữ ký mã độc chuẩn quốc tế trong tệp tin tải lên. |
| **yara-python & libyara** | VirusTotal (BSD-3-Clause) | Khớp mẫu nhị phân, chuỗi ký tự độc hại và kiểm tra hơn 734 quy tắc YARA của Florian Roth. |
| **oletools** | Philippe Lagadec (BSD-2-Clause) | Phân tích sâu các tài liệu Microsoft Office (Word, Excel, PowerPoint) phát hiện mã macro VBA độc hại, mã obfuscated. |
| **pefile** | Ero Carrera (MIT) | Phân tích cấu trúc tệp thực thi Windows PE (EXE, DLL), đọc bảng Import/Export Address Table, phát hiện các API nguy hiểm (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread). |
| **pypdf** | pypdf contributors (BSD-3-Clause) | Phân tích cấu trúc tệp PDF, phát hiện các đối tượng JavaScript nhúng ngầm hoặc lỗ hổng mở luồng tự động. |
| **python-magic & libmagic** | Christos Zoulas (BSD-2-Clause) | Xác định định dạng tệp thực tế dựa trên Magic Bytes thay vì dựa vào phần mở rộng tệp do kẻ tấn công đổi tên. |
| **flare-capa** | Mandiant (Apache-2.0) | Nhận diện các khả năng thực thi hành vi nguy hiểm của mã nhị phân. |
| **exiftool** | Phil Harvey (GPL-1.0-or-later) | Trích xuất toàn bộ siêu dữ liệu ẩn (metadata) của tệp tin phục vụ công tác điều tra số. |
| **p7zip-full** | Igor Pavlov (LGPL) | Hỗ trợ giải nén an toàn các định dạng nén (ZIP, RAR, 7Z) để kiểm tra các payload bên trong. |

---

### 5.4. Thư viện Giao diện Người dùng & Client-side Assets (Frontend Stack)

| Thư viện / Tài nguyên | Nhà phát triển / Nguồn | Giấy phép | Vai trò & Mục đích sử dụng |
| :--- | :--- | :--- | :--- |
| **Tailwind CSS v4** | Tailwind Labs | MIT | Khung CSS Utility-First xây dựng giao diện hiện đại phong cách Liquid Glass. |
| **Alpine.js (v3.x)** | Caleb Porzio | MIT | Khung JavaScript tối giản điều khiển trạng thái giao diện tương tác (modal, accordion suy luận, dropdown). |
| **Chart.js (v4.x)** | Chart.js Team | MIT | Vẽ biểu đồ trực quan hóa dữ liệu thống kê lừa đảo, phân bổ loại hình tấn công trên Scam Radar và Admin Dashboard. |
| **SweetAlert2 (v11)** | Limon Monte | MIT | Hiển thị hộp thoại cảnh báo an toàn, xác nhận thao tác nhạy cảm và thông báo kết quả thân thiện. |
| **Marked.js** | Christopher Jeffrey | MIT | Phân giải Markdown phía trình duyệt cho câu trả lời thời gian thực của AI Assistant và kết quả quét tệp. |
| **CKEditor 5 Community Edition** | CKSource | GPL-2.0-or-later | Trình soạn thảo văn bản giàu tính năng phục vụ đăng bài viết diễn đàn và cẩm nang giáo dục. |
| **Lucide Icons** | Lucide Project | ISC | Bộ biểu tượng vector SVG hiện đại hiển thị trực quan các công cụ quét và trạng thái an toàn. |
| **Bootstrap Icons (v1.11)** | The Bootstrap Authors | MIT | Bộ biểu tượng bổ trợ cho huy hiệu cấp bậc thành viên, cờ cảnh báo và các nút tương tác diễn đàn. |
| **Animate.css (v4.1)** | Daniel Eden | MIT | Thư viện hiệu ứng chuyển động CSS mượt mà cho các thông báo popup và kết quả quét. |
| **AOS (Animate On Scroll v2.3)** | Michał Sajnóg | MIT | Hiệu ứng chuyển động mượt mà khi cuộn trang giới thiệu và các thẻ thống kê. |
| **Google Fonts (Inter)** | Rasmus Andersson | SIL OFL 1.1 | Phông chữ chuẩn quốc tế tối ưu khả năng hiển thị tiếng Việt trên màn hình số độ phân giải cao. |

---

## 6. KÊ KHAI THUẬT TOÁN & CƠ CHẾ BẢO VỆ NỘI BỘ (CORE ALGORITHMS & HEURISTICS)

| Tên thuật toán / Cơ chế | Vị trí trong mã nguồn | Nguyên lý hoạt động | Ứng dụng cụ thể trong hệ thống |
| :--- | :--- | :--- | :--- |
| **Shannon Entropy** | `api/utils/sandbox_analyzer.py` | Tính độ hỗn loạn của chuỗi byte dữ liệu ($H = -\sum p_i \log_2 p_i$, thang điểm 0.0 - 8.0). | Phát hiện mã nguồn bị obfuscate, tệp nhị phân bị nén (packer), payload mã hóa XOR/Base64 độc hại. Nếu entropy > 7.5, hệ thống từ chối mở nội dung thô để tránh tấn công tràn bộ nhớ. |
| **Levenshtein Distance & Homoglyph Substitution** | `api/utils/scan_utils.py` | Tính khoảng cách chỉnh sửa giữa chuỗi tên miền với danh sách tên miền ngân hàng tin cậy, kết hợp bản đồ thay thế ký tự tương đồng thị giác (`0 -> o`, `1 -> l`, `rn -> m`, `vv -> w`). | Phát hiện tấn công giả mạo tên miền (Typosquatting / Lookalike domains) mạo danh các ngân hàng như Vietcombank, Techcombank, MBBank. |
| **Reporter Trust Score & Exponential Decay** | `api/utils/trust_score.py`, `api/utils/scan_utils.py` | Tính toán điểm uy tín người báo cáo dựa trên tỷ lệ báo cáo chính xác trong lịch sử, kết hợp hàm phân rã thời gian $e^{-\lambda \cdot \Delta t}$ với $\lambda = 0.15$. | Ngăn chặn hiện tượng spam báo cáo phá hoại hoặc trả đũa cá nhân; giảm dần trọng số rủi ro của các báo cáo đã quá cũ. |
| **SSRF Protection & Private IP Filtering** | `api/utils/security.py`, `scripts/puppeteer_host/browser/utils.js` | Phân giải toàn bộ địa chỉ IP của hostname trước khi gửi request; chặn triệt để dải IP riêng tư (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), Loopback, Link-local, và endpoint metadata điện toán đám mây (`169.254.169.254`). | Ngăn chặn hoàn toàn các cuộc tấn công Server-Side Request Forgery lợi dụng công cụ quét web để thăm dò hạ tầng mạng nội bộ. |
| **Email Security Forensics (SPF, DKIM, DMARC)** | `api/core/tasks.py`, `api/core/views/scan_views.py` | Bóc tách cú pháp tiêu đề tệp email `.eml`, đối soát bản ghi DNS SPF của máy chủ gửi, xác thực chữ ký số mã hóa DKIM và chính sách căn chỉnh DMARC. | Phát hiện các email mạo danh ngân hàng, hóa đơn điện tử giả mạo có địa chỉ người gửi (From header) bị làm giả. |
| **Định dạng Chuẩn hóa Đa phương thức** | `api/utils/normalization.py` | Chuẩn hóa số điện thoại theo chuẩn quốc gia 0xxx và quốc tế E.164 (+84); chuẩn hóa tên miền theo RFC 3986 (bỏ scheme, port, www); chuẩn hóa email theo RFC 5322. | Đồng nhất hóa dữ liệu đầu vào trước khi tra cứu chỉ mục cơ sở dữ liệu và vector DB, loại bỏ dữ liệu rác. |

---

## 7. KÊ KHAI CÁC CHUẨN GIAO THỨC MỞ (OPEN STANDARDS & PROTOCOLS)

1. **Model Context Protocol (MCP)**:
   - Hệ thống triển khai đầy đủ đặc tả kỹ thuật MCP của Anthropic (JSON-RPC 2.0).
   - Cung cấp hai phương thức vận chuyển: Server-Sent Events (SSE Transport) tại `/api/v1/mcp/sse/` và Streamable JSON-RPC tại `/api/v1/mcp/`.
   - Cho phép các công cụ phân tích an toàn số của ShieldCall VN được gọi trực tiếp bởi các ứng dụng AI hàng đầu thế giới (Claude Desktop, LibreChat, Open WebUI).
2. **Server-Sent Events (SSE - W3C)**:
   - Toàn bộ kết quả phân tích AI và quá trình hiển thị khối suy luận (Thinking block) được truyền tải thời gian thực bằng luồng SSE, đem lại trải nghiệm phản hồi tức thì cho người dùng.
3. **Mã hóa Web Push VAPID (RFC 8291 & RFC 8292)**:
   - Giao thức thông báo đẩy tiêu chuẩn W3C bảo mật với thuật toán đường cong elip ECDSA P-256.
4. **Time-Based One-Time Password (TOTP - RFC 6238)**:
   - Giao thức chuẩn hóa xác thực đa yếu tố không phụ thuộc vào dịch vụ SMS viễn thông.

---

## 8. BIÊN BẢN RÀ SOÁT & DỌN DẸP THƯ VIỆN THỪA, API RÁC (REFACTORING RECORD)

### 8.1. Thư viện phần mềm đã gỡ bỏ khỏi `requirements.txt`

| Tên thư viện gỡ bỏ | Lý do kỹ thuật | Biện pháp thay thế đã kiểm chứng |
| :--- | :--- | :--- |
| `vt-py` | Dự án không gọi API VirusTotal bên ngoài, toàn bộ pipeline quét tệp và URL được thực thi 100% nội bộ (on-premise). | Đã chuyển đổi hoàn toàn sang `LocalSandboxAnalyzer` (Docker Zero-Trust Sandbox + ClamAV + Heuristic Static Analysis). |
| `django-environ` | Thư viện không được nạp ở bất kỳ mô-đun nào trong toàn bộ dự án. | Hệ thống sử dụng trực tiếp `python-dotenv` kết hợp `os.getenv` trong `PKV/settings.py` đem lại sự ổn định và minh bạch cao hơn. |
| `soundfile` | Thư viện âm thanh phụ thuộc không được mã nguồn import hoặc sử dụng. | Tiến trình phiên âm âm thanh `faster-whisper` sử dụng trực tiếp động cơ CTranslate2 và bộ công cụ `ffmpeg` độc lập của hệ điều hành. |
| `django-allauth` (khai báo trùng) | Dòng khai báo `django-allauth` đơn thuần bị trùng lặp với `django-allauth[socialaccount]`. | Hợp nhất thành một dòng khai báo chuẩn xác duy nhất: `django-allauth[socialaccount]`. |

### 8.2. Các điểm cuối API rác / Mã nguồn lỗi thời đã dọn dẹp khỏi `PKV/urls.py`

| Tuyến đường API đã dọn dẹp | Ứng dụng nguồn | Lý do gỡ bỏ | Endpoint thay thế chính thức |
| :--- | :--- | :--- | :--- |
| `/api/v1/check-session` | `api.sessions_api` | Điểm cuối giả lập phiên cũ từ giai đoạn thử nghiệm sơ khởi, không liên kết với cơ chế xác thực Django session/token chuẩn. | Cơ chế Session/Token chuẩn qua `/api/v1/auth/me/` và cookie phiên HTTPS. |
| `/api/v1/check-phone` | `api.phone_security` | Điểm cuối stub trả về dữ liệu mẫu cơ bản, không có tính điểm uy tín hay AI phân tích. | `/api/v1/scan/phone/` tích hợp đầy đủ Hybrid Scoring, Network Signals, và AI kịch bản. |
| `/api/v1/analyze-images` | `api.media_analysis` | Điểm cuối cũ nhận file thô trả OCR thuần, bị bỏ qua hoàn toàn bởi luồng quét web. | `/api/v1/scan/image/` và `/api/v1/scan/analyze-sse/` có bounding box và phân tích bẫy lừa đảo. |
| `/api/v1/analyze-audio` | `api.media_analysis` | Điểm cuối cũ nhận file âm thanh thô, bị bỏ qua hoàn toàn bởi luồng quét web. | `/api/v1/scan/audio/` và `/api/v1/scan/analyze-sse/` tích hợp Faster-Whisper và kịch bản giọng nói. |
| `/api/v1/report-crash` | `api.maintenance` | Điểm cuối ghi nhận crash từ thiết bị cũ không còn sử dụng. | Hệ thống logging chuẩn của Django (`logging.getLogger`) và giám sát tiến trình qua PM2. |

---

## 9. CAM KẾT LIÊM CHÍNH KỸ THUẬT & BẢN QUYỀN

1. **Tính xác thực tuyệt đối**: Toàn bộ danh mục công cụ AI, dữ liệu, API, thư viện, công cụ container sandbox và thuật toán bảo mật được kê khai ở trên đều hiện diện và đang vận hành thực tế 100% trong mã nguồn của ShieldCall VN, không có bất kỳ thành phần hư cấu hay sai lệch nào.
2. **Bản quyền & Giấy phép**: Các thư viện và mô hình mã nguồn mở đều được sử dụng tuân thủ nghiêm ngặt theo các điều khoản cấp phép tương ứng (MIT, Apache-2.0, BSD, GPL, LGPL).
3. **Quyền riêng tư & Bảo vệ dữ liệu**: Hệ thống không lưu trữ trái phép dữ liệu cá nhân nhạy cảm, áp dụng cơ chế băm mật khẩu một chiều PBKDF2/Argon2, bảo mật truyền tải HTTPS/TLS và cơ chế cách ly tuyệt đối đối với các tệp tin nghi ngờ mã độc.
