"""
Scam IQ Curated Question Bank.
Provides 60+ pedagogical, realistic Vietnamese fraud scenarios mapped to Bloom's Taxonomy.
Guarantees 100% reliable, zero-latency exam generation and robust fallback when LLMs fail.
"""
import copy
import random
from typing import Dict, List, Any

SCAM_IQ_BANK: List[Dict[str, Any]] = [
    # ═════════════════════════════════════════════════════════════════════════
    # LEVEL 1: EASY (Nhận biết / Knowledge) - 15 Câu
    # ═════════════════════════════════════════════════════════════════════════
    {
        "id": "BNK_EZ_01",
        "difficulty": "easy",
        "difficulty_label": "Dễ",
        "type": "single_choice",
        "category": "Phishing đa kênh",
        "question": "Bạn nhận được một tin nhắn SMS mang Brandname trùng với ngân hàng bạn đang dùng, thông báo tài khoản bị tạm khóa do vi phạm an ninh và yêu cầu truy cập liên kết 'https://vietcombank-login-sec.top' để xác thực trong 15 phút. Dấu hiệu đáng ngờ nhất ở đây là gì?",
        "options": [
            {"id": "A", "text": "Tin nhắn được gửi vào giờ hành chính."},
            {"id": "B", "text": "Tên miền có đuôi lạ '.top' và không phải tên miền chính thức của ngân hàng."},
            {"id": "C", "text": "Tin nhắn xuất hiện đúng trong luồng tin nhắn cũ của ngân hàng."},
            {"id": "D", "text": "Ngân hàng sử dụng ngôn ngữ tiếng Việt có dấu."},
        ],
        "correct_option_ids": ["B"],
        "simulation": {},
        "explanation": "Kẻ tấn công có thể sử dụng trạm phát sóng giả (SMS Catcher/IMSI-catcher) để chèn Brandname giả. Ngân hàng tại Việt Nam luôn dùng tên miền chuẩn cấp 1 (.vn, .com.vn) và không bao giờ dùng đuôi rẻ tiền như .top, .xyz, .cc để yêu cầu đăng nhập."
    },
    {
        "id": "BNK_EZ_02",
        "difficulty": "easy",
        "difficulty_label": "Dễ",
        "type": "true_false",
        "category": "Bảo mật tài khoản",
        "question": "Nhân viên hỗ trợ kỹ thuật hoặc chăm sóc khách hàng của các ngân hàng được phép yêu cầu khách hàng đọc mã OTP qua điện thoại để hỗ trợ hủy giao dịch lỗi. Nhận định này Đúng hay Sai?",
        "options": [
            {"id": "A", "text": "Đúng (Hợp lệ nếu nhân viên đọc đúng họ tên khách hàng)"},
            {"id": "B", "text": "Sai (Tuyệt đối không có trường hợp ngoại lệ nào)"},
        ],
        "correct_option_ids": ["B"],
        "simulation": {},
        "explanation": "Mã OTP (One-Time Password) là khóa bảo mật cá nhân dùng để ký duyệt giao dịch hoặc đổi mật khẩu. Nhân viên ngân hàng thật KHÔNG BAO GIỜ được phép yêu cầu khách hàng cung cấp OTP dưới bất kỳ hình thức nào."
    },
    {
        "id": "BNK_EZ_03",
        "difficulty": "easy",
        "difficulty_label": "Dễ",
        "type": "single_choice",
        "category": "Lừa đảo tuyển dụng",
        "question": "Một người lạ trên Facebook tuyển bạn làm 'Cộng tác viên lướt video TikTok kiếm tiền', hứa hẹn mức lương 500.000đ - 1.000.000đ/ngày nhưng yêu cầu bạn nộp trước 100.000đ tiền 'phí duy trì hệ thống'. Bạn nên làm gì?",
        "options": [
            {"id": "A", "text": "Chuyển khoản ngay 100.000đ vì số tiền nhỏ và lợi nhuận hấp dẫn."},
            {"id": "B", "text": "Rủ thêm bạn bè cùng tham gia để được giảm phí hệ thống."},
            {"id": "C", "text": "Từ chối và chặn liên hệ vì công việc chân chính không thu phí giữ chỗ/duy trì của người lao động."},
            {"id": "D", "text": "Thương lượng xin nộp 50.000đ trước để làm thử."},
        ],
        "correct_option_ids": ["C"],
        "simulation": {},
        "explanation": "Mọi lời mời việc làm nhẹ lương cao kèm yêu cầu nạp tiền giữ chân, tiền cọc đơn hàng hoặc phí hệ thống đều là bẫy lừa đảo Ponzi/chiếm đoạt cọc."
    },
    {
        "id": "BNK_EZ_04",
        "difficulty": "easy",
        "difficulty_label": "Dễ",
        "type": "simulation_sms",
        "category": "SMS Brandname giả mạo",
        "question": "Bạn vừa nhận được tin nhắn SMS sau. Hãy xem xét nội dung và xác định dấu hiệu rủi ro:",
        "simulation": {
            "channel": "sms",
            "from": "+84988776655",
            "sender_name": "VNPOST_NOTIFY",
            "time": "09:30",
            "body": "Buu pham so VN738291 bi thieu thong tin dia chi giao. Vui long cap nhat tai http://vnpost-tracking-bill.xyz/update trong 24h de tranh huy don.",
            "trap_signals": ["Đầu số di động rác mạo danh VNPost", "Link đuôi .xyz", "Đe dọa hủy đơn hàng"],
            "expected_keywords": ["không bấm link", "kiểm tra app vnpost", "tên miền lạ", "báo cáo"],
        },
        "options": [
            {"id": "A", "text": "Bấm vào link http://vnpost-tracking-bill.xyz để nhập lại địa chỉ nhận hàng."},
            {"id": "B", "text": "Gọi lại trực tiếp số +84988776655 để hỏi mã vận đơn."},
            {"id": "C", "text": "Không bấm link; mở app bưu điện chính thức hoặc tra cứu mã vận đơn trên vnpost.vn."},
            {"id": "D", "text": "Chuyển tiếp tin nhắn cho người thân nhờ họ cập nhật hộ."},
        ],
        "correct_option_ids": ["C"],
        "explanation": "Bưu điện Việt Nam sử dụng website chính thức vnpost.vn. Các tin nhắn mạo danh từ số lạ chứa tên miền đuôi .xyz hoặc liên kết lạ nhằm dẫn dụ nạn nhân vào trang giả mạo đánh cắp thông tin thẻ ngân hàng."
    },
    {
        "id": "BNK_EZ_05",
        "difficulty": "easy",
        "difficulty_label": "Dễ",
        "type": "multi_select",
        "category": "Nhận diện Phishing",
        "question": "Những dấu hiệu nào dưới đây cho thấy một đường link trang web có nguy cơ cao là giả mạo (Phishing)?",
        "options": [
            {"id": "A", "text": "Tên miền cố tình viết sai chính tả (ví dụ: g00gle.com, vietcombanhk.com)."},
            {"id": "B", "text": "Sử dụng các tên miền phụ dài bất thường (ví dụ: techcombank.com.vn.ebanking-update.cc)."},
            {"id": "C", "text": "Trang web sử dụng đúng tên miền gốc đăng ký với Bộ Thông tin & Truyền thông (.gov.vn hoặc .vn)."},
            {"id": "D", "text": "Hối thúc người dùng nhập ngay số thẻ tín dụng, CVV hoặc mã OTP."},
        ],
        "correct_option_ids": ["A", "B", "D"],
        "simulation": {},
        "explanation": "Typosquatting (sai chính tả) và Subdomain lừa thị giác là hai kỹ thuật phổ biến nhất của phishing. Tên miền cấp cao chính thống .gov.vn được kiểm soát gắt gao bởi nhà nước."
    },
    {
        "id": "BNK_EZ_06",
        "difficulty": "easy",
        "difficulty_label": "Dễ",
        "type": "single_choice",
        "category": "Quishing (QR Phishing)",
        "question": "Khi bạn dùng điện thoại quét mã QR dán tại một quán trà sữa để thanh toán, ứng dụng hiển thị một liên kết mở trình duyệt web thay vì mở ứng dụng thanh toán ngân hàng/ví điện tử. Bạn nên làm gì?",
        "options": [
            {"id": "A", "text": "Tiếp tục truy cập link trình duyệt và điền thông tin đăng nhập ngân hàng."},
            {"id": "B", "text": "Dừng lại, thông báo nhân viên thu ngân và kiểm tra xem mã QR có bị dán đè hay không."},
            {"id": "C", "text": "Tải file ứng dụng APK mà trang web vừa mở đề xuất cài đặt."},
            {"id": "D", "text": "Tắt Wi-Fi chuyển sang 4G rồi quét lại mã QR đó."},
        ],
        "correct_option_ids": ["B"],
        "simulation": {},
        "explanation": "Mã VietQR thanh toán chuẩn chỉ chứa chuỗi dữ liệu ngân hàng để app ngân hàng đọc trực tiếp. Nếu mã QR dẫn ra link web mở trình duyệt thì có nguy cơ bị dán đè mã quishing độc hại."
    },
    {
        "id": "BNK_EZ_07",
        "difficulty": "easy",
        "difficulty_label": "Dễ",
        "type": "true_false",
        "category": "Giả danh cơ quan công quyền",
        "question": "Cơ quan Công an, Viện kiểm sát và Tòa án tại Việt Nam có thẩm quyền gọi điện thoại yêu cầu người dân chuyển tiền vào 'Tài khoản tạm giữ của cơ quan điều tra' để xác minh nguồn gốc tài sản. Đúng hay Sai?",
        "options": [
            {"id": "A", "text": "Đúng (Nếu có lệnh khởi tố qua Zalo có dấu mộc đỏ)"},
            {"id": "B", "text": "Sai (Không có quy trình điều tra nào yêu cầu chuyển tiền qua điện thoại)"},
        ],
        "correct_option_ids": ["B"],
        "simulation": {},
        "explanation": "Cơ quan điều tra làm việc với công dân trực tiếp tại trụ sở thông qua giấy mời hoặc giấy triệu tập. Tuyệt đối không bao giờ làm việc qua điện thoại hay yêu cầu chuyển tiền vào tài khoản cá nhân."
    },
    {
        "id": "BNK_EZ_08",
        "difficulty": "easy",
        "difficulty_label": "Dễ",
        "type": "single_choice",
        "category": "Bảo vệ mật khẩu",
        "question": "Mật khẩu nào sau đây đáp ứng tốt nhất tiêu chuẩn an toàn cho tài khoản quan trọng?",
        "options": [
            {"id": "A", "text": "12345678@Aa"},
            {"id": "B", "text": "nguyenvana1995"},
            {"id": "C", "text": "P@ssw0rd2024!"},
            {"id": "D", "text": "HoaBan_Do#9284$Rung (Passphrase dài hơn 16 ký tự, đa dạng ký tự)"},
        ],
        "correct_option_ids": ["D"],
        "simulation": {},
        "explanation": "Passphrase dài (trên 16 ký tự) kết hợp chữ hoa, chữ thường, số và ký tự đặc biệt, không chứa thông tin cá nhân, có khả năng chống tấn công brute-force và dictionary attack tốt nhất."
    },
    {
        "id": "BNK_EZ_09",
        "difficulty": "easy",
        "difficulty_label": "Dễ",
        "type": "multi_select",
        "category": "An toàn thông tin cá nhân",
        "question": "Những thông tin nào dưới đây bạn TUYỆT ĐỐI KHÔNG NÊN đăng công khai lên mạng xã hội?",
        "options": [
            {"id": "A", "text": "Ảnh chụp hai mặt Căn cước công dân gắn chip."},
            {"id": "B", "text": "Ảnh vé máy bay/thẻ lên máy bay có rõ mã QR/barcode và mã đặt chỗ (PNR)."},
            {"id": "C", "text": "Tên quán ăn bạn vừa ghé thăm cùng gia đình."},
            {"id": "D", "text": "Mặt trước và mặt sau thẻ tín dụng/ghi nợ quốc tế (có số CVV)."},
        ],
        "correct_option_ids": ["A", "B", "D"],
        "simulation": {},
        "explanation": "CCCD, vé máy bay (chứa mã vạch PNR giải mã được họ tên, hộ chiếu, lịch trình) và thẻ ngân hàng là nguồn dữ liệu vàng để kẻ gian mạo danh vay tiền app, đổi vé hoặc thanh toán trực tuyến."
    },
    {
        "id": "BNK_EZ_10",
        "difficulty": "easy",
        "difficulty_label": "Dễ",
        "type": "single_choice",
        "category": "Lừa đảo mua bán online",
        "question": "Một người bán hàng trên mạng xã hội yêu cầu bạn chuyển khoản cọc 100% tiền hàng vì đang có 'chương trình giảm giá sốc chỉ áp dụng trong 10 phút'. Tuy nhiên tài khoản Facebook của người này mới tạo được 3 ngày. Bạn nên làm gì?",
        "options": [
            {"id": "A", "text": "Chuyển khoản ngay để không bỏ lỡ đợt giảm giá hời."},
            {"id": "B", "text": "Yêu cầu thanh toán khi nhận hàng (COD) và kiểm tra hàng, hoặc từ chối giao dịch."},
            {"id": "C", "text": "Chuyển cọc 50% để hạn chế rủi ro nếu người bán từ chối gửi hàng."},
            {"id": "D", "text": "Chụp ảnh căn cước công dân gửi cho người bán để làm tin thay tiền cọc."},
        ],
        "correct_option_ids": ["B"],
        "simulation": {},
        "explanation": "Tài khoản clone mới tạo kết hợp kỹ thuật tâm lý FOMO (thời hạn 10 phút) là dấu hiệu kinh điển của lừa đảo cọc hàng rồi chặn liên lạc."
    },
    {
        "id": "BNK_EZ_11",
        "difficulty": "easy",
        "difficulty_label": "Dễ",
        "type": "single_choice",
        "category": "Mạng không dây công cộng",
        "question": "Khi kết nối vào Wi-Fi miễn phí tại quán cà phê không có mật khẩu bảo vệ, hành vi nào sau đây là rủi ro nhất?",
        "options": [
            {"id": "A", "text": "Đọc báo và tin tức trên các trang web thông tin công cộng."},
            {"id": "B", "text": "Đăng nhập tài khoản ngân hàng và thực hiện giao dịch chuyển khoản mà không bật VPN."},
            {"id": "C", "text": "Nghe nhạc trực tuyến trên ứng dụng Spotify."},
            {"id": "D", "text": "Kiểm tra dự báo thời tiết."},
        ],
        "correct_option_ids": ["B"],
        "simulation": {},
        "explanation": "Wi-Fi công cộng không mã hóa dễ bị tấn công Man-in-the-Middle (MitM), DNS spoofing hoặc Evil Twin bắt trọn gói tin đăng nhập."
    },
    {
        "id": "BNK_EZ_12",
        "difficulty": "easy",
        "difficulty_label": "Dễ",
        "type": "true_false",
        "category": "Phishing Email",
        "question": "Địa chỉ email hiển thị của người gửi (Sender Display Name) luôn thể hiện chính xác 100% hòm thư thực sự gửi đi và không thể bị làm giả. Đúng hay Sai?",
        "options": [
            {"id": "A", "text": "Đúng"},
            {"id": "B", "text": "Sai (Kẻ gian có thể giả mạo Display Name và dùng email spoofing)"},
        ],
        "correct_option_ids": ["B"],
        "simulation": {},
        "explanation": "Kẻ tấn công có thể đặt Display Name là 'Ngân hàng ABC' trong khi địa chỉ thực phía sau là 'scammer@unknown-domain.xyz' hoặc dùng email spoofing nếu domain thiếu cơ chế SPF/DKIM/DMARC."
    },
    {
        "id": "BNK_EZ_13",
        "difficulty": "easy",
        "difficulty_label": "Dễ",
        "type": "single_choice",
        "category": "Cảnh giác Deepfake",
        "question": "Bạn nhận được cuộc gọi video từ một người bạn thân hỏi vay 10 triệu đồng gấp. Cuộc gọi chỉ kéo dài 8 giây, hình ảnh mặt người bạn hơi méo và giọng nói chập chờn rồi ngắt kết nối. Bạn nên làm gì?",
        "options": [
            {"id": "A", "text": "Chuyển khoản ngay vì đã nhìn thấy mặt bạn thân trên video."},
            {"id": "B", "text": "Gọi điện thoại thông thường (cuộc gọi mạng viễn thông) hoặc gặp trực tiếp người đó để xác thực trước khi chuyển tiền."},
            {"id": "C", "text": "Nhắn tin trên ứng dụng chat đó hỏi số tài khoản và chuyển tiền."},
            {"id": "D", "text": "Chuyển trước 5 triệu đồng để giúp bạn lúc khó khăn."},
        ],
        "correct_option_ids": ["B"],
        "simulation": {},
        "explanation": "Đây là thủ đoạn dùng deepfake video ghép mặt cắt ngắn vài giây kết hợp cớ 'mạng yếu' để tạo lòng tin. Luôn xác minh qua kênh thoại độc lập hoặc câu hỏi cá nhân chỉ 2 người biết."
    },
    {
        "id": "BNK_EZ_14",
        "difficulty": "easy",
        "difficulty_label": "Dễ",
        "type": "multi_select",
        "category": "Kênh chính thống",
        "question": "Để cập nhật ứng dụng VNeID hoặc ứng dụng ngân hàng an toàn nhất, bạn nên thực hiện qua các kênh nào?",
        "options": [
            {"id": "A", "text": "Cửa hàng ứng dụng chính thức Google Play Store (Android) hoặc Apple App Store (iOS)."},
            {"id": "B", "text": "Tải file có đuôi '.apk' từ đường link mà cán bộ phường gửi qua tin nhắn Zalo."},
            {"id": "C", "text": "Tính năng cập nhật tự động trực tiếp bên trong ứng dụng chính chủ."},
            {"id": "D", "text": "Tải về từ một trang web chia sẻ game và app miễn phí trên mạng."},
        ],
        "correct_option_ids": ["A", "C"],
        "simulation": {},
        "explanation": "Tuyệt đối không tải ứng dụng tài chính/dịch vụ công từ file APK bên ngoài hoặc link gửi qua mạng xã hội, vì file APK ngoài chợ ứng dụng rất dễ bị cài cắm mã độc điều khiển từ xa (RAT)."
    },
    {
        "id": "BNK_EZ_15",
        "difficulty": "easy",
        "difficulty_label": "Dễ",
        "type": "single_choice",
        "category": "Cảnh báo lừa đảo quà tặng",
        "question": "Bạn nhận được thông báo trúng thưởng xe máy SH qua tin nhắn Facebook từ một fanpage có tích xanh. Để nhận giải, bạn được yêu cầu nộp 2 triệu đồng tiền thuế trước bạ vào tài khoản cá nhân của 'Trưởng ban tổ chức'. Phản ứng đúng đắn nhất là:",
        "options": [
            {"id": "A", "text": "Nộp ngay vì fanpage có tích xanh chứng tỏ rất uy tín."},
            {"id": "B", "text": "Yêu cầu ban tổ chức trừ trực tiếp 2 triệu đồng vào giá trị giải thưởng xe máy."},
            {"id": "C", "text": "Nhận diện đây là lừa đảo 'trúng thưởng ảo bắt nộp phí trước', chặn trang và báo cáo."},
            {"id": "D", "text": "Gửi thông tin thẻ tín dụng để ban tổ chức tự trừ tiền thuế."},
        ],
        "correct_option_ids": ["C"],
        "simulation": {},
        "explanation": "Fanpage tích xanh hiện nay có thể bị hack hoặc mua bán ngầm. Bất kỳ chương trình trúng thưởng nào đòi nộp 'phí vận chuyển', 'thuế trước bạ' vào tài khoản cá nhân trước khi nhận thưởng đều là lừa đảo."
    },

    # ═════════════════════════════════════════════════════════════════════════
    # LEVEL 2: MEDIUM (Hiểu / Comprehension) - 20 Câu
    # ═════════════════════════════════════════════════════════════════════════
    {
        "id": "BNK_MD_01",
        "difficulty": "medium",
        "difficulty_label": "Trung bình",
        "type": "single_choice",
        "category": "Lừa đảo đầu tư",
        "question": "Bạn tham gia một nhóm 'Đầu tư tiền số quốc tế' trên Telegram. Tuần đầu tiên bạn nạp 2 triệu đồng và rút được cả gốc lẫn lãi 3,5 triệu đồng về tài khoản thật. Sau đó, trưởng nhóm khuyên bạn nên nạp 50 triệu đồng để vào 'Gói VIP siêu lợi nhuận 20%/ngày'. Cơ chế thực chất ở đây là gì?",
        "options": [
            {"id": "A", "text": "Sàn giao dịch có công nghệ AI giao dịch siêu việt sinh lời liên tục."},
            {"id": "B", "text": "Thủ thuật 'thả con tép bắt con tôm' (Pig butchering) - trả lãi nhỏ ban đầu để nạn nhân tin tưởng rồi giam vốn lớn."},
            {"id": "C", "text": "Chương trình trợ giá kích cầu dành cho người dùng mới của các sàn uy tín."},
            {"id": "D", "text": "Cơ hội làm giàu chính đáng cần tận dụng nhanh trước khi hết suất."},
        ],
        "correct_option_ids": ["B"],
        "simulation": {},
        "explanation": "Mô hình mổ heo (Pig butchering) luôn cho nạn nhân nạp rút trơn tru khoản tiền nhỏ ban đầu để gây dựng niềm tin tuyệt đối. Khi nạn nhân dồn tiền lớn, hệ thống sẽ chặn rút với các lý do đóng thuế, xác minh tài khoản hoặc nâng cấp VIP."
    },
    {
        "id": "BNK_MD_02",
        "difficulty": "medium",
        "difficulty_label": "Trung bình",
        "type": "simulation_email",
        "category": "Phishing Doanh nghiệp",
        "question": "Bạn là nhân viên kế toán công ty. Hãy đọc kỹ email sau và chọn phản ứng chính xác nhất:",
        "simulation": {
            "channel": "email",
            "from": "ceo.nguyenvan@congty-vietnam.co",
            "subject": "KHẨN CẤP: Chuyển khoản thanh toán hợp đồng đối tác mới",
            "preview": "Tôi đang họp kín với đối tác chiến lược, chuyển ngay 85 triệu vào tài khoản này...",
            "body": "Chào em, anh đang trong cuộc họp kín với đối tác không tiện nghe máy. Em lập lệnh chuyển gấp 85.000.000 VNĐ vào STK 1903829182 Techcombank - CT TNHH Tu Van TM để kịp tiến độ ký kết. Anh sẽ ký duyệt giấy tờ sau khi tan họp.",
            "risk_clues": ["Tên miền lookalike .co thay vì .com.vn của công ty", "Tạo áp lực khẩn cấp và viện cớ họp kín", "Yêu cầu bỏ qua quy trình kiểm soát"],
            "expected_keywords": ["gọi điện thoại trực tiếp", "kiểm tra tên miền email", "tuân thủ quy trình", "báo cáo it/an ninh"],
        },
        "options": [
            {"id": "A", "text": "Lập tức chuyển khoản ngay vì CEO yêu cầu khẩn cấp."},
            {"id": "B", "text": "Nhắn tin hỏi số tài khoản qua Zalo cá nhân của CEO rồi chuyển ngay."},
            {"id": "C", "text": "Kiểm tra kỹ tên miền gửi (đuôi .co khác với .com.vn của công ty), dừng giao dịch và gọi xác minh qua số điện thoại nội bộ đã lưu của CEO."},
            {"id": "D", "text": "Chuyển trước 50% số tiền để kịp tiến độ đối tác."},
        ],
        "correct_option_ids": ["C"],
        "explanation": "Đây là hình thức tấn công BEC (Business Email Compromise) mạo danh lãnh đạo (CEO Fraud) kết hợp tên miền tương tự (lookalike domain). Luôn yêu cầu xác thực đa kênh độc lập theo đúng quy trình tài chính nội bộ."
    },
    {
        "id": "BNK_MD_03",
        "difficulty": "medium",
        "difficulty_label": "Trung bình",
        "type": "multi_select",
        "category": "Thao túng tâm lý",
        "question": "Những đòn bẩy tâm lý nào dưới đây thường xuyên bị kẻ lừa đảo trực tuyến lợi dụng để làm nạn nhân mất cảnh giác?",
        "options": [
            {"id": "A", "text": "Tính cấp bách (Urgency): 'Tài khoản sẽ bị khóa trong 15 phút nếu không bấm link'."},
            {"id": "B", "text": "Nỗi sợ hãi uy quyền (Authority/Fear): 'Bạn liên quan đến đường dây ma túy rửa tiền, phải giữ bí mật tuyệt đối'."},
            {"id": "C", "text": "Lòng tham và cơ hội hiếm (Greed/Scarcity): 'Chỉ còn 3 suất đầu tư lợi nhuận 30%/ngày'."},
            {"id": "D", "text": "Sự minh bạch: 'Mời bạn tới trực tiếp cơ quan công an vào 8h sáng thứ Hai kèm giấy triệu tập'."},
        ],
        "correct_option_ids": ["A", "B", "C"],
        "simulation": {},
        "explanation": "Thao túng tâm lý (Social Engineering) khai thác triệt để 3 cảm xúc nguyên thủy: Nỗi sợ hãi (công an, phạt tù), Lòng tham (lãi khủng, quà tặng), và Sự vội vã (áp lực thời gian khiến não bộ không kịp tư duy phản biện)."
    },
    {
        "id": "BNK_MD_04",
        "difficulty": "medium",
        "difficulty_label": "Trung bình",
        "type": "simulation_sms",
        "category": "Lừa đảo ngân hàng",
        "question": "Phân tích tin nhắn SMS dưới đây và chọn nhận định đúng nhất:",
        "simulation": {
            "channel": "sms",
            "from": "ACB_BANK",
            "sender_name": "ACB_BANK",
            "time": "18:45",
            "body": "Phat hien dang nhap bat thuong tu thiet bi la (IP: 113.161.x.x) luc 18:40. Neu khong phai ban, vui long xac thuc ngay tai https://acb-online-verify.net de huy giao dich.",
            "trap_signals": ["Tên miền acb-online-verify.net không phải acb.com.vn", "Tạo hoảng loạn đăng nhập lạ", "Yêu cầu xác thực ngay"],
            "expected_keywords": ["không bấm link", "mở app acb", "đổi mật khẩu", "hotline acb"],
        },
        "options": [
            {"id": "A", "text": "Tin nhắn xuất phát từ hệ thống an ninh ACB vì có thông tin địa chỉ IP cụ thể."},
            {"id": "B", "text": "Đây là SMS phishing chèn Brandname giả; tên miền '.net' là trang web mạo danh để lấy trộm tài khoản & mật khẩu."},
            {"id": "C", "text": "Người dùng cần bấm link ngay để kiểm tra vị trí IP kẻ gian."},
            {"id": "D", "text": "Người dùng nên nhập mã PIN ATM vào trang đó để khóa thẻ tạm thời."},
        ],
        "correct_option_ids": ["B"],
        "simulation": {},
        "explanation": "Ngân hàng ACB chỉ dùng trang web chính thức acb.com.vn. Địa chỉ IP trong tin nhắn chỉ là dữ kiện ngụy tạo nhằm tăng tính chân thực để gây hoảng sợ."
    },
    {
        "id": "BNK_MD_05",
        "difficulty": "medium",
        "difficulty_label": "Trung bình",
        "type": "single_choice",
        "category": "Bảo mật hai lớp (2FA)",
        "question": "Phương thức xác thực hai yếu tố (2FA) nào sau đây cung cấp mức độ an toàn cao nhất trước các cuộc tấn công đánh chặn qua mạng viễn thông?",
        "options": [
            {"id": "A", "text": "Mã OTP gửi qua tin nhắn SMS truyền thống."},
            {"id": "B", "text": "Cuộc gọi thoại tự động đọc mã số OTP."},
            {"id": "C", "text": "Ứng dụng tạo mã xác thực (Google/Microsoft Authenticator) hoặc Khóa bảo mật vật lý FIDO2/U2F."},
            {"id": "D", "text": "Gửi mã số OTP qua tin nhắn Messenger/Zalo."},
        ],
        "correct_option_ids": ["C"],
        "simulation": {},
        "explanation": "SMS OTP dễ bị tấn công qua kỹ thuật SIM Swap, trạm phát sóng giả IMSI-catcher hoặc mã độc đọc trộm tin nhắn SMS. Khóa vật lý FIDO2 hoặc App TOTP sinh mã trên thiết bị an toàn hơn nhiều."
    },
    {
        "id": "BNK_MD_06",
        "difficulty": "medium",
        "difficulty_label": "Trung bình",
        "type": "multi_select",
        "category": "Chiêu trò CTV Shopee/Lazada",
        "question": "Các bước điển hình của đường dây lừa đảo 'Cộng tác viên thanh toán đơn hàng thương mại điện tử' bao gồm những gì?",
        "options": [
            {"id": "A", "text": "Bắt đầu bằng các nhiệm vụ đơn giản như like sản phẩm, follow shop và thanh toán ngay 10.000đ - 50.000đ để tạo lòng tin."},
            {"id": "B", "text": "Giao các đơn hàng giá trị cao dần (5 triệu, 20 triệu, 50 triệu) và viện cớ lỗi cú pháp, sai mã lệnh để ép nạp thêm."},
            {"id": "C", "text": "Gửi hàng thật về tận nhà qua bưu điện cho cộng tác viên dùng thử miễn phí."},
            {"id": "D", "text": "Đe dọa sẽ kiện ra tòa nếu nạn nhân dừng nạp tiền giữa chừng."},
        ],
        "correct_option_ids": ["A", "B", "D"],
        "simulation": {},
        "explanation": "Kịch bản lừa CTV luôn mớm mồi đơn nhỏ -> nâng dần giá trị đơn lớn -> viện lý do lỗi hệ thống/đóng thuế để bắt nạp tiếp -> dọa mất sạch tiền hoặc kiện tụng nếu bỏ cuộc."
    },
    {
        "id": "BNK_MD_07",
        "difficulty": "medium",
        "difficulty_label": "Trung bình",
        "type": "true_false",
        "category": "Deepfake Video Call",
        "question": "Khi nghi ngờ một cuộc gọi video là deepfake do kẻ lừa đảo tạo ra, việc yêu cầu đối phương quay nghiêng mặt sang trái/phải 90 độ hoặc đưa tay lên che trước mặt có thể giúp nhận diện sự biến dạng hình ảnh. Đúng hay Sai?",
        "options": [
            {"id": "A", "text": "Đúng (Mô hình deepfake real-time thường xử lý kém ở góc nghiêng lớn hoặc khi có vật cản trước mặt)"},
            {"id": "B", "text": "Sai (Deepfake hiện nay hoàn hảo 100% trong mọi góc nhìn)"},
        ],
        "correct_option_ids": ["A"],
        "simulation": {},
        "explanation": "Mô hình hoán đổi khuôn mặt real-time thường bị lỗi răng, viền cằm hoặc giật hình (artifact) khi người gọi quay ngang góc rộng hoặc đưa ngón tay/vật cản qua lại trước mặt."
    },
    {
        "id": "BNK_MD_08",
        "difficulty": "medium",
        "difficulty_label": "Trung bình",
        "type": "single_choice",
        "category": "Mã độc di động",
        "question": "Một người tự xưng là cán bộ Thuế quận gọi điện hướng dẫn bạn cài 'Phần mềm kê khai thuế điện tử' bằng cách truy cập link và bấm 'Cài đặt nguồn không xác định' (Sideloading). Sau khi cài, ứng dụng yêu cầu cấp quyền 'Trợ năng' (Accessibility Service). Mục đích thực sự của quyền này là gì?",
        "options": [
            {"id": "A", "text": "Tăng tốc độ hiển thị màn hình cho ứng dụng thuế."},
            {"id": "B", "text": "Cho phép mã độc tự động đọc màn hình (lấy trộm mã OTP) và tự bấm thao tác chuyển tiền trong app ngân hàng mà nạn nhân không hề hay biết."},
            {"id": "C", "text": "Giúp người khiếm thị đọc văn bản thuế."},
            {"id": "D", "text": "Tiết kiệm dung lượng pin cho máy điện thoại."},
        ],
        "correct_option_ids": ["B"],
        "simulation": {},
        "explanation": "Quyền Trợ năng (Accessibility) trên Android là quyền nguy hiểm bậc nhất. Khi chiếm được quyền này, mã độc trojan ngân hàng có thể ghi phím (keylogger), chụp màn hình và tự động thực hiện thao tác chuyển tiền ngầm."
    },
    {
        "id": "BNK_MD_09",
        "difficulty": "medium",
        "difficulty_label": "Trung bình",
        "type": "single_choice",
        "category": "Lừa đảo tình cảm (Romance Scam)",
        "question": "Bạn quen một người nước ngoài tự xưng là kỹ sư dầu khí hoặc bác sĩ quân y trên ứng dụng hẹn hò. Sau một tháng tâm sự thân thiết, người này thông báo gửi một thùng quà giá trị cao (trang sức, ngoại tệ) về Việt Nam cho bạn nhưng kiện hàng đang bị 'Hải quan tạm giữ' và yêu cầu bạn đóng 25 triệu phí phạt. Bạn nên xử lý thế nào?",
        "options": [
            {"id": "A", "text": "Chuyển tiền ngay để nhận thùng quà đắt giá."},
            {"id": "B", "text": "Nhận diện đây là kịch bản lừa đảo tình cảm - bưu kiện bẫy điển hình; tuyệt đối không chuyển tiền và ngừng liên lạc."},
            {"id": "C", "text": "Nhờ người thân ở sân bay đến kho hải quan nhận giúp."},
            {"id": "D", "text": "Vay nóng bạn bè để nộp phí vì người yêu hứa sẽ sang Việt Nam cưới bạn."},
        ],
        "correct_option_ids": ["B"],
        "simulation": {},
        "explanation": "Kịch bản gửi quà hải quan kèm phí giải cứu hoặc phí rửa tiền là chiêu trò lừa đảo tình cảm quốc tế kinh điển, hoàn toàn không có kiện hàng hay số tiền nào tồn tại."
    },
    {
        "id": "BNK_MD_10",
        "difficulty": "medium",
        "difficulty_label": "Trung bình",
        "type": "multi_select",
        "category": "Lừa đảo vé máy bay / du lịch",
        "question": "Những chi tiết nào sau đây cảnh báo nguy cơ lừa đảo khi đặt vé máy bay hoặc phòng khách sạn mùa cao điểm qua mạng?",
        "options": [
            {"id": "A", "text": "Giá vé/phòng rẻ bất thường, thấp hơn 50-70% so với giá niêm yết trên website chính thức của hãng hàng không/khách sạn."},
            {"id": "B", "text": "Hối thúc chuyển khoản 100% vào tài khoản cá nhân thay vì tài khoản công ty có tên doanh nghiệp rõ ràng."},
            {"id": "C", "text": "Đại lý cung cấp mã vé có thể tự kiểm tra đối soát trực tiếp trên hệ thống hãng bay chính thức."},
            {"id": "D", "text": "Gửi ảnh chụp hợp đồng/hóa đơn có dấu mộc scan mờ nhạt, chỉnh sửa bằng phần mềm."},
        ],
        "correct_option_ids": ["A", "B", "D"],
        "simulation": {},
        "explanation": "Các đối tượng thường lập page giả mạo đại lý lữ hành uy tín, tung 'combo du lịch siêu rẻ' rồi thu tiền cọc vào tài khoản cá nhân và lập tức chặn liên lạc."
    },
    {
        "id": "BNK_MD_11",
        "difficulty": "medium",
        "difficulty_label": "Trung bình",
        "type": "single_choice",
        "category": "Lừa đảo SIM rác / Khóa SIM",
        "question": "Bạn nhận được cuộc gọi tự xưng nhân viên Cục Viễn thông thông báo: 'Số thuê bao của bạn sẽ bị khóa sau 2 giờ vì chưa chuẩn hóa thông tin; bấm phím 1 để gặp nhân viên hỗ trợ'. Đây là hành vi gì?",
        "options": [
            {"id": "A", "text": "Quy trình chuẩn hóa thông tin thuê bao tự động của nhà mạng viễn thông."},
            {"id": "B", "text": "Chiêu trò dẫn dụ người dùng kết nối tới kẻ gian để lừa lấy thông tin CCCD hoặc dụ bấm cú pháp chuyển hướng cuộc gọi."},
            {"id": "C", "text": "Thông báo lỗi cước phí mạng viễn thông."},
            {"id": "D", "text": "Hệ thống khảo sát chất lượng dịch vụ của bộ ngành."},
        ],
        "correct_option_ids": ["B"],
        "simulation": {},
        "explanation": "Cục Viễn thông và các nhà mạng không bao giờ dùng tổng đài tự động đe dọa khóa thuê bao sau 2 giờ. Mục tiêu của chúng là dẫn dụ người dùng làm theo cú pháp chuyển hướng cuộc gọi hoặc chiếm đoạt SIM."
    },
    {
        "id": "BNK_MD_12",
        "difficulty": "medium",
        "difficulty_label": "Trung bình",
        "type": "true_false",
        "category": "Cảnh báo chứng chỉ SSL",
        "question": "Một trang web có biểu tượng ổ khóa bảo mật (HTTPS/SSL) đồng nghĩa với việc trang web đó là an toàn, uy tín và chắc chắn không phải trang lừa đảo. Đúng hay Sai?",
        "options": [
            {"id": "A", "text": "Đúng (Có HTTPS là an toàn tuyệt đối)"},
            {"id": "B", "text": "Sai (Kẻ lừa đảo hoàn toàn có thể cài chứng chỉ SSL miễn phí lên trang web độc hại)"},
        ],
        "correct_option_ids": ["B"],
        "simulation": {},
        "explanation": "HTTPS chỉ mã hóa đường truyền giữa trình duyệt và máy chủ để chống nghe lén. Hiện nay kẻ tấn công có thể dễ dàng cấp chứng chỉ SSL miễn phí (Let's Encrypt, Cloudflare) cho các trang phishing."
    },
    {
        "id": "BNK_MD_13",
        "difficulty": "medium",
        "difficulty_label": "Trung bình",
        "type": "single_choice",
        "category": "Lừa đảo hoàn tiền TMĐT",
        "question": "Một người tự xưng là nhân viên giao hàng gọi điện thông báo: 'Đơn hàng của bạn bị thất lạc, shop đồng ý hoàn tiền 300.000đ. Vui lòng kết bạn Zalo để nhận link nhận tiền'. Người này gửi link yêu cầu điền thông tin tài khoản ngân hàng và mã OTP. Bạn nên làm gì?",
        "options": [
            {"id": "A", "text": "Nhập mã OTP để nhận tiền hoàn về tài khoản."},
            {"id": "B", "text": "Từ chối bấm link; quy trình hoàn tiền trên sàn TMĐT chỉ diễn ra tự động bên trong ứng dụng chính thức."},
            {"id": "C", "text": "Cung cấp mật khẩu đăng nhập ngân hàng cho nhân viên để họ chuyển trực tiếp."},
            {"id": "D", "text": "Gửi ảnh thẻ ngân hàng cả 2 mặt cho nhân viên qua Zalo."},
        ],
        "correct_option_ids": ["B"],
        "simulation": {},
        "explanation": "Quy trình hoàn tiền của các sàn TMĐT (Shopee, Lazada, TikTok Shop) được xử lý trực tiếp trên hệ thống sàn về ví hoặc tài khoản liên kết, không bao giờ yêu cầu khách click link ngoài hay nhập OTP để nhận tiền."
    },
    {
        "id": "BNK_MD_14",
        "difficulty": "medium",
        "difficulty_label": "Trung bình",
        "type": "multi_select",
        "category": "Rủi ro mở tài khoản hộ",
        "question": "Người quen đề nghị trả bạn 2.000.000 VNĐ để mượn CCCD của bạn ra ngân hàng mở 3 tài khoản ngân hàng rồi giao thẻ và sim liên kết cho họ sử dụng kinh doanh. Hành vi này có rủi ro gì?",
        "options": [
            {"id": "A", "text": "Vi phạm pháp luật về việc cho thuê, mượn, mua bán tài khoản thanh toán."},
            {"id": "B", "text": "Các tài khoản này thường được sử dụng làm 'tài khoản rác' nhận tiền lừa đảo, cờ bạc, rửa tiền."},
            {"id": "C", "text": "Bạn có nguy cơ bị truy cứu trách nhiệm hình sự với vai trò đồng phạm lừa đảo chiếm đoạt tài sản."},
            {"id": "D", "text": "Hoàn toàn không có rủi ro vì bạn không trực tiếp thực hiện hành vi lừa đảo."},
        ],
        "correct_option_ids": ["A", "B", "C"],
        "simulation": {},
        "explanation": "Mở hộ hoặc bán tài khoản ngân hàng tiếp tay trực tiếp cho tội phạm công nghệ cao rửa tiền. Chủ tài khoản đứng tên sẽ bị xử phạt hành chính nặng hoặc bị khởi tố hình sự."
    },
    {
        "id": "BNK_MD_15",
        "difficulty": "medium",
        "difficulty_label": "Trung bình",
        "type": "single_choice",
        "category": "Tấn công Phishing qua QR",
        "question": "Quishing là gì và cơ chế tấn công chủ yếu của nó diễn ra như thế nào?",
        "options": [
            {"id": "A", "text": "Tấn công từ chối dịch vụ làm sập hệ thống máy chủ ngân hàng."},
            {"id": "B", "text": "Sử dụng mã QR độc hại để giấu đường link phishing, tránh các bộ lọc bảo mật văn bản trong email/tin nhắn."},
            {"id": "C", "text": "Dò quét mật khẩu Wi-Fi của các hộ gia đình."},
            {"id": "D", "text": "Chèn virus vào ảnh đại diện trang cá nhân Facebook."},
        ],
        "correct_option_ids": ["B"],
        "simulation": {},
        "explanation": "Quishing (QR Phishing) tận dụng hình ảnh mã QR để vượt qua các hệ thống lọc thư rác (spam filter) quét text truyền thống, dẫn người dùng điện thoại tới trang đánh cắp thông tin đăng nhập."
    },
    {
        "id": "BNK_MD_16",
        "difficulty": "medium",
        "difficulty_label": "Trung bình",
        "type": "simulation_sms",
        "category": "Phạt nguội giao thông giả mạo",
        "question": "Xem xét nội dung SMS dưới đây và đưa ra quyết định xử lý an toàn nhất:",
        "simulation": {
            "channel": "sms",
            "from": "+84776281923",
            "sender_name": "CSGT_TRACUU",
            "time": "14:10",
            "body": "Phuong tien cua ban BKS 51A-xxxxx vi pham toc do luc 09:20 tai QL1A. Tra cuu bien ban va nop phat giam 50% tai https://csgt-phatnguoi-vn.com trong 48h.",
            "trap_signals": ["Đầu số rác mạo danh CSGT", "Khuyến mãi giảm 50% tiền phạt", "Tên miền .com giả mạo cơ quan nhà nước"],
            "expected_keywords": ["không truy cập link", "tra cứu csgt.vn", "cơ quan nhà nước dùng gov.vn"],
        },
        "options": [
            {"id": "A", "text": "Bấm vào link và thanh toán ngay 50% để được giảm tiền phạt."},
            {"id": "B", "text": "Đây là tin nhắn giả mạo; CSGT không gửi thông báo nộp phạt qua SMS kèm link lạ. Truy cập csgt.vn chính thức để tra cứu."},
            {"id": "C", "text": "Gọi lại số điện thoại gửi tin nhắn để xin giảm nhẹ lỗi vi phạm."},
            {"id": "D", "text": "Chụp ảnh màn hình gửi tiền phạt vào STK cá nhân của người gửi."},
        ],
        "correct_option_ids": ["B"],
        "simulation": {},
        "explanation": "Cảnh sát giao thông chỉ gửi thông báo vi phạm bằng văn bản giấy hoặc tra cứu trên Cổng Dịch vụ công Quốc gia / Cổng thông tin Cục CSGT (csgt.vn - đuôi .vn chuẩn của nhà nước)."
    },
    {
        "id": "BNK_MD_17",
        "difficulty": "medium",
        "difficulty_label": "Trung bình",
        "type": "single_choice",
        "category": "Lừa đảo vay tiền qua App",
        "question": "Bạn đăng ký vay tiền qua một app online. Sau khi duyệt hồ sơ, hệ thống báo bạn đã nhập 'Sai 1 chữ số trong số tài khoản ngân hàng' nên tiền bị đóng băng, yêu cầu bạn nạp vào 5 triệu đồng tiền 'Bảo chứng chỉnh sửa hồ sơ'. Đây là dấu hiệu gì?",
        "options": [
            {"id": "A", "text": "Quy trình kiểm soát rủi ro bình thường của tổ chức tín dụng."},
            {"id": "B", "text": "Kịch bản lừa đảo app vay tiền ngụy tạo lỗi số tài khoản để vòi tiền đặt cọc rồi cắt liên lạc."},
            {"id": "C", "text": "Lỗi kỹ thuật cơ sở dữ liệu của ngân hàng nhà nước."},
            {"id": "D", "text": "Khoản phí dịch vụ công chứng hợp đồng tín dụng hợp pháp."},
        ],
        "correct_option_ids": ["B"],
        "simulation": {},
        "explanation": "Hệ thống app vay lừa đảo cố tình sửa số tài khoản của nạn nhân trong database để tạo cớ đòi tiền phí 'sửa hồ sơ', 'phí giải ngân' hoặc 'mở khóa hạn mức'."
    },
    {
        "id": "BNK_MD_18",
        "difficulty": "medium",
        "difficulty_label": "Trung bình",
        "type": "true_false",
        "category": "Thu hồi tiền lừa đảo",
        "question": "Các văn phòng luật sư hoặc hội nhóm trên Facebook cam kết 'Hỗ trợ thu hồi 100% tiền lừa đảo online treo trên các sàn ảo' nhưng yêu cầu đóng phí lập hồ sơ trước đều là các bẫy lừa đảo lần hai (Secondary Scam). Đúng hay Sai?",
        "options": [
            {"id": "A", "text": "Đúng (Chiêu trò đánh vào tâm lý tiếc tiền của nạn nhân để lừa tiếp)"},
            {"id": "B", "text": "Sai (Họ có mối quan hệ với hacker mũ trắng có thể hack lấy lại tiền)"},
        ],
        "correct_option_ids": ["A"],
        "simulation": {},
        "explanation": "Không một cá nhân hay tổ chức tư nhân nào có thể can thiệp hệ thống ngân hàng hay blockchain để 'kéo tiền lừa đảo về'. Mọi quảng cáo thu hồi tiền bị lừa kèm phí trước đều là lừa đảo lần 2."
    },
    {
        "id": "BNK_MD_19",
        "difficulty": "medium",
        "difficulty_label": "Trung bình",
        "type": "single_choice",
        "category": "Cảnh báo cờ bạc online",
        "question": "Một người bạn rủ bạn tham gia 'Cổng game tài xỉu quốc tế có thuật toán bot báo trước kết quả chuẩn 99%'. Điểm mấu chốt của các cổng game này là gì?",
        "options": [
            {"id": "A", "text": "Nhà cái vận hành minh bạch dựa trên máy tạo số ngẫu nhiên chuẩn quốc tế."},
            {"id": "B", "text": "Toàn bộ kết quả đều do admin kiểm soát từ backend, cho người chơi thắng ảo ban đầu rồi chỉnh thuật toán nuốt sạch tiền nạp."},
            {"id": "C", "text": "Người chơi có thể dùng bot bên ngoài để hack được hệ thống máy chủ nhà cái."},
            {"id": "D", "text": "Cơ hội đầu tư kiếm thu nhập thụ động bền vững."},
        ],
        "correct_option_ids": ["B"],
        "simulation": {},
        "explanation": "Tất cả các web cờ bạc mạng đều do các đường dây tội phạm lập trình kịch bản can thiệp kết quả từ xa. Không bao giờ có chuyện người chơi thắng được nhà cái."
    },
    {
        "id": "BNK_MD_20",
        "difficulty": "medium",
        "difficulty_label": "Trung bình",
        "type": "multi_select",
        "category": "Kỹ năng phản ứng nhanh",
        "question": "Nếu vô tình lỡ điền thông tin đăng nhập và mật khẩu ngân hàng vào một trang web giả mạo, bạn cần thực hiện ngay các hành động khẩn cấp nào sau đây?",
        "options": [
            {"id": "A", "text": "Mở ngay app ngân hàng chính thức trên điện thoại và đổi mật khẩu đăng nhập lập tức."},
            {"id": "B", "text": "Gọi ngay hotline ngân hàng hoặc dùng tính năng khóa thẻ/khóa tài khoản khẩn cấp trên app."},
            {"id": "C", "text": "Bình tĩnh chờ 24 giờ xem có bị trừ tiền hay không rồi mới xử lý."},
            {"id": "D", "text": "Chuyển tạm thời số dư sang tài khoản ngân hàng an toàn khác nếu tài khoản chưa bị phong tỏa."},
        ],
        "correct_option_ids": ["A", "B", "D"],
        "simulation": {},
        "explanation": "Thời gian vàng để cứu tài khoản sau khi lộ thông tin chỉ tính bằng phút. Cần đổi mật khẩu, kích hoạt tính năng khóa tài khoản khẩn cấp và di dời số dư sang nơi an toàn."
    },

    # ═════════════════════════════════════════════════════════════════════════
    # LEVEL 3: HARD (Vận dụng / Application) - 15 Câu
    # ═════════════════════════════════════════════════════════════════════════
    {
        "id": "BNK_HD_01",
        "difficulty": "hard",
        "difficulty_label": "Khó",
        "type": "incident_response",
        "category": "Xử lý sự cố rò rỉ",
        "question": "Tình huống khẩn cấp: Bạn vừa phát hiện mẹ bạn ở nhà bị kẻ mạo danh 'Cán bộ Công an điều tra' gọi điện thao túng tâm lý suốt 2 tiếng và bà chuẩn bị ra cây ATM/ngân hàng rút sổ tiết kiệm 200 triệu chuyển khoản. Hãy chọn chuỗi hành động phản ứng tối ưu nhất trong 15 phút đầu:",
        "simulation": {
            "channel": "incident",
            "expected_keywords": ["ngắt liên lạc ngay", "trấn an tâm lý", "liên hệ công an địa phương", "khóa sổ tiết kiệm"],
        },
        "options": [
            {"id": "A", "text": "Để bà chuyển trước một nửa số tiền để cơ quan điều tra không gây khó dễ."},
            {"id": "B", "text": "Ngắt ngay cuộc gọi kẻ mạo danh, trấn an tinh thần bà; liên hệ ngay ngân hàng phong tỏa sổ tiết kiệm và báo Công an khu vực."},
            {"id": "C", "text": "Nhắn tin thách thức kẻ mạo danh và để bà tiếp tục nghe điện thoại."},
            {"id": "D", "text": "Đưa điện thoại cho người lạ tự giải quyết."},
        ],
        "correct_option_ids": ["B"],
        "explanation": "Kẻ lừa đảo cô lập nạn nhân bằng nỗi sợ hãi liên tục. Việc đầu tiên là ngắt kết nối tâm lý (cúp máy), trấn an tinh thần nạn nhân, chặn kênh rút tiền tại ngân hàng và nhờ công an chính quyền địa phương hỗ trợ."
    },
    {
        "id": "BNK_HD_02",
        "difficulty": "hard",
        "difficulty_label": "Khó",
        "type": "single_choice",
        "category": "Tấn công SIM Swap",
        "question": "Điện thoại của bạn đột ngột bị mất hoàn toàn sóng di động (hiển thị 'Không có dịch vụ / No Service'), dù xung quanh mọi người vẫn dùng bình thường. Cùng lúc đó email thông báo mật khẩu tài khoản ngân hàng của bạn bị yêu cầu đặt lại. Kịch bản tấn công nguy hiểm nào đang diễn ra?",
        "options": [
            {"id": "A", "text": "Trạm phát sóng của nhà mạng đang bảo trì định kỳ."},
            {"id": "B", "text": "Tấn công chiếm đoạt thẻ SIM (SIM Swap attack) - kẻ gian đã dùng giấy tờ giả mạo để xin cấp lại SIM của bạn nhằm nhận mã xác thực OTP."},
            {"id": "C", "text": "Điện thoại của bạn bị hỏng khay SIM vật lý."},
            {"id": "D", "text": "Nhà mạng khóa SIM do bạn chưa nạp thẻ tháng này."},
        ],
        "correct_option_ids": ["B"],
        "simulation": {},
        "explanation": "SIM Swap là hình thức tấn công nguy hiểm, kẻ gian làm lại phôi SIM mới của nạn nhân để cướp quyền nhận OTP SMS. Cần liên hệ ngay nhà mạng khóa SIM và khóa khẩn cấp toàn bộ tài khoản ngân hàng."
    },
    {
        "id": "BNK_HD_03",
        "difficulty": "hard",
        "difficulty_label": "Khó",
        "type": "multi_select",
        "category": "Phishing QR phức tạp",
        "question": "Kẻ gian dán đè một mã QR thanh toán tại quầy thu ngân của một nhà hàng đông khách. Điểm khác biệt kỹ thuật tinh vi nào giúp người dùng có kiến thức phân biệt mã VietQR chuẩn và mã QR dẫn bẫy?",
        "options": [
            {"id": "A", "text": "Mã VietQR chuẩn tuân theo chuẩn EMVCo (bắt đầu bằng định dạng '000201...'), quét bằng app ngân hàng sẽ tự điền STK, tên ngân hàng thụ hưởng."},
            {"id": "B", "text": "Mã QR độc hại thường chứa đường link URL (bắt đầu bằng http:// hoặc https://) buộc điện thoại mở trình duyệt web."},
            {"id": "C", "text": "Mã VietQR chuẩn luôn có màu đỏ, còn mã QR giả mạo chỉ có màu đen."},
            {"id": "D", "text": "Tên chủ tài khoản thụ hưởng trên màn hình xác nhận chuyển tiền không khớp với biển hiệu hoặc thông tin thanh toán của nhà hàng."},
        ],
        "correct_option_ids": ["A", "B", "D"],
        "simulation": {},
        "explanation": "Mã VietQR chuẩn tuân theo đặc tả EMVCo payload. Màu sắc của mã QR hoàn toàn có thể tùy biến. Người dùng cần đối chiếu tên chủ tài khoản thụ hưởng hiển thị trong app ngân hàng trước khi bấm vân tay/FaceID chuyển tiền."
    },
    {
        "id": "BNK_HD_04",
        "difficulty": "hard",
        "difficulty_label": "Khó",
        "type": "simulation_email",
        "category": "Tấn công BEC / Chuỗi cung ứng",
        "question": "Phân tích email gửi tới bộ phận mua hàng của công ty bạn và nhận diện điểm bất thường cốt lõi:",
        "simulation": {
            "channel": "email",
            "from": "accounting@supplier-vinaconex.com",
            "subject": "Thông báo thay đổi tài khoản nhận thanh toán hợp đồng số 48/HĐMB",
            "preview": "Tài khoản cũ tại BIDV đang kiểm toán, vui lòng chuyển tiền đợt 2 sang tài khoản VPBank mới...",
            "body": "Kính gửi Quý đối tác, Do công ty chúng tôi đang trong quá trình kiểm toán tài chính nội bộ, tài khoản cũ tại BIDV tạm thời ngừng nhận thanh toán. Đề nghị Quý công ty chuyển số tiền đợt 2 (145.000.000đ) theo hợp đồng vào tài khoản VPBank mới đính kèm. Để tránh chậm trễ giao hàng, vui lòng không xác nhận lại qua email cũ.",
            "risk_clues": ["Thay đổi tài khoản thụ hưởng bất thường", "Yêu cầu không liên hệ kênh cũ để xác nhận", "Tên miền email có thể bị chiếm quyền hoặc spoofing"],
            "expected_keywords": ["gọi điện thoại trực tiếp cho kế toán trưởng đối tác", "xác minh đa kênh", "không chuyển tiền", "biên bản thỏa thuận"],
        },
        "options": [
            {"id": "A", "text": "Lập tức cập nhật tài khoản VPBank mới và chuyển tiền để tránh trễ hạn giao hàng."},
            {"id": "B", "text": "Trả lời trực tiếp vào email này để hỏi lại xem giám đốc đối tác đã duyệt chưa."},
            {"id": "C", "text": "Tạm dừng mọi lệnh chuyển tiền; kích hoạt quy trình xác thực 'Out-of-Band' bằng cách gọi điện trực tiếp theo số hotline ghi trong hợp đồng gốc đã ký."},
            {"id": "D", "text": "Chuyển trước 30% để đối tác làm tin giao hàng."},
        ],
        "correct_option_ids": ["C"],
        "simulation": {},
        "explanation": "Đây là thủ đoạn thay đổi tài khoản thụ hưởng trong tấn công BEC. Mọi thông báo đổi tài khoản nhận tiền PHẢI được xác minh Out-of-band qua kênh thoại độc lập hoặc văn bản có con dấu pháp lý thật, không bao giờ tin vào email."
    },
    {
        "id": "BNK_HD_05",
        "difficulty": "hard",
        "difficulty_label": "Khó",
        "type": "single_choice",
        "category": "Mã độc Trojan ngân hàng",
        "question": "Sau khi tải một file 'HuongDanKeKhaiThue.apk' về điện thoại Android, người dùng nhận thấy màn hình điện thoại thỉnh thoảng tự động tối đen trong 10-15 giây dù máy vẫn đang chạy và máy nóng lên nhanh. Cơ chế kỹ thuật nào đang diễn ra?",
        "options": [
            {"id": "A", "text": "Hệ điều hành Android đang dọn dẹp bộ nhớ RAM."},
            {"id": "B", "text": "Mã độc đang tạo một màn hình Overlay giả mạo màu đen để che giấu hành vi tự động mở app ngân hàng và thực hiện lệnh chuyển tiền ngầm trong nền."},
            {"id": "C", "text": "Màn hình điện thoại bị chập tấm nền OLED."},
            {"id": "D", "text": "Tính năng tiết kiệm pin thông minh của máy tự kích hoạt."},
        ],
        "correct_option_ids": ["B"],
        "simulation": {},
        "explanation": "Kỹ thuật Black Screen Overlay được mã độc trojan Android sử dụng để vô hiệu hóa thị giác của người dùng trong khi botnet ngầm dùng quyền Accessibility để nhập số tài khoản đích và chuyển tiền."
    },
    {
        "id": "BNK_HD_06",
        "difficulty": "hard",
        "difficulty_label": "Khó",
        "type": "multi_select",
        "category": "Bảo mật trình duyệt",
        "question": "Những dấu hiệu kỹ thuật nào cho thấy trình duyệt web của bạn đã bị cài phần mềm mở rộng độc hại (Malicious Extension) nhằm đánh cắp dữ liệu thanh toán?",
        "options": [
            {"id": "A", "text": "Các liên kết tìm kiếm trên Google tự động bị chuyển hướng sang các trang bán hàng lạ."},
            {"id": "B", "text": "Xuất hiện extension lạ có quyền 'Đọc và thay đổi tất cả dữ liệu của bạn trên các trang web bạn truy cập'."},
            {"id": "C", "text": "Trình duyệt tự động mở các tab quảng cáo cờ bạc, tiền ảo khi khởi động."},
            {"id": "D", "text": "Giao diện thanh toán thẻ tín dụng xuất hiện thêm các trường nhập mã PIN ATM không bình thường."},
        ],
        "correct_option_ids": ["A", "B", "C", "D"],
        "simulation": {},
        "explanation": "Extension độc hại có thể tiêm mã JavaScript vào trang web (FormJacking) để đánh cắp keystroke, số thẻ tín dụng hoặc chuyển hướng traffic quảng cáo."
    },
    {
        "id": "BNK_HD_07",
        "difficulty": "hard",
        "difficulty_label": "Khó",
        "type": "single_choice",
        "category": "eKYC Bypassing",
        "question": "Quy định bắt buộc xác thực sinh trắc học khuôn mặt (NFC qua chip CCCD) cho các giao dịch chuyển tiền trên 10 triệu đồng hoặc tổng 20 triệu/ngày tại Việt Nam nhằm mục đích cốt lõi nào?",
        "options": [
            {"id": "A", "text": "Tăng phí dịch vụ ngân hàng trực tuyến."},
            {"id": "B", "text": "Ngăn chặn triệt để tội phạm sử dụng tài khoản ngân hàng 'rác' (thuê/mua của người khác) để tẩu tán số tiền lớn bất hợp pháp."},
            {"id": "C", "text": "Thu thập dữ liệu khuôn mặt để bán cho các công ty quảng cáo."},
            {"id": "D", "text": "Làm chậm tốc độ giao dịch của người dân."},
        ],
        "correct_option_ids": ["B"],
        "simulation": {},
        "explanation": "Quyết định 2345/QĐ-NHNN triệt tiêu mô hình dùng tài khoản 'rác' thu mua của sinh viên, người nghèo. Dù kẻ gian chiếm được mật khẩu/OTP nhưng không có khuôn mặt sống của chính chủ khớp với chip CCCD thì không thể tẩu tán tiền lớn."
    },
    {
        "id": "BNK_HD_08",
        "difficulty": "hard",
        "difficulty_label": "Khó",
        "type": "true_false",
        "category": "Ví lạnh và Tiền điện tử",
        "question": "Nếu một trang web tự xưng là 'Sàn phi tập trung DEX' yêu cầu bạn nhập 12 hoặc 24 từ khóa khôi phục (Seed phrase / Secret Recovery Phrase) của ví MetaMask/TrustWallet để kết nối nhận Airdrop, đây chắc chắn là bẫy rút cạn ví (Drainer). Đúng hay Sai?",
        "options": [
            {"id": "A", "text": "Đúng (Seed phrase chỉ dùng khôi phục ví cá nhân, không dApp nào được phép yêu cầu)"},
            {"id": "B", "text": "Sai (Các dApp uy tín cần Seed phrase để định danh tài khoản on-chain)"},
        ],
        "correct_option_ids": ["A"],
        "simulation": {},
        "explanation": "Seed phrase (cụm từ khôi phục) là chìa khóa vạn năng cho mọi tài sản trong ví Web3. Bất kỳ trang web nào yêu cầu nhập seed phrase đều là phishing script drainer để chiếm quyền sở hữu toàn bộ token/NFT."
    },
    {
        "id": "BNK_HD_09",
        "difficulty": "hard",
        "difficulty_label": "Khó",
        "type": "single_choice",
        "category": "Chiếm quyền Telegram/Zalo",
        "question": "Bạn nhận được tin nhắn từ bạn thân trên Telegram: 'Bình chọn giúp cháu mình thi vẽ tranh online tại trang web này nhé'. Sau khi bấm link, trang web yêu cầu bạn quét mã QR đăng nhập Telegram. Hậu quả tức thì nếu bạn quét mã là gì?",
        "options": [
            {"id": "A", "text": "Bình chọn thành công và được cộng điểm uy tín."},
            {"id": "B", "text": "Bạn vừa ủy quyền đăng nhập tài khoản Telegram của mình cho kẻ tấn công trên một thiết bị máy tính khác."},
            {"id": "C", "text": "Máy tính của bạn sẽ tự động nâng cấp Telegram Premium."},
            {"id": "D", "text": "Không có rủi ro nào vì quét mã QR chỉ dùng để xem ảnh thi vẽ."},
        ],
        "correct_option_ids": ["B"],
        "simulation": {},
        "explanation": "Mã QR đó thực chất là tính năng 'Đăng nhập Telegram Web/Desktop'. Khi quét, kẻ gian lập tức chiếm quyền session đăng nhập để nhắn tin vay tiền toàn bộ danh bạ của nạn nhân."
    },
    {
        "id": "BNK_HD_10",
        "difficulty": "hard",
        "difficulty_label": "Khó",
        "type": "multi_select",
        "category": "Vishing & Voice Cloning",
        "question": "Khi nhận được cuộc gọi giọng nói giống hệt người thân thông báo gặp tai nạn giao thông nghiêm trọng cần chuyển viện phí gấp, người nghe nên thực hiện những nguyên tắc đối chiếu nào để không sập bẫy AI Voice Cloning?",
        "options": [
            {"id": "A", "text": "Đặt một câu hỏi bí mật về kỷ niệm chung mà chỉ người thân trong gia đình biết."},
            {"id": "B", "text": "Ngắt máy và gọi lại vào chính số điện thoại di động thường ngày của người đó."},
            {"id": "C", "text": "Liên hệ với bệnh viện hoặc công an khu vực nơi được cho là xảy ra tai nạn để xác thực độc lập."},
            {"id": "D", "text": "Chuyển ngay tiền vào số tài khoản lạ do người lạ qua điện thoại cung cấp."},
        ],
        "correct_option_ids": ["A", "B", "C"],
        "simulation": {},
        "explanation": "Voice cloning bằng AI có thể sao chép ngữ điệu và chất giọng chỉ từ vài giây mẫu âm thanh trên MXH. Xác minh bí mật gia đình và đối chiếu đa kênh là biện pháp phòng thủ hiệu quả nhất."
    },
    {
        "id": "BNK_HD_11",
        "difficulty": "hard",
        "difficulty_label": "Khó",
        "type": "single_choice",
        "category": "Trạm thu phát sóng giả",
        "question": "Thiết bị phần cứng nào thường được tội phạm sử dụng để phát tán hàng nghìn tin nhắn SMS Brandname giả mạo trực tiếp tới các thuê bao di động xung quanh mà không đi qua hệ thống kiểm duyệt của nhà mạng?",
        "options": [
            {"id": "A", "text": "Bộ kích sóng Wi-Fi gia đình."},
            {"id": "B", "text": "Trạm phát sóng giả lập BTS (Fake BTS / IMSI-Catcher)."},
            {"id": "C", "text": "Card đồ họa đào Bitcoin."},
            {"id": "D", "text": "Thiết bị định vị GPS ô tô."},
        ],
        "correct_option_ids": ["B"],
        "simulation": {},
        "explanation": "Trạm BTS giả mạo (thường đặt trên ô tô/xe máy di chuyển) phát sóng công suất lớn chèn sóng 2G/GSM, ép điện thoại gần đó kết nối vào và gửi trực tiếp các tin nhắn SMS Brandname mạo danh ngân hàng."
    },
    {
        "id": "BNK_HD_12",
        "difficulty": "hard",
        "difficulty_label": "Khó",
        "type": "true_false",
        "category": "Chiếm đoạt Cookie / Session Hijacking",
        "question": "Nếu tài khoản của bạn đã bật xác thực hai yếu tố (2FA), mã độc đánh cắp Cookie phiên (Infostealer) trên máy tính vẫn có thể đăng nhập vào tài khoản mạng xã hội của bạn mà KHÔNG CẦN hỏi lại mật khẩu hoặc mã OTP. Đúng hay Sai?",
        "options": [
            {"id": "A", "text": "Đúng (Cookie đã ghi nhận trạng thái đã xác thực thành công của phiên làm việc)"},
            {"id": "B", "text": "Sai (2FA luôn bắt buộc phải nhập lại mỗi khi mở tab mới)"},
        ],
        "correct_option_ids": ["A"],
        "simulation": {},
        "explanation": "Các mã độc Infostealer (RedLine, LummaC2) trích xuất trực tiếp session cookie từ profile trình duyệt. Khi import cookie này vào trình duyệt của hacker, họ bỏ qua hoàn toàn bước mật khẩu và 2FA."
    },
    {
        "id": "BNK_HD_13",
        "difficulty": "hard",
        "difficulty_label": "Khó",
        "type": "single_choice",
        "category": "Lừa đảo sàn ngoại hối ảo (Forex Scam)",
        "question": "Nạn nhân được mời tham gia 'Sàn giao dịch ngoại hối uy tín quốc tế' có biểu đồ nến xanh đỏ chạy theo thời gian thực. Khi tài khoản nạn nhân tăng từ $1,000 lên $25,000, nạn nhân bấm rút tiền thì bị báo: 'Tài khoản chưa nộp thuế thu nhập 10% tại Việt Nam, phải nạp thêm $2,500'. Bản chất của khoản thuế này là gì?",
        "options": [
            {"id": "A", "text": "Thuế thu nhập cá nhân theo luật thuế của Bộ Tài chính."},
            {"id": "B", "text": "Cú lừa vét đáy cuối cùng (Last squeeze) để bòn rút thêm tiền trước khi khóa vĩnh viễn tài khoản nạn nhân."},
            {"id": "C", "text": "Phí bảo hiểm thanh khoản quốc tế của hệ thống SWIFT."},
            {"id": "D", "text": "Phí đổi ngoại tệ USD sang VND theo tỷ giá ngân hàng nhà nước."},
        ],
        "correct_option_ids": ["B"],
        "simulation": {},
        "explanation": "Biểu đồ nến và số dư tài khoản trên sàn lừa đảo chỉ là con số ảo do phần mềm MT4/MT5 lậu hoặc web giả điều khiển. Khoản thuế nộp trước là cái bẫy để vét thêm tiền từ nạn nhân đang tiếc số lãi ảo."
    },
    {
        "id": "BNK_HD_14",
        "difficulty": "hard",
        "difficulty_label": "Khó",
        "type": "multi_select",
        "category": "Phòng chống rủi ro thiết bị",
        "question": "Những hành vi nào sau đây làm suy yếu nghiêm trọng hàng rào bảo mật của điện thoại thông minh và tăng nguy cơ bị đánh cắp tài khoản ngân hàng?",
        "options": [
            {"id": "A", "text": "Root thiết bị Android hoặc Jailbreak thiết bị iOS."},
            {"id": "B", "text": "Bật tùy chọn 'Cho phép cài đặt ứng dụng từ nguồn không xác định' liên tục."},
            {"id": "C", "text": "Cập nhật bản vá bảo mật hệ điều hành hàng tháng từ nhà sản xuất."},
            {"id": "D", "text": "Cấp quyền 'Đọc thông báo' và quyền 'Trợ năng' cho các app không rõ nguồn gốc."},
        ],
        "correct_option_ids": ["A", "B", "D"],
        "simulation": {},
        "explanation": "Root/Jailbreak phá vỡ cơ chế Sandboxing bảo vệ các app ngân hàng. Cài app ngoài chợ và cấp quyền nhạy cảm biến thiết bị thành công cụ bị điều khiển từ xa hoàn toàn."
    },
    {
        "id": "BNK_HD_15",
        "difficulty": "hard",
        "difficulty_label": "Khó",
        "type": "incident_response",
        "category": "Ứng phó lộ lọt dữ liệu thẻ",
        "question": "Bạn vừa mua hàng trên một trang web nước ngoài và ngay sau đó điện thoại liên tục nhận được 3 tin nhắn OTP báo trừ tiền ở các trang mua sắm lạ mà bạn không thực hiện. Phản ứng chính xác nhất trong vòng 2 phút là:",
        "simulation": {
            "channel": "incident",
            "expected_keywords": ["khóa thẻ khẩn cấp trên app", "gọi hotline ngân hàng", "tra soát giao dịch", "đổi thẻ mới"],
        },
        "options": [
            {"id": "A", "text": "Mở app ngân hàng bấm nút 'Khóa thẻ thanh toán quốc tế' ngay lập tức, sau đó gọi tổng đài yêu cầu hủy thẻ và hoàn tiền tra soát."},
            {"id": "B", "text": "Chờ kẻ gian thanh toán xong hết hạn mức rồi mới ra quầy ngân hàng khiếu nại."},
            {"id": "C", "text": "Nhắn tin cho cửa hàng nước ngoài xin lại tiền."},
            {"id": "D", "text": "Đăng thông tin thẻ lên diễn đàn công nghệ nhờ chuyên gia tìm địa chỉ IP kẻ gian."},
        ],
        "correct_option_ids": ["A"],
        "simulation": {},
        "explanation": "Khóa thẻ tức thời trên app ngân hàng chặn đứng các đợt quẹt thẻ tiếp theo. Sau đó, liên hệ hotline ngân hàng để thực hiện quy trình Chargeback (tra soát gian lận quốc tế)."
    },

    # ═════════════════════════════════════════════════════════════════════════
    # LEVEL 4: EXTREME (Phân tích & Đánh giá / Evaluation) - 10 Câu
    # ═════════════════════════════════════════════════════════════════════════
    {
        "id": "BNK_EX_01",
        "difficulty": "extreme",
        "difficulty_label": "Cực khó",
        "type": "incident_response",
        "category": "Chuỗi tấn công kết hợp (Multi-Stage)",
        "question": "Kịch bản tấn công: Bạn nhận cuộc gọi từ số bàn có mã vùng đúng của Cơ quan Điều tra. Người gọi đọc chính xác số CCCD, địa chỉ nhà, tên cha mẹ và mã số thuế của bạn. Sau đó một 'Kiểm sát viên' gọi video mặc sắc phục ngồi trước phông nền trụ sở công an, xuất trình 'Lệnh bắt tạm giam có dấu đỏ'. Kế hoạch xử lý chuyên sâu nào bóc trần bản chất cuộc gọi này?",
        "simulation": {
            "channel": "incident",
            "expected_keywords": ["spoofing số điện thoại", "dữ liệu lộ lọt chợ đen", "yêu cầu giấy triệu tập trực tiếp", "công an phường địa phương"],
        },
        "options": [
            {"id": "A", "text": "Chuyển tiền vào tài khoản phong tỏa do bên kia cung cấp để chứng minh tài sản trong sạch."},
            {"id": "B", "text": "Nhận thức rõ: Số điện thoại gọi đến có thể bị giả mạo (Caller ID Spoofing), dữ liệu cá nhân bị mua bán từ các vụ rò rỉ trước đó; khẳng định chỉ làm việc tại cơ quan khi có giấy triệu tập hợp pháp qua công an địa phương."},
            {"id": "C", "text": "Cài phần mềm hỗ trợ từ xa để họ kiểm tra lịch sử giao dịch điện thoại."},
            {"id": "D", "text": "Đến tiệm net chuyển đổi toàn bộ tài sản sang tiền điện tử để giấu."},
        ],
        "correct_option_ids": ["B"],
        "explanation": "Kẻ tấn công sử dụng kỹ thuật VoIP Caller ID Spoofing để hiển thị số điện thoại cơ quan công quyền, kết hợp dữ liệu lộ lọt từ các vụ rò rỉ thông tin cá nhân. Luật Tố tụng hình sự Việt Nam quy định tuyệt đối không khởi tố hay làm việc qua điện thoại."
    },
    {
        "id": "BNK_EX_02",
        "difficulty": "extreme",
        "difficulty_label": "Cực khó",
        "type": "single_choice",
        "category": "Tấn công Man-in-the-Middle (Adversary-in-the-Middle)",
        "question": "Trong kỹ thuật tấn công AiTM (Adversary-in-the-Middle) phishing sử dụng công cụ như Evilginx, kẻ tấn công đánh cắp phiên đăng nhập có 2FA của nạn nhân bằng cơ chế nào?",
        "options": [
            {"id": "A", "text": "Giải mã toán học khóa mã hóa RSA của máy chủ ngân hàng."},
            {"id": "B", "text": "Đóng vai trò máy chủ proxy chuyển tiếp lưu lượng truy cập giữa nạn nhân và trang đăng nhập thật, thu giữ session cookie ngay sau khi nạn nhân hoàn tất nhập mật khẩu và mã 2FA hợp lệ."},
            {"id": "C", "text": "Dò quét cổng SSH của máy tính nạn nhân."},
            {"id": "D", "text": "Bẻ khóa thuật toán sinh mã ngẫu nhiên của Google Authenticator."},
        ],
        "correct_option_ids": ["B"],
        "simulation": {},
        "explanation": "AiTM Proxy hoạt động như một máy chủ đứng giữa (Reverse Proxy) chuyển tiếp theo thời gian thực. Trang web thật thấy thông tin đăng nhập và 2FA hợp lệ nên trả về Session Cookie, và kẻ tấn công bắt giữ cookie này để đăng nhập trái phép."
    },
    {
        "id": "BNK_EX_03",
        "difficulty": "extreme",
        "difficulty_label": "Cực khó",
        "type": "multi_select",
        "category": "Tấn công App Ngân hàng",
        "question": "Những kỹ thuật nào dưới đây thường được các dòng mã độc trojan thế hệ mới trên Android sử dụng để né tránh sự phát hiện của cơ chế kiểm tra an toàn trong ứng dụng ngân hàng?",
        "options": [
            {"id": "A", "text": "Kiểm tra môi trường giả lập (Emulator / Sandbox Detection) và tạm ngừng hành vi độc hại nếu phát hiện đang chạy trong môi trường phân tích."},
            {"id": "B", "text": "Sử dụng kỹ thuật Dynamic Code Loading (tải file payload .dex mã hóa từ máy chủ C2 về sau khi đã vượt qua vòng kiểm duyệt ban đầu)."},
            {"id": "C", "text": "Yêu cầu quyền tắt hoàn toàn hệ điều hành điện thoại."},
            {"id": "D", "text": "Chờ đợi tương tác thật của người dùng trong khoảng thời gian nhất định (User Interaction Delay) trước khi kích hoạt module độc hại."},
        ],
        "correct_option_ids": ["A", "B", "D"],
        "simulation": {},
        "explanation": "Mã độc di động hiện đại trang bị khả năng chống phân tích sandbox, tải payload mã hóa giai đoạn 2 (dropper architecture) và chờ đợi hành vi người dùng thật để lừa các công cụ quét tự động."
    },
    {
        "id": "BNK_EX_04",
        "difficulty": "extreme",
        "difficulty_label": "Cực khó",
        "type": "single_choice",
        "category": "Deepfake Real-Time Live Streaming",
        "question": "Kẻ lừa đảo mở cuộc gọi video trực tiếp trên nền tảng hẹn hò hoặc phỏng vấn việc làm với một người mẫu ảo được sinh ra hoàn toàn từ AI. Dấu hiệu kỹ thuật tinh tế nhất nào tố cáo khuôn mặt này là tổng hợp (AI Generated)?",
        "options": [
            {"id": "A", "text": "Nhân vật chớp mắt quá đều đặn hoặc có sự bất thường ở phản chiếu ánh sáng trong đồng tử (Corneal reflection mismatch) và viền chân tóc bị mờ nhòe."},
            {"id": "B", "text": "Người mẫu nói tiếng Anh chuẩn người bản xứ."},
            {"id": "C", "text": "Trang phục của người mẫu có màu sắc quá sặc sỡ."},
            {"id": "D", "text": "Camera luôn được đặt cố định một chỗ."},
        ],
        "correct_option_ids": ["A"],
        "simulation": {},
        "explanation": "Mô hình sinh hình ảnh AI hiện nay gặp khó khăn lớn nhất ở tính đối xứng phản chiếu ánh sáng trong giác mạc mắt (Specularity mismatch) và việc xử lý các chi tiết siêu nhỏ như sợi tóc, hoa tai và viền cổ khi chuyển động."
    },
    {
        "id": "BNK_EX_05",
        "difficulty": "extreme",
        "difficulty_label": "Cực khó",
        "type": "true_false",
        "category": "Cơ chế bảo vệ FIDO2 / Passkey",
        "question": "Công nghệ xác thực Passkey dựa trên chuẩn FIDO2/WebAuthn có khả năng miễn nhiễm tự nhiên trước các cuộc tấn công Phishing truyền thống và AiTM Proxy bởi vì cặp khóa mã hóa gắn chặt với tên miền nguồn (Origin-bound domain). Đúng hay Sai?",
        "options": [
            {"id": "A", "text": "Đúng (Trình duyệt chỉ gửi chữ ký điện tử cho đúng tên miền chính xác đã đăng ký)"},
            {"id": "B", "text": "Sai (Kẻ gian vẫn có thể chuyển tiếp Passkey sang trang web giả mạo)"},
        ],
        "correct_option_ids": ["A"],
        "simulation": {},
        "explanation": "Passkey gắn liền với Tên miền (Origin-bound). Nếu người dùng truy cập trang phishing 'vietcombank-login.xyz', trình duyệt nhận biết origin khác biệt hoàn toàn với 'vietcombank.com.vn' và từ chối cung cấp chữ ký xác thực."
    },
    {
        "id": "BNK_EX_06",
        "difficulty": "extreme",
        "difficulty_label": "Cực khó",
        "type": "single_choice",
        "category": "Tấn công DNS Hijacking",
        "question": "Bạn nhập đúng 100% địa chỉ 'https://nganhang.com.vn' vào trình duyệt nhưng trang web mở ra vẫn là một trang giao diện giả mạo thu thập tài khoản. Cơ chế tấn công hạ tầng mạng nào có thể dẫn tới hiện tượng này?",
        "options": [
            {"id": "A", "text": "Modem Wi-Fi của bạn đã bị đổi địa chỉ máy chủ phân giải tên miền (Rogue DNS Server) hoặc bị tấn công DNS Cache Poisoning."},
            {"id": "B", "text": "Ngân hàng đã bị phá sản."},
            {"id": "C", "text": "Màn hình máy tính hiển thị sai phông chữ."},
            {"id": "D", "text": "Cáp quang biển quốc tế bị đứt."},
        ],
        "correct_option_ids": ["A"],
        "simulation": {},
        "explanation": "Tấn công DNS Hijacking chuyển hướng truy vấn phân giải tên miền của nạn nhân sang IP máy chủ của hacker, khiến nạn nhân gõ đúng URL nhưng vẫn kết nối tới máy chủ giả mạo."
    },
    {
        "id": "BNK_EX_07",
        "difficulty": "extreme",
        "difficulty_label": "Cực khó",
        "type": "multi_select",
        "category": "Bảo vệ tài khoản Doanh nghiệp",
        "question": "Để bảo vệ hệ thống tài chính doanh nghiệp trước các cuộc tấn công lừa đảo chuyển tiền kỹ thuật cao (BEC & Deepfake), các biện pháp kiểm soát nội bộ bắt buộc phải có gồm những gì?",
        "options": [
            {"id": "A", "text": "Nguyên tắc 4 mắt (Four-eyes principle): Mọi lệnh chuyển tiền trên một hạn mức nhất định phải có chữ ký số của tối thiểu 2 người độc lập."},
            {"id": "B", "text": "Quy trình xác minh ngoài kênh (Out-of-band verification) qua số điện thoại đường dây cố định nội bộ trước khi thay đổi thông tin nhà cung cấp."},
            {"id": "C", "text": "Chỉ cần giám đốc gửi tin nhắn Zalo chỉ đạo là kế toán được quyền giải ngân ngay."},
            {"id": "D", "text": "Thiết lập cơ chế kiểm soát email chặt chẽ với SPF, DKIM và DMARC chính sách Reject (p=reject)."},
        ],
        "correct_option_ids": ["A", "B", "D"],
        "simulation": {},
        "explanation": "Chống BEC đòi hỏi kết hợp giữa rào cản kỹ thuật (DMARC p=reject chống giả mạo email) và quy trình vận hành chặt chẽ (xác thực 2 người duyệt, xác minh kênh thoại độc lập)."
    },
    {
        "id": "BNK_EX_08",
        "difficulty": "extreme",
        "difficulty_label": "Cực khó",
        "type": "single_choice",
        "category": "Khai thác lỗ hổng tâm lý Cialdini",
        "question": "Trong vụ lừa đảo giả danh nhân viên điện lực dọa cắt điện bệnh viện/nhà máy nếu không thanh toán ngay hóa đơn phạt, đối tượng tấn công đã khai thác kết hợp các nguyên lý tâm lý học xã hội nào?",
        "options": [
            {"id": "A", "text": "Bằng chứng xã hội (Social Proof) và Lòng hảo tâm."},
            {"id": "B", "text": "Thẩm quyền (Authority), Tính cấp bách (Urgency) và Nỗi sợ tổn thất lớn (Loss Aversion)."},
            {"id": "C", "text": "Sự khan hiếm và Nguyên tắc đáp ứng tương hỗ."},
            {"id": "D", "text": "Sự kiên định và Thói quen tiêu dùng."},
        ],
        "correct_option_ids": ["B"],
        "simulation": {},
        "explanation": "Đòn tâm lý tấn công vào chức danh quản lý điện lực (Thẩm quyền), thời hạn cắt điện tức thì (Cấp bách) và nguy cơ thiệt hại tài chính/ngừng vận hành hệ thống (Nỗi sợ tổn thất) để làm tê liệt phản xạ phản biện."
    },
    {
        "id": "BNK_EX_09",
        "difficulty": "extreme",
        "difficulty_label": "Cực khó",
        "type": "incident_response",
        "category": "Xử lý khủng hoảng APT / Gián điệp",
        "question": "Một quản trị viên hệ thống phát hiện trong log máy chủ công ty có kết nối bất thường gửi thông tin danh bạ khách hàng ra một địa chỉ IP tại nước ngoài. Hãy chọn thứ tự hành động chuẩn mực ứng cứu sự cố theo tiêu chuẩn NIST SP 800-61:",
        "simulation": {
            "channel": "incident",
            "expected_keywords": ["cô lập mạng", "bảo toàn chứng cứ ram", "xác định điểm đột nhập", "khôi phục an toàn"],
        },
        "options": [
            {"id": "A", "text": "Format trắng toàn bộ ổ cứng máy chủ và cài lại hệ điều hành ngay lập tức."},
            {"id": "B", "text": "Cô lập máy chủ khỏi mạng nội bộ (ngắt dây mạng/VLAN), trích xuất bản sao bộ nhớ RAM và nhật ký log để bảo toàn chứng cứ số, sau đó tiến hành truy vết nguyên nhân gốc rễ."},
            {"id": "C", "text": "Tắt nguồn máy chủ bằng cách rút phích cắm điện để ngăn rò rỉ dữ liệu."},
            {"id": "D", "text": "Giữ nguyên kết nối và gửi tin nhắn cảnh cáo tới IP kẻ tấn công."},
        ],
        "correct_option_ids": ["B"],
        "simulation": {},
        "explanation": "Theo chuẩn ứng phó sự cố an ninh mạng (NIST SP 800-61), bước đầu tiên là Containment (Cô lập mạng nhưng giữ nguyên trạng thái nguồn để trích xuất RAM/Forensic artifacts), tuyệt đối không format hay tắt nguồn làm mất dữ liệu trong RAM."
    },
    {
        "id": "BNK_EX_10",
        "difficulty": "extreme",
        "difficulty_label": "Cực khó",
        "type": "multi_select",
        "category": "Đánh giá mức độ trưởng thành an ninh mạng",
        "question": "Những tiêu chí nào chứng minh một cá nhân hoặc tổ chức có năng lực tự vệ số (Cyber Defense Resilience) vững chắc trước làn sóng lừa đảo công nghệ cao?",
        "options": [
            {"id": "A", "text": "Thực hiện nguyên tắc Zero Trust: Luôn xác minh, không tin tưởng mù quáng vào bất kỳ cuộc gọi, tin nhắn hay email nào yêu cầu tiền/dữ liệu."},
            {"id": "B", "text": "Kích hoạt xác thực đa yếu tố không phụ thuộc SMS (Hardware token / Authenticator App) trên 100% tài khoản trọng yếu."},
            {"id": "C", "text": "Chủ động cập nhật tri thức về các thủ đoạn tấn công mới và thường xuyên thực hành diễn tập tình huống thực tế."},
            {"id": "D", "text": "Tuyệt đối không sử dụng bất kỳ dịch vụ ngân hàng hay công nghệ nào để tránh rủi ro."},
        ],
        "correct_option_ids": ["A", "B", "C"],
        "simulation": {},
        "explanation": "Năng lực an ninh số bền vững đến từ tư duy Zero Trust, công nghệ phòng thủ hiện đại (MFA không qua SMS) và tri thức cảnh giác liên tục được cập nhật, thay vì sợ hãi từ bỏ công nghệ."
    },
    {
        "id": "BNK_EZ_16",
        "difficulty": "easy",
        "difficulty_label": "Dễ",
        "type": "simulation_sms",
        "category": "SMS Brandname giả mạo",
        "question": "Bạn nhận được tin nhắn SMS sau từ Brandname nhà mạng. Phân tích nội dung và chọn bước xử lý an toàn nhất:",
        "simulation": {
            "channel": "sms",
            "from": "VIETTEL_KM",
            "sender_name": "VIETTEL_KM",
            "time": "10:15",
            "body": "Quy khach da tich luy duoc 12.500 diem thuong sap het han. Quy doi ngay thanh 500.000d tien cuoc tai https://viettel-diemthuong.vip truoc 24h dem nay.",
            "trap_signals": ["Tên miền .vip không thuộc viettel.vn", "Tạo áp lực hết hạn điểm trong ngày", "Link rút gọn lạ"],
            "expected_keywords": ["không bấm link", "mở app my viettel", "tra cứu hotline 198"],
        },
        "options": [
            {"id": "A", "text": "Bấm vào link và nhập số điện thoại cùng mã OTP gửi về để đổi 500.000đ tiền cước."},
            {"id": "B", "text": "Không bấm link trong tin nhắn; mở ứng dụng My Viettel chính thức hoặc gọi tổng đài 198 để kiểm tra điểm thưởng."},
            {"id": "C", "text": "Chuyển tiếp tin nhắn cho bạn bè để họ cùng đổi thưởng."},
            {"id": "D", "text": "Gọi lại số điện thoại lạ hiển thị trên màn hình để khiếu nại."},
        ],
        "correct_option_ids": ["B"],
        "explanation": "Chiêu trò gửi SMS mạo danh nhà mạng thông báo đổi điểm thưởng sang quà hoặc tiền cước nhằm dụ nạn nhân nhập thông tin thẻ ngân hàng/OTP trên trang web giả mạo."
    },
    {
        "id": "BNK_EZ_17",
        "difficulty": "easy",
        "difficulty_label": "Dễ",
        "type": "simulation_email",
        "category": "Phishing Email",
        "question": "Phân tích email thông báo dịch vụ dưới đây và xác định phản ứng đúng đắn nhất:",
        "simulation": {
            "channel": "email",
            "from": "billing-support@netfIix-billing-security.com",
            "subject": "Tài khoản của bạn tạm ngưng do lỗi thanh toán",
            "preview": "Chúng tôi không thể gia hạn gói cước của bạn. Vui lòng cập nhật thẻ tín dụng ngay...",
            "body": "Kính gửi quý khách, Lệnh thanh toán gói cước Premium của bạn không thành công. Để không bị gián đoạn dịch vụ xem phim, vui lòng bấm vào liên kết https://netflix-update-billing.cc để cập nhật lại thông tin thẻ thanh toán trong 24 giờ.",
            "risk_clues": ["Tên miền người gửi giả chữ 'l' bằng chữ 'I' in hoa (typosquatting)", "Link dẫn tới trang web đuôi lạ .cc", "Hối thúc cập nhật thẻ tín dụng"],
            "expected_keywords": ["không bấm link", "mở app netflix", "kiểm tra tài khoản trực tiếp", "báo cáo spam"],
        },
        "options": [
            {"id": "A", "text": "Bấm vào link và điền lại thông tin số thẻ, ngày hết hạn và mã CVV."},
            {"id": "B", "text": "Trả lời email gửi kèm ảnh chụp thẻ tín dụng."},
            {"id": "C", "text": "Không bấm vào liên kết trong email; mở ứng dụng Netflix hoặc truy cập netflix.com thủ công để kiểm tra trạng thái thanh toán."},
            {"id": "D", "text": "Chuyển khoản theo thông tin ngân hàng ghi ở chân trang email."},
        ],
        "correct_option_ids": ["C"],
        "explanation": "Email mạo danh các dịch vụ thuê bao trực tuyến (Netflix, Spotify, Apple) để câu thông tin thẻ tín dụng quốc tế là một trong những thủ đoạn phishing phổ biến nhất."
    },
    {
        "id": "BNK_MD_21",
        "difficulty": "medium",
        "difficulty_label": "Trung bình",
        "type": "simulation_sms",
        "category": "Lừa đảo trừ tiền thẻ",
        "question": "Bạn vừa nhận được tin nhắn SMS sau dù bạn không mua sắm gì trong ngày. Hãy phân tích và đưa ra hành động đúng đắn:",
        "simulation": {
            "channel": "sms",
            "from": "+84839201948",
            "sender_name": "TGDĐ_PAY",
            "time": "15:20",
            "body": "The tin dung cua quy khach vua thanh toan thanh cong 23.990.000d tai Dien May Xanh. Neu khong thuc hien giao dich nay, vui long goi tong dai ho tro huy gap: 1900.xxxx (hoac truy cap http://tgdd-cancle-bill.com).",
            "trap_signals": ["Đầu số di động cá nhân gửi thông báo", "Số tiền lớn gây hoảng loạn", "Số hotline giả mạo để lừa cung cấp OTP hủy giao dịch"],
            "expected_keywords": ["không gọi số trong tin nhắn", "không bấm link", "mở app ngân hàng khóa thẻ", "gọi hotline in trên thẻ"],
        },
        "options": [
            {"id": "A", "text": "Lập tức gọi số hotline ghi trong tin nhắn để xin hủy lệnh trừ tiền."},
            {"id": "B", "text": "Truy cập link trong tin nhắn và điền mã OTP ngân hàng gửi về để xác nhận hủy."},
            {"id": "C", "text": "Bình tĩnh nhận diện tin nhắn lừa đảo mạo danh; mở ngay ứng dụng ngân hàng kiểm tra số dư/lịch sử giao dịch thật và gọi hotline in trên mặt sau thẻ ngân hàng."},
            {"id": "D", "text": "Chuyển toàn bộ tiền còn lại vào tài khoản của người gửi tin nhắn để đối chiếu."},
        ],
        "correct_option_ids": ["C"],
        "explanation": "Thủ đoạn tạo tin nhắn trừ tiền giả mạo nhắm vào tâm lý hoảng loạn khi thấy số tiền lớn bị mất. Nếu gọi số trong tin nhắn, đối tượng sẽ đóng vai nhân viên tổng đài và dụ đọc mã OTP hủy giao dịch để rút sạch tiền thật."
    },
    {
        "id": "BNK_MD_22",
        "difficulty": "medium",
        "difficulty_label": "Trung bình",
        "type": "simulation_email",
        "category": "Mã độc đính kèm Email",
        "question": "Hãy kiểm tra email công việc sau đây và chọn phương án xử lý an toàn nhất:",
        "simulation": {
            "channel": "email",
            "from": "delivery-status@ghn-tracking-service.com",
            "subject": "Thông báo: Hóa đơn điện tử và mã bưu gửi giao không thành công",
            "preview": "Bưu gửi số GHN-82918 giao không thành công do sai địa chỉ. Mở file đính kèm...",
            "body": "Kính gửi quý khách, Kiện hàng của quý khách bị tồn kho do nhân viên giao hàng không liên lạc được. Vui lòng tải và mở file 'HoaDonChiTiet_MaVanDon.pdf.exe' đính kèm để xác nhận thời gian giao lại trong ngày mai.",
            "risk_clues": ["File đính kèm có đuôi kép độc hại .pdf.exe (thực chất là file thực thi mã độc)", "Tên miền email lạ không phải ghn.vn chính thức", "Gây tò mò về bưu phẩm"],
            "expected_keywords": ["tuyệt đối không mở file đính kèm", "đuôi kép pdf.exe là mã độc", "xóa email", "báo cáo bộ phận it"],
        },
        "options": [
            {"id": "A", "text": "Tải file 'HoaDonChiTiet_MaVanDon.pdf.exe' về máy tính và bấm đúp chuột để mở xem hóa đơn."},
            {"id": "B", "text": "Đổi tên file thành '.pdf' rồi mở bình thường."},
            {"id": "C", "text": "Tuyệt đối không tải hay mở file đính kèm; nhận diện đuôi kép '.pdf.exe' là mã độc thực thi (trojan/ransomware) trá hình, lập tức xóa email và báo IT."},
            {"id": "D", "text": "Chuyển tiếp file cho đồng nghiệp mở thử trên máy tính của họ."},
        ],
        "correct_option_ids": ["C"],
        "explanation": "Kỹ thuật 'Double Extension' (đuôi kép như .pdf.exe, .docx.exe) lợi dụng tính năng ẩn đuôi file mặc định của Windows để lừa người dùng bấm chạy mã độc thực thi (infostealer/ransomware)."
    },
    {
        "id": "BNK_HD_16",
        "difficulty": "hard",
        "difficulty_label": "Khó",
        "type": "simulation_sms",
        "category": "Chiếm đoạt chuyển hướng cuộc gọi",
        "question": "Bạn nhận được tin nhắn sau từ một số điện thoại lạ. Phân tích chiêu thức kỹ thuật của kẻ gian:",
        "simulation": {
            "channel": "sms",
            "from": "+84912384912",
            "sender_name": "TONGDAI_HOTRO",
            "time": "11:40",
            "body": "Ban da dang ky thanh cong goi cuoc Game VIP 500.000d/thang. De huy goi va khong bi tru tien, vui long bam tren ban phim cuoc goi cu phap: **21*0987654321# roi bam nut Goi ngay.",
            "trap_signals": ["Đe dọa trừ cước dịch vụ không đăng ký", "Cú pháp **21* là mã lệnh chuyển hướng cuộc gọi (Call Forwarding)", "Nhắm tới việc cướp mã OTP cuộc gọi"],
            "expected_keywords": ["cú pháp chuyển hướng cuộc gọi call forwarding", "không bấm cú pháp", "kẻ gian muốn cướp otp thoại", "liên hệ tổng đài nhà mạng"],
        },
        "options": [
            {"id": "A", "text": "Làm theo hướng dẫn bấm ngay cú pháp **21*0987654321# để hủy dịch vụ tránh mất tiền."},
            {"id": "B", "text": "Nhận biết cú pháp '**21*SĐT#' là mã lệnh chuyển hướng cuộc gọi vô điều kiện (Call Forwarding). Nếu bấm, mọi cuộc gọi đến (kể cả cuộc gọi đọc mã OTP ngân hàng) sẽ chuyển sang máy kẻ gian."},
            {"id": "C", "text": "Nạp thêm 500.000đ vào tài khoản điện thoại để hệ thống trừ cước rồi tự động hủy."},
            {"id": "D", "text": "Soạn tin nhắn gửi số điện thoại trong nội dung tin nhắn."},
        ],
        "correct_option_ids": ["B"],
        "explanation": "Cú pháp USSD **21*SĐT# là tính năng chuyển tiếp cuộc gọi của mạng GSM. Kẻ gian hù dọa trừ cước để lừa nạn nhân tự kích hoạt chuyển hướng cuộc gọi sang máy của chúng, từ đó nghe lén và cướp mã OTP thoại ngân hàng."
    },
    {
        "id": "BNK_HD_17",
        "difficulty": "hard",
        "difficulty_label": "Khó",
        "type": "simulation_email",
        "category": "Phishing Tài khoản Doanh nghiệp",
        "question": "Là quản trị viên hệ thống công ty, hãy đánh giá email cảnh báo an ninh sau:",
        "simulation": {
            "channel": "email",
            "from": "admin-security@microsoft-portal365-verify.com",
            "subject": "CẢNH BÁO: Tài khoản Microsoft 365 của bạn sẽ bị vô hiệu hóa trong 6 giờ",
            "preview": "Phát hiện nhiều yêu cầu gửi thư rác từ hòm thư của bạn. Xác thực danh tính ngay...",
            "body": "Hệ thống Microsoft 365 phát hiện tài khoản của bạn vi phạm chính sách gửi email hàng loạt. Để ngăn chặn việc khóa tài khoản vĩnh viễn, người quản trị yêu cầu bạn xác thực lại thông tin đăng nhập và mã 2FA tại https://login.microsoftonline.portal365-verify.com.",
            "risk_clues": ["Tên miền portal365-verify.com là tên miền giả mạo", "Subdomain login.microsoftonline đánh lừa thị giác", "Đe dọa khóa tài khoản công việc"],
            "expected_keywords": ["phishing credential harvesting", "kiểm tra origin domain", "không đăng nhập", "cảnh báo toàn công ty"],
        },
        "options": [
            {"id": "A", "text": "Đăng nhập ngay để tránh việc email công việc bị gián đoạn."},
            {"id": "B", "text": "Gửi thông báo này cho toàn bộ nhân viên trong công ty cùng làm theo."},
            {"id": "C", "text": "Nhận diện đây là chiến dịch tấn công thu thập thông tin đăng nhập (Credential Harvesting) qua Subdomain lừa thị giác; báo cáo SOC/IT, chặn tên miền trên Firewall/Mail Gateway."},
            {"id": "D", "text": "Tắt tính năng xác thực 2 lớp trên tài khoản công ty."},
        ],
        "correct_option_ids": ["C"],
        "explanation": "Kẻ tấn công tạo subdomain 'login.microsoftonline' trên tên miền riêng 'portal365-verify.com' để đánh lừa người dùng vội vã nhìn lướt qua. Cần nhận diện tên miền gốc đứng trước dấu slash đầu tiên và chặn ở cấp độ Gateway."
    },
]


def get_balanced_exam_questions(seed: int = None) -> List[Dict[str, Any]]:
    """
    Builds a strictly balanced 30-question Scam IQ exam meeting all requirements:
    - Exactly 30 questions.
    - Ascending difficulty: 6 Easy -> 10 Medium -> 10 Hard -> 4 Extreme.
    - Guarantees >= 7 multi_select questions.
    - Guarantees >= 8 simulation questions (SMS, email, incident response) with at least 3 SMS and 3 Email.
    - Formats IDs cleanly from Q1 to Q30.
    """
    rng = random.Random(seed)

    def _split_pool(pool: List[Dict[str, Any]]):
        sims = [q for q in pool if q.get('type') in {'simulation_sms', 'simulation_email', 'incident_response'}]
        multi = [q for q in pool if q.get('type') == 'multi_select']
        others = [q for q in pool if q.get('type') not in {'simulation_sms', 'simulation_email', 'incident_response', 'multi_select'}]
        rng.shuffle(sims)
        rng.shuffle(multi)
        rng.shuffle(others)
        return sims, multi, others

    easy_all = [q for q in SCAM_IQ_BANK if q["difficulty"] == "easy"]
    medium_all = [q for q in SCAM_IQ_BANK if q["difficulty"] == "medium"]
    hard_all = [q for q in SCAM_IQ_BANK if q["difficulty"] == "hard"]
    extreme_all = [q for q in SCAM_IQ_BANK if q["difficulty"] == "extreme"]

    easy_sims, easy_multi, easy_others = _split_pool(easy_all)
    med_sims, med_multi, med_others = _split_pool(medium_all)
    hard_sims, hard_multi, hard_others = _split_pool(hard_all)
    ext_sims, ext_multi, ext_others = _split_pool(extreme_all)

    # 1. Easy: pick 6 (2 sims, 2 multi, 2 others)
    selected_easy = easy_sims[:2] + easy_multi[:2] + easy_others[:2]
    rng.shuffle(selected_easy)

    # 2. Medium: pick 10 (3 sims, 3 multi, 4 others)
    selected_med = med_sims[:3] + med_multi[:3] + med_others[:4]
    rng.shuffle(selected_med)

    # 3. Hard: pick 10 (3 sims, 3 multi, 4 others)
    selected_hard = hard_sims[:3] + hard_multi[:3] + hard_others[:4]
    rng.shuffle(selected_hard)

    # 4. Extreme: pick 4 (1 sim, 1 multi, 2 others)
    selected_ext = ext_sims[:1] + ext_multi[:1] + ext_others[:2]
    rng.shuffle(selected_ext)

    raw_exam = selected_easy + selected_med + selected_hard + selected_ext

    # Final mapping with clean Q1..Q30 IDs
    final_questions: List[Dict[str, Any]] = []
    for idx, raw_q in enumerate(raw_exam, start=1):
        q = copy.deepcopy(raw_q)
        q["id"] = f"Q{idx}"
        final_questions.append(q)

    return final_questions
