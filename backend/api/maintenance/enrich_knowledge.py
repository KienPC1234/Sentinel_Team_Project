"""
Enrich Knowledge Base: Adds comprehensive lessons, scenarios, and quizzes
for missing categories (story, inclusive, empathy, guide, alert) and enhances
existing lessons with additional quizzes.
"""
import os
import django

import sys
sys.path.insert(0, '/data/Sentinel_Team_Project/backend')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'PKV.settings')
django.setup()

from api.core.models import LearnLesson, LearnScenario, LearnQuiz, QuizQuestionType


def enrich_lessons():
    # 1. Lesson: Bay dau tu san tai chinh ao & Forex (Pig Butchering)
    l1, created = LearnLesson.objects.get_or_create(
        slug="bay-dau-tu-san-tai-chinh-ao-forex-crypto-mo-heo",
        defaults={
            "title": "Chuyên đề: Nhận diện bẫy đầu tư Sàn tài chính ảo, Forex & Tiền mã hóa (Pig Butchering)",
            "category": "alert",
            "summary": "Phân tích toàn diện mô hình 'Mổ heo' (Pig Butchering), thủ đoạn can thiệp biểu đồ nến giả lập, bẫy khóa rút tiền và phí bảo hiểm giải ngân.",
            "is_published": True,
            "content": """## I. Bản chất mô hình lừa đảo "Mổ heo" (Pig Butchering)

Thuật ngữ "Pig Butchering" (Sha Zhu Pan - Mổ heo) bắt nguồn từ các tổ chức tội phạm xuyên biên giới, mô tả quá trình nuôi dưỡng lòng tin nạn nhân (vỗ béo) trước khi dẫn dụ nạp toàn bộ tài sản rồi cắt đứt liên lạc (mổ thịt).

### 1. Quy trình 4 giai đoạn tinh vi của kẻ gian:
1. **Tiếp cận & Kết bạn (The Approach)**: Đối tượng tạo vỏ bọc doanh nhân thành đạt, chuyên gia phân tích tài chính trên Facebook, Tinder, LinkedIn. Chủ động nhắn tin "nhầm số" lịch sự hoặc trò chuyện chia sẻ cuộc sống từ vài tuần đến hàng tháng.
2. **Khoe lợi nhuận & Dẫn dụ (The Hook)**: Khéo léo khoe ảnh chụp sao kê tài khoản ngân hàng, lợi nhuận giao dịch từ các sàn ngoại hối (Forex) hoặc tiền mã hóa (Crypto). Giả vờ chia sẻ "lỗ hổng thuật toán" hoặc lệnh nội gián độc quyền giúp thắng 100%.
3. **Thử nghiệm thành công nhỏ (The Taste)**: Hướng dẫn nạn nhân nạp số vốn nhỏ (từ 500.000 đến vài triệu đồng). Hệ thống sàn cho phép giao dịch thắng ngay lập tức và cho phép rút tiền gốc lẫn lãi về tài khoản ngân hàng thật nhằm triệt tiêu hoàn toàn sự nghi ngờ.
4. **Kích động lòng tham & Ép vay nợ (The Trap)**: Thúc giục nạn nhân bán đất, rút sổ tiết kiệm hoặc vay ngân hàng tiền tỷ để vào các gói "VIP", "Bảo hiểm vốn". Sau đó hệ thống báo lỗi tài khoản bị đóng băng, yêu cầu nạp thêm 20% đến 50% tiền bảo lãnh, thuế thu nhập cá nhân thì mới được rút tiền. Khi nạn nhân kiệt quệ tài chính, nhóm đối tượng lập tức chặn liên lạc và đóng website.

## II. Dấu hiệu kỹ thuật vạch trần sàn đầu tư lừa đảo

- **Tên miền mới đăng ký**: Các website sàn giao dịch thường sử dụng đuôi tên miền rẻ tiền như `.top`, `.vip`, `.xyz`, `.cc` và tuổi đời tên miền chỉ từ vài ngày đến vài tháng.
- **Biểu đồ nến thao túng cục bộ**: Biểu đồ giá chạy độc lập trên website của kẻ gian, hoàn toàn không khớp với dữ liệu quốc tế từ Binance, TradingView hoặc Reuters. Máy chủ backend có thể can thiệp đẩy giá tăng giảm theo ý muốn của quản trị viên.
- **Địa chỉ ví nạp và tài khoản nhận tiền cá nhân**: Thay vì tích hợp cổng thanh toán doanh nghiệp có pháp nhân, hệ thống bắt chuyển khoản vào tài khoản cá nhân mở tại ngân hàng nội địa hoặc chuyển tiền mã hóa USDT vào ví cá nhân không định danh.

## III. Nguyên tắc phòng vệ cốt lõi

1. **Không có lợi nhuận phi thực tế**: Mọi cam kết lợi nhuận trên 15%/tháng mà "bao lỗ, cam kết hoàn vốn 100%" đều là dấu hiệu lừa đảo tài chính.
2. **Kiểm tra pháp lý**: Ngân hàng Nhà nước Việt Nam và Ủy ban Chứng khoán Nhà nước chưa cấp phép cho bất kỳ sàn giao dịch ngoại hối hay tiền mã hóa nào hoạt động tại Việt Nam.
3. **Cắt lỗ dứt khoát**: Khi sàn yêu cầu nộp thêm tiền để mở khóa rút tiền, tuyệt đối không chuyển thêm một đồng nào. Việc nộp thêm tiền chỉ làm gia tăng thiệt hại vì kẻ gian sẽ không bao giờ cho rút vốn.""",
        }
    )
    if created:
        print("Created Lesson: Pig Butchering")

    # Scenario for Lesson 1
    sc1, sc1_created = LearnScenario.objects.get_or_create(
        lesson=l1,
        title="Diễn tập: Thao túng tâm lý trong nhóm đầu tư tài chính VIP",
        defaults={
            "description": "Thực hành phát hiện thủ đoạn giăng bẫy của nhóm chuyên gia đầu tư ảo khi yêu cầu nộp phí bảo hiểm để rút tiền.",
            "content": {
                "steps": [
                    {
                        "actor": "Kẻ lừa đảo",
                        "text": "Chúc mừng anh Nam! Lệnh BTC đêm qua của anh đã chạm mốc chốt lời 45.000 USD (khoảng 1,1 tỷ VNĐ). Anh vào mục Rút tiền trên sàn FastTrade-Global.vip để chuyển về Vietcombank nhé.",
                        "analysis": "Kẻ gian hiển thị số dư ảo trên giao diện web do chúng tự lập trình để kích hoạt cảm xúc phấn khích tột độ của nạn nhân."
                    },
                    {
                        "actor": "Nạn nhân",
                        "text": "Tuyệt vời quá chuyên gia ơi! Mình vừa đặt lệnh rút 1,1 tỷ rồi nhưng hệ thống lại báo: 'Lệnh rút bị treo do vi phạm quy tắc rửa tiền'. Giờ phải làm sao hả bạn?",
                        "analysis": "Giai đoạn đóng băng tài khoản bắt đầu: Kẻ gian tạo ra lý do giả mạo để chặn dòng tiền."
                    },
                    {
                        "actor": "Kẻ lừa đảo",
                        "text": "Anh bình tĩnh, do số tiền quá lớn nên Ủy ban tài chính quốc tế yêu cầu đóng 20% phí xác minh bảo hiểm (tương đương 220 triệu VNĐ). Anh chuyển tiền vào số tài khoản Giám đốc tài chính này, sau 15 phút hệ thống sẽ giải ngân toàn bộ 1,32 tỷ về tài khoản anh ngay.",
                        "analysis": "Chiêu bài Chi phí chìm (Sunk Cost Fallacy): Ép nạn nhân nộp thêm tiền cứu số tiền đang bị kẹt."
                    },
                    {
                        "actor": "Hệ thống ShieldCall",
                        "text": "CẢNH BÁO TỐI NGUY: ĐÂY LÀ BẪY TỐNG TIỀN KÉP! Tên miền FastTrade-Global.vip mới đăng ký 14 ngày. Không có cơ quan tài chính nào bắt nộp phí để rút tiền của chính mình. Dừng chuyển tiền ngay lập tức!",
                        "analysis": "Cắt đứt ngay lập tức vòng xoáy chuyển tiền tiếp theo. Bảo toàn số tiền 220 triệu còn lại."
                    },
                    {
                        "actor": "Nạn nhân",
                        "text": "May quá nhờ hệ thống cảnh báo kịp thời, mình từ chối chuyển 220 triệu. Ngay lập tức tài khoản của mình trên web bị khóa và tên chuyên gia chặn Zalo của mình luôn!",
                        "analysis": "Hành động chính xác: Nạn nhân chấp nhận sự thật, bảo toàn tài sản còn lại và lưu lại chứng cứ để trình báo công an."
                    }
                ]
            }
        }
    )
    if sc1_created:
        print("Created Scenario 1")

    # Quizzes for Lesson 1
    q1_1, q1_1_created = LearnQuiz.objects.get_or_create(
        lesson=l1,
        question="Khi tham gia đầu tư trên một website sàn giao dịch và bị hệ thống yêu cầu nộp thêm 20% 'thuế/phí bảo hiểm' để mở khóa số tiền rút, hành động đúng đắn nhất là gì?",
        defaults={
            "question_type": QuizQuestionType.SINGLE,
            "options": [
                {"id": "A", "text": "Vay mượn người thân để nộp đúng 20% số tiền yêu cầu nhằm cứu số vốn ban đầu."},
                {"id": "B", "text": "Dừng nộp tiền ngay lập tức, lưu lại toàn bộ bằng chứng giao dịch và liên hệ cơ quan công an trình báo."},
                {"id": "C", "text": "Nhắn tin xin chuyên gia cho nộp trước 10% rồi rút tiền ra nộp nốt."},
                {"id": "D", "text": "Đổi mật khẩu tài khoản sàn giao dịch và gửi email khiếu nại cho sàn."}
            ],
            "correct_answer": "B",
            "correct_answers": ["B"],
            "explanation": "Quy tắc cốt lõi: Mọi yêu cầu nộp thêm phí để rút tiền trên sàn giao dịch đều là bẫy lừa đảo 100%. Càng nộp thêm tiền thì thiệt hại càng lớn."
        }
    )
    q1_2, q1_2_created = LearnQuiz.objects.get_or_create(
        lesson=l1,
        question="Dấu hiệu kỹ thuật nào sau đây chứng minh chắc chắn một website sàn giao dịch trực tuyến là giả mạo và lừa đảo?",
        defaults={
            "question_type": QuizQuestionType.SINGLE,
            "options": [
                {"id": "A", "text": "Trang web có ngôn ngữ tiếng Việt và giao diện tối màu (Dark mode)."},
                {"id": "B", "text": "Bắt buộc người tham gia phải nạp tiền thông qua chuyển khoản vào tài khoản ngân hàng cá nhân hoặc ví tiền mã hóa không định danh."},
                {"id": "C", "text": "Trang web yêu cầu người dùng phải xác thực email trước khi tạo tài khoản."},
                {"id": "D", "text": "Trang web có tính năng chat hỗ trợ trực tuyến 24/7."}
            ],
            "correct_answer": "B",
            "correct_answers": ["B"],
            "explanation": "Các tổ chức tài chính hợp pháp không bao giờ yêu cầu khách hàng nạp tiền đầu tư vào tài khoản cá nhân. Việc nhận tiền qua tài khoản cá nhân chứng minh đây là các tài khoản 'rác' nhằm tẩu tán tiền bất hợp pháp."
        }
    )

    # 2. Lesson: Ma doc gian diep Android & Dich vu cong gia mao
    l2, created = LearnLesson.objects.get_or_create(
        slug="ma-doc-gian-diep-android-accessibility-dich-vu-cong-gia-mao",
        defaults={
            "title": "Kỹ năng nhận diện Mã độc gián điệp Android & Bẫy cài đặt Dịch vụ công giả mạo",
            "category": "guide",
            "summary": "Phân tích cơ chế mã độc gián điệp lạm dụng quyền Trợ năng (Accessibility Service) trên hệ điều hành Android để đọc lén màn hình, cướp mã OTP và chiếm quyền điều khiển điện thoại.",
            "is_published": True,
            "content": """## I. Mối đe dọa từ mã độc gián điệp Android giả danh Dịch vụ công

Thủ đoạn lừa đảo qua ứng dụng mã độc Android (file có đuôi `.apk`) giả danh Cổng Dịch vụ công, Tổng cục Thuế, VNeID hoặc Bộ Công an hiện đang là nguyên nhân gây mất tiền lớn nhất tại Việt Nam.

### 1. Kịch bản tiếp cận của kẻ lừa đảo:
- Kẻ gian gọi điện xưng là cán bộ Công an phường/quận hoặc cán bộ Thuế thông báo hồ sơ định danh điện tử VNeID của nạn nhân bị lỗi, sai lệch thông tin bảo hiểm y tế hoặc nợ thuế.
- Do nạn nhân không có thời gian đến cơ quan trực tiếp, đối tượng nhiệt tình đề nghị "hướng dẫn xử lý online qua điện thoại để hỗ trợ người dân".
- Đối tượng gửi đường link qua Zalo/SMS yêu cầu nạn nhân tải về một ứng dụng mang tên như `Dichvucong.apk`, `VNeID_capnhat.apk` hoặc `eTaxMobile.apk`.

## II. Cơ chế kỹ thuật: Quyền Hỗ trợ tiếp cận (Accessibility Service)

Trên hệ điều hành Android, **Quyền Hỗ trợ tiếp cận (Accessibility Service)** vốn là tính năng nhân văn dành cho người khuyết tật (hỗ trợ đọc màn hình, tự động bấm phím). Tuy nhiên, các dòng mã độc (như Spyware, Banking Trojan) đã lạm dụng quyền này để:

1. **Ghi lại toàn bộ thao tác bàn phím (Keylogging)**: Mọi ký tự mật khẩu đăng nhập tài khoản ngân hàng, mã PIN khi người dùng gõ vào đều bị gửi về máy chủ của kẻ gian.
2. **Chụp và đọc trộm màn hình (Screen Scraping)**: Mã độc theo dõi trực tiếp màn hình khi tin nhắn SMS OTP gửi về máy, tự động sao chép mã OTP mà nạn nhân không hề hay biết.
3. **Thao tác ngầm từ xa (Remote Control)**: Khi nạn nhân ngủ hoặc khi màn hình điện thoại tắt, đối tượng kích hoạt chuyển tiền ngầm từ tài khoản nạn nhân sang các tài khoản thụ hưởng của tội phạm.

## III. Dấu hiệu nhận biết điện thoại bị nhiễm mã độc

- Điện thoại bỗng nhiên chạy rất chậm, nhanh nóng máy và hao pin bất thường dù không sử dụng.
- Xuất hiện hiện tượng màn hình tự sáng, cảm ứng tự nhảy như có người đang chạm vào điện thoại.
- Tin nhắn thông báo biến động số dư hoặc mã OTP bị tự động đọc và xóa khỏi hộp thư.

## IV. Biện pháp phòng chống và khắc phục khẩn cấp

- **Nguyên tắc vàng**: Tuyệt đối không cài đặt bất kỳ file ứng dụng nào có đuôi `.apk` từ đường link gửi qua tin nhắn Zalo, Facebook, SMS hay website lạ. Mọi ứng dụng chỉ cài đặt qua kho ứng dụng chính thức **Google Play Store**.
- **Cách xử lý khi đã lỡ cài đặt**:
  1. Lập tức bật chế độ Máy bay (Airplane Mode) hoặc tháo SIM, tắt Wifi để cắt đứt liên lạc giữa điện thoại và máy chủ kẻ lừa đảo.
  2. Sử dụng một thiết bị khác đăng nhập vào app ngân hàng để khóa thẻ và tài khoản khẩn cấp, hoặc gọi ngay lên tổng đài ngân hàng yêu cầu phong tỏa tài khoản.
  3. Khôi phục cài đặt gốc của điện thoại (Factory Reset) để quét sạch hoàn toàn mã độc.""",
        }
    )
    if created:
        print("Created Lesson: Android Malware")

    # Scenario for Lesson 2
    sc2, sc2_created = LearnScenario.objects.get_or_create(
        lesson=l2,
        title="Diễn tập: Xử lý cuộc gọi giả danh Cán bộ Thuế yêu cầu cài app eTax",
        defaults={
            "description": "Thực hành xử lý tình huống nhận cuộc gọi hỗ trợ hoàn thuế TNCN kèm đường link tải ứng dụng mã độc.",
            "content": {
                "steps": [
                    {
                        "actor": "Kẻ lừa đảo",
                        "text": "Chào chị Mai, tôi là Tuấn, cán bộ Chi cục Thuế quận. Hồ sơ quyết toán thuế năm 2025 của chị được hoàn trả 8.500.000 VNĐ nhưng sai thông tin căn cước. Chị vào link thuedientu-gov.xyz tải app eTax về để xác nhận nhận tiền nhé.",
                        "analysis": "Kẻ gian đánh vào tâm lý muốn nhận tiền hoàn thuế hợp pháp và giả danh cán bộ nhà nước để tạo niềm tin."
                    },
                    {
                        "actor": "Nạn nhân",
                        "text": "Ủa sao trên Google Play mình cũng thấy có app eTax Mobile mà, sao anh không bảo em tải trên đó mà lại gửi link qua Zalo?",
                        "analysis": "Nạn nhân có tinh thần cảnh giác rất tốt khi phát hiện nguồn tải ứng dụng bất thường."
                    },
                    {
                        "actor": "Kẻ lừa đảo",
                        "text": "Bản trên Google Play là bản cũ chưa cập nhật thông tư mới nhất chị ơi. Bản link em gửi là bản nội bộ Cục Thuế mới đồng bộ dữ liệu hoàn tiền tự động được.",
                        "analysis": "Kẻ gian ngụy biện bằng các thuật ngữ kỹ thuật nhằm thuyết phục nạn nhân cài file APK."
                    },
                    {
                        "actor": "Hệ thống ShieldCall",
                        "text": "CẢNH BÁO NGUY HIỂM: Tên miền thuedientu-gov.xyz là website giả mạo. Cục Thuế chỉ sử dụng tên miền thuedientu.gdt.gov.vn. Tuyệt đối không tải và mở file APK!",
                        "analysis": "Nhận diện tên miền lookalike và ngăn chặn hành vi tải phần mềm độc hại."
                    },
                    {
                        "actor": "Nạn nhân",
                        "text": "Tôi vừa kiểm tra cổng Cục Thuế chính thức rồi, không có thông báo nào như anh nói. Tôi sẽ ghi âm cuộc gọi này gửi cơ quan công an!",
                        "analysis": "Phản ứng chuẩn mực: Vạch trần đối tượng và chủ động bảo vệ an toàn cho thiết bị."
                    }
                ]
            }
        }
    )
    if sc2_created:
        print("Created Scenario 2")

    # Quizzes for Lesson 2
    q2_1, q2_1_created = LearnQuiz.objects.get_or_create(
        lesson=l2,
        question="Trên hệ điều hành Android, quyền cài đặt nào là nguy hiểm nhất khi bị mã độc lừa đảo lợi dụng để chiếm toàn quyền kiểm soát điện thoại và đọc trộm mã OTP?",
        defaults={
            "question_type": QuizQuestionType.SINGLE,
            "options": [
                {"id": "A", "text": "Quyền truy cập Bluetooth và thiết bị ngoại vi."},
                {"id": "B", "text": "Quyền Hỗ trợ tiếp cận (Accessibility Service)."},
                {"id": "C", "text": "Quyền tự động xoay màn hình (Auto-rotate)."},
                {"id": "D", "text": "Quyền điều chỉnh độ sáng màn hình."}
            ],
            "correct_answer": "B",
            "correct_answers": ["B"],
            "explanation": "Quyền Accessibility Service cho phép ứng dụng đọc mọi nội dung hiển thị trên màn hình (bao gồm mật khẩu, mã OTP) và tự động thực hiện các thao tác cảm ứng thay người dùng mà không cần tương tác vật lý."
        }
    )
    q2_2, q2_2_created = LearnQuiz.objects.get_or_create(
        lesson=l2,
        question="Nếu bạn lỡ cài đặt một ứng dụng lạ từ link gửi qua Zalo và nghi ngờ điện thoại bị nhiễm mã độc đánh cắp tài khoản ngân hàng, thao tác xử lý khẩn cấp đầu tiên phải làm là gì?",
        defaults={
            "question_type": QuizQuestionType.SINGLE,
            "options": [
                {"id": "A", "text": "Bật chế độ Máy bay (Airplane Mode) hoặc tắt Wifi/tháo SIM ngay lập tức để ngắt kết nối mạng của thiết bị."},
                {"id": "B", "text": "Cắm sạc điện thoại để pin không bị cạn kiệt."},
                {"id": "C", "text": "Đăng nhập ngay vào tài khoản ngân hàng trên chính điện thoại đó để kiểm tra số dư."},
                {"id": "D", "text": "Gửi tin nhắn thông báo cho bạn bè trên mạng xã hội."}
            ],
            "correct_answer": "A",
            "correct_answers": ["A"],
            "explanation": "Ngắt kết nối mạng (Bật Airplane Mode) lập tức chặn đứng luồng truyền dữ liệu giữa mã độc trên máy và máy chủ của kẻ gian, ngăn chặn kẻ gian kích hoạt lệnh chuyển tiền từ xa."
        }
    )

    # 3. Lesson: Bay tinh cam xuyen bien gioi (Romance Scam) - Category STORY
    l3, created = LearnLesson.objects.get_or_create(
        slug="chuyen-canh-giac-bay-tinh-cam-xuyen-bien-gioi-romance-scam",
        defaults={
            "title": "Chuyện cảnh giác: Hành trình bóc trần bẫy tình cảm trực tuyến xuyên biên giới (Romance Scam)",
            "category": "story",
            "summary": "Câu chuyện cảnh giác thực tế về kịch bản thao túng cảm xúc của các đối tượng giả danh phi công, kỹ sư dầu khí hoặc bác sĩ quân y nước ngoài gửi kiện hàng quà tặng triệu đô về Việt Nam.",
            "is_published": True,
            "content": """## I. Câu chuyện từ góc khuất: Bẫy tình cảm xuyên biên giới

Chị H. (42 tuổi, Hà Nội, mẹ đơn thân) quen một tài khoản tự xưng là David Miller qua ứng dụng giao lưu ngôn ngữ. Đối tượng giới thiệu là kỹ sư trưởng làm việc trên giàn khoan ngoài khơi Scotland, góa vợ và đang tìm kiếm một bến đỗ bình yên cho phần đời còn lại.

Trong suốt 3 tháng, David nhắn tin hỏi han ân cần từ sáng sớm đến đêm muộn. Bằng sự chu đáo, lịch thiệp và thấu hiểu, đối tượng từng bước xây dựng lòng tin tuyệt đối và vẽ nên viễn cảnh tương lai về một cuộc sống gia đình hạnh phúc tại Việt Nam.

## II. Kịch bản "Kiện hàng tình yêu" và các khoản phí vô tận

Khi lòng tin đã vững chắc, David thông báo:
- Đối tượng chuẩn bị kết thúc hợp đồng giàn khoan và gửi toàn bộ tài sản tích lũy (bao gồm 500.000 USD tiền mặt, trang sức kim cương và tài liệu giá trị) trong một thùng hàng ngoại giao gửi về Việt Nam nhờ chị H. giữ hộ.
- Vài ngày sau, một người phụ nữ tự xưng là "Nhân viên công ty chuyển phát nhanh quốc tế" gọi điện thông báo kiện hàng đã về sân bay Tân Sơn Nhất nhưng bị hải quan giữ lại do chứa lượng tiền mặt lớn trái phép.
- Để thông quan trót lọt, chị H. được yêu cầu nộp 50 triệu đồng "phí hải quan". Tiếp theo là các lý do nối tiếp: "phí đóng dấu chống rửa tiền" (120 triệu), "phí hối lộ hải quan" (300 triệu), "phí xác nhận tài sản ngoại giao" (500 triệu).
- Đối tượng David liên tục nhắn tin van xin, thề thốt: *"Em hãy cứu anh, nếu không đóng tiền kiện hàng sẽ bị tịch thu và anh sẽ bị tống giam khi hạ cánh. Toàn bộ tiền sau này đều là của em"*.

Chị H. đã vay mượn người thân, cầm cố nhà cửa để chuyển tổng cộng 1,8 tỷ đồng trước khi nhận ra kẻ lừa đảo biến mất không để lại dấu vết.

## III. Giải mã kỹ thuật thao túng tâm lý (Social Engineering)

1. **Love Bombing (Dội bom tình cảm)**: Đối tượng tạo cảm giác gắn kết mãnh liệt trong thời gian cực ngắn bằng những lời tán tỉnh, quan tâm quá mức để làm tê liệt lý trí nạn nhân.
2. **Kịch bản hoàn cảnh ngặt nghèo**: Đối tượng luôn gắn mình với các công việc đặc thù không thể gọi video call bình thường: lính gìn giữ hòa bình, kỹ sư giàn khoan, bác sĩ chiến trường.
3. **Đóng giả nhiều vai diễn**: Nhóm lừa đảo có kịch bản phối hợp nhịp nhàng giữa "người yêu online", "nhân viên hải quan", "công ty vận chuyển" để tạo cảm giác chân thực tuyệt đối.

## IV. Bài học xương máu

- **Nguyên tắc bất di bất dịch**: Cơ quan Hải quan Việt Nam không bao giờ làm việc qua điện thoại yêu cầu chuyển tiền vào tài khoản cá nhân để thông quan hàng hóa.
- **Dừng lại ngay khi nhắc đến TIỀN**: Bất kỳ mối quan hệ quen biết qua mạng xã hội nào mà chưa từng gặp mặt ngoài đời thực mà yêu cầu chuyển tiền, nhận quà hay đóng phí đều là lừa đảo 100%.""",
        }
    )
    if created:
        print("Created Lesson: Romance Scam")

    # Scenario for Lesson 3
    sc3, sc3_created = LearnScenario.objects.get_or_create(
        lesson=l3,
        title="Diễn tập: Xử lý cuộc gọi từ 'Công ty giao nhận' đòi phí thông quan kiện hàng quà tặng",
        defaults={
            "description": "Thực hành đối thoại và xử lý tình huống kẻ gian giả mạo nhân viên hải quan sân bay yêu cầu nộp tiền chuộc kiện hàng từ bạn quen qua mạng.",
            "content": {
                "steps": [
                    {
                        "actor": "Kẻ lừa đảo",
                        "text": "Alo chị Phương phải không? Em là nhân viên bưu cục hải quan sân bay Nội Bài. Có một kiện hàng ngoại giao từ Anh Quốc của ông William gửi cho chị, bên trong máy quét phát hiện có 300.000 USD tiền mặt. Chị phải nộp phạt 45 triệu đồng để làm thủ tục thông quan nếu không sẽ bị khởi tố tội buôn lậu.",
                        "analysis": "Kẻ gian phối hợp kịch bản đe dọa pháp lý kết hợp mồi nhử số tiền mặt khổng lồ trong kiện hàng."
                    },
                    {
                        "actor": "Nạn nhân",
                        "text": "Sao anh William bảo gửi quà kỷ niệm chứ đâu nói gửi tiền mặt đâu? Sao hải quan lại yêu cầu chuyển tiền vào tài khoản cá nhân Nguyễn Văn A thế này?",
                        "analysis": "Nạn nhân chỉ ra điểm mâu thuẫn lớn nhất: Cơ quan nhà nước không bao giờ dùng tài khoản cá nhân nhận phí."
                    },
                    {
                        "actor": "Kẻ lừa đảo",
                        "text": "Đây là tài khoản ủy thác của Đội trưởng kiểm soát hải quan để xử lý nội bộ kín cho chị. Trong vòng 30 phút chị không chuyển là bên em chuyển hồ sơ sang Cục Cảnh sát kinh tế đấy!",
                        "analysis": "Tạo áp lực thời gian cực đoan (Urgency) để ép nạn nhân không kịp suy nghĩ hay hỏi ý kiến người khác."
                    },
                    {
                        "actor": "Hệ thống ShieldCall",
                        "text": "DỪNG LẠI NGAY! Đây là chiêu bài lừa đảo 'Bưu kiện ngoại giao' kinh điển của tội phạm mạng quốc tế. Hải quan không bao giờ thu tiền qua tài khoản cá nhân. Hãy cúp máy ngay!",
                        "analysis": "Kích hoạt lá chắn tri thức, xác nhận 100% bẫy lừa đảo bưu kiện."
                    },
                    {
                        "actor": "Nạn nhân",
                        "text": "Tôi sẽ đến trực tiếp Chi cục Hải quan cửa khẩu sân bay Quốc tế Nội Bài để làm việc trực tiếp theo đúng quy định pháp luật. Chào anh!",
                        "analysis": "Xử lý đanh thép, chuẩn xác: Đề nghị làm việc trực tiếp tại trụ sở cơ quan công quyền khiến kẻ gian tự động rút lui."
                    }
                ]
            }
        }
    )
    if sc3_created:
        print("Created Scenario 3")

    # Quizzes for Lesson 3
    q3_1, q3_1_created = LearnQuiz.objects.get_or_create(
        lesson=l3,
        question="Dấu hiệu nào sau đây là đặc trưng điển hình nhất của thủ đoạn lừa đảo bẫy tình cảm trực tuyến (Romance Scam)?",
        defaults={
            "question_type": QuizQuestionType.SINGLE,
            "options": [
                {"id": "A", "text": "Đối tượng luôn chủ động rủ nạn nhân đi uống cà phê hoặc gặp mặt trực tiếp ngay tuần đầu tiên."},
                {"id": "B", "text": "Đối tượng vẽ ra hoàn cảnh sống ở nước ngoài, quan tâm yêu thương dồn dập, sau đó nhờ giữ hộ kiện hàng chứa tiền/vàng và yêu cầu nạn nhân chuyển tiền đóng phí hải quan."},
                {"id": "C", "text": "Đối tượng chia sẻ hình ảnh căn cước công dân có công chứng rõ ràng."},
                {"id": "D", "text": "Đối tượng yêu cầu gọi video call liên tục 24/24."}
            ],
            "correct_answer": "B",
            "correct_answers": ["B"],
            "explanation": "Kịch bản gửi kiện hàng ngoại giao chứa ngoại tệ/trang sức kèm yêu cầu đóng phí thông quan vào tài khoản cá nhân là dấu hiệu kinh điển của các băng nhóm lừa đảo tình cảm quốc tế."
        }
    )

    # 4. Lesson: An ninh so Bao trum (Inclusive) - Bao ve nguoi cao tuoi
    l4, created = LearnLesson.objects.get_or_create(
        slug="an-ninh-so-bao-trum-la-chan-bao-ve-nguoi-cao-tuoi-truoc-toi-pham-mang",
        defaults={
            "title": "An ninh số Bao trùm: Cẩm nang xây dựng 'Lá chắn số' bảo vệ người cao tuổi trong gia đình",
            "category": "inclusive",
            "summary": "Hướng dẫn thực chiến cho con cháu trong việc đồng hành, cấu hình thiết bị an toàn và xây dựng phản xạ bảo mật cho cha mẹ, ông bà trước các chiêu trò lừa đảo qua mạng.",
            "is_published": True,
            "content": """## I. Tại sao người cao tuổi là mục tiêu hàng đầu của tội phạm mạng?

Người cao tuổi là nhóm đối tượng dễ bị tổn thương nhất trên không gian số do:
- **Khoảng cách công nghệ**: Khó phân biệt giữa giao diện website thật và giả, dễ bị đánh lừa bởi tên thương hiệu hiển thị trên màn hình.
- **Tâm lý lo lắng cho con cháu**: Kẻ gian dễ thao túng bằng các cuộc gọi tin giả "con đang cấp cứu trong bệnh viện" hoặc "cháu bị công an bắt vì tai nạn".
- **Lòng trắc ẩn và sự cô đơn**: Dễ tin vào những lời hỏi han, thăm hỏi của người lạ trên các hội nhóm mạng xã hội.

## II. Xây dựng "Quy ước an toàn gia đình" (Family Safe Protocol)

Để bảo vệ người thân lớn tuổi, các gia đình cần thiết lập các nguyên tắc cụ thể:

### 1. Mật mã an toàn nội bộ (Safe Word)
Gia đình quy ước một từ khóa hoặc một câu hỏi bí mật chỉ các thành viên trong nhà biết (ví dụ: tên con vật nuôi đầu tiên, kỷ niệm đặc biệt). Bất cứ khi nào nhận được cuộc gọi khẩn cấp mượn tiền, chuyển viện từ người tự xưng là người thân, bắt buộc phải hỏi lại mật mã này.

### 2. Nguyên tắc "Chậm lại 15 phút"
Dặn dò cha mẹ tuyệt đối không bao giờ thao tác chuyển tiền ngay lập tức khi đang nghe điện thoại. Hãy giữ nguyên tắc:
- Dập máy ngay.
- Chờ 2 phút cho tâm lý bình tĩnh lại.
- Gọi lại cho con cháu theo số điện thoại quen thuộc đã lưu trong danh bạ để kiểm chứng.

### 3. Cấu hình kỹ thuật an toàn trên điện thoại của cha mẹ
- **Hạn mức giao dịch (Transaction Limit)**: Cài đặt hạn mức chuyển khoản trên app ngân hàng của cha mẹ ở mức vừa phải (ví dụ tối đa 5 triệu VNĐ/ngày). Khi cần giao dịch lớn, con cháu sẽ hỗ trợ đối soát.
- **Khóa cài đặt ứng dụng ngoài**: Kích hoạt tính năng chặn cài đặt từ nguồn không xác định trên Android.
- **Tắt tính năng 2G**: Vào phần cài đặt mạng di động tắt tùy chọn 'Cho phép 2G' để vô hiệu hóa trạm phát sóng BTS giả mạo.""",
        }
    )
    if created:
        print("Created Lesson: Inclusive")

    # Scenario for Lesson 4
    sc4, sc4_created = LearnScenario.objects.get_or_create(
        lesson=l4,
        title="Diễn tập: Cuộc gọi báo tin giả 'Con trai đang cấp cứu cần chuyển tiền gấp'",
        defaults={
            "description": "Thực hành phản xạ kiểm chứng thông tin khi người cao tuổi nhận được cuộc gọi thông báo người thân gặp tai nạn nguy kịch.",
            "content": {
                "steps": [
                    {
                        "actor": "Kẻ lừa đảo",
                        "text": "Bác Lan phải không? Tôi là bác sĩ Hùng ở Bệnh viện Chợ Rẫy. Cháu Minh con bác bị tai nạn giao thông chấn thương sọ não rất nặng, đang ở phòng mổ cấp cứu. Bác phải chuyển khoản ngay 30 triệu tiền viện phí vào số tài khoản bệnh viện này để kịp truyền máu cứu cháu!",
                        "analysis": "Đòn tâm lý đánh thẳng vào tình mẫu tử với âm thanh còi hú cấp cứu giả lập phía sau nhằm làm nạn nhân hoảng loạn."
                    },
                    {
                        "actor": "Nạn nhân",
                        "text": "Trời ơi thằng Minh con tôi... Tay chân run rẩy không cầm nổi điện thoại... Để tôi ra ngân hàng chuyển tiền ngay...",
                        "analysis": "Nạn nhân rơi vào trạng thái sốc tâm lý, mất hoàn toàn khả năng tư duy logic."
                    },
                    {
                        "actor": "Hệ thống ShieldCall",
                        "text": "BÌNH TĨNH! DỪNG LẠI! Bệnh viện công luôn cấp cứu bệnh nhân trước trong tình huống nguy kịch, không bao giờ bắt chuyển tiền qua số tài khoản cá nhân. Hãy gọi ngay số điện thoại riêng của cháu Minh hoặc đồng nghiệp của cháu!",
                        "analysis": "Kịp thời can thiệp nhắc nhở nguyên tắc vàng: Kiểm chứng qua kênh thứ hai."
                    },
                    {
                        "actor": "Nạn nhân",
                        "text": "Tôi cúp máy và bấm gọi trực tiếp cho con trai. Minh nghe máy bảo: 'Mẹ ơi con đang họp ở công ty mà, có tai nạn gì đâu!'. Suýt chút nữa là tôi mất trắng tiền dưỡng già!",
                        "analysis": "Cứu vãn tình huống xuất sắc nhờ thực hiện cuộc gọi đối soát chéo."
                    }
                ]
            }
        }
    )
    if sc4_created:
        print("Created Scenario 4")

    # Quizzes for Lesson 4
    q4_1, q4_1_created = LearnQuiz.objects.get_or_create(
        lesson=l4,
        question="Giải pháp kỹ thuật và quy ước gia đình nào hiệu quả nhất để bảo vệ người lớn tuổi trước các cuộc gọi Deepfake giả giọng người thân mượn tiền?",
        defaults={
            "question_type": QuizQuestionType.SINGLE,
            "options": [
                {"id": "A", "text": "Cấm người lớn tuổi sử dụng điện thoại thông minh."},
                {"id": "B", "text": "Thiết lập một 'Mật mã an toàn gia đình' (Safe Word) bí mật và cài đặt hạn mức chuyển khoản ngân hàng ở mức an toàn."},
                {"id": "C", "text": "Chuyển tiền ngay khi nghe thấy đúng giọng của con cháu để tránh làm lỡ việc gấp."},
                {"id": "D", "text": "Tắt nguồn điện thoại vào ban đêm."}
            ],
            "correct_answer": "B",
            "correct_answers": ["B"],
            "explanation": "Quy ước mật mã gia đình (câu hỏi/từ khóa bí mật) là biện pháp phi kỹ thuật chống Deepfake hiệu quả nhất, kết hợp cùng hạn mức giao dịch ngân hàng thấp giúp ngăn ngừa thất thoát tài sản lớn."
        }
    )

    # 5. Lesson: Goc thau cam (Empathy) - Phuc hoi sau lua dao
    l5, created = LearnLesson.objects.get_or_create(
        slug="goc-thau-cam-phuc-hoi-tam-ly-va-tai-chinh-sau-khi-bi-lua-dao",
        defaults={
            "title": "Góc thấu cảm: Vượt qua sang chấn tâm lý và phục hồi tài chính sau khi bị lừa đảo trực tuyến",
            "category": "empathy",
            "summary": "Chia sẻ phương pháp giải tỏa cảm giác tội lỗi, tự trách bản thân, đối diện với gia đình và các bước phòng tránh bẫy lừa đảo thứ cấp 'Dịch vụ thu hồi tiền lừa đảo'.",
            "is_published": True,
            "content": """## I. Sang chấn tâm lý sau khi sập bẫy lừa đảo

Rất nhiều nạn nhân sau khi bị chiếm đoạt tài sản qua mạng phải đối mặt với nỗi đau tinh thần còn lớn hơn cả sự mất mát về vật chất:
- **Cảm giác tự trách và xấu hổ**: *"Tại sao mình có ăn học đàng hoàng, hiểu biết xã hội mà lại có thể ngu ngốc để bị lừa như vậy?"*
- **Nỗi sợ hãi bị người thân phán xét**: Sợ gia đình ruồng bỏ, sợ bạn bè chê cười nên chọn cách giấu kín và chịu đựng một mình trong bế tắc.
- **Rối loạn lo âu và trầm cảm**: Mất ngủ triền miên, suy sụp tinh thần, thậm chí có những suy nghĩ tiêu cực về cuộc sống.

## II. Sự thật cần phải thấu hiểu

1. **Bạn không có lỗi, kẻ phạm tội mới là kẻ có tội**: Các băng nhóm tội phạm mạng được huấn luyện tâm lý bài bản, có sự hỗ trợ của các chuyên gia công nghệ và kịch bản thao túng hành vi tinh vi. Bất kỳ ai, từ giáo sư, bác sĩ đến cán bộ quản lý đều có thể trở thành nạn nhân khi bị đánh trúng điểm yếu tâm lý.
2. **Đối diện và sẻ chia**: Việc chia sẻ thật lòng với gia đình là bước đầu tiên để giải tỏa áp lực. Thừa nhận tổn thất là khởi đầu của sự phục hồi.

## III. Cảnh báo đỏ: Bẫy lừa đảo thứ cấp "Dịch vụ lấy lại tiền bị lừa"

Khi nạn nhân hoang mang tìm cách lấy lại tiền trên mạng xã hội, một cái bẫy mới nguy hiểm không kém lập tức mở ra:
- **Chiêu bài**: Các fanpage chạy quảng cáo rầm rộ mang tên "Văn phòng Luật sư hỗ trợ thu hồi vốn", "Cục An ninh mạng thu hồi tiền treo", "Hacker mũ trắng giúp lấy lại tiền bị lừa".
- **Thủ đoạn**: Kẻ gian yêu cầu nạn nhân cung cấp thông tin tài khoản bị lừa, thông báo "đã tìm thấy dòng tiền và đóng băng được trên sàn", sau đó yêu cầu nạn nhân nộp 10% đến 20% "phí kỹ thuật kéo tiền về".
- **Sự thật**: Khi nạn nhân chuyển thêm tiền, nhóm này lập tức chặn tài khoản. Đây là đòn giáng bồi khiến nạn nhân mất thêm số tiền tích lũy ít ỏi còn lại.

## IV. Quy trình xử lý pháp lý đúng chuẩn

1. **Thu thập chứng cứ**: Chụp ảnh lại toàn bộ tin nhắn, sao kê tài khoản ngân hàng, số điện thoại, đường link website của kẻ lừa đảo.
2. **Nộp đơn trình báo**: Đến trực tiếp Cơ quan Cảnh sát điều tra (Công an cấp Quận/Huyện hoặc Phòng An ninh mạng và phòng chống tội phạm công nghệ cao - PA05 Công an Tỉnh/Thành phố) nơi bạn cư trú để nộp đơn tố giác tội phạm.""",
        }
    )
    if created:
        print("Created Lesson: Empathy")

    # Scenario for Lesson 5
    sc5, sc5_created = LearnScenario.objects.get_or_create(
        lesson=l5,
        title="Diễn tập: Nhận diện bẫy lừa đảo thứ cấp 'Văn phòng luật sư cam kết lấy lại tiền'",
        defaults={
            "description": "Thực hành phát hiện thủ đoạn của các fanpage giả danh luật sư/hacker hỗ trợ lấy lại tiền bị lừa đảo trên mạng xã hội.",
            "content": {
                "steps": [
                    {
                        "actor": "Nạn nhân",
                        "text": "Chào Luật sư, tuần trước em bị lừa mất 150 triệu trên sàn đầu tư ảo. Thấy bên mình quảng cáo hỗ trợ thu hồi tiền bị lừa đảo, luật sư có lấy lại giúp em được không?",
                        "analysis": "Nạn nhân đang trong trạng thái tâm lý suy sụp, khao khát gỡ gạc tài sản bị mất."
                    },
                    {
                        "actor": "Kẻ lừa đảo",
                        "text": "Bên anh đã can thiệp vào máy chủ sàn và truy vết thành công số tiền 150 triệu của em đang bị treo tại cổng thanh toán quốc tế. Em nộp 15 triệu phí lập hồ sơ ủy thác ngân hàng nhà nước thì bên anh sẽ đẩy tiền về tài khoản em trong 30 phút.",
                        "analysis": "Đòn đánh tâm lý vào hy vọng cuối cùng của nạn nhân. Cam kết thời gian siêu tốc và số tiền lấy lại 100%."
                    },
                    {
                        "actor": "Hệ thống ShieldCall",
                        "text": "CẢNH BÁO CỰC KỲ NGUY HIỂM: ĐÂY LÀ BẪY LỪA ĐẢO THỨ CẤP! Chỉ có Cơ quan Cảnh sát điều tra mới có thẩm quyền phong tỏa và thu hồi tài sản theo luật tố tụng hình sự. Không có bất kỳ cá nhân, luật sư hay hacker nào can thiệp được máy chủ ngân hàng để lấy lại tiền!",
                        "analysis": "Chặn đứng ngay lập tức nguy cơ bị lừa đảo lần hai."
                    },
                    {
                        "actor": "Nạn nhân",
                        "text": "Suýt chút nữa là em lại bị lừa thêm 15 triệu nữa! Em sẽ in toàn bộ chứng cứ ra Công an quận trình báo theo đúng pháp luật.",
                        "analysis": "Lựa chọn con đường chính thống và bảo vệ số tiền còn lại của bản thân."
                    }
                ]
            }
        }
    )
    if sc5_created:
        print("Created Scenario 5")

    # Quizzes for Lesson 5
    q5_1, q5_1_created = LearnQuiz.objects.get_or_create(
        lesson=l5,
        question="Sau khi bị lừa đảo chiếm đoạt tiền qua mạng, các dịch vụ tự xưng là 'Văn phòng luật sư/Hacker mũ trắng cam kết lấy lại 100% tiền bị lừa trong 24 giờ' trên Facebook có bản chất là gì?",
        defaults={
            "question_type": QuizQuestionType.SINGLE,
            "options": [
                {"id": "A", "text": "Là các chuyên gia công nghệ cao được nhà nước cấp phép hỗ trợ người dân."},
                {"id": "B", "text": "Là thủ đoạn lừa đảo thứ cấp (Recovery Scam), chuyên nhắm vào các nạn nhân đang tuyệt vọng để lừa nộp thêm phí rồi chiếm đoạt tiếp."},
                {"id": "C", "text": "Là dịch vụ đòi nợ thuê hợp pháp."},
                {"id": "D", "text": "Là nhân viên hỗ trợ của các ngân hàng thương mại."}
            ],
            "correct_answer": "B",
            "correct_answers": ["B"],
            "explanation": "Tất cả các dịch vụ mạng xã hội cam kết 'lấy lại tiền lừa đảo' đều là lừa đảo thứ cấp. Chỉ có cơ quan Công an thụ lý vụ án mới có thẩm quyền điều tra, phong tỏa và thu hồi tài sản theo đúng trình tự pháp luật."
        }
    )

    # 6. Add more quizzes to existing lessons (to make every lesson rich with 2-3 questions)
    existing_lessons = {l.slug: l for l in LearnLesson.objects.all()}

    # Lesson 5 (Deepfake)
    l_deepfake = existing_lessons.get("ky-nang-nhan-dien-va-phong-chong-cuoc-goi-deepfake-ai")
    if l_deepfake:
        LearnQuiz.objects.get_or_create(
            lesson=l_deepfake,
            question="Khi nhận được video call có hình ảnh người thân nhưng nghi ngờ là Deepfake AI, phương pháp kiểm tra thực địa nào sau đây giúp bóc trần công nghệ giả mạo này nhanh nhất?",
            defaults={
                "question_type": QuizQuestionType.SINGLE,
                "options": [
                    {"id": "A", "text": "Yêu cầu người gọi đưa bàn tay qua lại trước khuôn mặt hoặc quay nghiêng đầu 90 độ sang hai bên."},
                    {"id": "B", "text": "Tắt camera của mình đi và chỉ nghe tiếng."},
                    {"id": "C", "text": "Hỏi xem thời tiết nơi người đó đang ở thế nào."},
                    {"id": "D", "text": "Chụp màn hình video call gửi lên mạng xã hội."}
                ],
                "correct_answer": "A",
                "correct_answers": ["A"],
                "explanation": "Các thuật toán Deepfake thời gian thực xử lý vật cản rất kém. Khi có vật thể (bàn tay) che trước mặt hoặc khi quay đầu nhanh, mô hình AI sẽ bị biến dạng (glitch), xé hình và nhòe khuôn mặt rõ rệt."
            }
        )

    # Lesson 6 (Quyết định 2345)
    l_2345 = existing_lessons.get("quyet-inh-2345q-nhnn-va-la-chan-sinh-trac-hoc-tai-khoan-ngan-hang")
    if l_2345:
        LearnQuiz.objects.get_or_create(
            lesson=l_2345,
            question="Mục đích cốt lõi quan trọng nhất của Quyết định 2345/QĐ-NHNN về xác thực sinh trắc học khuôn mặt khớp với chip CCCD là gì?",
            defaults={
                "question_type": QuizQuestionType.SINGLE,
                "options": [
                    {"id": "A", "text": "Giúp ngân hàng thu thêm phí dịch vụ hàng tháng từ khách hàng."},
                    {"id": "B", "text": "Xóa sổ triệt để vấn nạn tài khoản ngân hàng 'rác' (mua bán, thuê mượn CMND/CCCD giả) dùng để rửa tiền và nhận tiền lừa đảo."},
                    {"id": "C", "text": "Bắt buộc khách hàng phải thay đổi điện thoại mới đắt tiền hơn."},
                    {"id": "D", "text": "Thay thế hoàn toàn mật khẩu đăng nhập ngân hàng."}
                ],
                "correct_answer": "B",
                "correct_answers": ["B"],
                "explanation": "Khi mọi giao dịch trên 10 triệu đồng hoặc chuyển tiền lần đầu trên thiết bị mới đều bắt buộc quét khuôn mặt khớp với chip CCCD đã đối soát với cơ sở dữ liệu Bộ Công an, kẻ lừa đảo không thể dùng tài khoản rác mua trôi nổi để tẩu tán tiền được nữa."
            }
        )

    # Lesson 8 (Việc nhẹ lương cao)
    l_job = existing_lessons.get("nhan-dien-bay-tuyen-dung-viec-nhe-luong-cao-va-bay-giat-on-shopeetiktok")
    if l_job:
        LearnQuiz.objects.get_or_create(
            lesson=l_job,
            question="Dấu hiệu tâm lý nào khiến nạn nhân của bẫy 'Việc nhẹ lương cao - Giật đơn ảo' tiếp tục nạp số tiền lớn hơn dù đã nghi ngờ mình bị lừa?",
            defaults={
                "question_type": QuizQuestionType.SINGLE,
                "options": [
                    {"id": "A", "text": "Hiệu ứng tâm lý chi phí chìm (Sunk Cost Fallacy) — tâm lý tiếc nuối số tiền đã nạp và hy vọng nạp thêm một lần cuối sẽ lấy lại được toàn bộ vốn."},
                    {"id": "B", "text": "Sự tin tưởng tuyệt đối vào uy tín của người tuyển dụng."},
                    {"id": "C", "text": "Nhu cầu muốn học hỏi thêm kỹ năng bán hàng trực tuyến."},
                    {"id": "D", "text": "Mong muốn được thăng chức lên làm quản lý nhóm."}
                ],
                "correct_answer": "A",
                "correct_answers": ["A"],
                "explanation": "Hiệu ứng chi phí chìm là đòn bẩy tâm lý nguy hiểm nhất. Nạn nhân vì tiếc 10-20 triệu đã nạp trước đó nên sẵn sàng đi vay thêm hàng trăm triệu để cố 'hoàn thành đơn hàng cuối' nhằm rút tiền về, dẫn đến kiệt quệ tài chính."
            }
        )

    # Lesson 9 (Quishing)
    l_qr = existing_lessons.get("quishing-moi-nguy-hiem-tiem-an-tu-ma-qr-dan-e-o-noi-cong-cong")
    if l_qr:
        LearnQuiz.objects.get_or_create(
            lesson=l_qr,
            question="Khi thanh toán tiền tại quầy thu ngân hoặc bàn ăn ở quán cà phê bằng mã QR, thao tác bảo mật bắt buộc người tiêu dùng phải kiểm tra trước khi xác nhận chuyển tiền là gì?",
            defaults={
                "question_type": QuizQuestionType.SINGLE,
                "options": [
                    {"id": "A", "text": "Kiểm tra xem mã QR có màu sắc đẹp mắt và rõ nét không."},
                    {"id": "B", "text": "Kiểm tra Tên chủ tài khoản thụ hưởng hiển thị trên màn hình ứng dụng ngân hàng có đúng tên của cửa hàng/nhân viên thu ngân hay không."},
                    {"id": "C", "text": "Đổi mật khẩu tài khoản ngân hàng ngay trước khi quét mã."},
                    {"id": "D", "text": "Bật đèn flash của điện thoại khi quét mã."}
                ],
                "correct_answer": "B",
                "correct_answers": ["B"],
                "explanation": "Kẻ gian thường dán đè mã QR của tài khoản cá nhân lên trên mã QR của quán. Việc đối soát Tên chủ tài khoản thụ hưởng trên màn hình ứng dụng ngân hàng trước khi bấm Chuyển tiền là bước duy nhất giúp bạn không chuyển nhầm tiền cho kẻ lừa đảo."
            }
        )

    print("Finished enriching lessons, scenarios, and quizzes.")


if __name__ == "__main__":
    enrich_lessons()
