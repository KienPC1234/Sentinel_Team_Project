"""
Seed data management command for ShieldCall VN (Sentinel Team Project).
Populates realistic Vietnamese cyber threat demo data across:
- Users & User Profiles
- Educational Articles & News (CMS)
- Community Forum Discussions & Multilevel Comments
- Educational Lessons, Quizzes & Interactive Scenarios
- Tracked Fraud Bank Accounts Blacklist
- Community Scam Reports & Evidence
- 30-Day Daily Scam Trend Statistics
- System Announcements & Support Tickets
"""
import hashlib
from datetime import timedelta
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.db import transaction

from api.core.models import (
    UserProfile, Domain, BankAccount, Report, ScanEvent,
    TrendDaily, EntityLink, ForumCategory, ForumPost, ForumComment,
    ForumLike, ForumCommentLike, ForumPostReaction, ForumReactionType,
    ArticleCategory, Article, ArticleComment, ArticleReaction,
    LearnLesson, LearnQuiz, LearnScenario, LearnReactionType,
    QuizQuestionType, Announcement, AnnouncementReaction, SupportTicket,
    ScamType, Severity, RiskLevel, ReportStatus, TargetType
)
from api.phone_security.models import PhoneNumber, PhoneReport, PhoneRiskLevel

User = get_user_model()


class Command(BaseCommand):
    help = "Seed comprehensive, realistic Vietnamese sample data for ShieldCall VN"

    def add_arguments(self, parser):
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear previous demo data before seeding (preserves superuser and api keys)',
        )

    def handle(self, *args, **options):
        clear_data = options.get('clear', False)

        self.stdout.write(self.style.NOTICE("=== BẮT ĐẦU KHỞI TẠO DỮ LIỆU THỰC TẾ SHIELDCALL VN ==="))

        with transaction.atomic():
            if clear_data:
                self.stdout.write("Dọn dẹp dữ liệu mẫu cũ...")
                EntityLink.objects.all().delete()
                PhoneReport.objects.all().delete()
                PhoneNumber.objects.all().delete()
                Report.objects.all().delete()
                BankAccount.objects.all().delete()
                ForumPostReaction.objects.all().delete()
                ForumCommentLike.objects.all().delete()
                ForumLike.objects.all().delete()
                ForumComment.objects.all().delete()
                ForumPost.objects.all().delete()
                ArticleReaction.objects.all().delete()
                ArticleComment.objects.all().delete()
                Article.objects.all().delete()
                LearnQuiz.objects.all().delete()
                LearnScenario.objects.all().delete()
                LearnLesson.objects.all().delete()
                AnnouncementReaction.objects.all().delete()
                Announcement.objects.all().delete()
                SupportTicket.objects.all().delete()
                TrendDaily.objects.all().delete()
                # Delete demo users only, keep superusers / primary admin
                User.objects.filter(is_superuser=False).delete()
                self.stdout.write(self.style.SUCCESS("Đã dọn dẹp dữ liệu cũ."))

            # ──────────────────────────────────────────────────────────────────
            # 1. USERS & PROFILES (15+ Community Members)
            # ──────────────────────────────────────────────────────────────────
            self.stdout.write("1. Khởi tạo 15 tài khoản thành viên cộng đồng...")
            users_meta = [
                {
                    'username': 'admin_sentinel',
                    'email': 'admin@shieldcall.vn',
                    'first_name': 'Quản Trị',
                    'last_name': 'Hệ Thống',
                    'is_staff': True,
                    'is_superuser': True,
                    'display_name': 'Ban Quản Trị ShieldCall',
                    'bio': 'Tài khoản chính thức của Đội ngũ Điều hành An ninh Mạng ShieldCall VN.',
                    'rank_points': 5800,
                },
                {
                    'username': 'chuyen_gia_an_ninh',
                    'email': 'bach.hoang@shieldcall.vn',
                    'first_name': 'Hoàng',
                    'last_name': 'Văn Bách',
                    'is_staff': True,
                    'is_superuser': False,
                    'display_name': 'Bách Hoàng (SOC Lead)',
                    'bio': 'Trưởng bộ phận Giám sát và Phản ứng Sự cố An ninh Mạng (SOC). 10 năm kinh nghiệm điều tra mã độc.',
                    'rank_points': 4250,
                },
                {
                    'username': 'vu_quoc_viet',
                    'email': 'viet.vu@cyberthreat.vn',
                    'first_name': 'Việt',
                    'last_name': 'Vũ Quốc',
                    'is_staff': False,
                    'is_superuser': False,
                    'display_name': 'Vũ Quốc Việt (OSINT Specialist)',
                    'bio': 'Chuyên gia phân tích tình báo an ninh nguồn mở (OSINT) và truy vết mạng lưới lừa đảo xuyên biên giới.',
                    'rank_points': 3650,
                },
                {
                    'username': 'do_thi_thu_trang',
                    'email': 'trang.lawyer@justice.vn',
                    'first_name': 'Trang',
                    'last_name': 'Đỗ Thị Thu',
                    'is_staff': False,
                    'is_superuser': False,
                    'display_name': 'Luật sư Thu Trang',
                    'bio': 'Luật sư chuyên ngành Tội phạm Công nghệ cao & Tư vấn pháp lý hỗ trợ nạn nhân lừa đảo tài chính.',
                    'rank_points': 3100,
                },
                {
                    'username': 'pham_minh_duc',
                    'email': 'duc.pham@viettelcyber.com',
                    'first_name': 'Đức',
                    'last_name': 'Phạm Minh',
                    'is_staff': False,
                    'is_superuser': False,
                    'display_name': 'Phạm Minh Đức (Security Researcher)',
                    'bio': 'Kỹ sư nghiên cứu an ninh ứng dụng di động & Phát hiện bẫy trojan banking Android.',
                    'rank_points': 2850,
                },
                {
                    'username': 'nguyen_van_an',
                    'email': 'an.nguyen@gmail.com',
                    'first_name': 'An',
                    'last_name': 'Nguyễn Văn',
                    'is_staff': False,
                    'is_superuser': False,
                    'display_name': 'Nguyễn Văn An',
                    'bio': 'Thành viên cộng đồng tích cực tham gia rà soát và đối soát số điện thoại spam/scam.',
                    'rank_points': 1850,
                },
                {
                    'username': 'tran_thi_mai',
                    'email': 'mai.tran@gmail.com',
                    'first_name': 'Mai',
                    'last_name': 'Trần Thị',
                    'is_staff': False,
                    'is_superuser': False,
                    'display_name': 'Trần Thị Mai',
                    'bio': 'Từng suýt bị lừa 80 triệu qua Telegram, tích cực chia sẻ cảnh báo cho các bạn trẻ và mẹ bỉm sữa.',
                    'rank_points': 1420,
                },
                {
                    'username': 'le_hoang_nam',
                    'email': 'nam.le@fpt.edu.vn',
                    'first_name': 'Nam',
                    'last_name': 'Lê Hoàng',
                    'is_staff': False,
                    'is_superuser': False,
                    'display_name': 'Lê Hoàng Nam',
                    'bio': 'Sinh viên chuyên ngành An toàn Thông tin - FPT University.',
                    'rank_points': 980,
                },
                {
                    'username': 'nguyen_thu_huong',
                    'email': 'huong.edu@hn.edu.vn',
                    'first_name': 'Hương',
                    'last_name': 'Nguyễn Thu',
                    'is_staff': False,
                    'is_superuser': False,
                    'display_name': 'Cô Thu Hương (Cán bộ hưu trí)',
                    'bio': 'Cán bộ giáo dục hưu trí, tích cực tuyên truyền an toàn số cho chi hội phụ nữ và người cao tuổi.',
                    'rank_points': 890,
                },
                {
                    'username': 'bui_van_thanh',
                    'email': 'thanh.delivery@ghtk.vn',
                    'first_name': 'Thành',
                    'last_name': 'Bùi Văn',
                    'is_staff': False,
                    'is_superuser': False,
                    'display_name': 'Bùi Văn Thành (Giao hàng nhanh)',
                    'bio': 'Tài xế giao hàng công nghệ, chuyên phát hiện và cảnh báo các thủ đoạn giao đơn hàng khống thu tiền COD.',
                    'rank_points': 760,
                },
                {
                    'username': 'dang_tuan_anh',
                    'email': 'tuananh.telecom@vnpt.vn',
                    'first_name': 'Anh',
                    'last_name': 'Đặng Tuấn',
                    'is_staff': False,
                    'is_superuser': False,
                    'display_name': 'Đặng Tuấn Anh (Kỹ sư Viễn thông)',
                    'bio': 'Kỹ sư hạ tầng mạng viễn thông di động, nghiên cứu cơ chế phòng chống trạm BTS giả.',
                    'rank_points': 1650,
                },
                {
                    'username': 'hoang_kim_ngan',
                    'email': 'ngan.media@agency.vn',
                    'first_name': 'Ngân',
                    'last_name': 'Hoàng Kim',
                    'is_staff': False,
                    'is_superuser': False,
                    'display_name': 'Hoàng Kim Ngân (Digital Creator)',
                    'bio': 'Quản trị viên cộng đồng Cảnh giác không gian mạng, chuyên sản xuất video infographic phòng vệ số.',
                    'rank_points': 1220,
                },
                {
                    'username': 'dinh_quang_huy',
                    'email': 'huy.fintech@vnpay.vn',
                    'first_name': 'Huy',
                    'last_name': 'Đinh Quang',
                    'is_staff': False,
                    'is_superuser': False,
                    'display_name': 'Đinh Quang Huy (Chuyên viên Fintech)',
                    'bio': 'Chuyên viên kiểm toán rủi ro thanh toán điện tử & giám sát gian lận giao dịch QR Code.',
                    'rank_points': 1950,
                },
                {
                    'username': 'phan_thanh_tung',
                    'email': 'tung.invest@crypto.vn',
                    'first_name': 'Tùng',
                    'last_name': 'Phan Thanh',
                    'is_staff': False,
                    'is_superuser': False,
                    'display_name': 'Phan Thanh Tùng',
                    'bio': 'Nhà đầu tư cá nhân, chia sẻ dấu hiệu nhận diện các dự án tiền ảo Ponzi đa cấp lừa đảo.',
                    'rank_points': 1130,
                },
                {
                    'username': 'ngoc_anh_cyber',
                    'email': 'ngocanh.soc@bkav.com',
                    'first_name': 'Ánh',
                    'last_name': 'Trần Ngọc',
                    'is_staff': False,
                    'is_superuser': False,
                    'display_name': 'Ngọc Ánh (SOC Analyst)',
                    'bio': 'Phân tích cảnh báo an ninh thông tin, theo dõi các chiến dịch Phishing mạo danh tổ chức tài chính.',
                    'rank_points': 2200,
                },
            ]

            user_map = {}
            for u_data in users_meta:
                u, created = User.objects.get_or_create(
                    username=u_data['username'],
                    defaults={
                        'email': u_data['email'],
                        'first_name': u_data['first_name'],
                        'last_name': u_data['last_name'],
                        'is_staff': u_data['is_staff'],
                        'is_superuser': u_data['is_superuser'],
                    }
                )
                if created:
                    u.set_password('ShieldCallDemo@2026')
                    u.save()

                prof, _ = UserProfile.objects.get_or_create(user=u)
                prof.display_name = u_data['display_name']
                prof.bio = u_data['bio']
                prof.rank_points = u_data['rank_points']
                prof.save()
                user_map[u_data['username']] = u

            # Keep user 1 updated if exists
            u1 = User.objects.filter(id=1).first()
            if u1 and u1.username not in user_map:
                prof1, _ = UserProfile.objects.get_or_create(user=u1)
                if not prof1.display_name:
                    prof1.display_name = u1.username
                prof1.rank_points = max(prof1.rank_points, 500)
                prof1.save()
                user_map[u1.username] = u1

            # ──────────────────────────────────────────────────────────────────
            # 2. ARTICLES & NEWS (10 Comprehensive CMS Articles)
            # ──────────────────────────────────────────────────────────────────
            self.stdout.write("2. Khởi tạo 10 bài báo tri thức an ninh mạng...")
            articles_data = [
                {
                    'title': 'Cục An toàn thông tin cảnh báo 25 kịch bản lừa đảo trực tuyến phổ biến đầu năm 2026',
                    'category': ArticleCategory.NEWS,
                    'summary': 'Báo cáo tổng hợp từ Cục An toàn thông tin (Bộ TT&TT) chỉ rõ 5 nhóm thủ đoạn chính và 25 kịch bản lừa đảo đang bùng phát nhắm vào người dùng internet tại Việt Nam.',
                    'content': """### 1. Bức tranh toàn cảnh an ninh mạng 2025 - 2026
Theo số liệu thống kê mới nhất từ Trung tâm Giám sát an toàn không gian mạng quốc gia (NCSC), tội phạm mạng tại Việt Nam đang có xu hướng dịch chuyển mạnh mẽ từ các phương thức tấn công kỹ thuật thuần túy sang **thao túng tâm lý xã hội (Social Engineering)** kết hợp công nghệ trí tuệ nhân tạo (AI).

### 2. Phân loại 5 nhóm thủ đoạn trọng điểm
1. **Mạo danh cơ quan công quyền**: Giả danh Công an, Viện kiểm sát, Tòa án, Cục Thuế, Bảo hiểm Xã hội gọi điện đe dọa liên quan án ma túy, trốn thuế hoặc hướng dẫn kích hoạt tài khoản định danh điện tử VNeID giả.
2. **Lừa đảo công nghệ cao (Deepfake/AI Voice)**: Thu thập video, hình ảnh công khai trên mạng xã hội rồi tạo video call giả dạng khuôn mặt và giọng nói của người thân để vay tiền gấp.
3. **Bẫy tài chính & Tuyển dụng cộng tác viên**: Tuyển việc làm online giật đơn hàng sàn thương mại điện tử, mời gọi tham gia các sàn đầu tư chứng khoán, ngoại hối quốc tế với cam kết sinh lời 20 - 30%/tháng.
4. **Lừa đảo thương mại điện tử**: Phát tán tin nhắn trúng thưởng, gửi bưu phẩm đơn hàng 0 đồng (COD), sử dụng biên lai chuyển tiền Photoshop giả mạo để chiếm đoạt hàng hóa.
5. **Đánh cắp danh tính & Chiếm quyền thiết bị**: Dụ dỗ người dùng cài đặt tệp `.APK` chứa mã độc gián điệp, quét mã QR dán đè tại nơi công cộng (Quishing), hoặc gửi email mạo danh ngân hàng đòi xác thực OTP.

### 3. Nguyên tắc 3 KHÔNG bảo vệ bản thân
- **KHÔNG TIN**: Không tin vào các lời đe dọa qua điện thoại hay các lời mời đầu tư lãi suất cao bất thường.
- **KHÔNG LÀM THEO**: Tuyệt đối không click link lạ, không tải app ngoài kho ứng dụng Google Play / App Store, không gửi mã OTP cho bất kỳ ai.
- **KHÔNG CHUYỂN TIỀN**: Dù bất kỳ tình huống khẩn cấp nào, hãy dừng lại 15 phút và gọi điện trực tiếp vào số máy bàn chính thống của cơ quan hoặc người thân để đối soát.""",
                    'author': user_map['chuyen_gia_an_ninh'],
                },
                {
                    'title': 'Bộ Công an triệt phá đường dây giả danh cán bộ VNeID chiếm đoạt hơn 200 tỷ đồng',
                    'category': ArticleCategory.NEWS,
                    'summary': 'Cục Cảnh sát hình sự phối hợp cùng Cục An ninh mạng và Phòng chống tội phạm công nghệ cao (A05) vừa triệt phá thành công băng nhóm tội phạm xuyên quốc gia phát tán mã độc chiếm quyền điều khiển điện thoại.',
                    'content': """### 1. Diễn biến chuyên án
Ngày 12 vừa qua, lực lượng nghiệp vụ Bộ Công an đã đồng loạt khám xét khẩn cấp 8 địa điểm tại TP.HCM, Hà Nội và Đà Nẵng, bắt giữ 24 đối tượng chủ chốt trong đường dây lừa đảo chiếm đoạt tài sản qua mạng.

Cơ quan điều tra xác định nhóm đối tượng đã sử dụng các tổng đài VoIP đặt tại nước ngoài, sử dụng sim rác và kỹ thuật giả mạo số điện thoại (Caller ID Spoofing) để gọi đến hàng chục nghìn người dân trên cả nước, tự xưng là cán bộ Công an các quận/huyện yêu cầu cập nhật căn cước công dân mức 2.

### 2. Thủ đoạn chiếm quyền điều khiển điện thoại
Khi nạn nhân đồng ý kết bạn qua Zalo hoặc Telegram, đối tượng gửi liên kết dẫn tới website giả mạo có giao diện giống hệt Cổng Dịch vụ công Quốc gia (`dichvucong-gov-vn.xyz`), hướng dẫn tải về tệp tin có tên `DichVuCong.apk`.

Sau khi cài đặt thành công, ứng dụng lập tức yêu cầu cấp quyền **Trợ năng (Accessibility Service)**. Quyền này cho phép mã độc:
- Theo dõi toàn bộ thao tác bàn phím, mật khẩu đăng nhập tài khoản ngân hàng.
- Tự động đọc nội dung màn hình và tin nhắn SMS chứa mã xác thực OTP.
- Khóa đen màn hình điện thoại vào ban đêm và tự động chuyển tiền từ tài khoản nạn nhân sang hệ thống tài khoản ngân hàng rác thu mua từ trước.

### 3. Khuyến cáo chính thức từ Cục An ninh mạng (A05)
Cơ quan Công an khẳng định:
- **Không bao giờ làm việc qua điện thoại** hay mạng xã hội để giải quyết thủ tục hành chính.
- Mọi hướng dẫn định danh điện tử VNeID đều phải thực hiện trực tiếp tại Công an phường/xã nơi cư trú.
- Người dân cần cảnh giác, tuyệt đối không cài đặt ứng dụng từ các đường link gửi qua tin nhắn chat.""",
                    'author': user_map['admin_sentinel'],
                },
                {
                    'title': 'Cảnh báo khẩn: Trạm phát sóng BTS giả mạo phát tán tin nhắn SMS Brandname ngân hàng',
                    'category': ArticleCategory.ALERT,
                    'summary': 'Cục Tần số Vô tuyến điện phối hợp cùng NCSC phát hiện nhiều vụ việc các đối tượng mang thiết bị trạm phát sóng di động giả mạo (Fake BTS) di chuyển bằng ô tô, xe máy tại các khu đô thị lớn để phát tán tin nhắn lừa đảo.',
                    'content': """### 1. Cơ chế hoạt động của trạm BTS giả
Trạm BTS giả (Fake Base Transceiver Station) là thiết bị phát sóng vô tuyến trái phép có kích thước nhỏ gọn, dễ dàng ngụy trang trong cốp xe máy hoặc ba lô ô tô. Khi kích hoạt, thiết bị này phát công suất đè lên sóng của các nhà mạng chính thức (Viettel, Vinaphone, MobiFone) và ép các thiết bị di động trong bán kính 100 - 300m kết nối vào.

Sau khi điện thoại kết nối, trạm BTS giả sẽ gửi trực tiếp các tin nhắn văn bản chèn vào đúng luồng tin nhắn chính thức của các ngân hàng thương mại lớn (SMS Brandname) như **Vietcombank, MB, Techcombank, BIDV, ACB**.

### 2. Kịch bản lừa đảo phổ biến
Nội dung tin nhắn thường có kịch bản kích động tâm lý khẩn cấp:
- *"Tai khoan cua ban da bi dang nhap tren thiet bi la tai Ha Noi. Vui long truy cap link http://vietcombank-verify.top de huy giao dich."*
- *"Quy khach duoc tang goi qua tri an 2.000.000d tu ngan hang. Bam link de nhan thuong ngay hom nay."*

Do tin nhắn nằm cùng hộp thư với các tin nhắn biến động số dư thật của ngân hàng, nhiều người dân đã mất cảnh giác, bấm vào đường dẫn và nhập mã xác thực OTP, dẫn đến việc tài khoản bị trừ sạch tiền trong tích tắc.

### 3. Dấu hiệu nhận biết và cách ứng phó
- Tin nhắn gửi từ trạm BTS giả thường đi kèm liên kết lạ có đuôi tên miền quốc tế rẻ tiền như `.top`, `.vip`, `.xyz`, `.cc` thay vì đuôi `.vn` hoặc `.com.vn`.
- Điện thoại thường bị tụt sóng từ 4G/5G xuống 2G (GSM) đột ngột trước khi nhận được tin nhắn.
- **Hành động ngay**: Tuyệt đối không click vào bất kỳ liên kết nào trong tin nhắn SMS. Hãy mở trực tiếp app ngân hàng trên điện thoại hoặc gọi tổng đài hotline chính thức in trên mặt sau thẻ ATM để kiểm tra.""",
                    'author': user_map['dang_tuan_anh'],
                },
                {
                    'title': 'Mã độc Spynote đội lốt ứng dụng Dịch vụ công: Phân tích kỹ thuật & Cách phòng tránh',
                    'category': ArticleCategory.ALERT,
                    'summary': 'Báo cáo giải mã mã độc di động từ nhóm chuyên gia an ninh mạng ShieldCall VN vạch trần cách thức mã độc Spynote chiếm quyền Accessibility và vượt qua các cơ chế phòng vệ của Android.',
                    'content': """### 1. Nguồn gốc và biến thể mã độc
Spynote là một dòng mã độc gián điệp thương mại (Trojan RAT) xuất hiện từ lâu, nhưng trong năm 2025 - 2026 đã được các nhóm tội phạm lừa đảo tại Đông Nam Á chỉnh sửa lại chuyên biệt để nhắm vào người dùng ngân hàng số tại Việt Nam.

Mã độc được đóng gói ngụy trang dưới các tên gọi phổ biến:
- `DichVuCong.apk`, `VNeID_CapNhat.apk`, `ThueDienTu.apk`, `CapNuocHN.apk`.

### 2. Các hành vi nguy hiểm khi mã độc kích hoạt
- **Keylogger**: Ghi lại toàn bộ thao tác gõ phím, mật khẩu mở khóa màn hình, mã PIN ứng dụng ngân hàng.
- **Overlay Attack**: Hiển thị một màn hình đăng nhập giả đè lên trên app ngân hàng thật khi người dùng mở ứng dụng.
- **SMS Interception**: Đọc ngầm tin nhắn mã OTP gửi về và xóa ngay tin nhắn đó khỏi hộp thư để nạn nhân không kịp nhận biết.
- **Remote Control**: Khi màn hình điện thoại tắt, mã độc tự động kích hoạt tính năng tự động chuyển tiền qua các giao thức headless.

### 3. Dấu hiệu nhận biết điện thoại đã bị nhiễm mã độc
- Điện thoại hao pin nhanh bất thường và máy nóng ngay cả khi không sử dụng.
- Lưu lượng dữ liệu mạng (4G/Wifi) tăng đột biến.
- Trong mục *Cài đặt > Hỗ trợ (Trợ năng / Accessibility)* xuất hiện dịch vụ lạ đang ở trạng thái BẬT.

### 4. Quy trình xử lý khẩn cấp khi nghi ngờ nhiễm mã độc
1. **Lập tức bật Chế độ máy bay (Airplane Mode)** hoặc tháo sim, tắt Wifi để ngắt hoàn toàn kết nối điều khiển của kẻ gian.
2. Dùng một thiết bị an toàn khác đăng nhập app ngân hàng và thực hiện **khóa tài khoản / đổi mật khẩu ngay**.
3. Thực hiện **Sao lưu dữ liệu cá nhân (ảnh, danh bạ) và Khôi phục cài đặt gốc (Factory Reset)** cho điện thoại.""",
                    'author': user_map['pham_minh_duc'],
                },
                {
                    'title': 'Quy trình 4 bước vàng ứng phó khẩn cấp trong 15 phút đầu khi lỡ chuyển tiền cho kẻ gian',
                    'category': ArticleCategory.GUIDE,
                    'summary': 'Thời gian là yếu tố quyết định cơ hội thu hồi dòng tiền. Hướng dẫn quy trình 4 bước hành động chuẩn xác được các chuyên gia khuyến nghị để chặn đứng thiệt hại.',
                    'content': """### 1. Thời khắc 15 phút vàng
Khi nạn nhân vừa bấm nút xác nhận chuyển khoản cho kẻ lừa đảo, tiền thường chưa được kẻ gian rút ra tiền mặt ngay lập tức mà sẽ qua một hệ thống tài khoản trung gian (tài khoản gom tiền). Bạn có từ **15 đến 30 phút** trước khi dòng tiền bị phân tán sang hàng chục tài khoản rác khác hoặc đổi sang tiền số (Crypto/USDT).

### 2. Quy trình 4 bước chuẩn mực
#### Bước 1: Gọi ngay đường dây nóng ngân hàng (Hotline khẩn cấp)
- Tìm số hotline chính thức in trên mặt sau thẻ ngân hàng hoặc website chính thức.
- Bấm phím chọn nhánh báo khẩn cấp hoặc gặp tổng đài viên.
- Cung cấp: Số tài khoản của bạn, số tài khoản thụ hưởng của kẻ gian, ngân hàng nhận, số tiền và mã giao dịch (FT Code).
- **Yêu cầu phong tỏa giao dịch hoặc tạm giữ tài khoản nhận tiền** với lý do nghi vấn chuyển nhầm / lừa đảo gian lận.

#### Bước 2: Bảo toàn chứng cứ kỹ thuật số
- Chụp ảnh toàn bộ màn hình biên lai chuyển tiền có đầy đủ mã giao dịch, thời gian.
- Chụp ảnh toàn bộ đoạn chat trên Zalo, Facebook, Telegram với đối tượng.
- Lưu lại số điện thoại gọi đến và đường link website mà đối tượng đã gửi.
- **Tuyệt đối không xóa tin nhắn hay chặn đối tượng ngay** để giữ nguyên lịch sử bằng chứng phục vụ điều tra.

#### Bước 3: Nộp hồ sơ tố giác tội phạm tại Cơ quan Công an
- Đến ngay Công an phường/xã nơi bạn cư trú hoặc Cơ quan Cảnh sát điều tra Công an quận/huyện.
- Nộp Đơn trình báo tố giác tội phạm kèm toàn bộ tập tài liệu chứng cứ đã in ra.
- Cơ quan điều tra sẽ phát lệnh khẩn cấp gửi Ngân hàng Nhà nước và ngân hàng thương mại để phong tỏa tài khoản thụ hưởng.

#### Bước 4: Đăng tải cảnh báo lên hệ thống ShieldCall VN
- Sử dụng tính năng Báo cáo lừa đảo trên website ShieldCall để đưa số điện thoại và số tài khoản của kẻ gian vào danh sách đen, giúp bảo vệ cộng đồng không bị mắc bẫy tương tự.""",
                    'author': user_map['do_thi_thu_trang'],
                },
                {
                    'title': 'Hướng dẫn chi tiết cài đặt và xác thực khuôn mặt sinh trắc học theo Quyết định 2345/QĐ-NHNN',
                    'category': ArticleCategory.GUIDE,
                    'summary': 'Giải đáp toàn diện về quy định bắt buộc xác thực sinh trắc học khi chuyển khoản trên 10 triệu đồng và các lưu ý bảo mật để tránh bị kẻ xấu lợi dụng.',
                    'content': """### 1. Quyết định 2345/QĐ-NHNN có ý nghĩa gì?
Kể từ ngày 01/07/2024, Ngân hàng Nhà nước Việt Nam bắt buộc áp dụng biện pháp xác thực sinh trắc học (khuôn mặt khớp với dữ liệu thẻ Căn cước công dân gắn chip) đối với:
- Giao dịch chuyển tiền trên **10.000.000 VNĐ** trong một lần.
- Tổng giá trị giao dịch chuyển tiền vượt quá **20.000.000 VNĐ** trong một ngày.
- Lần đầu tiên đăng nhập ứng dụng Mobile Banking trên một thiết bị mới.

Biện pháp này đã tạo ra một lá chắn thép, triệt tiêu triệt để việc tội phạm mua bán tài khoản ngân hàng rác của sinh viên để nhận tiền lừa đảo, bởi kẻ gian không thể vượt qua bước quét khuôn mặt sống (Liveness Detection) khớp với Bộ Công an.

### 2. Các bước cập nhật sinh trắc học an toàn tại nhà
1. Chuẩn bị thẻ CCCD gắn chip và điện thoại có hỗ trợ NFC.
2. Mở ứng dụng ngân hàng chính thức, chọn mục *Cài đặt > Cập nhật thông tin sinh trắc học*.
3. Chụp mặt trước và mặt sau thẻ CCCD theo khung hướng dẫn.
4. Áp phần chip của thẻ CCCD vào vị trí đầu đọc NFC ở lưng điện thoại cho đến khi máy rung lên và thông báo quét thành công.
5. Đưa khuôn mặt vào vòng tròn nhận diện để quét hình ảnh sống.

### 3. Cảnh báo các chiêu trò lừa đảo 'hỗ trợ cài sinh trắc học'
Nhiều đối tượng đã lợi dụng việc người dân gặp khó khăn khi quét chip NFC để gọi điện, tự xưng nhân viên ngân hàng hỗ trợ kích hoạt sinh trắc học từ xa qua link lạ:
- **Lưu ý tối thượng**: Ngân hàng **KHÔNG BAO GIỜ** hỗ trợ cài đặt sinh trắc học qua Zalo hay cuộc gọi video.
- Nếu không tự quét được tại nhà, người dân chỉ cần mang thẻ CCCD ra trực tiếp quầy giao dịch của ngân hàng để được nhân viên hỗ trợ miễn phí.""",
                    'author': user_map['dinh_quang_huy'],
                },
                {
                    'title': 'Hành trình 30 ngày lật tẩy bẫy đầu tư sàn Forex ảo đa cấp và bài học đắt giá',
                    'category': ArticleCategory.STORY,
                    'summary': 'Câu chuyện có thật từ một nhà đầu tư cá nhân về cách các đường dây lừa đảo tài chính quốc tế xây dựng kịch bản tâm lý, mồi chài nạn nhân từ vài triệu đồng đến hàng tỷ đồng.',
                    'content': """### 1. Lời mời kết bạn định mệnh
Đầu tháng trước, tôi nhận được lời mời kết bạn từ một phụ nữ có hình ảnh đại diện thanh lịch, giới thiệu là chuyên gia phân tích tài chính tại Singapore. Sau vài tuần trò chuyện hỏi thăm cuộc sống gia đình để tạo niềm tin, cô ấy bắt đầu khoe các lệnh giao dịch ngoại hối có lợi nhuận khủng trên một sàn giao dịch có tên `acm-fx-global.cc`.

### 2. Kịch bản thao túng tâm lý 3 giai đoạn
#### Giai đoạn 1: Mồi nhử nạp thử và cho rút tiền thật
Tôi nạp thử 5 triệu đồng. Sau 2 ngày theo lệnh của 'chuyên gia', tài khoản hiển thị lãi 1,2 triệu đồng. Tôi thử đặt lệnh rút tiền và chỉ trong 5 phút, 6,2 triệu đồng đã về đúng tài khoản ngân hàng của tôi. Bước này đã phá vỡ hoàn toàn sự phòng bị của tôi.

#### Giai đoạn 2: Kích thích lòng tham và nạp số tiền lớn
Sau khi thấy rút được tiền dễ dàng, tôi được mời vào nhóm VIP có các 'thầy' liên tục phân tích lệnh vàng và dầu thô. Tôi đã dốc toàn bộ tiền tiết kiệm 300 triệu đồng và vay mượn thêm bạn bè 200 triệu đồng để nâng gói đầu tư VIP.

#### Giai đoạn 3: Khóa tài khoản và đòi phí giải ngân
Khi tài khoản hiển thị số dư tăng lên 1,5 tỷ đồng, tôi làm lệnh rút tiền thì hệ thống báo lỗi: *"Tài khoản vi phạm quy chế giao dịch rửa tiền, yêu cầu nộp 20% tiền ký quỹ (300 triệu đồng) để mở khóa"*. Khi tôi nói không còn tiền, đối tượng lập tức xóa nhóm Telegram và chặn mọi liên lạc.

### 3. Bài học đắt giá cho mọi người
- Tất cả các sàn Forex, sàn quyền chọn nhị phân (BO) quốc tế chào mời tại Việt Nam đều là **sàn ảo không được pháp luật cấp phép**.
- Toàn bộ đồ thị nến xanh đỏ và số dư tài khoản đều được các đối tượng điều khiển bằng phần mềm nội bộ (MT4/MT5 lậu).
- Tiền nạp vào chuyển vào tài khoản cá nhân của kẻ gian, không hề có dòng tiền nào đi ra thị trường quốc tế.""",
                    'author': user_map['phan_thanh_tung'],
                },
                {
                    'title': "Lời kể của nạn nhân suýt mất 500 triệu vì cuộc gọi Deepfake video 'con đang cấp cứu'",
                    'category': ArticleCategory.STORY,
                    'summary': 'Chia sẻ từ cô Nguyễn Thu Hương về khoảnh khắc thót tim khi nhận cuộc gọi video AI mạo danh bác sĩ bệnh viện và hình ảnh con trai nằm trên giường bệnh đòi chuyển tiền mổ khẩn cấp.',
                    'content': """### 1. Cuộc gọi lúc giữa trưa
Vào lúc 11h30 trưa thứ Ba tuần trước, tôi nhận được cuộc gọi từ số lạ tự xưng là Bác sĩ Trưởng khoa Cấp cứu Bệnh viện Chợ Rẫy. Người này nói con trai tôi đang đi công tác tại TP.HCM thì bị tai nạn giao thông nghiêm trọng, đang bất tỉnh và cần mổ gấp, yêu cầu gia đình chuyển ngay 500 triệu đồng tiền viện phí và thiết bị phẫu thuật.

### 2. Đoạn video call Deepfake tinh vi
Khi tôi hoảng loạn khóc lóc yêu cầu được nhìn thấy con, đối tượng lập tức gọi video qua Zalo. Trên màn hình chập chờn xuất hiện hình ảnh con trai tôi đang nằm trên cáng bệnh viện, đầu băng bó, miệng cử động thì thào: *"Mẹ ơi cứu con... chuyển tiền cho bác sĩ gấp..."*. Đoạn video chỉ kéo dài đúng 6 giây rồi tắt phụt với lý do đang đẩy vào phòng mổ vô trùng.

### 3. Cú quay đầu nhờ nguyên tắc xác minh độc lập
Trong lúc tay run lẩy bẩy chuẩn bị mở app ngân hàng chuyển tiền vào số tài khoản cá nhân mang tên *NGUYEN DUC PHAT* mà đối tượng gửi, may mắn thay người hàng xóm sang chơi đã kịp thời giữ tay tôi lại. 

Anh hàng xóm đã gọi điện thoại trực tiếp vào số di động cá nhân của con trai tôi. Chỉ sau 3 hồi chuông, con trai tôi nhấc máy và ngạc nhiên cho biết đang ngồi ăn cơm trưa với đồng nghiệp tại văn phòng công ty ở Hà Nội, hoàn toàn khỏe mạnh.

### 4. Lời khuyên chân thành gửi tới các bậc phụ huynh
- Tội phạm mạng hiện nay thu thập thông tin gia đình, trường học, nơi làm việc của con cái bạn từ chính các bài đăng khoe ảnh trên Facebook.
- Các bệnh viện chính thống **không bao giờ yêu cầu chuyển tiền viện phí vào tài khoản cá nhân** của bác sĩ qua điện thoại.
- Trong mọi tình huống khẩn cấp, hãy giữ bình tĩnh và liên hệ trực tiếp với người thân qua số điện thoại thường dùng.""",
                    'author': user_map['nguyen_thu_huong'],
                },
                {
                    'title': 'Lá chắn an toàn số cho người cao tuổi: 5 nguyên tắc con cháu cần hướng dẫn cha mẹ',
                    'category': ArticleCategory.INCLUSIVE,
                    'summary': 'Người cao tuổi là nhóm đối tượng dễ bị tổn thương nhất trên không gian mạng do ít cập nhật công nghệ. Cẩm nang giúp gia đình đồng hành bảo vệ người lớn tuổi.',
                    'content': """### 1. Vì sao người cao tuổi là mục tiêu hàng đầu của tội phạm mạng?
- Người lớn tuổi thường có tâm lý lo sợ khi bị đe dọa liên quan đến pháp luật hoặc chính quyền.
- Họ tích lũy được số tiền tiết kiệm dưỡng già và thường ở nhà một mình trong giờ hành chính khi con cháu đi làm.
- Khả năng phân biệt các giao diện giả mạo, đầu số ảo hoặc thủ đoạn công nghệ của người già còn hạn chế.

### 2. Năm nguyên tắc vàng bảo vệ cha mẹ
1. **Thiết lập hạn mức chuyển tiền thấp**: Cài đặt hạn mức giao dịch chuyển khoản trên điện thoại của cha mẹ ở mức an toàn (ví dụ: tối đa 5 - 10 triệu đồng/ngày). Khi cần giao dịch lớn, con cái sẽ hỗ trợ thực hiện.
2. **Kích hoạt tính năng chặn cuộc gọi rác**: Cài đặt ứng dụng ShieldCall VN hoặc kích hoạt tính năng chặn cuộc gọi từ số lạ ngoài danh bạ trên điện thoại của người lớn tuổi.
3. **Quy tắc cuộc gọi vàng**: Thống nhất với cha mẹ rằng bất cứ khi nào có ai gọi điện yêu cầu chuyển tiền, đòi nộp tiền phạt viễn thông, tiền điện nước hay xưng danh công an, cha mẹ phải **gác máy ngay và gọi điện cho con cái để hỏi ý kiến**.
4. **Không lưu mật khẩu thẻ vào sổ tay hoặc ốp lưng điện thoại**: Hướng dẫn cha mẹ cách bảo quản mã PIN thẻ ATM và thông tin tài khoản an toàn.
5. **Thường xuyên trò chuyện và cập nhật thông tin**: Thay vì trách móc khi cha mẹ nhẹ dạ, hãy dành thời gian cuối tuần kể cho cha mẹ nghe về các thủ đoạn lừa đảo mới đang diễn ra trên bản tin thời sự.""",
                    'author': user_map['hoang_kim_ngan'],
                },
                {
                    'title': 'Vượt qua khủng hoảng tâm lý sau khi bị lừa đảo tài chính trực tuyến',
                    'category': ArticleCategory.EMPATHY,
                    'summary': 'Bên cạnh thiệt hại tài chính, cú sốc tâm lý và cảm giác tội lỗi, tự trách bản thân là rào cản lớn nhất của nạn nhân lừa đảo. Chia sẻ góc nhìn thấu cảm và hướng phục hồi.',
                    'content': """### 1. Cú sốc vô hình sau khi mất tiền
Nhiều nạn nhân sau khi bị lừa đảo trực tuyến rơi vào trạng thái hoảng loạn, mất ngủ, trầm cảm và thậm chí có ý nghĩ tiêu cực. Họ bị ám ảnh bởi câu hỏi: *"Tại sao một người có học thức, cẩn thận như mình lại có thể bị lừa một cách ngớ ngẩn như vậy?"*.

Sự thật là: **Bạn không ngớ ngẩn!** Bạn đã phải đối đầu với một tổ chức tội phạm chuyên nghiệp với hàng trăm con người được đào tạo bài bản về tâm lý học hành vi, kịch bản thao túng được tinh chỉnh hàng nghìn lần để khai thác nỗi sợ hãi hoặc lòng trắc ẩn của con người.

### 2. Các bước chữa lành và vượt qua khủng hoảng
#### Bước 1: Ngừng tự trách bản thân
Hãy chấp nhận sự thật rằng điều tồi tệ đã xảy ra và bạn là nạn nhân của tội phạm, không phải là người có lỗi. Hãy tự tha thứ cho bản thân vì sự mất mát đó.

#### Bước 2: Chia sẻ với người đáng tin cậy
Sự im lặng và cô lập chính là mảnh đất màu mỡ cho sự suy sụp tinh thần. Hãy tâm sự với người thân, bạn bè thân thiết hoặc chuyên gia tâm lý để giải tỏa gánh nặng cảm xúc.

#### Bước 3: Cảnh giác trước bẫy lừa đảo lần hai
Rất nhiều nạn nhân vì quá nóng vội muốn lấy lại tiền đã tìm đến các trang web, fanpage quảng cáo *"Dịch vụ luật sư thu hồi tiền lừa đảo treo", "Hacker hỗ trợ lấy lại tiền đã chuyển"*. Đây 100% là các bẫy lừa đảo bồi thêm của chính các nhóm tội phạm nhằm bòn rút nốt số tiền còn lại của nạn nhân.

#### Bước 4: Chuyển hóa đau thương thành hành động tích cực
Nhiều thành viên trên diễn đàn ShieldCall VN sau khi gặp sự cố đã trở thành những cộng tác viên tích cực nhất, chia sẻ trải nghiệm của mình để giúp hàng nghìn người khác không rơi vào hoàn cảnh tương tự. Bảo vệ người khác cũng chính là cách tốt nhất để chữa lành cho chính mình.""",
                    'author': user_map['chuyen_gia_an_ninh'],
                },
            ]

            created_articles = []
            for a_idx, a_data in enumerate(articles_data):
                art, _ = Article.objects.get_or_create(
                    title=a_data['title'],
                    defaults={
                        'category': a_data['category'],
                        'summary': a_data['summary'],
                        'content': a_data['content'],
                        'author': a_data['author'],
                        'is_published': True,
                    }
                )
                created_articles.append(art)

                # Add 2 comments per article
                c1, _ = ArticleComment.objects.get_or_create(
                    article=art,
                    author=user_map['nguyen_van_an'],
                    defaults={'content': 'Bài viết rất hữu ích và chi tiết! Mong ban quản trị tiếp tục cập nhật các thủ đoạn mới để người dân cùng cảnh giác.'}
                )
                ArticleComment.objects.get_or_create(
                    article=art,
                    author=user_map['tran_thi_mai'],
                    defaults={'content': 'Đọc bài này mới thấy bọn lừa đảo giờ quá bài bản. Em đã gửi link bài viết cho bố mẹ ở quê đọc rồi ạ.'}
                )
                # Add reactions
                ArticleReaction.objects.get_or_create(
                    user=user_map['le_hoang_nam'],
                    article=art,
                    defaults={'reaction_type': LearnReactionType.HELPFUL}
                )
                ArticleReaction.objects.get_or_create(
                    user=user_map['vu_quoc_viet'],
                    article=art,
                    defaults={'reaction_type': LearnReactionType.LIKE}
                )

            # ──────────────────────────────────────────────────────────────────
            # 3. COMMUNITY FORUM (16 Detailed Discussion Topics)
            # ──────────────────────────────────────────────────────────────────
            self.stdout.write("3. Khởi tạo 16 chủ đề diễn đàn cộng đồng & thảo luận đa cấp...")
            forum_data = [
                # --- WARNING CATEGORY ---
                {
                    'author': user_map['chuyen_gia_an_ninh'],
                    'title': 'Cảnh báo khẩn: Chiến dịch phát tán mã độc VNeID giả mạo qua Zalo chiếm quyền trợ năng Android',
                    'category': ForumCategory.WARNING,
                    'is_pinned': True,
                    'content': """Kính gửi toàn thể cộng đồng ShieldCall VN,

Trong 48 giờ qua, hệ thống ghi nhận hàng loạt người dân nhận được cuộc gọi từ các số điện thoại lạ tự xưng là Cảnh sát khu vực hoặc cán bộ Đội Cảnh sát QLHC về TTXH Công an quận, yêu cầu:
1. Hướng dẫn 'kích hoạt định danh điện tử mức 2' hoặc 'sửa lỗi sai lệch quê quán trên cơ sở dữ liệu dân cư'.
2. Gửi đường link kết bạn qua Zalo và gửi file có đuôi `.apk` (ví dụ: `dichvucong.apk`, `vneid_update.apk`).

⚠️ **CẢNH BÁO KỸ THUẬT NGUY HIỂM**:
File APK này sau khi cài đặt sẽ lừa người dùng bật quyền **Trợ năng (Accessibility Service)**. Khi quyền này được kích hoạt, mã độc sẽ tự động đọc trộm màn hình, ghi lại thao tác gõ mật khẩu ngân hàng, đánh cắp mã OTP và tự động chuyển sạch tiền trong tài khoản vào lúc nửa đêm khi bạn đang ngủ.

Công an chỉ hướng dẫn làm thủ tục trực tiếp tại trụ sở Công an phường/xã. Tuyệt đối KHÔNG tải file APK từ bất kỳ ai trên mạng xã hội!""",
                    'comments': [
                        ('nguyen_van_an', 'Mẹ em ở quê vừa hôm qua nhận được cuộc gọi y hệt thế này, may mà em đã dặn trước nên bà cúp máy ngay lập tức!'),
                        ('chuyen_gia_an_ninh', 'Rất mừng vì gia đình bạn đã cảnh giác kịp thời! Hãy tiếp tục chia sẻ cho hàng xóm và người thân nhé.'),
                        ('le_hoang_nam', 'Em dùng Android thấy khi bật quyền Accessibility hệ thống có cảnh báo đỏ mà nhiều người vẫn bấm cho qua vì bị thao túng tâm lý.'),
                    ]
                },
                {
                    'author': user_map['le_hoang_nam'],
                    'title': 'Phát hiện mã VietQR bị dán đè tại chuỗi quán cà phê và quán ăn khu vực Cầu Giấy',
                    'category': ForumCategory.WARNING,
                    'is_pinned': False,
                    'content': """Trưa nay em đi ăn trưa tại một quán phở trên đường Trần Thái Tông. Lúc ra bàn quét mã VietQR dán trên mica để chuyển tiền thanh toán bát phở 50k, em để ý thấy tên chủ tài khoản hiện lên là *LE VAN DUC* thay vì tên chị chủ quán là *NGUYEN THI HOA*.

Em hỏi lại chị chủ thì mới tá hỏa: Mã QR của quán đã bị kẻ gian dán đè một lớp decal mỏng in mã QR khác lên trên từ lúc nào không hay!

Mọi người quét mã thanh toán ở hàng quán công cộng nhớ:
1. Luôn dùng tay sờ mép mã QR xem có bị cộm hay dán đè không.
2. Kiểm tra chính xác Tên chủ tài khoản thụ hưởng hiển thị trên app ngân hàng trước khi bấm Chuyển tiền!""",
                    'comments': [
                        ('dinh_quang_huy', 'Chiêu này gọi là Quishing vật lý. Các chủ quán nên dùng biển mica đúc liền hoặc kiểm tra lại mã QR đầu mỗi ca làm việc.'),
                        ('bui_van_thanh', 'Nhiều quán giờ bật loa thông báo nhận tiền tự động, khách chuyển mà loa không báo là biết ngay có biến.'),
                    ]
                },
                {
                    'author': user_map['dang_tuan_anh'],
                    'title': 'Cảnh giác tin nhắn SMS giả mạo Cục CSGT thông báo phạt nguội giao thông kèm link độc',
                    'category': ForumCategory.WARNING,
                    'is_pinned': False,
                    'content': """Hôm qua số điện thoại của tôi nhận được tin nhắn từ đầu số di động rác: *"Cuc Canh sat Giao thong thong bao phuong tien BKS 29A-xxxxx vi pham loi toc do. Vui long tra cuu va nop phat tai http://csgt-tracuuphatnguoi.top truoc ngay 20/09 de tranh bi tich thu bang lai."*

Khi tôi dùng máy ảo phân tích liên kết trên thì thấy trang web yêu cầu nhập họ tên, số CCCD và thông tin thẻ tín dụng/ngân hàng để nộp phạt trực tuyến.

**Lưu ý**: Cục CSGT chỉ gửi thông báo phạt nguội bằng văn bản giấy qua bưu điện hoặc người dân tự tra cứu trên Cổng thông tin điện tử Cục CSGT (`csgt.vn`), không bao giờ gửi tin nhắn SMS đe dọa nộp phạt trực tuyến qua link lạ.""",
                    'comments': [
                        ('do_thi_thu_trang', 'Đúng rồi anh, theo quy định pháp luật hiện hành cơ quan chức năng không gửi tin nhắn phạt nguội qua SMS cá nhân.'),
                        ('ngoc_anh_cyber', 'Tên miền .top này em tra cứu mới đăng ký được 2 ngày qua nhà cung cấp Namesilo.'),
                    ]
                },
                {
                    'author': user_map['bui_van_thanh'],
                    'title': 'Thủ đoạn shipper giả mạo giao bưu phẩm COD 0 đồng: Cảnh báo cho cư dân chung cư',
                    'category': ForumCategory.WARNING,
                    'is_pinned': False,
                    'content': """Mình là tài xế giao hàng công nghệ hơn 4 năm nay, gần đây thấy nở rộ thủ đoạn lừa đảo đơn hàng COD (giao hàng thu tiền hộ) rất nguy hiểm:
- Đối tượng mua thông tin đơn hàng bị lộ từ các sàn TMĐT (tên người nhận, số điện thoại, địa chỉ căn hộ).
- Chúng cho người đóng các gói hàng nhỏ bên trong chỉ có giấy vụn, kẹp tóc giá 2.000đ nhưng ghi tiền thu hộ 150.000đ - 250.000đ.
- Kẻ gian canh lúc người nhận đi làm vắng, gọi điện thoại bảo gửi lễ tân hoặc nhờ hàng xóm nhận hộ và bảo người nhận chuyển khoản.

Nhiều người vì đang bận họp nên chuyển khoản ngay mà không kiểm tra lại lịch sử đơn hàng trên app Shopee/Lazada!""",
                    'comments': [
                        ('tran_thi_mai', 'Em từng bị dính một đơn 180k y hệt thế này, bóc ra bên trong là cục xà phòng vỡ nát!'),
                        ('nguyen_thu_huong', 'Bác ở nhà hay nhận hộ con cái, đọc bài này bác sẽ dặn các cháu từ nay đơn nào chuyển tiền trước mới nhận.'),
                    ]
                },

                # --- EXPERIENCE CATEGORY ---
                {
                    'author': user_map['tran_thi_mai'],
                    'title': 'Bài học xương máu: Tôi đã suýt mất 80 triệu vì bẫy tuyển cộng tác viên giật đơn Shopee',
                    'category': ForumCategory.EXPERIENCE,
                    'is_pinned': False,
                    'content': """Hôm nay em xin viết bài chia sẻ thật về trải nghiệm suýt mất trắng số tiền dành dụm của hai vợ chồng vì tìm việc làm thêm online.

Ban đầu em thấy tin tuyển dụng trên Facebook 'Nhận đơn hàng online kiếm 200k-500k mỗi ngày tại nhà'. Em để lại số điện thoại thì được một bạn kết bạn Zalo hướng dẫn làm nhiệm vụ:
- Đơn 1: Nạp 100k -> Nhận lại 130k (rút tiền về tài khoản trong 2 phút).
- Đơn 2: Nạp 500k -> Nhận lại 650k.
- Đơn 3: Nạp 3 triệu -> Nhận lại 3,8 triệu.
- Đơn 4: Nhiệm vụ nâng cấp lên hệ thống VIP, yêu cầu nạp 25 triệu. Nạp xong thì đối tượng báo 'sai cú pháp giao dịch, hệ thống bị treo, phải nạp thêm đơn đền bù 55 triệu để mở khóa'.

Lúc đó em hoảng loạn định đi vay bạn bè để nạp nốt 55 triệu nhằm lấy lại 25 triệu ban đầu. May mắn thay chồng em về kịp, phát hiện ra và kiên quyết ngăn cản. Mất 25 triệu là bài học quá đắt, nhưng may mắn em không lún sâu vào đơn 55 triệu tiếp theo!""",
                    'comments': [
                        ('chuyen_gia_an_ninh', 'Chúc mừng bạn đã dừng lại đúng lúc! Tâm lý tiếc số tiền ban đầu (Sunk Cost Fallacy) chính là đòn bẩy tâm lý để chúng moi sạch tiền nạn nhân.'),
                        ('vu_quoc_viet', 'Các nhóm Telegram này 99 thành viên đều là tài khoản ảo của cùng một ổ nhóm tung hứng để tạo hiệu ứng đám đông.'),
                    ]
                },
                {
                    'author': user_map['nguyen_van_an'],
                    'title': 'Cách tôi lấy lại được 70 triệu đồng nhờ phong tỏa ngân hàng kịp thời trong 10 phút đầu',
                    'category': ForumCategory.EXPERIENCE,
                    'is_pinned': False,
                    'content': """Hôm thứ Sáu tuần trước, em trai tôi bị lừa chuyển 70 triệu đồng tiền cọc mua xe máy thanh lý giá rẻ trên Facebook. Vừa bấm chuyển tiền xong thì bên bán khóa trang và chặn số điện thoại.

Lúc đó em trai tôi gọi điện khóc lóc, tôi lập tức thực hiện quy trình khẩn cấp:
1. Mở app ngân hàng Vietcombank của em trai, lấy ngay **Mã giao dịch (FT Code)** và số tài khoản thụ hưởng của kẻ gian bên Techcombank.
2. Gọi thẳng vào hotline Techcombank báo khẩn cấp tài khoản nhận tiền vừa thực hiện hành vi lừa đảo chiếm đoạt tài sản có tổ chức.
3. Đồng thời ra ngay Công an phường xin giấy xác nhận đang tiếp nhận tố giác tội phạm.

Nhờ phản ứng nhanh trong vòng 10 phút, phía ngân hàng Techcombank đã kịp thời gắn cờ tạm giữ số tiền 70 triệu đồng khi kẻ gian vừa đặt lệnh chuyển sang tài khoản thứ 3! Đến nay sau khi có công văn của cơ quan công an, gia đình tôi đã làm thủ tục nhận lại được tiền.""",
                    'comments': [
                        ('do_thi_thu_trang', 'Xử lý quá chuẩn mực! Yếu tố thời gian trong 15 phút đầu tiên quyết định 90% khả năng phong tỏa dòng tiền.'),
                        ('le_hoang_nam', 'Bài viết kinh nghiệm cực kỳ giá trị, mọi người nên lưu lại quy trình này để dùng khi hữu sự.'),
                    ]
                },
                {
                    'author': user_map['do_thi_thu_trang'],
                    'title': "Cảnh giác thủ đoạn lừa đảo lần hai: 'Luật sư cam kết thu hồi 100% tiền lừa đảo treo'",
                    'category': ForumCategory.EXPERIENCE,
                    'is_pinned': False,
                    'content': """Với tư cách là một luật sư hành nghề, tôi xin cảnh báo một hiện tượng đặc biệt nhức nhối hiện nay:

Trên mạng xã hội xuất hiện hàng trăm trang fanpage có tên như: *'Văn phòng Luật sư hỗ trợ thu hồi tiền lừa đảo', 'Cục An ninh mạng hỗ trợ lấy lại tiền treo trên sàn', 'Đội ngũ IT hỗ trợ can thiệp dòng tiền'*.

Các trang này sử dụng hình ảnh thật của các luật sư uy tín hoặc phù hiệu công an, chạy quảng cáo nhắm vào những người vừa bị mất tiền. Kịch bản của chúng:
1. Cam kết lấy lại được 80 - 100% số tiền đã bị lừa đảo trong vòng 24 giờ.
2. Yêu cầu nạn nhân gửi biên lai chuyển tiền và thông tin vụ việc.
3. Yêu cầu nạn nhân nộp **'phí hồ sơ pháp lý'** hoặc **'phí cổng thanh toán quốc tế'** từ vài triệu đến vài chục triệu đồng.

**Khẳng định pháp lý**: Không có bất kỳ luật sư hay chuyên gia IT nào có khả năng tự ý 'thu hồi tiền treo' từ tài khoản người khác. Mọi biện pháp phong tỏa, thu hồi tiền bắt buộc phải thông qua Lệnh của Cơ quan điều tra và Viện kiểm sát!""",
                    'comments': [
                        ('tran_thi_mai', 'Em từng nhắn tin hỏi thử một trang như này, chúng đòi nộp trước 5 triệu tiền phí thụ lý hồ sơ.'),
                        ('chuyen_gia_an_ninh', 'Thậm chí nhiều trang còn dùng mã độc bắt nạn nhân cài app để xem tiến độ thu hồi tiền.'),
                    ]
                },
                {
                    'author': user_map['phan_thanh_tung'],
                    'title': 'Bẫy tình cảm hẹn hò (Romance Scam / Pig Butchering) dẫn dụ sang sàn Crypto lừa đảo',
                    'category': ForumCategory.EXPERIENCE,
                    'is_pinned': False,
                    'content': """Thuật ngữ quốc tế gọi đây là 'Sha Zhu Pan' (Mổ heo). Chiêu thức này rất tinh vi vì kẻ gian sẵn sàng bỏ ra từ 1 đến 3 tháng chỉ để nhắn tin tâm sự, xây dựng mối quan hệ tình cảm lãng mạn qua Tinder, Bumble, Facebook Dating:

- Đối tượng xây dựng profile là người thành đạt, lịch lãm, chia sẻ cuộc sống sang chảnh, tinh tế.
- Chúng không bao giờ hỏi vay tiền bạn trực tiếp mà chỉ khéo léo khoe việc kiếm tiền thụ động từ các hợp đồng quyền chọn tiền mã hóa ngắn hạn (DeFi Option).
- Khi bạn tò mò, chúng nhiệt tình hướng dẫn nạp 50$ - 100$ vào một sàn giao dịch phi tập trung giả mạo và cho bạn rút lãi thật.
- Khi bạn đã hoàn toàn tin tưởng và nạp số tiền lớn (vài trăm triệu đến vài tỷ), chúng sẽ đánh sập sàn hoặc báo lỗi khóa tài khoản.

Đừng bao giờ tin những lời hứa hẹn làm giàu từ những người bạn quen qua mạng mà chưa từng gặp mặt ngoài đời thực!""",
                    'comments': [
                        ('vu_quoc_viet', 'Đặc điểm chung của các sàn này là tên miền đăng ký chưa quá 3 tháng và chạy trên máy chủ đám mây không định danh.'),
                        ('hoang_kim_ngan', 'Nhiều bạn trẻ tâm lý cô đơn rất dễ ngã vào bẫy này vì đối tượng nói chuyện cực kỳ tâm lý và kiên nhẫn.'),
                    ]
                },

                # --- QUESTION CATEGORY ---
                {
                    'author': user_map['nguyen_thu_huong'],
                    'title': 'Nhận cuộc gọi đe dọa bắt tạm giam từ số điện thoại bàn đầu 024... có phải lừa đảo không?',
                    'category': ForumCategory.QUESTION,
                    'is_pinned': False,
                    'content': """Chào các cháu chuyên gia,

Sáng nay bác nhận được cuộc gọi từ số `024.71098822`. Một người tự xưng là cán bộ Cơ quan Cảnh sát điều tra Bộ Công an nói bác đứng tên mở tài khoản ngân hàng liên quan đến đường dây rửa tiền ma túy 50 tỷ ở Đà Nẵng, đe dọa chiều nay sẽ có lệnh bắt tạm giam bác 4 tháng để phục vụ điều tra.

Bác là giáo viên về hưu cả đời chưa từng vi phạm gì, nghe vậy bác hoang mang lo lắng quá huyết áp tăng vọt. Họ bảo nếu muốn chứng minh trong sạch thì chiều nay phải ra ngân hàng rút sổ tiết kiệm chuyển vào tài khoản tạm giữ của cơ quan điều tra. Cho bác hỏi đây có phải lừa đảo không?""",
                    'comments': [
                        ('do_thi_thu_trang', 'Bác yên tâm 100% đây là lừa đảo ạ! Cơ quan công an làm việc theo quy định tố tụng hình sự phải gửi giấy triệu tập hoặc giấy mời thông qua Cảnh sát khu vực, tuyệt đối không làm việc qua điện thoại và không bao giờ yêu cầu công dân chuyển tiền!'),
                        ('chuyen_gia_an_ninh', 'Bác hãy chặn số điện thoại này ngay và tuyệt đối không ra ngân hàng rút tiền nhé bác.'),
                        ('nguyen_van_an', 'Bác cứ bình tĩnh uống nước nghỉ ngơi, bọn cháu đã báo cáo số này lên hệ thống ShieldCall rồi ạ.'),
                    ]
                },
                {
                    'author': user_map['le_hoang_nam'],
                    'title': 'Đã lỡ bấm vào đường link lạ nhưng chưa cài đặt file APK thì có bị mất tiền không?',
                    'category': ForumCategory.QUESTION,
                    'is_pinned': False,
                    'content': """Em chào các anh chị,

Hôm qua em có nhận được tin nhắn tuyển dụng và lỡ tay bấm vào đường link `tuyendung-ctv-tiktok.vip`. Trình duyệt Chrome trên điện thoại có mở ra một trang web yêu cầu tải file `TikTok_Job.apk`.

Lúc trình duyệt hỏi *"Tệp này có thể gây hại cho thiết bị của bạn, bạn có muốn tải xuống không?"* thì em đã giật mình bấm **Hủy (Cancel)** và đóng tab trình duyệt ngay, chưa tải file và chưa nhập bất kỳ thông tin nào.

Em muốn hỏi trong trường hợp này thì điện thoại của em có bị cài cắm mã độc ngầm hay có nguy cơ bị trừ tiền tài khoản ngân hàng không ạ?""",
                    'comments': [
                        ('pham_minh_duc', 'Chào em, trên hệ điều hành Android hiện đại, nếu em chỉ mới truy cập website và chưa tải/cài đặt file APK (chưa cấp quyền Cài đặt ứng dụng không rõ nguồn gốc) thì điện thoại hoàn toàn an toàn em nhé. Em chỉ cần vào Cài đặt Chrome > Xóa dữ liệu duyệt web và cookie là yên tâm.'),
                        ('ngoc_anh_cyber', 'Em kiểm tra thêm trong thư mục Download của máy xem có file apk nào tải dở không, nếu có thì xóa hẳn đi là được.'),
                    ]
                },
                {
                    'author': user_map['bui_van_thanh'],
                    'title': 'Làm thế nào để kiểm tra một số tài khoản ngân hàng có nằm trong danh sách đen trước khi giao dịch?',
                    'category': ForumCategory.QUESTION,
                    'is_pinned': False,
                    'content': """Các bác cho em hỏi, em làm nghề buôn bán xe máy cũ online, thường xuyên phải nhận cọc và giao dịch chuyển khoản với khách lạ ở các tỉnh.

Làm thế nào để trước khi chuyển tiền đặt cọc hoặc giao dịch, em có thể kiểm tra xem số tài khoản của người nhận đã từng bị ai tố cáo lừa đảo trên mạng hay chưa ạ? Có công cụ nào tra cứu nhanh và miễn phí không?""",
                    'comments': [
                        ('admin_sentinel', 'Chào bạn Thành, bạn có thể sử dụng ngay tính năng [Tra cứu STK Ngân hàng](/scan/account/) trên ShieldCall VN. Hệ thống kết nối cơ sở dữ liệu đối soát gian lận toàn quốc, chỉ cần nhập tên ngân hàng và số tài khoản là kiểm tra được ngay độ rủi ro.'),
                        ('vu_quoc_viet', 'Ngoài ra bạn có thể kiểm tra thêm số điện thoại của họ trên mục Quét số điện thoại để xem có phải số sim rác mới kích hoạt không.'),
                    ]
                },
                {
                    'author': user_map['tran_thi_mai'],
                    'title': 'Bị kẻ xấu trên mạng ghép mặt vào clip nhạy cảm tống tiền thì phải xử lý thế nào?',
                    'category': ForumCategory.QUESTION,
                    'is_pinned': False,
                    'content': """Bạn thân của em vừa gặp tình huống cực kỳ khủng khiếp: Bạn ấy nhận được tin nhắn từ tài khoản ẩn danh trên Telegram gửi hình ảnh và video nhạy cảm bị ghép khuôn mặt của bạn ấy bằng công nghệ Deepfake AI.

Đối tượng đe dọa nếu không chuyển 30 triệu đồng vào tài khoản của chúng thì trong 24 giờ tới sẽ gửi video này cho toàn bộ danh bạ bạn bè trên Facebook và ban giám đốc công ty nơi bạn ấy đang làm việc.

Bạn em đang rất sợ hãi và quẫn trí định đi vay tiền chuyển cho chúng. Xin các luật sư và chuyên gia cho lời khuyên gấp ạ!""",
                    'comments': [
                        ('do_thi_thu_trang', 'TUYỆT ĐỐI KHÔNG CHUYỂN TIỀN! Hãy nhớ rằng tội phạm tống tiền sẽ không bao giờ dừng lại sau lần chuyển tiền đầu tiên. Ngay lập tức chụp lại toàn bộ màn hình tin nhắn tống tiền, số tài khoản đòi tiền, sau đó làm đơn tố giác khẩn cấp gửi Cơ quan CSĐT Công an quận/huyện nơi cư trú (Tội Cưỡng đoạt tài sản theo Điều 170 BLHS).'),
                        ('chuyen_gia_an_ninh', 'Đồng thời hãy chủ động đăng một bài viết cảnh báo trên trang cá nhân rằng đang bị kẻ xấu sử dụng công nghệ Deepfake cắt ghép hình ảnh nhằm bôi nhọ tống tiền. Khi bạn công khai trước, đòn bẩy đe dọa của kẻ tống tiền sẽ bị vô hiệu hóa hoàn toàn.'),
                    ]
                },

                # --- DISCUSSION CATEGORY ---
                {
                    'author': user_map['dinh_quang_huy'],
                    'title': 'Đánh giá thực tế: Sinh trắc học khuôn mặt theo QĐ 2345 đã làm giảm các vụ lừa đảo tài khoản như thế nào?',
                    'category': ForumCategory.DISCUSSION,
                    'is_pinned': False,
                    'content': """Sau hơn nửa năm triển khai bắt buộc xác thực sinh trắc học khuôn mặt đối với các giao dịch chuyển tiền trên 10 triệu đồng, theo số liệu từ Hiệp hội Ngân hàng Việt Nam (VNBA), số vụ việc gian lận chiếm đoạt tài khoản thanh toán đã giảm hơn 50%.

Trước đây, tội phạm mạng chỉ cần mua tài khoản ngân hàng rác với giá 500k - 1 triệu đồng là có thể nhận tiền và tẩu tán tức thì. Hiện nay, kẻ gian không thể chuyển số tiền lớn nếu không có khuôn mặt sống của chính chủ khớp với cơ sở dữ liệu thẻ CCCD gắn chip của Bộ Công an.

Tuy nhiên, các đối tượng cũng đang chuyển hướng thủ đoạn:
1. Chia nhỏ giao dịch dưới 10 triệu đồng (ví dụ chuyển nhiều lần 9.900.000đ).
2. Lừa nạn nhân cài mã độc chiếm quyền điều khiển để thực hiện thao tác quét mặt trực tiếp trên máy nạn nhân.

Mời các chuyên gia và anh em trong ngành cùng thảo luận về các giải pháp tiếp theo!""",
                    'comments': [
                        ('chuyen_gia_an_ninh', 'Chính xác! Hiện tại các ngân hàng đang tiếp tục áp dụng ngưỡng tổng giao dịch 20 triệu/ngày để chặn việc chia nhỏ lệnh chuyển.'),
                        ('vu_quoc_viet', 'Đồng thời các giải pháp AI phát hiện hành vi bất thường (Behavioral Analytics) như đổi thiết bị, giao dịch vào khung giờ 2h-4h sáng đang được tích hợp mạnh.'),
                    ]
                },
                {
                    'author': user_map['vu_quoc_viet'],
                    'title': 'Tại sao các ổ nhóm lừa đảo quốc tế đặc biệt ưa chuộng đầu số tổng đài ảo VoIP 024/028/077?',
                    'category': ForumCategory.DISCUSSION,
                    'is_pinned': False,
                    'content': """Trong quá trình phân tích dữ liệu hơn 10.000 số điện thoại spam/scam được cộng đồng gửi về ShieldCall, chúng tôi nhận thấy có tới 68% cuộc gọi lừa đảo xuất phát từ các dải đầu số dịch vụ VoIP:

1. **Đầu số mã vùng cố định TP.HCM và Hà Nội** (như `024.710xxxxx`, `028.999xxxxx`): Tạo cảm giác trang trọng, uy tín của cơ quan nhà nước hoặc tổng đài tập đoàn lớn.
2. **Kỹ thuật Caller ID Spoofing**: Kẻ gian thuê máy chủ SIP trung gian tại Campuchia, Myanmar hoặc Philippines, sau đó dùng giao thức Asterisk để chèn số hiển thị tùy ý lên máy nạn nhân.
3. **Cước phí siêu rẻ**: Các gói cước SIP Trunking quốc tế cho phép quay số tự động (Autodialer) hàng triệu cuộc gọi mỗi ngày với chi phí chỉ vài trăm đồng một cuộc gọi.

Giải pháp căn cơ đòi hỏi các nhà mạng viễn thông phải triển khai triệt để cơ chế xác thực nguồn gốc cuộc gọi (STIR/SHAKEN) và chặn các luồng lưu lượng thoại quốc tế giả mạo đầu số nội địa.""",
                    'comments': [
                        ('dang_tuan_anh', 'Bộ TT&TT hiện đang chỉ đạo các nhà mạng quét và siết chặt các doanh nghiệp cung cấp dịch vụ tổng đài SIP Trunking vi phạm.'),
                        ('nguyen_van_an', 'Giờ hễ thấy đầu số bàn lạ gọi đến bảo nợ tiền điện thoại hay công an là em dập máy ngay không cần nghe hết câu.'),
                    ]
                },
                {
                    'author': user_map['pham_minh_duc'],
                    'title': 'Tổng hợp các công cụ kiểm tra độ an toàn của đường link website và tệp tin dành cho người dùng phổ thông',
                    'category': ForumCategory.DISCUSSION,
                    'is_pinned': False,
                    'content': """Để trang bị cho bản thân và người thân khả năng tự phòng vệ trước các đường link độc hại, em xin tổng hợp lại danh mục các công cụ kiểm tra an toàn trực tuyến hoàn toàn miễn phí và cực kỳ hiệu quả:

1. **ShieldCall VN ([/scan/website/](/scan/website/))**: Công cụ quét chuyên biệt cho không gian mạng Việt Nam, nhận diện tên miền nhái ngân hàng (lookalike domain) và đối soát blacklist cộng đồng.
2. **VirusTotal (virustotal.com)**: Quét link hoặc tệp tin qua hơn 70 engine antivirus hàng đầu thế giới.
3. **Cổng Không gian mạng quốc gia (canhbao.khonggianmang.vn)**: Cơ sở dữ liệu chính thống của NCSC ghi nhận các website giả mạo lừa đảo người dân.
4. **URLScan.io**: Chụp ảnh màn hình sandbox trang web và kiểm tra các đoạn mã JavaScript chuyển hướng độc hại.

Mọi người có đang dùng công cụ nào khác hiệu quả không, cùng chia sẻ thêm nhé!""",
                    'comments': [
                        ('le_hoang_nam', 'Em hay kết hợp dùng thêm tiện ích mở rộng Chống Lừa Đảo trên trình duyệt Chrome, rất tiện cho người lớn tuổi.'),
                        ('ngoc_anh_cyber', 'Nên lưu lại bài này ghim lên đầu diễn đàn để ai cần là tra cứu được ngay.'),
                    ]
                },
                {
                    'author': user_map['hoang_kim_ngan'],
                    'title': 'Chiến dịch truyền thông an ninh mạng cần thay đổi: Làm sao để cảnh báo tiếp cận được giới trẻ và người cao tuổi?',
                    'category': ForumCategory.DISCUSSION,
                    'is_pinned': False,
                    'content': """Nhiều người hay nghĩ chỉ có người ít học mới bị lừa, nhưng thực tế thời gian qua có cả thạc sĩ, bác sĩ, giảng viên đại học bị lừa hàng tỷ đồng.

Vấn đề nằm ở chỗ các văn bản cảnh báo truyền thống thường quá khô khan, dài dòng và khó hiểu đối với người dân bình thường. Để thông điệp cảnh giác thực sự đi vào đời sống, chúng ta cần:
1. **Dạng thức ngắn (Short-form video)**: Sản xuất các video TikTok, Reels, Shorts mô phỏng tình huống lừa đảo kịch tính, ngắn gọn dưới 60 giây.
2. **Infographic sinh động**: Hình ảnh hóa quy trình lừa đảo thay vì những trang văn bản dày đặc chữ.
3. **Phát thanh cơ sở và hội phụ nữ**: Kênh tiếp cận trực tiếp và hiệu quả nhất đối với các bà, các mẹ ở nông thôn và tổ dân phố.

Mời các anh chị em cùng đóng góp ý tưởng để xây dựng nội dung truyền thông cho cộng đồng ShieldCall!""",
                    'comments': [
                        ('nguyen_thu_huong', 'Bác rất tán thành! Các cháu làm video ngắn dễ hiểu rồi gửi vào các nhóm Zalo gia đình là bác chia sẻ ngay cho các bạn già trong hội.'),
                        ('admin_sentinel', 'Ý tưởng rất tuyệt vời. ShieldCall VN đang chuẩn bị ra mắt chuỗi infographic cảnh giác số tuần tới.'),
                    ]
                },
            ]

            created_posts = []
            for p_idx, p_data in enumerate(forum_data):
                post, _ = ForumPost.objects.get_or_create(
                    title=p_data['title'],
                    defaults={
                        'author': p_data['author'],
                        'category': p_data['category'],
                        'content': p_data['content'],
                        'is_pinned': p_data['is_pinned'],
                        'views_count': 150 + p_idx * 35,
                        'likes_count': 10 + (p_idx * 3) % 25,
                        'helpful_count': 5 + (p_idx * 2) % 15,
                    }
                )
                created_posts.append(post)

                # Create comments
                for c_author_key, c_text in p_data.get('comments', []):
                    c_author = user_map.get(c_author_key, user_map['nguyen_van_an'])
                    ForumComment.objects.get_or_create(
                        post=post,
                        author=c_author,
                        content=c_text,
                        defaults={'likes_count': 3, 'helpful_count': 2}
                    )

                # Add likes and reactions
                ForumLike.objects.get_or_create(user=user_map['nguyen_van_an'], post=post)
                ForumLike.objects.get_or_create(user=user_map['le_hoang_nam'], post=post)
                ForumPostReaction.objects.get_or_create(
                    user=user_map['tran_thi_mai'],
                    post=post,
                    defaults={'reaction_type': ForumReactionType.HELPFUL}
                )

            # ──────────────────────────────────────────────────────────────────
            # 4. LEARN LESSONS, QUIZZES & SCENARIOS (6 Complete Cyber Courses)
            # ──────────────────────────────────────────────────────────────────
            self.stdout.write("4. Khởi tạo 6 bài học giáo dục tương tác & bộ câu hỏi kiểm tra...")
            lessons_data = [
                {
                    'title': 'Kỹ năng nhận diện và phòng chống cuộc gọi Deepfake AI',
                    'category': ArticleCategory.GUIDE,
                    'summary': 'Hướng dẫn toàn diện cách phân biệt cuộc gọi video deepfake và các biện pháp bảo vệ bản thân khi người thân hỏi mượn tiền gấp.',
                    'content': """### 1. Bản chất của công nghệ Deepfake trong lừa đảo
Deepfake là công nghệ sử dụng trí tuệ nhân tạo (AI) để hoán đổi khuôn mặt và tái tạo giọng nói của một người dựa trên các hình ảnh, video có sẵn trên mạng xã hội.

### 2. Các dấu hiệu nhận biết cuộc gọi Deepfake
- **Thời lượng cuộc gọi rất ngắn**: Thường chỉ kéo dài từ 5 - 15 giây với lý do 'đang ở chỗ mạng yếu', 'sắp hết pin'.
- **Cử động khuôn mặt thiếu tự nhiên**: Mắt chớp không đều, miệng cử động không khớp khẩu hình tiếng nói.
- **Biến dạng quang học**: Khi người gọi quay nghiêng đầu hoặc đưa tay lên mặt, viền khuôn mặt sẽ bị nhòe hoặc giật hình.

### 3. Nguyên tắc phòng thủ sống còn
- Luôn gọi lại bằng cuộc gọi mạng viễn thông thông thường vào số điện thoại thường ngày của người đó.
- Đặt câu hỏi bảo mật riêng tư mà chỉ người thân trong gia đình mới biết câu trả lời.""",
                    'quiz': {
                        'question': 'Khi nhận được cuộc gọi video từ người thân mượn tiền gấp có hình ảnh chập chờn, hành động an toàn nhất là gì?',
                        'options': [
                            {'id': 'A', 'text': 'Chuyển tiền ngay vì đã nhìn thấy mặt người thân trên màn hình.'},
                            {'id': 'B', 'text': 'Ngắt máy và gọi lại bằng cuộc gọi viễn thông thông thường hoặc hỏi câu hỏi bí mật của gia đình.'},
                            {'id': 'C', 'text': 'Chuyển trước một nửa số tiền để giúp đỡ lúc khẩn cấp.'},
                            {'id': 'D', 'text': 'Nhắn tin hỏi số tài khoản qua chính ứng dụng đó.'},
                        ],
                        'correct_answer': 'B',
                        'explanation': 'Tuyệt đối không tin vào hình ảnh video call ngắn ngủi. Cần xác minh độc lập qua cuộc gọi viễn thông hoặc câu hỏi bí mật riêng tư.',
                    },
                    'scenario': {
                        'title': 'Tình huống: Cuộc gọi video vay tiền lúc 22h đêm',
                        'description': 'Bạn nhận được cuộc gọi video Messenger từ tài khoản của bạn thân hỏi mượn 20 triệu đồng đóng viện phí.',
                        'content': {
                            'step1': {
                                'prompt': 'Bạn thân gọi video khuôn mặt hơi giật, nói mạng yếu rồi ngắt, sau đó nhắn số tài khoản ngân hàng lạ yêu cầu chuyển gấp. Bạn làm gì?',
                                'choices': [
                                    {'text': 'Chuyển khoản ngay 20 triệu.', 'next': 'fail'},
                                    {'text': 'Gọi điện thoại trực tiếp vào số thuê bao di động của bạn thân.', 'next': 'success'},
                                ]
                            },
                            'success': {'result': 'Xuất sắc! Bạn thân của bạn nghe máy và cho biết tài khoản Facebook vừa bị kẻ gian hack lúc tối.'},
                            'fail': {'result': 'Rất tiếc! Bạn đã bị sập bẫy deepfake video và mất số tiền 20 triệu đồng.'},
                        }
                    }
                },
                {
                    'title': 'Quyết định 2345/QĐ-NHNN và lá chắn Sinh trắc học tài khoản ngân hàng',
                    'category': ArticleCategory.ALERT,
                    'summary': 'Tìm hiểu tại sao xác thực khuôn mặt khớp với chip CCCD là biện pháp triệt tiêu các tài khoản ngân hàng rác lừa đảo.',
                    'content': """### 1. Quy định bắt buộc
Kể từ ngày 01/07/2024, các giao dịch chuyển tiền trên 10 triệu đồng hoặc tổng 20 triệu đồng/ngày bắt buộc phải xác thực sinh trắc học khuôn mặt.

### 2. Tác động triệt tiêu tội phạm
Quy định này buộc kẻ gian phải có khuôn mặt sống của chính chủ khớp với cơ sở dữ liệu Bộ Công an, triệt tiêu đường dây mua bán tài khoản rác của sinh viên.""",
                    'quiz': {
                        'question': 'Quy định xác thực sinh trắc học khi chuyển tiền trên 10 triệu đồng nhằm ngăn chặn điều gì?',
                        'options': [
                            {'id': 'A', 'text': 'Ngăn chặn người dân rút tiền mặt.'},
                            {'id': 'B', 'text': 'Triệt tiêu việc tội phạm dùng tài khoản ngân hàng rác mua của người khác để tẩu tán tiền lừa đảo.'},
                            {'id': 'C', 'text': 'Tăng phí chuyển khoản của các ngân hàng thương mại.'},
                            {'id': 'D', 'text': 'Làm chậm thời gian giao dịch điện tử.'},
                        ],
                        'correct_answer': 'B',
                        'explanation': 'Xác thực sinh trắc học bắt buộc chính chủ thực hiện, ngăn chặn tội phạm mạng dùng tài khoản mua bán trôi nổi.',
                    },
                },
                {
                    'title': 'Kỹ thuật phân biệt website ngân hàng thật vs website Phishing giả mạo',
                    'category': ArticleCategory.GUIDE,
                    'summary': 'Cách nhận diện tên miền nhái thương hiệu (lookalike domain), kiểm tra chứng chỉ SSL và nhận diện các giao diện thu thập mã OTP.',
                    'content': """### 1. Tên miền Lookalike là gì?
Kẻ gian đăng ký các tên miền có phát âm hoặc ký tự gần giống ngân hàng thật:
- Ví dụ ngân hàng thật: `vietcombank.com.vn`
- Tên miền giả: `vietcombank-login.top`, `vietcombank-ibanking.xyz`, `vietcombank.com.co`

### 2. Các điểm cần kiểm tra trước khi đăng nhập
1. Đuôi tên miền: Ngân hàng tại Việt Nam hầu hết sử dụng đuôi `.com.vn` hoặc `.vn`.
2. Biểu tượng ổ khóa SSL không đồng nghĩa với website an toàn: Hiện nay kẻ lừa đảo dễ dàng đăng ký chứng chỉ SSL miễn phí (Let's Encrypt).
3. Không bao giờ gõ mã OTP vào website nếu nội dung tin nhắn OTP ghi là 'xác nhận chuyển tiền' thay vì 'đăng nhập'.""",
                    'quiz': {
                        'question': 'Đặc điểm nào chứng minh một website ngân hàng là an toàn để đăng nhập?',
                        'options': [
                            {'id': 'A', 'text': 'Trang web có biểu tượng ổ khóa màu xanh lá.'},
                            {'id': 'B', 'text': 'Tên miền chính xác là tên miền chính thống của ngân hàng (ví dụ: vietcombank.com.vn), không có tiền tố hay hậu tố lạ.'},
                            {'id': 'C', 'text': 'Giao diện trang web có logo và màu sắc đẹp mắt.'},
                            {'id': 'D', 'text': 'Đường link được gửi từ tin nhắn SMS của một người quen.'},
                        ],
                        'correct_answer': 'B',
                        'explanation': 'Chỉ có tên miền chính xác (Domain name) mới là yếu tố định danh duy nhất không thể làm giả.',
                    },
                },
                {
                    'title': "Nhận diện bẫy tuyển dụng 'Việc nhẹ lương cao' và bẫy giật đơn Shopee/TikTok",
                    'category': ArticleCategory.GUIDE,
                    'summary': 'Phân tích mô hình lừa đảo cộng tác viên trực tuyến, quy luật nhử mồi thả tép bắt tôm và cách phòng tránh dứt khoát.',
                    'content': """### 1. Kịch bản thả tép bắt tôm
Các đối tượng luôn cho nạn nhân nạp số tiền nhỏ (100k - 500k) và trả lại tiền gốc kèm hoa hồng rất sòng phẳng trong 1 - 2 đơn đầu để tạo niềm tin tuyệt đối.

### 2. Giai đoạn siết bẫy
Khi nạn nhân tin tưởng và nạp số tiền lớn (hàng chục triệu đồng), hệ thống sẽ báo lỗi kỹ thuật và ép nạp thêm tiền đền bù liên tục cho đến khi nạn nhân kiệt quệ tài chính.

### 3. Nguyên tắc vàng
Không có bất kỳ công việc tuyển dụng chân chính nào lại bắt người lao động phải nộp tiền túi của mình trước để làm nhiệm vụ!""",
                    'quiz': {
                        'question': 'Khi tham gia việc làm CTV online và được yêu cầu nạp tiền để nâng cấp đơn hàng lấy lại tiền cũ, bạn nên làm gì?',
                        'options': [
                            {'id': 'A', 'text': 'Nạp thêm tiền theo yêu cầu để lấy lại số tiền đã nạp ban đầu.'},
                            {'id': 'B', 'text': 'Vay mượn bạn bè nạp nốt lần cuối rồi nghỉ.'},
                            {'id': 'C', 'text': 'Dừng lại ngay lập tức, không nạp thêm bất kỳ đồng nào và lưu lại bằng chứng tố giác công an.'},
                            {'id': 'D', 'text': 'Chia sẻ link cho bạn bè cùng làm để nhận hoa hồng giới thiệu.'},
                        ],
                        'correct_answer': 'C',
                        'explanation': 'Dừng lại ngay lập tức là cách duy nhất để cắt lỗ. Nạp thêm chắc chắn sẽ mất thêm.',
                    },
                },
                {
                    'title': 'Quishing: Mối nguy hiểm tiềm ẩn từ mã QR dán đè ở nơi công cộng',
                    'category': ArticleCategory.ALERT,
                    'summary': 'Hiểu rõ về hình thức tấn công Phishing qua mã QR (Quishing), nguy cơ bị chuyển hướng sang website giả mạo hoặc mất tiền khi quét mã tại quán ăn, cây xăng.',
                    'content': """### 1. Quishing là gì?
Quishing là từ ghép của QR Code và Phishing. Kẻ gian in các mã QR chứa liên kết độc hại và dán đè lên mã QR thanh toán của cửa hàng, quầy thu ngân hoặc biển quảng cáo công cộng.

### 2. Cách phòng ngừa hiệu quả
- Kiểm tra mép dán của mã QR trên bàn ăn.
- Trước khi bấm xác nhận chuyển tiền trên app ngân hàng, luôn ngẩng lên nhìn bảng hiệu để đối chiếu TÊN CHỦ TÀI KHOẢN thụ hưởng.""",
                    'quiz': {
                        'question': 'Bước kiểm tra quan trọng nhất trước khi bấm xác nhận chuyển tiền qua mã QR là gì?',
                        'options': [
                            {'id': 'A', 'text': 'Kiểm tra tốc độ mạng 4G.'},
                            {'id': 'B', 'text': 'Đối soát Tên chủ tài khoản thụ hưởng hiển thị trên app ngân hàng với người nhận thực tế.'},
                            {'id': 'C', 'text': 'Chụp ảnh màn hình điện thoại.'},
                            {'id': 'D', 'text': 'Quét lại mã QR lần thứ hai.'},
                        ],
                        'correct_answer': 'B',
                        'explanation': 'Tên chủ tài khoản thụ hưởng hiển thị chính xác tài khoản sẽ nhận tiền, giúp phát hiện ngay nếu mã QR bị tráo đổi.',
                    },
                },
                {
                    'title': 'Tấn công trạm BTS giả và SMS Brandname lừa đảo: Cơ chế và cách phòng vệ',
                    'category': ArticleCategory.ALERT,
                    'summary': 'Giải mã lý do vì sao tin nhắn lừa đảo lại có thể chui vào cùng một luồng tin nhắn chính thức của ngân hàng và cách phân biệt tức thì.',
                    'content': """### 1. Nguyên lý trạm BTS giả mạo
Trạm phát sóng BTS giả mạo phát sóng công suất cao ép điện thoại hạ xuống băng tần 2G (GSM không có cơ chế xác thực hai chiều) và chèn tin nhắn mang tên Brandname bất kỳ.

### 2. Cách phòng ngừa tối thượng
- Ngân hàng tại Việt Nam không bao giờ gửi link yêu cầu đăng nhập tài khoản trong tin nhắn SMS biến động số dư.
- Tuyệt đối không click vào bất kỳ đường link nào gửi kèm trong tin nhắn SMS.""",
                    'quiz': {
                        'question': 'Nếu nhận được tin nhắn SMS mang tên ngân hàng bạn đang dùng thông báo tài khoản bị khóa và gửi kèm link, bạn nên làm gì?',
                        'options': [
                            {'id': 'A', 'text': 'Click link và đăng nhập ngay để mở khóa.'},
                            {'id': 'B', 'text': 'Không click vào link trong tin nhắn; mở app ngân hàng chính thức hoặc gọi hotline kiểm tra.'},
                            {'id': 'C', 'text': 'Chuyển tiếp tin nhắn cho người thân.'},
                            {'id': 'D', 'text': 'Nhắn tin trả lời lại SMS đó.'},
                        ],
                        'correct_answer': 'B',
                        'explanation': 'Tuyệt đối không truy cập đường dẫn trong SMS. Luôn sử dụng app chính thức hoặc gọi hotline.',
                    },
                },
            ]

            for l_data in lessons_data:
                lesson, _ = LearnLesson.objects.get_or_create(
                    title=l_data['title'],
                    defaults={
                        'category': l_data['category'],
                        'summary': l_data['summary'],
                        'content': l_data['content'],
                        'is_published': True,
                    }
                )
                if 'quiz' in l_data:
                    q = l_data['quiz']
                    LearnQuiz.objects.get_or_create(
                        lesson=lesson,
                        question=q['question'],
                        defaults={
                            'question_type': QuizQuestionType.SINGLE,
                            'options': q['options'],
                            'correct_answer': q['correct_answer'],
                            'explanation': q['explanation'],
                        }
                    )
                if 'scenario' in l_data:
                    s = l_data['scenario']
                    LearnScenario.objects.get_or_create(
                        lesson=lesson,
                        title=s['title'],
                        defaults={
                            'description': s['description'],
                            'content': s['content'],
                        }
                    )

            # ──────────────────────────────────────────────────────────────────
            # 5. FRAUD BANK ACCOUNTS BLACKLIST (40+ Realistic Tracked Accounts)
            # ──────────────────────────────────────────────────────────────────
            self.stdout.write("5. Khởi tạo danh sách đen 40+ tài khoản ngân hàng gian lận...")
            bank_blacklist_data = [
                ('Vietcombank', '1029384756', 95, 24, ScamType.BANK_IMPERSONATION),
                ('Vietcombank', '998877665544', 92, 18, ScamType.POLICE_IMPERSONATION),
                ('Vietcombank', '0011004328912', 90, 15, ScamType.INVESTMENT_SCAM),
                ('Techcombank', '19038291823019', 94, 21, ScamType.INVESTMENT_SCAM),
                ('Techcombank', '19033481920192', 88, 12, ScamType.RECRUITMENT_SCAM),
                ('Techcombank', '19128394819201', 91, 16, ScamType.BANK_IMPERSONATION),
                ('MBBank', '098765432100', 96, 32, ScamType.RECRUITMENT_SCAM),
                ('MBBank', '091234567899', 89, 14, ScamType.DELIVERY_SCAM),
                ('MBBank', '888899991111', 93, 22, ScamType.POLICE_IMPERSONATION),
                ('MBBank', '034819283912', 87, 11, ScamType.LOAN_SCAM),
                ('VietinBank', '100029384756', 91, 17, ScamType.DELIVERY_SCAM),
                ('VietinBank', '103829182391', 88, 13, ScamType.BANK_IMPERSONATION),
                ('VietinBank', '107829102938', 93, 19, ScamType.INVESTMENT_SCAM),
                ('VPBank', '1582910482', 95, 28, ScamType.POLICE_IMPERSONATION),
                ('VPBank', '1928394812', 89, 14, ScamType.LOAN_SCAM),
                ('VPBank', '2048192839', 92, 18, ScamType.RECRUITMENT_SCAM),
                ('ACB', '284759281', 88, 12, ScamType.LOAN_SCAM),
                ('ACB', '391829384', 90, 15, ScamType.BANK_IMPERSONATION),
                ('ACB', '182938475', 86, 9, ScamType.DELIVERY_SCAM),
                ('BIDV', '21510002938475', 94, 23, ScamType.BANK_IMPERSONATION),
                ('BIDV', '12410003928192', 89, 13, ScamType.POLICE_IMPERSONATION),
                ('BIDV', '62110004829182', 91, 17, ScamType.INVESTMENT_SCAM),
                ('Agribank', '1500205829182', 93, 20, ScamType.POLICE_IMPERSONATION),
                ('Agribank', '2200206192839', 87, 10, ScamType.DELIVERY_SCAM),
                ('Agribank', '4900207382918', 90, 15, ScamType.LOAN_SCAM),
                ('TPBank', '03918293801', 92, 16, ScamType.RECRUITMENT_SCAM),
                ('TPBank', '04829182302', 88, 11, ScamType.OTP_STEAL),
                ('Sacombank', '060281928391', 91, 15, ScamType.BANK_IMPERSONATION),
                ('Sacombank', '070192839481', 89, 12, ScamType.INVESTMENT_SCAM),
                ('HDBank', '0817281928391', 86, 8, ScamType.DELIVERY_SCAM),
                ('SHB', '101928394812', 88, 10, ScamType.LOAN_SCAM),
                ('MSB', '03201019283948', 90, 14, ScamType.POLICE_IMPERSONATION),
                ('VIB', '04970406192839', 89, 13, ScamType.RECRUITMENT_SCAM),
                ('OCB', '0112100029384', 87, 9, ScamType.DELIVERY_SCAM),
                ('SeABank', '0000019283948', 85, 7, ScamType.OTHER),
                ('MoMo', '0912839481', 94, 25, ScamType.OTP_STEAL),
                ('MoMo', '0981726354', 91, 19, ScamType.DELIVERY_SCAM),
                ('MoMo', '0772819283', 88, 14, ScamType.RECRUITMENT_SCAM),
                ('ZaloPay', '0904819283', 90, 16, ScamType.OTHER),
                ('ViettelMoney', '0988776655', 93, 21, ScamType.POLICE_IMPERSONATION),
            ]

            bank_objs = []
            for b_name, acc_raw, r_score, rep_cnt, s_type in bank_blacklist_data:
                h = BankAccount.hash_account(acc_raw)
                m = BankAccount.mask_account(acc_raw)
                b, _ = BankAccount.objects.get_or_create(
                    bank_name=b_name,
                    account_number_hash=h,
                    defaults={
                        'account_number_masked': m,
                        'risk_score': r_score,
                        'report_count': rep_cnt,
                        'scam_type': s_type,
                    }
                )
                bank_objs.append(b)

            # ──────────────────────────────────────────────────────────────────
            # 6. COMMUNITY SCAM REPORTS (25+ Detailed Verified Reports)
            # ──────────────────────────────────────────────────────────────────
            self.stdout.write("6. Khởi tạo 25+ hồ sơ báo cáo lừa đảo thực tế...")
            reports_data = [
                {
                    'reporter': user_map['nguyen_van_an'],
                    'target_type': TargetType.ACCOUNT,
                    'target_value': 'Vietcombank: 1029384756',
                    'scam_type': ScamType.BANK_IMPERSONATION,
                    'severity': Severity.CRITICAL,
                    'description': 'Đối tượng giả danh nhân viên Vietcombank gọi điện thông báo thẻ bị trừ 15 triệu, hướng dẫn chuyển tiền vào STK 1029384756 để bảo lưu tài sản. Đã lừa của tôi 15.000.000 VNĐ.',
                    'scammer_phone': '+84898234912',
                    'scammer_bank_account': '1029384756',
                    'scammer_bank_name': 'Vietcombank',
                    'scammer_name': 'NGUYEN VAN QUYET',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Đã đối soát với blacklist ngân hàng, xác nhận tài khoản lừa đảo có tổ chức.',
                },
                {
                    'reporter': user_map['tran_thi_mai'],
                    'target_type': TargetType.PHONE,
                    'target_value': '+842471098822',
                    'scam_type': ScamType.POLICE_IMPERSONATION,
                    'severity': Severity.CRITICAL,
                    'description': 'Số điện thoại tự xưng Thiếu úy Lê Văn Long - Công an TP Hà Nội đe dọa tôi dính vào vụ án rửa tiền ma túy, yêu cầu kết bạn Zalo nhận lệnh bắt tạm giam có dấu đỏ.',
                    'scammer_phone': '+842471098822',
                    'scammer_name': 'Lê Văn Long (Giả mạo)',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Kịch bản giả mạo công an điều tra kinh điển qua tổng đài VoIP.',
                },
                {
                    'reporter': user_map['le_hoang_nam'],
                    'target_type': TargetType.DOMAIN,
                    'target_value': 'dichvucong-gov-vn.xyz',
                    'scam_type': ScamType.POLICE_IMPERSONATION,
                    'severity': Severity.CRITICAL,
                    'description': 'Trang web mạo danh Cổng dịch vụ công quốc gia, dụ dỗ người dân tải file DichVuCong.apk chứa mã độc gián điệp chiếm quyền trợ năng Android.',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Phân tích sandbox phát hiện trojan banking Spynote.',
                },
                {
                    'reporter': user_map['tran_thi_mai'],
                    'target_type': TargetType.ACCOUNT,
                    'target_value': 'MB: 098765432100',
                    'scam_type': ScamType.RECRUITMENT_SCAM,
                    'severity': Severity.HIGH,
                    'description': 'Đường dây tuyển CTV giật đơn Shopee trên Telegram. 3 đơn đầu cho rút tiền lãi 200k, đến đơn 25 triệu thì khóa rút tiền và bắt nạp thêm 30 triệu.',
                    'scammer_bank_account': '098765432100',
                    'scammer_bank_name': 'MBBank',
                    'scammer_name': 'LE MINH TUAN',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Đã ghi nhận nhiều phản ánh cùng số tài khoản.',
                },
                {
                    'reporter': user_map['nguyen_van_an'],
                    'target_type': TargetType.MESSAGE,
                    'target_value': 'SMS VIETTEL_KM Phishing',
                    'scam_type': ScamType.PHISHING,
                    'severity': Severity.HIGH,
                    'description': 'Nhận SMS mang tên VIETTEL_KM thông báo đổi 10.000 điểm lấy 500k thẻ cào, dẫn link vào viettel-diemthuong.vip để đánh cắp tài khoản ngân hàng.',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'SMS phát tán qua trạm BTS giả mạo.',
                },
                {
                    'reporter': user_map['le_hoang_nam'],
                    'target_type': TargetType.ACCOUNT,
                    'target_value': 'TCB: 19038291823019',
                    'scam_type': ScamType.INVESTMENT_SCAM,
                    'severity': Severity.CRITICAL,
                    'description': 'Sàn giao dịch vàng và ngoại hối ảo Forex cam kết sinh lời 25%/tháng. Khi yêu cầu rút vốn thì đòi nộp thuế thu nhập 10% trước.',
                    'scammer_bank_account': '19038291823019',
                    'scammer_bank_name': 'Techcombank',
                    'scammer_name': 'CT TNHH TU VAN TM DAU TU',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Pháp nhân ma, tài khoản có dấu hiệu rửa tiền xuyên quốc gia.',
                },
                {
                    'reporter': user_map['bui_van_thanh'],
                    'target_type': TargetType.PHONE,
                    'target_value': '+84981726354',
                    'scam_type': ScamType.DELIVERY_SCAM,
                    'severity': Severity.MEDIUM,
                    'description': 'Người tự xưng shipper giao đơn Shopee 180.000đ, tôi nhờ lễ tân chung cư nhận hộ và chuyển khoản xong thì mở ra bên trong chỉ có giấy vụn.',
                    'scammer_phone': '+84981726354',
                    'scammer_name': 'Shipper lừa đảo',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Lừa đảo giao đơn hàng 0 đồng (COD scam).',
                },
                {
                    'reporter': user_map['dinh_quang_huy'],
                    'target_type': TargetType.QR,
                    'target_value': 'Mã QR quishing dán đè tại quán ăn Trần Thái Tông',
                    'scam_type': ScamType.PHISHING,
                    'severity': Severity.HIGH,
                    'description': 'Mã QR thanh toán bàn ăn bị dán đè decal mỏng. Khi quét dẫn tới trang web giả mạo acb-online-verify.net thu thập thông tin thẻ.',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Phishing QR code (Quishing). Đã thông báo cho chủ cơ sở kinh doanh.',
                },
                {
                    'reporter': user_map['nguyen_thu_huong'],
                    'target_type': TargetType.PHONE,
                    'target_value': '+842899981234',
                    'scam_type': ScamType.POLICE_IMPERSONATION,
                    'severity': Severity.CRITICAL,
                    'description': 'Cuộc gọi tự xưng điều tra viên Viện Kiểm sát Nhân dân Tối cao dọa phong tỏa tài sản liên quan đường dây buôn lậu, bắt chuyển 50 triệu tiền bảo chứng.',
                    'scammer_phone': '+842899981234',
                    'scammer_name': 'Viện kiểm sát giả mạo',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'VoIP Caller ID Spoofing đầu số bàn TP.HCM.',
                },
                {
                    'reporter': user_map['ngoc_anh_cyber'],
                    'target_type': TargetType.EMAIL,
                    'target_value': 'billing-support@netfIix-billing-security.com',
                    'scam_type': ScamType.PHISHING,
                    'severity': Severity.MEDIUM,
                    'description': 'Email giả mạo Netflix báo tài khoản bị khóa do lỗi thẻ tín dụng, yêu cầu nhập số thẻ và mã CVV tại link netflix-update-billing.cc.',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Email phishing credential harvesting.',
                },
                {
                    'reporter': user_map['le_hoang_nam'],
                    'target_type': TargetType.ACCOUNT,
                    'target_value': 'VPBank: 1582910482',
                    'scam_type': ScamType.LOAN_SCAM,
                    'severity': Severity.HIGH,
                    'description': 'App vay tiền online EasyVay dụ đóng 3.500.000đ tiền phí bảo hiểm khoản vay và sửa số tài khoản bị sai 1 số.',
                    'scammer_bank_account': '1582910482',
                    'scammer_bank_name': 'VPBank',
                    'scammer_name': 'HOANG VAN THAO',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Lừa đảo app vay tiền ngụy tạo lỗi tài khoản.',
                },
                {
                    'reporter': user_map['hoang_kim_ngan'],
                    'target_type': TargetType.MESSAGE,
                    'target_value': 'Tin nhắn Facebook Meta Security Support',
                    'scam_type': ScamType.OTP_STEAL,
                    'severity': Severity.HIGH,
                    'description': 'Tin nhắn từ fanpage giả thông báo tài khoản vi phạm bản quyền cộng đồng, yêu cầu click link và nhập mã 2FA để kháng nghị.',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Chiếm quyền fanpage và tài khoản cá nhân.',
                },
                {
                    'reporter': user_map['nguyen_thu_huong'],
                    'target_type': TargetType.PHONE,
                    'target_value': '+84904819283',
                    'scam_type': ScamType.OTHER,
                    'severity': Severity.MEDIUM,
                    'description': 'Cuộc gọi tự xưng nhân viên điện lực EVN thông báo gia đình nợ tiền điện 4 tháng và sẽ bị cắt điện sau 2 giờ nếu không thanh toán gấp.',
                    'scammer_phone': '+84904819283',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Mạo danh EVN đe dọa cắt điện nhằm chiếm đoạt tiền.',
                },
                {
                    'reporter': user_map['pham_minh_duc'],
                    'target_type': TargetType.EMAIL,
                    'target_value': 'accounting@supplier-vinaconex.com',
                    'scam_type': ScamType.BANK_IMPERSONATION,
                    'severity': Severity.CRITICAL,
                    'description': 'Tấn công email doanh nghiệp (BEC) mạo danh nhà cung cấp thông báo tài khoản BIDV đang kiểm toán, đề nghị thanh toán 145 triệu sang VPBank mới.',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Tấn công BEC chuỗi cung ứng doanh nghiệp.',
                },
                {
                    'reporter': user_map['phan_thanh_tung'],
                    'target_type': TargetType.DOMAIN,
                    'target_value': 'san-binance-forex.cc',
                    'scam_type': ScamType.INVESTMENT_SCAM,
                    'severity': Severity.CRITICAL,
                    'description': 'Sàn giao dịch tiền mã hóa nhái thương hiệu Binance, dụ dỗ người dùng tham gia nhóm VIP kéo lệnh rồi khóa tài khoản.',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Sàn tiền ảo lừa đảo quốc tế.',
                },
                {
                    'reporter': user_map['tran_thi_mai'],
                    'target_type': TargetType.PHONE,
                    'target_value': '+84988776655',
                    'scam_type': ScamType.POLICE_IMPERSONATION,
                    'severity': Severity.CRITICAL,
                    'description': 'Đối tượng tự xưng cán bộ điều tra đe dọa lệnh bắt tạm giam, yêu cầu chuyển 20 triệu tiền bảo chứng vào STK MBBank.',
                    'scammer_phone': '+84988776655',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Đã xác minh đối tượng mạo danh cơ quan điều tra.',
                },
                {
                    'reporter': user_map['nguyen_thu_huong'],
                    'target_type': TargetType.DOMAIN,
                    'target_value': 'evn-thanh-toan-dien-luc.com',
                    'scam_type': ScamType.PHISHING,
                    'severity': Severity.CRITICAL,
                    'description': 'Trang web mạo danh EVN thông báo nợ cước tiền điện, lừa nạn nhân nhập số thẻ và mã OTP chuyển tiền vào tài khoản Techcombank 19038291823019.',
                    'scammer_phone': '02477712345',
                    'scammer_bank_account': '19038291823019',
                    'scammer_bank_name': 'Techcombank',
                    'scammer_name': 'NGUYEN VAN TOAN',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Mạo danh cổng thanh toán EVN.',
                },
                {
                    'reporter': user_map['bui_van_thanh'],
                    'target_type': TargetType.DOMAIN,
                    'target_value': 'vssid-baohiem-xahoi.top',
                    'scam_type': ScamType.PHISHING,
                    'severity': Severity.CRITICAL,
                    'description': 'Website lừa đồng bộ mã số BHXH và VNeID để nhận trợ cấp 3.5 triệu đồng, yêu cầu cài đặt ứng dụng độc hại chiếm quyền trợ năng Android.',
                    'scammer_phone': '+84389998877',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Phát tán mã độc chiếm quyền trợ năng Android.',
                },
                {
                    'reporter': user_map['le_hoang_nam'],
                    'target_type': TargetType.DOMAIN,
                    'target_value': 'vemaybay-vietnam-airline-km.net',
                    'scam_type': ScamType.OTHER,
                    'severity': Severity.HIGH,
                    'description': 'Website bán vé máy bay khuyến mãi Tết giá siêu rẻ mạo danh Vietnam Airlines, yêu cầu chuyển khoản cọc vào STK Vietcombank 998877665544 rồi chặn số.',
                    'scammer_phone': '+84901234567',
                    'scammer_bank_account': '998877665544',
                    'scammer_bank_name': 'Vietcombank',
                    'scammer_name': 'CONG TY CP DU LICH VE MAY BAY',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Lừa đảo bán vé máy bay giả.',
                },
                {
                    'reporter': user_map['dang_tuan_anh'],
                    'target_type': TargetType.PHONE,
                    'target_value': '02888899999',
                    'scam_type': ScamType.LOAN_SCAM,
                    'severity': Severity.HIGH,
                    'description': 'Tổng đài tự động gọi điện mời vay lãi suất 0% nhưng thực chất lừa phí bảo hiểm khoản vay và đe dọa người thân khi không nộp.',
                    'scammer_phone': '02888899999',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Tín dụng đen mạo danh ngân hàng.',
                },
                {
                    'reporter': user_map['hoang_kim_ngan'],
                    'target_type': TargetType.PHONE,
                    'target_value': '+84865554433',
                    'scam_type': ScamType.RECRUITMENT_SCAM,
                    'severity': Severity.HIGH,
                    'description': 'Dụ dỗ làm nhiệm vụ bình chọn ca sĩ trên ZingMP3 hưởng hoa hồng, sau đó yêu cầu nạp 30 triệu vào STK MBBank 098765432100 để nâng hạng VIP.',
                    'scammer_phone': '+84865554433',
                    'scammer_bank_account': '098765432100',
                    'scammer_bank_name': 'MBBank',
                    'scammer_name': 'TRAN DINH QUANG',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Bẫy cộng tác viên bình chọn âm nhạc lừa đảo.',
                },
                {
                    'reporter': user_map['dinh_quang_huy'],
                    'target_type': TargetType.PHONE,
                    'target_value': '+84911223344',
                    'scam_type': ScamType.DELIVERY_SCAM,
                    'severity': Severity.MEDIUM,
                    'description': 'Kẻ gian gọi điện mạo danh shipper bưu cục báo có đơn COD 120.000đ yêu cầu chuyển khoản thanh toán gấp vào tài khoản VPBank 1582910482.',
                    'scammer_phone': '+84911223344',
                    'scammer_bank_account': '1582910482',
                    'scammer_bank_name': 'VPBank',
                    'scammer_name': 'HOANG VAN MINH',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Lừa đảo giao hàng COD giả mạo bưu tá.',
                },
                {
                    'reporter': user_map['tran_thi_mai'],
                    'target_type': TargetType.ACCOUNT,
                    'target_value': 'OCB: 0112100029384',
                    'scam_type': ScamType.OTHER,
                    'severity': Severity.HIGH,
                    'description': 'Thông báo trúng thưởng xe máy Honda SH 150i qua tin nhắn Messenger, yêu cầu nộp 5 triệu phí trước bạ vào STK OCB 0112100029384.',
                    'scammer_phone': '+84933445566',
                    'scammer_bank_account': '0112100029384',
                    'scammer_bank_name': 'OCB',
                    'scammer_name': 'LE THI CAM TU',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Lừa đảo trúng thưởng xe máy mạng xã hội.',
                },
                {
                    'reporter': user_map['nguyen_van_an'],
                    'target_type': TargetType.ACCOUNT,
                    'target_value': 'VietinBank: 100029384756',
                    'scam_type': ScamType.BANK_IMPERSONATION,
                    'severity': Severity.CRITICAL,
                    'description': 'Người mua hàng gửi ảnh biên lai chuyển tiền VietinBank giả rồi hối thúc giao hàng, tài khoản thụ hưởng ghi 100029384756.',
                    'scammer_phone': '+84944556677',
                    'scammer_bank_account': '100029384756',
                    'scammer_bank_name': 'VietinBank',
                    'scammer_name': 'VO VAN DUC',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Lừa đảo tạo hóa đơn chuyển khoản ngân hàng giả.',
                },
                {
                    'reporter': user_map['phan_thanh_tung'],
                    'target_type': TargetType.DOMAIN,
                    'target_value': 'modgame-freefire-kimcuong.net',
                    'scam_type': ScamType.OTP_STEAL,
                    'severity': Severity.CRITICAL,
                    'description': 'Website phát tán file APK hack kim cương game FreeFire chứa Trojan Spynote đánh cắp mã xác thực OTP ngân hàng.',
                    'scammer_phone': '+84977889900',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Phát tán mã độc Android đánh cắp OTP ngân hàng.',
                },
                {
                    'reporter': user_map['do_thi_thu_trang'],
                    'target_type': TargetType.ACCOUNT,
                    'target_value': 'Sacombank: 060281928391',
                    'scam_type': ScamType.ROMANCE_SCAM,
                    'severity': Severity.HIGH,
                    'description': 'Đối tượng quen qua mạng mạo danh sĩ quan quân đội gửi kiện hàng 500.000 USD, yêu cầu chuyển 35 triệu phí hải quan vào STK Sacombank 060281928391.',
                    'scammer_phone': '+84833221100',
                    'scammer_bank_account': '060281928391',
                    'scammer_bank_name': 'Sacombank',
                    'scammer_name': 'DANG THI THU THAO',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Kịch bản lừa đảo tình cảm và phí thông quan hải quan.',
                },
            ]

            for r_data in reports_data:
                Report.objects.get_or_create(
                    target_value=r_data['target_value'],
                    defaults={
                        'reporter': r_data['reporter'],
                        'target_type': r_data['target_type'],
                        'scam_type': r_data['scam_type'],
                        'severity': r_data['severity'],
                        'description': r_data['description'],
                        'scammer_phone': r_data.get('scammer_phone', ''),
                        'scammer_bank_account': r_data.get('scammer_bank_account', ''),
                        'scammer_bank_name': r_data.get('scammer_bank_name', ''),
                        'scammer_name': r_data.get('scammer_name', ''),
                        'status': r_data['status'],
                        'moderator': user_map['admin_sentinel'],
                        'moderation_note': r_data.get('moderation_note', ''),
                    }
                )

            # ──────────────────────────────────────────────────────────────────
            # 6b. TRACKED PHISHING & SCAM DOMAINS
            # ──────────────────────────────────────────────────────────────────
            self.stdout.write("6b. Khởi tạo danh mục tên miền lừa đảo nguy hiểm...")
            domains_data = [
                ('dang-nhap-vietcombank-digi.com', 98, ScamType.BANK_IMPERSONATION, 4, False, 'Mạo danh cổng đăng nhập Vietcombank Digibank đánh cắp thông tin tài khoản'),
                ('dvc-quocgia-vneid.gov-vn.info', 95, ScamType.PHISHING, 2, False, 'Website giả mạo Cổng Dịch vụ công Quốc gia phát tán mã độc VNeID giả'),
                ('vn-post-tra-cuu-kien-hang.xyz', 90, ScamType.DELIVERY_SCAM, 6, False, 'Giả mạo VNPost bưu điện Việt Nam yêu cầu thanh toán cước phí tồn kho'),
                ('san-binance-forex.cc', 95, ScamType.INVESTMENT_SCAM, 12, False, 'Sàn đầu tư tài chính nhái Binance dụ dỗ nạp tiền rồi khóa tài khoản'),
                ('shopee-tuyen-dung-ctv247.site', 92, ScamType.RECRUITMENT_SCAM, 5, False, 'Bẫy tuyển dụng cộng tác viên Shopee giật đơn ảo thả tép bắt tôm'),
                ('evn-thanh-toan-dien-luc.com', 94, ScamType.PHISHING, 3, False, 'Mạo danh Tập đoàn Điện lực EVN đe dọa cắt điện để lừa chuyển tiền'),
                ('vssid-baohiem-xahoi.top', 95, ScamType.PHISHING, 3, False, 'Giả mạo Bảo hiểm Xã hội Việt Nam phát tán mã độc chiếm quyền điện thoại'),
                ('vemaybay-vietnam-airline-km.net', 88, ScamType.OTHER, 8, False, 'Bán vé máy bay giả mùa Tết mạo danh hãng hàng không quốc gia'),
                ('modgame-freefire-kimcuong.net', 96, ScamType.OTP_STEAL, 10, False, 'Phát tán mã độc Android Trojan Spynote đánh cắp SMS và mã OTP ngân hàng'),
                ('vpbank-neo-xac-thuc-sinh-trac.online', 97, ScamType.BANK_IMPERSONATION, 2, False, 'Giả mạo hướng dẫn xác thực sinh trắc học VPBank NEO chiếm đoạt tài khoản'),
                ('agribank-ebank-smart-otp.top', 96, ScamType.OTP_STEAL, 4, False, 'Trang đăng nhập Agribank giả mạo yêu cầu cung cấp Smart OTP'),
                ('bidv-smartbanking-capnhat.site', 95, ScamType.BANK_IMPERSONATION, 5, False, 'Mạo danh thông báo nâng cấp bảo mật BIDV SmartBanking'),
            ]

            domain_objs = {}
            for d_name, d_score, d_scam, d_age, d_ssl, d_desc in domains_data:
                dom, _ = Domain.objects.update_or_create(
                    domain_name=d_name,
                    defaults={
                        'risk_score': d_score,
                        'scam_type': d_scam,
                        'domain_age_days': d_age,
                        'ssl_valid': d_ssl,
                        'report_count': 15,
                        'whois_snapshot': {
                            'threat': 'phishing',
                            'description': d_desc,
                            'registrar': 'Namecheap Inc.',
                            'country': 'IS',
                            'tags': 'malware,phishing,vietnam_banking',
                        }
                    }
                )
                domain_objs[d_name] = dom

            # ──────────────────────────────────────────────────────────────────
            # 6c. SUSPICIOUS PHONE NUMBERS & FRAUD CALLS
            # ──────────────────────────────────────────────────────────────────
            self.stdout.write("6c. Khởi tạo danh bạ số điện thoại lừa đảo & phản ánh cuộc gọi rác...")
            phones_data = [
                ('+84988776655', PhoneRiskLevel.RED, 'Mạo danh cán bộ điều tra Bộ Công an đe dọa lệnh bắt', 'Viettel', 'Mobile', 24, [
                    ('SCAM', 'Gọi điện xưng là cán bộ C02 dọa liên quan đường dây ma túy rửa tiền'),
                    ('FRAUD', 'Yêu cầu chuyển 50 triệu tiền bảo chứng thanh tra vào tài khoản ngân hàng'),
                ]),
                ('+84389998877', PhoneRiskLevel.RED, 'Mạo danh cán bộ công an phường hỗ trợ định danh VNeID mức 2', 'Viettel', 'Mobile', 19, [
                    ('SCAM', 'Hướng dẫn tải app Dịch vụ công giả mạo đuôi .apk'),
                    ('FRAUD', 'Chiếm quyền điều khiển điện thoại Samsung và chuyển trộm tiền'),
                ]),
                ('02477712345', PhoneRiskLevel.RED, 'Tổng đài giả mạo Điện lực EVN thông báo cắt điện khẩn cấp', 'VoIP CMC', 'VoIP', 32, [
                    ('SCAM', 'Gặp tổng đài viên tự động báo nợ cước 3.5 triệu yêu cầu bấm phím 9'),
                    ('SPAM', 'Cuộc gọi tự động làm phiền liên tục vào giờ nghỉ trưa'),
                ]),
                ('02888899999', PhoneRiskLevel.YELLOW, 'Tổng đài quấy rối mời chào tín dụng đen và vay nặng lãi', 'VNPT', 'Landline', 15, [
                    ('SPAM', 'Mời vay tiền trả góp lãi suất thấp thủ tục chỉ cần CMND'),
                    ('HARASSMENT', 'Nhắn tin đe dọa và gọi quấy rối khi từ chối vay'),
                ]),
                ('+84865554433', PhoneRiskLevel.RED, 'Đối tượng tuyển dụng CTV online bình chọn ca sĩ và giật đơn', 'Viettel', 'Mobile', 22, [
                    ('SCAM', 'Dụ tham gia nhóm Telegram làm nhiệm vụ tăng tương tác nhận hoa hồng'),
                    ('FRAUD', 'Yêu cầu nạp tiền bảo lãnh đơn hàng rồi chặn tài khoản'),
                ]),
                ('+84911223344', PhoneRiskLevel.YELLOW, 'Mạo danh bưu tá giao hàng COD bưu phẩm rác', 'Vinaphone', 'Mobile', 14, [
                    ('FRAUD', 'Bảo giao hàng thu hộ 150k khi tôi không đặt mua bất kỳ món gì'),
                ]),
                ('+84933445566', PhoneRiskLevel.RED, 'Thông báo trúng thưởng xe máy Honda SH lừa phí trước bạ', 'MobiFone', 'Mobile', 18, [
                    ('SCAM', 'Bảo tôi trúng giải đặc biệt tri ân khách hàng sàn thương mại điện tử'),
                ]),
                ('+84944556677', PhoneRiskLevel.RED, 'Sử dụng biên lai chuyển khoản giả tạo áp lực nhận hàng', 'Vinaphone', 'Mobile', 11, [
                    ('FRAUD', 'Gửi ảnh fake bill VietinBank và giục gửi hàng qua xe khách ngay'),
                ]),
                ('+84977889900', PhoneRiskLevel.RED, 'Phát tán link tải file APK chứa mã độc Trojan Spynote', 'Viettel', 'Mobile', 28, [
                    ('SCAM', 'Gửi link tải game bản mod kim cương nhưng thực chất là mã độc đánh cắp SMS'),
                ]),
                ('+84833221100', PhoneRiskLevel.RED, 'Mạo danh nhân viên hải quan sân bay yêu cầu nộp phí bưu kiện ngoại giao', 'Vinaphone', 'Mobile', 16, [
                    ('SCAM', 'Bảo có thùng quà 500k USD từ Mỹ gửi về bị hải quan giữ do có hàng cấm'),
                ]),
                ('+84901234567', PhoneRiskLevel.YELLOW, 'Bán vé máy bay giả mạo chiết khấu cao dịp Tết', 'MobiFone', 'Mobile', 13, [
                    ('FRAUD', 'Bán vé máy bay không có thật rồi khóa liên lạc Zalo'),
                ]),
                ('02873001234', PhoneRiskLevel.YELLOW, 'Tổng đài cuộc gọi rác mạo danh cơ quan Thuế quyết toán thuế TNCN', 'FPT Telecom', 'VoIP', 25, [
                    ('SPAM', 'Mời cài app Tổng cục Thuế để nhận hoàn thuế thu nhập cá nhân'),
                ]),
            ]

            phone_objs = {}
            for p_num, p_risk, p_label, p_carrier, p_type, p_count, p_reports in phones_data:
                phone_inst, _ = PhoneNumber.objects.update_or_create(
                    phone_number=p_num,
                    defaults={
                        'risk_level': p_risk,
                        'risk_label': p_label,
                        'carrier': p_carrier,
                        'line_type': p_type,
                        'reports_count': p_count,
                        'trust_score': 10.0 if p_risk == PhoneRiskLevel.RED else 35.0,
                        'country_code': 'VN',
                        'is_virtual': (p_type == 'VoIP'),
                        'recommendations': [
                            'Tuyệt đối không chuyển tiền vào bất kỳ tài khoản nào theo chỉ dẫn qua điện thoại.',
                            'Cơ quan nhà nước, công an và viện kiểm sát không làm việc qua điện thoại.',
                            'Chặn số và thông báo cho người thân trong gia đình phòng ngừa.',
                        ]
                    }
                )
                phone_objs[p_num] = phone_inst
                for r_type, r_desc in p_reports:
                    PhoneReport.objects.get_or_create(
                        phone_number=phone_inst,
                        description=r_desc,
                        defaults={
                            'report_type': r_type,
                        }
                    )

            # ──────────────────────────────────────────────────────────────────
            # 6d. FRAUD GRAPH ENTITY LINKS
            # ──────────────────────────────────────────────────────────────────
            self.stdout.write("6d. Thiết lập mạng lưới liên kết thực thể lừa đảo (Fraud Graph)...")
            bank_accounts_by_hash = {b.account_number_hash: b for b in BankAccount.objects.all()}

            def find_bank(acc_num):
                h = BankAccount.hash_account(acc_num)
                return bank_accounts_by_hash.get(h)

            links_to_create = [
                ('+84988776655', 'phone', '888899991111', 'account', 'shared_report', 0.95),
                ('+84865554433', 'phone', '098765432100', 'account', 'shared_report', 0.90),
                ('+84911223344', 'phone', '1582910482', 'account', 'shared_report', 0.85),
                ('+84933445566', 'phone', '0112100029384', 'account', 'shared_report', 0.92),
                ('+84944556677', 'phone', '100029384756', 'account', 'shared_report', 0.94),
                ('+84833221100', 'phone', '060281928391', 'account', 'shared_report', 0.96),
                ('02477712345', 'phone', '19038291823019', 'account', 'shared_report', 0.88),
                ('dang-nhap-vietcombank-digi.com', 'domain', '1029384756', 'account', 'shared_url', 0.95),
                ('san-binance-forex.cc', 'domain', '19038291823019', 'account', 'shared_url', 0.93),
                ('shopee-tuyen-dung-ctv247.site', 'domain', '098765432100', 'account', 'shared_url', 0.91),
                ('vemaybay-vietnam-airline-km.net', 'domain', '998877665544', 'account', 'shared_url', 0.89),
                ('+84389998877', 'phone', 'dvc-quocgia-vneid.gov-vn.info', 'domain', 'shared_text', 0.96),
                ('02477712345', 'phone', 'evn-thanh-toan-dien-luc.com', 'domain', 'shared_text', 0.90),
                ('+84977889900', 'phone', 'modgame-freefire-kimcuong.net', 'domain', 'shared_text', 0.95),
                ('+84865554433', 'phone', 'shopee-tuyen-dung-ctv247.site', 'domain', 'shared_text', 0.92),
            ]

            for from_val, from_t, to_val, to_t, reason, conf in links_to_create:
                from_id = None
                to_id = None
                if from_t == 'phone' and from_val in phone_objs:
                    from_id = phone_objs[from_val].id
                elif from_t == 'domain' and from_val in domain_objs:
                    from_id = domain_objs[from_val].id
                elif from_t == 'account':
                    b = find_bank(from_val)
                    if b:
                        from_id = b.id

                if to_t == 'phone' and to_val in phone_objs:
                    to_id = phone_objs[to_val].id
                elif to_t == 'domain' and to_val in domain_objs:
                    to_id = domain_objs[to_val].id
                elif to_t == 'account':
                    b = find_bank(to_val)
                    if b:
                        to_id = b.id

                if from_id and to_id:
                    EntityLink.objects.get_or_create(
                        from_type=from_t,
                        from_entity_id=from_id,
                        to_type=to_t,
                        to_entity_id=to_id,
                        defaults={
                            'link_reason': reason,
                            'confidence': conf,
                        }
                    )

            # ──────────────────────────────────────────────────────────────────
            # 7. DAILY TREND STATISTICS (Past 30 Days)
            # ──────────────────────────────────────────────────────────────────
            self.stdout.write("7. Khởi tạo dữ liệu thống kê xu hướng 30 ngày gần nhất...")
            today = timezone.now().date()
            scam_types_sample = [
                (ScamType.BANK_IMPERSONATION, 45),
                (ScamType.POLICE_IMPERSONATION, 38),
                (ScamType.RECRUITMENT_SCAM, 62),
                (ScamType.INVESTMENT_SCAM, 28),
                (ScamType.DELIVERY_SCAM, 31),
                (ScamType.PHISHING, 55),
                (ScamType.OTP_STEAL, 42),
                (ScamType.LOAN_SCAM, 25),
                (ScamType.ROMANCE_SCAM, 18),
                (ScamType.OTHER, 20),
            ]

            for day_offset in range(30, -1, -1):
                target_date = today - timedelta(days=day_offset)
                multiplier = 1.0 + (30 - day_offset) * 0.02
                for s_type, base_cnt in scam_types_sample:
                    cnt = int(base_cnt * multiplier) + (day_offset % 7)
                    TrendDaily.objects.update_or_create(
                        date=target_date,
                        region='VN',
                        scam_type=s_type,
                        defaults={'count': cnt}
                    )

            # ──────────────────────────────────────────────────────────────────
            # 8. ANNOUNCEMENTS & SUPPORT TICKETS
            # ──────────────────────────────────────────────────────────────────
            self.stdout.write("8. Khởi tạo thông báo hệ thống và phiếu hỗ trợ...")
            announcements = [
                {
                    'title': 'Ra mắt máy chủ giao thức Model Context Protocol (MCP Server) kết nối AI Chatbot',
                    'content': 'ShieldCall VN chính thức phát hành hệ thống MCP Server cho phép kết nối cơ sở dữ liệu an ninh số trực tiếp vào Claude Desktop, Cursor, Windsurf và ChatGPT.',
                    'is_pinned': True,
                    'likes': 68,
                    'views': 520,
                },
                {
                    'title': 'Nâng cấp mô hình trí tuệ nhân tạo phân tích kịch bản lừa đảo tiếng Việt thế hệ mới',
                    'content': 'Hệ thống đã cập nhật bộ phân tích ngôn ngữ tự nhiên chuyên sâu, nâng cao độ chính xác nhận diện các kịch bản mạo danh cán bộ VNeID và lừa đảo tuyển dụng lên 98%.',
                    'is_pinned': True,
                    'likes': 45,
                    'views': 380,
                },
                {
                    'title': 'Cập nhật danh mục 65+ ngân hàng thành viên VietQR phục vụ đối soát tài khoản',
                    'content': 'Toàn bộ danh mục ngân hàng thương mại, ngân hàng số và ví điện tử tại Việt Nam đã được đồng bộ hóa mã BIN để phục vụ người dân thẩm định tài khoản thụ hưởng.',
                    'is_pinned': False,
                    'likes': 32,
                    'views': 290,
                },
                {
                    'title': "Phát động chiến dịch 'Gia đình an toàn số' bảo vệ người cao tuổi trên mạng xã hội",
                    'content': 'Cộng đồng ShieldCall cùng các chuyên gia pháp lý và an toàn thông tin phát động chiến dịch tuyên truyền phòng chống cuộc gọi Deepfake và lừa đảo viễn thông.',
                    'is_pinned': False,
                    'likes': 54,
                    'views': 410,
                },
            ]

            for a_info in announcements:
                ann, _ = Announcement.objects.get_or_create(
                    title=a_info['title'],
                    defaults={
                        'author': user_map['admin_sentinel'],
                        'content': a_info['content'],
                        'is_pinned': a_info['is_pinned'],
                        'likes_count': a_info['likes'],
                        'views_count': a_info['views'],
                    }
                )
                AnnouncementReaction.objects.get_or_create(
                    user=user_map['nguyen_van_an'],
                    announcement=ann,
                    defaults={'reaction_type': 'helpful'}
                )

            tickets = [
                {
                    'author': user_map['tran_thi_mai'],
                    'title': 'Đề xuất bổ sung kiểm tra số tài khoản ngân hàng số Cake by VPBank',
                    'description': 'Em thấy hiện tại hệ thống chưa có tùy chọn ngân hàng Cake, mong ban quản trị bổ sung thêm ạ.',
                    'category': 'feature',
                    'priority': SupportTicket.TicketPriority.MEDIUM,
                    'status': SupportTicket.TicketStatus.RESOLVED,
                    'admin_reply': 'Cảm ơn bạn! Đội ngũ phát triển đã cập nhật danh sách ngân hàng số bao gồm Cake, Timo, Viettel Money trong bản cập nhật hôm nay.',
                    'resolved': True,
                },
                {
                    'author': user_map['le_hoang_nam'],
                    'title': 'Báo cáo lỗi: Hình ảnh chứng cứ dạng HEIC từ iPhone tải lên bị chậm',
                    'description': 'Khi em tải ảnh chụp màn hình định dạng HEIC từ iPhone 15 thì mất khoảng 5 giây để xử lý OCR.',
                    'category': 'bug',
                    'priority': SupportTicket.TicketPriority.LOW,
                    'status': SupportTicket.TicketStatus.IN_PROGRESS,
                    'admin_reply': 'Cảm ơn bạn Nam! Đội ngũ kỹ thuật đang tối ưu bộ nén ảnh tự động trên worker Celery để xử lý ảnh HEIC nhanh hơn.',
                    'resolved': False,
                },
                {
                    'author': user_map['bui_van_thanh'],
                    'title': 'Đề xuất thêm tính năng tra cứu nhanh biển số xe máy nghi vấn lừa đảo',
                    'description': 'Nhiều đối tượng giao hàng giả mạo đi xe máy biển số giả, nếu có tra cứu biển số thì rất tiện cho anh em shipper.',
                    'category': 'feature',
                    'priority': SupportTicket.TicketPriority.MEDIUM,
                    'status': SupportTicket.TicketStatus.OPEN,
                    'admin_reply': '',
                    'resolved': False,
                },
                {
                    'author': user_map['nguyen_thu_huong'],
                    'title': 'Nhờ hỗ trợ: Cách cài đặt biểu tượng lối tắt ShieldCall ra màn hình chính điện thoại',
                    'description': 'Tôi muốn đưa trang web ra màn hình chính điện thoại Samsung để mỗi lần có số lạ gọi đến là mở kiểm tra được ngay.',
                    'category': 'account',
                    'priority': SupportTicket.TicketPriority.LOW,
                    'status': SupportTicket.TicketStatus.RESOLVED,
                    'admin_reply': "Dạ thưa cô, ShieldCall là ứng dụng web cấp tiến (PWA). Cô chỉ cần mở trình duyệt Chrome, bấm vào dấu 3 chấm ở góc trên bên phải và chọn 'Cài đặt ứng dụng' hoặc 'Thêm vào màn hình chính' là biểu tượng chiếc khiên xanh sẽ xuất hiện ngay trên màn hình điện thoại ạ.",
                    'resolved': True,
                },
            ]

            for t_info in tickets:
                SupportTicket.objects.get_or_create(
                    title=t_info['title'],
                    defaults={
                        'author': t_info['author'],
                        'description': t_info['description'],
                        'category': t_info['category'],
                        'priority': t_info['priority'],
                        'status': t_info['status'],
                        'admin_reply': t_info['admin_reply'],
                        'replied_by': user_map['admin_sentinel'] if t_info['admin_reply'] else None,
                        'resolved_at': timezone.now() if t_info['resolved'] else None,
                    }
                )

        self.stdout.write(self.style.SUCCESS("=== HOÀN TẤT KHỞI TẠO DỮ LIỆU THỰC TẾ CHO SHIELDCALL VN ==="))
