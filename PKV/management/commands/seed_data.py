"""
Seed data management command for ShieldCall VN (Sentinel Team Project).
Populates realistic Vietnamese demo data across users, scam reports, tracked bank accounts,
domains, entity fraud graph links, community forum discussions, educational lessons & quizzes,
scenarios, and 14-day daily trends.
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
    ArticleCategory, Article, LearnLesson, LearnQuiz, LearnScenario,
    QuizQuestionType, Announcement, AnnouncementReaction, SupportTicket,
    ScamType, Severity, RiskLevel, ReportStatus, TargetType
)

User = get_user_model()


class Command(BaseCommand):
    help = "Seed comprehensive, realistic Vietnamese sample data for ShieldCall VN"

    def add_arguments(self, parser):
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear previous demo data before seeding (preserves initial user)',
        )

    def handle(self, *args, **options):
        clear_data = options.get('clear', False)

        self.stdout.write(self.style.NOTICE("=== BẮT ĐẦU KHỞI TẠO DỮ LIỆU MẪU SHIELDCALL VN ==="))

        with transaction.atomic():
            if clear_data:
                self.stdout.write("Dọn dẹp dữ liệu mẫu cũ...")
                EntityLink.objects.all().delete()
                Report.objects.all().delete()
                BankAccount.objects.all().delete()
                ForumPostReaction.objects.all().delete()
                ForumCommentLike.objects.all().delete()
                ForumLike.objects.all().delete()
                ForumComment.objects.all().delete()
                ForumPost.objects.all().delete()
                LearnQuiz.objects.all().delete()
                LearnScenario.objects.all().delete()
                LearnLesson.objects.all().delete()
                Article.objects.all().delete()
                AnnouncementReaction.objects.all().delete()
                Announcement.objects.all().delete()
                SupportTicket.objects.all().delete()
                TrendDaily.objects.all().delete()
                # Delete demo users only (keep user with id=1)
                User.objects.filter(username__in=[
                    'admin_sentinel', 'chuyen_gia_an_ninh',
                    'nguyen_van_an', 'tran_thi_mai', 'le_hoang_nam'
                ]).delete()
                self.stdout.write(self.style.SUCCESS("Đã dọn dẹp dữ liệu demo thành công."))

            # 1. Users & Profiles
            self.stdout.write("1. Khởi tạo tài khoản người dùng mẫu...")
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
                    'email': 'security.lead@shieldcall.vn',
                    'first_name': 'Hoàng',
                    'last_name': 'Văn Bách',
                    'is_staff': True,
                    'is_superuser': False,
                    'display_name': 'Bách Hoàng (SOC Lead)',
                    'bio': 'Chuyên gia phân tích mối đe dọa trực tuyến và kỹ thuật đảo ngược mã độc.',
                    'rank_points': 3450,
                },
                {
                    'username': 'nguyen_van_an',
                    'email': 'an.nguyen@gmail.com',
                    'first_name': 'An',
                    'last_name': 'Nguyễn Văn',
                    'is_staff': False,
                    'is_superuser': False,
                    'display_name': 'Nguyễn Văn An',
                    'bio': 'Thành viên tích cực đóng góp dữ liệu cảnh giác lừa đảo.',
                    'rank_points': 1420,
                },
                {
                    'username': 'tran_thi_mai',
                    'email': 'mai.tran@gmail.com',
                    'first_name': 'Mai',
                    'last_name': 'Trần Thị',
                    'is_staff': False,
                    'is_superuser': False,
                    'display_name': 'Trần Thị Mai',
                    'bio': 'Nạn nhân từng suýt bị lừa 80 triệu qua Telegram, chia sẻ kinh nghiệm cảnh giác.',
                    'rank_points': 680,
                },
                {
                    'username': 'le_hoang_nam',
                    'email': 'nam.le@fpt.edu.vn',
                    'first_name': 'Nam',
                    'last_name': 'Lê Hoàng',
                    'is_staff': False,
                    'is_superuser': False,
                    'display_name': 'Lê Hoàng Nam',
                    'bio': 'Sinh viên An toàn Thông tin - FPT University.',
                    'rank_points': 450,
                },
            ]

            user_objs = {}
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

                profile, _ = UserProfile.objects.get_or_create(user=u)
                profile.display_name = u_data['display_name']
                profile.bio = u_data['bio']
                profile.rank_points = u_data['rank_points']
                profile.save()
                user_objs[u_data['username']] = u

            # Also ensure initial user 1 has rank points if exists
            initial_u = User.objects.filter(id=1).first()
            if initial_u:
                prof, _ = UserProfile.objects.get_or_create(user=initial_u)
                if not prof.display_name:
                    prof.display_name = initial_u.username
                if prof.rank_points < 100:
                    prof.rank_points = 250
                prof.save()
                user_objs['tri_kien'] = initial_u

            # 2. Bank Accounts
            self.stdout.write("2. Khởi tạo danh sách tài khoản ngân hàng lừa đảo theo dõi...")
            bank_accounts_data = [
                {
                    'bank_name': 'Vietcombank',
                    'acc_num': '1029384756',
                    'risk_score': 95,
                    'report_count': 16,
                    'scam_type': ScamType.BANK_IMPERSONATION,
                },
                {
                    'bank_name': 'Techcombank',
                    'acc_num': '19038291823019',
                    'risk_score': 92,
                    'report_count': 12,
                    'scam_type': ScamType.INVESTMENT_SCAM,
                },
                {
                    'bank_name': 'MBBank',
                    'acc_num': '098765432100',
                    'risk_score': 88,
                    'report_count': 9,
                    'scam_type': ScamType.RECRUITMENT_SCAM,
                },
                {
                    'bank_name': 'VietinBank',
                    'acc_num': '100029384756',
                    'risk_score': 85,
                    'report_count': 8,
                    'scam_type': ScamType.DELIVERY_SCAM,
                },
                {
                    'bank_name': 'ACB',
                    'acc_num': '284759281',
                    'risk_score': 78,
                    'report_count': 5,
                    'scam_type': ScamType.LOAN_SCAM,
                },
                {
                    'bank_name': 'VPBank',
                    'acc_num': '1582910482',
                    'risk_score': 90,
                    'report_count': 11,
                    'scam_type': ScamType.POLICE_IMPERSONATION,
                },
                {
                    'bank_name': 'Momo',
                    'acc_num': '0912839481',
                    'risk_score': 82,
                    'report_count': 7,
                    'scam_type': ScamType.OTP_STEAL,
                },
            ]

            bank_objs = []
            for b_data in bank_accounts_data:
                h = BankAccount.hash_account(b_data['acc_num'])
                m = BankAccount.mask_account(b_data['acc_num'])
                b, _ = BankAccount.objects.get_or_create(
                    bank_name=b_data['bank_name'],
                    account_number_hash=h,
                    defaults={
                        'account_number_masked': m,
                        'risk_score': b_data['risk_score'],
                        'report_count': b_data['report_count'],
                        'scam_type': b_data['scam_type'],
                    }
                )
                bank_objs.append(b)

            # 3. Phishing Domains
            self.stdout.write("3. Khởi tạo danh sách tên miền lừa đảo giả mạo...")
            domains_data = [
                {
                    'domain_name': 'vietcombank-login-sec.top',
                    'risk_score': 95,
                    'report_count': 22,
                    'scam_type': ScamType.BANK_IMPERSONATION,
                    'domain_age_days': 4,
                    'ssl_valid': True,
                },
                {
                    'domain_name': 'dichvucong-gov-vn.xyz',
                    'risk_score': 98,
                    'report_count': 35,
                    'scam_type': ScamType.POLICE_IMPERSONATION,
                    'domain_age_days': 2,
                    'ssl_valid': True,
                },
                {
                    'domain_name': 'shopee-tuyendung-ctv.vip',
                    'risk_score': 90,
                    'report_count': 18,
                    'scam_type': ScamType.RECRUITMENT_SCAM,
                    'domain_age_days': 6,
                    'ssl_valid': False,
                },
                {
                    'domain_name': 'san-binance-forex.cc',
                    'risk_score': 92,
                    'report_count': 14,
                    'scam_type': ScamType.INVESTMENT_SCAM,
                    'domain_age_days': 10,
                    'ssl_valid': True,
                },
                {
                    'domain_name': 'vnpost-tracking-bill.xyz',
                    'risk_score': 88,
                    'report_count': 19,
                    'scam_type': ScamType.DELIVERY_SCAM,
                    'domain_age_days': 3,
                    'ssl_valid': True,
                },
                {
                    'domain_name': 'acb-online-verify.net',
                    'risk_score': 91,
                    'report_count': 11,
                    'scam_type': ScamType.BANK_IMPERSONATION,
                    'domain_age_days': 5,
                    'ssl_valid': True,
                },
            ]

            domain_objs = []
            for d_data in domains_data:
                d, _ = Domain.objects.get_or_create(
                    domain_name=d_data['domain_name'],
                    defaults={
                        'risk_score': d_data['risk_score'],
                        'report_count': d_data['report_count'],
                        'scam_type': d_data['scam_type'],
                        'domain_age_days': d_data['domain_age_days'],
                        'ssl_valid': d_data['ssl_valid'],
                    }
                )
                domain_objs.append(d)

            # 4. Scam Reports
            self.stdout.write("4. Khởi tạo các báo cáo lừa đảo thực tế...")
            reports_data = [
                {
                    'reporter': user_objs['nguyen_van_an'],
                    'target_type': TargetType.ACCOUNT,
                    'target_value': 'VCB: 1029384756',
                    'scam_type': ScamType.BANK_IMPERSONATION,
                    'severity': Severity.CRITICAL,
                    'description': 'Đối tượng giả danh nhân viên Vietcombank gọi điện thông báo thẻ bị trừ 15 triệu, hướng dẫn chuyển tiền vào STK 1029384756 để bảo lưu tài sản. Đã lừa của tôi 15.000.000 VNĐ.',
                    'scammer_phone': '0898234912',
                    'scammer_bank_account': '1029384756',
                    'scammer_bank_name': 'Vietcombank',
                    'scammer_name': 'NGUYEN VAN QUYET',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Đã đối soát với blacklist ngân hàng, xác nhận tài khoản lừa đảo.',
                },
                {
                    'reporter': user_objs['tran_thi_mai'],
                    'target_type': TargetType.PHONE,
                    'target_value': '02471098822',
                    'scam_type': ScamType.POLICE_IMPERSONATION,
                    'severity': Severity.CRITICAL,
                    'description': 'Số điện thoại tự xưng Thiếu úy Lê Văn Long - Công an TP Hà Nội đe dọa tôi dính vào vụ án rửa tiền ma túy, yêu cầu kết bạn Zalo nhận lệnh bắt tạm giam có dấu đỏ.',
                    'scammer_phone': '02471098822',
                    'scammer_name': 'Lê Văn Long (Giả mạo)',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Kịch bản giả mạo công an điều tra kinh điển.',
                },
                {
                    'reporter': user_objs['le_hoang_nam'],
                    'target_type': TargetType.DOMAIN,
                    'target_value': 'dichvucong-gov-vn.xyz',
                    'scam_type': ScamType.POLICE_IMPERSONATION,
                    'severity': Severity.CRITICAL,
                    'description': 'Trang web mạo danh Cổng dịch vụ công quốc gia, dụ dỗ người dân tải file DichVuCong.apk chứa mã độc gián điệp chiếm quyền trợ năng Android.',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Phân tích sandbox phát hiện trojan banking Spynote.',
                },
                {
                    'reporter': user_objs['tran_thi_mai'],
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
                    'reporter': user_objs['nguyen_van_an'],
                    'target_type': TargetType.MESSAGE,
                    'target_value': 'VIETTEL_KM SMS Phishing',
                    'scam_type': ScamType.PHISHING,
                    'severity': Severity.HIGH,
                    'description': 'Nhận SMS mang tên VIETTEL_KM thông báo đổi 10.000 điểm lấy 500k thẻ cào, dẫn link vào viettel-diemthuong.vip để đánh cắp tài khoản ngân hàng.',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'SMS phát tán qua trạm BTS giả.',
                },
                {
                    'reporter': user_objs['le_hoang_nam'],
                    'target_type': TargetType.ACCOUNT,
                    'target_value': 'TCB: 19038291823019',
                    'scam_type': ScamType.INVESTMENT_SCAM,
                    'severity': Severity.CRITICAL,
                    'description': 'Sàn giao dịch vàng và ngoại hối ảo Forex cam kết sinh lời 25%/tháng. Khi yêu cầu rút vốn thì đòi nộp thuế thu nhập 10% trước.',
                    'scammer_bank_account': '19038291823019',
                    'scammer_bank_name': 'Techcombank',
                    'scammer_name': 'CT TNHH TU VAN TM DAU TU',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Pháp nhân ma, tài khoản có dấu hiệu rửa tiền.',
                },
                {
                    'reporter': user_objs['tran_thi_mai'],
                    'target_type': TargetType.PHONE,
                    'target_value': '0981726354',
                    'scam_type': ScamType.DELIVERY_SCAM,
                    'severity': Severity.MEDIUM,
                    'description': 'Người tự xưng shipper giao hàng đơn Shopee 180.000đ, tôi nhờ hàng xóm nhận hộ và chuyển khoản xong thì mở ra bên trong chỉ có giấy vụn.',
                    'scammer_phone': '0981726354',
                    'scammer_name': 'Shipper lừa đảo',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Lừa đảo giao đơn hàng 0 đồng (COD scam).',
                },
                {
                    'reporter': user_objs['le_hoang_nam'],
                    'target_type': TargetType.QR,
                    'target_value': 'Mã QR quishing dán đè tại quán trà sữa Xuân Thủy',
                    'scam_type': ScamType.PHISHING,
                    'severity': Severity.HIGH,
                    'description': 'Mã QR thanh toán bàn ăn bị dán đè một lớp decal mỏng. Khi quét dẫn tới trang web giả mạo acb-online-verify.net thu thập thông tin thẻ.',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Phishing QR code (Quishing). Đã cảnh báo cho cơ sở kinh doanh.',
                },
                {
                    'reporter': user_objs['nguyen_van_an'],
                    'target_type': TargetType.PHONE,
                    'target_value': '02899981234',
                    'scam_type': ScamType.POLICE_IMPERSONATION,
                    'severity': Severity.CRITICAL,
                    'description': 'Cuộc gọi tự xưng điều tra viên Viện Kiểm sát Nhân dân Tối cao dọa phong tỏa tài sản liên quan đường dây buôn lậu, bắt chuyển 50 triệu tiền bảo chứng.',
                    'scammer_phone': '02899981234',
                    'scammer_name': 'Viện kiểm sát giả mạo',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'VoIP Caller ID Spoofing đầu số bàn TP.HCM.',
                },
                {
                    'reporter': user_objs['tran_thi_mai'],
                    'target_type': TargetType.EMAIL,
                    'target_value': 'billing-support@netfIix-billing-security.com',
                    'scam_type': ScamType.PHISHING,
                    'severity': Severity.MEDIUM,
                    'description': 'Email giả mạo Netflix báo tài khoản bị khóa do lỗi thẻ tín dụng, yêu cầu nhập số thẻ và mã CVV tại link netflix-update-billing.cc.',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Email phishing credential harvesting.',
                },
                {
                    'reporter': user_objs['le_hoang_nam'],
                    'target_type': TargetType.ACCOUNT,
                    'target_value': 'VPB: 1582910482',
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
                    'reporter': user_objs['nguyen_van_an'],
                    'target_type': TargetType.MESSAGE,
                    'target_value': 'Tin nhắn Facebook Security Team',
                    'scam_type': ScamType.OTP_STEAL,
                    'severity': Severity.HIGH,
                    'description': 'Tin nhắn từ page giả thông báo tài khoản vi phạm bản quyền cộng đồng, yêu cầu click link và nhập mã 2FA để kháng nghị.',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Chiếm quyền fanpage/tài khoản Facebook.',
                },
                {
                    'reporter': user_objs['tran_thi_mai'],
                    'target_type': TargetType.PHONE,
                    'target_value': '0904819283',
                    'scam_type': ScamType.OTHER,
                    'severity': Severity.MEDIUM,
                    'description': 'Cuộc gọi tự xưng nhân viên điện lực EVN thông báo gia đình nợ tiền điện 4 tháng và sẽ bị cắt điện sau 2 giờ nếu không thanh toán gấp.',
                    'scammer_phone': '0904819283',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Mạo danh EVN đe dọa cắt điện.',
                },
                {
                    'reporter': user_objs['le_hoang_nam'],
                    'target_type': TargetType.EMAIL,
                    'target_value': 'accounting@supplier-vinaconex.com',
                    'scam_type': ScamType.BANK_IMPERSONATION,
                    'severity': Severity.CRITICAL,
                    'description': 'Tấn công email doanh nghiệp (BEC) mạo danh nhà cung cấp thông báo tài khoản BIDV đang kiểm toán, đề nghị thanh toán 145 triệu sang VPBank mới.',
                    'status': ReportStatus.APPROVED,
                    'moderation_note': 'Tấn công BEC chuỗi cung ứng.',
                },
            ]

            report_objs = []
            for r_data in reports_data:
                r = Report.objects.create(
                    reporter=r_data['reporter'],
                    target_type=r_data['target_type'],
                    target_value=r_data['target_value'],
                    scam_type=r_data['scam_type'],
                    severity=r_data['severity'],
                    description=r_data['description'],
                    scammer_phone=r_data.get('scammer_phone', ''),
                    scammer_bank_account=r_data.get('scammer_bank_account', ''),
                    scammer_bank_name=r_data.get('scammer_bank_name', ''),
                    scammer_name=r_data.get('scammer_name', ''),
                    status=r_data['status'],
                    moderator=user_objs['admin_sentinel'],
                    moderation_note=r_data.get('moderation_note', ''),
                )
                report_objs.append(r)

            # 5. Entity Fraud Graph Links
            self.stdout.write("5. Khởi tạo liên kết thực thể (Fraud Knowledge Graph)...")
            if bank_objs and domain_objs:
                EntityLink.objects.create(
                    from_type='account',
                    from_entity_id=bank_objs[0].id,
                    to_type='domain',
                    to_entity_id=domain_objs[0].id,
                    link_reason='shared_report',
                    confidence=0.92,
                )
                EntityLink.objects.create(
                    from_type='account',
                    from_entity_id=bank_objs[1].id,
                    to_type='domain',
                    to_entity_id=domain_objs[3].id,
                    link_reason='shared_text',
                    confidence=0.88,
                )
                EntityLink.objects.create(
                    from_type='account',
                    from_entity_id=bank_objs[3].id,
                    to_type='domain',
                    to_entity_id=domain_objs[4].id,
                    link_reason='ocr_match',
                    confidence=0.95,
                )

            # 6. Community Forum (Posts, Comments, Reactions)
            self.stdout.write("6. Khởi tạo diễn đàn cộng đồng & điểm uy tín...")
            forum_posts_data = [
                {
                    'author': user_objs['chuyen_gia_an_ninh'],
                    'title': 'Cảnh báo khẩn: Chiến dịch phát tán mã độc VNeID giả mạo qua Zalo',
                    'category': ForumCategory.WARNING,
                    'is_pinned': True,
                    'content': """Kính gửi cộng đồng ShieldCall VN,

Trong 48 giờ qua, hệ thống ghi nhận hàng loạt người dân nhận được cuộc gọi từ các số điện thoại lạ tự xưng là Cảnh sát khu vực hoặc cán bộ Công an phường yêu cầu:
1. Hướng dẫn 'kích hoạt định danh mức 2' hoặc 'cập nhật sai sót thông tin căn cước'.
2. Gửi link kết bạn qua Zalo và gửi đường dẫn tải file có đuôi `.apk` (ví dụ: `dichvucong.apk`, `vneid_update.apk`).

⚠️ **CẢNH BÁO KỸ THUẬT**: File APK này sau khi cài đặt sẽ yêu cầu quyền 'Trợ năng' (Accessibility Service). Khi được cấp quyền, mã độc sẽ tự động đọc màn hình, đánh cắp mật khẩu ngân hàng, mã OTP và tự chuyển tiền trong đêm.

Tuyệt đối KHÔNG tải file APK từ Zalo. Công an chỉ hướng dẫn làm trực tiếp tại trụ sở!""",
                },
                {
                    'author': user_objs['tran_thi_mai'],
                    'title': 'Kinh nghiệm cay đắng: Bài học suýt mất 80 triệu vì bẫy CTV giật đơn Shopee',
                    'category': ForumCategory.EXPERIENCE,
                    'is_pinned': False,
                    'content': """Hôm nay em xin viết bài này để cảnh tỉnh mọi người, nhất là các bạn sinh viên và mẹ bỉm sữa đang tìm việc làm thêm online.

Ban đầu em thấy bài tuyển dụng trên Facebook 'Làm việc tại nhà 2-3 tiếng/ngày kiếm 300k'. Khi tham gia, họ cho em vào nhóm Telegram có gần 100 người liên tục khoe ảnh nhận tiền thưởng.
- Đơn 1: nạp 100k -> nhận lại 130k.
- Đơn 2: nạp 500k -> nhận lại 650k.
- Đến đơn thứ 4: họ yêu cầu đơn 18 triệu. Sau khi chuyển xong, họ báo sai cú pháp, yêu cầu nạp thêm đơn đền bù 35 triệu. Lúc đó em bừng tỉnh và dừng lại, may mắn giữ lại được phần lớn số tiền tiết kiệm.

Mong mọi người hãy nhớ: Không có công việc nào chân chính mà bắt ứng viên phải nạp tiền túi của mình trước cả!""",
                },
                {
                    'author': user_objs['le_hoang_nam'],
                    'title': 'Phát hiện mã QR bị dán đè tại quán trà sữa khu vực Cầu Giấy',
                    'category': ForumCategory.WARNING,
                    'is_pinned': False,
                    'content': """Trưa nay em đi uống trà sữa tại một quán trên đường Xuân Thủy. Lúc ra quầy quét mã VietQR dán trên bàn thì thấy app ngân hàng báo lỗi không nhận diện được.
Nhìn kỹ lại thì thấy mép mã QR bị cộm lên. Bóc lớp dán đè ra thì bên dưới là mã chuẩn của quán, còn lớp dán đè dẫn tới trang web giả mạo thanh toán.

Mọi người quét QR ở hàng quán nhớ:
1. Sờ tay kiểm tra xem mã có bị dán đè không.
2. Kiểm tra tên chủ tài khoản người nhận trước khi xác nhận chuyển khoản!""",
                },
                {
                    'author': user_objs['nguyen_van_an'],
                    'title': 'Cần làm gì ngay trong 5 phút đầu khi lỡ nhập thông tin vào trang phishing?',
                    'category': ForumCategory.QUESTION,
                    'is_pinned': False,
                    'content': """Chào các anh chị chuyên gia, em có người bạn vừa lỡ điền tài khoản ngân hàng và mật khẩu vào trang web nhận quà tặng giả mạo. Xin cho em hỏi trong tình huống khẩn cấp này thì thứ tự các bước cần làm ngay lập tức là gì ạ?""",
                },
            ]

            posts = []
            for p_data in forum_posts_data:
                post = ForumPost.objects.create(
                    author=p_data['author'],
                    title=p_data['title'],
                    category=p_data['category'],
                    content=p_data['content'],
                    is_pinned=p_data['is_pinned'],
                    views_count=180,
                )
                posts.append(post)

            # Comments
            c1 = ForumComment.objects.create(
                post=posts[0],
                author=user_objs['nguyen_van_an'],
                content='Cảm ơn chuyên gia! Mẹ em ở quê vừa hôm qua nhận được cuộc gọi y hệt thế này, may mà em đã dặn trước nên bà cúp máy ngay.',
            )
            c2 = ForumComment.objects.create(
                post=posts[0],
                author=user_objs['chuyen_gia_an_ninh'],
                parent=c1,
                content='Rất mừng vì gia đình bạn đã cảnh giác kịp thời! Hãy tiếp tục chia sẻ cho hàng xóm và người thân nhé.',
            )
            c3 = ForumComment.objects.create(
                post=posts[3],
                author=user_objs['chuyen_gia_an_ninh'],
                content="""Quy trình khẩn cấp trong 5 phút vàng:
1. Mở ngay app ngân hàng chính thức trên điện thoại và ĐỔI MẬT KHẨU ngay lập tức.
2. Dùng tính năng 'Khóa thẻ / Khóa tài khoản khẩn cấp' có sẵn trên app.
3. Chuyển tạm toàn bộ số dư sang tài khoản ngân hàng an toàn khác (nếu còn kịp).
4. Gọi ngay hotline tổng đài ngân hàng yêu cầu phong tỏa tài khoản để tra soát.""",
            )

            # Reactions & Likes
            ForumLike.objects.get_or_create(user=user_objs['nguyen_van_an'], post=posts[0])
            ForumLike.objects.get_or_create(user=user_objs['tran_thi_mai'], post=posts[0])
            ForumLike.objects.get_or_create(user=user_objs['le_hoang_nam'], post=posts[0])
            ForumPostReaction.objects.get_or_create(
                user=user_objs['tran_thi_mai'], post=posts[0],
                defaults={'reaction_type': ForumReactionType.HELPFUL}
            )
            ForumPostReaction.objects.get_or_create(
                user=user_objs['le_hoang_nam'], post=posts[0],
                defaults={'reaction_type': ForumReactionType.SHARE}
            )
            ForumCommentLike.objects.get_or_create(user=user_objs['nguyen_van_an'], comment=c3)

            # 7. Educational Content (Article & LearnLesson & Quizzes & Scenarios)
            self.stdout.write("7. Khởi tạo nội dung giáo dục & tình huống tương tác...")
            lesson1 = LearnLesson.objects.create(
                title='Kỹ năng nhận diện và phòng chống cuộc gọi Deepfake AI',
                category=ArticleCategory.GUIDE,
                summary='Hướng dẫn toàn diện cách phân biệt cuộc gọi video deepfake và các biện pháp bảo vệ bản thân khi người thân hỏi mượn tiền gấp.',
                content="""### 1. Bản chất của công nghệ Deepfake trong lừa đảo
Deepfake là công nghệ sử dụng trí tuệ nhân tạo (AI) để hoán đổi khuôn mặt và tái tạo giọng nói của một người dựa trên các hình ảnh, video có sẵn trên mạng xã hội.

### 2. Các dấu hiệu nhận biết cuộc gọi Deepfake
- **Thời lượng cuộc gọi rất ngắn**: Thường chỉ kéo dài từ 5 - 15 giây với lý do 'đang ở chỗ mạng yếu', 'sắp hết pin'.
- **Cử động khuôn mặt thiếu tự nhiên**: Mắt chớp không đều, miệng cử động không khớp khẩu hình tiếng nói.
- **Biến dạng quang học**: Khi người gọi quay nghiêng đầu hoặc đưa tay lên mặt, viền khuôn mặt sẽ bị nhòe hoặc giật hình.

### 3. Nguyên tắc phòng thủ sống còn
- Luôn gọi lại bằng cuộc gọi mạng viễn thông thông thường vào số điện thoại thường ngày của người đó.
- Đặt câu hỏi bảo mật riêng tư mà chỉ người thân trong gia đình mới biết câu trả lời.""",
            )

            LearnQuiz.objects.create(
                lesson=lesson1,
                question='Khi nhận được cuộc gọi video từ người thân mượn tiền gấp có hình ảnh chập chờn, hành động an toàn nhất là gì?',
                question_type=QuizQuestionType.SINGLE,
                options=[
                    {'id': 'A', 'text': 'Chuyển tiền ngay vì đã nhìn thấy mặt người thân trên màn hình.'},
                    {'id': 'B', 'text': 'Ngắt máy và gọi lại bằng cuộc gọi di động thông thường hoặc hỏi câu hỏi bí mật của gia đình.'},
                    {'id': 'C', 'text': 'Chuyển trước một nửa số tiền để giúp đỡ lúc khẩn cấp.'},
                    {'id': 'D', 'text': 'Nhắn tin hỏi số tài khoản qua chính ứng dụng đó.'},
                ],
                correct_answer='B',
                explanation='Tuyệt đối không tin vào hình ảnh video call ngắn ngủi. Cần xác minh độc lập qua cuộc gọi viễn thông hoặc câu hỏi bí mật riêng tư.',
            )

            LearnScenario.objects.create(
                lesson=lesson1,
                title='Tình huống: Cuộc gọi video vay tiền lúc 22h đêm',
                description='Bạn nhận được cuộc gọi video Messenger từ tài khoản của bạn thân hỏi mượn 20 triệu đồng đóng viện phí.',
                content={
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
            )

            lesson2 = LearnLesson.objects.create(
                title='Quyết định 2345/QĐ-NHNN và lá chắn Sinh trắc học tài khoản',
                category=ArticleCategory.ALERT,
                summary='Tìm hiểu tại sao xác thực khuôn mặt khớp với chip CCCD là biện pháp triệt tiêu các tài khoản ngân hàng rác lừa đảo.',
                content="""Quy định bắt buộc xác thực sinh trắc học khuôn mặt đối với các giao dịch chuyển tiền trên 10 triệu đồng hoặc tổng 20 triệu đồng/ngày đã chính thức đi vào cuộc sống.
Quy định này buộc kẻ gian phải có khuôn mặt sống của chính chủ khớp với cơ sở dữ liệu Bộ Công an, triệt tiêu đường dây mua bán tài khoản rác của sinh viên.""",
            )

            LearnQuiz.objects.create(
                lesson=lesson2,
                question='Quy định xác thực sinh trắc học khi chuyển tiền trên 10 triệu đồng nhằm ngăn chặn điều gì?',
                question_type=QuizQuestionType.SINGLE,
                options=[
                    {'id': 'A', 'text': 'Ngăn chặn người dân rút tiền mặt.'},
                    {'id': 'B', 'text': 'Triệt tiêu việc tội phạm dùng tài khoản ngân hàng rác mua của người khác để tẩu tán tiền lừa đảo.'},
                    {'id': 'C', 'text': 'Tăng phí chuyển khoản của các ngân hàng thương mại.'},
                    {'id': 'D', 'text': 'Làm chậm thời gian giao dịch điện tử.'},
                ],
                correct_answer='B',
                explanation='Xác thực sinh trắc học bắt buộc chính chủ thực hiện, ngăn chặn tội phạm mạng dùng tài khoản mua bán trôi nổi.',
            )

            # 8. Daily Trend Statistics (Past 14 Days)
            self.stdout.write("8. Khởi tạo dữ liệu thống kê xu hướng 14 ngày gần nhất...")
            today = timezone.now().date()
            scam_types_sample = [
                (ScamType.BANK_IMPERSONATION, 45),
                (ScamType.POLICE_IMPERSONATION, 38),
                (ScamType.RECRUITMENT_SCAM, 62),
                (ScamType.INVESTMENT_SCAM, 28),
                (ScamType.DELIVERY_SCAM, 31),
                (ScamType.PHISHING, 55),
            ]

            for day_offset in range(14, -1, -1):
                target_date = today - timedelta(days=day_offset)
                multiplier = 1.0 + (14 - day_offset) * 0.03  # slight upward trend
                for s_type, base_cnt in scam_types_sample:
                    cnt = int(base_cnt * multiplier) + (day_offset % 5)
                    TrendDaily.objects.update_or_create(
                        date=target_date,
                        region='VN',
                        scam_type=s_type,
                        defaults={'count': cnt}
                    )

            # 9. Announcements
            self.stdout.write("9. Khởi tạo thông báo hệ thống...")
            ann = Announcement.objects.create(
                author=user_objs['admin_sentinel'],
                title='Cập nhật hệ thống: Ra mắt tính năng phân tích bẫy lừa đảo Quishing & Deepfake',
                content='ShieldCall VN vừa cập nhật cơ chế phân tích trí tuệ nhân tạo thế hệ mới, hỗ trợ nhận diện mã QR độc hại và đánh giá rủi ro đa kênh.',
                is_pinned=True,
                views_count=320,
                likes_count=45,
            )
            AnnouncementReaction.objects.create(
                user=user_objs['nguyen_van_an'],
                announcement=ann,
                reaction_type='helpful'
            )

            # 10. Support Tickets
            self.stdout.write("10. Khởi tạo vé hỗ trợ kỹ thuật...")
            SupportTicket.objects.create(
                author=user_objs['tran_thi_mai'],
                title='Đề xuất bổ sung kiểm tra số tài khoản ngân hàng số Cake by VPBank',
                description='Em thấy hiện tại hệ thống chưa có tùy chọn ngân hàng Cake, mong ban quản trị bổ sung thêm ạ.',
                category='feature',
                priority=SupportTicket.TicketPriority.MEDIUM,
                status=SupportTicket.TicketStatus.RESOLVED,
                admin_reply='Cảm ơn bạn! Đội ngũ phát triển đã cập nhật danh sách ngân hàng số bao gồm Cake, Timo, Viettel Money trong bản cập nhật hôm nay.',
                replied_by=user_objs['admin_sentinel'],
                resolved_at=timezone.now(),
            )
            SupportTicket.objects.create(
                author=user_objs['le_hoang_nam'],
                title='Báo cáo lỗi: Hình ảnh chứng cứ dạng HEIC từ iPhone tải lên bị chậm',
                description='Khi em tải ảnh chụp màn hình định dạng HEIC từ iPhone 15 thì mất khoảng 5 giây để xử lý OCR.',
                category='bug',
                priority=SupportTicket.TicketPriority.LOW,
                status=SupportTicket.TicketStatus.IN_PROGRESS,
            )

        self.stdout.write(self.style.SUCCESS("=== KHỞI TẠO DỮ LIỆU MẪU HOÀN TẤT THÀNH CÔNG! ==="))
