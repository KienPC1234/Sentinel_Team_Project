"""
Seed kho tri thức Việt Nam cho RAG từ nguồn báo đài & cơ quan chức năng.

- Tạo/cập nhật Article (+ vài LearnLesson) với nội dung thực tế về phòng chống lừa đảo,
  kèm khối "Nguồn tham khảo" trỏ tới báo chí & cổng thông tin chính thức.
- Hỗ trợ ảnh: nếu có ảnh tại `static/knowledge_images/<slug>.(jpg|png|webp)` thì
  gán làm cover_image (sẽ được lưu lên object storage/S3 khi bật).

Chạy:  python manage.py seed_vn_knowledge
Sau đó: rebuild chỉ mục RAG (POST /api/v1/admin/rag/rebuild/ hoặc Celery task).
"""
import os

from django.conf import settings
from django.core.files import File
from django.core.management.base import BaseCommand
from django.utils.text import slugify

from api.core.models import Article, ArticleCategory, LearnLesson

REF_IMG_DIR = os.path.join(settings.BASE_DIR, 'static', 'knowledge_images')

ARTICLES = [
    {
        "title": "Giả danh công an, viện kiểm sát, cơ quan chức năng để lừa đảo",
        "category": ArticleCategory.ALERT,
        "summary": "Đối tượng gọi điện thoại/tin nhắn tự xưng là công an, viện kiểm sát, đe dọa liên quan "
                   "đến án ma túy, rửa tiền… yêu cầu chuyển tiền hoặc cung cấp OTP để 'xác minh'.",
        "content": (
            "Thủ đoạn: Kẻ gian mạo danh cơ quan chức năng (công an, viện kiểm sát, tòa án, ngân hàng) "
            "gọi điện hoặc gửi tin nhắn, tạo hoảng loạn và yêu cầu nạn nhân chuyển tiền vào 'tài khoản tạm giữ' "
            "hoặc cung cấp mã OTP.\n\n"
            "Dấu hiệu nhận biết:\n"
            "- Yêu cầu cung cấp OTP, mật khẩu, mã xác thực hoặc cài ứng dụng lạ.\n"
            "- Đe dọa khóa tài khoản, phong tỏa, bắt giam nếu không làm theo.\n"
            "- Yêu cầu chuyển tiền gấp, giữ bí mật, không nói với người thân.\n\n"
            "Hành động đúng:\n"
            "- TUYỆT ĐỐI không cung cấp OTP/mật khẩu, không cài app theo yêu cầu.\n"
            "- Không chuyển tiền. Ngắt cuộc gọi và xác minh qua kênh chính thức.\n"
            "- Gọi 113 (công an) hoặc tổng đài quốc gia 156 để trình báo.\n\n"
            "Nguồn tham khảo:\n"
            "- Cục An toàn thông tin: https://canhbao.ncsc.gov.vn\n"
            "- Tổng đài quốc gia phòng chống lừa đảo: https://khonggianmang.vn\n"
            "- Bộ Công an: https://bocongan.gov.vn"
        ),
    },
    {
        "title": "Cảnh báo SMS Brandname giả & link lạ (phishing)",
        "category": ArticleCategory.ALERT,
        "summary": "Tin nhắn mạo danh thương hiệu ngân hàng/tổ chức, kèm link lạ yêu cầu 'xác thực', "
                   "'khóa tài khoản', 'nhận thưởng'.",
        "content": (
            "Kẻ gian lợi dụng Brandname/SMS giả hoặc tin nhắn từ số lạ để dẫn dụ người dùng bấm vào "
            "tên miền mạo danh (ví dụ ngân hàng nhưng đuôi .net/.xyz).\n\n"
            "Dấu hiệu:\n"
            "- Tên miền nhìn 'giống' nhưng khác tên miền chính thức.\n"
            "- Nội dung giục giã, yêu cầu đăng nhập lại ngay.\n\n"
            "Hành động:\n"
            "- Không bấm link. Tự mở app/truy cập tên miền chính thức bằng tay.\n"
            "- Kiểm tra tên miền bằng công cụ quét của ShieldCall.\n\n"
            "Nguồn tham khảo:\n"
            "- Cục An toàn thông tin: https://canhbao.ncsc.gov.vn\n"
            "- VnExpress (an ninh mạng): https://vnexpress.net\n"
            "- Tuổi Trẻ: https://tuoitre.vn"
        ),
    },
    {
        "title": "Hướng dẫn bảo vệ tài khoản ngân hàng và mã OTP",
        "category": ArticleCategory.GUIDE,
        "summary": "Nguyên tắc vàng: OTP là chìa khóa tài khoản — không chia sẻ cho bất kỳ ai, "
                   "kể cả người tự xưng là nhân viên ngân hàng.",
        "content": (
            "Ngân hàng KHÔNG bao giờ gọi/yêu cầu bạn đọc OTP, mật khẩu, số thẻ đầy đủ.\n\n"
            "Khuyến nghị:\n"
            "- Bật xác thực 2 lớp (2FA), sinh trắc học.\n"
            "- Đặt hạn mức giao dịch online; bật thông báo biến động số dư.\n"
            "- Chỉ dùng mạng tin cậy, không dùng WiFi công cộng để giao dịch.\n"
            "- Khi nghi ngờ: khóa thẻ ngay trên app, gọi tổng đài ngân hàng.\n\n"
            "Nguồn tham khảo:\n"
            "- Ngân hàng Nhà nước: https://sbv.gov.vn\n"
            "- Thanh Niên (chuyển đổi số): https://thanhnien.vn\n"
            "- Dân Trí (công nghệ): https://dantri.com.vn"
        ),
    },
    {
        "title": "Nhận diện Deepfake & giọng nói giả mạo",
        "category": ArticleCategory.GUIDE,
        "summary": "Deepfake có thể giả hình ảnh, giọng nói của người thân/lãnh đạo để yêu cầu chuyển tiền. "
                   "Cần xác minh bằng kênh thứ hai.",
        "content": (
            "Deepfake dùng AI để tạo video/âm thanh giả chân thực. Kẻ gian gọi video 'người thân' khẩn cấp "
            "đòi tiền, hoặc giả giọng lãnh đạo yêu cầu chuyển khoản.\n\n"
            "Cách phòng tránh:\n"
            "- Bình tĩnh, không chuyển tiền ngay. Gọi lại qua số chính thức đã biết.\n"
            "- Đặt câu hỏi riêng tư chỉ người thật mới biết.\n"
            "- Cảnh giác yêu cầu gấp gáp, bí mật, đổi số tài khoản.\n\n"
            "Nguồn tham khảo:\n"
            "- Cục An toàn thông tin: https://canhbao.ncsc.gov.vn\n"
            "- VTV: https://vtv.vn\n"
            "- VietnamPlus: https://vietnamplus.vn"
        ),
    },
    {
        "title": "Tổng đài 156 và các kênh trình báo lừa đảo chính thức",
        "category": ArticleCategory.NEWS,
        "summary": "Khi nghi bị lừa đảo, trình báo qua kênh chính thức để được hỗ trợ kịp thời: "
                   "156, 113, NCSC, VNCERT/CC.",
        "content": (
            "Danh sách kênh chính thức:\n"
            "- Tổng đài quốc gia phòng chống lừa đảo trực tuyến: 156 (khonggianmang.vn).\n"
            "- Công an khẩn cấp: 113; Cảnh sát hình sự: 069.2342609.\n"
            "- Cục An toàn thông tin: canhbao.ncsc.gov.vn.\n"
            "- VNCERT/CC: 0869 100 001, vncert.vn.\n\n"
            "Khi bị lừa:\n"
            "- Liên hệ ngân hàng khoá tài khoản/thẻ, yêu cầu tra soát.\n"
            "- Lưu bằng chứng (tin nhắn, số tài khoản, giao dịch) và trình báo.\n\n"
            "Nguồn tham khảo:\n"
            "- Không gian mạng VN: https://khonggianmang.vn\n"
            "- Báo Chính phủ: https://baochinhphu.vn"
        ),
    },
    {
        "title": "Lừa đảo 'việc nhẹ lương cao' và đầu tư tiền ảo",
        "category": ArticleCategory.ALERT,
        "summary": "Chiêu trò tuyển dụng/làm thêm online và sàn đầu tư 'lãi khủng' để chiếm đoạt tiền.",
        "content": (
            "Đối tượng dụ nạn nhân tham gia 'việc nhẹ lương cao', đặt cọc, hoặc đầu tư tiền ảo/forex "
            "với lợi nhuận phi thực tế, ban đầu cho rút thử rồi chiếm đoạt.\n\n"
            "Dấu hiệu:\n"
            "- Lợi nhuận cao bất thường, cam kết 'bao lời'.\n"
            "- Yêu cầu nạp tiền/đặt cọc trước; không có hợp đồng/hóa đơn rõ ràng.\n\n"
            "Hành động:\n"
            "- Không nạp tiền. Kiểm tra pháp lý doanh nghiệp/sàn.\n"
            "- Cảnh giác nhóm kín, người lạ mời chào qua Zalo/Telegram.\n\n"
            "Nguồn tham khảo:\n"
            "- Bộ Công an: https://bocongan.gov.vn\n"
            "- Công an nhân dân: https://cand.com.vn\n"
            "- Dân Trí: https://dantri.com.vn"
        ),
    },
    {
        "title": "An toàn khi mua sắm online và thanh toán QR",
        "category": ArticleCategory.GUIDE,
        "summary": "Kiểm tra người bán, đối chiếu thông tin nhận tiền, không quét QR lạ.",
        "content": (
            "Khuyến nghị khi mua sắm online:\n"
            "- Ưu tiên sàn/người bán uy tín, có đánh giá; thanh toán qua kênh có bảo vệ.\n"
            "- Đối chiếu tên chủ tài khoản nhận tiền với người bán; cảnh giác STK cá nhân lạ.\n"
            "- Không quét mã QR không rõ nguồn; kiểm tra nội dung trước khi xác nhận.\n\n"
            "Nguồn tham khảo:\n"
            "- Cục An toàn thông tin: https://canhbao.ncsc.gov.vn\n"
            "- VietnamNet: https://vietnamnet.vn"
        ),
    },
    {
        "title": "Chuyện cảnh giác: Mất tiền vì cung cấp OTP cho 'nhân viên ngân hàng'",
        "category": ArticleCategory.STORY,
        "summary": "Một nạn nhân bị chiếm đoạt tiền sau khi đọc OTP cho kẻ tự xưng nhân viên ngân hàng.",
        "content": (
            "Anh X nhận cuộc gọi tự xưng nhân viên ngân hàng thông báo tài khoản có giao dịch lạ, "
            "yêu cầu đọc OTP để 'hủy giao dịch'. Sau khi đọc OTP, tài khoản bị chuyển tiền.\n\n"
            "Bài học:\n"
            "- Không đọc OTP cho bất kỳ ai.\n"
            "- Khóa thẻ/gọi tổng đài ngân hàng ngay khi nghi ngờ.\n"
            "- Trình báo 156/113 và lưu bằng chứng.\n\n"
            "Nguồn tham khảo:\n"
            "- Thanh Niên: https://thanhnien.vn\n"
            "- Tuổi Trẻ: https://tuoitre.vn"
        ),
    },
    {
        "title": "Giả mạo dịch vụ công, VNeID & 'định danh điện tử'",
        "category": ArticleCategory.ALERT,
        "summary": "Kẻ gian giả danh cán bộ gọi điện/tin nhắn yêu cầu 'cập nhật VNeID', 'định danh điện tử', "
                   "cài app giả hoặc truy cập link giả để chiếm quyền tài khoản.",
        "content": (
            "Thủ đoạn: Giả danh cán bộ công an/phường/xã, thông báo hồ sơ VNeID, căn cước, "
            "định danh điện tử 'bị lỗi', yêu cầu cài ứng dụng ngoài kho ứng dụng để 'cập nhật' "
            "rồi chiếm quyền điều khiển điện thoại, đánh cắp OTP/sinh trắc học.\n\n"
            "Dấu hiệu:\n"
            "- Yêu cầu cài app từ link lạ (APK, file .apk/.ipa) hoặc nhờ cài UltraViewer/AnyDesk.\n"
            "- Yêu cầu cung cấp OTP, mật khẩu VNeID, ảnh căn cước, sinh trắc học.\n"
            "- Giục gấp, đe dọa 'không cập nhật sẽ bị khóa tài khoản/hủy dịch vụ công'.\n\n"
            "Hành động đúng:\n"
            "- Chỉ cài VNeID từ CH Play/App Store; không cài từ link/file nhận được.\n"
            "- Không đọc OTP, không quét khuôn mặt/chia sẻ mật khẩu cho người khác.\n"
            "- Ra trực tiếp công an phường/xã hoặc Cổng Dịch vụ công để được hỗ trợ.\n\n"
            "Nguồn tham khảo:\n"
            "- Cổng Dịch vụ công Quốc gia: https://dichvucong.gov.vn\n"
            "- Cục An toàn thông tin: https://canhbao.ncsc.gov.vn\n"
            "- Bộ Công an: https://bocongan.gov.vn"
        ),
    },
    {
        "title": "Lừa đảo tình cảm (romance) & 'quà tặng từ nước ngoài'",
        "category": ArticleCategory.ALERT,
        "summary": "Kẻ gian kết bạn, xây dựng tình cảm qua mạng rồi dụ chuyển tiền, đóng 'phí hải quan' "
                   "cho quà tặng, hoặc mời đầu tư chung.",
        "content": (
            "Đối tượng tạo hình ảnh 'người thành đạt/ở nước ngoài', nhắn tin hàng ngày để lấy lòng tin, "
            "sau đó nhờ nhận hộ quà/bưu phẩm rồi yêu cầu đóng 'phí hải quan', 'phí phạt', hoặc rủ đầu tư.\n\n"
            "Dấu hiệu:\n"
            "- Người lạ chủ động nhắn tin, tiến triển tình cảm nhanh, tránh gặp mặt/gọi video.\n"
            "- Thông báo có quà/bưu phẩm bị giữ ở hải quan, cần nộp phí để nhận.\n\n"
            "Hành động:\n"
            "- Không chuyển bất kỳ khoản tiền nào để 'nhận quà' hay 'làm thủ tục'.\n"
            "- Không có chuyện hải quan thu phí qua tài khoản cá nhân.\n\n"
            "Nguồn tham khảo:\n"
            "- Cục An toàn thông tin: https://canhbao.ncsc.gov.vn\n"
            "- Người Lao Động: https://nld.com.vn"
        ),
    },
    {
        "title": "Sàn đầu tư 'quốc tế', forex, tiền ảo: lãi khủng, rút không được",
        "category": ArticleCategory.ALERT,
        "summary": "Sàn/ứng dụng đầu tư tự xưng lợi nhuận cao, cho rút thử vài lần rồi khóa tài khoản, "
                   "đòi 'nộp thuế/phí' mới cho rút.",
        "content": (
            "Đối tượng mời tham gia sàn forex/chứng khoán quốc tế/tiền ảo qua quảng cáo hoặc nhóm Zalo/Telegram, "
            "cam kết lợi nhuận cao. Ban đầu cho rút một khoản nhỏ tạo niềm tin, sau đó khóa/đòi nộp phí, thuế.\n\n"
            "Dấu hiệu:\n"
            "- Cam kết 'bao lời', lợi nhuận cao bất thường, có 'chuyên gia' hướng dẫn.\n"
            "- Không tra cứu được pháp lý; website/sàn không rõ đơn vị vận hành.\n"
            "- Yêu cầu nộp thêm 'thuế', 'phí mở khóa' khi rút.\n\n"
            "Hành động:\n"
            "- Không nạp thêm tiền. Tra cứu pháp lý doanh nghiệp/sàn trên Cổng thông tin quốc gia về đăng ký doanh nghiệp.\n"
            "- Cảnh giác tham gia đầu tư qua người lạ/người quen mới trên mạng.\n\n"
            "Nguồn tham khảo:\n"
            "- Bộ Công an: https://bocongan.gov.vn\n"
            "- Cổng thông tin Chính phủ: https://chinhphu.vn\n"
            "- ICTNews: https://ictnews.vn"
        ),
    },
    {
        "title": "Giả danh Bảo hiểm xã hội / hoàn thuế để chiếm tiền",
        "category": ArticleCategory.ALERT,
        "summary": "Gọi/tin nhắn giả danh BHXH, thuế: 'cập nhật sổ BHXH', 'hoàn thuế', 'truy thu' "
                   "yêu cầu cung cấp thông tin/cài app/chuyển tiền.",
        "content": (
            "Kẻ gian giả danh cán bộ BHXH/thuế, thông báo hoàn thuế, trợ cấp, cập nhật sổ BHXH và "
            "yêu cầu cung cấp CCCD, số tài khoản, cài app giả hoặc chuyển khoản 'phí'.\n\n"
            "Dấu hiệu:\n"
            "- Yêu cầu cung cấp CCCD/OTP, cài ứng dụng ngoài, hoặc đóng phí trước.\n"
            "- Link/tên miền không phải của cơ quan nhà nước.\n\n"
            "Hành động:\n"
            "- Tra cứu trên ứng dụng/cổng chính thức: VssID, dichvucong.gov.vn, thuedientu.gdt.gov.vn.\n"
            "- Liên hệ tổng đài chính thức của cơ quan (không gọi lại số trên tin nhắn).\n\n"
            "Nguồn tham khảo:\n"
            "- Bảo hiểm xã hội Việt Nam: https://bhxh.gov.vn\n"
            "- Tổng cục Thuế: https://gdt.gov.vn\n"
            "- Báo Chính phủ: https://baochinhphu.vn"
        ),
    },
    {
        "title": "Lừa đảo giao hàng, shipper & 'hoàn tiền đơn hàng'",
        "category": ArticleCategory.ALERT,
        "summary": "Giả danh shipper/sàn TMĐT đòi phí giao hàng, phí lưu kho, hoặc hướng dẫn "
                   "'hoàn tiền đơn lỗi' để lấy OTP/tài khoản.",
        "content": (
            "Kẻ gian giả shipper gọi báo có đơn hàng/đòi phí, hoặc giả nhân viên sàn hướng dẫn "
            "'hoàn tiền đơn hàng lỗi' và yêu cầu truy cập link, đọc OTP, cài app.\n\n"
            "Dấu hiệu:\n"
            "- Yêu cầu thanh toán vào tài khoản cá nhân, không phải kênh của sàn/đơn vị giao hàng.\n"
            "- Yêu cầu cung cấp OTP/mật khẩu để 'nhận hoàn tiền'.\n\n"
            "Hành động:\n"
            "- Tra đơn hàng trực tiếp trong app sàn; không bấm link trong tin nhắn.\n"
            "- Hoàn tiền thật diễn ra trong app, không cần OTP qua điện thoại.\n\n"
            "Nguồn tham khảo:\n"
            "- Cục An toàn thông tin: https://canhbao.ncsc.gov.vn\n"
            "- Tiền Phong: https://tienphong.vn"
        ),
    },
    {
        "title": "Bị chiếm tài khoản mạng xã hội rồi nhắn vay tiền người thân",
        "category": ArticleCategory.ALERT,
        "summary": "Tài khoản Facebook/Zalo bị hack, kẻ gian mạo danh chủ tài khoản nhắn tin vay tiền, "
                   "nhờ chuyển khoản gấp.",
        "content": (
            "Sau khi chiếm tài khoản, kẻ gian nhắn tin cho bạn bè/người thân của chủ tài khoản để vay tiền "
            "hoặc nhờ chuyển khoản gấp, thường kèm ảnh/số tài khoản lạ.\n\n"
            "Dấu hiệu:\n"
            "- Nhắn tin vay tiền gấp, đổi số tài khoản, tránh gọi điện trực tiếp.\n"
            "- Văn phong khác thường so với người thật.\n\n"
            "Hành động:\n"
            "- Xác minh bằng cách gọi trực tiếp cho người đó qua số đã biết.\n"
            "- Không chuyển tiền theo tin nhắn mạng xã hội.\n"
            "- Bật xác thực 2 lớp cho tài khoản mạng xã hội.\n\n"
            "Nguồn tham khảo:\n"
            "- Cục An toàn thông tin: https://canhbao.ncsc.gov.vn\n"
            "- An ninh Thủ đô: https://anninhthudo.vn"
        ),
    },
    {
        "title": "Vay tiền qua app (tín dụng đen) và vòng xoáy đòi nợ",
        "category": ArticleCategory.ALERT,
        "summary": "App vay 'online nhanh' lãi cắt cổ, đòi nợ kiểu khủng bố, xâm phạm dữ liệu "
                   "người thân sau khi cấp quyền danh bạ.",
        "content": (
            "Các app vay mạo danh/không phép cho vay nhanh với lãi suất thực tế rất cao, thu thập danh bạ "
            "rồi đòi nợ bằng cách nhắn/gọi cho người thân, đăng ảnh ghép.\n\n"
            "Dấu hiệu:\n"
            "- Yêu cầu cấp quyền danh bạ, ảnh, tin nhắn; phí/phạt cắt cổ.\n"
            "- Đe dọa, làm nhục nếu chưa trả.\n\n"
            "Hành động:\n"
            "- Không vay qua app không rõ pháp lý; chỉ vay tại tổ chức tín dụng được cấp phép.\n"
            "- Nếu bị đòi nợ kiểu khủng bố: lưu bằng chứng, trình báo công an; hủy quyền truy cập danh bạ.\n\n"
            "Nguồn tham khảo:\n"
            "- Ngân hàng Nhà nước: https://sbv.gov.vn\n"
            "- Bộ Công an: https://bocongan.gov.vn"
        ),
    },
    {
        "title": "Bảo vệ trẻ em và người cao tuổi trên không gian mạng",
        "category": ArticleCategory.GUIDE,
        "summary": "Trẻ em và người cao tuổi là nhóm dễ bị nhắm tới; cần giám sát, đặt quy tắc "
                   "và biết kênh hỗ trợ (tổng đài 111).",
        "content": (
            "Người cao tuổi thường bị nhắm qua cuộc gọi mạo danh; trẻ em bị dụ nạp thẻ game, "
            "gửi ảnh nhạy cảm, bắt nạt/đe dọa trên mạng.\n\n"
            "Khuyến nghị cho gia đình:\n"
            "- Đặt quy tắc: người lớn xác nhận trước mọi giao dịch/chuyển tiền.\n"
            "- Bật kiểm soát của phụ huynh, giới hạn chi tiêu trong game.\n"
            "- Dạy trẻ không chia sẻ ảnh/thông tin cá nhân, không gặp người lạ qua mạng.\n\n"
            "Kênh hỗ trợ:\n"
            "- Tổng đài Quốc gia Bảo vệ Trẻ em: 111.\n"
            "- Khẩn cấp: 113; phòng chống lừa đảo: 156.\n\n"
            "Nguồn tham khảo:\n"
            "- Tổng đài 111: https://tongdai111.vn\n"
            "- Cục An toàn thông tin: https://canhbao.ncsc.gov.vn"
        ),
    },
    {
        "title": "Đã bị lừa rồi phải làm gì? Quy trình xử lý trong 'giờ vàng'",
        "category": ArticleCategory.GUIDE,
        "summary": "Hành động càng nhanh càng tăng cơ hội thu hồi tiền: khóa thẻ/tài khoản, "
                   "trình báo ngân hàng & công an, lưu bằng chứng.",
        "content": (
            "Các bước ưu tiên ngay sau khi phát hiện bị lừa:\n"
            "1. Gọi ngay tổng đài ngân hàng/ví để KHÓA thẻ/tài khoản, yêu cầu tra soát giao dịch.\n"
            "2. Thu thập & lưu bằng chứng: tin nhắn, số tài khoản nhận tiền, biên lai, ảnh chụp.\n"
            "3. Trình báo công an (113 hoặc công an địa phương) và tổng đài 156.\n"
            "4. Không chuyển thêm tiền 'để gỡ' — đó là lừa đảo lần hai.\n"
            "5. Đổi mật khẩu, bật 2FA các tài khoản liên quan.\n\n"
            "Lưu ý: giữ bình tĩnh, không xóa tin nhắn/lịch sử giao dịch.\n\n"
            "Nguồn tham khảo:\n"
            "- Không gian mạng VN: https://khonggianmang.vn\n"
            "- Báo Công an nhân dân: https://cand.com.vn"
        ),
    },
    {
        "title": "Cách kiểm tra doanh nghiệp, sàn, người bán trước khi xuống tiền",
        "category": ArticleCategory.GUIDE,
        "summary": "Tra cứu pháp lý doanh nghiệp, đối chiếu tên chủ tài khoản, kiểm tra website "
                   "và đánh giá cộng đồng trước khi chuyển tiền/đầu tư.",
        "content": (
            "Trước khi đầu tư/mua hàng/đặt cọc, hãy kiểm tra:\n"
            "- Pháp lý doanh nghiệp trên Cổng thông tin quốc gia về đăng ký doanh nghiệp.\n"
            "- Tên chủ tài khoản nhận tiền có khớp với người bán/công ty không.\n"
            "- Website: tuổi tên miền, chứng chỉ SSL, thông tin liên hệ rõ ràng.\n"
            "- Đánh giá/ khiếu nại của người dùng khác; cảnh giác 'lợi nhuận cam kết'.\n\n"
            "Dùng công cụ quét của ShieldCall để kiểm tra URL/SĐT/STK trước khi giao dịch.\n\n"
            "Nguồn tham khảo:\n"
            "- Cổng thông tin Chính phủ: https://chinhphu.vn\n"
            "- Cục An toàn thông tin: https://canhbao.ncsc.gov.vn"
        ),
    },
]


class Command(BaseCommand):
    help = "Seed kho tri thức VN (báo đài & cơ quan chức năng) cho RAG."

    def add_arguments(self, parser):
        parser.add_argument('--lessons', action='store_true', help="Cũng tạo LearnLesson tương ứng.")

    def _attach_cover(self, obj, slug):
        for ext in ('jpg', 'jpeg', 'png', 'webp'):
            p = os.path.join(REF_IMG_DIR, f"{slug}.{ext}")
            if os.path.exists(p):
                with open(p, 'rb') as fh:
                    obj.cover_image.save(f"{slug}.{ext}", File(fh), save=True)
                self.stdout.write(f"  + ảnh: {p}")
                return True
        return False

    def handle(self, *args, **opts):
        created = updated = 0
        for item in ARTICLES:
            slug = slugify(item['title'])[:350]
            obj, is_new = Article.objects.get_or_create(
                slug=slug,
                defaults={
                    'title': item['title'], 'summary': item['summary'],
                    'content': item['content'], 'category': item['category'], 'is_published': True,
                },
            )
            if is_new:
                created += 1
            else:
                obj.title = item['title']
                obj.summary = item['summary']
                obj.content = item['content']
                obj.category = item['category']
                obj.is_published = True
                obj.save()
                updated += 1
            self._attach_cover(obj, slug)
            self.stdout.write(f"  ✓ [{item['category']}] {item['title'][:60]}")

            if opts.get('lessons') and is_new:
                LearnLesson.objects.get_or_create(
                    slug=slug[:350],
                    defaults={
                        'title': item['title'], 'summary': item['summary'],
                        'content': item['content'], 'category': item['category'], 'is_published': True,
                    },
                )

        self.stdout.write(self.style.SUCCESS(
            f"Hoàn tất: {created} bài mới, {updated} cập nhật. "
            "Hãy rebuild chỉ mục RAG để đưa vào kho tri thức."
        ))
