#!/usr/bin/env python3
"""
Script to enrich short learning articles and lessons with comprehensive,
authoritative cybersecurity content, complete with structured Markdown,
action checklists, technical explanations, red flags, and hotline references.
Also attaches quizzes and scenarios to Lessons 24-27.
"""

import os
import sys
import django

# Setup Django environment
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'PKV.settings')
django.setup()

from api.core.models import Article, LearnLesson, LearnQuiz, LearnScenario
from django.db import transaction

# -----------------------------------------------------------------------------
# ENRICHMENT DATA
# -----------------------------------------------------------------------------

LESSONS_ENRICHMENT = {
    24: {
        "title": "Kỹ năng nhận diện và phòng chống thủ đoạn giả danh Cơ quan thực thi pháp luật",
        "summary": "Phân tích toàn diện thủ đoạn giả danh công an, viện kiểm sát, tòa án đe dọa khởi tố để lừa đảo chiếm đoạt tài sản và quy trình ứng phó theo đúng quy định pháp luật.",
        "content": """## I. Bản chất và Kỹ thuật thao túng của tội phạm

Giả danh cơ quan thực thi pháp luật (Công an, Viện kiểm sát, Tòa án, Thanh tra giao thông) là một trong những hình thức lừa đảo gây thiệt hại tài chính nặng nề nhất tại Việt Nam. Kẻ gian thường đánh vào hai điểm yếu tâm lý phổ biến: **nỗi sợ hãi vướng vào vòng lao lý** và **sự thiếu hiểu biết về quy trình tố tụng hình sự**.

Đối tượng sử dụng công nghệ giả mạo số điện thoại (Caller ID Spoofing / VoIP) để hiển thị số gọi đến giống với số máy bàn của cơ quan công an hoặc tổng đài cơ quan nhà nước.

![Cơ quan thực thi pháp luật làm việc theo đúng quy trình quy định](https://images.unsplash.com/photo-1589829545856-d10d557cf95f?auto=format&fit=crop&w=1200&q=80)

---

## II. Kịch bản thao túng tâm lý 4 giai đoạn điển hình

1. **Giai đoạn 1 - Kích động hoang mang:**
   Kẻ gian xưng là cán bộ công an hoặc viện kiểm sát, thông báo số CMND/CCCD hoặc số điện thoại của nạn nhân đang liên quan trực tiếp đến một đường dây tội phạm xuyên quốc gia (rửa tiền, buôn bán ma túy, lừa đảo ngân hàng).
2. **Giai đoạn 2 - Tạo dựng chứng cứ giả mạo:**
   Đối tượng gửi hình ảnh các tài liệu pháp lý giả mạo qua Zalo, Telegram hoặc hướng dẫn nạn nhân truy cập các website mạo danh (như `congan.gov-vn.xyz`) có hiển thị "Lệnh bắt tạm giam", "Lệnh phong tỏa tài sản" có đóng dấu đỏ và chữ ký giả mạo của lãnh đạo ngành công an/VKS.
3. **Giai đoạn 3 - Cách ly xã hội nạn nhân:**
   Yêu cầu nạn nhân phải tuyệt đối giữ bí mật "nguyên tắc điều tra", không được kể cho bất kỳ ai, thậm chí yêu cầu nạn nhân thuê phòng khách sạn riêng hoặc tắt định vị để "lấy lời khai trực tuyến".
4. **Giai đoạn 4 - Chiếm đoạt tài sản:**
   Yêu cầu nạn nhân chuyển toàn bộ tiền tiết kiệm vào một "Tài khoản tạm giữ của Ban chuyên án" để cơ quan điều tra thanh tra nguồn tiền, cam kết "sau 2-24 giờ kiểm tra nếu trong sạch sẽ hoàn trả lại 100%". Ngay khi tiền vào tài khoản, kẻ gian lập tức chia nhỏ và tẩu tán qua mạng lưới tài khoản rác.

---

## III. 5 Nguyên tắc pháp lý bắt buộc phải ghi nhớ

Theo Bộ luật Tố tụng hình sự Việt Nam:

| Tiêu chí | Cơ quan chức năng thực tế | Kẻ lừa đảo mạo danh |
| :--- | :--- | :--- |
| **Hình thức làm việc** | Bằng văn bản giấy triệu tập/giấy mời gửi trực tiếp hoặc qua Công an phường/xã | Gọi điện thoại, nhắn tin qua Zalo, Telegram |
| **Địa điểm làm việc** | Trụ sở cơ quan Công an, Viện kiểm sát có ghi rõ địa chỉ | Gọi video call, yêu cầu thuê phòng khách sạn |
| **Yêu cầu tài chính** | KHÔNG BAO GIỜ yêu cầu chuyển tiền vào tài khoản để chứng minh trong sạch | Bắt buộc chuyển tiền vào tài khoản chỉ định để "bảo lưu / tạm giữ" |
| **Văn bản tố tụng** | Tống đạt trực tiếp có ký nhận biên bản | Gửi ảnh chụp qua mạng xã hội |
| **Mật mã ngân hàng** | Tuyệt đối không can thiệp vào tài khoản ngân hàng | Đòi hỏi mật khẩu, OTP hoặc mã Smart OTP |

---

## IV. Quy trình ứng phó khẩn cấp khi nhận cuộc gọi nghi vấn

1. **Giữ bình tĩnh và ngắt máy ngay lập tức:** Không tranh cãi, không giải thích hay phân bua. Cơ quan công an chân chính không làm việc qua điện thoại.
2. **Xác minh độc lập:** Đến trực tiếp Công an phường/xã nơi cư trú hoặc gọi điện đến trực ban Công an quận/huyện để trình báo và nhờ xác minh.
3. **Tuyệt đối không chuyển tiền:** Không bấm vào bất kỳ đường link nào được gửi qua tin nhắn hay ứng dụng chat.
4. **Báo cáo sự việc:**
   - Tổng đài tiếp nhận phản ánh cuộc gọi rác, lừa đảo: **156** hoặc gửi tin nhắn miễn phí cú pháp `V [Nội dung cuộc gọi/số điện thoại]` gửi **156**.
   - Trực ban Cục Cảnh sát hình sự: **069.2348560**.
   - Báo cáo địa chỉ lừa đảo đến Cục An toàn thông tin: `https://canhbao.ncsc.gov.vn`.
""",
    },
    25: {
        "title": "Chuyên đề: Cảnh báo SMS Brandname giả mạo & Tấn công trạm BTS giả",
        "summary": "Phân tích cơ chế kỹ thuật trạm BTS giả mạo chèn sóng 2G để phát tán tin nhắn mang tên thương hiệu ngân hàng chính hãng và các giải pháp phòng vệ trên thiết bị di động.",
        "content": """## I. Cơ chế kỹ thuật của trạm BTS giả mạo (Fake BTS / IMSI-Catcher)

Nhiều người dùng băn khoăn: *“Tại sao tin nhắn lừa đảo lại xuất hiện ngay trong cùng một luồng (thread) tin nhắn với thông báo biến động số dư thực tế của ngân hàng?”*

Câu trả lời nằm ở cơ chế hoạt động của mạng viễn thông thế hệ cũ (2G GSM):
1. **Thiếu cơ chế xác thực hai chiều trên sóng 2G:** Trạm phát sóng di động 2G không yêu cầu xác thực tính hợp pháp đối với thiết bị đầu cuối. Kẻ gian mang theo thiết bị trạm thu phát di động giả mạo kích thước nhỏ (đặt trên ô tô, xe máy di chuyển quanh khu vực đông dân cư).
2. **Chèn ép sóng công suất cao:** Trạm BTS giả phát sóng công suất mạnh, gây nhiễu sóng 4G/LTE và buộc các điện thoại xung quanh phải tự động hạ cấp kết nối (fall back) xuống sóng 2G của trạm giả.
3. **Mạo danh Header Brandname:** Khi điện thoại kết nối vào trạm giả, thiết bị giả phát tán hàng loạt tin nhắn SMS với trường thông tin tên người gửi (`Sender ID / Brandname`) được đặt tùy ý: `Vietcombank`, `MBBank`, `Techcombank`, `BIDV`, `VNPT`... Hệ điều hành trên smartphone tự động gom các tin nhắn có cùng chuỗi ký tự Brandname vào chung một cuộc trò chuyện.

![Mô hình tấn công mạo danh sóng viễn thông](https://images.unsplash.com/photo-1544197150-b99a580bb7a8?auto=format&fit=crop&w=1200&q=80)

---

## II. Các dạng kịch bản nội dung SMS lừa đảo phổ biến

- **Cảnh báo bảo mật khẩn cấp:** *"Tai khoan cua ban dang dang nhap tai thiet bi khac. Neu khong phai ban, nhap vao link http://vietcombank-login-sec.xyz de huy giao dich."*
- **Đe dọa khóa tài khoản / trừ phí:** *"Dich vu SmartBanking cua quy khach bi khoa do het han. Vui long cap nhat tai http://bidv-smartbanking.top de tiep tuc su dung."*
- **Nhận tiền quà tặng / hoàn tiền:** *"Chuc mung ban da nhan duoc 1.500.000d tu chuong trinh tri an khach hang. Nhan thuong tai http://mbbank-voucher.com."*

---

## III. Dấu hiệu bóc trần đường link Phishing trong SMS

| Yếu tố | Website Ngân hàng chính thống | Website Lừa đảo Phishing |
| :--- | :--- | :--- |
| **Đuôi tên miền (TLD)** | `.com.vn` hoặc `.vn` đăng ký tại Việt Nam | `.xyz`, `.top`, `.cc`, `.vip`, `.site`, `.fun` |
| **Tên miền phụ (Subdomain)** | `vietcombank.com.vn` | `vietcombank.com.vn.online-sec.xyz` (Tên miền thực là `online-sec.xyz`) |
| **Giao thức và chứng chỉ** | EV SSL tổ chức được chứng thực rõ ràng | Chứng chỉ Let's Encrypt ẩn danh hoặc không có SSL |
| **Hành vi yêu cầu** | Đăng nhập an toàn, không hỏi mật khẩu khi hủy giao dịch | Bắt buộc nhập Tên đăng nhập, Mật khẩu, OTP SMS / Smart OTP |

---

## IV. Giải pháp phòng ngừa triệt để

1. **Tắt sóng 2G trên smartphone:**
   - Trên **Android (Android 12 trở lên)**: Vào *Cài đặt (Settings)* -> *Mạng & Internet (Network & Internet)* -> *SIM* -> Tắt mục **"Cho phép 2G" (Allow 2G)**.
   - Trên **iOS (iPhone)**: Kích hoạt chế độ Lockdown Mode khi ở khu vực nhạy cảm hoặc bật giới hạn kết nối LTE/5G.
2. **Quy tắc vàng 3 KHÔNG:**
   - KHÔNG bấm vào bất kỳ liên kết nào đính kèm trong tin nhắn SMS, kể cả SMS nằm trong luồng Brandname ngân hàng.
   - KHÔNG nhập mật khẩu ngân hàng hay mã OTP vào bất kỳ website nào mở ra từ tin nhắn.
   - KHÔNG gọi lại số điện thoại ghi trong tin nhắn nghi vấn.
3. **Kênh tra cứu an toàn duy nhất:**
   Chỉ mở ứng dụng Ngân hàng số chính thức đã cài sẵn trên điện thoại hoặc tự gõ địa chỉ trang web chính thống của ngân hàng vào trình duyệt.
""",
    },
    26: {
        "title": "Cẩm nang bảo mật Tài khoản Ngân hàng số, Tiền gửi & Bảo vệ mã OTP",
        "summary": "Hướng dẫn thực chiến bảo vệ tài sản ngân hàng số, tuân thủ Quyết định 2345/QĐ-NHNN về sinh trắc học và các biện pháp ứng phó khi phát hiện tài khoản bị xâm nhập.",
        "content": """## I. Bức tranh toàn cảnh về an toàn tài khoản ngân hàng số

Trong hệ sinh thái ngân hàng trực tuyến hiện đại, kẻ gian không tấn công trực diện vào hệ thống tường lửa của ngân hàng mà tập trung tấn công vào mắt xích yếu nhất: **người sử dụng (User-centric Attacks)**.

Tài sản trong tài khoản của bạn được bảo vệ bởi các lớp phòng ngự:
- **Lớp 1:** Tên đăng nhập và Mật khẩu (Knowledge factor).
- **Lớp 2:** Mã xác thực giao dịch OTP SMS / Smart OTP (Possession factor).
- **Lớp 3:** Xác thực sinh trắc học khuôn mặt / vân tay theo **Quyết định 2345/QĐ-NHNN** (Inherence factor).

Kẻ lừa đảo chỉ cần chiếm được Lớp 1 và Lớp 2 là có thể thực hiện giao dịch chuyển tiền dưới hạn mức sinh trắc học (dưới 10 triệu đồng/giao dịch).

![Bảo mật tài khoản ngân hàng số đa lớp](https://images.unsplash.com/photo-1563986768609-322da13575f3?auto=format&fit=crop&w=1200&q=80)

---

## II. Các phương thức đánh cắp OTP và tài khoản ngân hàng phổ biến

1. **Phishing (Trang web giả mạo):** Lừa nạn nhân tự tay điền mật khẩu và mã OTP vào biểu mẫu web giả mạo ngân hàng.
2. **Malware / Accessibility Service Abuse:** Dụ người dùng cài file APK mã độc (đội lốt phần mềm Thuế, VNeID, Dịch vụ công). Mã độc kích hoạt quyền Hỗ trợ tiếp cận (Accessibility), tự động đọc màn hình, lấy cắp mã Smart OTP và chuyển tiền ngầm trong đêm.
3. **SIM Swap (Hoán đổi SIM):** Giả danh nhân viên viễn thông lừa nâng cấp SIM 4G/5G để chiếm đoạt SIM vật lý, từ đó nhận mã OTP SMS gửi về máy kẻ gian.

---

## III. Danh mục kiểm tra bảo mật tài khoản cá nhân

| Nội dung kiểm tra | Tiêu chuẩn an toàn | Mức độ rủi ro nếu vi phạm |
| :--- | :--- | :--- |
| **Mật khẩu app ngân hàng** | Tối thiểu 12 ký tự, gồm hoa, thường, số, ký tự đặc biệt; không trùng ngày sinh | Rất cao (Dễ bị brute-force hoặc đoán) |
| **Tính độc lập của mật khẩu** | Mật khẩu ngân hàng KHÔNG ĐƯỢC trùng với mật khẩu Facebook, Gmail, Zalo | Cực kỳ nguy hiểm (Dò quét Credential Stuffing) |
| **Kích hoạt Smart OTP** | Sử dụng mã PIN Soft OTP tạo ngay trong app ngân hàng thay vì nhận SMS OTP | Cao (SMS OTP có thể bị nghe lén sóng 2G) |
| **Đăng ký sinh trắc học** | Đã thu thập khuôn mặt khớp dữ liệu CCCD gắn chip theo Quyết định 2345/QĐ-NHNN | An toàn cao cho giao dịch lớn trên 10 triệu |
| **Hạn mức giao dịch ngày** | Cài đặt hạn mức chuyển khoản phù hợp với nhu cầu chi tiêu thực tế | Giảm thiểu tối đa thiệt hại nếu bị lộ tài khoản |

---

## IV. Quy trình xử lý khẩn cấp khi nghi ngờ bị lộ thông tin

Nếu bạn vô tình nhấn link lạ hoặc đã trót điền mật khẩu/OTP:
1. **Khóa thẻ và khóa app cấp tốc:** Mở app ngân hàng bấm tính năng "Khóa thẻ khẩn cấp" hoặc đăng nhập sai mật khẩu 5 lần liên tiếp để hệ thống tự động khóa tài khoản tạm thời.
2. **Gọi hotline khẩn cấp của ngân hàng:** Yêu cầu tổng đài viên khóa toàn bộ dịch vụ ngân hàng điện tử (Internet Banking / Mobile Banking) ngay lập tức.
3. **Bật chế độ máy bay trên điện thoại:** Ngắt ngay Wifi và 4G để ngăn chặn mã độc điều khiển từ xa truyền dữ liệu ra ngoài.
4. **Kiểm tra thiết bị:** Nếu điện thoại có cài file APK lạ, thực hiện khôi phục cài đặt gốc (Factory Reset) sau khi đã sao lưu danh bạ và dữ liệu quan trọng.
""",
    },
    27: {
        "title": "Chuyên đề: Nhận diện thủ đoạn Deepfake AI & Giọng nói giả mạo người thân",
        "summary": "Nhận biết công nghệ Deepfake hoán đổi khuôn mặt và nhân bản giọng nói AI (Voice Cloning) dùng trong các vụ lừa đảo mượn tiền khẩn cấp và cách kiểm chứng xác thực an toàn.",
        "content": """## I. Công nghệ Deepfake và Voice Cloning được tội phạm mạng ứng dụng thế nào?

Trí tuệ nhân tạo tạo sinh (Generative AI) đã đạt đến bước tiến cho phép tái tạo khuôn mặt và bắt chước ngữ điệu giọng nói của bất kỳ ai chỉ từ một đoạn video hoặc ghi âm mẫu rất ngắn (từ 5 đến 15 giây). Kẻ gian thường khai thác video, hình ảnh công khai trên Facebook, TikTok, Instagram của người dùng để huấn luyện mô hình.

Kịch bản điển hình: Kẻ gian chiếm đoạt tài khoản Facebook/Messenger của một người đang sinh sống, làm việc xa nhà hoặc du học sinh, sau đó thực hiện cuộc gọi video ngắn vài giây đến bố mẹ, người thân ở quê để vay tiền cấp bách (tai nạn giao thông, đóng học phí, kẹt tiền hàng).

![Công nghệ Deepfake tái tạo khuôn mặt và giọng nói giả mạo](https://images.unsplash.com/photo-1534972195531-a756b1126f24?auto=format&fit=crop&w=1200&q=80)

---

## II. 6 Dấu hiệu thị giác và thính giác bóc trần cuộc gọi Deepfake

Khi nhận cuộc gọi video từ người thân có nội dung liên quan đến tiền bạc, hãy chú ý quan sát:

1. **Khẩu hình miệng bất thường:** Chuyển động môi và răng không khớp hoàn toàn với ngữ điệu âm thanh phát ra; khẩu hình có cảm giác trễ nhịp hoặc nhòe mờ.
2. **Hiện tượng giật cục khi cử động:** Khi người trong video quay đầu sang một bên hoặc đưa bàn tay lên cào mặt, vuốt tóc, hình ảnh khuôn mặt giả lập sẽ bị méo mó, bóng mờ (ghosting) hoặc xuất hiện các khối pixel biến dạng.
3. **Ánh mắt vô hồn và tần suất chớp mắt:** Mô hình Deepfake thường gặp khó khăn trong việc mô phỏng phản xạ chớp mắt tự nhiên hoặc hướng nhìn của đồng tử không ăn khớp với góc quay camera.
4. **Ánh sáng khuôn mặt không đồng nhất:** Hướng sáng trên gương mặt không tương thích với bối cảnh ánh sáng xung quanh căn phòng.
5. **Thời lượng cuộc gọi cực ngắn:** Kẻ gian thường ngắt cuộc gọi chỉ sau 5-10 giây với lý do *"sóng yếu", "mạng chập chờn", "đang ngồi trong viện/trên máy bay"* rồi chuyển sang nhắn tin văn bản để tránh bị lộ sơ hở.
6. **Âm sắc giọng nói có tiếng kim loại:** Giọng nói nghe có cảm giác rè, phẳng (flat tone), thiếu cảm xúc tự nhiên hoặc có tạp âm xử lý số.

---

## III. Biện pháp đối phó và câu hỏi bẫy kiểm chứng

Khi đối phương yêu cầu chuyển tiền gấp, hãy áp dụng ngay các biện pháp sau:

| Biện pháp | Cách thức thực hiện | Ý nghĩa an toàn |
| :--- | :--- | :--- |
| **Yêu cầu hành động thể chất** | *"Con đưa tay che một bên mắt rồi vẫy tay trước camera xem nào"* | Thuật toán Deepfake thời gian thực sẽ lập tức bị vỡ hình và lộ nguyên hình |
| **Đặt câu hỏi bí mật gia đình** | Hỏi về một kỷ niệm riêng tư, tên món ăn gia đình hay một chi tiết chỉ hai người biết | Kẻ lừa đảo không thể có câu trả lời trong dữ liệu mạng xã hội |
| **Gọi điện thoại thông thường (Cellular Call)** | Cúp máy ứng dụng mạng xã hội, bấm số điện thoại di động SIM vật lý để gọi lại | Kênh viễn thông truyền thống không bị ảnh hưởng bởi việc hack tài khoản Facebook/Zalo |
| **Kiểm tra tài khoản nhận tiền** | Xem tên chủ tài khoản ngân hàng có đúng tên của người thân hay là tên một người hoàn toàn xa lạ | 99% các vụ lừa đảo đều yêu cầu chuyển tiền vào tài khoản trung gian lạ |

---

## IV. Kết luận & Khuyến cáo an toàn số

Tuyệt đối không bao giờ chuyển tiền chỉ dựa trên một tin nhắn hay một cuộc gọi video call trên mạng xã hội. Trong mọi trường hợp có yếu tố chuyển tiền, **xác minh đa kênh (Multi-channel Verification)** là nguyên tắc sống còn bảo vệ tài sản của bạn và gia đình.
""",
    },
}

ARTICLES_ENRICHMENT = {
    21: {
        "title": "Cảnh báo khẩn: Thủ đoạn giả danh công an, viện kiểm sát gọi điện đe dọa khởi tố",
        "summary": "Chi tiết kịch bản lừa đảo mạo danh cán bộ cơ quan tư pháp gọi điện thông báo lệnh bắt tạm giam, yêu cầu chuyển tiền vào tài khoản tạm giữ để chiếm đoạt tài sản.",
        "content": """## I. Toàn cảnh thủ đoạn giả danh cơ quan bảo vệ pháp luật

Thời gian qua, tình trạng người dân nhận được các cuộc gọi mạo danh cán bộ Công an, Viện kiểm sát nhân dân, Tòa án nhân dân diễn biến hết sức phức tạp. Nhiều nạn nhân bị thao túng tâm lý dẫn đến việc chuyển hàng trăm triệu, thậm chí hàng chục tỷ đồng vào các tài khoản ngân hàng rác của các băng nhóm tội phạm xuyên biên giới.

Kẻ gian sử dụng thiết bị viễn thông công nghệ cao để làm giả số máy gọi đến (Caller ID Spoofing), hiển thị các dãy số giống với số điện thoại công khai của cơ quan nhà nước (như đầu số 024.xxx, 028.xxx).

![Cơ quan tư pháp luôn làm việc bằng văn bản chính thức](https://images.unsplash.com/photo-1589829545856-d10d557cf95f?auto=format&fit=crop&w=1200&q=80)

---

## II. Các bước thao túng tâm lý nạn nhân có tổ chức

1. **Thông báo sai phạm nghiêm trọng:** Đối tượng gọi điện thông báo số tài khoản hoặc thông tin CCCD của nạn nhân bị đối tượng tội phạm lợi dụng để rửa tiền trong chuyên án buôn ma túy lớn, hoặc liên quan đến một vụ án tham nhũng đang chuẩn bị bắt giam.
2. **Tạo sức ép bằng tài liệu giả mạo:** Gửi ảnh chụp "Lệnh bắt tạm giam", "Lệnh phong tỏa tài sản" có con dấu đỏ và tên tuổi chính xác của nạn nhân qua ứng dụng Zalo, Telegram nhằm triệt tiêu khả năng phản kháng.
3. **Yêu cầu giữ bí mật tuyệt đối:** Cấm nạn nhân nói chuyện với gia đình, người thân với lý do "đang trong quá trình điều tra bí mật quốc gia". Nếu tiết lộ sẽ bị coi là đồng phạm và xử lý hình sự ngay lập tức.
4. **Chiếm đoạt tiền tiết kiệm:** Yêu cầu nạn nhân rút toàn bộ tiền tiết kiệm gửi vào tài khoản của "cán bộ thanh tra" để kiểm tra tính hợp pháp, hứa hẹn sẽ trả lại nguyên vẹn sau khi xác minh xong.

---

## III. Bảng đối chiếu nhận diện thủ đoạn

| Tiêu chí phân biệt | Quy định của Pháp luật Việt Nam | Dấu hiệu của Tội phạm lừa đảo |
| :--- | :--- | :--- |
| **Hình thức liên hệ** | Bằng văn bản gửi trực tiếp hoặc qua Công an khu vực | Gọi điện thoại qua mạng, gọi Zalo/Telegram |
| **Lấy lời khai** | Trực tiếp tại trụ sở cơ quan chức năng | Lấy lời khai trực tuyến, yêu cầu ở phòng kín |
| **Xử lý tài sản** | Thực hiện theo quyết định của Hội đồng thẩm phán | Yêu cầu chuyển tiền vào số tài khoản cá nhân |
| **Yêu cầu bảo mật** | Quyền được thông báo cho người thân và luật sư | Đe dọa, bắt giữ bí mật không cho ai biết |

---

## IV. Khuyến cáo từ Bộ Công an và Cục An toàn thông tin

- **Cơ quan Công an, Viện kiểm sát KHÔNG BAO GIỜ:**
  1. Làm việc với công dân qua điện thoại hoặc mạng xã hội.
  2. Yêu cầu công dân chuyển tiền vào bất kỳ tài khoản ngân hàng nào để "chứng minh trong sạch" hay "tạm giữ điều tra".
  3. Gửi văn bản tố tụng, lệnh bắt qua Zalo, Facebook, tin nhắn điện thoại.
- **Hành động cần làm ngay:**
  - Cúp máy ngay khi người gọi tự xưng là công an, tòa án đòi tiền.
  - Gọi ngay đến Tổng đài Quốc gia phòng chống lừa đảo **156** hoặc số điện thoại Công an phường/xã nơi cư trú để trình báo.
  - Báo cáo vụ việc đến Cục An toàn thông tin qua cổng `https://canhbao.ncsc.gov.vn`.
""",
    },
    22: {
        "title": "Cảnh báo SMS Brandname giả mạo: Nhận diện trạm phát sóng BTS lậu",
        "summary": "Hướng dẫn nhận biết tin nhắn giả mạo thương hiệu ngân hàng chèn vào hộp thư chính hãng do trạm BTS giả phát tán và cách tắt kết nối 2G để phòng vệ.",
        "content": """## I. Mối đe dọa từ tin nhắn SMS Brandname giả mạo

Nhiều người dân bị mất tiền oan khi nhận được tin nhắn mạo danh ngân hàng nhưng lại nằm chung luồng hội thoại với các tin nhắn thông báo số dư thật. Nguyên nhân kỹ thuật xuất phát từ việc các đối tượng sử dụng thiết bị trạm phát sóng di động giả mạo (Fake BTS).

Trạm BTS lậu này phát sóng đè bẹp sóng viễn thông tiêu chuẩn, ép các thiết bị di động trong bán kính 100-500m phải kết nối vào mạng 2G không mã hóa của chúng, từ đó gửi tin nhắn giả mạo với bất kỳ tên Brandname nào mà đối tượng mong muốn.

![Mạng viễn thông và nguy cơ trạm phát sóng lậu](https://images.unsplash.com/photo-1544197150-b99a580bb7a8?auto=format&fit=crop&w=1200&q=80)

---

## II. Các nội dung giả mạo thường gặp nhất

- *"Tài khoản của bạn đang đăng nhập trên thiết bị lạ tại TP.HCM. Nếu không phải bạn, hãy truy cập link http://vietcombank-online.vip để hủy."*
- *"Dịch vụ Internet Banking của quý khách sắp hết hạn, xin vui lòng truy cập http://mbbank-update.cc để tránh bị phong tỏa."*
- *"Quý khách nhận được gói hỗ trợ an sinh 2.000.000đ. Nhấn vào http://bidv-trocap.top để hoàn tất hồ sơ."*

Tất cả các đường link này đều dẫn về trang web có giao diện giống hệt trang đăng nhập của ngân hàng. Khi nạn nhân nhập Tên đăng nhập, Mật khẩu và mã OTP, kẻ gian lập tức chiếm quyền và chuyển hết tiền đi.

---

## III. Dấu hiệu nhận diện link Phishing qua mắt thường

| Đặc điểm | Website Ngân hàng chân chính | Website Giả mạo Phishing |
| :--- | :--- | :--- |
| **Đuôi tên miền** | `.vn`, `.com.vn` do VNNIC quản lý | `.vip`, `.top`, `.xyz`, `.cc`, `.site`, `.me` |
| **Cấu trúc URL** | Tên miền ngắn gọn: `vcb.com.vn`, `tcb.com.vn` | Tên miền dài ngoằng kèm từ khóa: `mbbank-xac-thuc-smart-otp.com` |
| **Nội dung yêu cầu** | Không bao giờ yêu cầu nhập mật khẩu để nhận tiền | Yêu cầu nhập ngay mật khẩu, OTP, mã PIN |

---

## IV. Giải pháp phòng chống từ Bộ Thông tin và Truyền thông

1. **Vô hiệu hóa 2G trên điện thoại thông minh:**
   - Trên hệ điều hành Android: Vào *Cài đặt* -> *Mạng di động* -> *SIM* -> Tắt tùy chọn **Cho phép 2G (Allow 2G)**.
   - Khi tắt 2G, điện thoại sẽ chỉ kết nối vào mạng 4G/5G có bảo mật hai chiều, vô hiệu hóa hoàn toàn trạm BTS lậu.
2. **Nguyên tắc ứng xử:**
   - Tuyệt đối không bấm vào bất cứ đường link nào gửi qua tin nhắn SMS.
   - Khi cần kiểm tra tài khoản, chỉ sử dụng ứng dụng Ngân hàng số chính thức tải từ Google Play hoặc Apple App Store.
   - Phản ánh tin nhắn rác, lừa đảo bằng cách gửi tin nhắn cú pháp `S [Nội dung tin nhắn] [Số gửi]` gửi về đầu số **156**.
""",
    },
    23: {
        "title": "Hướng dẫn bảo vệ tài khoản ngân hàng và tiền gửi trực tuyến an toàn",
        "summary": "Chiến lược bảo mật đa tầng cho tài khoản ngân hàng cá nhân, quy định xác thực sinh trắc học theo Quyết định 2345 và quy trình khóa tài khoản khẩn cấp.",
        "content": """## I. Mối nguy tiềm ẩn đối với tài khoản ngân hàng trực tuyến

Ngân hàng điện tử đã trở thành phương tiện thanh toán hàng ngày của hàng chục triệu người dân Việt Nam. Tuy nhiên, cùng với sự tiện lợi là nguy cơ bị tội phạm mạng tấn công qua nhiều hình thức tinh vi: cài mã độc chiếm quyền điều khiển điện thoại, bẫy lừa đảo qua trang web phishing, và kỹ thuật phi kỹ thuật (Social Engineering).

Bảo vệ tài khoản ngân hàng đòi hỏi người dùng phải xây dựng thói quen số an toàn và nắm vững các công cụ phòng vệ có sẵn.

![Bảo mật ngân hàng số đa lớp an toàn](https://images.unsplash.com/photo-1563986768609-322da13575f3?auto=format&fit=crop&w=1200&q=80)

---

## II. 5 Lớp bảo vệ tài khoản ngân hàng số toàn diện

1. **Lớp 1 - Mật khẩu độc lập và mạnh mẽ:**
   Không dùng chung mật khẩu ngân hàng với các tài khoản mạng xã hội hay email. Sử dụng mật khẩu có độ dài tối thiểu 12 ký tự kết hợp chữ hoa, chữ thường, số và ký tự đặc biệt.
2. **Lớp 2 - Xác thực sinh trắc học bắt buộc:**
   Theo Quyết định số **2345/QĐ-NHNN** của Ngân hàng Nhà nước, từ ngày 01/07/2024, mọi giao dịch chuyển tiền trên **10 triệu đồng/lần** hoặc tổng giao dịch trong ngày vượt **20 triệu đồng** bắt buộc phải xác thực bằng khuôn mặt khớp với dữ liệu thẻ CCCD gắn chip. Đây là lá chắn thép ngăn ngừa kẻ gian chuyển tiền số lượng lớn dù có lấy được mật khẩu.
3. **Lớp 3 - Chuyển sang sử dụng Smart OTP:**
   Thay thế SMS OTP bằng Smart OTP được tích hợp trực tiếp trong ứng dụng ngân hàng. Smart OTP được mã hóa nội bộ, không phụ thuộc vào sóng viễn thông và không thể bị nghe lén.
4. **Lớp 4 - Quản lý hạn mức giao dịch hợp lý:**
   Chủ động cài đặt hạn mức chuyển khoản tối đa trong ngày ở mức vừa phải với nhu cầu thực tế. Chỉ nâng hạn mức khi có nhu cầu giao dịch lớn tạm thời.
5. **Lớp 5 - Tách bạch tài khoản chi tiêu và tài khoản tiết kiệm:**
   Không giữ số dư lớn trong tài khoản thanh toán hàng ngày liên kết thẻ ghi nợ. Chuyển tiền nhàn rỗi vào sổ tiết kiệm online không có quyền thanh toán tức thì qua thẻ.

---

## III. Danh sách việc cần làm ngay khi nghi ngờ tài khoản bị lộ

| Thời điểm | Hành động khẩn cấp |
| :--- | :--- |
| **0 - 5 phút** | Mở app ngân hàng thực hiện tính năng "Khóa thẻ / Khóa dịch vụ ngân hàng điện tử". Nếu không vào được app, nhập sai mật khẩu 5 lần để khóa tạm thời. |
| **5 - 15 phút** | Gọi điện thoại đến Hotline 24/7 của ngân hàng yêu cầu nhân viên khóa khẩn cấp chiều chuyển tiền đi. |
| **15 - 30 phút** | Đổi ngay mật khẩu email liên kết với tài khoản ngân hàng và kiểm tra lịch sử biến động số dư. |
| **Sau 30 phút** | Đến phòng giao dịch ngân hàng gần nhất để làm thủ tục đối soát và đổi thông tin định danh mới. |
""",
    },
    24: {
        "title": "Nhận diện Deepfake & Giọng nói giả mạo người thân (Voice Cloning)",
        "summary": "Cách thức tội phạm mạng ứng dụng trí tuệ nhân tạo để mô phỏng hình ảnh, giọng nói người thân vay tiền và các phương pháp kiểm chứng bảo đảm an toàn.",
        "content": """## I. Sự trỗi dậy của tội phạm công nghệ cao ứng dụng AI

Công nghệ Deepfake (hoán đổi khuôn mặt) và Voice Cloning (nhân bản giọng nói) phát triển vượt bậc đã tạo ra những kịch bản lừa đảo vô cùng chân thực. Tội phạm chỉ cần thu thập một vài đoạn video hoặc ghi âm ngắn mà nạn nhân công khai trên mạng xã hội là có thể tạo ra một cuộc gọi video giả mạo với hình ảnh và âm thanh giống người thật đến 90%.

Đối tượng thường nhắm vào các nạn nhân lớn tuổi có con cháu đang đi du học, làm việc xa nhà hoặc các mối quan hệ bạn bè thân thiết.

![Ứng dụng trí tuệ nhân tạo nhận diện và giả lập khuôn mặt](https://images.unsplash.com/photo-1534972195531-a756b1126f24?auto=format&fit=crop&w=1200&q=80)

---

## II. Kịch bản lừa đảo mượn tiền Deepfake điển hình

1. Đối tượng chiếm quyền điều khiển (hack) tài khoản Facebook/Messenger hoặc Zalo của nạn nhân A.
2. Đối tượng đọc lịch sử trò chuyện để nắm bắt mối quan hệ thân thiết và phong cách xưng hô thường ngày.
3. Đối tượng thực hiện cuộc gọi video call kéo dài 5-10 giây đến bạn bè, người thân của A với khuôn mặt và giọng nói của A.
4. Kẻ gian lập tức tắt máy với lý do: *"Chỗ con mạng yếu quá", "Đang trên đường đi làm không nghe rõ"* và chuyển sang nhắn tin: *"Con đang cần gấp 20 triệu để đóng tiền bảo hiểm/trả nợ, mẹ chuyển gấp vào số tài khoản này giùm con..."*
5. Số tài khoản nhận tiền được giải thích là *"tài khoản của đồng nghiệp / đối tác"* để tránh việc người nhận nghi ngờ vì sao tên chủ tài khoản không phải của con mình.

---

## III. Dấu hiệu nhận biết cuộc gọi video Deepfake

- **Khẩu hình giật cục:** Cử động môi không ăn khớp hoàn toàn với âm thanh tiếng nói.
- **Biến dạng vật lý khi có vật cản:** Nếu người trong video đưa tay lên gãi má, vuốt tóc, hình ảnh khuôn mặt giả sẽ bị mờ nhòe hoặc biến dạng cục bộ.
- **Ánh mắt thiếu tự nhiên:** Mắt không chớp hoặc chớp quá nhanh, đồng tử không nhìn thẳng vào góc máy.
- **Cuộc gọi chớp nhoáng:** Đối phương luôn chủ động ngắt cuộc gọi thật nhanh sau vài câu ngắn ngủi.

---

## IV. Biện pháp phòng vệ tuyệt đối

- **Quy tắc cuộc gọi truyền thống:** Khi nhận được tin nhắn hỏi vay tiền từ người thân qua mạng xã hội, dù đã nhìn thấy mặt qua video call, hãy **ngắt kết nối và gọi lại bằng số điện thoại di động thông thường (mạng viễn thông)**.
- **Tạo mật khẩu gia đình (Family Safeword):** Đặt ra một từ khóa hoặc câu hỏi bí mật mà chỉ các thành viên trong gia đình mới biết để kiểm tra danh tính trong các trường hợp khẩn cấp liên quan đến tiền bạc.
- **Nguyên tắc tài khoản thụ hưởng:** Tuyệt đối không chuyển tiền vào tài khoản có tên người thụ hưởng khác với tên người thân của mình, bất kể đối phương đưa ra lý do gì.
""",
    },
    25: {
        "title": "Tổng đài 156 và các kênh trình báo lừa đảo mạng chính thức tại Việt Nam",
        "summary": "Hướng dẫn đầy đủ về cách phản ánh cuộc gọi rác, tin nhắn lừa đảo qua tổng đài 156, Cục An toàn thông tin và quy trình gửi đơn tố giác đến cơ quan Công an.",
        "content": """## I. Giới thiệu hệ thống tiếp nhận phản ánh quốc gia 156

Đầu số **156** là đầu số quốc gia được Bộ Thông tin và Truyền thông phối hợp cùng các nhà mạng viễn thông (Viettel, VNPT/VinaPhone, MobiFone) triển khai nhằm tiếp nhận thông tin phản ánh của người dân về cuộc gọi rác, cuộc gọi lừa đảo và tin nhắn vi phạm pháp luật.

Đầu số 156 hoạt động 24/7 và hoàn toàn **miễn phí cước cuộc gọi và tin nhắn**.

![Tổng đài hỗ trợ và bảo vệ an toàn mạng quốc gia](https://images.unsplash.com/photo-1534536281715-e28d76689b4d?auto=format&fit=crop&w=1200&q=80)

---

## II. Hướng dẫn phản ánh qua tin nhắn và cuộc gọi đến 156

### 1. Phản ánh qua tin nhắn SMS (Miễn phí):
- **Phản ánh cuộc gọi rác:** Gửi tin nhắn theo cú pháp:
  `V [Số điện thoại phát tán] [Nội dung cuộc gọi]` gửi **156** (hoặc 5656).
- **Phản ánh cuộc gọi lừa đảo, đe dọa:** Gửi tin nhắn theo cú pháp:
  `LD [Số điện thoại lừa đảo] [Nội dung cuộc gọi lừa đảo]` gửi **156**.
- **Phản ánh tin nhắn rác, link lừa đảo:** Gửi tin nhắn theo cú pháp:
  `S [Số điện thoại gửi tin] [Nội dung tin nhắn lừa đảo]` gửi **156**.

### 2. Phản ánh qua cuộc gọi thoại:
Gọi trực tiếp đến số **156**, bấm phím theo hướng dẫn của tổng đài viên để cung cấp số điện thoại đối tượng và mô tả chi tiết thủ đoạn lừa đảo.

---

## III. Các kênh trình báo chính thống khác

| Cơ quan tiếp nhận | Kênh tiếp nhận | Nhiệm vụ chính |
| :--- | :--- | :--- |
| **Cục An toàn thông tin (NCSC)** | Website: `https://canhbao.ncsc.gov.vn` hoặc `https://tinnhiemmang.vn` | Tiếp nhận báo cáo website lừa đảo, ứng dụng độc hại, tài khoản ngân hàng lừa đảo |
| **Cục An ninh mạng và PCTP công nghệ cao (A05)** | Hotline: **069.2348560**; Địa chỉ: 47 Phạm Văn Đồng, Cầu Giấy, Hà Nội | Điều tra các đường dây tội phạm mạng quy mô lớn, lừa đảo công nghệ cao |
| **Công an Quận/Huyện/Tỉnh địa phương** | Trực tiếp tại trụ sở Công an nơi cư trú | Tiếp nhận đơn tố giác tội phạm, lấy lời khai và thụ lý vụ việc theo Bộ luật Tố tụng hình sự |
| **Đường dây nóng Cảnh sát phản ứng nhanh** | Số điện thoại khẩn cấp: **113** | Xử lý các tình huống đe dọa khẩn cấp đến an toàn tính mạng, thân thể |

---

## IV. Hồ sơ cần chuẩn bị khi gửi đơn tố giác lừa đảo

Khi gửi đơn tố giác đến cơ quan Công an, người bị hại cần chuẩn bị đầy đủ chứng cứ gồm:
1. Đơn tố giác tội phạm trình bày chi tiết diễn biến sự việc.
2. Bản sao CCCD của người tố giác.
3. Bản in lịch sử tin nhắn, thư điện tử trao đổi với kẻ lừa đảo.
4. Sao kê ngân hàng có dấu đỏ xác nhận các giao dịch chuyển tiền (nêu rõ số tài khoản, tên chủ tài khoản thụ hưởng, thời gian giao dịch).
5. File ghi âm cuộc gọi (nếu có) được lưu vào đĩa CD/USB kèm theo đơn.
""",
    },
    26: {
        "title": "Nhận diện bẫy lừa đảo 'Việc nhẹ lương cao' và Giật đơn hàng thương mại điện tử",
        "summary": "Phân tích bẫy tâm lý hoa hồng ảo khi làm cộng tác viên online shopee, lazada, tiktok và cách nhận diện các hội nhóm mồi chài giật đơn hàng trên Telegram.",
        "content": """## I. Bản chất chiêu trò 'Cộng tác viên online - Việc nhẹ lương cao'

Lừa đảo tuyển dụng cộng tác viên giật đơn hàng sàn thương mại điện tử (Shopee, Lazada, Tiki, TikTok Shop) hoặc bình chọn ca sĩ, đánh giá video YouTube là một trong những hình thức phổ biến nhất đánh vào tâm lý muốn kiếm thêm thu nhập của học sinh, sinh viên, phụ nữ nuôi con nhỏ và người tìm việc.

Kẻ gian xây dựng kịch bản bài bản theo từng nấc thang tâm lý, áp dụng nguyên lý "thả con săn sắt, bắt con cá rô" để đưa nạn nhân vào tròng.

![Bẫy việc làm trực tuyến và thao túng tâm lý](https://images.unsplash.com/photo-1551836022-d5d88e9218df?auto=format&fit=crop&w=1200&q=80)

---

## II. 4 Bước bẫy hoa hồng điển hình

1. **Giai đoạn tiếp cận (Mồi nhử):** Nạn nhân nhận tin nhắn qua Zalo/Facebook mời làm việc online với mức lương 300.000 - 800.000đ/ngày, chỉ cần thao tác trên điện thoại.
2. **Nhiệm vụ đầu tiên (Tạo niềm tin):** Đối tượng yêu cầu nạn nhân hoàn thành đơn hàng giá trị nhỏ (100.000 - 300.000đ). Ngay sau khi chuyển tiền, hệ thống lập tức hoàn trả tiền gốc kèm hoa hồng 10-20% về tài khoản ngân hàng của nạn nhân trong vòng 5 phút.
3. **Nâng cấp gói nhiệm vụ (Kích thích lòng tham):** Nạn nhân được thêm vào nhóm Telegram có hàng trăm "thành viên" (thực chất là tài khoản ảo/chim mồi liên tục gửi ảnh chụp nhận tiền thành công). Lúc này, các đơn hàng yêu cầu nạp số tiền lớn: 5 triệu, 20 triệu, 50 triệu đồng.
4. **Đóng bẫy (Chiếm đoạt tài sản):** Khi số tiền nạp đã lớn, hệ thống báo lỗi: *"Sai cú pháp", "Hệ thống bị nghẽn", "Chưa hoàn thành đủ 3 đơn liên hoàn"*. Kẻ gian ép nạn nhân phải nạp thêm 50% hoặc 100% số tiền hiện có để "mở khóa tài khoản". Cứ như vậy, nạn nhân vì tiếc tiền đã nộp (chi phí chìm) nên tiếp tục vay mượn để nạp thêm cho đến khi kiệt quệ tài chính.

---

## III. Dấu hiệu nhận diện kẻ lừa đảo tuyển dụng

| Dấu hiệu | Nhà tuyển dụng chân chính | Đối tượng lừa đảo mạo danh |
| :--- | :--- | :--- |
| **Yêu cầu nạp tiền** | KHÔNG BAO GIỜ yêu cầu ứng viên nộp tiền trước để nhận việc | Bắt buộc chuyển tiền "đặt cọc / nạp vốn giật đơn" |
| **Phương thức phỏng vấn** | Trực tiếp tại công ty hoặc qua email doanh nghiệp chính thức | Trao đổi qua Telegram, Zalo cá nhân, không có hợp đồng lao động |
| **Kênh thanh toán** | Tài khoản công ty có đăng ký pháp nhân | Tài khoản cá nhân lạ, thay đổi liên tục qua từng đơn hàng |
| **Mức thù lao** | Tương xứng với kỹ năng và khối lượng công việc thực tế | Cam kết lợi nhuận phi lý: 20-30% chỉ sau vài phút |

---

## IV. Lời khuyên vàng bảo vệ bản thân

- **Dừng lại ngay lập tức:** Khi hệ thống yêu cầu nạp thêm tiền để rút tiền cũ, hãy dừng lại ngay. Càng nạp thêm, bạn càng mất thêm tiền.
- **Không tin vào các hội nhóm Telegram:** Mọi hình ảnh sao kê tiền về, lời khen ngợi trong các nhóm chat đều là kịch bản dàn dựng của các tài khoản mồi chài.
- **Báo cáo và tố giác:** Chụp lại toàn bộ chứng từ chuyển khoản, nội dung tin nhắn và số tài khoản của kẻ gian để gửi đơn tố giác đến cơ quan Công an và trang web `https://canhbao.ncsc.gov.vn`.
""",
    },
    27: {
        "title": "An toàn khi mua sắm online và thanh toán qua QR Code (Phòng chống Quishing)",
        "summary": "Cảnh báo thủ đoạn dán đè mã QR độc hại tại quầy thanh toán, mã QR ẩn link phishing và các quy tắc kiểm tra đối soát trước khi bấm xác nhận chuyển tiền.",
        "content": """## I. Mối đe dọa mang tên Quishing (QR Code Phishing)

Mã QR đã trở thành phương thức thanh toán phổ thông tại Việt Nam từ quán trà đá vỉa hè đến các trung tâm thương mại lớn. Tuy nhiên, tính chất của mã QR là **con người không thể đọc trực tiếp nội dung bằng mắt thường**, điều này tạo cơ hội cho tội phạm mạng thực hiện tấn công Quishing (lừa đảo qua mã QR).

Kẻ gian lợi dụng sự chủ quan của khách hàng và người bán để tráo đổi mã QR thanh toán hoặc lồng ghép đường link độc hại vào mã QR khuyến mại.

![Thanh toán an toàn qua mã QR Code](https://images.unsplash.com/photo-1556742049-0a67c5574f73?auto=format&fit=crop&w=1200&q=80)

---

## II. Các thủ đoạn lừa đảo qua mã QR phổ biến

1. **Dán đè mã QR tại quầy thanh toán:** Lợi dụng lúc cửa hàng đông khách hoặc nhân viên sơ hở, kẻ gian dán đè mã QR của mình lên bảng mã QR của cửa hàng. Khách hàng quét mã chuyển tiền tưởng đã thanh toán cho quán nhưng tiền thực chất chảy vào ví kẻ lừa đảo.
2. **Mã QR trúng thưởng / voucher giả mạo:** Kẻ gian in các tờ rơi phát tại chung cư hoặc dán trên xe máy thông báo "Quét mã nhận voucher 500k mua sắm". Khi quét mã, trình duyệt tự động mở ra trang web phishing yêu cầu điền thông tin tài khoản ngân hàng.
3. **Mã QR chứa mã độc APK:** Một số mã QR khi quét sẽ kích hoạt tải xuống tự động tập tin cài đặt ứng dụng Android (.apk) chứa mã độc trojan gián điệp đánh cắp dữ liệu thiết bị.

---

## III. 4 Bước kiểm tra bắt buộc khi thanh toán QR Code

| Bước | Hành động | Mục đích an toàn |
| :--- | :--- | :--- |
| **Bước 1** | Quan sát bề mặt mã QR tại cửa hàng | Kiểm tra xem mã có bị dán đè, mép dán có bị kênh hoặc có dấu hiệu dán đè giấy decal lên không |
| **Bước 2** | Quét bằng ứng dụng Ngân hàng (không dùng camera thường) | App ngân hàng chỉ nhận diện lệnh thanh toán chuẩn VietQR, cảnh báo nếu là link web lạ |
| **Bước 3** | **ĐỐI SOÁT TÊN CHỦ TÀI KHOẢN** | So sánh tên hiển thị trên màn hình app ngân hàng với tên chủ quán hoặc bảng hiệu |
| **Bước 4** | Xác nhận số tiền chính xác | Kiểm tra lại số tiền trước khi nhập mã PIN / sinh trắc học |

---

## IV. Lời khuyên cho chủ cơ sở kinh doanh

- Thường xuyên kiểm tra bảng mã QR tại quầy, sử dụng bảng mã in chất lượng cao gắn cố định hoặc mã QR động hiển thị trên máy POS/màn hình điện tử.
- Bật tính năng thông báo biến động số dư qua loa phát âm thanh để nghe xác nhận tiền đã về tài khoản trước khi để khách hàng rời đi.
- Hạn chế để bảng mã QR ở các khu vực khuất tầm nhìn của nhân viên thu ngân.
""",
    },
    28: {
        "title": "Chuyện cảnh giác: Mất tiền vì cung cấp mã OTP cho 'nhân viên viễn thông nâng cấp SIM 5G'",
        "summary": "Phân tích chiêu thức chiếm đoạt SIM vật lý (SIM Swap) bằng cách lừa nạn nhân cung cấp mã OTP đổi eSIM/SIM 5G để chiếm đoạt tài khoản ngân hàng.",
        "content": """## I. Câu chuyện thực tế và bài học đắt giá

Chị N.T.H (42 tuổi, trú tại Hà Nội) nhận được cuộc gọi từ số máy lạ xưng là nhân viên kỹ thuật của nhà mạng viễn thông. Người này thông báo sóng 3G sắp bị khai tử trên toàn quốc và đề nghị hỗ trợ chị nâng cấp miễn phí SIM hiện tại lên SIM 5G trực tuyến để tránh bị gián đoạn liên lạc.

Tin lời, chị H làm theo hướng dẫn: nhắn tin theo cú pháp đối tượng gửi và cung cấp một mã xác thực (OTP) gửi về máy. Chỉ 3 phút sau, điện thoại của chị mất hoàn toàn cột sóng (hiển thị "Không có dịch vụ"). Khi chị mượn điện thoại người thân đăng nhập vào app ngân hàng, tài khoản tiết kiệm 350 triệu đồng đã bị rút sạch qua 5 giao dịch chuyển khoản liên tiếp.

![Cảnh giác thủ đoạn lừa đảo chiếm đoạt thẻ SIM](https://images.unsplash.com/photo-1512428559087-560fa5ceab42?auto=format&fit=crop&w=1200&q=80)

---

## II. Cơ chế kỹ thuật của cuộc tấn công SIM Swap (Hoán đổi SIM)

1. **Thu thập thông tin cá nhân:** Đối tượng đã thu thập được số điện thoại, số CCCD và thông tin tài khoản ngân hàng của nạn nhân từ các dữ liệu rò rỉ trên mạng.
2. **Kích hoạt quy trình đổi SIM:** Đối tượng sử dụng tính năng đổi SIM trực tuyến hoặc yêu cầu cấp eSIM mới từ cổng dịch vụ của nhà mạng.
3. **Đánh cắp mã xác thực:** Hệ thống nhà mạng gửi một mã OTP về số điện thoại cũ của nạn nhân để xác nhận đổi sang phôi SIM mới. Kẻ gian lừa nạn nhân đọc mã OTP này với lý do *"mã xác nhận nâng cấp 5G thành công"*.
4. **Chiếm đoạt tài khoản:** Ngay khi mã OTP được điền, phôi SIM mới trong tay kẻ gian được kích hoạt, phôi SIM cũ trên máy nạn nhân lập tức bị vô hiệu hóa. Kẻ gian dùng chính số điện thoại này để bấm "Quên mật khẩu" trên app ngân hàng, nhận mã OTP khôi phục và chuyển sạch tiền.

---

## III. Dấu hiệu cảnh báo và cách ứng phó tức thì

| Dấu hiệu | Hành động cấp bách cần làm ngay |
| :--- | :--- |
| **Có người tự xưng nhà mạng gọi nâng cấp SIM qua điện thoại** | **Từ chối ngay lập tức.** Các nhà mạng (Viettel, VinaPhone, MobiFone) không bao giờ yêu cầu khách hàng đọc mã OTP qua điện thoại để nâng cấp SIM. |
| **Điện thoại đột ngột mất sóng bất thường dù xung quanh vẫn có sóng** | Nghi ngờ SIM đã bị chiếm đoạt. Lập tức mượn điện thoại khác gọi ngay tổng đài nhà mạng yêu cầu **KHÓA SIM KHẨN CẤP**. |
| **Tài khoản ngân hàng có thông báo đăng nhập lạ** | Gọi ngay hotline ngân hàng yêu cầu **KHÓA TOÀN BỘ TÀI KHOẢN VÀ THẺ**. |

---

## IV. Số hotline khẩn cấp của các nhà mạng viễn thông

- **Viettel:** 1800 8098 (miễn phí)
- **VinaPhone:** 1800 1091 (miễn phí)
- **MobiFone:** 1800 1090 (miễn phí)
- **Vietnamobile:** 0922 789 789

Ghi nhớ nguyên tắc: Mọi thủ tục chuyển đổi SIM, đăng ký eSIM chính chủ phải được thực hiện trực tiếp tại điểm giao dịch của nhà mạng có xuất trình CCCD gốc.
""",
    },
    29: {
        "title": "Cảnh báo mã độc đội lốt VNeID, Dịch vụ công & 'Cập nhật định danh mức 2'",
        "summary": "Mã độc Android kích hoạt quyền Hỗ trợ tiếp cận (Accessibility Service) tự động điều khiển thiết bị, đọc trộm Smart OTP và chuyển sạch tiền trong tài khoản.",
        "content": """## I. Thủ đoạn phát tán ứng dụng giả mạo Cơ quan Thuế và VNeID

Lợi dụng chủ trương đẩy mạnh chuyển đổi số quốc gia và chuẩn hóa dữ liệu định danh điện tử, các nhóm tội phạm mạng đã phát triển các phần mềm độc hại giả mạo ứng dụng **VNeID** của Bộ Công an, ứng dụng **eTax Mobile** của Tổng cục Thuế, hoặc ứng dụng **Dịch vụ công quốc gia**.

Đối tượng đóng giả cán bộ công an khu vực hoặc cán bộ thuế gọi điện thoại giục nạn nhân: *"Hồ sơ định danh mức 2 bị lỗi thông tin", "Cần cập nhật mã số thuế gấp để không bị phạt"*. Sau đó, chúng kết bạn Zalo và gửi cho nạn nhân một đường link tải tập tin có đuôi `.apk` (ví dụ: `vneid.apk`, `dichvucong.apk`).

![Cảnh báo mã độc tấn công thiết bị di động Android](https://images.unsplash.com/photo-1563986768609-322da13575f3?auto=format&fit=crop&w=1200&q=80)

---

## II. Cơ chế tấn công của quyền Hỗ trợ tiếp cận (Accessibility Service)

Khi nạn nhân cài đặt file APK lạ và cấp quyền **Hỗ trợ tiếp cận (Accessibility)**:
1. **Kiểm soát toàn bộ màn hình:** Mã độc có quyền đọc mọi ký tự hiển thị trên màn hình, bao gồm mật khẩu gõ vào và mã Smart OTP hiển thị trong app ngân hàng.
2. **Tự động thao tác từ xa:** Mã độc tự động bấm phím, cuộn trang, tự mở ứng dụng ngân hàng và điền thông tin chuyển tiền mà người dùng không hề hay biết.
3. **Thực hiện giao dịch lúc nửa đêm:** Kẻ gian thường hẹn giờ tấn công vào khoảng thời gian từ 1h - 4h sáng khi nạn nhân đang ngủ say, làm tối màn hình điện thoại để nạn nhân không phát hiện máy đang tự chuyển tiền.

---

## III. Dấu hiệu nhận biết điện thoại đã bị nhiễm mã độc gián điệp

- Máy bỗng nhiên chạy chậm, nhanh nóng máy và tụt pin bất thường kể cả khi không sử dụng.
- Màn hình thỉnh thoảng tự động sáng hoặc tự động chuyển qua lại giữa các ứng dụng.
- Cửa sổ cài đặt xuất hiện ứng dụng lạ yêu cầu quyền "Hỗ trợ tiếp cận" hoặc "Hiển thị trên các ứng dụng khác".
- Ứng dụng ngân hàng số tự động văng ra hoặc hiển thị cảnh báo: *"Thiết bị không an toàn / Đã phát hiện quyền trợ năng được bật"*.

---

## IV. Quy trình xử lý khẩn cấp khi đã lỡ cài file APK độc hại

| Bước | Hành động tức thời | Mục đích |
| :--- | :--- | :--- |
| **Bước 1** | **Bật chế độ máy bay ngay lập tức (Airplane Mode)** | Ngắt kết nối Wifi và 4G để máy chủ hacker mất liên lạc với mã độc trong máy |
| **Bước 2** | Dùng máy khác gọi hotline ngân hàng khóa tài khoản | Ngăn chặn các giao dịch chuyển tiền tự động |
| **Bước 3** | Khôi phục cài đặt gốc điện thoại (Factory Reset) | Xóa sạch toàn bộ mã độc ẩn sâu trong hệ điều hành |
| **Bước 4** | Đổi toàn bộ mật khẩu tài khoản ngân hàng và email | Đảm bảo kẻ gian không thể đăng nhập lại sau khi có thiết bị mới |
""",
    },
    30: {
        "title": "Bẫy lừa đảo tình cảm trực tuyến (Romance Scam) & 'Gói quà từ nước ngoài'",
        "summary": "Giải mã tâm lý trong các vụ lừa đảo hẹn hò qua mạng, chiêu bài gửi thùng hàng giá trị lớn rồi bắt đóng tiền thuế phí hải quan để chiếm đoạt.",
        "content": """## I. Ma trận thao túng tâm lý trong bẫy lừa đảo tình cảm

Lừa đảo tình cảm trực tuyến (Romance Scam) là loại hình tội phạm có tính chất thao túng tâm lý kéo dài và tinh vi bậc nhất. Đối tượng thường nhắm vào phụ nữ đơn thân, người lớn tuổi góa bụa, hoặc những người đang thiếu thốn tình cảm trên các nền tảng mạng xã hội (Facebook, Instagram, Tinder, Bumble).

Kẻ gian xây dựng hồ sơ cá nhân hoàn hảo: kỹ sư dầu khí, bác sĩ quân y đang làm nhiệm vụ ở vùng chiến sự, phi công góa vợ, hoặc doanh nhân thành đạt nhưng có số phận cô đơn, hiếu thảo.

![Lừa đảo tình cảm qua mạng xã hội](https://images.unsplash.com/photo-1516589178581-6cd7833ae3b2?auto=format&fit=crop&w=1200&q=80)

---

## II. Kịch bản 'Thùng hàng quà tặng và triệu đô la'

1. **Xây dựng lòng tin (Giai đoạn 1-3 tháng):** Đối tượng nhắn tin trò chuyện mỗi ngày, chia sẻ tâm tư, tặng những lời ngọt ngào và hứa hẹn về một tương lai tươi đẹp tại Việt Nam.
2. **Thông báo gửi quà đặc biệt:** Đối tượng thông báo đã gửi về Việt Nam một kiện hàng đặc biệt chứa: vàng bạc, trang sức, đồng hồ đắt tiền hoặc thậm chí một vali chứa hàng triệu USD tiền mặt để chuẩn bị mua nhà tại Việt Nam. Đối tượng gửi kèm hóa đơn vận chuyển và mã vận đơn (tracking code) của một công ty vận chuyển quốc tế giả mạo.
3. **Đóng bẫy với chiêu bài 'Hải quan sân bay':**
   - Vài ngày sau, một người phụ nữ tự xưng là "nhân viên hải quan / công ty giao hàng sân bay" gọi điện thông báo kiện hàng đã về đến sân bay Nội Bài/Tân Sơn Nhất nhưng bị giữ lại vì chứa lượng tiền mặt lớn.
   - Nạn nhân được yêu cầu chuyển tiền đóng "phí thông quan", "phí bảo hiểm hàng hóa" vào tài khoản chỉ định.
   - Khi nạn nhân chuyển xong, đối tượng tiếp tục bịa ra các khoản phí mới: "phí chống rửa tiền", "tiền phạt hải quan", "tiền lót tay thanh tra"... Nạn nhân vì sợ đối phương gặp nguy hiểm hoặc tiếc số tiền đã chuyển nên tiếp tục nộp tiền cho đến khi nhận ra bị lừa.

---

## III. Các quy tắc vàng nhận diện kẻ lừa đảo tình cảm

| Tiêu chuẩn | Người yêu chân thành | Kẻ lừa đảo qua mạng |
| :--- | :--- | :--- |
| **Gặp mặt thực tế** | Luôn muốn gặp mặt trực tiếp hoặc gọi video call rõ nét | Luôn tìm lý do từ chối video call (nhiệm vụ bí mật, mạng hỏng) |
| **Yêu cầu tiền bạc** | Không bao giờ đòi hỏi chuyển tiền đóng phí hải quan | Sớm muộn cũng dẫn dắt đến việc chuyển tiền, nhận quà hoặc đầu tư tài chính |
| **Văn phong giao tiếp** | Tự nhiên, phù hợp với văn hóa thực tế | Sử dụng văn phong dịch từ Google Translate, hoa mỹ nhưng gượng gạo |
| **Tài khoản nhận tiền** | Minh bạch | Luôn là số tài khoản cá nhân tại ngân hàng Việt Nam đứng tên người lạ |

---

## IV. Lời khuyên khi phát hiện bản thân hoặc người thân dính bẫy

- Ngưng ngay mọi giao dịch chuyển tiền, không tin vào bất cứ lời giải thích hay đe dọa nào từ đối tượng.
- Lưu lại toàn bộ hình ảnh tài khoản, tin nhắn, biên lai chuyển khoản và đến ngay cơ quan Công an gần nhất để trình báo.
- Tâm sự với người thân, bạn bè tin cậy để giải tỏa áp lực tâm lý và nhận được sự hỗ trợ kịp thời.
""",
    },
    31: {
        "title": "Bẫy sàn đầu tư tài chính quốc tế, Forex, Tiền ảo & Quyền chọn nhị phân (BO)",
        "summary": "Bóc trần thuật toán can thiệp lệnh của các sàn đầu tư ảo cam kết lãi suất khủng 30%/ngày và chiêu bài chuyên gia kéo lệnh để lừa đảo.",
        "content": """## I. Thực trạng các sàn giao dịch tài chính lừa đảo tại Việt Nam

Theo quy định của pháp luật Việt Nam hiện hành, Nhà nước **chưa cấp phép cho bất kỳ sàn giao dịch ngoại hối (Forex), chứng khoán quốc tế hay tiền mã hóa (Crypto)** nào hoạt động tại Việt Nam. Mọi sàn tự xưng là "sàn quốc tế uy tín", "được cấp phép tại Anh/Mỹ" đều là các sàn do các nhóm đối tượng người Việt hoặc cấu kết với tội phạm nước ngoài tự lập trình và vận hành.

Kẻ gian đánh trúng tâm lý hám lợi, muốn kiếm tiền nhanh chóng mà không cần kiến thức tài chính của nạn nhân.

![Sàn đầu tư tài chính ảo và cạm bẫy lợi nhuận](https://images.unsplash.com/photo-1611974789855-9c2a0a7236a3?auto=format&fit=crop&w=1200&q=80)

---

## II. Bản chất kỹ thuật: Sàn ảo tự chỉnh thuật toán

Các sàn BO (Binary Options), sàn Forex lậu hoạt động theo cơ chế hoàn toàn bị thao túng:
1. **Can thiệp biểu đồ nến:** Máy chủ của sàn có thể can thiệp trực tiếp vào kết quả lệnh xanh/đỏ theo ý muốn của quản trị viên (Admin).
2. **Cho thắng vốn nhỏ:** Khi nạn nhân nạp vài triệu đồng, hệ thống luôn cho lệnh thắng và cho phép rút tiền nhanh chóng để tạo niềm tin tuyệt đối.
3. **Thúc giục tăng vốn:** Đội ngũ "chuyên gia đọc lệnh", "thầy phong thủy tài chính" trong nhóm kín Telegram thúc giục nạn nhân nâng vốn lên hàng trăm triệu để vào "Gói VIP", hưởng cam kết bảo hiểm vốn 100%.
4. **Đánh cháy tài khoản hoặc khóa rút tiền:** Khi nạn nhân muốn rút số tiền lớn, sàn sẽ đưa ra hàng loạt yêu cầu vô lý: nộp thuế thu nhập 10%, nộp phí xác minh tài khoản 20%, nộp tiền nâng cấp đòn bẩy... Cuối cùng, sàn đánh sập website hoặc khóa tài khoản của nạn nhân và biến mất.

---

## III. Bảng đối chiếu sàn đầu tư hợp pháp và sàn lừa đảo

| Tiêu chí | Công ty Chứng khoán hợp pháp tại VN | Sàn đầu tư tài chính lừa đảo |
| :--- | :--- | :--- |
| **Giấy phép** | Do Ủy ban Chứng khoán Nhà nước (UBCKNN) cấp phép | Giấy phép giả mạo quốc tế (SVG, Belize, Vanuatu...) |
| **Cam kết lợi nhuận** | Tuân thủ biến động thị trường, không cam kết lãi suất | Cam kết lãi suất phi lý: 1-5%/ngày, 30-50%/tháng, bao lỗ |
| **Kênh nạp tiền** | Tài khoản công ty mở tại ngân hàng thương mại Việt Nam | Chuyển khoản vào tài khoản cá nhân lạ hoặc mua tiền ảo USDT |
| **Rút vốn** | Rút về tài khoản ngân hàng chính chủ bất cứ lúc nào | Gặp khó khăn, bắt đóng thêm tiền "thuế, phí" mới cho rút |

---

## IV. Khuyến cáo bảo vệ tài sản

- Tuyệt đối không tham gia vào các hội nhóm kêu gọi đầu tư tài chính trên Telegram, Zalo khi không rõ pháp nhân đứng sau.
- Tra cứu danh sách các công ty chứng khoán, công ty quản lý quỹ được phép hoạt động chính thức trên website của Ủy ban Chứng khoán Nhà nước: `https://ssc.gov.vn`.
- Nếu đã bị lừa đảo, lưu lại toàn bộ bằng chứng chuyển tiền và liên hệ Cục An ninh mạng và phòng chống tội phạm sử dụng công nghệ cao (A05) để trình báo.
""",
    },
    32: {
        "title": "Cảnh báo thủ đoạn mạo danh Bảo hiểm xã hội & Hoàn thuế để lừa đảo",
        "summary": "Chiêu bài thông báo đồng bộ lại hồ sơ bảo hiểm xã hội VssID hoặc nhận tiền hoàn thuế thu nhập cá nhân nhằm chiếm đoạt tài khoản ngân hàng.",
        "content": """## I. Kịch bản lừa đảo mượn danh cơ quan Bảo hiểm xã hội và Thuế

Lợi dụng các đợt quyết toán thuế hàng năm hoặc các chính sách chi trả hỗ trợ của Bảo hiểm xã hội (BHXH), các nhóm đối tượng đã lập các trang web, tổng đài giả mạo để lừa gạt người lao động.

Đối tượng thường gọi điện với giọng điệu nghiêm túc, đọc vanh vách thông tin cá nhân của nạn nhân (họ tên, ngày sinh, nơi công tác) khiến nạn nhân hoàn toàn tin tưởng người gọi là cán bộ nhà nước thật.

![Cơ quan thuế và bảo hiểm xã hội cảnh báo lừa đảo](https://images.unsplash.com/photo-1450133064473-71024230f91b?auto=format&fit=crop&w=1200&q=80)

---

## II. Hai thủ đoạn phổ biến nhất

### 1. Giả danh Bảo hiểm xã hội (VssID):
- Thông báo hồ sơ BHXH của người dùng bị sai lệch thông tin cá nhân, nếu không cập nhật sẽ bị gián đoạn quyền lợi bảo hiểm y tế.
- Hướng dẫn nạn nhân bấm vào đường link lạ có giao diện giống ứng dụng VssID hoặc cài file APK độc hại để "đồng bộ dữ liệu tự động".

### 2. Giả danh Cơ quan Thuế hoàn tiền thuế TNCN:
- Thông báo người dùng có một khoản tiền hoàn thuế thu nhập cá nhân thừa (từ 3 đến 15 triệu đồng).
- Yêu cầu người dùng truy cập website giả mạo Tổng cục Thuế để điền số tài khoản ngân hàng, mật khẩu và mã OTP để nhận tiền hoàn thuế về máy.

---

## III. Nguyên tắc làm việc của cơ quan Thuế và BHXH

| Quy trình thực tế | Cơ quan Nhà nước chân chính | Kẻ mạo danh lừa đảo |
| :--- | :--- | :--- |
| **Kênh thông báo** | Qua Cổng dịch vụ công quốc gia, thông báo giấy hoặc app chính thức | Gọi điện thoại cá nhân, nhắn tin qua Zalo |
| **Quy trình hoàn thuế** | Hoàn tiền trực tiếp vào số tài khoản đã đăng ký trong hồ sơ quyết toán | Bắt bấm vào link lạ để điền thông tin và OTP |
| **Cài đặt ứng dụng** | Chỉ tải từ Google Play / App Store (VssID, eTax Mobile) | Gửi link cài file APK hoặc link web lạ đuôi .xyz, .cc |

---

## IV. Các kênh tra cứu chính thống

- **Cổng thông tin Bảo hiểm xã hội Việt Nam:** `https://baohiemxahoi.gov.vn`
- **Tổng đài chăm sóc khách hàng BHXH:** **1900 9068**
- **Cổng thông tin điện tử Tổng cục Thuế:** `https://gdt.gov.vn`
- **Ứng dụng chính thức:** Chỉ cài ứng dụng **VssID** và **eTax Mobile** từ kho ứng dụng chính thống của Apple và Google.
""",
    },
    33: {
        "title": "Thủ đoạn lừa đảo giao hàng (Shipper giả) và bẫy hoàn tiền đơn hàng COD",
        "summary": "Phân tích bẫy gọi điện giao hàng khi vắng nhà yêu cầu chuyển khoản trước, sau đó gửi link hoàn tiền để hack tài khoản ngân hàng.",
        "content": """## I. Mối nguy từ thói quen mua hàng trực tuyến

Với tần suất mua sắm online dày đặc của người dân, nhiều người thường xuyên có các đơn hàng đang trên đường vận chuyển và không nhớ chính xác mình đã đặt những món gì. Lợi dụng điều này, kẻ gian đã phát triển thủ đoạn lừa đảo "Shipper giao hàng".

Kẻ gian thường theo dõi các buổi livestream bán hàng để thu thập số điện thoại và địa chỉ mà khách hàng để lại công khai trong phần bình luận, hoặc mua dữ liệu thông tin khách hàng từ các nguồn rò rỉ.

![Lừa đảo mạo danh nhân viên giao hàng](https://images.unsplash.com/photo-1586528116311-ad8dd3c8310d?auto=format&fit=crop&w=1200&q=80)

---

## II. Kịch bản lừa đảo 2 bước tinh vi

1. **Bước 1 - Lừa chuyển tiền đơn hàng nhỏ (100.000 - 300.000đ):**
   Đối tượng gọi điện xưng là shipper của Giao Hàng Tiết Kiệm, J&T, Viettel Post thông báo có đơn hàng giao đến nhà. Khi nạn nhân bảo đang đi làm vắng nhà, shipper bảo: *"Anh/chị chuyển khoản tiền hàng giúp em để em gửi hàng cho bảo vệ/hàng xóm"*. Nạn nhân vì bận rộn nên chuyển khoản luôn.
2. **Bước 2 - Đóng bẫy hoàn tiền (Mất tiền tỷ):**
   Sau khi nhận được tiền, đối tượng gọi lại với giọng hoảng hốt: *"Chết rồi anh ơi, em gửi nhầm số tài khoản của Công ty mẹ, tài khoản này tự động đăng ký gói Hội viên giao hàngVIP bị trừ 5 triệu/tháng. Anh phải bấm vào link này để hủy đăng ký và nhận lại tiền ngay!"*.
   Đường link đối tượng gửi là trang web phishing mạo danh ngân hàng hoặc dịch vụ khách hàng. Khi nạn nhân nhập thông tin thẻ và OTP, toàn bộ tiền trong tài khoản sẽ bốc hơi.

---

## III. Quy tắc an toàn khi nhận hàng mua sắm online

- **Quy tắc Kiểm tra mã vận đơn:** Luôn mở ứng dụng mua hàng (Shopee, Lazada, TikTok) để đối chiếu đúng mã vận đơn và tên shipper phụ trách giao hàng trước khi chuyển tiền.
- **Không chuyển tiền khi chưa nhận hàng:** Chỉ chuyển khoản khi người nhà hoặc chính mình đã cầm gói hàng trên tay và kiểm tra đúng thông tin người gửi.
- **Cảnh giác với mọi yêu cầu "bấm link hoàn tiền":** Các công ty giao hàng không bao giờ yêu cầu khách hàng bấm vào link để hủy đăng ký hay nhận lại tiền hoàn.
""",
    },
    34: {
        "title": "Bị chiếm quyền tài khoản mạng xã hội rồi nhắn tin vay tiền khắp danh bạ",
        "summary": "Nguyên nhân tài khoản Facebook, Zalo, Telegram bị hack và cách phòng ngừa, xử lý khẩn cấp khi danh bạ bị đối tượng nhắn tin mượn tiền lừa đảo.",
        "content": """## I. Vấn nạn hack tài khoản mạng xã hội tống tiền, mượn tiền

Tài khoản mạng xã hội cá nhân (Facebook, Zalo, Telegram) không chỉ chứa đựng đời sống riêng tư mà còn là kênh kết nối uy tín giữa bạn và người thân, đối tác. Khi tài khoản bị kẻ gian chiếm đoạt, uy tín cá nhân của bạn sẽ bị lợi dụng để đi lừa đảo toàn bộ bạn bè trong danh bạ.

Kẻ gian thường sử dụng các kỹ thuật tinh vi: gửi link bình chọn cuộc thi ảnh, link xem video giật gân, hoặc tấn công đánh cắp Cookie đăng nhập trình duyệt (Session Hijacking).

![Bảo vệ tài khoản mạng xã hội an toàn](https://images.unsplash.com/photo-1614064641938-3bbee52942c7?auto=format&fit=crop&w=1200&q=80)

---

## II. Kịch bản mượn tiền sau khi chiếm đoạt tài khoản

1. Kẻ gian không đổi mật khẩu ngay mà âm thầm đọc lịch sử tin nhắn để nắm bắt mối quan hệ: ai là người hay chuyển tiền, xưng hô ra sao (anh/em, mày/tao, bố/con).
2. Kẻ gian đổi thông tin liên kết (email, số điện thoại) và đăng xuất chủ tài khoản ra khỏi thiết bị.
3. Đồng loạt nhắn tin cho hàng chục người trong danh bạ với lý do khẩn cấp: *"Đang có việc cần gấp 10-20 triệu chuyển khoản giúp, chiều/mai trả lại ngay"*.
4. Số tài khoản nhận tiền thường có tên chủ tài khoản trùng tên hoặc gần giống với tên nạn nhân (nhờ sử dụng các tài khoản ngân hàng rác được thuê/mua) khiến người nhận hoàn toàn mất cảnh giác.

---

## III. Hướng dẫn thiết lập bảo mật tối đa cho tài khoản

| Biện pháp | Hướng dẫn thao tác |
| :--- | :--- |
| **Bật xác thực hai yếu tố (2FA)** | Sử dụng ứng dụng xác thực như **Google Authenticator** hoặc **Microsoft Authenticator** (không dùng SMS 2FA) |
| **Cảnh báo đăng nhập lạ** | Bật thông báo khi có thiết bị lạ hoặc trình duyệt mới đăng nhập vào tài khoản |
| **Kiểm tra phiên đăng nhập** | Thường xuyên vào phần *Bảo mật* -> *Nơi bạn đã đăng nhập* để đăng xuất khỏi các thiết bị lạ |
| **Tuyệt đối không click link lạ** | Không đăng nhập Facebook/Zalo qua các trang web bình chọn, trắc nghiệm tính cách |

---

## IV. Quy trình xử lý khi tài khoản vừa bị hack

1. **Thông báo công khai ngay lập tức:** Dùng số điện thoại hoặc nhờ người thân đăng bài cảnh báo lên Facebook/Zalo: *"Tài khoản của tôi đang bị hack, tuyệt đối không chuyển tiền nếu nhận được tin nhắn hỏi vay mượn!"*.
2. **Liên hệ hỗ trợ lấy lại tài khoản:** Sử dụng trang hỗ trợ chính thức `facebook.com/hacked` hoặc liên hệ bộ phận hỗ trợ của nền tảng để gửi giấy tờ tùy thân khôi phục.
3. **Quét virus thiết bị:** Chạy phần mềm diệt virus trên máy tính và điện thoại để loại bỏ mã độc đánh cắp cookie.
""",
    },
    35: {
        "title": "Bẫy vay tiền qua App (Tín dụng đen) và các chiêu trò tống tiền, khủng bố",
        "summary": "Bóc trần cạm bẫy vay tiền nhanh qua ứng dụng truy cập danh bạ, lãi suất cắt cổ 1000%/năm và cách ứng phó pháp lý khi bị khủng bố đòi nợ.",
        "content": """## I. Bản chất của các ứng dụng vay tiền tín dụng đen

Quảng cáo "Vay tiền nhanh không cần thế chấp, giải ngân trong 5 phút chỉ cần CCCD" xuất hiện tràn lan trên mạng xã hội thực chất là cạm bẫy của các đường dây tín dụng đen công nghệ cao. Khi cài đặt các ứng dụng này, người dùng bị buộc phải cấp quyền truy cập toàn bộ: **Danh bạ điện thoại, Vị trí GPS, Bộ sưu tập hình ảnh, Lịch sử cuộc gọi**.

Số tiền thực nhận luôn bị trừ đi 30-50% gọi là "phí dịch vụ", "phí thẩm định", trong khi tiền lãi tăng theo cấp số nhân mỗi ngày, biến khoản vay vài triệu thành khoản nợ hàng trăm triệu chỉ sau vài tuần.

![Tín dụng đen qua ứng dụng di động](https://images.unsplash.com/photo-1554224155-8d04cb21cd6c?auto=format&fit=crop&w=1200&q=80)

---

## II. Các thủ đoạn khủng bố đòi nợ tàn độc

- **Khủng bố danh bạ:** Gọi điện liên tục ngày đêm cho người thân, bạn bè, lãnh đạo công ty của nạn nhân để chửi bới, đe dọa ép trả nợ thay.
- **Ghép ảnh bôi nhọ nhân phẩm:** Ghép ảnh chân dung của nạn nhân và người thân vào các hình ảnh nhạy cảm, hình ảnh cáo phó đám tang, lệnh truy nã giả để phát tán trên mạng xã hội.
- **Dọa giết, tạt chất bẩn:** Nhắn tin đe dọa tính mạng con cái, gia đình nạn nhân nhằm triệt tiêu tinh thần phản kháng.

---

## III. Hướng dẫn ứng phó theo đúng quy định pháp luật

1. **Tuyệt đối không vay app này trả app kia:** Hành động vay app mới để trả nợ app cũ chỉ làm quy mô nợ phình to nhanh chóng và khiến bạn sập bẫy hoàn toàn.
2. **Cắt đứt liên lạc với đối tượng:**
   - Cài đặt ứng dụng chặn cuộc gọi lạ (Truecaller, ShieldCall).
   - Tạm khóa các tài khoản mạng xã hội để ngăn chặn đối tượng lấy cắp thêm hình ảnh bạn bè.
3. **Thông báo cho người thân và đồng nghiệp:**
   Chủ động giải thích rõ ràng với gia đình, cơ quan rằng mình là nạn nhân của bẫy lừa đảo tín dụng đen và hướng dẫn họ chặn số điện thoại đối tượng.
4. **Làm đơn tố cáo đến Cơ quan Công an:**
   Hành vi cho vay lãi nặng trong giao dịch dân sự (lãi suất trên 100%/năm) và hành vi cưỡng đoạt tài sản, làm nhục người khác là các tội danh hình sự nghiêm trọng theo Bộ luật Hình sự. Lưu giữ toàn bộ tin nhắn, ghi âm và sao kê để tố giác.
""",
    },
    36: {
        "title": "Cẩm nang bảo vệ Trẻ em và Người cao tuổi trên không gian mạng",
        "summary": "Phương pháp thiết lập lá chắn an toàn số cho hai đối tượng dễ bị tổn thương nhất trong gia đình trước bẫy lừa đảo và nội dung độc hại trên internet.",
        "content": """## I. Vì sao Trẻ em và Người cao tuổi là mục tiêu hàng đầu?

Trong mỗi gia đình, trẻ em và người cao tuổi là hai nhóm đối tượng yếu thế nhất về mặt nhận thức an ninh mạng:
- **Người cao tuổi:** Thường có tiền tiết kiệm, thiếu kiến thức về công nghệ số, dễ bị hoang mang trước các lời đe dọa của kẻ mạo danh công an, hoặc dễ tin vào các sản phẩm thuốc tiên, bẫy đầu tư sinh lời.
- **Trẻ em:** Chưa có khả năng tự bảo vệ, dễ bị dụ dỗ vào các bẫy nạp thẻ game ảo, gửi ảnh nhạy cảm (sextortion), bắt nạt trực tuyến (cyberbullying) hoặc tiếp xúc với nội dung bạo lực, độc hại.

![Bảo vệ thế hệ trẻ và người lớn tuổi trên không gian số](https://images.unsplash.com/photo-1516627145497-ae6968895b74?auto=format&fit=crop&w=1200&q=80)

---

## II. Biện pháp thiết thực bảo vệ Người cao tuổi

1. **Cài đặt giới hạn kỹ thuật trên điện thoại:**
   - Tắt tính năng cài đặt ứng dụng từ nguồn không xác định (Unknown Sources) trên điện thoại Android của bố mẹ.
   - Bật tính năng cảnh báo cuộc gọi rác và tự động chặn số lạ ngoài danh bạ.
2. **Tách biệt tài khoản ngân hàng:**
   - Hướng dẫn bố mẹ không để số tiền lớn trong tài khoản ngân hàng có kết nối Internet Banking trên điện thoại.
   - Sử dụng sổ tiết kiệm truyền thống tại quầy cho các khoản tiền dưỡng già.
3. **Thường xuyên trò chuyện và cập nhật thông tin:**
   - Chia sẻ các tin tức lừa đảo mới nhất trong bữa cơm gia đình để người lớn tuổi có phản xạ nhận diện.
   - Nhắc nhở nguyên tắc: *Mọi cuộc gọi thông báo tiền bạc, kiện tụng phải hỏi ý kiến con cháu trước khi làm theo*.

---

## III. Biện pháp bảo vệ Trẻ em trên internet

- **Sử dụng công cụ kiểm soát gia đình:** Cài đặt **Google Family Link** hoặc **Apple Screen Time** để quản lý thời gian sử dụng, phê duyệt các ứng dụng trước khi con cài đặt.
- **Giáo dục nguyên tắc bí mật đời tư:** Dạy con không bao giờ chia sẻ địa chỉ nhà, tên trường học, số điện thoại hay hình ảnh cá nhân cho người lạ quen qua game online.
- **Thiết lập không gian an toàn:** Khuyến khích con chia sẻ cởi mở khi gặp phải các tình huống bị đe dọa, ép buộc trên mạng mà không sợ bị bố mẹ mắng mỏ.
""",
    },
    37: {
        "title": "Đã bị lừa đảo trực tuyến: Quy trình 5 bước phản ứng khẩn cấp để giảm thiểu thiệt hại",
        "summary": "Các bước xử lý khẩn cấp trong 24 giờ đầu sau khi bị lừa đảo chuyển tiền: khóa tài khoản, thu thập bằng chứng pháp lý và trình báo cơ quan chức năng.",
        "content": """## I. Tầm quan trọng của 'Khoảng thời gian vàng'

Khi nhận ra mình đã bị lừa đảo chuyển tiền hoặc bị đánh cắp thông tin tài khoản, tâm lý chung của nạn nhân là hoảng loạn, sợ hãi và tự trách bản thân. Tuy nhiên, việc hành động nhanh chóng và chính xác trong **khoảng thời gian vàng (ngay sau khi giao dịch phát sinh)** có ý nghĩa quyết định trong việc bảo toàn số tiền còn lại và tăng cơ hội truy vết dòng tiền.

Hãy thực hiện ngay quy trình 5 bước ứng phó khẩn cấp dưới đây:

![Xử lý khẩn cấp khi bị lừa đảo trực tuyến](https://images.unsplash.com/photo-1450133064473-71024230f91b?auto=format&fit=crop&w=1200&q=80)

---

## II. Quy trình 5 bước phản ứng khẩn cấp

### Bước 1: Khóa tài khoản và liên hệ ngân hàng lập tức (Phút thứ 0 - 15)
- Mở ngay ứng dụng ngân hàng kích hoạt tính năng **Khóa thẻ / Khóa dịch vụ chuyển tiền**.
- Gọi điện thoại ngay đến Hotline của ngân hàng bạn vừa chuyển tiền đi, thông báo bạn vừa thực hiện giao dịch bị lừa đảo, đề nghị ngân hàng hỗ trợ **đình chỉ giao dịch (nếu tiền chưa sang tài khoản đích) hoặc phối hợp với ngân hàng thụ hưởng để phong tỏa tài khoản nhận**.

### Bước 2: Chụp lại toàn bộ chứng cứ điện tử (Phút thứ 15 - 30)
- Chụp ảnh màn hình toàn bộ tin nhắn trao đổi trên Zalo, Facebook, Telegram (chú ý chụp cả thông tin trang cá nhân của đối tượng).
- Xuất sao kê giao dịch ngân hàng có hiển thị rõ: Số tiền, Giờ phút giây giao dịch, Số tài khoản nhận, Tên chủ tài khoản nhận, Mã tham chiếu giao dịch.
- Lưu lại số điện thoại, đường link website, file ứng dụng mà kẻ gian đã gửi cho bạn.

### Bước 3: Đổi toàn bộ mật khẩu từ một thiết bị sạch khác
- Nếu bạn nghi ngờ điện thoại bị cài mã độc, lập tức mượn một chiếc điện thoại sạch khác để đổi mật khẩu email, mật khẩu app ngân hàng, mạng xã hội.
- Đăng xuất tài khoản khỏi tất cả các phiên đăng nhập khác.

### Bước 4: Đến trực tiếp cơ quan Công an làm đơn tố giác tội phạm
- Đến trụ sở Công an phường/xã hoặc Công an quận/huyện nơi bạn cư trú để trình báo sự việc.
- Cung cấp toàn bộ hồ sơ chứng cứ đã chuẩn bị ở Bước 2. Lấy giấy biên nhận tiếp nhận đơn tố giác tội phạm.

### Bước 5: Báo cáo lên Cổng an toàn thông tin quốc gia
- Báo cáo số tài khoản lừa đảo, website độc hại lên hệ thống của Cục An toàn thông tin tại địa chỉ: `https://canhbao.ncsc.gov.vn`.
- Cảnh báo cho người thân, bạn bè để phòng ngừa kẻ gian dùng danh tính của bạn tiếp tục lừa người khác.
""",
    },
    38: {
        "title": "Phương pháp kiểm tra tính pháp lý của doanh nghiệp, sàn giao dịch và website uy tín",
        "summary": "Công cụ và cách thức tra cứu dữ liệu chính thống từ cổng thông tin quốc gia, cơ sở dữ liệu VNNIC, Tín nhiệm mạng trước khi thực hiện giao dịch chuyển tiền.",
        "content": """## I. Tầm quan trọng của việc tự thẩm định thông tin

Trước khi ký hợp đồng làm việc, nạp tiền đầu tư hay mua hàng giá trị lớn qua mạng, việc dành ra 5 phút để kiểm tra tính pháp lý của đối tác có thể giúp bạn tránh được những rủi ro mất tiền tỷ.

Nhà nước Việt Nam đã công khai các cổng dữ liệu mở cho phép bất kỳ công dân nào cũng có thể tra cứu thông tin doanh nghiệp, tên miền và chứng chỉ tín nhiệm hoàn toàn miễn phí.

![Tra cứu thông tin doanh nghiệp và website uy tín](https://images.unsplash.com/photo-1460925895917-afdab827c52f?auto=format&fit=crop&w=1200&q=80)

---

## II. 4 Cổng tra cứu quốc gia chính thống bắt buộc phải biết

### 1. Cổng thông tin quốc gia về đăng ký doanh nghiệp
- **Địa chỉ:** `https://dangkykinhdoanh.gov.vn`
- **Tác dụng:** Nhập mã số thuế hoặc tên doanh nghiệp để tra cứu: Tình trạng hoạt động (còn hoạt động hay đã giải thể), Tên người đại diện theo pháp luật, Vốn điều lệ, Ngành nghề đăng ký kinh doanh thực tế.

### 2. Cổng tra cứu thông tin tên miền quốc gia (VNNIC)
- **Địa chỉ:** `https://tracuutenmien.gov.vn` hoặc nhắn tin cú pháp `TMT [Tên miền]` gửi **156**.
- **Tác dụng:** Kiểm tra chủ sở hữu tên miền là tổ chức hay cá nhân ẩn danh, ngày đăng ký tên miền. Các website lừa đảo thường có tên miền mới đăng ký dưới 6 tháng và sử dụng dịch vụ ẩn danh tính chủ thể.

### 3. Hệ sinh thái Tín nhiệm mạng (Bộ Thông tin và Truyền thông)
- **Địa chỉ:** `https://tinnhiemmang.vn`
- **Tác dụng:** Tra cứu danh bạ website đạt chuẩn an toàn thông tin (nhãn tín nhiệm mạng), đồng thời tra cứu danh sách các trang web lừa đảo, tài khoản ngân hàng lừa đảo đã bị cơ quan chức năng đưa vào danh sách đen (Blacklist).

### 4. Cổng thông tin Ủy ban Chứng khoán Nhà nước
- **Địa chỉ:** `https://ssc.gov.vn`
- **Tác dụng:** Tra cứu danh sách các công ty chứng khoán, công ty quản lý quỹ được pháp luật Việt Nam bảo hộ. Nếu một sàn giao dịch tài chính không có tên trong danh sách này, đó 100% là sàn hoạt động bất hợp pháp.

---

## III. Bảng kiểm tra nhanh (Checklist) trước khi chuyển tiền giao dịch

| Tiêu chí | Đạt chuẩn an toàn | Nghi ngờ lừa đảo |
| :--- | :--- | :--- |
| **Tên chủ tài khoản nhận tiền** | Đúng tên pháp nhân công ty đã đăng ký | Tên tài khoản cá nhân hoặc tên công ty ma không tìm thấy trên cổng đăng ký kinh doanh |
| **Tên miền website** | Tên miền `.vn` xác thực danh tính rõ ràng | Tên miền quốc tế lạ (.xyz, .top, .vip, .cc) mới đăng ký ít ngày |
| **Địa chỉ trụ sở** | Có địa chỉ vật lý rõ ràng, có biển hiệu, kiểm tra được trên bản đồ | Địa chỉ chung cư, địa chỉ ảo hoặc không có số điện thoại cố định |
| **Cam kết tài chính** | Minh bạch, có điều khoản hợp đồng rõ ràng | Cam kết lợi nhuận bất thường, thúc ép chuyển tiền gấp |
""",
    },
}

# Quizzes for lessons 24 to 27
LESSON_QUIZZES = {
    24: [
        {
            "question": "Khi nhận được cuộc gọi từ người tự xưng là cán bộ Viện kiểm sát yêu cầu chuyển 200 triệu đồng vào 'tài khoản tạm giữ của cơ quan điều tra' để chứng minh không liên quan đường dây rửa tiền, bạn nên làm gì?",
            "options": [
                {"id": "A", "text": "Lập tức ra ngân hàng chuyển tiền ngay vì sợ bị phát lệnh bắt tạm giam."},
                {"id": "B", "text": "Cúp máy ngay lập tức, không chuyển bất kỳ khoản tiền nào và đến trực tiếp Công an phường/xã để trình báo."},
                {"id": "C", "text": "Nhắn tin năn nỉ cán bộ giảm số tiền tạm giữ xuống 50 triệu."},
                {"id": "D", "text": "Hỏi xin số tài khoản cá nhân của cán bộ đó để gửi tiền lót tay."},
            ],
            "correct_answer": "B",
            "explanation": "Cơ quan Công an, Viện kiểm sát KHÔNG BAO GIỜ làm việc qua điện thoại và KHÔNG BAO GIỜ yêu cầu công dân chuyển tiền vào bất kỳ tài khoản ngân hàng nào để chứng minh trong sạch.",
        }
    ],
    25: [
        {
            "question": "Thao tác cài đặt kỹ thuật nào trên điện thoại thông minh Android giúp ngăn chặn hiệu quả tin nhắn mạo danh từ trạm BTS giả mạo?",
            "options": [
                {"id": "A", "text": "Bật chế độ tiết kiệm pin tối đa."},
                {"id": "B", "text": "Vào phần cài đặt SIM và tắt tính năng 'Cho phép 2G' (Allow 2G)."},
                {"id": "C", "text": "Xóa toàn bộ ứng dụng mạng xã hội khỏi máy."},
                {"id": "D", "text": "Bật chế độ Không làm phiền liên tục."},
            ],
            "correct_answer": "B",
            "explanation": "Trạm BTS giả mạo lợi dụng lỗ hổng không xác thực hai chiều của mạng 2G để phát tán tin nhắn mạo danh Brandname. Tắt 2G buộc điện thoại chỉ kết nối vào 4G/5G an toàn.",
        }
    ],
    26: [
        {
            "question": "Theo quy định tại Quyết định số 2345/QĐ-NHNN của Ngân hàng Nhà nước, hạn mức chuyển khoản nào bắt buộc phải xác thực bằng sinh trắc học khuôn mặt khớp với dữ liệu CCCD gắn chip?",
            "options": [
                {"id": "A", "text": "Tất cả các giao dịch từ 50.000 đồng trở lên."},
                {"id": "B", "text": "Giao dịch trên 10 triệu đồng/lần hoặc tổng giao dịch trong ngày vượt quá 20 triệu đồng."},
                {"id": "C", "text": "Chỉ áp dụng cho các giao dịch chuyển tiền ra nước ngoài."},
                {"id": "D", "text": "Chỉ áp dụng khi mở tài khoản tiết kiệm mới tại quầy."},
            ],
            "correct_answer": "B",
            "explanation": "Quyết định 2345/QĐ-NHNN quy định bắt buộc xác thực sinh trắc học khuôn mặt đối với các giao dịch chuyển tiền trên 10 triệu đồng/lần hoặc tổng giá trị giao dịch trong ngày vượt 20 triệu đồng.",
        }
    ],
    27: [
        {
            "question": "Khi nhận được cuộc gọi video call từ tài khoản Facebook của con bạn đang du học hỏi vay tiền gấp, dấu hiệu nào cho thấy đây có thể là cuộc gọi Deepfake giả mạo?",
            "options": [
                {"id": "A", "text": "Khẩu hình miệng không khớp tiếng, hình ảnh khuôn mặt bị giật méo khi cử động và cuộc gọi bị ngắt sau vài giây."},
                {"id": "B", "text": "Điện thoại hiển thị đúng tên tài khoản Facebook của con."},
                {"id": "C", "text": "Âm thanh cuộc gọi nghe to rõ ràng."},
                {"id": "D", "text": "Con yêu cầu chuyển tiền vào đúng số tài khoản ngân hàng chính chủ của con."},
            ],
            "correct_answer": "A",
            "explanation": "Thuật toán Deepfake thời gian thực thường gặp lỗi trễ khẩu hình, biến dạng hình ảnh khi có chuyển động nhanh hoặc góc quay nghiêng, và kẻ gian thường cúp máy rất nhanh lấy cớ mạng yếu.",
        }
    ],
}

# Scenarios for lessons 24 to 27
LESSON_SCENARIOS = {
    24: {
        "title": "Diễn tập: Cuộc gọi mạo danh Viện kiểm sát thông báo Lệnh bắt tạm giam",
        "description": "Thực hành xử lý tình huống nhận cuộc gọi đe dọa khởi tố vụ án rửa tiền và yêu cầu chuyển tiền vào tài khoản tạm giữ.",
        "steps": [
            {
                "actor": "Kẻ lừa đảo",
                "text": "Tôi là Thiếu tá Nguyễn Văn Hùng, Cán bộ Cục Cảnh sát điều tra tội phạm về ma túy. Số CCCD của anh đang liên quan trực tiếp đến đường dây rửa tiền xuyên quốc gia của đối tượng Trần Văn Nam. Hiện Viện kiểm sát tối cao đã phê chuẩn Lệnh bắt tạm giam đối với anh!",
                "analysis": "Kẻ gian dùng tên tuổi chức danh cơ quan pháp luật cụ thể, tạo áp lực tâm lý hoảng loạn ngay từ câu đầu tiên.",
            },
            {
                "actor": "Nạn nhân",
                "text": "Trời ơi, tôi là công chức nhà nước cả đời lương thiện, có bao giờ biết ma túy rửa tiền gì đâu cán bộ! Có nhầm lẫn gì không ạ?",
                "analysis": "Nạn nhân rơi vào trạng thái sợ hãi, bắt đầu thanh minh và vô tình tạo điều kiện cho đối tượng dẫn dắt.",
            },
            {
                "actor": "Kẻ lừa đảo",
                "text": "Tôi đã gửi hình ảnh Lệnh bắt có chữ ký và dấu đỏ qua Zalo cho anh. Để chứng minh trong sạch, anh phải giữ bí mật tuyệt đối, thuê phòng kín không cho ai biết và chuyển ngay toàn bộ số tiền tiết kiệm 300 triệu vào Tài khoản tạm giữ của Ban chuyên án để giám định nguồn tiền!",
                "analysis": "Dấu hiệu bóc trần: Cơ quan điều tra không bao giờ làm việc qua Zalo, không có cái gọi là 'Tài khoản tạm giữ của Ban chuyên án'.",
            },
            {
                "actor": "Hệ thống ShieldCall",
                "text": "CẢNH BÁO NGUY HIỂM: Đây là thủ đoạn lừa đảo 100%! Cơ quan Công an và VKS chỉ làm việc trực tiếp tại trụ sở có giấy triệu tập giấy. Hãy ngắt cuộc gọi ngay lập tức và đến Công an phường trình báo!",
                "analysis": "Nguyên tắc bất di bất dịch: Tuyệt đối không chuyển tiền theo bất kỳ yêu cầu nào qua điện thoại.",
            },
            {
                "actor": "Nạn nhân",
                "text": "Tôi đã cúp máy và đến thẳng Công an phường nơi cư trú. Các đồng chí công an khẳng định đây là chiêu trò lừa đảo qua mạng và hướng dẫn tôi làm đơn phản ánh. Suýt chút nữa là mất trắng 300 triệu tích góp cả đời!",
                "analysis": "Hành động chuẩn xác: Ngắt liên lạc và xác minh trực tiếp tại cơ quan chức năng sở tại.",
            },
        ],
    },
    25: {
        "title": "Diễn tập: Xử lý SMS Brandname giả mạo báo lỗi bảo mật tài khoản",
        "description": "Nhận diện tin nhắn mạo danh ngân hàng gửi từ trạm BTS giả và cách ứng xử phòng vệ.",
        "steps": [
            {
                "actor": "Kẻ lừa đảo",
                "text": "[Vietcombank] Canh bao: Tai khoan cua quy khach da bi dang nhap tren mot thiet bi khac. Neu khong phai ban, vui long truy cap link http://vietcombank-login-security.xyz de xac thuc ngay.",
                "analysis": "Tin nhắn nằm chung hộp thư Vietcombank do BTS giả phát sóng 2G. Đuôi tên miền lạ .xyz là dấu hiệu phishing rõ ràng.",
            },
            {
                "actor": "Nạn nhân",
                "text": "Ủa tin nhắn nằm trong hộp thư của Vietcombank thật nè, chắc tài khoản mình bị ai hack rồi, phải bấm link hủy đăng nhập ngay mới được!",
                "analysis": "Tâm lý hoảng sợ khiến nạn nhân tin vào tên Brandname hiển thị mà không để ý địa chỉ URL mạo danh.",
            },
            {
                "actor": "Hệ thống ShieldCall",
                "text": "DỪNG LẠI! Trang web chính thức của Vietcombank chỉ có địa chỉ duy nhất: https://vietcombank.com.vn. Tên miền .xyz là giả mạo! Hãy tắt 2G trên điện thoại và mở app VCB Digibank để kiểm tra!",
                "analysis": "Chỉ kiểm tra thông tin tài khoản qua ứng dụng ngân hàng số chính thống đã cài trên máy.",
            },
            {
                "actor": "Nạn nhân",
                "text": "Mình vừa mở app VCB Digibank bằng vân tay, tài khoản hoàn toàn bình thường, không có cảnh báo nào cả. Mình cũng đã tắt tùy chọn 'Cho phép 2G' trên máy Android theo hướng dẫn!",
                "analysis": "Nạn nhân đã bảo vệ tài sản an toàn và nâng cao năng lực tự vệ kỹ thuật cho thiết bị.",
            },
        ],
    },
    26: {
        "title": "Diễn tập: Kẻ gian dụ dỗ cài đặt ứng dụng Dịch vụ công chứa mã độc",
        "summary": "Nhận biết bẫy gửi file APK mạo danh cổng Dịch vụ công quốc gia để chiếm quyền Accessibility.",
        "steps": [
            {
                "actor": "Kẻ lừa đảo",
                "text": "Chào anh, tôi là cán bộ hỗ trợ dịch vụ công quận. Hồ sơ định danh mức 2 của anh đang bị treo do sai lệch thông tin bảo hiểm. Tôi gửi anh link tải app DichVuCong.apk qua Zalo, anh cài đặt và cấp quyền để hệ thống tự cập nhật nhé.",
                "analysis": "Kẻ gian viện cớ hỗ trợ dịch vụ công để dụ nạn nhân cài file APK ngoài kho ứng dụng Google Play / App Store.",
            },
            {
                "actor": "Nạn nhân",
                "text": "Ủa sao app này khi cài nó đòi cấp quyền 'Hỗ trợ tiếp cận' (Accessibility) và quyền xem màn hình vậy cán bộ?",
                "analysis": "Dấu hiệu cực kỳ nguy hiểm: Quyền Hỗ trợ tiếp cận cho phép ứng dụng đọc trộm mật khẩu, mã OTP và tự bấm chuyển tiền.",
            },
            {
                "actor": "Hệ thống ShieldCall",
                "text": "NGUY HIỂM CỰC ĐỘ! Cơ quan nhà nước không bao giờ gửi file APK qua Zalo. Nếu cấp quyền Accessibility, mã độc sẽ đọc trộm Smart OTP và chuyển sạch tiền trong tài khoản của bạn. Xóa file ngay!",
                "analysis": "Quy tắc an toàn thiết bị di động: Tuyệt đối không cài file APK từ link lạ và không bật quyền Hỗ trợ tiếp cận cho ứng dụng không rõ nguồn gốc.",
            },
            {
                "actor": "Nạn nhân",
                "text": "Mình lập tức hủy cài đặt, xóa file APK và chặn số Zalo đối tượng. Sau đó mình kiểm tra lại trên app VNeID chính thức thì định danh mức 2 của mình đã hoàn tất từ lâu rồi!",
                "analysis": "Xử lý chuẩn xác: Xóa mã độc kịp thời và kiểm chứng qua ứng dụng chính thống.",
            },
        ],
    },
    27: {
        "title": "Diễn tập: Cuộc gọi video Deepfake mượn tiền gấp từ tài khoản bạn thân",
        "description": "Nhận biết cuộc gọi video Deepfake mượn tiền và phương pháp kiểm chứng qua câu hỏi bí mật.",
        "steps": [
            {
                "actor": "Kẻ lừa đảo",
                "text": "(Gọi video call Messenger 8 giây) 'Mày hả... tao đang ở viện với người nhà... mạng yếu quá... tao nhắn tin nhé!' (Ngắt cuộc gọi và nhắn tin): 'Mày chuyển gấp cho tao mượn 15 triệu đóng viện phí với, chiều tao về tao chuyển trả lại ngay!'",
                "analysis": "Đối tượng gọi video cực ngắn với hình ảnh bạn thân để tạo lòng tin rồi chuyển sang nhắn tin hỏi vay tiền.",
            },
            {
                "actor": "Nạn nhân",
                "text": "Thấy đúng mặt bạn thân mình trong viện rồi. Để mình chuyển khoản luôn cho nó, sợ người nhà nó có chuyện gấp...",
                "analysis": "Nạn nhân bị tác động bởi tình cảm bạn bè và hình ảnh video ngắn nên chuẩn bị chuyển tiền vội vã.",
            },
            {
                "actor": "Hệ thống ShieldCall",
                "text": "KHOAN ĐÃ! Nhìn kỹ số tài khoản nhận tiền: Tên chủ tài khoản là ai? Hãy hỏi bạn một câu hỏi bí mật mà chỉ hai người biết, hoặc cúp Messenger gọi trực tiếp vào số SIM di động của bạn!",
                "analysis": "Luôn kiểm tra tên chủ tài khoản thụ hưởng và xác minh qua kênh viễn thông độc lập.",
            },
            {
                "actor": "Nạn nhân",
                "text": "Mình nhắn lại: 'Ủa thế con cún nhà mày hôm qua đỡ chưa?'. Đối tượng trả lời bừa: 'Đỡ rồi mày chuyển tiền nhanh đi!'. Trong khi bạn mình chỉ nuôi mèo, không nuôi chó! Mình gọi điện SIM di động cho bạn thì bạn bảo tài khoản Facebook vừa bị hack 30 phút trước!",
                "analysis": "Áp dụng câu hỏi bẫy kiểm chứng thành công xuất sắc: Lật tẩy hoàn toàn kẻ mạo danh Deepfake.",
            },
        ],
    },
}


def run_enrichment():
    print("=== STARTING COMPREHENSIVE CONTENT ENRICHMENT ===")

    with transaction.atomic():
        # 1. Enrich Lessons 24-27
        print("\n--- Enriching Lessons 24-27 ---")
        for lesson_id, data in LESSONS_ENRICHMENT.items():
            try:
                lesson = LearnLesson.objects.get(id=lesson_id)
                lesson.title = data["title"]
                lesson.summary = data["summary"]
                lesson.content = data["content"].strip()
                lesson.save(update_fields=["title", "summary", "content"])
                print(f"[OK] Enriched Lesson {lesson.id}: {lesson.title} (len={len(lesson.content)})")
            except LearnLesson.DoesNotExist:
                print(f"[WARN] Lesson {lesson_id} not found!")

        # 2. Enrich Articles 21-38
        print("\n--- Enriching Articles 21-38 ---")
        for article_id, data in ARTICLES_ENRICHMENT.items():
            try:
                article = Article.objects.get(id=article_id)
                article.title = data["title"]
                article.summary = data["summary"]
                article.content = data["content"].strip()
                article.save(update_fields=["title", "summary", "content"])
                print(f"[OK] Enriched Article {article.id}: {article.title} (len={len(article.content)})")
            except Article.DoesNotExist:
                print(f"[WARN] Article {article_id} not found!")

        # 3. Add Quizzes for Lessons 24-27
        print("\n--- Adding Quizzes for Lessons 24-27 ---")
        for lesson_id, quiz_list in LESSON_QUIZZES.items():
            try:
                lesson = LearnLesson.objects.get(id=lesson_id)
                for q_data in quiz_list:
                    quiz, created = LearnQuiz.objects.get_or_create(
                        lesson=lesson,
                        question=q_data["question"],
                        defaults={
                            "question_type": "single",
                            "options": q_data["options"],
                            "correct_answer": q_data["correct_answer"],
                            "correct_answers": [q_data["correct_answer"]],
                            "explanation": q_data["explanation"],
                        }
                    )
                    if not created:
                        quiz.options = q_data["options"]
                        quiz.correct_answer = q_data["correct_answer"]
                        quiz.correct_answers = [q_data["correct_answer"]]
                        quiz.explanation = q_data["explanation"]
                        quiz.save()
                    print(f"[OK] Quiz attached to Lesson {lesson_id}: ID={quiz.id}")
            except LearnLesson.DoesNotExist:
                print(f"[WARN] Lesson {lesson_id} not found for quiz!")

        # 4. Add Scenarios for Lessons 24-27
        print("\n--- Adding Scenarios for Lessons 24-27 ---")
        for lesson_id, sc_data in LESSON_SCENARIOS.items():
            try:
                lesson = LearnLesson.objects.get(id=lesson_id)
                sc, created = LearnScenario.objects.get_or_create(
                    lesson=lesson,
                    defaults={
                        "title": sc_data["title"],
                        "description": sc_data.get("description", ""),
                        "content": {"steps": sc_data["steps"]},
                    }
                )
                if not created:
                    sc.title = sc_data["title"]
                    sc.description = sc_data.get("description", "")
                    sc.content = {"steps": sc_data["steps"]}
                    sc.save()
                print(f"[OK] Scenario attached to Lesson {lesson_id}: ID={sc.id} ({sc.title})")
            except LearnLesson.DoesNotExist:
                print(f"[WARN] Lesson {lesson_id} not found for scenario!")

    print("\n=== CONTENT ENRICHMENT COMPLETE! ===")

if __name__ == '__main__':
    run_enrichment()

