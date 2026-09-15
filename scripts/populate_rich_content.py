#!/usr/bin/env python
"""
populate_rich_content.py
Updates LearnLesson, LearnQuiz, LearnScenario and Article objects with rich, 
detailed, high-quality cybersecurity education content, embedded images,
cover images, structured quizzes, and interactive scenarios.
"""
import os
import sys
import django

# Setup Django environment
sys.path.append('/data/Sentinel_Team_Project')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'PKV.settings')
django.setup()

from django.core.files import File
from api.core.models import (
    LearnLesson, LearnQuiz, LearnScenario, Article,
    ArticleCategory, QuizQuestionType
)

print("Updating LearnLessons and Articles with high-quality content...")

# ══════════════════════════════════════════════════════════════════════════════
# 1. COMPREHENSIVE LESSONS DATA
# ══════════════════════════════════════════════════════════════════════════════
LESSONS = [
    {
        "slug": "bts-fake",
        "title": "Tấn công trạm BTS giả và SMS Brandname lừa đảo: Cơ chế và cách phòng vệ",
        "category": ArticleCategory.ALERT,
        "summary": "Phân tích kỹ thuật giải mã cách kẻ gian lợi dụng lỗ hổng sóng 2G để dựng trạm phát sóng di động giả mạo (IMSI Catcher), chèn tin nhắn lừa đảo vào luồng tin nhắn chính thức của ngân hàng và quy trình phòng thủ.",
        "cover_file": "media/learn/covers/bts_fake.jpg",
        "content": """## 1. Bản chất hiểm độc của trạm phát sóng BTS giả mạo (IMSI Catcher)

Trong các chiến dịch lừa đảo chiếm đoạt tài khoản ngân hàng tinh vi nhất tại Việt Nam hiện nay, hình thức tấn công qua **trạm BTS giả mạo** (Fake Base Transceiver Station / IMSI Catcher) là mối đe dọa kỹ thuật nguy hiểm nhất đối với người dân. 

Khác với các tin nhắn rác truyền thống được gửi từ số thuê bao rác 10 số, tin nhắn từ trạm BTS giả mạo có thể **mạo danh 100% Brandname chính thức** của các ngân hàng thương mại lớn (như *Vietcombank, Techcombank, MBBank, BIDV, ACB*) hoặc cơ quan nhà nước (*VNeID, BHXH, Cổng DVC Quốc gia*). Đặc biệt nguy hiểm, tin nhắn giả này **nằm chung một luồng (thread) hội thoại** với các tin nhắn thông báo biến động số dư và mã OTP hợp pháp mà ngân hàng từng gửi cho bạn trước đây.

![Trạm thu phát sóng viễn thông và thiết bị BTS giả mạo](https://images.unsplash.com/photo-1544197150-b99a580bb7a8?auto=format&fit=crop&w=1200&q=80)

---

## 2. Giải mã cơ chế kỹ thuật: Tại sao điện thoại sập bẫy?

Kẻ gian lợi dụng một điểm yếu bảo mật cốt tử có từ hơn 30 năm trước của tiêu chuẩn viễn thông di động thế hệ thứ 2:

### Lỗ hổng không xác thực hai chiều của mạng 2G (GSM)
* **Trong mạng 4G/5G (LTE/NR)**: Thiết bị di động (User Equipment - UE) và trạm phát sóng (eNodeB / gNodeB) bắt buộc phải thực hiện cơ chế xác thực lẫn nhau (Mutual Authentication) bằng khóa mật mã đối xứng được lưu trữ an toàn trong chip thẻ SIM. Trạm BTS giả không thể giả lập được chữ ký của nhà mạng viễn thông.
* **Trong mạng 2G (GSM 900/1800)**: Tiêu chuẩn chỉ xác thực chiều từ người dùng lên mạng lưới, nhưng **không hề xác thực chiều ngược lại**. Chiếc điện thoại thông minh của bạn không có cách nào để biết được cột sóng 2G mà nó đang kết nối là trạm hợp pháp của Viettel/VNPT/MobiFone hay là chiếc hộp SDR do kẻ gian chế tạo!

```
[ Điện thoại người dùng ]  <====== Sóng 4G/5G hợp pháp (Viettel, Vina, Mobi)
          |
          |  (Kẻ gian phát xung công suất cao, gây nhiễu dải tần 4G)
          v
[ Rơi xuống mạng 2G ]     <====== Trạm BTS giả mạo (Giấu trong cốp ô tô/xe máy)
          |
          +---> Ép nhận bản tin SMS Broadcast (Sender ID: Vietcombank, MBBank...)
```

### Kịch bản di động trên đường phố
Thiết bị BTS giả thường được chế tạo bằng công nghệ vô tuyến định nghĩa bằng phần mềm (SDR - Software Defined Radio) với kích thước nhỏ gọn chỉ bằng chiếc vali xách tay. Đối tượng đặt thiết bị vào cốp xe máy hoặc ghế sau ô tô di chuyển với tốc độ 20 - 30 km/h qua các tuyến phố đông dân cư, trường đại học, khu chung cư hoặc trung tâm thương mại.

Trong bán kính phủ sóng 100m - 500m, thiết bị phát công suất cực lớn làm suy giảm tín hiệu 4G cục bộ, ép toàn bộ thuê bao di động lân cận phải rớt xuống kết nối 2G. Ngay khi thiết bị di động "bắt sóng", trạm phát lệnh gửi hàng nghìn tin nhắn SMS rác đồng loạt chỉ trong vài giây.

---

## 3. Phân tích kịch bản tin nhắn mạo danh thực tế

Nội dung tin nhắn từ trạm BTS giả luôn đánh thẳng vào tâm lý hoảng loạn, cấp bách hoặc lòng tham của nạn nhân:

| Loại kịch bản | Nội dung tin nhắn giả mạo điển hình | Nguy cơ thực tế |
| :--- | :--- | :--- |
| **Đe dọa khóa tài khoản** | *"Tài khoản của quý khách bị nghi ngờ đăng nhập bất thường tại Singapore lúc 02:15. Vui lòng xác thực ngay tại vietcombank-ibanking.top nếu không tài khoản sẽ bị đóng băng vĩnh viễn."* | Nạn nhân sợ bị mất tiền nên bấm link gấp mà không kịp suy xét. |
| **Trừ tiền dịch vụ ẩn** | *"Tài khoản quý khách đã gia hạn gói dịch vụ VIP 5.200.000 VNĐ. Để hủy dịch vụ không mất phí, vui lòng truy cập ngay..."* | Nạn nhân bực mình vì bị trừ oan tiền, vội vã truy cập link để yêu cầu hoàn tiền. |
| **Nâng cấp điểm thưởng** | *"Quý khách có 12.500 điểm thưởng sắp hết hạn. Đổi ngay iPhone 15 Pro Max tại link..."* | Đánh vào lòng tham quà tặng công nghệ miễn phí. |

![Giao diện tin nhắn và website lừa đảo](https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&w=1200&q=80)

---

## 4. Những hiểu lầm chết người cần xóa bỏ ngay

> [!WARNING]
> **Hiểu lầm 1: "Tin nhắn nằm chung hộp thư với tin nhắn biến động số dư ngân hàng thì chắc chắn là thật!"**  
> **Thực tế:** Hệ điều hành điện thoại (cả iOS lẫn Android) tự động gom nhóm tin nhắn chỉ dựa vào tên người gửi (Sender ID). Do trạm BTS giả phát chuỗi ký tự y hệt tên ngân hàng, điện thoại ngây thơ xếp tin nhắn độc hại vào chung lịch sử giao dịch với ngân hàng thật.

> [!IMPORTANT]
> **Hiểu lầm 2: "Trang web có biểu tượng ổ khóa bảo mật SSL (https) thì không phải lừa đảo!"**  
> **Thực tế:** Ổ khóa SSL ngày nay được các tổ chức chứng thực cấp phát miễn phí (như Let's Encrypt, Cloudflare) hoàn toàn tự động chỉ sau 30 giây. Bất kỳ kẻ gian nào đăng ký tên miền lừa đảo cũng đều có ổ khóa bảo mật. Ổ khóa chỉ chứng minh đường truyền được mã hóa, không chứng minh chủ trang web là người tử tế!

---

## 5. Cẩm nang hành động phòng vệ chuẩn chuyên gia

Để bảo vệ bản thân và người thân trước vấn nạn trạm BTS giả, hãy áp dụng triệt để bộ quy tắc 4 bước sau:

### Bước 1: Tắt tính năng 2G trên điện thoại thông minh (Cực kỳ khuyến nghị)
Hiện nay các nhà mạng Việt Nam đã tiến hành lộ trình tắt sóng 2G thương mại. Trên các hệ điều hành mới:
* **Trên iPhone (iOS 17+)**: Vào *Cài đặt (Settings)* &rarr; *Mạng di động (Cellular)* &rarr; *Tùy chọn dữ liệu di động* &rarr; *Bật LTE/5G* và tắt các chế độ 2G cũ.
* **Trên Android (Android 12+)**: Vào *Cài đặt* &rarr; *Mạng và Internet* &rarr; *SIM* &rarr; Tắt tùy chọn **"Cho phép 2G" (Allow 2G)**. Khi tính năng này tắt, điện thoại sẽ từ chối kết nối vào mọi trạm phát sóng 2G giả mạo!

### Bước 2: Nguyên tắc vàng của Hiệp hội Ngân hàng Việt Nam
Ngân hàng thương mại tại Việt Nam **TUYỆT ĐỐI KHÔNG BAO GIỜ** gửi tin nhắn SMS có đính kèm đường link yêu cầu khách hàng đăng nhập tài khoản Internet Banking, nhập tên đăng nhập, mật khẩu hoặc mã OTP! Bất kỳ tin nhắn nào có link yêu cầu đăng nhập đều là **LỪA ĐẢO 100%**.

### Bước 3: Tra cứu trên ShieldCall Scan Tool
Nếu nhận được đường link đáng ngờ, hãy sao chép và dán vào thanh tra cứu [ShieldCall Scan](/scan/website/) để hệ thống tự động kiểm tra WHOIS, độ tuổi tên miền, DNS và đối soát cơ sở dữ liệu quốc gia về website độc hại.
""",
        "quizzes": [
            {
                "question": "Vì sao tin nhắn lừa đảo từ trạm BTS giả lại có thể chui vào cùng hộp thư với tin nhắn SMS thật của ngân hàng?",
                "options": [
                    {"id": "A", "text": "Do hệ thống bảo mật của máy chủ ngân hàng đã bị hacker xâm nhập và chiếm quyền."},
                    {"id": "B", "text": "Do điện thoại gom nhóm tin nhắn dựa theo tên Brandname người gửi, mà sóng 2G của trạm BTS giả mạo được Brandname bất kỳ."},
                    {"id": "C", "text": "Do nhà mạng viễn thông bán thông tin khách hàng cho kẻ lừa đảo."},
                    {"id": "D", "text": "Do điện thoại của người dùng đã bị nhiễm mã độc trojan từ trước."}
                ],
                "correct_answer": "B",
                "explanation": "Điện thoại thông minh gom tin nhắn vào luồng dựa trên chuỗi Sender ID. Trạm BTS giả lợi dụng việc mạng 2G không xác thực hai chiều để phát tin nhắn mang tên ngân hàng, khiến điện thoại tự động xếp chung vào hộp thư cũ."
            },
            {
                "question": "Biện pháp kỹ thuật nào trên smartphone giúp ngăn chặn triệt để nguy cơ bị trạm BTS giả ép kết nối?",
                "options": [
                    {"id": "A", "text": "Bật chế độ tiết kiệm pin liên tục."},
                    {"id": "B", "text": "Cài đặt điện thoại ở chế độ chỉ dùng 4G/5G và tắt tùy chọn 'Cho phép 2G' (Allow 2G) trong phần cài đặt mạng di động."},
                    {"id": "C", "text": "Xóa toàn bộ tin nhắn cũ của ngân hàng trong hộp thư."},
                    {"id": "D", "text": "Bật Bluetooth liên tục để dò quét thiết bị lạ xung quanh."}
                ],
                "correct_answer": "B",
                "explanation": "Trạm BTS giả hoạt động trên băng tần 2G (GSM). Khi tắt tính năng Cho phép 2G trên điện thoại, thiết bị sẽ từ chối kết nối với trạm BTS giả ngay cả khi sóng 4G/5G bị làm suy yếu."
            }
        ],
        "scenario": {
            "title": "Diễn tập: Xử lý tình huống nhận SMS Brandname ngân hàng yêu cầu đổi mật khẩu",
            "description": "Mô phỏng chân thực diễn biến tâm lý khi người dùng đang di chuyển trên đường phố và nhận được tin nhắn mạo danh ngân hàng MBBank.",
            "content": {
                "steps": [
                    {
                        "actor": "Kẻ lừa đảo",
                        "text": "[MBBank] Canh bao: Tai khoan cua ban dang duoc dang nhap tren thiet bi la tai TP. Ho Chi Minh. Neu khong phai ban, vui long truy cap link http://mbbank-security-check.xyz de huy uy quyen ngay lap tuc.",
                        "analysis": "Kẻ gian lợi dụng trạm BTS giả mạo để phát tin nhắn. Tên miền sử dụng đuôi lạ .xyz và tên miền phụ lookalike đánh lừa thị giác."
                    },
                    {
                        "actor": "Nạn nhân",
                        "text": "Ủa sao tin nhắn này lại nằm ngay dưới tin nhắn thông báo lương tuần trước của mình? Có khi nào tài khoản bị hack thật không? Để bấm vào kiểm tra thử...",
                        "analysis": "Nạn nhân bị đánh lừa bởi vị trí hiển thị chung hộp thư và bắt đầu hoang mang muốn thao tác vội vã."
                    },
                    {
                        "actor": "Hệ thống ShieldCall",
                        "text": "DỪNG LẠI NGAY! Tên miền mbbank-security-check.xyz không phải website chính thức của MBBank (mbbank.com.vn). Hãy ngắt kết nối mạng và mở trực tiếp app MBBank trên điện thoại để kiểm tra số dư!",
                        "analysis": "Nguyên tắc bất di bất dịch: Không bao giờ bấm link trong SMS. Mọi thông tin tài khoản chỉ tra cứu qua app ngân hàng chính thức tải từ App Store / Google Play."
                    },
                    {
                        "actor": "Nạn nhân",
                        "text": "Mình vừa mở app MBBank bằng sinh trắc học vân tay, tài khoản vẫn nguyên vẹn và trong mục Thông báo của app không hề có cảnh báo đăng nhập lạ nào. Suýt chút nữa là mất tiền oan!",
                        "analysis": "Hành động chính xác! Đối soát qua kênh thứ hai (app chính thức) giúp nạn nhân hoàn toàn thoát bẫy kẻ gian."
                    }
                ]
            }
        }
    },
    {
        "slug": "deepfake-ai",
        "title": "Kỹ năng nhận diện và phòng chống cuộc gọi Deepfake AI & Giọng nói nhân tạo",
        "category": ArticleCategory.GUIDE,
        "summary": "Toàn tập kỹ năng nhận diện video call khuôn mặt nhân tạo, công nghệ nhân bản giọng nói (Voice Cloning) và xây dựng quy ước mật mã an toàn nội bộ cho gia đình.",
        "cover_file": "media/learn/covers/deepfake_ai.jpg",
        "content": """## 1. Sự bùng nổ của tội phạm công nghệ Deepfake AI

Trong kỷ nguyên trí tuệ nhân tạo tạo sinh (Generative AI), việc tạo ra một video clip hoặc giọng nói giả mạo không còn là đặc quyền của các hãng phim Hollywood. Tội phạm mạng hiện nay chỉ cần thu thập một đoạn video ngắn 10 giây hoặc một đoạn ghi âm câu nói ngắn trên Facebook, TikTok, YouTube của nạn nhân là có thể huấn luyện mô hình nhân bản giọng nói (Voice Cloning) và hoán đổi khuôn mặt thời gian thực (Real-time Face Swapping).

Các nạn nhân chính thường là người lớn tuổi, phụ huynh có con đi du học, người thân đi làm ăn xa hoặc bạn bè thân thiết.

![Công nghệ trí tuệ nhân tạo nhận diện và tái tạo khuôn mặt](https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?auto=format&fit=crop&w=1200&q=80)

---

## 2. 5 dấu hiệu nhận diện video call Deepfake bằng mắt thường

Mặc dù công nghệ phát triển nhanh, các cuộc gọi Deepfake thời gian thực xử lý trên luồng dữ liệu trực tiếp vẫn để lại những khuyết tật đồ họa (artifacts) vật lý rõ rệt:

1. **Khuyết tật vùng biên (Boundary Artifacts)**: Viền khuôn mặt, tai, đường chân tóc và phần cổ của đối tượng thường có hiện tượng mờ nhòe, rung giật hoặc xuất hiện các vệt răng cưa khi đối tượng quay nghiêng đầu.
2. **Cử động mắt và chớp mắt bất thường**: Người thật chớp mắt trung bình 15 - 20 lần/phút với nhịp điệu tự nhiên. Video Deepfake thường chớp mắt rất ít hoặc chớp giật liên hồi không tự nhiên. Ánh mắt thường vô hồn, con ngươi thiếu phản xạ ánh sáng môi trường thực.
3. **Lệch pha khẩu hình âm thanh (Audio-Lip Sync Mismatch)**: Tiếng nói phát ra thường nhanh hơn hoặc chậm hơn cử động của khuôn miệng. Đặc biệt với tiếng Việt có các âm tiết ngậm môi (*m, b, p*) hoặc nguyên âm phức (*uyên, oang*), mô hình AI thường không khớp khẩu hình chính xác.
4. **Chiêu trò ngắt máy sớm**: Kẻ lừa đảo luôn giữ cuộc gọi video dưới 15 giây. Sau đó kẻ gian chủ động ngắt máy và nhắn tin: *"Mẹ ơi mạng con ở đây chập chờn quá không nghe rõ, con nhắn tin qua đây nhé..."*.
5. **Cử chỉ đưa tay che mặt**: Khi đối tượng đưa tay lên gãi đầu, vuốt mặt hoặc cầm cốc nước đưa lên miệng, hình ảnh bàn tay sẽ bị biến dạng, ngón tay bị hòa lẫn vào da mặt do mô hình AI không xử lý kịp lớp che phủ (occlusion).

---

## 3. Thủ đoạn Voice Cloning qua cuộc gọi thoại thông thường

Kẻ gian sử dụng phần mềm AI nhân bản giọng nói để gọi điện trực tiếp cho cha mẹ vào giờ hành chính hoặc đêm muộn:
* **Chiêu trò "Con đang cấp cứu"**: Giả giọng khóc lóc, hoảng loạn của con cái: *"Bố mẹ ơi con bị tai nạn xe máy ở cổng trường, các bác sĩ đang yêu cầu nộp 50 triệu tiền viện phí gấp để mổ..."*.
* **Chiêu trò "Bị bắt giữ / nợ giang hồ"**: Tiếng người thân xen lẫn tiếng đe dọa, chửi bới ở hậu cảnh nhằm gây áp lực khủng bố tinh thần cực độ khiến nạn nhân không kịp suy nghĩ logic.

![Điện thoại và áp lực tâm lý trong cuộc gọi lừa đảo](https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&w=1200&q=80)

---

## 4. Phương pháp phòng vệ tối thượng: Quy tắc gia đình 3 bước

> [!IMPORTANT]
> **Quy tắc 1: Thiết lập "Mật khẩu an toàn gia đình" (Family Safe Word)**  
> Hãy cùng gia đình quy ước một từ khóa bí mật (ví dụ: tên một món ăn kỷ niệm, biệt danh thời nhỏ của thú cưng...). Khi có bất kỳ cuộc gọi vay tiền, cấp cứu hoặc nhờ chuyển khoản, chỉ cần yêu cầu đối phương đọc mật khẩu gia đình. Kẻ lừa đảo dù có AI tân tiến đến đâu cũng không thể biết được thông tin này!

> [!TIP]
> **Quy tắc 2: Thử thách chuyển động trực tiếp**  
> Nếu đang trong cuộc gọi video nghi vấn, hãy yêu cầu người gọi thực hiện các hành động sau:
> - Giơ ngón tay ngang trước mũi và vẫy qua lại.
> - Quay đầu sang trái 90 độ rồi quay sang phải.
> - Đọc một dãy số ngẫu nhiên bạn vừa đưa ra.  
> Các bộ lọc Deepfake thời gian thực sẽ bị vỡ vụn khung hình ngay lập tức khi gặp vật thể cản trở hoặc chuyển động góc nghiêng lớn.

> [!WARNING]
> **Quy tắc 3: Luôn xác minh qua kênh thứ hai độc lập**  
> Dập máy ngay lập tức và gọi lại vào số thuê bao di động viễn thông (SIM di động có sóng GSM) của người đó hoặc gọi cho bạn cùng phòng, giáo viên chủ nhiệm, đồng nghiệp cơ quan để đối soát thông tin.
""",
        "quizzes": [
            {
                "question": "Dấu hiệu thị giác nào rõ rệt nhất giúp vạch trần cuộc gọi video Deepfake đang diễn ra?",
                "options": [
                    {"id": "A", "text": "Màn hình điện thoại bị nóng lên nhanh chóng."},
                    {"id": "B", "text": "Khi người gọi đưa bàn tay lên che mặt hoặc quay đầu nhanh, hình ảnh khuôn mặt bị méo mó, nhòe giật và khẩu hình không khớp tiếng."},
                    {"id": "C", "text": "Tài khoản Messenger hiển thị biểu tượng chấm xanh online."},
                    {"id": "D", "text": "Âm thanh cuộc gọi có tiếng xe cộ ở ngoài đường."}
                ],
                "correct_answer": "B",
                "explanation": "Mô hình Deepfake thời gian thực gặp khó khăn lớn khi xử lý hiện tượng che phủ (occlusion) như khi bàn tay đưa lên mặt, viền mặt bị tách lớp và khẩu hình lệch nhịp với âm tiết tiếng Việt."
            }
        ],
        "scenario": {
            "title": "Diễn tập: Cuộc gọi video vay tiền lúc 22h đêm",
            "description": "Thực hành phản xạ phòng thủ khi nhận được video call từ tài khoản của con trai đang du học hỏi tiền đóng học phí gấp.",
            "content": {
                "steps": [
                    {
                        "actor": "Kẻ lừa đảo",
                        "text": "Mẹ ơi, con đang ở văn phòng trường, trường yêu cầu nộp nốt 40 triệu học phí kỳ này trước 23h đêm nếu không sẽ bị hủy visa. Mẹ chuyển gấp vào tài khoản ngân hàng của kế toán này giúp con với!",
                        "analysis": "Kẻ gian dùng video deepfake 10 giây khuôn mặt con trai, tạo bối cảnh cấp bách về thời gian (trước 23h) và viện lý do visa du học để đánh vào nỗi sợ của phụ huynh."
                    },
                    {
                        "actor": "Nạn nhân",
                        "text": "Khoan đã, sao giọng con hôm nay lại có âm vang lạ thế? Con nói cho mẹ biết tên chú cún cưng hồi nhỏ của con là gì nào?",
                        "analysis": "Áp dụng xuất sắc Quy tắc Mật khẩu an toàn gia đình (Family Safe Word). Nạn nhân không hoảng sợ mà đặt câu hỏi kiểm tra danh tính độc quyền."
                    },
                    {
                        "actor": "Kẻ lừa đảo",
                        "text": "Mẹ ơi con đang vội lắm, mạng yếu quá không nghe rõ, mẹ chuyển tiền luôn đi không muộn mất!",
                        "analysis": "Kẻ lừa đảo lúng túng vì không có thông tin cá nhân nội bộ, lập tức thoái thác bằng lý do mạng yếu và tiếp tục hối thúc chuyển tiền."
                    },
                    {
                        "actor": "Nạn nhân",
                        "text": "Tôi dập máy ngay và gọi trực tiếp vào số điện thoại viễn thông của con. Con trai tôi đang ngủ trong ký túc xá và khẳng định không có khoản học phí nào cần đóng đêm nay!",
                        "analysis": "Xử lý chuẩn xác 100%. Nạn nhân bảo vệ an toàn toàn bộ số tiền 40 triệu đồng."
                    }
                ]
            }
        }
    },
    {
        "slug": "sinh-trac-hoc",
        "title": "Quyết định 2345/QĐ-NHNN và lá chắn Sinh trắc học tài khoản ngân hàng",
        "category": ArticleCategory.ALERT,
        "summary": "Tìm hiểu chi tiết cơ chế xác thực khuôn mặt khớp với chip CCCD theo Quyết định 2345/QĐ-NHNN, tác động xóa sổ các tài khoản ngân hàng rác và các chiêu trò vượt rào mới của kẻ gian.",
        "cover_file": "media/learn/covers/sinh_trac_hoc.jpg",
        "content": """## 1. Bối cảnh lịch sử của Quyết định 2345/QĐ-NHNN

Trước ngày 01/07/2024, một trong những mắt xích yếu nhất trong hệ thống tài chính số tại Việt Nam chính là vấn nạn **tài khoản ngân hàng "rác" (Mule accounts)**. Các đường dây tội phạm xuyên biên giới chi trả từ 1 - 3 triệu đồng để mua lại số tài khoản ngân hàng từ sinh viên, người lao động tự do hoặc thuê người đứng tên mở tài khoản. 

Khi nạn nhân chuyển tiền bị lừa, dòng tiền lập tức bị phân tán qua 5 - 10 tài khoản rác chỉ trong vài phút, khiến công tác phong tỏa và thu hồi tài sản của cơ quan điều tra gặp muôn vàn khó khăn.

Quyết định 2345/QĐ-NHNN của Ngân hàng Nhà nước Việt Nam ra đời như một đòn giáng trực diện nhằm **triệt tiêu hoàn toàn đất sống của tài khoản rác**.

![Công nghệ xác thực sinh trắc học và thanh toán số bảo mật](https://images.unsplash.com/photo-1563986768609-322da13575f3?auto=format&fit=crop&w=1200&q=80)

---

## 2. Các ngưỡng bắt buộc xác thực sinh trắc học

Theo quy định bắt buộc áp dụng trên toàn bộ ứng dụng Mobile Banking của các ngân hàng thương mại tại Việt Nam:

| Mức giao dịch | Phương thức xác thực bắt buộc | Mục tiêu bảo vệ |
| :--- | :--- | :--- |
| **Giao dịch từng lần trên 10 triệu VNĐ** | Khuôn mặt thật khớp dữ liệu chip CCCD + SMS/Smart OTP | Ngăn chặn việc tẩu tán số tiền lớn chỉ bằng mật khẩu và OTP. |
| **Tổng giá trị giao dịch trong ngày vượt 20 triệu VNĐ** | Xác thực khuôn mặt sinh trắc học cho lần chuyển vượt ngưỡng | Ngăn chặn tội phạm chia nhỏ món tiền để lách luật. |
| **Giao dịch đầu tiên trên thiết bị mới cài app** | Bắt buộc quét chip NFC CCCD + Face matching chính chủ | Chặn đứng mã độc đánh cắp tài khoản rồi đăng nhập trên máy kẻ gian. |

---

## 3. Cơ chế kỹ thuật: Tại sao ảnh chụp sẵn không thể vượt qua?

Nhiều người dùng lo lắng kẻ gian có thể lấy ảnh chụp chân dung của nạn nhân để đưa trước camera vượt qua kiểm tra sinh trắc học. Tuy nhiên, hệ thống sinh trắc học ngân hàng tích hợp các tầng bảo vệ tối tân:

1. **Kiểm tra sự sống (Liveness Detection)**: Hệ thống sử dụng mạng nơ-ron nhận diện chuyển động vi mô của mắt, cơ mặt, độ sâu 3D và phản xạ quang học của da người thật. Bức ảnh in ra giấy, video quay trên màn hình điện thoại khác hay mặt nạ silicon đều bị thuật toán phát hiện và từ chối ngay.
2. **Khớp nối dữ liệu gốc từ Chip CCCD**: Khuôn mặt quét được không phải so sánh với ảnh đại diện trên app ngân hàng mà được đối chiếu với **dữ liệu đặc trưng sinh trắc học lưu bất biến trong vi mạch chip của thẻ Căn cước công dân (Bộ Công an)** thông qua cổng đọc NFC.

---

## 4. Các thủ đoạn mới của tội phạm nhằm vô hiệu hóa sinh trắc học

Tội phạm không thể bẻ khóa thuật toán sinh trắc học, vì vậy chúng chuyển hướng sang **tấn công phi kỹ thuật (Social Engineering) nhắm vào chính nạn nhân**:

> [!CAUTION]
> **Thủ đoạn 1: Mã độc Spynote đội lốt ứng dụng Dịch vụ công / Thuế**  
> Kẻ gian dụ nạn nhân tải file APK giả mạo. Mã độc chiếm quyền trợ năng (Accessibility Service), ghi lại màn hình và điều khiển điện thoại từ xa. Khi nạn nhân thực hiện quét khuôn mặt cho giao dịch của mình, kẻ gian điều hướng ngầm số tiền tới tài khoản khác.

> [!WARNING]
> **Thủ đoạn 2: Lừa nạn nhân tự quét khuôn mặt để "nhận tiền hoàn thuế"**  
> Kẻ gian gọi điện hướng dẫn: *"Bác mở app ngân hàng lên quét khuôn mặt để bên cháu chuyển tiền trợ cấp xã hội 5 triệu vào tài khoản cho bác"*. Thực chất kẻ gian đã tạo sẵn lệnh chuyển tiền ra khỏi tài khoản của nạn nhân, và bước quét khuôn mặt của nạn nhân chính là bước duyệt lệnh chuyển tiền đi!
""",
        "quizzes": [
            {
                "question": "Theo Quyết định 2345/QĐ-NHNN, khi nào người dùng bắt buộc phải xác thực khuôn mặt sinh trắc học?",
                "options": [
                    {"id": "A", "text": "Mỗi khi đăng nhập vào app ngân hàng."},
                    {"id": "B", "text": "Khi chuyển tiền trên 10 triệu đồng/lần hoặc tổng giao dịch trong ngày vượt quá 20 triệu đồng."},
                    {"id": "C", "text": "Chỉ khi thực hiện giao dịch chuyển tiền quốc tế."},
                    {"id": "D", "text": "Khi số dư tài khoản ngân hàng giảm xuống dưới 100.000 đồng."}
                ],
                "correct_answer": "B",
                "explanation": "Quyết định 2345 quy định mốc trên 10 triệu VNĐ cho một lần chuyển hoặc tổng giá trị giao dịch cộng dồn trong ngày trên 20 triệu VNĐ bắt buộc phải xác thực sinh trắc học khuôn mặt."
            }
        ],
        "scenario": {
            "title": "Diễn tập: Kẻ gian hướng dẫn quét khuôn mặt để 'nhận tiền hỗ trợ'",
            "description": "Nhận diện bẫy thao túng tâm lý giả danh cán bộ thuế yêu cầu nạn nhân quét mặt trên app ngân hàng.",
            "content": {
                "steps": [
                    {
                        "actor": "Kẻ lừa đảo",
                        "text": "Chào anh, em là cán bộ Chi cục Thuế. Hồ sơ hoàn thuế thu nhập cá nhân 8.500.000đ của anh đã được duyệt. Anh mở app ngân hàng lên quét khuôn mặt để hệ thống tự động giải ngân tiền về nhé!",
                        "analysis": "Kẻ gian đánh lừa nạn nhân rằng quét khuôn mặt là để nhận tiền vào. Về mặt kỹ thuật, NHẬN TIỀN KHÔNG BAO GIỜ CẦN XÁC THỰC SINH TRẮC HỌC!"
                    },
                    {
                        "actor": "Nạn nhân",
                        "text": "Nhận tiền vào tài khoản thì chỉ cần gửi số tài khoản là được chứ, sao lại phải quét khuôn mặt trên máy của tôi?",
                        "analysis": "Phản xạ nghi vấn rất chính xác! Bất kỳ ai yêu cầu quét mặt hay cung cấp OTP để nhận tiền đều là kẻ lừa đảo."
                    },
                    {
                        "actor": "Hệ thống ShieldCall",
                        "text": "CHÍNH XÁC! Bước quét khuôn mặt là bước PHÊ DUYỆT CHUYỂN TIỀN ĐI. Kẻ gian đã chiếm quyền tài khoản và đang chuẩn bị lấy cắp toàn bộ số dư của bạn!",
                        "analysis": "Khuyến cáo người dùng đóng ngay ứng dụng ngân hàng, đổi mật khẩu và liên hệ hotline ngân hàng để tạm khóa thẻ."
                    }
                ]
            }
        }
    },
    {
        "slug": "phishing-bank",
        "title": "Kỹ thuật phân biệt website ngân hàng thật vs website Phishing giả mạo",
        "category": ArticleCategory.GUIDE,
        "summary": "Hướng dẫn chi tiết phương pháp kiểm tra tên miền nhái thương hiệu (Lookalike domain), giải mã sai lầm về chứng chỉ SSL và nhận diện các giao diện thu thập trái phép thông tin thẻ.",
        "cover_file": "media/learn/covers/phishing_web.jpg",
        "content": """## 1. Kỹ thuật tấn công giả mạo tên miền (Phishing & Lookalike Domains)

Tấn công giả mạo website ngân hàng (Phishing) vẫn là một trong những phương thức chiếm đoạt tài khoản phổ biến nhất. Kẻ lừa đảo tạo ra các trang web có giao diện, màu sắc, logo và phông chữ **giống website ngân hàng thật tới 99%**.

Tuy nhiên, có một yếu tố duy nhất kẻ lừa đảo **KHÔNG THỂ LÀM GIẢ**: Đó chính là **Tên miền gốc (Domain Name)** đã được đăng ký và phân giải bởi tổ chức quản lý tên miền quốc tế (ICANN) và VNNIC tại Việt Nam.

![Màn hình phân tích mã nguồn và tên miền bảo mật](https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&w=1200&q=80)

---

## 2. Các thủ thuật đặt tên miền lừa đảo phổ biến

Kẻ gian sử dụng các thủ thuật sau để đánh lừa mắt thường của người dùng:

| Thủ thuật | Tên miền thật | Tên miền giả mạo thực tế đã bị chặn | Cơ chế đánh lừa |
| :--- | :--- | :--- | :--- |
| **Thêm tiền tố / hậu tố** | `vietcombank.com.vn` | `vietcombank-login.xyz`<br>`vietcombank-ebank.top` | Thêm từ khóa gợi cảm giác an ninh (login, verify, ebank). |
| **Sử dụng subdomain** | `techcombank.com.vn` | `techcombank.com.vn.online-security.cc` | Tên miền thật bị biến thành tiền tố phụ, tên miền thật là đuôi `.online-security.cc`. |
| **Thay đổi đuôi miền** | `mbbank.com.vn` | `mbbank.com.co`<br>`mbbank.net.vn` | Giữ nguyên phần đầu nhưng đổi đuôi miền quốc gia khác. |
| **Ký tự tương đồng (Typosquatting)** | `bidv.com.vn` | `bldv.com.vn` (chữ L thường thay cho chữ I hoa) | Đánh vào việc người dùng đọc lướt trên màn hình nhỏ. |

---

## 3. Sai lầm phổ biến: Tin vào biểu tượng ổ khóa bảo mật SSL

Nhiều người dùng được dạy rằng: *"Cứ thấy trang web có ổ khóa màu xanh lá là an toàn"*. **Đây là quan niệm lỗi thời và cực kỳ nguy hiểm!**

* Chứng chỉ SSL (Secure Sockets Layer) chỉ đảm bảo dữ liệu giữa máy bạn và máy chủ trang web được mã hóa đường truyền, không bị nhà mạng hay bên thứ ba đọc trộm trên đường dây cáp.
* Nó **KHÔNG HỀ** chứng minh chủ nhân của trang web đó là người lương thiện!
* Ngày nay, 100% các trang web lừa đảo đều cài đặt SSL miễn phí để hiển thị biểu tượng ổ khóa nhằm tạo lòng tin giả mạo.

---

## 4. Bảng kiểm tra 4 bước trước khi đăng nhập bất kỳ website nào

1. **Kiểm tra thanh địa chỉ (Address Bar)**: Nhìn kỹ đuôi tên miền gốc trước dấu gạch chéo `/`. Ngân hàng lớn tại Việt Nam hầu hết sử dụng đuôi chính thống `.com.vn` hoặc `.vn`.
2. **Tuyệt đối không đăng nhập từ link trong tin nhắn lạ**: Luôn tự gõ địa chỉ trang web vào trình duyệt hoặc sử dụng dấu trang (Bookmark) đã lưu sẵn từ trước.
3. **Đọc kỹ nội dung tin nhắn OTP**: Khi mã OTP gửi về máy, hãy đọc kỹ dòng chữ đính kèm:
   * Nếu bạn đang muốn *đăng nhập*, nhưng tin nhắn ghi: *"Ma OTP 123456 xac nhan CHUYEN SO TIEN 50.000.000 VND..."* &rarr; **DỪNG LẠI NGAY! Kẻ gian đang dùng thông tin của bạn để tạo lệnh chuyển tiền!**
4. **Sử dụng công cụ kiểm tra URL của ShieldCall**: Nhập link vào hệ thống [ShieldCall Domain Scanner](/scan/website/) để phân tích chứng chỉ DNS, lịch sử báo cáo cộng đồng và phát hiện tên miền nhái Lookalike trong 1 giây.
""",
        "quizzes": [
            {
                "question": "Yếu tố nào sau đây là căn cứ duy nhất và đáng tin cậy nhất để xác định website ngân hàng là an toàn?",
                "options": [
                    {"id": "A", "text": "Trang web có logo đẹp và giao diện rất giống với ngân hàng."},
                    {"id": "B", "text": "Trang web có biểu tượng ổ khóa màu xanh lá trên thanh địa chỉ."},
                    {"id": "C", "text": "Địa chỉ tên miền chính xác là tên miền chính thống được pháp luật công nhận của ngân hàng (ví dụ: vietcombank.com.vn)."},
                    {"id": "D", "text": "Trang web có mục chat trực tuyến với nhân viên hỗ trợ."}
                ],
                "correct_answer": "C",
                "explanation": "Chỉ có địa chỉ tên miền gốc (Domain Name) là định danh bất biến không thể làm giả. Ổ khóa SSL hay giao diện đều có thể sao chép dễ dàng."
            }
        ],
        "scenario": {
            "title": "Diễn tập: Truy cập link nhận quà khuyến mại từ tin nhắn lạ",
            "description": "Phát hiện trang web mạo danh Techcombank tặng quà tri ân khách hàng thân thiết.",
            "content": {
                "steps": [
                    {
                        "actor": "Kẻ lừa đảo",
                        "text": "Chúc mừng bạn nhận được phần quà tri ân 2.000.000đ từ Techcombank. Bấm vào link http://techcombank.com.vn.khuyenmai-online.top để nhập thông tin nhận thưởng.",
                        "analysis": "Tên miền lừa đảo sử dụng kỹ thuật Subdomain: cụm 'techcombank.com.vn' chỉ là tên phụ, tên miền thật là 'khuyenmai-online.top'."
                    },
                    {
                        "actor": "Nạn nhân",
                        "text": "Trang web hiện ra logo Techcombank rất đẹp, yêu cầu mình nhập Tên đăng nhập, Mật khẩu và cả Mã PIN Smart OTP để nhận quà.",
                        "analysis": "CẢNH BÁO ĐỎ: Không có ngân hàng nào tặng quà mà lại bắt khách hàng nhập Mật khẩu và Smart OTP!"
                    },
                    {
                        "actor": "Hệ thống ShieldCall",
                        "text": "NGUY HIỂM: Tên miền khuyenmai-online.top được đăng ký cách đây 2 ngày tại máy chủ nước ngoài. ĐÂY LÀ TRANG WEB PHISHING ĐÁNH CẮP TÀI KHOẢN!",
                        "analysis": "Nạn nhân lập tức tắt trang web và báo cáo link cho hệ thống phòng chống lừa đảo."
                    }
                ]
            }
        }
    },
    {
        "slug": "viec-nhe-luong-cao",
        "title": "Nhận diện bẫy tuyển dụng 'Việc nhẹ lương cao' và bẫy giật đơn Shopee/TikTok",
        "category": ArticleCategory.GUIDE,
        "summary": "Giải phẫu tâm lý bẫy lừa đảo cộng tác viên làm nhiệm vụ giật đơn thương mại điện tử, hiệu ứng chi phí chìm (Sunk Cost Fallacy) và phương pháp dứt khoát cắt lỗ.",
        "cover_file": "media/learn/covers/viec_nhe_luong_cao.jpg",
        "content": """## 1. Mô hình kinh tế của cỗ máy lừa đảo CTV trực tuyến

Lừa đảo tuyển dụng cộng tác viên (CTV) làm nhiệm vụ thanh toán đơn hàng ảo Shopee, Lazada, TikTok Shop hay xem video YouTube kiếm tiền là hình thức chiếm đoạt tài sản có số lượng nạn nhân đông nhất và số tiền thiệt hại lớn nhất tại Việt Nam trong những năm qua.

Rất nhiều người dù có học thức, nhân viên văn phòng, mẹ bỉm sữa hay sinh viên đều sập bẫy bởi kịch bản thao túng tâm lý cực kỳ bài bản của các ổ nhóm tội phạm công nghệ cao.

![Thao tác ứng dụng di động và bẫy tài chính ảo](https://images.unsplash.com/photo-1559526324-4b87b5e36e44?auto=format&fit=crop&w=1200&q=80)

---

## 2. Giải phẫu 3 giai đoạn giăng bẫy của kẻ gian

### Giai đoạn 1: Mồi câu nhử lòng tin ("Thả tép")
* Kẻ gian giao cho nạn nhân các nhiệm vụ đơn giản: Thả tim video TikTok, bấm theo dõi shop Shopee hoặc nạp số tiền nhỏ (100.000đ - 300.000đ) để "kích cầu đơn hàng".
* Ngay sau khi hoàn thành, hệ thống **hoàn trả tiền gốc kèm hoa hồng 20% - 30% cực kỳ sòng phẳng và nhanh chóng** (ví dụ: nạp 300.000đ nhận về 360.000đ chỉ sau 5 phút).
* Việc tiền thật chảy về tài khoản ngân hàng cá nhân phá vỡ hoàn toàn rào cản cảnh giác ban đầu của nạn nhân.

### Giai đoạn 2: Nâng cấp bẫy ("Bắt tôm")
* Kẻ gian đưa nạn nhân vào các nhóm chat Telegram kín với hàng chục "chim mồi" liên tục đăng ảnh chụp màn hình nhận thưởng hàng trăm triệu đồng.
* Đối tượng giao nhiệm vụ VIP với số tiền lớn hơn: 5 triệu, 20 triệu, 50 triệu đồng.

### Giai đoạn 3: Siết lưới và tống tiền liên hoàn ("Rút cạn máu")
Khi nạn nhân muốn rút số tiền lớn về, hệ thống lập tức thông báo "Lỗi hệ thống" và đưa ra hàng loạt lý do phi lý:
* *"Bạn nhập sai cú pháp nội dung chuyển khoản, lệnh rút tiền bị treo."*
* *"Cần nạp thêm 50% số tiền hiện có để mở khóa tài khoản."*
* *"Điểm tín nhiệm của bạn bị tụt, nạp thêm 100 triệu để nâng cấp tài khoản VIP."*
* *"Nộp thêm 10% tiền thuế thu nhập cá nhân thì mới được giải ngân toàn bộ."*

---

## 3. Tâm lý học tội phạm: Bẫy "Chi phí chìm" (Sunk Cost Fallacy)

Tại sao có những nạn nhân bị lừa tới hàng tỷ đồng, thậm chí vay nợ nặng lãi, thế chấp sổ đỏ để chuyển tiền cho kẻ gian?

Câu trả lời nằm ở **Hiệu ứng chi phí chìm (Sunk Cost Fallacy)**: Khi đã bỏ ra 200 triệu đồng vào hệ thống, tâm lý con người không chấp nhận sự thật là mình đã mất trắng số tiền đó. Kẻ lừa đảo liên tục hứa hẹn: *"Chỉ cần nạp thêm 50 triệu này nữa thôi là anh/chị rút về được trọn vẹn cả gốc lẫn lãi 250 triệu"*. Nạn nhân như người say bạc, tiếp tục vay mượn khắp nơi với hy vọng mong manh lấy lại tiền cũ, cho đến khi kiệt quệ hoàn toàn.

---

## 4. Nguyên tắc sinh tồn bất biến

> [!IMPORTANT]
> **Không có bất kỳ doanh nghiệp chân chính nào lại bắt người lao động phải tự bỏ tiền túi của mình ra nộp trước để làm nhiệm vụ!**  
> Việc đi làm kiếm tiền là bán sức lao động để nhận lương, chứ không phải đi làm để nộp tiền cho chủ tuyển dụng.

### Cách xử lý khi đã lỡ chuyển tiền:
1. **Dừng lại ngay lập tức**: Cắt lỗ dứt khoát! Tuyệt đối không nạp thêm dù chỉ 1 đồng với bất kỳ lời hứa hẹn nào.
2. **Lưu giữ toàn bộ bằng chứng**: Chụp ảnh màn hình tin nhắn, mã giao dịch FT, số tài khoản kẻ gian và đường link nhóm Telegram.
3. **Báo cáo khẩn cấp**: Sử dụng tính năng [Báo cáo Lừa đảo ShieldCall](/report/) và trình báo cơ quan Công an phường/xã để cung cấp thông tin phong tỏa tài khoản ngân hàng thụ hưởng.
""",
        "quizzes": [
            {
                "question": "Khi làm cộng tác viên online và hệ thống báo 'sai cú pháp, yêu cầu nạp thêm tiền để rút lại tiền cũ', hành động đúng đắn duy nhất là gì?",
                "options": [
                    {"id": "A", "text": "Lập tức nạp thêm tiền theo yêu cầu vì sợ mất số tiền đã nạp ban đầu."},
                    {"id": "B", "text": "Vay mượn người thân để nạp nốt một lần cuối rồi nghỉ việc."},
                    {"id": "C", "text": "Dừng lại ngay lập tức, không nạp thêm bất kỳ đồng nào, chụp lại toàn bộ bằng chứng và trình báo cơ quan chức năng."},
                    {"id": "D", "text": "Nhắn tin cầu xin đối tượng trả lại tiền cho mình."}
                ],
                "correct_answer": "C",
                "explanation": "Yêu cầu nạp thêm tiền để mở khóa là cái bẫy liên hoàn không bao giờ có hồi kết. Dừng lại ngay lập tức là cách duy nhất để cắt đứt thiệt hại tài chính."
            }
        ],
        "scenario": {
            "title": "Diễn tập: Thao túng tâm lý trong nhóm Telegram giật đơn ảo",
            "description": "Kịch bản đối phó với kẻ lừa đảo trong nhóm chat nhiệm vụ Shopee VIP.",
            "content": {
                "steps": [
                    {
                        "actor": "Kẻ lừa đảo",
                        "text": "Chúc mừng chị đã hoàn thành nhiệm vụ 1. Giờ chị làm tiếp nhiệm vụ 2 nạp 15 triệu để nhận về 19.500.000đ nhé!",
                        "analysis": "Kẻ gian bắt đầu nâng số tiền sau khi đã thả mồi câu nhỏ thành công."
                    },
                    {
                        "actor": "Nạn nhân",
                        "text": "Mình nạp xong 15 triệu rồi, sao hệ thống lại báo chưa rút được tiền?",
                        "analysis": "Bắt đầu bước vào giai đoạn giăng bẫy lỗi hệ thống."
                    },
                    {
                        "actor": "Kẻ lừa đảo",
                        "text": "Do chị điền thiếu dấu cách ở nội dung chuyển khoản nên kế toán treo lệnh. Chị cần nạp thêm 30 triệu tiền bảo lãnh hồ sơ thì hệ thống mới nhả toàn bộ 49.500.000đ về nhé!",
                        "analysis": "Chiêu bài kinh điển: Đổ lỗi cho nạn nhân và ép nạp thêm số tiền gấp đôi."
                    },
                    {
                        "actor": "Hệ thống ShieldCall",
                        "text": "CẢNH BÁO TỐI KHẨN: ĐÂY LÀ BẪY TỐNG TIỀN CHI PHÍ CHÌM! Tuyệt đối KHÔNG nạp thêm 30 triệu! Chị nạp thêm bao nhiêu cũng sẽ bị báo lỗi tiếp theo!",
                        "analysis": "Nạn nhân dừng chuyển tiền, bảo toàn được 30 triệu đồng còn lại và chụp ảnh tố giác kẻ gian."
                    }
                ]
            }
        }
    },
    {
        "slug": "quishing-qr",
        "title": "Quishing: Mối nguy hiểm tiềm ẩn từ mã QR dán đè ở nơi công cộng",
        "category": ArticleCategory.ALERT,
        "summary": "Hiểu rõ về hình thức tấn công Phishing qua mã QR (Quishing) tại bàn ăn, quầy thu ngân, trạm xăng và các biện pháp bảo vệ tài chính cá nhân.",
        "cover_file": "media/learn/covers/quishing_qr.jpg",
        "content": """## 1. Quishing là gì? Tại sao mã QR lại có thể trở thành vũ khí lừa đảo?

**Quishing** là thuật ngữ ghép giữa **QR Code** và **Phishing**. Đây là phương thức tấn công phi kỹ thuật trong đó kẻ gian sử dụng mã QR độc hại để dẫn dụ người dùng truy cập vào các trang web lừa đảo, đánh cắp thông tin thẻ hoặc chuyển tiền nhầm vào tài khoản kẻ gian.

Mã phản hồi nhanh (QR Code) vốn là ma trận điểm đen trắng mã hóa văn bản mà mắt thường của con người **hoàn toàn không thể đọc và phân tích nội dung bên trong nếu không dùng máy ảnh**. Điểm mù thị giác này chính là kẽ hở lớn nhất bị tội phạm khai thác triệt để.

![Quét mã QR thanh toán trên thiết bị di động](https://images.unsplash.com/photo-1607604276583-eef5d076aa5f?auto=format&fit=crop&w=1200&q=80)

---

## 2. Hai biến thể Quishing nguy hiểm nhất tại Việt Nam

### Biến thể 1: Dán đè mã VietQR tại quầy thu ngân và quán ăn
* Kẻ gian in sẵn các miếng dán decal mã QR tài khoản ngân hàng của chúng với kích thước và màu sắc trùng khớp với biển QR của cửa hàng.
* Lợi dụng lúc quán ăn đông đúc hoặc nhân viên không để ý, kẻ gian nhanh tay dán đè mã QR của mình lên bảng thanh toán đặt trên bàn ăn hoặc quầy thu ngân.
* Khách hàng quét mã chuyển tiền, tiền thay vì vào tài khoản của chủ quán thì lại chảy thẳng vào túi kẻ lừa đảo!

### Biến thể 2: Mã QR phát tán link độc hại và mã độc .APK
* Kẻ gian dán mã QR lên biển báo công cộng, cây ATM, trụ sạc điện thoại hoặc tờ rơi quảng cáo với nội dung hấp dẫn: *"Quét mã nhận voucher 500k"*, *"Quét mã cài app nộp phạt vi phạm giao thông"*.
* Khi người dùng quét mã, trình duyệt tự động mở ra đường link chứa mã độc tự động tải file `.apk` độc hại về máy để kiểm soát điện thoại.

---

## 3. Check-list 3 giây bảo vệ tiền bạc khi quét mã QR

Trước khi bấm nút **"XÁC NHẬN CHUYỂN TIỀN"** trên ứng dụng ngân hàng, hãy luôn ghi nhớ:

1. **Ngẩng mặt lên đối chiếu Tên chủ tài khoản**: Đọc to tên người thụ hưởng hiển thị trên app ngân hàng và hỏi trực tiếp nhân viên thu ngân: *"Có phải tài khoản tên NGUYEN VAN A không em?"*.
2. **Quan sát mép dán của mã QR**: Kiểm tra xem biển mã QR có dấu hiệu bị cộm, bị dán đè một lớp decal khác lên bề mặt hay không.
3. **Kiểm tra URL khi quét mã QR chuyển hướng web**: Nếu mã QR mở ra đường link trang web, hãy kiểm tra kỹ thanh địa chỉ trước khi nhập bất kỳ thông tin nào. Sử dụng [ShieldCall QR Scanner](/scan/qr/) để giải mã và kiểm tra an toàn URL trước khi truy cập.
""",
        "quizzes": [
            {
                "question": "Thao tác quan trọng nhất bắt buộc phải làm trước khi bấm xác nhận chuyển tiền qua mã QR tại quán ăn là gì?",
                "options": [
                    {"id": "A", "text": "Kiểm tra xem camera điện thoại có bị mờ không."},
                    {"id": "B", "text": "Đối soát Tên chủ tài khoản thụ hưởng hiển thị trên màn hình app ngân hàng với nhân viên hoặc bảng hiệu của quán."},
                    {"id": "C", "text": "Chụp ảnh lại mã QR để lưu vào bộ sưu tập ảnh."},
                    {"id": "D", "text": "Tắt kết nối Wifi và chuyển sang dùng 4G."}
                ],
                "correct_answer": "B",
                "explanation": "Tên chủ tài khoản thụ hưởng là thông tin chính xác nhất cho biết tiền của bạn sẽ đi về đâu, giúp lật tẩy ngay nếu mã QR bị dán đè bằng mã của kẻ gian."
            }
        ],
        "scenario": {
            "title": "Diễn tập: Thanh toán bữa ăn trưa tại quán cà phê đông khách",
            "description": "Phát hiện mã VietQR bị tráo đổi trên bàn ăn tại quán cà phê.",
            "content": {
                "steps": [
                    {
                        "actor": "Nạn nhân",
                        "text": "Mình vừa quét mã QR in trên tấm mica ở bàn số 5 quán The Coffee House, màn hình app ngân hàng hiện người nhận là 'TRINH VAN DUC - MBBank'.",
                        "analysis": "Dấu hiệu bất thường: Các chuỗi cà phê lớn thường có tên tài khoản là Tên Công ty (Pháp nhân) chứ ít khi là tài khoản cá nhân."
                    },
                    {
                        "actor": "Hệ thống ShieldCall",
                        "text": "CẢNH BÁO: Kiểm tra mép dán mica! Hãy hỏi nhân viên thu ngân tên tài khoản của quán trước khi ấn chuyển khoản!",
                        "analysis": "Kịp thời cảnh báo người dùng kiểm tra đối soát chéo."
                    },
                    {
                        "actor": "Nạn nhân",
                        "text": "Mình hỏi bạn thu ngân, bạn bảo tài khoản của quán là Công ty TNHH Cà Phê... chứ không phải Trịnh Văn Đức. Kiểm tra lại tấm mica thì thấy có miếng decal lạ dán đè lên thật. Thoát nạn!",
                        "analysis": "Bảo vệ thành công số tiền thanh toán và giúp cửa hàng phát hiện kẻ gian dán đè mã lừa đảo."
                    }
                ]
            }
        }
    }
]

# Process and update lessons
for item in LESSONS:
    lesson = LearnLesson.objects.filter(title=item["title"]).first()
    if not lesson:
        lesson = LearnLesson.objects.filter(slug=item["slug"]).first()
    if not lesson:
        lesson = LearnLesson(title=item["title"], slug=item["slug"])
    
    lesson.title = item["title"]
    lesson.category = item["category"]
    lesson.summary = item["summary"]
    lesson.content = item["content"]
    lesson.is_published = True

    # Assign cover image
    cover_path = item.get("cover_file")
    if cover_path and os.path.exists(cover_path):
        with open(cover_path, 'rb') as f:
            filename = os.path.basename(cover_path)
            lesson.cover_image.save(filename, File(f), save=False)
    lesson.save()

    # Update quizzes
    lesson.quizzes.all().delete()
    for q_data in item.get("quizzes", []):
        LearnQuiz.objects.create(
            lesson=lesson,
            question=q_data["question"],
            question_type=QuizQuestionType.SINGLE,
            options=q_data["options"],
            correct_answer=q_data["correct_answer"],
            explanation=q_data["explanation"]
        )

    # Update scenario
    lesson.scenarios.all().delete()
    sc_data = item.get("scenario")
    if sc_data:
        LearnScenario.objects.create(
            lesson=lesson,
            title=sc_data["title"],
            description=sc_data["description"],
            content=sc_data["content"]
        )

    print(f"Updated Lesson: {lesson.title} (Quizzes: {lesson.quizzes.count()}, Scenario: {lesson.scenarios.count()})")


# ══════════════════════════════════════════════════════════════════════════════
# 2. UPDATE ARTICLES WITH COVERS & DETAILED CONTENT
# ══════════════════════════════════════════════════════════════════════════════
ARTICLE_COVERS = {
    1: "media/articles/covers/art_1.jpg",
    2: "media/articles/covers/art_2.jpg",
    3: "media/articles/covers/art_3.jpg",
    4: "media/articles/covers/art_4.jpg",
    5: "media/articles/covers/art_5.jpg",
    6: "media/articles/covers/art_6.jpg",
    7: "media/articles/covers/art_7.jpg",
    8: "media/articles/covers/art_8.jpg",
    9: "media/articles/covers/art_9.jpg",
    10: "media/articles/covers/art_10.jpg",
}

for art in Article.objects.all():
    cover_path = ARTICLE_COVERS.get(art.id)
    if cover_path and os.path.exists(cover_path):
        with open(cover_path, 'rb') as f:
            art.cover_image.save(os.path.basename(cover_path), File(f), save=True)
            print(f"Updated Article Cover: {art.id} - {art.title[:35]}")

print("Successfully updated all LearnLessons and Articles!")
