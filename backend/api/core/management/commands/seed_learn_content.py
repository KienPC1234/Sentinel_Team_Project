"""
Lệnh Django: seed thêm **bài học + quiz + diễn tập** cho Cẩm nang (Learn), kèm ảnh bìa.

Idempotent theo slug (chạy lại không tạo trùng). Cấp cover bằng bộ sinh thương hiệu.

    python manage.py seed_learn_content
    python manage.py seed_learn_content --no-cover
"""

from __future__ import annotations

from django.core.files.base import ContentFile
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils.text import slugify

from api.core.models import LearnLesson, LearnQuiz, LearnScenario
from api.utils.cover_gen import generate_cover

# ── Nội dung 8 chuyên đề bổ sung ────────────────────────────────────────────
LESSONS = [
    {
        "title": "Giả mạo Bảo hiểm xã hội, Hoàn thuế & Hải quan: nhận diện và xử lý",
        "category": "alert",
        "summary": "Kẻ gian giả danh BHXH/thuế/hải quan để dụ cài app, đọc OTP và chiếm đoạt tiền.",
        "content": """## Vì sao hiệu quả?
Cơ quan BHXH, Thuế, Hải quan là những cái tên quen thuộc với người dân và doanh nghiệp. Kẻ gian lợi dụng điều đó để tạo cảm giác "việc nhà nước, phải làm ngay".

## Dấu hiệu nhận diện
- Yêu cầu **cài ứng dụng lạ** (APK ngoài Google Play/App Store) hoặc "app BHXH/thuế" không có trong chợ ứng dụng chính thức.
- Dụ **cập nhật sổ BHXH/VNeID**, **hoàn thuế**, **thông quan hàng** rồi hỏi **OTP**, mã xác thực, mật khẩu internet banking.
- Tạo áp lực: "hết hạn hôm nay", "phạt nguội", "kê khai gấp".
- Số điện thoại/gọi đến không phải tổng đài chính thức; yêu cầu chuyển khoản **phí/hồ sơ**.

## Nguyên tắc an toàn
1. **Không cài app ngoài chợ ứng dụng chính thức.** Không bấm link trong tin nhắn/gọi từ số lạ.
2. **Không bao giờ cung cấp OTP**, mật khẩu, mã PIN, ảnh CCCD/hộ chiếu cho người gọi đến.
3. Tự tra cứu qua kênh chính thức: **VssID**, Cổng Dịch vụ công Quốc gia, website của cơ quan thuế/HQ.
4. Khi nghi ngờ, **gọi lại tổng đài chính thức** tra trên trang chính thức — không gọi số do người lạ cung cấp.
5. Nếu đã lỡ cung cấp OTP: gọi **ngân hàng khoá tài khoản ngay**, đổi mật khẩu, và trình báo.

## Trình báo
Phản ánh tin nhắn/cuộc gọi rác: đầu số **156**. Tố giác lừa đảo: cơ quan công an nơi cư trú.""",
        "quizzes": [
            {"q": "Người tự xưng 'cán bộ BHXH' yêu cầu bạn cài app qua link và đọc mã OTP để 'cập nhật sổ BHXH'. Bạn nên làm gì?",
             "opts": [("A", "Cài app và đọc OTP vì sợ chậm hồ sơ."),
                      ("B", "Không cài, không cung cấp OTP; tự tra cứu qua VssID/Dịch vụ công và gọi tổng đài chính thức."),
                      ("C", "Chuyển phí hồ sơ trước cho nhanh."),
                      ("D", "Gửi ảnh CCCD qua Zalo cho cán bộ.")],
             "correct": "B", "exp": "Cơ quan nhà nước không bao giờ yêu cầu OTP hay cài app ngoài chợ ứng dụng qua điện thoại."},
            {"q": "Tổng đài tiếp nhận phản ánh tin nhắn/cuộc gọi rác, có dấu hiệu lừa đảo của Việt Nam là?",
             "opts": [("A", "113"), ("B", "156"), ("C", "1900"), ("D", "115")],
             "correct": "B", "exp": "Đầu số 156 do Bộ TT&TT vận hành để tiếp nhận phản ánh tin nhắn/cuộc gọi rác, lừa đảo."},
        ],
        "scenario": {
            "title": "Diễn tập: Cuộc gọi tự xưng 'cán bộ Thuế' yêu cầu cài app hoàn thuế",
            "description": "Mô phỏng cuộc gọi tự xưng cán bộ thuế, hướng dẫn cài 'ứng dụng hoàn thuế' để chiếm OTP.",
            "steps": [
                {"actor": "Kẻ lừa đảo", "text": "Chào anh/chị, em bên Chi cục Thuế. Hồ sơ của anh/chị được hoàn thuế 12 triệu, nhưng hôm nay hết hạn. Anh tải app 'HoanThue2026' theo link này rồi đọc mã OTP em xác nhận nhé.", "analysis": "Dùng thẩm quyền + thời hạn giả để gây áp lực; đòi cài app ngoài chợ và đòi OTP — hai dấu hiệu điển hình."},
                {"actor": "Nạn nhân", "text": "Dạ 12 triệu cũng nhiều, mà hết hạn hôm nay thì tiếc. Để tôi cài nhanh...", "analysis": "Bị cuốn theo cảm giác tiếc tiền và gấp gáp — đúng điểm kẻ gian nhắm vào."},
                {"actor": "Hệ thống ShieldCall", "text": "DỪNG LẠI! Cơ quan thuế KHÔNG bao giờ gọi đòi OTP hay bắt cài app qua link. Hãy tự tra Cổng Dịch vụ công/website thuế chính thức.", "analysis": "Cắt cơn gấp gáp, đưa nguyên tắc vàng: không OTP, không app ngoài chợ, tự tra kênh chính thức."},
            ],
        },
    },
    {
        "title": "Bẫy vay tiền qua App, tín dụng đen & đòi nợ khủng bố",
        "category": "alert",
        "summary": "App vay 'giải ngân nhanh' thu thập dữ liệu, lãi cắt cổ và khủng bố tinh thần người vay.",
        "content": """## Cơ chế
App vay "không cần chứng minh thu nhập" thường chỉ giải ngân khoản nhỏ nhưng ép người vay **cấp quyền danh bạ, ảnh, vị trí**. Khi đến hạn (vài ngày), lãi và phí cộng dồn khiến số nợ tăng vọt. Sau đó chúng **khủng bố**: gọi/nhắn cho người thân, đồng nghiệp, chỉnh ảnh bôi nhọ.

## Dấu hiệu
- Hứa hẹn "không thẩm định", "giải ngân 5 phút", lãi "chỉ vài nghìn/ngày".
- Đòi **toàn quyền danh bạ/ảnh** — điều kiện để đe doạ sau này.
- Phí "mở hồ sơ", "phí bảo hiểm khoản vay" **đóng trước**.
- Link tải apk ngoài chợ ứng dụng.

## Nguyên tắc an toàn
1. Chỉ vay tại **tổ chức tín dụng được NHNN cấp phép**; kiểm tra trên website NHNN.
2. **Không cấp quyền danh bạ/ảnh** cho app vay; không cài APK ngoài chợ.
3. Không đóng phí trước để "được giải ngân".
4. Nếu bị khủng bố: lưu bằng chứng (ghi âm, tin nhắn), **báo công an**, chặn số. Tống tiền/đe doạ là hành vi vi phạm pháp luật.

## Nếu đã vướng
- Ngừng trả các khoản phí vô lý; liên hệ tổ chức tín dụng hợp pháp để cơ cấu.
- Không nhượng bộ yêu cầu gửi ảnh nhạy cảm. Trình báo để được hỗ trợ.""",
        "quizzes": [
            {"q": "Ứng dụng vay yêu cầu bạn cấp quyền truy cập toàn bộ danh bạ và thư viện ảnh. Điều này nguy hiểm vì?",
             "opts": [("A", "Chỉ để tính điểm tín dụng."),
                      ("B", "Là điều kiện để sau này đe doạ, gọi cho người thân/đồng nghiệp gây áp lực đòi nợ."),
                      ("C", "Giúp bảo mật tài khoản tốt hơn."),
                      ("D", "Không có rủi ro gì.")],
             "correct": "B", "exp": "Dữ liệu danh bạ/ảnh bị dùng để khủng bố tinh thần khi người vay không kịp trả."},
            {"q": "Khi bị đòi nợ kiểu khủng bố (gọi cho người thân, bôi nhọ), bạn nên?",
             "opts": [("A", "Im lặng chịu đựng và trả bằng mọi giá."),
                      ("B", "Lưu bằng chứng và trình báo công an; chỉ làm việc với tổ chức tín dụng hợp pháp."),
                      ("C", "Vay app khác để trả."),
                      ("D", "Gửi ảnh nhạy cảm theo yêu cầu để 'xin tha'.")],
             "correct": "B", "exp": "Đe doạ/tống tiền là vi phạm pháp luật; cần lưu bằng chứng và trình báo."},
        ],
        "scenario": {
            "title": "Diễn tập: App vay 'giải ngân 3 phút' đòi quyền danh bạ",
            "description": "Mô phỏng tải app vay nhanh và bị ép cấp quyền danh bạ, sau đó bị khủng bố đòi nợ.",
            "steps": [
                {"actor": "Kẻ lừa đảo", "text": "Để giải ngân 3 phút, bạn cho app quyền truy cập danh bạ và ảnh nhé. Không thẩm định gì đâu, lãi chỉ 5.000đ/ngày.", "analysis": "Đòi quyền nhạy cảm + lãi 'rẻ' là mồi nhử điển hình của tín dụng đen."},
                {"actor": "Nạn nhân", "text": "Nghe nhanh gọn thật, mà app xin danh bạ hơi lạ. Nhưng đang cần tiền gấp...", "analysis": "Mâu thuẫn giữa nhu cầu tiền gấp và dấu hiệu bất thường."},
                {"actor": "Hệ thống ShieldCall", "text": "CẢNH BÁO: Vay hợp pháp không cần quyền danh bạ/ảnh và không thu phí trước. Hãy dừng lại và kiểm tra tổ chức tín dụng được NHNN cấp phép.", "analysis": "Đưa tiêu chí phân biệt vay hợp pháp và tín dụng đen."},
            ],
        },
    },
    {
        "title": "Chiếm quyền tài khoản mạng xã hội (hack nick) rồi nhắn tin vay tiền",
        "category": "alert",
        "summary": "Kẻ gian chiếm Facebook/Zalo của bạn rồi mạo danh nhắn người thân mượn tiền.",
        "content": """## Cơ chế
Kẻ gian chiếm tài khoản bằng **link phishing đăng nhập**, **mã độc/extension đọc cookie**, hoặc **chiêu 'xác minh tài khoản'**. Sau đó chúng dùng chính tài khoản của bạn nhắn cho bạn bè/người thân **mượn tiền**, gửi **link lừa đảo** hoặc **mã QR**.

## Dấu hiệu tin nhắn mạo danh
- Người thân đột nhiên nhắn **mượn tiền gấp**, đổi giọng văn, không gọi được.
- Xin **OTP**, "gửi giúp mã xác minh", chuyển tiền vào STK lạ, hoặc thanh toán qua QR.
- Gửi link lạ "nhận quà / hoàn tiền".

## Phòng tránh
1. Bật **xác thực 2 lớp (2FA)** và cảnh báo đăng nhập lạ cho Facebook/Zalo/Google.
2. **Không bấm link đăng nhập** từ tin nhắn; kiểm tra tên miền kỹ (lookalike).
3. **Xác minh bằng kênh khác**: gọi trực tiếp người thân qua số đã biết trước khi chuyển tiền.
4. Không cài extension/tệp lạ "tăng tương tác".

## Nếu bị chiếm tài khoản
- Báo ngay cho bạn bè/người thân **đừng chuyển tiền**.
- Báo cáo tài khoản bị hack tới nền tảng, đổi mật khẩu, đăng xuất thiết bị lạ, bật lại 2FA.
- Khoá/đổi mật khẩu email, ngân hàng nếu dùng chung mật khẩu.""",
        "quizzes": [
            {"q": "Bạn thân nhắn qua Facebook mượn gấp 20 triệu, kèm STK lạ và giục chuyển ngay. Việc đúng nên làm?",
             "opts": [("A", "Chuyển ngay vì là bạn thân."),
                      ("B", "Gọi trực tiếp qua số đã biết để xác minh trước khi chuyển."),
                      ("C", "Nhờ người khác chuyển hộ."),
                      ("D", "Đợi bạn nhắn lại.")],
             "correct": "B", "exp": "Xác minh qua kênh khác (gọi trực tiếp) là cách chắc chắn nhất, vì nick có thể đã bị hack."},
            {"q": "Cách tốt nhất để hạn chế bị chiếm tài khoản mạng xã hội?",
             "opts": [("A", "Dùng cùng một mật khẩu cho mọi nơi cho dễ nhớ."),
                      ("B", "Bật xác thực 2 lớp (2FA) và không bấm link đăng nhập từ tin nhắn."),
                      ("C", "Cài extension lạ để tăng tương tác."),
                      ("D", "Chia sẻ OTP cho bạn bè tin cậy.")],
             "correct": "B", "exp": "2FA + cảnh giác link phishing là lá chắn quan trọng nhất."},
        ],
        "scenario": {
            "title": "Diễn tập: Nick Facebook bị hack nhắn mượn tiền người thân",
            "description": "Mô phỏng kẻ gian chiếm nick và mạo danh chủ tài khoản để vay tiền, kèm QR thanh toán.",
            "steps": [
                {"actor": "Kẻ lừa đảo", "text": "Em đây, đang gấp quá. Anh chuyển giúp em 20 triệu vào STK này nhé, tối em trả. Quét QR cho nhanh!", "analysis": "Tận dụng quan hệ thân thiết + áp lực thời gian + QR để né xác minh."},
                {"actor": "Người thân", "text": "Ừ để anh chuyển luôn... mà sao số tài khoản lạ vậy?", "analysis": "Dấu hiệu nghi ngờ đúng lúc — cần xác minh thay vì chuyển ngay."},
                {"actor": "Hệ thống ShieldCall", "text": "Hãy GỌI TRỰC TIẾP cho người thân qua số đã biết để xác minh. Nick có thể đã bị chiếm đoạt.", "analysis": "Xác minh chéo là biện pháp quyết định trước mọi giao dịch nhạy cảm."},
            ],
        },
    },
    {
        "title": "Giả mạo giao hàng/bưu phẩm & chiêu 'hoàn tiền' sàn thương mại điện tử",
        "category": "alert",
        "summary": "Tin nhắn 'đơn hàng thất lạc, bồi thường' hoặc 'giao không thành công' dụ đóng phí, đọc OTP.",
        "content": """## Hai chiêu phổ biến
1. **Shipper giả**: "Đơn của bạn giao không thành công, phí phát lại 20-30k, bấm link thanh toán." Link thực chất là trang thu thập thẻ/OTP.
2. **Hoàn tiền sàn TMĐT**: "Đơn bị lỗi, hệ thống hoàn tiền, cần bạn đọc OTP/xác nhận giao dịch" — thực ra là **lệnh chuyển tiền** từ tài khoản bạn.

## Dấu hiệu
- Link rút gọn/tên miền lạ (không phải app/website chính thức).
- Yêu cầu **số thẻ, CVV, OTP**, "xác nhận" để nhận tiền.
- Đòi phí nhỏ để nhận "bồi thường/quà" lớn.
- Đội ngũ chăm sóc khách hàng chỉ liên hệ qua số cá nhân/Zalo, không qua kênh chính thức.

## Nguyên tắc an toàn
1. **Tra đơn hàng trong app/website chính thức** của đơn vị vận chuyển/sàn, không bấm link lạ.
2. Không đọc OTP/số thẻ/CVV cho bất kỳ ai.
3. Nhớ: **để nhận tiền hoàn, bạn không cần đọc OTP**; OTP chỉ để xác nhận chi tiền.
4. Cảnh giác đuôi miền lạ và các tên gần giống (lookalike).""",
        "quizzes": [
            {"q": "Tin nhắn nói 'đơn hàng lỗi, hệ thống hoàn tiền, vui lòng đọc mã OTP để nhận'. Đúng hay Sai: cần đọc OTP để nhận tiền hoàn?",
             "opts": [("A", "Đúng, cần OTP để hoàn tiền."),
                      ("B", "Sai, OTP chỉ dùng để xác nhận giao dịch chi tiền; đọc OTP là mất tiền.")],
             "correct": "B", "exp": "Nguyên tắc vàng: OTP = xác nhận CHI tiền. Nhận tiền không cần OTP."},
            {"q": "Cách kiểm tra tình trạng đơn hàng an toàn nhất?",
             "opts": [("A", "Bấm link trong tin nhắn shipper."),
                      ("B", "Mở app/website chính thức của hãng vận chuyển hoặc sàn để tra mã vận đơn."),
                      ("C", "Nhờ người lạ kiểm tra hộ."),
                      ("D", "Chuyển phí phát lại trước.")],
             "correct": "B", "exp": "Luôn tra qua kênh chính thức, không dùng link trong tin nhắn."},
        ],
        "scenario": {
            "title": "Diễn tập: Shipper giả đòi phí phát lại kèm link lạ",
            "description": "Mô phỏng tin nhắn giả shipper đòi phí phát lại và dẫn tới trang thu thập thẻ.",
            "steps": [
                {"actor": "Kẻ lừa đảo", "text": "Đơn 150k của bạn giao không thành công do sai địa chỉ. Vui lòng thanh toán phí phát lại 25k tại link: ghtk-fee.xyz/thanhtoan", "analysis": "Tên miền lookalike + số tiền nhỏ để dễ dàng bấm."},
                {"actor": "Nạn nhân", "text": "25k thôi, bấm cho nhanh...", "analysis": "Số tiền nhỏ khiến nạn nhân chủ quan; trang sau link thực chất đòi thẻ/OTP."},
                {"actor": "Hệ thống ShieldCall", "text": "DỪNG LẠI! Đơn vị vận chuyển không thu phí qua link lạ. Hãy mở app/website chính thức tra mã vận đơn.", "analysis": "Chặn thao tác và hướng về kênh chính thức."},
            ],
        },
    },
    {
        "title": "Đặt cọc mua bán, thuê nhà: nhận diện bẫy giữ chỗ",
        "category": "guide",
        "summary": "Bẫy ép đặt cọc gấp cho nhà/xe/đất không tồn tại hoặc không phải của người bán.",
        "content": """## Cơ chế
Kẻ gian đăng tin **nhà/xe/đất giá rẻ**, hối thúc "nhiều người hỏi, cọc trước mới giữ được". Sau khi nhận cọc, chúng **chặn liên lạc** hoặc dùng **giấy tờ giả**.

## Dấu hiệu
- Ảnh/giá quá tốt so với thị trường; thúc cọc gấp trong ngày.
- Chủ nhà "ở nước ngoài", chỉ liên hệ qua Zalo; **không cho xem nhà trực tiếp**/xem qua video dàn dựng.
- Yêu cầu cọc vào **STK cá nhân** không trùng tên chủ sở hữu.
- Giấy tờ nhà đất/hợp đồng mơ hồ, không cho kiểm tra.

## Nguyên tắc an toàn
1. **Xem trực tiếp** nhà/xe/đất; gặp đúng chủ sở hữu.
2. **Kiểm tra pháp lý**: sổ đỏ/sổ hồng, CMND/CCCD chủ sở hữu, tình trạng tranh chấp.
3. Chuyển cọc vào **STK trùng tên chủ sở hữu**, có biên nhận/đặt cọc ghi rõ điều kiện hoàn cọc.
4. Ưu tiên giao dịch qua **sàn/môi giới có pháp nhân**, qua công chứng.
5. Không cọc khi chưa xem và chưa xác thực danh tính người bán.""",
        "quizzes": [
            {"q": "Người bán đất 'đang ở nước ngoài', không cho xem trực tiếp nhưng giục cọc gấp. Bạn nên?",
             "opts": [("A", "Cọc ngay kẻo mất."),
                      ("B", "Không cọc; yêu cầu xem trực tiếp và kiểm tra giấy tờ, danh tính chủ sở hữu."),
                      ("C", "Cọc một nửa."),
                      ("D", "Nhờ người lạ xem hộ rồi cọc.")],
             "correct": "B", "exp": "Không xem trực tiếp + giục cọc gấp là dấu hiệu điển hình của bẫy đặt cọc."},
            {"q": "Khi chuyển tiền đặt cọc, an toàn nhất là?",
             "opts": [("A", "Chuyển vào bất kỳ STK nào người bán đưa."),
                      ("B", "Chuyển vào STK trùng tên chủ sở hữu, có biên nhận/hợp đồng đặt cọc rõ điều kiện."),
                      ("C", "Đưa tiền mặt không giấy tờ."),
                      ("D", "Chuyển qua ví của người môi giới.")],
             "correct": "B", "exp": "Tên chủ tài khoản phải khớp chủ sở hữu; giấy tờ đặt cọc bảo vệ quyền hoàn cọc."},
        ],
        "scenario": {
            "title": "Diễn tập: Tin thuê nhà giá rẻ giục cọc giữ chỗ",
            "description": "Mô phỏng chủ nhà 'ở nước ngoài' hối thúc đặt cọc trước khi xem nhà.",
            "steps": [
                {"actor": "Kẻ lừa đảo", "text": "Nhà trung tâm chỉ 5 triệu/tháng, có 3 người đang hỏi. Em cọc trước 10 triệu giữ chỗ nhé, anh đang ở nước ngoài không xem trực tiếp được.", "analysis": "Giá rẻ + khan hiếm giả + không cho xem là bộ ba dấu hiệu."},
                {"actor": "Nạn nhân", "text": "Rẻ thật, mà không được xem nhà thì hơi lo...", "analysis": "Trực giác đúng — cần xác minh trước."},
                {"actor": "Hệ thống ShieldCall", "text": "KHÔNG cọc khi chưa xem và chưa xác minh chủ sở hữu. Yêu cầu xem trực tiếp và kiểm tra giấy tờ.", "analysis": "Nguyên tắc: xem trực tiếp + xác thực danh tính/pháp lý trước khi đặt cọc."},
            ],
        },
    },
    {
        "title": "Pig Butchering: bẫy đầu tư tiền mã hóa 'nuôi lợn rồi mổ'",
        "category": "alert",
        "summary": "Kẻ gian xây dựng niềm tin dài hạn rồi dẫn dụ nạn nhân nạp tiền vào 'sàn ảo' không thể rút.",
        "content": """## Cơ chế 'nuôi rồi mổ'
Khác với đầu tư ảo thông thường, **Pig Butchering** kéo dài **tuần tới tháng**: kẻ gian kết bạn (đôi khi qua tình cảm), chia sẻ 'cơ hội đầu tư', cho nạn nhân **rút thử vài lần thành công** để tạo tin tưởng, rồi thúc nạp số lớn. Khi muốn rút, sàn báo **'cần đóng thuế/phí'** và tiếp tục moi tiền cho tới khi nạn nhân kiệt quệ.

## Dấu hiệu
- Được 'người quen qua mạng' giới thiệu sàn/nền tảng **không có pháp nhân rõ ràng**.
- **Lợi nhuận cao ổn định bất thường**; app/sàn riêng, không minh bạch.
- Rút nhỏ được nhưng **rút lớn bị chặn**, đòi thêm "phí thuế", "phí xác minh".
- Bị thúc nạp thêm, vay mượn khắp nơi để "gỡ".

## Nguyên tắc an toàn
1. Chỉ đầu tư qua **công ty chứng khoán/tổ chức được cấp phép**; kiểm tra trên Ủy ban Chứng khoán Nhà nước.
2. **Không có khoản đầu tư nào đảm bảo lợi nhuận cao, chắc thắng.**
3. Không nạp tiền vào sàn/app do người quen qua mạng giới thiệu.
4. Dừng ngay khi bị đòi phí để rút tiền; lưu bằng chứng và **trình báo công an**.

## Nếu đã bị cuốn
Ngừng nạp thêm; lưu toàn bộ tin nhắn/giao dịch; trình báo. Đừng vay thêm để "gỡ" — đó là bẫy tăng dần.""",
        "quizzes": [
            {"q": "Bạn đầu tư qua 'sàn' do người quen qua mạng giới thiệu, lãi rất cao và rút nhỏ được. Dấu hiệu nào cho thấy đây có thể là bẫy?",
             "opts": [("A", "Rút nhỏ được chứng tỏ sàn uy tín."),
                      ("B", "Lợi nhuận cao bất thường + không có pháp nhân rõ ràng + rút lớn bị đòi thêm phí."),
                      ("C", "Có app riêng là chắc chắn tốt."),
                      ("D", "Người giới thiệu nói thân thiết.")],
             "correct": "B", "exp": "Cho rút nhỏ để tạo tin tưởng rồi chặn rút lớn và đòi phí — đúng kịch bản 'nuôi rồi mổ'."},
            {"q": "Khi sàn yêu cầu đóng thêm 'thuế/phí' để rút tiền, bạn nên?",
             "opts": [("A", "Đóng thêm để rút được số đã nạp."),
                      ("B", "Dừng lại, lưu bằng chứng và trình báo; không nạp thêm."),
                      ("C", "Vay thêm để đóng phí."),
                      ("D", "Nhờ người quen giới thiệu can thiệp.")],
             "correct": "B", "exp": "Đây là dấu hiệu điển hình của lừa đảo; càng đóng càng mất."},
        ],
        "scenario": {
            "title": "Diễn tập: 'Người quen qua mạng' rủ đầu tư sàn crypto lãi 20%/tuần",
            "description": "Mô phỏng chuỗi tin nhắn xây dựng niềm tin rồi dẫn dụ nạp số lớn vào sàn ảo.",
            "steps": [
                {"actor": "Kẻ lừa đảo", "text": "Em vừa rút 50 triệu lãi từ sàn X, chỉ cần nạp vốn là auto sinh lời 20%/tuần. Chị nạp 100 triệu đi, em hướng dẫn.", "analysis": "Cam kết lợi nhuận cao bất thường + bằng chứng rút tiền dàn dựng."},
                {"actor": "Nạn nhân", "text": "20%/tuần thì quá tốt, mà sàn này nghe lạ quá...", "analysis": "Nhận ra bất thường — cần kiểm tra pháp nhân."},
                {"actor": "Hệ thống ShieldCall", "text": "CẢNH BÁO: Không có đầu tư nào lãi cao chắc thắng. Chỉ đầu tư qua tổ chức được cấp phép; kiểm tra UBCKNN.", "analysis": "Đưa nguyên tắc phòng ngừa và kênh tra cứu chính thức."},
            ],
        },
    },
    {
        "title": "Bảo vệ trẻ em trên không gian mạng: game, quà tặng và chat lạ",
        "category": "guide",
        "summary": "Bảo vệ trẻ khỏi lừa nạp thẻ game, mua bán tài khoản, làm quen qua mạng và nội dung xấu.",
        "content": """## Rủi ro với trẻ
- **Nạp thẻ/skin game** giá trị lớn, bị dụ "nhân đôi kim cương", "nhận skin free".
- **Làm quen qua mạng** rồi dụ gửi ảnh, gặp mặt, hoặc **tống tình dục** (sextortion).
- **Mua bán tài khoản game** rồi bị chiếm đoạt, lộ thông tin.
- Bị rủ tham gia **"kiếm tiền online"**, nhận quà rồi chuyển khoản hộ.

## Nguyên tắc cho phụ huynh
1. **Bật chế độ gia đình / giới hạn thanh toán**, không lưu thẻ trong thiết bị dùng chung.
2. Trò chuyện cởi mở: con **không có lỗi** nếu bị dụ; hãy nói với người lớn ngay.
3. Dạy trẻ: **không gửi ảnh nhạy cảm**, không gặp người lạ, không đọc OTP, không nhận quà-nạp thẻ từ người lạ.
4. Kiểm tra app/thiết bị định kỳ; cảnh giác app ngoài chợ ứng dụng.

## Khi có sự cố
- Lưu bằng chứng (ảnh chụp, tin nhắn), **không xoá**.
- Báo cho nhà trường và **tổng đài 111 — Bảo vệ Trẻ em**; trình báo công an khi cần.
- Nếu bị tống tình: không trả tiền, **dừng liên lạc**, trình báo.""",
        "quizzes": [
            {"q": "Trẻ nhận tin 'nhân đôi kim cương' trong game và được yêu cầu cung cấp tài khoản/OTP. Đúng hay Sai: nên cung cấp để nhận thưởng?",
             "opts": [("A", "Đúng."), ("B", "Sai — có thể mất tài khoản/tiền và lộ thông tin.")],
             "correct": "B", "exp": "Không trò chơi chính thức nào yêu cầu OTP hay đăng nhập để 'nhân đôi' phần thưởng."},
            {"q": "Tổng đài quốc gia bảo vệ trẻ em ở Việt Nam là?",
             "opts": [("A", "113"), ("B", "115"), ("C", "111"), ("D", "156")],
             "correct": "C", "exp": "111 là Tổng đài Quốc gia Bảo vệ Trẻ em."},
        ],
        "scenario": {
            "title": "Diễn tập: Trẻ bị dụ nạp thẻ game 'nhân đôi kim cương'",
            "description": "Mô phỏng người lạ nhắn cho trẻ trong game, dụ nạp thẻ và xin OTP.",
            "steps": [
                {"actor": "Kẻ lừa đảo", "text": "Anh tặng em 10.000 kim cương, chỉ cần em nạp thẻ 200k theo mã này rồi gửi anh mã xác minh nhé.", "analysis": "Mồi 'phần thưởng' + đòi nạp trước + mã xác minh — dấu hiệu lừa đảo."},
                {"actor": "Trẻ", "text": "Được tặng nhiều quá, mà sao phải nạp trước nhỉ?", "analysis": "Thắc mắc đúng lúc; người lớn cần được thông báo."},
                {"actor": "Hệ thống ShieldCall", "text": "Hãy nói với bố mẹ/cô giáo NGAY. Không nạp thẻ, không gửi mã xác minh cho người lạ. Gọi 111 nếu cần hỗ trợ.", "analysis": "Khuyến khích trẻ lên tiếng, không tự xử lý."},
            ],
        },
    },
    {
        "title": "Lừa đảo xuất khẩu lao động, visa & du học",
        "category": "alert",
        "summary": "Dịch vụ 'bao đậu' visa/đi làm nước ngoài thu phí cao rồi bặt vô âm tín.",
        "content": """## Cơ chế
Kẻ gian mạo danh công ty xuất khẩu lao động/tư vấn du học, hứa **'bao visa', 'việc nhẹ lương cao ở nước ngoài'**, thu **phí trước** nhiều đợt rồi biến mất hoặc đưa sang làm việc bất hợp pháp.

## Dấu hiệu
- Cam kết **'bao đậu' visa**, thu nhập cao bất thường, không cần bằng cấp/chứng chỉ.
- Thu **phí đặt cọc/đặt chỗ** lớn, không hợp đồng rõ ràng, không có pháp nhân.
- Không xuất trình **giấy phép hoạt động** đưa người lao động đi làm việc ở nước ngoài.
- Văn phòng mờ nhạt, chỉ liên hệ Zalo, hợp đồng sơ sài.

## Nguyên tắc an toàn
1. Kiểm tra công ty có **giấy phép** của Bộ LĐ-TB&XH (danh sách công ty được phép).
2. Yêu cầu **hợp đồng rõ ràng**, biên nhận, điều khoản hoàn phí.
3. Không nộp phí lớn cho cá nhân; đối chiếu với mức phí hợp lý và quy định.
4. Cảnh giác lời hứa 'bao đậu' — không ai đảm bảo visa 100%.
5. Tra cứu thông tin tại nguồn chính thức, tham khảo cơ quan quản lý.""",
        "quizzes": [
            {"q": "Công ty hứa 'bao đậu visa', thu nhập cao, chỉ cần đóng phí đặt chỗ lớn, không cần bằng cấp. Bạn nên?",
             "opts": [("A", "Nộp phí ngay để giữ suất."),
                      ("B", "Kiểm tra giấy phép công ty và danh sách hợp pháp; yêu cầu hợp đồng rõ ràng trước khi nộp phí."),
                      ("C", "Nộp qua Zalo cho nhân viên."),
                      ("D", "Bỏ qua giấy tờ cho nhanh.")],
             "correct": "B", "exp": "Không ai 'bao đậu' visa; công ty hợp pháp phải có giấy phép và hợp đồng minh bạch."},
            {"q": "Đâu là cách xác minh công ty xuất khẩu lao động đáng tin?",
             "opts": [("A", "Nghe lời giới thiệu của người quen."),
                      ("B", "Đối chiếu danh sách công ty được Bộ LĐ-TB&XH cấp phép."),
                      ("C", "Xem quảng cáo Facebook."),
                      ("D", "Cứ nộp tiền rồi biết.")],
             "correct": "B", "exp": "Danh sách công ty được cấp phép là nguồn xác minh chính thức."},
        ],
        "scenario": {
            "title": "Diễn tập: Môi giới 'bao đậu' visa Nhật, đòi đặt cọc 80 triệu",
            "description": "Mô phỏng công ty môi giới hứa việc lương cao và ép đóng cọc trước.",
            "steps": [
                {"actor": "Kẻ lừa đảo", "text": "Chỉ còn 2 suất đi Nhật lương 40 triệu/tháng, bao đậu visa. Đóng cọc 80 triệu trong hôm nay nhé, tên em nhận.", "analysis": "Lương cao bất thường + bao đậu + đóng cọc cho cá nhân + thời hạn giả."},
                {"actor": "Nạn nhân", "text": "Lương vậy tốt thật, mà sao phải chuyển cho cá nhân?", "analysis": "Nhận ra điều bất thường — cần xác minh pháp nhân."},
                {"actor": "Hệ thống ShieldCall", "text": "DỪNG LẠI! Không nộp tiền cho cá nhân. Kiểm tra giấy phép công ty trong danh sách Bộ LĐ-TB&XH và yêu cầu hợp đồng rõ ràng.", "analysis": "Hướng dẫn xác minh đúng kênh và yêu cầu giấy tờ."},
            ],
        },
    },
]


class Command(BaseCommand):
    help = "Seed thêm bài học + quiz + diễn tập cho Cẩm nang (Learn)."

    def add_arguments(self, parser):
        parser.add_argument("--no-cover", action="store_true", help="Không sinh ảnh bìa.")

    def handle(self, *args, **options):
        no_cover = options.get("no_cover", False)
        created = skipped = 0
        for item in LESSONS:
            slug = slugify(item["title"], allow_unicode=False)[:340]
            if LearnLesson.objects.filter(slug=slug).exists():
                skipped += 1
                continue
            with transaction.atomic():
                lesson = LearnLesson.objects.create(
                    title=item["title"], slug=slug, summary=item["summary"],
                    content=item["content"], category=item["category"], is_published=True,
                )
                if not no_cover:
                    try:
                        data = generate_cover(item["title"], item["category"], subtitle=item["summary"][:120])
                        lesson.cover_image.save(f"gen_{slug[:60]}.jpg", ContentFile(data), save=True)
                    except Exception as exc:  # noqa: BLE001
                        self.stderr.write(self.style.WARNING(f"cover lỗi ({item['title'][:40]}): {exc}"))
                for q in item.get("quizzes", []):
                    options_list = [{"id": oid, "text": text} for oid, text in q["opts"]]
                    LearnQuiz.objects.create(
                        lesson=lesson, question=q["q"], question_type="single_choice",
                        options=options_list, correct_answer=q["correct"], explanation=q.get("exp", ""),
                    )
                sc = item.get("scenario")
                if sc:
                    LearnScenario.objects.create(
                        title=sc["title"], lesson=lesson, description=sc["description"],
                        content={"steps": sc["steps"]},
                    )
            created += 1
        self.stdout.write(self.style.SUCCESS(
            f"Seed Cẩm nang: tạo {created} bài học (kèm quiz + diễn tập), bỏ qua {skipped} (đã có)."))
