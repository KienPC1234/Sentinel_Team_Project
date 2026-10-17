'use client';
import { useEffect, useRef, useState } from 'react';
import { asList, learnApi } from '../../lib/api';
import { warmTts } from '../../lib/tts';

type LearnSubTab = 'signs' | 'scenarios' | 'lessons' | 'quiz';

interface ScenarioItem {
  id: string;
  title: string;
  icon: string;
  tag: string;
  scammerSays: string;
  seniorTrap: string;
  truth: string;
  action: string;
}

interface CuratedLesson {
  id: string | number;
  slug?: string;
  title: string;
  summary: string;
  content: string;
  category: string;
  icon: string;
}

interface QuizItem {
  id: number;
  question: string;
  options: { text: string; correct: boolean; explanation: string }[];
}

const SIGNS = [
  {
    icon: 'bi-person-badge-fill',
    text: 'Tự xưng là công an, viện kiểm sát, tòa án hoặc nhân viên ngân hàng rồi đòi bác chuyển tiền vào "tài khoản an toàn/kiểm tra".',
    tip: 'Công an thật không bao giờ làm việc qua điện thoại và không bao giờ bắt chuyển tiền.',
  },
  {
    icon: 'bi-alarm-fill',
    text: 'Giục bác phải làm ngay trong 15-30 phút, bắt giữ bí mật, cấm không được kể hay hỏi ý kiến con cháu trong nhà.',
    tip: 'Càng bị giục bác càng phải dừng lại, đi hỏi con cháu ngay.',
  },
  {
    icon: 'bi-key-fill',
    text: 'Hỏi xin mã OTP gửi về điện thoại, hỏi mật khẩu tài khoản, hoặc bảo bác quét khuôn mặt / chụp ảnh thẻ căn cước.',
    tip: 'Mã OTP và mật khẩu giống như chìa khóa két sắt, tuyệt đối không đưa cho ai.',
  },
  {
    icon: 'bi-phone-fill',
    text: 'Bảo bác bấm vào đường link lạ để cài ứng dụng "Dịch vụ công", "VNeID", hoặc "Cục Thuế" về điện thoại.',
    tip: 'Ứng dụng tải qua link lạ là phần mềm gián điệp sẽ rút sạch tiền trong tài khoản.',
  },
  {
    icon: 'bi-gift-fill',
    text: 'Báo bác trúng thưởng xe máy, tiền mặt hoặc quà tri ân nhưng bắt nộp trước phí vận chuyển hay thuế.',
    tip: 'Bắt nộp tiền trước để nhận quà thì 100% là lừa đảo.',
  },
  {
    icon: 'bi-bank',
    text: 'Đòi chuyển tiền vào một tài khoản mang tên NGƯỜI LẠ (không phải tên bác hay người nhà) vì bất cứ lý do gì.',
    tip: 'Tiền vào tài khoản người lạ là mất luôn. Người thân thật sẽ cho bác biết trước tên chủ tài khoản.',
  },
  {
    icon: 'bi-android2',
    text: 'Yêu cầu bác tải và cài một ứng dụng ngoài kho CH Play / App Store (file .apk hoặc link tải trực tiếp).',
    tip: 'Chỉ cài ứng dụng từ CH Play (Android) hoặc App Store (iPhone). App ngoài chợ có thể chiếm quyền điện thoại.',
  },
  {
    icon: 'bi-envelope-exclamation-fill',
    text: 'Tin nhắn, email báo bác vi phạm, nợ cước, bị khóa sim/tài khoản và đòi xử lý gấp qua đường link trong tin nhắn.',
    tip: 'Đừng bấm link trong tin nhắn. Bác tự mở app hoặc website chính thức để kiểm tra, hoặc gọi tổng đài in trên thẻ.',
  },
];

const SCENARIOS: ScenarioItem[] = [
  {
    id: 'police',
    title: 'Giả danh Công an dọa bắt giam vì rửa tiền',
    icon: 'bi-shield-exclamation',
    tag: 'Rất nguy hiểm',
    scammerSays:
      'Tôi là cán bộ điều tra. Bác có liên quan đến đường dây rửa tiền ma túy 10 tỷ đồng. Nếu không muốn bị bắt tạm giam ngay hôm nay, bác phải chuyển toàn bộ tiền tiết kiệm vào tài khoản kiểm tra của cơ quan!',
    seniorTrap: 'Kẻ gian đánh vào tâm lý hoang mang, sợ bị bắt oan và sợ ảnh hưởng đến danh dự gia đình.',
    truth: 'Cơ quan công an, viện kiểm sát KHÔNG BAO GIỜ làm việc qua điện thoại và KHÔNG CÓ tài khoản tạm giữ nào bắt người dân chuyển tiền.',
    action: 'Dập máy ngay lập tức! Bác không sợ, đi kể ngay cho con cháu hoặc gọi Công an 113 để báo tin.',
  },
  {
    id: 'vneid',
    title: 'Giả cán bộ phường bảo cài VNeID / Dịch vụ công qua mạng',
    icon: 'bi-person-vcard-fill',
    tag: 'Phổ biến nhất hiện nay',
    scammerSays:
      'Bác ơi, hồ sơ căn cước định danh của bác đang bị sai thông tin. Bác vào Zalo bấm vào đường link cháu gửi để tải ứng dụng Dịch vụ công về máy, quét khuôn mặt là xong, không phải ra phường.',
    seniorTrap: 'Bác nghĩ là thủ tục giấy tờ bình thường của nhà nước và thấy tiện vì khỏi phải đi lại.',
    truth: 'Công an phường không bao giờ gửi link lạ qua Zalo bảo dân cài app. App cài từ link ngoài sẽ chiếm quyền điện thoại và tự động chuyển hết tiền trong tài khoản ngân hàng của bác.',
    action: 'Tuyệt đối không bấm vào link lạ. Bác trả lời: "Để tôi tự ra trực tiếp trụ sở Công an phường làm việc" rồi tắt máy.',
  },
  {
    id: 'deepfake',
    title: 'Cuộc gọi video thấy mặt con cháu mượn tiền cấp cứu',
    icon: 'bi-camera-video-fill',
    tag: 'Công nghệ AI giả mạo',
    scammerSays:
      'Bố/mẹ ơi, con đang bị công an giữ xe / bị tai nạn ngoài đường, điện thoại sắp hết pin. Bố/mẹ chuyển gấp 20 triệu vào số tài khoản bạn con này giúp con với!',
    seniorTrap: 'Bác nhìn thấy đúng mặt con/cháu mình trên màn hình và quá xót ruột lo cho con nên vội chuyển tiền ngay.',
    truth: 'Kẻ gian dùng trí tuệ nhân tạo (Deepfake) ghép mặt con cháu. Đặc điểm: hình ảnh hay bị giật, chớp mắt bất thường, âm thanh chập chờn, gọi rất nhanh rồi cúp, và bảo chuyển vào tài khoản tên người lạ.',
    action: 'Cúp máy ngay! Dùng số điện thoại quen thuộc hàng ngày gọi lại trực tiếp cho con cháu, hoặc gọi cho người thân khác trong nhà để kiểm tra trước khi làm.',
  },
  {
    id: 'lottery',
    title: 'Báo trúng thưởng xe máy / quà tặng tri ân',
    icon: 'bi-trophy-fill',
    tag: 'Bẫy lòng tham & may mắn',
    scammerSays:
      'Chúc mừng bác đã trúng giải đặc biệt xe máy Honda SH 80 triệu từ chương trình tri ân khách hàng. Bác chỉ cần chuyển 2 triệu đồng tiền cước vận chuyển để nhận xe tận nhà.',
    seniorTrap: 'Bác thấy mình may mắn trúng quà to, chỉ phải bỏ ra chút tiền nhỏ tiền cước.',
    truth: 'Không có cơ quan, nhãn hàng uy tín nào bắt người trúng thưởng phải nộp tiền trước qua tài khoản cá nhân để nhận quà.',
    action: 'Xóa ngay tin nhắn, dập máy ngay. Tuyệt đối không chuyển một đồng nào.',
  },
  {
    id: 'parcel',
    title: 'Giả nhân viên giao hàng báo đơn thất lạc, đòi phí phát lại',
    icon: 'bi-box-seam-fill',
    tag: 'Đánh vào thói quen mua hàng',
    scammerSays:
      'Chào bác, đơn hàng của bác giao không thành công do sai địa chỉ. Bác thanh toán phí phát lại 25.000 đồng tại đường link này để shipper giao lại nhé, kẻo mai hàng hoàn về kho.',
    seniorTrap: 'Bác đang chờ hàng, thấy số tiền nhỏ nên chủ quan bấm link và điền thông tin thẻ.',
    truth: 'Đơn vị vận chuyển không bao giờ thu phí phát lại qua link lạ. Trang sau đường link là web giả mạo để lấy số thẻ và mã OTP.',
    action: 'Không bấm link. Bác mở app hoặc website chính thức của đơn vị vận chuyển, nhập mã vận đơn để tự kiểm tra.',
  },
  {
    id: 'investment',
    title: 'Mời góp vốn "sàn" đầu tư lãi cao, rút được vài lần rồi bị chặn',
    icon: 'bi-graph-up-arrow',
    tag: 'Nuôi rồi mổ',
    scammerSays:
      'Cháu có sàn tài chính lãi 20% một tuần, an toàn lắm. Bác nạp 50 triệu, tuần sau rút cả gốc lẫn lãi. Bác thử rút 5 triệu trước cho tin nhé.',
    seniorTrap: 'Bác cho rút thử vài lần thật nên tin tưởng, rồi nạp số lớn thì bị chặn rút và bị đòi thêm tiền phí.',
    truth: 'Không có đầu tư nào lãi cao mà chắc thắng. Sàn "ảo" cho rút nhỏ để tạo niềm tin rồi chiếm đoạt số tiền lớn.',
    action: 'Không nạp thêm. Chỉ đầu tư qua tổ chức được cấp phép; bác tra cứu trên website Ủy ban Chứng khoán Nhà nước.',
  },
  {
    id: 'romance',
    title: 'Kết bạn làm quen qua mạng rồi hỏi mượn tiền, xin quà',
    icon: 'bi-heart-fill',
    tag: 'Nhẹ dạ cả tin',
    scammerSays:
      'Bác à, cháu sắp sang Việt Nam thăm bác nhưng bị giữ ở sân bay, cần đóng 30 triệu tiền phạt. Bác cho cháu vay, sang cháu trả gấp đôi.',
    seniorTrap: 'Bác coi người quen qua mạng như người thân thật, thương hoàn cảnh nên cho vay tiền.',
    truth: 'Sau khi nhận tiền, "người quen" sẽ chặn liên lạc. Đây là chiêu lừa tình cảm rất phổ biến với người cao tuổi.',
    action: 'Dừng ngay, không chuyển khoản cho người chưa từng gặp mặt. Kể lại câu chuyện này cho con cháu.',
  },
  {
    id: 'sim',
    title: 'Giả nhân viên viễn thông báo khóa SIM, dọa cắt liên lạc',
    icon: 'bi-sim-fill',
    tag: 'Dọa khóa dịch vụ',
    scammerSays:
      'Thuê bao của bác sắp bị khóa 2 chiều trong 30 phút tới. Bác đọc mã OTP vừa nhận để cháu gia hạn, không thì bị cắt liên lạc hết.',
    seniorTrap: 'Sợ bị cắt liên lạc với con cháu nên bác vội làm theo và đọc mã OTP.',
    truth: 'Nhà mạng không bao giờ gọi đòi OTP để gia hạn. Kẻ gian cần mã OTP để chiếm tài khoản ngân hàng và ứng dụng của bác.',
    action: 'Không đọc OTP. Dập máy, gọi tổng đài chính thức của nhà mạng in trên hợp đồng/thẻ để kiểm tra.',
  },
];

const FALLBACK_LESSONS: CuratedLesson[] = [
  {
    id: 'lesson-1',
    title: 'Bí quyết nhận diện cuộc gọi Deepfake AI giả mặt con cháu',
    category: 'Cảnh giác cao',
    icon: 'bi-camera-video',
    summary: 'Kẻ gian có thể dùng máy tính để giả hình ảnh và giọng nói của con cháu gọi về mượn tiền.',
    content:
      '1. Đặc điểm nhận biết: Khuôn mặt trên màn hình hơi mờ, mắt ít chớp hoặc chớp đơ, giọng nói có tiếng vang như máy móc, cuộc gọi chỉ kéo dài vài giây rồi tắt lấy lý do sóng yếu.\n'
      + '2. Cách xử lý: Khi thấy nghi ngờ, bác hãy hỏi một câu hỏi chỉ có người trong nhà mới biết (ví dụ: "Hôm nay con ăn cơm với món gì mẹ nấu?").\n'
      + '3. Luôn lấy số điện thoại thường ngày của con cháu để gọi lại xác nhận trước khi chuyển tiền.',
  },
  {
    id: 'lesson-2',
    title: 'Nguyên tắc vàng bảo vệ mã OTP và tài khoản ngân hàng',
    category: 'Bảo vệ tiền',
    icon: 'bi-credit-card-2-front',
    summary: 'Mã OTP là mật mã mở khóa rút tiền, tuyệt đối không bao giờ được chia sẻ cho người khác.',
    content:
      '1. Không đọc mã OTP cho bất kỳ ai, kể cả người tự xưng là giám đốc ngân hàng hay công an.\n'
      + '2. Nhân viên ngân hàng thật không bao giờ có quyền hỏi mật khẩu hay mã OTP của khách hàng.\n'
      + '3. Nếu lỡ đọc mã OTP cho người lạ: Lập tức gọi số hotline in ở mặt sau thẻ ATM của bác để khóa thẻ khẩn cấp!',
  },
  {
    id: 'lesson-3',
    title: 'Cảnh giác mã QR lạ dán ở nơi công cộng và trên thư từ',
    category: 'Mẹo an toàn',
    icon: 'bi-qr-code-scan',
    summary: 'Kẻ gian dán đè mã QR độc hại để lừa bác vào trang web giả mạo đánh cắp tài khoản.',
    content:
      '1. Không quét mã QR lạ được gửi trong tin nhắn hoặc dán ở bưu cục, cổng bệnh viện, quán ăn nếu chưa kiểm tra kỹ.\n'
      + '2. Khi quét mã thanh toán, luôn kiểm tra đúng tên người nhận tiền hiển thị trên màn hình trước khi xác nhận.\n'
      + '3. Chỗ nào nghi ngờ, bác nhờ người quen hoặc con cháu kiểm tra giúp.',
  },
  {
    id: 'lesson-4',
    title: 'Cách con cháu trong nhà lập quy ước an toàn cùng ông bà',
    category: 'Gia đình',
    icon: 'bi-people-fill',
    summary: 'Đặt ra một "mật khẩu gia đình" để kiểm tra người gọi có đúng là người nhà hay không.',
    content:
      '1. Đặt một từ khóa bí mật giữa bác và con cháu trong nhà (ví dụ tên con vật cưng, tên quê quán xưa).\n'
      + '2. Khi có cuộc gọi gấp nhờ chuyển tiền, chỉ cần hỏi từ khóa này, kẻ gian sẽ chịu thua ngay.\n'
      + '3. Khi gặp chuyện lo lắng, việc đầu tiên là thở sâu và gọi điện cho con cháu chia sẻ.',
  },
  {
    id: 'lesson-5',
    title: 'Lỡ chuyển tiền cho kẻ lừa đảo — 3 việc làm ngay trong ngày',
    category: 'Cấp cứu khẩn',
    icon: 'bi-life-preserver',
    summary: 'Càng làm sớm càng có cơ hội giữ lại tiền. Bác làm theo đúng thứ tự dưới đây.',
    content:
      '1. Gọi NGAY tổng đài ngân hàng in ở mặt sau thẻ ATM, yêu cầu khóa thẻ/tài khoản và báo có giao dịch gian lận để tra soát.\n'
      + '2. Giữ nguyên bằng chứng: tin nhắn, số điện thoại, ảnh chuyển tiền, nội dung trò chuyện. Không xóa gì cả.\n'
      + '3. Ra cơ quan Công an gần nhất trình báo, hoặc gọi tổng đài 156 (báo lừa đảo) và 113 nếu bị đe dọa. Nhờ con cháu đi cùng.',
  },
  {
    id: 'lesson-6',
    title: '4 bước kiểm tra trước khi chuyển khoản cho bất kỳ ai',
    category: 'Trước khi mất tiền',
    icon: 'bi-shield-check',
    summary: 'Một phút kiểm tra kỹ giúp bác tránh mất cả số tiền tiết kiệm.',
    content:
      '1. Tự hỏi: chuyển cho AI, tên chủ tài khoản có đúng người bác thật sự biết không?\n'
      + '2. Gọi lại bằng SỐ CŨ đã lưu trong máy — không gọi số vừa gọi đến, không chỉ nhắn Zalo.\n'
      + '3. Không chịu áp lực thời gian: nếu bị giục gấp thì càng phải dừng lại hỏi con cháu.\n'
      + '4. Đang phân vân thì KHOAN bấm nút chuyển — để mai hãy làm cũng chưa muộn.',
  },
  {
    id: 'lesson-7',
    title: 'An toàn khi dùng điện thoại thông minh hằng ngày',
    category: 'Mẹo an toàn',
    icon: 'bi-phone',
    summary: 'Vài thói quen nhỏ giúp điện thoại của bác khó bị kẻ gian tấn công hơn.',
    content:
      '1. Đặt mật khẩu/PIN cho điện thoại và bật khóa bằng vân tay/khuôn mặt nếu máy hỗ trợ.\n'
      + '2. Bật cập nhật tự động cho hệ điều hành và ứng dụng; chỉ cài app từ CH Play/App Store.\n'
      + '3. Không nhấn vào link trong tin nhắn lạ; không cài file .apk gửi qua tin nhắn/Zalo.\n'
      + '4. Không lưu ảnh chụp 2 mặt thẻ căn cước hay mật khẩu trong ghi chú, ảnh, tin nhắn.',
  },
  {
    id: 'lesson-8',
    title: 'Nhận biết tin nhắn, email lừa đảo trong 30 giây',
    category: 'Nhìn dấu hiệu',
    icon: 'bi-envelope-exclamation',
    summary: 'Kẻ gian thường để lộ vài dấu hiệu chỉ cần để ý là thấy ngay.',
    content:
      '1. Tên người gửi/tên miền lạ hoặc sai chính tả so với thương hiệu thật (ví dụ vietcombank-luudan.com).\n'
      + '2. Nội dung tạo cảm giác GẤP, dọa phạt/khóa tài khoản, hoặc báo bác trúng thưởng.\n'
      + '3. Có đường link rút gọn hoặc link lạ; nhìn kỹ tên miền trước khi bấm — tốt nhất là KHÔNG bấm.\n'
      + '4. Yêu cầu cung cấp OTP, mật khẩu, số thẻ hoặc chuyển tiền. Ngân hàng thật không bao giờ hỏi những thứ này.',
  },
];

const QUIZ_LIST: QuizItem[] = [
  {
    id: 1,
    question: 'Có người gọi tự xưng Công an dọa bác có lệnh bắt giam và bắt chuyển 50 triệu vào "tài khoản an toàn" để kiểm tra, bác nên làm gì?',
    options: [
      {
        text: 'Dập máy ngay lập tức, không chuyển tiền, rồi gọi Công an 113 hoặc con cháu.',
        correct: true,
        explanation: 'Hoan hô bác! Bác nhớ rất chuẩn: Công an thật KHÔNG BAO GIỜ làm việc qua điện thoại và không bao giờ bắt dân chuyển tiền vào tài khoản kiểm tra.',
      },
      {
        text: 'Lẳng lặng ra ngân hàng chuyển tiền ngay vì sợ bị công an đến bắt.',
        correct: false,
        explanation: 'Chưa đúng bác nhé! Đây là chiêu lừa đảo giả danh công an kinh điển. Chuyển tiền là mất sạch. Bác phải dập máy ngay!',
      },
    ],
  },
  {
    id: 2,
    question: 'Người tự xưng nhân viên ngân hàng bảo tài khoản bác bị lỗi, xin mã OTP gửi về máy bác để sửa lỗi giúp, bác làm gì?',
    options: [
      {
        text: 'Tuyệt đối KHÔNG đọc mã OTP cho ai, dập máy gọi số tổng đài in sau thẻ ngân hàng.',
        correct: true,
        explanation: 'Chính xác rồi bác! Mã OTP là chìa khóa mở két sắt, nhân viên ngân hàng thật không bao giờ được phép hỏi mã này.',
      },
      {
        text: 'Đọc ngay mã OTP để nhân viên sửa lỗi giúp khỏi bị mất tiền.',
        correct: false,
        explanation: 'Nguy hiểm lắm bác ơi! Đọc mã OTP cho kẻ gian là kẻ gian sẽ rút hết sạch tiền trong tài khoản của bác ngay lập tức.',
      },
    ],
  },
  {
    id: 3,
    question: 'Tin nhắn báo bác trúng xe máy Honda SH 80 triệu, bảo chuyển 2 triệu phí vận chuyển để nhận quà tại nhà, bác làm gì?',
    options: [
      {
        text: 'Xóa ngay tin nhắn và không chuyển đồng nào vì đây là chiêu lừa trúng thưởng.',
        correct: true,
        explanation: 'Tuyệt vời bác ơi! Bắt nộp tiền trước để nhận quà thì 100% là bẫy lừa đảo.',
      },
      {
        text: 'Chuyển trước 2 triệu vì bỏ 2 triệu nhận xe 80 triệu vẫn quá hời.',
        correct: false,
        explanation: 'Mắc bẫy kẻ gian rồi bác ơi! Sau khi chuyển 2 triệu, kẻ gian sẽ chặn số của bác và không có chiếc xe nào cả.',
      },
    ],
  },
  {
    id: 4,
    question: 'Người tự xưng công an xã gọi bảo gửi link qua Zalo bảo bác tải ứng dụng Dịch vụ công về điện thoại, bác làm gì?',
    options: [
      {
        text: 'Không bấm vào link lạ. Nói: "Để tôi tự ra trực tiếp Công an xã làm việc".',
        correct: true,
        explanation: 'Rất chuẩn bác ơi! Công an không bao giờ gửi link lạ qua Zalo bảo cài phần mềm. Bác ra trực tiếp trụ sở công an là an toàn nhất.',
      },
      {
        text: 'Bấm vào link tải về ngay cho tiện đỡ phải đi lại.',
        correct: false,
        explanation: 'Cực kỳ nguy hiểm! Ứng dụng từ link ngoài là mã độc, sẽ theo dõi màn hình và chiếm quyền điều khiển tài khoản ngân hàng của bác.',
      },
    ],
  },
  {
    id: 5,
    question: 'Tin nhắn từ số lạ xưng là đơn vị giao hàng, bảo đơn thất lạc và đòi 25.000 đồng phí phát lại qua đường link, bác làm gì?',
    options: [
      {
        text: 'Không bấm link. Mở app/website chính thức của đơn vị giao hàng để tự kiểm tra mã vận đơn.',
        correct: true,
        explanation: 'Chuẩn bác ơi! Đơn vị vận chuyển không thu phí phát lại qua link lạ. Tự tra trên kênh chính thức là an toàn nhất.',
      },
      {
        text: 'Bấm link đóng 25.000 đồng cho nhanh vì tiền nhỏ.',
        correct: false,
        explanation: 'Nguy hiểm! Trang sau link là web giả để lấy số thẻ và mã OTP, không phải chỉ 25.000 đồng đâu bác.',
      },
    ],
  },
  {
    id: 6,
    question: 'Người lạ nhắn Zalo bảo bác tải file .apk rồi cài để "cập nhật căn cước", bác làm gì?',
    options: [
      {
        text: 'Không cài. Chỉ cài ứng dụng từ CH Play hoặc App Store.',
        correct: true,
        explanation: 'Chính xác! File .apk ngoài chợ ứng dụng là mã độc, có thể chiếm quyền điện thoại và tự chuyển tiền.',
      },
      {
        text: 'Cài thử xem sao, không được thì xóa.',
        correct: false,
        explanation: 'Đừng bác ơi! Mã độc chạy ngầm ngay khi cài, có thể đọc tin nhắn OTP và rút tiền trước khi bác phát hiện.',
      },
    ],
  },
  {
    id: 7,
    question: 'Bác phát hiện vừa chuyển nhầm 30 triệu cho kẻ lừa đảo. Việc cần làm NGAY là gì?',
    options: [
      {
        text: 'Gọi ngay tổng đài ngân hàng (in sau thẻ) để khóa tài khoản/báo gian lận, giữ bằng chứng rồi trình báo công an.',
        correct: true,
        explanation: 'Rất đúng! Làm càng sớm càng có cơ hội giữ lại tiền; giữ nguyên bằng chứng và trình báo công an/156.',
      },
      {
        text: 'Chờ vài ngày xem có lấy lại được không đã.',
        correct: false,
        explanation: 'Chậm là mất! Tiền có thể bị rút/chuyển tiếp trong vài phút. Phải gọi ngân hàng khóa tài khoản ngay.',
      },
    ],
  },
  {
    id: 8,
    question: 'Quảng cáo trên mạng bán điện thoại đời mới giá rẻ hơn một nửa, bắt chuyển khoản trước rồi mới gửi hàng, bác làm gì?',
    options: [
      {
        text: 'Cảnh giác, không chuyển trước cho người bán lạ. Ưu tiên nơi cho kiểm tra hàng hoặc thanh toán khi nhận.',
        correct: true,
        explanation: 'Chuẩn bác! Giá rẻ bất thường cộng với đòi chuyển trước là dấu hiệu lừa. Mua nơi uy tín, có bảo hành.',
      },
      {
        text: 'Chuyển khoản trước cho rẻ, tiếc gì vài phút.',
        correct: false,
        explanation: 'Coi chừng mất tiền! Nhiều vụ "bán rẻ" là bẫy: nhận tiền xong chặn liên lạc, không giao hàng.',
      },
    ],
  },
];

export default function ElderLearn({
  canSpeak,
  speak,
}: {
  canSpeak: boolean;
  speak: (text: string) => void;
}) {
  const [subTab, setSubTab] = useState<LearnSubTab>('signs');
  const [activeScenario, setActiveScenario] = useState<string>(SCENARIOS[0].id);
  const [lessons, setLessons] = useState<CuratedLesson[]>(FALLBACK_LESSONS);
  const [selectedLesson, setSelectedLesson] = useState<CuratedLesson | null>(null);

  const dialogRef = useRef<HTMLDivElement>(null);
  const closeLessonRef = useRef<HTMLButtonElement>(null);

  // Quiz state
  const [quizIdx, setQuizIdx] = useState(0);
  const [selectedOpt, setSelectedOpt] = useState<number | null>(null);
  const [answered, setAnswered] = useState(false);
  const [quizScore, setQuizScore] = useState(0);

  // Load backend lessons if available
  useEffect(() => {
    let alive = true;
    learnApi
      .lessons({ category: 'all' })
      .then((res) => {
        if (!alive) return;
        const list = asList<{ id?: number; slug: string; title: string; summary?: string; content?: string }>(res);
        if (list.length > 0) {
          const mapped: CuratedLesson[] = list.slice(0, 12).map((l, i) => ({
            id: l.id || l.slug || i,
            slug: l.slug,
            title: l.title,
            summary: l.summary || 'Bài học hữu ích giúp bác nhận biết và phòng tránh các thủ đoạn lừa đảo phổ biến.',
            content: l.content || l.summary || '',
            category: 'Cẩm nang',
            icon: i % 2 === 0 ? 'bi-journal-bookmark-fill' : 'bi-shield-check',
          }));
          setLessons(mapped);
        }
      })
      .catch(() => {
        // use fallback lessons silently
      });
    return () => {
      alive = false;
    };
  }, []);

  /* Build trước audio ở server cho toàn bộ nội dung tĩnh của tab Học — lần bấm
   * "Đọc to/Nghe" sau đó là tức thì. Chạy nền, lỗi thì bỏ qua (tự fallback). */
  useEffect(() => {
    const texts: string[] = [];
    SIGNS.forEach((s, i) => {
      texts.push(`Dấu hiệu ${i + 1}: ${s.text}. Lời khuyên: ${s.tip}`);
    });
    texts.push(
      SIGNS.map((s, i) => `Dấu hiệu ${i + 1}: ${s.text}. Lời khuyên của cháu: ${s.tip}`).join('. '),
    );
    SCENARIOS.forEach((sc) => {
      texts.push(
        `Tình huống: ${sc.title}. Kẻ gian nói: "${sc.scammerSays}". Thực tế là: ${sc.truth}. Bác cần làm: ${sc.action}`,
      );
    });
    FALLBACK_LESSONS.forEach((ls) => {
      texts.push(`${ls.title}. Tóm tắt: ${ls.summary}. ${ls.content}`);
      texts.push(`${ls.title}. ${ls.content}`);
    });
    QUIZ_LIST.forEach((q) => {
      texts.push(q.question);
      q.options.forEach((o) => texts.push(o.explanation));
    });
    void warmTts(texts);
  }, []);

  /* Bài học tải từ server (nội dung động) → warm khi có. */
  useEffect(() => {
    if (lessons.length === 0) return;
    void warmTts(
      lessons.flatMap((ls) => [
        `${ls.title}. Tóm tắt: ${ls.summary}. ${ls.content}`,
        `${ls.title}. ${ls.content}`,
      ]),
    );
  }, [lessons]);

  /* Modal xem bài học: khoá cuộn nền, đưa tiêu điểm vào nút "Đóng", đóng bằng
     phím Esc và giữ tiêu điểm (Tab) bên trong hộp thoại. */
  useEffect(() => {
    if (!selectedLesson) return;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    closeLessonRef.current?.focus();
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === 'Escape') {
        e.preventDefault();
        setSelectedLesson(null);
        return;
      }
      if (e.key !== 'Tab') return;
      const root = dialogRef.current;
      if (!root) return;
      const focusables = Array.from(
        root.querySelectorAll<HTMLElement>(
          'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])',
        ),
      );
      if (focusables.length === 0) return;
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = prevOverflow;
    };
  }, [selectedLesson]);

  const curQuiz = QUIZ_LIST[quizIdx];
  const curScenario = SCENARIOS.find((s) => s.id === activeScenario) || SCENARIOS[0];

  const handlePickOption = (idx: number) => {
    if (answered) return;
    setSelectedOpt(idx);
    setAnswered(true);
    if (curQuiz.options[idx].correct) {
      setQuizScore((s) => s + 1);
    }
    if (canSpeak) {
      speak(curQuiz.options[idx].explanation);
    }
  };

  const nextQuiz = () => {
    if (quizIdx + 1 < QUIZ_LIST.length) {
      setQuizIdx((i) => i + 1);
      setSelectedOpt(null);
      setAnswered(false);
    } else {
      // restart
      setQuizIdx(0);
      setSelectedOpt(null);
      setAnswered(false);
      setQuizScore(0);
    }
  };

  return (
    <div className="space-y-8" role="tabpanel" id="panel-learn" aria-labelledby="tab-learn">
      {/* ── Sub-navigation pills ───────────────────────────────────────── */}
      <div className="flex flex-wrap items-center justify-center gap-2 sm:gap-3">
        <button
          type="button"
          className={`elder-btn ${subTab === 'signs' ? 'border-brand-400 bg-brand-500/25 text-brand-100 font-extrabold' : 'elder-btn--quiet'}`}
          onClick={() => setSubTab('signs')}
        >
          <i className="bi bi-bookmark-star-fill elder-icon text-warn-300" aria-hidden="true"></i>
          {SIGNS.length} dấu hiệu nhận biết
        </button>
        <button
          type="button"
          className={`elder-btn ${subTab === 'scenarios' ? 'border-brand-400 bg-brand-500/25 text-brand-100 font-extrabold' : 'elder-btn--quiet'}`}
          onClick={() => setSubTab('scenarios')}
        >
          <i className="bi bi-chat-square-quote-fill elder-icon text-brand-300" aria-hidden="true"></i>
          Tình huống thực tế
        </button>
        <button
          type="button"
          className={`elder-btn ${subTab === 'lessons' ? 'border-brand-400 bg-brand-500/25 text-brand-100 font-extrabold' : 'elder-btn--quiet'}`}
          onClick={() => setSubTab('lessons')}
        >
          <i className="bi bi-journal-text elder-icon text-safe-300" aria-hidden="true"></i>
          Cẩm nang bài học
        </button>
        <button
          type="button"
          className={`elder-btn ${subTab === 'quiz' ? 'border-brand-400 bg-brand-500/25 text-brand-100 font-extrabold' : 'elder-btn--quiet'}`}
          onClick={() => setSubTab('quiz')}
        >
          <i className="bi bi-patch-question-fill elder-icon text-danger-300" aria-hidden="true"></i>
          Thử tài nhận diện
        </button>
      </div>

      {/* ── Phân đoạn 1: 5 DẤU HIỆU ──────────────────────────────────── */}
      {subTab === 'signs' && (
        <section className="space-y-5" aria-labelledby="elder-signs-heading">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 id="elder-signs-heading" className="elder-h2">
                <i className="bi bi-bookmark-star-fill elder-h-icon text-warn-300" aria-hidden="true"></i>
                {SIGNS.length} dấu hiệu nhận biết lừa đảo kinh điển
              </h2>
              <p className="elder-note mt-1">Gặp bất kỳ dấu hiệu nào trong {SIGNS.length} điều này, bác hãy dừng lại ngay.</p>
            </div>
            {canSpeak && (
              <button
                type="button"
                className="elder-btn"
                onClick={() =>
                  speak(
                    SIGNS.map(
                      (s, i) => `Dấu hiệu ${i + 1}: ${s.text}. Lời khuyên của cháu: ${s.tip}`,
                    ).join('. '),
                  )
                }
              >
                <i className="bi bi-volume-up-fill elder-icon" aria-hidden="true"></i> Đọc to {SIGNS.length} dấu hiệu
              </button>
            )}
          </div>

          <ul className="space-y-4">
            {SIGNS.map((s, i) => (
              <li key={i} className="elder-card space-y-2 border-border hover:border-brand-400/60 transition-colors">
                <div className="flex items-start gap-3">
                  <span className="elder-todo__num" aria-hidden="true">
                    {i + 1}
                  </span>
                  <i className={`bi ${s.icon} elder-icon text-warn-300 shrink-0 mt-0.5`} aria-hidden="true"></i>
                  <div className="flex-1 space-y-2">
                    <p className="elder-body font-bold text-foreground">{s.text}</p>
                    <div className="rounded-lg bg-safe-500/10 border border-safe-500/20 p-2.5 flex items-start gap-2">
                      <i className="bi bi-lightbulb-fill text-safe-300 shrink-0 mt-0.5" aria-hidden="true"></i>
                      <p className="elder-note text-safe-100 font-semibold">{s.tip}</p>
                    </div>
                  </div>
                </div>
                {canSpeak && (
                  <div className="flex justify-end pt-1">
                    <button
                      type="button"
                      className="elder-btn elder-btn--sm"
                      onClick={() => speak(`Dấu hiệu ${i + 1}: ${s.text}. Lời khuyên: ${s.tip}`)}
                    >
                      <i className="bi bi-volume-up elder-icon" aria-hidden="true"></i> Nghe dấu hiệu này
                    </button>
                  </div>
                )}
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* ── Phân đoạn 2: TÌNH HUỐNG THỰC TẾ ──────────────────────────── */}
      {subTab === 'scenarios' && (
        <section className="space-y-5" aria-labelledby="elder-scenarios-heading">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 id="elder-scenarios-heading" className="elder-h2">
                <i className="bi bi-chat-square-quote-fill elder-h-icon text-brand-300" aria-hidden="true"></i>
                Kịch bản tình huống lừa đảo hay gặp nhất
              </h2>
              <p className="elder-note mt-1">Bác chọn một tình huống bên dưới để xem kẻ gian lừa ra sao và cách bác đối phó.</p>
            </div>
            {canSpeak && (
              <button
                type="button"
                className="elder-btn"
                onClick={() =>
                  speak(
                    `Tình huống: ${curScenario.title}. Kẻ gian nói: "${curScenario.scammerSays}". Thực tế là: ${curScenario.truth}. Bác cần làm: ${curScenario.action}`,
                  )
                }
              >
                <i className="bi bi-volume-up-fill elder-icon" aria-hidden="true"></i> Đọc to tình huống này
              </button>
            )}
          </div>

          {/* Chọn tình huống */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {SCENARIOS.map((sc) => {
              const active = sc.id === activeScenario;
              return (
                <button
                  key={sc.id}
                  type="button"
                  aria-pressed={active}
                  onClick={() => setActiveScenario(sc.id)}
                  className="elder-btn elder-btn--choice text-left"
                >
                  <i className={`bi ${sc.icon} elder-icon text-brand-300`} aria-hidden="true"></i>
                  <div className="flex-1 min-w-0">
                    <span className="block font-bold">{sc.title}</span>
                    <span className="block elder-tag font-semibold text-danger-300">{sc.tag}</span>
                  </div>
                  {active && <i className="bi bi-check-circle-fill text-safe-300 shrink-0" aria-hidden="true"></i>}
                </button>
              );
            })}
          </div>

          {/* Chi tiết tình huống đang chọn */}
          <div className="elder-scenario-box space-y-4">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <h3 className="elder-h3 text-brand-200">{curScenario.title}</h3>
              <span className="rounded-full bg-danger-500/20 px-3 py-1 elder-tag font-bold text-danger-200">
                {curScenario.tag}
              </span>
            </div>

            {/* Kẻ gian nói */}
            <div className="rounded-xl border border-danger-500/30 bg-danger-500/10 p-3.5 space-y-1">
              <p className="elder-small font-bold text-danger-300 flex items-center gap-2">
                <i className="bi bi-megaphone-fill" aria-hidden="true"></i> Kẻ gian sẽ nói qua điện thoại:
              </p>
              <p className="elder-body font-semibold italic text-foreground">&ldquo;{curScenario.scammerSays}&rdquo;</p>
            </div>

            {/* Tâm lý mắc bẫy */}
            <div className="space-y-1 pl-1">
              <p className="elder-small font-bold text-warn-300 flex items-center gap-2">
                <i className="bi bi-exclamation-diamond-fill" aria-hidden="true"></i> Vì sao người cao tuổi hay mắc bẫy:
              </p>
              <p className="elder-note text-foreground">{curScenario.seniorTrap}</p>
            </div>

            {/* Sự thật */}
            <div className="rounded-xl border border-safe-500/30 bg-safe-500/10 p-3.5 space-y-1">
              <p className="elder-small font-bold text-safe-300 flex items-center gap-2">
                <i className="bi bi-shield-fill-check" aria-hidden="true"></i> Sự thật bác cần nhớ:
              </p>
              <p className="elder-body font-bold text-safe-100">{curScenario.truth}</p>
            </div>

            {/* Việc bác cần làm */}
            <div className="rounded-xl border border-brand-500/30 bg-brand-500/15 p-3.5 space-y-1">
              <p className="elder-small font-bold text-brand-300 flex items-center gap-2">
                <i className="bi bi-hand-thumbs-up-fill" aria-hidden="true"></i> Việc chuẩn xác bác cần làm ngay:
              </p>
              <p className="elder-body font-bold text-foreground">{curScenario.action}</p>
            </div>
          </div>
        </section>
      )}

      {/* ── Phân đoạn 3: CẨM NANG BÀI HỌC ────────────────────────────── */}
      {subTab === 'lessons' && (
        <section className="space-y-5" aria-labelledby="elder-lessons-heading">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 id="elder-lessons-heading" className="elder-h2">
                <i className="bi bi-journal-text elder-h-icon text-safe-300" aria-hidden="true"></i>
                Cẩm nang bài học phòng tránh lừa đảo
              </h2>
              <p className="elder-note mt-1">Các bài học ngắn gọn, dễ hiểu được soạn riêng cho người cao tuổi.</p>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {lessons.map((ls) => (
              <div key={ls.id} className="elder-card flex flex-col justify-between space-y-3">
                <div className="space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <span className="rounded-md bg-safe-500/20 px-2 py-0.5 elder-tag font-bold text-safe-200">
                      {ls.category}
                    </span>
                    <i className={`bi ${ls.icon} elder-icon text-brand-300`} aria-hidden="true"></i>
                  </div>
                  <h3 className="elder-h3 text-foreground font-bold">{ls.title}</h3>
                  <p className="elder-note">{ls.summary}</p>
                </div>
                <div className="flex flex-col sm:flex-row gap-2 pt-2">
                  <button
                    type="button"
                    className="elder-btn elder-btn--brand flex-1"
                    onClick={() => setSelectedLesson(ls)}
                  >
                    <i className="bi bi-book-fill elder-icon" aria-hidden="true"></i> Đọc bài học
                  </button>
                  {canSpeak && (
                    <button
                      type="button"
                      className="elder-btn flex-1"
                      onClick={() => speak(`${ls.title}. Tóm tắt: ${ls.summary}. ${ls.content}`)}
                      aria-label={`Nghe đọc bài ${ls.title}`}
                    >
                      <i className="bi bi-volume-up elder-icon" aria-hidden="true"></i> Nghe đọc
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>

          {/* Modal / Xem bài học chi tiết */}
          {selectedLesson && (
            <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm" role="presentation">
              <div
                ref={dialogRef}
                role="dialog"
                aria-modal="true"
                aria-labelledby="elder-lesson-title"
                className="elder-card bg-card border-brand-400 max-w-2xl w-full max-h-[85vh] overflow-y-auto space-y-4 shadow-2xl p-6"
              >
                <div className="flex items-start justify-between gap-3 border-b border-border pb-3">
                  <h3 id="elder-lesson-title" className="elder-h2 text-foreground font-extrabold">{selectedLesson.title}</h3>
                  <button
                    ref={closeLessonRef}
                    type="button"
                    className="elder-btn elder-btn--sm"
                    onClick={() => setSelectedLesson(null)}
                    aria-label="Đóng cửa sổ bài học"
                  >
                    <i className="bi bi-x-lg elder-icon" aria-hidden="true"></i> Đóng
                  </button>
                </div>

                <div className="rounded-lg bg-safe-500/10 p-3 border border-safe-500/20">
                  <p className="elder-body font-semibold text-safe-200">{selectedLesson.summary}</p>
                </div>

                <div className="elder-body whitespace-pre-line text-foreground leading-relaxed font-medium">
                  {selectedLesson.content}
                </div>

                <div className="flex flex-wrap justify-end gap-3 pt-4 border-t border-border">
                  {canSpeak && (
                    <button
                      type="button"
                      className="elder-btn"
                      onClick={() => speak(`${selectedLesson.title}. ${selectedLesson.content}`)}
                    >
                      <i className="bi bi-volume-up-fill elder-icon" aria-hidden="true"></i> Đọc to toàn bộ bài này
                    </button>
                  )}
                  <button
                    type="button"
                    className="elder-btn elder-btn--brand"
                    onClick={() => setSelectedLesson(null)}
                  >
                    Cháu cảm ơn, tôi đã đọc xong
                  </button>
                </div>
              </div>
            </div>
          )}
        </section>
      )}

      {/* ── Phân đoạn 4: THỬ TÀI NHẬN DIỆN (QUIZ) ───────────────────── */}
      {subTab === 'quiz' && (
        <section className="space-y-5" aria-labelledby="elder-quiz-heading">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 id="elder-quiz-heading" className="elder-h2">
                <i className="bi bi-patch-question-fill elder-h-icon text-danger-300" aria-hidden="true"></i>
                Thử tài nhận diện tình huống lừa đảo
              </h2>
              <p className="elder-note mt-1">Câu hỏi thực tế ngắn gọn, bác chỉ cần bấm chọn một đáp án.</p>
            </div>
            <div className="flex items-center gap-2 font-bold text-safe-300">
              <i className="bi bi-award-fill elder-icon" aria-hidden="true"></i>
              <span>Điểm của bác: {quizScore} / {QUIZ_LIST.length}</span>
            </div>
          </div>

          <div className="elder-card space-y-5 border-2 border-brand-500/40">
            <div className="flex items-center justify-between elder-small font-bold text-muted-foreground">
              <span>Câu hỏi {quizIdx + 1} trên {QUIZ_LIST.length}</span>
              {canSpeak && (
                <button
                  type="button"
                  className="elder-btn elder-btn--sm"
                  onClick={() => speak(curQuiz.question)}
                >
                  <i className="bi bi-volume-up elder-icon" aria-hidden="true"></i> Đọc câu hỏi
                </button>
              )}
            </div>

            <p className="elder-h3 font-extrabold text-foreground leading-snug">{curQuiz.question}</p>

            <div className="space-y-3">
              {curQuiz.options.map((opt, i) => {
                let optCls = 'elder-quiz-opt';
                if (answered) {
                  if (opt.correct) optCls += ' elder-quiz-opt--correct';
                  else if (selectedOpt === i) optCls += ' elder-quiz-opt--wrong';
                }
                return (
                  <button
                    key={i}
                    type="button"
                    disabled={answered}
                    className={optCls}
                    onClick={() => handlePickOption(i)}
                  >
                    <span className="elder-todo__num shrink-0 mt-0.5">
                      {String.fromCharCode(65 + i)}
                    </span>
                    <span className="flex-1 text-left">{opt.text}</span>
                    {answered && opt.correct && (
                      <i className="bi bi-check-circle-fill elder-icon text-safe-300 shrink-0" aria-hidden="true"></i>
                    )}
                    {answered && !opt.correct && selectedOpt === i && (
                      <i className="bi bi-x-circle-fill elder-icon text-danger-300 shrink-0" aria-hidden="true"></i>
                    )}
                  </button>
                );
              })}
            </div>

            {/* Phản hồi sau khi trả lời */}
            {answered && selectedOpt !== null && (
              <div
                className={`p-4 rounded-xl space-y-2 border ${
                  curQuiz.options[selectedOpt].correct
                    ? 'bg-safe-500/15 border-safe-400 text-safe-100'
                    : 'bg-danger-500/15 border-danger-400 text-danger-100'
                }`}
              >
                <div className="flex items-center gap-2 elder-h3">
                  <i
                    className={`bi ${
                      curQuiz.options[selectedOpt].correct ? 'bi-check-circle-fill' : 'bi-exclamation-triangle-fill'
                    } elder-icon`}
                    aria-hidden="true"
                  ></i>
                  <span>
                    {curQuiz.options[selectedOpt].correct ? 'Đúng rồi bác ơi!' : 'Chưa đúng rồi bác nhé!'}
                  </span>
                </div>
                <p className="elder-body font-semibold">{curQuiz.options[selectedOpt].explanation}</p>
                <div className="flex flex-wrap items-center justify-between gap-3 pt-3">
                  {canSpeak && (
                    <button
                      type="button"
                      className="elder-btn elder-btn--sm"
                      onClick={() => speak(curQuiz.options[selectedOpt].explanation)}
                    >
                      <i className="bi bi-volume-up elder-icon" aria-hidden="true"></i> Nghe giải thích
                    </button>
                  )}
                  <button type="button" className="elder-btn elder-btn--brand" onClick={nextQuiz}>
                    {quizIdx + 1 < QUIZ_LIST.length ? 'Làm câu tiếp theo' : 'Chơi lại từ đầu'}
                    <i className="bi bi-arrow-right elder-icon" aria-hidden="true"></i>
                  </button>
                </div>
              </div>
            )}
          </div>
        </section>
      )}
    </div>
  );
}
