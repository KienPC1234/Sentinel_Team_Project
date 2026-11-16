'use client';

/* Định nghĩa tour hướng dẫn theo từng trang (dùng với driver.js).
 * HợP ĐỒNG NEO (anchor contract): mọi bước có `element` PHẢI là selector
 * `[data-tour="..."]` và neo đó phải tồn tại trong file view tương ứng.
 * `npm run check:tours` (frontend/scripts/check-tours.mjs) quét toàn bộ
 * trang đích để bắt lỗi neo bị xoá/làm mất khi sửa code — chạy trước khi commit.
 *
 * Nguyên tắc UX để tránh hướng dẫn thừa / hiển nhiên:
 * - Chỉ định nghĩa tour cho trang có thao tác phức tạp (scan, report, radar,
 *   forum, learn, emergency, dashboard, scam-iq, home, người cao tuổi).
 *   Trang đơn giản (login, legal, 404, ai-assistant...) -> không có tour ->
 *   nút ? tự ẩn.
 * - Mỗi tour tối đa 4 bước, mỗi bước 1 ý duy nhất, tập trung vào điểm dễ sai
 *   (anti-spam, chuẩn hóa SĐT, privacy toggle, đọc guardrail, nút tố cáo).
 * - Bước đầu luôn là popover giữa màn hình (không cần element) nên tour không
 *   bao giờ trống; các bước còn lại bị lọc bỏ nếu selector không tồn tại.
 */

export interface TourStepDef {
  /** BẮT BUỘC là `[data-tour="..."]`. Bỏ trống = popover giữa màn hình. */
  element?: string;
  title: string;
  description: string;
  side?: 'top' | 'right' | 'bottom' | 'left';
  align?: 'start' | 'center' | 'end';
}

export interface TourDef {
  id: string;
  /** Tiêu đề hiển thị trên banner gợi ý. */
  label: string;
  /** Mô tả ngắn 1 dòng cho banner gợi ý. */
  hint: string;
  steps: TourStepDef[];
}

function scanTour(
  id: string,
  label: string,
  inputHint: string,
  submitLabel: string,
): TourDef {
  return {
    id,
    label,
    hint: inputHint,
    steps: [
      {
        title: label,
        description:
          '3 việc duy nhất cần làm: nhập đúng định dạng, vượt xác minh chống spam, bấm nút quét. Không cần đọc hết trang này.',
      },
      {
        element: '[data-tour="scan-form"]',
        title: '1 — Nhập đúng định dạng',
        description: inputHint,
        side: 'bottom',
        align: 'start',
      },
      {
        element: '[data-tour="scan-privacy"]',
        title: '2 — Đừng bỏ qua 2 dòng nhỏ',
        description:
          'Ô "Che thông tin nhạy cảm" nên để BẬT. Ô xác minh chống spam phải hiện dấu tích xanh thì nút quét mới có tác dụng.',
        side: 'top',
        align: 'center',
      },
      {
        element: '[data-tour="scan-submit"]',
        title: `3 — Bấm ${submitLabel} rồi đọc kết quả`,
        description:
          'ĐỎ = nguy hiểm, VÀNG = thận trọng, XÁM = chưa đủ căn cứ (không phải an toàn). Kéo xuống đọc "Tại sao có kết quả này" và "Bằng chứng" trước khi quyết định.',
        side: 'top',
        align: 'center',
      },
    ],
  };
}

export const TOURS: Record<string, TourDef> = {
  home: {
    id: 'home',
    label: 'Trang chủ ShieldCall VN',
    hint: 'Nhập SĐT / link / STK vào ô Scanner rồi bấm Quét.',
    steps: [
      {
        title: 'ShieldCall VN làm 2 việc chính',
        description:
          'Quét kiểm tra (SĐT, link, STK, file...) và nhận tố cáo từ cộng đồng. Bạn không cần tài khoản để quét thử.',
      },
      {
        element: '[data-tour="home-scanner"]',
        title: '1 — Ô Scanner dùng nhanh',
        description:
          'Dán SĐT, URL hoặc số tài khoản vào đây rồi bấm Quét. Hệ thống tự điều hướng sang đúng công cụ (không cần chọn tay).',
        side: 'bottom',
        align: 'center',
      },
      {
        element: '[data-tour="home-scam-iq"]',
        title: '2 — Bài kiểm tra Scam IQ',
        description:
          'Làm 5 phút để biết mình dễ sập bẫy nào. Chỉ cần làm 1 lần, không cần làm lại mỗi lần vào web.',
        side: 'top',
        align: 'center',
      },
    ],
  },

  'scan-phone': scanTour(
    'scan-phone',
    'Kiểm tra số điện thoại',
    'Nhập kiểu 0978589220 hoặc +84978589220. Số đúng định dạng vẫn có thể bị giả mạo Caller ID.',
    'SCAN',
  ),
  'scan-website': scanTour(
    'scan-website',
    'Kiểm tra website / link',
    'Nhập domain kiểu example.com hoặc URL đầy đủ. Bật Deep Scan chỉ khi cần soi kỹ (chậm hơn).',
    'SCAN',
  ),
  'scan-bank': scanTour(
    'scan-bank',
    'Kiểm tra tài khoản ngân hàng',
    'Chọn đúng ngân hàng trước, rồi nhập số tài khoản. Luôn kiểm tra trước khi chuyển tiền cho người lạ.',
    'TRA CỨU',
  ),
  'scan-message': scanTour(
    'scan-message',
    'Phân tích tin nhắn',
    'Dán nội dung tin nhắn trúng thưởng / đe dọa vào ô bên trái. Có ảnh chụp thì tải thêm để OCR chính xác hơn.',
    'PHÂN TÍCH',
  ),
  'scan-email': scanTour(
    'scan-email',
    'Phân tích email lừa đảo',
    'Tải file .eml cho kết quả chính xác nhất. Nhập tay chỉ dùng khi không xuất được file.',
    'PHÂN TÍCH',
  ),
  'scan-qr': scanTour(
    'scan-qr',
    'Quét QR / ảnh',
    'Chụp rõ mã QR rồi tải lên, đừng quét trực tiếp bằng camera điện thoại khi chưa rõ nguồn.',
    'PHÂN TÍCH',
  ),
  'scan-image': scanTour(
    'scan-image',
    'Quét ảnh / chứng từ',
    'Tải ảnh chuyển khoản, hóa đơn cần xác minh. Ảnh mờ / cắt góc sẽ làm AI đọc sai.',
    'PHÂN TÍCH',
  ),
  'scan-file': scanTour(
    'scan-file',
    'Quét file trong Sandbox',
    'Kéo file .apk / .exe / .pdf vào khung. Không mở file trước khi có kết quả.',
    'KIỂM TRA',
  ),
  'scan-audio': scanTour(
    'scan-audio',
    'Phân tích âm thanh cuộc gọi',
    'Tải file (MP3/WAV, tối đa 50MB) hoặc bấm micro để ghi âm trực tiếp. Ghi âm ít nhất 2 giây, nơi yên tĩnh.',
    'PHÂN TÍCH',
  ),
  'scan-lookup': {
    id: 'scan-lookup',
    label: 'Tra cứu nhanh',
    hint: 'Ô tra cứu tự nhận diện SĐT / link / STK.',
    steps: [
      {
        title: 'Tra cứu nhanh tự nhận diện',
        description:
          'Chỉ cần dán nội dung vào ô duy nhất, hệ thống tự nhận diện SĐT / link / STK và chuyển sang công cụ phù hợp.',
      },
      {
        element: '[data-tour="scan-form"]',
        title: '1 — Dán và bấm Tra cứu',
        description: 'Không cần chọn loại trước. Nếu sai loại, sửa lại ô nhập là đủ.',
        side: 'bottom',
        align: 'start',
      },
      {
        element: '[data-tour="scan-submit"]',
        title: '2 — Đọc nhãn guardrail',
        description:
          'Tin nhãn "CHƯA ĐỦ CƠ SỞ XÁC MINH" nghĩa là thiếu bằng chứng — không phải an toàn. Xác minh thêm qua kênh chính thức.',
        side: 'top',
        align: 'center',
      },
    ],
  },

  report: {
    id: 'report',
    label: 'Gửi báo cáo lừa đảo',
    hint: 'Chọn loại đối tượng → mô tả ≥10 ký tự → gửi.',
    steps: [
      {
        title: 'Báo cáo tốt cần 3 mảnh',
        description:
          'Đối tượng đúng loại, mô tả trên 10 ký tự, và ít nhất 1 bằng chứng (ảnh, link, STK). Thiếu 1 trong 3 thì duyệt rất chậm.',
      },
      {
        element: '[data-tour="report-form"]',
        title: '1 — Chọn đúng loại đối tượng',
        description:
          'Ô nhập tự nhận diện SĐT / link / email, nhưng bạn vẫn nên kiểm tra lại pill loại phía trên trước khi gửi.',
        side: 'bottom',
        align: 'center',
      },
      {
        element: '[data-tour="report-desc"]',
        title: '2 — Mô tả + bằng chứng',
        description:
          'Dùng nút gợi ý "+ Kênh & Thời gian", "+ Thủ đoạn" để chèn khung mô tả. Dán ảnh từ clipboard (Ctrl+V) cũng được, tối đa 5 ảnh.',
        side: 'top',
        align: 'center',
      },
    ],
  },

  'scam-radar': {
    id: 'scam-radar',
    label: 'Radar cảnh báo',
    hint: 'Lọc theo chủ đề lừa đảo đang nóng, bấm thẻ để quét ngay.',
    steps: [
      {
        title: 'Radar là bảng tin, không phải ô tìm kiếm',
        description:
          'Vào đây để xem chiêu lừa đang nóng qua nút lọc và thẻ quét nhanh. Thấy cái nào giống trường hợp của mình thì bấm vào.',
      },
      {
        element: '[data-tour="radar-filters"]',
        title: '1 — Lọc theo chủ đề',
        description:
          'Bấm các nút lọc (Việc làm, Đầu tư, Giả danh...) để xem đúng loại đang nóng, kèm khoảng thời gian 24h / 7 ngày.',
        side: 'bottom',
        align: 'start',
      },
      {
        element: '[data-tour="radar-cards"]',
        title: '2 — Quét nhanh từ Radar',
        description: 'Bấm vào thẻ công cụ để quét ngay loại đó. Nghi ngờ thì bấm "Gửi báo cáo" phía trên.',
        side: 'top',
        align: 'center',
      },
    ],
  },

  forum: {
    id: 'forum',
    label: 'Diễn đàn cộng đồng',
    hint: 'Tìm kiếm trước khi đăng bài mới.',
    steps: [
      {
        title: 'Hỏi 1 lần, đọc nhiều lần',
        description:
          'Tìm kiếm trước khi đăng bài mới — 90% câu hỏi SĐT lạ / việc làm online đã có người hỏi rồi.',
      },
      {
        element: '[data-tour="forum-search"]',
        title: '1 — Tìm trước khi hỏi',
        description: 'Gõ SĐT, tên miền hoặc STK vào ô tìm kiếm để xem đã có cảnh báo chưa.',
        side: 'bottom',
        align: 'start',
      },
      {
        element: '[data-tour="forum-create"]',
        title: '2 — Đăng bài mới',
        description: 'Chỉ đăng khi đã tìm mà chưa có. Đính kèm ảnh bằng chứng và che thông tin cá nhân của bạn.',
        side: 'bottom',
        align: 'center',
      },
    ],
  },

  learn: {
    id: 'learn',
    label: 'Kiến thức phòng tránh',
    hint: 'Bài học ngắn + tin tức lừa đảo mới.',
    steps: [
      {
        title: 'Học 5 phút mỗi ngày là đủ',
        description:
          'Đọc 1 bài trong "Kiến thức mới" là đủ, không cần cày hết. Bài nào có gắn Scam IQ thì làm ngay sau khi đọc.',
      },
      {
        element: '[data-tour="learn-search"]',
        title: '1 — Tìm theo chiêu lừa',
        description: 'Gõ "giả danh công an", "việc làm online", "deepfake" để lọc đúng bài mình cần.',
        side: 'bottom',
        align: 'start',
      },
    ],
  },

  emergency: {
    id: 'emergency',
    label: 'Hỗ trợ khẩn cấp',
    hint: 'Bị lừa chuyển tiền: khóa tài khoản → gọi 113 → báo ngân hàng.',
    steps: [
      {
        title: 'Đang bị lừa thì đừng đọc hết trang',
        description:
          'Làm đúng 3 bước theo thứ tự: 1) Khóa tiền (gọi ngân hàng), 2) Gọi 113 / trình báo, 3) Thu thập bằng chứng. Trang này sắp xếp đúng thứ tự đó.',
      },
      {
        element: '[data-tour="emergency-call"]',
        title: '1 — Số điện thoại khẩn cấp',
        description: 'Bấm trực tiếp để gọi. Gọi ngân hàng trước để đóng băng giao dịch, rồi mới gọi công an.',
        side: 'bottom',
        align: 'center',
      },
    ],
  },

  dashboard: {
    id: 'dashboard',
    label: 'Bảng điều khiển',
    hint: 'Lịch sử quét, báo cáo và huy hiệu của bạn.',
    steps: [
      {
        title: 'Đây là trang cá nhân dùng sau',
        description:
          'Không cần học thuộc. Khi cần xem lại kết quả quét cũ hoặc trạng thái báo cáo thì quay lại đây.',
      },
      {
        element: '[data-tour="dashboard-stats"]',
        title: '1 — 4 con số cần nhớ',
        description: 'Tổng lượt quét, số cảnh báo rủi ro, báo cáo đã gửi và điểm bảo vệ. Mọi thứ khác chỉ là chi tiết.',
        side: 'bottom',
        align: 'center',
      },
    ],
  },

  'scam-iq': {
    id: 'scam-iq',
    label: 'Bài kiểm tra Scam IQ',
    hint: 'Trả lời từng tình huống, không cần làm 1 mạch.',
    steps: [
      {
        title: 'Cứ trả lời như ngoài đời thật',
        description:
          'Không có điểm liệt, sai thì hệ thống giải thích ngay. Làm 1 lần duy nhất, không cần điểm tuyệt đối.',
      },
      {
        element: '[data-tour="scam-iq-start"]',
        title: '1 — Nút bắt đầu',
        description: 'Bấm "Khởi tạo câu hỏi" rồi trả lời như bạn sẽ làm ngoài đời (chuyển tiền, bấm link, gọi lại...), đừng chọn đáp án "đúng lý thuyết".',
        side: 'bottom',
        align: 'center',
      },
    ],
  },

  elder: {
    id: 'elder',
    label: 'Chế độ người cao tuổi',
    hint: 'Chữ to, nút to — chỉ cần nhập SĐT / tin nhắn rồi bấm kiểm tra.',
    steps: [
      {
        title: 'Chỉ cần nhớ 1 khung duy nhất',
        description: 'Chọn loại (SĐT hay tin nhắn), nhập nội dung rồi bấm kiểm tra. Chữ to sẵn, không cần đeo kính lúp.',
      },
      {
        element: '[data-tour="elder-form"]',
        title: '1 — Nhập rồi bấm kiểm tra',
        description: 'Đánh số điện thoại hoặc dán tin nhắn vào khung này rồi bấm nút kiểm tra bên dưới. Đánh cả khoảng trắng cũng được.',
        side: 'bottom',
        align: 'center',
      },
    ],
  },
};

/** Map pathname -> tour id. Trả về null khi trang không cần hướng dẫn. */
export function getTourIdForPath(pathname: string | null | undefined): string | null {
  if (!pathname) return null;
  const p = pathname.endsWith('/') && pathname !== '/' ? pathname.slice(0, -1) : pathname;
  if (p === '/' || p === '/home') return 'home';
  if (p.startsWith('/scan/phone')) return 'scan-phone';
  if (p.startsWith('/scan/website')) return 'scan-website';
  if (p.startsWith('/scan/bank')) return 'scan-bank';
  if (p.startsWith('/scan/message')) return 'scan-message';
  if (p.startsWith('/scan/email')) return 'scan-email';
  if (p.startsWith('/scan/qr')) return 'scan-qr';
  if (p.startsWith('/scan/image')) return 'scan-image';
  if (p.startsWith('/scan/file')) return 'scan-file';
  if (p.startsWith('/scan/audio')) return 'scan-audio';
  if (p.startsWith('/scan/lookup') || p.startsWith('/scan/status')) return 'scan-lookup';
  if (p.startsWith('/scan')) return 'scan-lookup';
  if (p.startsWith('/report') || p.startsWith('/reports') || p.startsWith('/my-reports')) return 'report';
  if (p.startsWith('/scam-radar')) return 'scam-radar';
  if (p.startsWith('/forum')) return 'forum';
  if (p.startsWith('/learn')) return 'learn';
  if (p.startsWith('/emergency')) return 'emergency';
  if (p.startsWith('/dashboard')) return 'dashboard';
  if (p.startsWith('/scam-iq-exam')) return 'scam-iq';
  if (p.startsWith('/nguoi-cao-tuoi')) return 'elder';
  if (p.startsWith('/ai-assistant')) return null;
  return null;
}
