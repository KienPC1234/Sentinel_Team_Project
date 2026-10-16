'use client';
/* Port 1-1 từ PKV/templates/Report/report.html (Alpine.js → React).
 * API giữ nguyên: POST /api/v1/report/ (upload), GET /api/v1/scan/banks/.
 * Turnstile dùng TurnstileWidget + getTsToken/resetTurnstile (ScanWidgets).
 */
import { useEffect, useRef, useState } from 'react';
import type { ChangeEvent, DragEvent } from 'react';
import Link from 'next/link';
import { api, ApiError, mediaUrl } from '../../lib/api';
import { showToast, showAlert } from '../../lib/ui/feedback';
import { TurnstileWidget, getTsToken, resetTurnstile } from '../../components/ScanWidgets';

type TargetType = 'phone' | 'domain' | 'account' | 'email' | 'message' | 'file' | 'social' | 'crypto' | 'audio' | 'qr';

const ACTIVE_CYAN = 'bg-brand-500 text-black shadow-lg shadow-brand-500/20 font-black';

interface TargetDef {
  v: TargetType;
  label: string;
  icon: string;
  active: string;
}

const TARGETS: TargetDef[] = [
  { v: 'phone', label: 'Số ĐT', icon: 'bi-telephone-fill', active: ACTIVE_CYAN },
  { v: 'domain', label: 'Website', icon: 'bi-globe', active: ACTIVE_CYAN },
  { v: 'account', label: 'Ngân hàng', icon: 'bi-bank', active: ACTIVE_CYAN },
  { v: 'email', label: 'Email', icon: 'bi-envelope-fill', active: ACTIVE_CYAN },
  { v: 'message', label: 'Tin nhắn', icon: 'bi-chat-dots-fill', active: ACTIVE_CYAN },
  { v: 'file', label: '📁 File / APK', icon: 'bi-file-earmark-binary', active: 'bg-danger-500 text-white shadow-lg shadow-danger-500/20 font-black' },
  { v: 'social', label: '🌐 MXH / Telegram', icon: 'bi-telegram', active: 'bg-brand2-500 text-white shadow-lg shadow-brand2-500/20 font-black' },
  { v: 'crypto', label: '🪙 Ví Crypto', icon: 'bi-coin', active: 'bg-warn-500 text-black shadow-lg shadow-warn-500/20 font-black' },
  { v: 'audio', label: '🎙️ Audio / Call', icon: 'bi-mic-fill', active: 'bg-brand-500 text-white shadow-lg shadow-brand-500/20 font-black' },
  { v: 'qr', label: 'QR Code', icon: 'bi-qr-code', active: ACTIVE_CYAN },
];

/* Icon bên trái ô nhập (chỉ 5 loại đầu có icon theo template gốc). */
const TARGET_INPUT_ICONS: Partial<Record<TargetType, string>> = {
  phone: 'bi-telephone',
  domain: 'bi-globe',
  account: 'bi-credit-card',
  email: 'bi-envelope',
  message: 'bi-chat-left-text',
};

interface ScamDef {
  v: string;
  label: string;
  icon: string;
  iconColor: string;
  active: string;
}

const SCAM_TYPES: ScamDef[] = [
  { v: 'police_impersonation', label: 'Giả danh Công an / Viện kiểm sát', icon: 'bi-shield-slash', iconColor: 'text-danger-400', active: 'bg-danger-500/20 border-danger-500 text-white font-black' },
  { v: 'bank_impersonation', label: 'Giả mạo Ngân hàng / Khóa thẻ', icon: 'bi-bank2', iconColor: 'text-warn-400', active: 'bg-warn-500/20 border-warn-500 text-white font-black' },
  { v: 'recruitment_scam', label: 'Lừa tuyển dụng / Việc làm online', icon: 'bi-briefcase', iconColor: 'text-brand-400', active: 'bg-brand-500/20 border-brand-500 text-white font-black' },
  { v: 'investment_scam', label: 'Lừa đầu tư tài chính / Tiền ảo', icon: 'bi-graph-up-arrow', iconColor: 'text-brand2-400', active: 'bg-brand2-500/20 border-brand2-500 text-white font-black' },
  { v: 'delivery_scam', label: 'Giả mạo Giao hàng / Nhận quà tặng', icon: 'bi-box-seam', iconColor: 'text-warn-400', active: 'bg-warn-500/20 border-warn-500 text-white font-black' },
  { v: 'loan_scam', label: 'Lừa vay tiền nhanh qua App / Giải ngân', icon: 'bi-cash-stack', iconColor: 'text-safe-400', active: 'bg-safe-500/20 border-safe-500 text-white font-black' },
  { v: 'phishing', label: 'Đánh cắp tài khoản / Phishing Link', icon: 'bi-link-45deg', iconColor: 'text-brand-400', active: 'bg-brand-500/20 border-brand-500 text-white font-black' },
  { v: 'gov_impersonation', label: 'Giả mạo Thuế / Dịch vụ công / VNeID', icon: 'bi-building', iconColor: 'text-warn-400', active: 'bg-warn-500/20 border-warn-500 text-white font-black' },
  { v: 'deepfake', label: 'Deepfake âm thanh / Video AI mạo danh', icon: 'bi-person-video3', iconColor: 'text-brand-400', active: 'bg-brand-500/20 border-brand-500 text-white font-black' },
  { v: 'malware_app', label: 'Mã độc / App APK chiếm đoạt tài khoản', icon: 'bi-file-earmark-binary', iconColor: 'text-danger-400', active: 'bg-danger-500/20 border-danger-500 text-white font-black' },
  { v: 'crypto_scam', label: 'Lừa Crypto / Ví Web3 / Airdrop', icon: 'bi-coin', iconColor: 'text-warn-400', active: 'bg-warn-500/20 border-warn-500 text-white font-black' },
  { v: 'social_engineering', label: 'Hội nhóm Telegram / Zalo / Fanpage', icon: 'bi-telegram', iconColor: 'text-brand2-400', active: 'bg-brand2-500/20 border-brand2-500 text-white font-black' },
  { v: 'prize_scam', label: 'Trúng thưởng / Quà tri ân / Đơn ảo', icon: 'bi-gift', iconColor: 'text-brand2-400', active: 'bg-brand2-500/20 border-brand2-500 text-white font-black' },
  { v: 'emergency_scam', label: 'Báo nạn cấp cứu / Tống tiền người thân', icon: 'bi-telephone-x', iconColor: 'text-warn-400', active: 'bg-warn-500/20 border-warn-500 text-white font-black' },
  { v: 'romance_scam', label: 'Lừa tình cảm / Pig Butchering', icon: 'bi-heart-fill', iconColor: 'text-danger-400', active: 'bg-danger-500/20 border-danger-500 text-white font-black' },
  { v: 'otp_steal', label: 'Chiêu trò OTP / 2FA', icon: 'bi-key', iconColor: 'text-brand-400', active: 'bg-brand-500/20 border-brand-500 text-white font-black' },
  { v: 'other', label: 'Hình thức lừa đảo khác', icon: 'bi-three-dots', iconColor: 'text-white/60', active: 'bg-white/20 border-white/40 text-white font-black' },
];

interface TmplDef {
  tag: string;
  label: string;
  icon: string;
  iconColor: string;
  hover: string;
  text: string;
}

const TEMPLATES: TmplDef[] = [
  { tag: 'time_channel', label: '+ Kênh & Thời gian', icon: 'bi-clock-history', iconColor: 'text-brand-400', hover: 'hover:text-brand-400 hover:border-brand-500/30', text: '• Thời gian xảy ra: \n• Kênh tiếp cận: (Zalo / Telegram / Cuộc gọi trực tiếp)' },
  { tag: 'scenario', label: '+ Thủ đoạn tiếp cận', icon: 'bi-chat-square-text', iconColor: 'text-warn-400', hover: 'hover:text-brand-400 hover:border-brand-500/30', text: '• Thủ đoạn: (Giả danh cán bộ công an / Giả mạo ngân hàng báo khóa thẻ / Dụ dỗ đầu tư)' },
  { tag: 'loss', label: '+ Số tiền thiệt hại', icon: 'bi-cash', iconColor: 'text-danger-400', hover: 'hover:text-brand-400 hover:border-brand-500/30', text: '• Số tiền thiệt hại: ... VNĐ' },
  { tag: 'request', label: '+ Yêu cầu của đối tượng', icon: 'bi-exclamation-triangle', iconColor: 'text-warn-400', hover: 'hover:text-brand-400 hover:border-brand-500/30', text: '• Yêu cầu của kẻ gian: (Yêu cầu chuyển tiền / Yêu cầu đọc mã OTP / Cài đặt app độc hại)' },
  { tag: 'vneid_apk', label: '+ VNeID / APK giả mạo', icon: 'bi-phone-fill', iconColor: 'text-danger-400', hover: 'hover:text-danger-400 hover:border-danger-500/30', text: '• Thủ đoạn: Giả mạo VNeID / Dịch vụ công, dụ cài app APK chiếm đoạt tiền\n• Link/app: \n• Số tiền thiệt hại: ... VNĐ' },
  { tag: 'deepfake_call', label: '+ Deepfake người thân', icon: 'bi-person-video3', iconColor: 'text-brand-400', hover: 'hover:text-brand-400 hover:border-brand-500/30', text: '• Thủ đoạn: Deepfake giả giọng người thân gọi video kêu cấp cứu, chuyển tiền gấp\n• Số gọi đến: \n• Số tiền yêu cầu: ... VNĐ' },
  { tag: 'telegram_task', label: '+ Nhóm Telegram đơn hàng', icon: 'bi-telegram', iconColor: 'text-brand2-400', hover: 'hover:text-brand2-400 hover:border-brand2-500/30', text: '• Thủ đoạn: Nhóm Telegram làm nhiệm vụ đơn hàng, hoàn tiền + thưởng\n• Link nhóm Telegram: \n• Số tiền đã nạp: ... VNĐ' },
  { tag: 'romance_crypto', label: '+ Tình cảm + Crypto', icon: 'bi-coin', iconColor: 'text-warn-400', hover: 'hover:text-warn-400 hover:border-warn-500/30', text: '• Thủ đoạn: Lừa tình cảm kết hợp dụ đầu tư tiền điện tử / sàn ảo\n• Nickname / kênh liên lạc: \n• Ví crypto nhận tiền: ' },
];

const POPULAR_BANKS: { shortName: string; name: string }[] = [
  { shortName: 'Vietcombank', name: 'Ngoại thương VN' },
  { shortName: 'Techcombank', name: 'Kỹ thương VN' },
  { shortName: 'MBBank', name: 'Quân đội' },
  { shortName: 'BIDV', name: 'Đầu tư và Phát triển' },
  { shortName: 'VietinBank', name: 'Công thương VN' },
  { shortName: 'ACB', name: 'Á Châu' },
  { shortName: 'VPBank', name: 'Việt Nam Thịnh Vượng' },
  { shortName: 'TPBank', name: 'Tiên Phong' },
];

const SEVERITIES: { v: string; label: string; active: string }[] = [
  { v: 'low', label: 'Thấp', active: 'bg-safe-500 text-black border-safe-400 shadow-md shadow-safe-500/20' },
  { v: 'medium', label: 'Vừa', active: 'bg-warn-500 text-black border-warn-400 shadow-md shadow-warn-500/20' },
  { v: 'high', label: 'Cao', active: 'bg-warn-500 text-black border-warn-400 shadow-md shadow-warn-500/20' },
  { v: 'critical', label: 'Khẩn cấp', active: 'bg-danger-600 text-white border-danger-500 shadow-md shadow-danger-600/30' },
];

const FIELD_LABELS: Record<string, string> = {
  target_type: 'Loại đối tượng',
  target_value: 'Thông tin đối tượng',
  scam_type: 'Phương thức lừa đảo',
  description: 'Nội dung mô tả',
  severity: 'Mức độ nghiêm trọng',
  scammer_phone: 'Số điện thoại kẻ gian',
  scammer_bank_account: 'Số tài khoản kẻ gian',
};

interface Bank {
  name?: string;
  code?: string;
  shortName?: string;
  logo?: string;
}

interface CustomPair {
  key: string;
  value: string;
}

/* ============ Helpers chuẩn hóa (port getters Alpine) ============ */

function normalizeTarget(raw: string, type: TargetType): string {
  const v = (raw || '').trim();
  if (!v) return '';

  if (type === 'phone') {
    const cleaned = v.replace(/[^\d+]/g, '');
    if (cleaned.startsWith('+')) return cleaned;
    const digits = cleaned.replace(/\D/g, '');
    if (digits.startsWith('84')) return '+' + digits;
    if (digits.startsWith('0')) return '+84' + digits.slice(1);
    return digits ? '+84' + digits : '';
  }

  if (type === 'domain') {
    let u = v.toLowerCase().replace(/\s+/g, '');
    if (!u.includes('://')) u = 'https://' + u;
    try {
      const parsed = new URL(u);
      let host = parsed.hostname || parsed.pathname.split('/')[0];
      if (host.startsWith('www.')) host = host.slice(4);
      return host.split(':')[0];
    } catch {
      return v.replace(/https?:\/\//i, '').replace(/www\./i, '').split('/')[0].split('?')[0];
    }
  }

  if (type === 'account') return v.replace(/[\s\-._]/g, '').toUpperCase();
  if (type === 'email') return v.toLowerCase().replace(/\s+/g, '');
  if (type === 'crypto') return v.replace(/\s+/g, '');
  return v;
}

function validationStatus(raw: string, type: TargetType): { valid: boolean; message: string } {
  const val = (raw || '').trim();
  if (!val) return { valid: false, message: 'Vui lòng nhập thông tin' };
  const norm = normalizeTarget(val, type);

  if (type === 'phone') {
    const digits = norm.replace(/\D/g, '');
    if (digits.length >= 9 && digits.length <= 13) return { valid: true, message: `Chuẩn hóa E.164: ${norm}` };
    return { valid: false, message: `Số điện thoại chưa đủ độ dài (${digits.length}/10 số)` };
  }
  if (type === 'domain') {
    if (norm.length >= 4 && norm.includes('.')) return { valid: true, message: `Tên miền chuẩn: ${norm}` };
    return { valid: false, message: 'Tên miền chưa hợp lệ (VD: scam-site.com)' };
  }
  if (type === 'account') {
    if (norm.length >= 4) return { valid: true, message: `STK chuẩn hóa: ${norm}` };
    return { valid: false, message: 'Số tài khoản tối thiểu 4 chữ số' };
  }
  if (type === 'email') {
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (emailRegex.test(norm)) return { valid: true, message: `Email chuẩn hóa: ${norm}` };
    return { valid: false, message: 'Định dạng email chưa đúng (VD: name@domain.com)' };
  }
  if (type === 'file') {
    if (val.length >= 2) return { valid: true, message: `Tệp tin: ${val.slice(0, 60)}` };
    return { valid: false, message: 'Nhập tên file hoặc mã băm SHA256' };
  }
  if (type === 'social') {
    if (val.length >= 2) return { valid: true, message: `Kênh MXH: ${val.slice(0, 60)}` };
    return { valid: false, message: 'Nhập username / link Telegram, Zalo, FB' };
  }
  if (type === 'crypto') {
    if (norm.length >= 10) return { valid: true, message: `Ví crypto: ${norm.slice(0, 24)}...` };
    return { valid: false, message: 'Địa chỉ ví chưa hợp lệ (tối thiểu 10 ký tự)' };
  }
  if (type === 'audio') {
    if (val.length >= 2) return { valid: true, message: 'Đã sẵn sàng (audio / deepfake)' };
    return { valid: false, message: 'Mô tả cuộc gọi / file audio nghi ngờ' };
  }
  return { valid: true, message: 'Đã sẵn sàng' };
}

function autoDetectTarget(raw: string): TargetType | null {
  const text = (raw || '').trim();
  if (!text) return null;
  if (/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(text) || (text.includes('@') && text.includes('.'))) {
    return 'email';
  }
  if (/^(https?:\/\/|www\.)/i.test(text) || /\.(com|vn|net|org|xyz|io|top|club|vip|online|info|cc|biz|site|me|co)(\/|$|\?)/i.test(text)) {
    return 'domain';
  }
  const digits = text.replace(/[^\d+]/g, '');
  if (/^(\+?84|0)[3|5|7|8|9][0-9]{7,9}$/.test(digits) || /^0[1-9][0-9]{7,9}$/.test(digits)) {
    return 'phone';
  }
  return null;
}

function placeholderFor(t: TargetType): string {
  switch (t) {
    case 'phone': return 'Nhập số điện thoại (VD: 0912345678 hoặc +84...)';
    case 'domain': return 'Nhập đường dẫn website (VD: https://bank-phish.com/login)';
    case 'account': return 'Nhập số tài khoản ngân hàng...';
    case 'email': return 'Nhập địa chỉ email giả mạo (VD: support@scam.vn)';
    case 'file': return 'Nhập tên file / mã băm SHA256 (VD: vneid.apk)';
    case 'social': return 'Nhập link Telegram / nhóm Zalo / username FB...';
    case 'crypto': return 'Nhập địa chỉ ví crypto (VD: 0x...)';
    case 'audio': return 'Mô tả cuộc gọi / file audio nghi ngờ...';
    default: return 'Nhập số điện thoại gửi tin nhắn, link hoặc thông tin đối tượng...';
  }
}

/* ============ Sidebar guide (port _scan_guide.html với scan_type='report') ============ */

function ReportGuide() {
  const [guideOpen, setGuideOpen] = useState(true);

  useEffect(() => {
    // oxlint-disable-next-line react/set-state-in-effect -- mở/đóng guide theo bề rộng màn hình như bản Alpine
    setGuideOpen(window.innerWidth >= 1024);
  }, []);

  return (
    <aside className="lg:sticky lg:top-24 h-fit">
      <button
        type="button"
        onClick={() => setGuideOpen(!guideOpen)}
        className="lg:hidden w-full flex items-center justify-between liquid-card p-4 mb-4 text-left group"
      >
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-brand-500/10 flex items-center justify-center text-brand-400">
            <i className="bi bi-question-circle text-xl"></i>
          </div>
          <span className="text-white font-bold">Hướng dẫn sử dụng</span>
        </div>
        <i className={`bi text-white/55 transition-transform ${guideOpen ? 'bi-chevron-up' : 'bi-chevron-down'}`}></i>
      </button>

      {guideOpen && (
        <div className="liquid-card p-6 space-y-5 border border-brand-500/10">
          <div className="flex items-center gap-3 pb-4 border-b border-white/5">
            <div className="w-10 h-10 rounded-xl bg-brand-500/10 flex items-center justify-center text-brand-400 shrink-0">
              <i className="bi bi-book text-lg"></i>
            </div>
            <div>
              <h3 className="text-white font-bold text-sm">Hướng dẫn sử dụng</h3>
              <p className="text-white/45 text-xs">Dành cho mọi người</p>
            </div>
          </div>

          <div className="space-y-3">
            <div className="flex gap-3">
              <div className="w-7 h-7 rounded-lg bg-danger-500/20 text-danger-400 flex items-center justify-center text-xs font-black shrink-0">1</div>
              <p className="text-white/70 text-sm leading-relaxed">Chọn <strong className="text-white">loại đối tượng</strong>: Số điện thoại, website, email, tài khoản ngân hàng, tin nhắn hoặc QR.</p>
            </div>
            <div className="flex gap-3">
              <div className="w-7 h-7 rounded-lg bg-danger-500/20 text-danger-400 flex items-center justify-center text-xs font-black shrink-0">2</div>
              <p className="text-white/70 text-sm leading-relaxed">Điền <strong className="text-white">thông tin chi tiết</strong>: Họ tên đối tượng, số tài khoản, ngân hàng (nếu có).</p>
            </div>
            <div className="flex gap-3">
              <div className="w-7 h-7 rounded-lg bg-danger-500/20 text-danger-400 flex items-center justify-center text-xs font-black shrink-0">3</div>
              <p className="text-white/70 text-sm leading-relaxed">Mô tả <strong className="text-white">chi tiết vụ việc</strong> và tải ảnh bằng chứng lên. Dùng AI quét chữ để tự động trích xuất.</p>
            </div>
            <div className="flex gap-3">
              <div className="w-7 h-7 rounded-lg bg-danger-500/20 text-danger-400 flex items-center justify-center text-xs font-black shrink-0">4</div>
              <p className="text-white/70 text-sm leading-relaxed">Nhấn <strong className="text-danger-400">GỬI BÁO CÁO</strong>; đội ngũ kiểm duyệt sẽ xử lý trong 24h.</p>
            </div>
          </div>

          <div className="border-t border-white/5"></div>

          <div>
            <h4 className="text-white font-bold text-xs uppercase tracking-wider mb-3 flex items-center gap-2">
              <i className="bi bi-palette text-white/55"></i>
              Hiểu kết quả
            </h4>
            <div className="space-y-2">
              <div className="flex items-center gap-3 p-2.5 rounded-lg bg-danger-500/5 border border-danger-500/10">
                <div className="w-3 h-3 rounded-full bg-danger-500 shrink-0"></div>
                <div>
                  <span className="text-danger-400 text-xs font-bold">ĐỎ: Nguy hiểm</span>
                  <p className="text-white/55 text-[11px]">Có dấu hiệu lừa đảo rõ ràng</p>
                </div>
              </div>
              <div className="flex items-center gap-3 p-2.5 rounded-lg bg-warn-500/5 border border-warn-500/10">
                <div className="w-3 h-3 rounded-full bg-warn-500 shrink-0"></div>
                <div>
                  <span className="text-warn-400 text-xs font-bold">VÀNG: Cẩn thận</span>
                  <p className="text-white/55 text-[11px]">Có dấu hiệu đáng ngờ, cần cảnh giác</p>
                </div>
              </div>
              <div className="flex items-center gap-3 p-2.5 rounded-lg bg-safe-500/5 border border-safe-500/10">
                <div className="w-3 h-3 rounded-full bg-safe-500 shrink-0"></div>
                <div>
                  <span className="text-safe-400 text-xs font-bold">XANH: An toàn</span>
                  <p className="text-white/55 text-[11px]">Không phát hiện dấu hiệu lừa đảo</p>
                </div>
              </div>
            </div>
          </div>

          <div className="border-t border-white/5"></div>

          <div>
            <h4 className="text-white font-bold text-xs uppercase tracking-wider mb-3 flex items-center gap-2">
              <i className="bi bi-lightbulb text-white/55"></i>
              Mẹo hay
            </h4>
            <ul className="space-y-2 text-white/60 text-xs leading-relaxed">
              <li className="flex gap-2"><i className="bi bi-check-circle text-danger-500/60 shrink-0 mt-0.5"></i>Thông tin càng chi tiết và có bằng chứng càng giúp cộng đồng nhiều.</li>
              <li className="flex gap-2"><i className="bi bi-check-circle text-danger-500/60 shrink-0 mt-0.5"></i>Tải ảnh bằng chứng (tin nhắn, chuyển khoản) và dùng AI quét chữ tự động.</li>
              <li className="flex gap-2"><i className="bi bi-check-circle text-danger-500/60 shrink-0 mt-0.5"></i>Nếu bị lừa tiền, hãy gọi 113 và báo ngân hàng đóng băng tài khoản ngay.</li>
            </ul>
          </div>

          <div className="pt-3 border-t border-white/5">
            <Link href="/scan/" className="flex items-center gap-2 text-xs text-brand-400/70 hover:text-brand-400 transition-colors">
              <i className="bi bi-shield-check"></i>
              <span>Muốn kiểm tra trước? <strong>Quét ngay tại đây</strong></span>
            </Link>
          </div>
        </div>
      )}
    </aside>
  );
}

/* ============ Trang báo cáo ============ */

export default function Report() {
  const [targetType, setTargetType] = useState<TargetType>('phone');
  const [targetValue, setTargetValue] = useState('');
  const [scamType, setScamType] = useState('');
  const [scamTypeOther, setScamTypeOther] = useState('');
  const [severity, setSeverity] = useState('medium');
  const [description, setDescription] = useState('');
  const [images, setImages] = useState<File[]>([]);
  const [dragOver, setDragOver] = useState(false);
  const [scammerName, setScammerName] = useState('');
  const [scammerPhone, setScammerPhone] = useState('');
  const [scammerBankAccount, setScammerBankAccount] = useState('');
  const [scammerBankName, setScammerBankName] = useState('');
  const [scammerSocial, setScammerSocial] = useState('');
  const [lossAmount, setLossAmount] = useState('');
  const [impersonatedOrg, setImpersonatedOrg] = useState('');
  const [cryptoWallet, setCryptoWallet] = useState('');
  const [fileHash, setFileHash] = useState('');
  const [customPairs, setCustomPairs] = useState<CustomPair[]>([]);
  const [newCustomKey, setNewCustomKey] = useState('');
  const [newCustomValue, setNewCustomValue] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [banks, setBanks] = useState<Bank[]>([]);
  const [bankSearch, setBankSearch] = useState('');
  const [showBankDropdown, setShowBankDropdown] = useState(false);
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [createdId, setCreatedId] = useState<number | null>(null);
  const [error, setError] = useState('');

  const descRef = useRef<HTMLTextAreaElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const imagesRef = useRef<File[]>([]);

  const validation = validationStatus(targetValue, targetType);

  useEffect(() => {
    imagesRef.current = images;
  }, [images]);

  /* URL params + fetch banks + paste listener (Alpine init). */
  useEffect(() => {
    const q = new URLSearchParams(window.location.search);
    const tv = q.get('target_value') || q.get('phone') || q.get('bank_account') || q.get('file') || q.get('q') || q.get('url') || q.get('email') || '';
    const tt = q.get('target_type') as TargetType | null;
    const st = q.get('scam_type') || '';

    setTargetValue(tv);
    setScamType(st);
    setScammerPhone(q.get('phone') || '');
    setScammerBankAccount(q.get('bank_account') || '');
    setScammerBankName(q.get('bank_name') || '');
    setScammerName(q.get('scammer_name') || '');
    setScammerSocial(q.get('scammer_social') || '');

    if (tt) setTargetType(tt);
    else if (tv) {
      const detected = autoDetectTarget(tv);
      if (detected) setTargetType(detected);
    }

    api
      .get<unknown>('/scan/banks/')
      .then((data) => {
        if (Array.isArray(data)) setBanks(data as Bank[]);
        else if (data && typeof data === 'object') {
          const rec = data as { banks?: unknown; data?: unknown };
          const list = rec.banks || rec.data;
          setBanks(Array.isArray(list) ? (list as Bank[]) : []);
        } else setBanks([]);
      })
      .catch(() => setBanks([]));

    const onPaste = (e: ClipboardEvent) => {
      if (!e.clipboardData || !e.clipboardData.items) return;
      const items = e.clipboardData.items;
      for (let i = 0; i < items.length; i++) {
        if (items[i].type.indexOf('image') !== -1) {
          const file = items[i].getAsFile();
          if (file) {
            addImageFile(file);
            showToast('Đã dán ảnh bằng chứng từ clipboard', 'success');
          }
        }
      }
    };
    window.addEventListener('paste', onPaste);
    return () => window.removeEventListener('paste', onPaste);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /* Đồng bộ trường phụ khi target_type === phone/account (Alpine $watch). */
  const syncAux = (type: TargetType, raw: string): void => {
    const norm = normalizeTarget(raw, type);
    if (type === 'phone') setScammerPhone(norm || raw);
    else if (type === 'account') setScammerBankAccount(norm || raw);
  };

  const onTargetInput = (raw: string): void => {
    setTargetValue(raw);
    let type = targetType;
    const detected = autoDetectTarget(raw.trim());
    if (detected && detected !== targetType) {
      type = detected;
      setTargetType(detected);
    }
    syncAux(type, raw);
  };

  const pickTarget = (t: TargetType): void => {
    setTargetType(t);
    syncAux(t, targetValue);
  };

  const selectBank = (shortName: string): void => {
    setScammerBankName(shortName);
    setShowBankDropdown(false);
    setBankSearch('');
  };

  const filteredBanks = (): Bank[] => {
    if (!bankSearch.trim()) return banks.slice(0, 15);
    const q = bankSearch.toLowerCase().trim();
    return banks
      .filter(
        (b) =>
          (b.shortName && b.shortName.toLowerCase().includes(q)) ||
          (b.name && b.name.toLowerCase().includes(q)) ||
          (b.code && b.code.toLowerCase().includes(q)),
      )
      .slice(0, 20);
  };

  const autoResize = (): void => {
    const el = descRef.current;
    if (el) {
      el.style.height = 'auto';
      el.style.height = Math.max(140, el.scrollHeight) + 'px';
    }
  };

  const insertTemplate = (tag: string): void => {
    const snippet = TEMPLATES.find((t) => t.tag === tag);
    const insertText = snippet ? snippet.text : tag;
    const textarea = descRef.current;
    if (!textarea) {
      setDescription((d) => d + (d ? '\n' : '') + insertText);
      return;
    }
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const before = description.substring(0, start);
    const after = description.substring(end);
    const prefix = before && !before.endsWith('\n') ? '\n' : '';
    setDescription(before + prefix + insertText + '\n' + after);

    requestAnimationFrame(() => {
      const el = descRef.current;
      if (!el) return;
      el.focus();
      const newPos = (before + prefix + insertText).length + 1;
      el.setSelectionRange(newPos, newPos);
      autoResize();
    });
  };

  const addImageFile = (file: File): void => {
    if (!file || !file.type.startsWith('image/')) {
      showToast('Chỉ chấp nhận tệp hình ảnh (JPG, PNG, WEBP)', 'warning');
      return;
    }
    if (file.size > 8 * 1024 * 1024) {
      showToast('Kích thước ảnh không được vượt quá 8MB', 'warning');
      return;
    }
    if (imagesRef.current.length >= 5) {
      showToast('Đã đạt giới hạn tối đa 5 ảnh bằng chứng', 'warning');
      return;
    }
    setImages((prev) => {
      const next = [...prev, file];
      imagesRef.current = next;
      return next;
    });
  };

  const handleFileDrop = (e: DragEvent<HTMLDivElement>): void => {
    e.preventDefault();
    setDragOver(false);
    const files = e.dataTransfer.files;
    if (!files || files.length === 0) return;
    for (let i = 0; i < files.length; i++) addImageFile(files[i]);
  };

  const handleFileInput = (e: ChangeEvent<HTMLInputElement>): void => {
    const files = e.target.files;
    if (!files || files.length === 0) return;
    for (let i = 0; i < files.length; i++) addImageFile(files[i]);
    e.target.value = '';
  };

  const removeImage = (index: number): void => {
    setImages((prev) => prev.filter((_, i) => i !== index));
  };

  const addCustomPair = (): void => {
    const k = newCustomKey.trim();
    const v = newCustomValue.trim();
    if (!k || !v) return;
    setCustomPairs((prev) => [...prev, { key: k, value: v }]);
    setNewCustomKey('');
    setNewCustomValue('');
  };

  const removeCustomPair = (index: number): void => {
    setCustomPairs((prev) => prev.filter((_, i) => i !== index));
  };

  const executeSubmit = async (): Promise<void> => {
    setError('');
    setLoading(true);
    const tsToken = getTsToken();
    const siteKey = (process.env.NEXT_PUBLIC_TURNSTILE_SITEKEY as string | undefined) || '';

    /* Không có sitekey thì widget không render, backend chắc chắn từ chối —
     * báo rõ nguyên nhân thay vì để người dùng thử mãi không được. */
    if (!siteKey) {
      const msg = 'Chưa cấu hình xác minh anti-spam (NEXT_PUBLIC_TURNSTILE_SITEKEY). Liên hệ quản trị viên.';
      setError(msg);
      setLoading(false);
      showToast(msg, 'error');
      return;
    }
    if (!tsToken) {
      const msg = 'Vui lòng hoàn thành xác minh bảo mật (Anti-Spam)';
      setError(msg);
      setLoading(false);
      showToast(msg, 'warning');
      return;
    }

    let finalDesc = description.trim();
    if (scamType === 'other' && scamTypeOther.trim()) {
      finalDesc = `[Phương thức cụ thể: ${scamTypeOther.trim()}]\n` + finalDesc;
    }

    const fd = new FormData();
    fd.append('target_type', targetType);
    fd.append('target_value', targetValue.trim());
    fd.append('scam_type', scamType);
    fd.append('severity', severity);
    fd.append('description', finalDesc);
    if (tsToken) fd.append('cf-turnstile-response', tsToken);

    if (targetType === 'phone') {
      fd.append('scammer_phone', normalizeTarget(targetValue, 'phone') || targetValue.trim());
    } else if (scammerPhone.trim()) {
      fd.append('scammer_phone', scammerPhone.trim());
    }

    if (targetType === 'account') {
      fd.append('scammer_bank_account', normalizeTarget(targetValue, 'account') || targetValue.trim());
    } else if (scammerBankAccount.trim()) {
      fd.append('scammer_bank_account', scammerBankAccount.trim());
    }

    if (scammerBankName.trim()) fd.append('scammer_bank_name', scammerBankName.trim());
    if (scammerName.trim()) fd.append('scammer_name', scammerName.trim());
    if (scammerSocial.trim()) fd.append('scammer_social', scammerSocial.trim());

    const custom: Record<string, string> = {};
    if (lossAmount.trim()) custom.loss_amount_vnd = lossAmount.trim();
    if (impersonatedOrg.trim()) custom.impersonated_org = impersonatedOrg.trim();
    if (cryptoWallet.trim()) custom.crypto_wallet = cryptoWallet.trim();
    if (fileHash.trim()) custom.file_hash = fileHash.trim();
    for (const p of customPairs) {
      if (p.key && p.value) custom[p.key] = p.value;
    }
    if (Object.keys(custom).length) fd.append('custom_fields', JSON.stringify(custom));

    if (images.length > 0) {
      fd.append('evidence_file', images[0]);
      for (let i = 1; i < images.length; i++) fd.append('evidence_images', images[i]);
    }

    try {
      const res = await api.upload<{ report_id?: number; id?: number; report?: { id?: number } }>('/report/', fd);
      setSuccess(true);
      setCreatedId(res.report_id || res.id || res.report?.id || null);
      showToast('Báo cáo đã được gửi thành công', 'success');
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        const data = err.data as { field_errors?: Record<string, string[] | string>; error?: string } | null;
        if (data && data.field_errors) {
          const parts: string[] = [];
          for (const [field, msgs] of Object.entries(data.field_errors)) {
            const label = FIELD_LABELS[field] || field;
            parts.push(`${label}: ${Array.isArray(msgs) ? msgs.join(', ') : msgs}`);
          }
          setError(parts.join(' | '));
          void showAlert('Dữ liệu chưa hợp lệ', parts.join('\n'), 'warning');
        } else {
          const msg = (data && data.error) || 'Gửi báo cáo thất bại';
          setError(msg);
          showToast(msg, 'error');
        }
      } else {
        const msg = 'Lỗi kết nối máy chủ. Vui lòng thử lại sau.';
        setError(msg);
        showToast(msg, 'error');
      }
    } finally {
      setLoading(false);
      try {
        resetTurnstile();
      } catch {
        /* ignore */
      }
    }
  };

  const submitReport = (): void => {
    if (!targetType) {
      showToast('Vui lòng chọn loại đối tượng', 'warning');
      return;
    }
    if (!targetValue.trim()) {
      showToast('Vui lòng nhập thông tin đối tượng', 'warning');
      return;
    }
    if (!validationStatus(targetValue, targetType).valid) {
      showToast(validationStatus(targetValue, targetType).message, 'warning');
      return;
    }
    if (!scamType) {
      showToast('Vui lòng chọn phương thức lừa đảo', 'warning');
      return;
    }
    if (scamType === 'other' && !scamTypeOther.trim()) {
      showToast('Vui lòng ghi rõ hình thức lừa đảo cụ thể', 'warning');
      return;
    }
    if (!description.trim() || description.trim().length < 10) {
      showToast('Nội dung mô tả tối thiểu 10 ký tự', 'warning');
      return;
    }
    void executeSubmit();
  };

  const resetForm = (): void => {
    setSuccess(false);
    setCreatedId(null);
    setTargetType('phone');
    setTargetValue('');
    setScamType('');
    setScamTypeOther('');
    setSeverity('medium');
    setDescription('');
    setImages([]);
    setScammerName('');
    setScammerPhone('');
    setScammerBankAccount('');
    setScammerBankName('');
    setScammerSocial('');
    setLossAmount('');
    setImpersonatedOrg('');
    setCryptoWallet('');
    setFileHash('');
    setCustomPairs([]);
    setNewCustomKey('');
    setNewCustomValue('');
    setShowAdvanced(false);
    setError('');
  };

  const inputIcon = TARGET_INPUT_ICONS[targetType];

  return (
    <div className="max-w-7xl mx-auto px-4 pt-16 sm:pt-20 pb-20 lg:grid lg:grid-cols-[1fr_340px] lg:gap-8 lg:items-start">
      <div className="animate-fadein max-w-3xl mx-auto space-y-8 w-full">
        {/* Header Section */}
        <div className="text-center space-y-3">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-danger-500/10 text-danger-500 mb-5 border border-danger-500/20 shadow-lg shadow-danger-500/10">
            <i className="bi bi-shield-fill-exclamation text-3xl"></i>
          </div>
          <h1 className="text-3xl sm:text-4xl font-black text-white tracking-tight">
            Gửi Báo Cáo <span className="glow-text text-danger-500">Đối Tượng Lừa Đảo</span>
          </h1>
          <p className="text-white/60 max-w-lg mx-auto text-xs sm:text-sm leading-relaxed">
            Hệ thống tự động chuẩn hóa dữ liệu viễn thông, tên miền và số tài khoản ngân hàng để cảnh báo tức thời cho cộng đồng.
          </p>
        </div>

        {/* Success State Card */}
        {success && (
          <div className="liquid-card p-10 text-center space-y-6 bg-safe-500/[0.03] border border-safe-500/20">
            <div className="w-20 h-20 bg-safe-500/20 rounded-full flex items-center justify-center mx-auto ring-8 ring-safe-500/5 shadow-2xl shadow-safe-500/20">
              <i className="bi bi-check-lg text-safe-400 text-4xl font-bold"></i>
            </div>
            <div className="space-y-2">
              <h2 className="text-2xl font-black text-white">Báo cáo đã được tiếp nhận</h2>
              {createdId && <p className="text-xs font-mono text-brand-400 font-bold tracking-wider">Mã hồ sơ: #{createdId}</p>}
              <p className="text-white/60 text-xs sm:text-sm max-w-md mx-auto leading-relaxed">
                Dữ liệu đã được chuyển sang hàng đợi phân tích AI và đối soát danh sách đen. Cảm ơn bạn đã bảo vệ cộng đồng an toàn mạng.
              </p>
            </div>
            <div className="pt-4 flex flex-wrap justify-center gap-4">
              <button className="liquid-btn bg-white/10 text-white py-3 px-8 text-xs font-black tracking-wider hover:bg-white/15" onClick={resetForm}>
                <i className="bi bi-plus-circle mr-2"></i> GỬI BÁO CÁO MỚI
              </button>
              <Link href="/admin-cp/reports/" className="liquid-btn bg-brand-500/10 text-brand-400 border-brand-500/20 py-3 px-8 text-xs font-black tracking-wider hover:bg-brand-500/20">
                <i className="bi bi-clock-history mr-2"></i> THEO DÕI HỒ SƠ
              </Link>
            </div>
          </div>
        )}

        {/* Main Form Card */}
        {!success && (
          <div className="liquid-card p-6 sm:p-10 space-y-8">
            {/* STEP 1: TARGET SELECTION & SMART INPUT */}
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-black text-brand-400 uppercase tracking-widest flex items-center gap-2">
                  <span className="w-5 h-5 rounded-full bg-brand-500/20 text-brand-400 flex items-center justify-center text-[10px]">1</span>
                  Mục tiêu nghi vấn
                </span>
                <span className="text-[10px] text-white/55 font-medium italic">Tự động nhận diện định dạng</span>
              </div>

              {/* Target Type Selector Pills */}
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 p-1.5 bg-black/40 rounded-2xl border border-white/5">
                {TARGETS.map((t) => (
                  <button
                    key={t.v}
                    type="button"
                    onClick={() => pickTarget(t.v)}
                    className={`py-2.5 px-3 rounded-xl text-xs font-bold transition-all flex items-center justify-center gap-2 ${
                      targetType === t.v ? t.active : 'text-white/60 hover:text-white hover:bg-white/5'
                    }`}
                  >
                    <i className={`bi ${t.icon} text-xs`}></i>
                    <span>{t.label}</span>
                  </button>
                ))}
              </div>

              {/* Value Input + Bank Selection if Account */}
              <div className="space-y-3">
                <div className="relative">
                  {inputIcon && (
                    <div className="absolute left-4 top-1/2 -translate-y-1/2 text-white/55 pointer-events-none flex items-center justify-center w-5 h-5 z-10">
                      <i className={`bi ${inputIcon} text-base`}></i>
                    </div>
                  )}
                  <input
                    type="text"
                    className="liquid-input has-icon-left w-full py-4 pl-12 pr-4 text-sm font-bold placeholder:text-white/45"
                    value={targetValue}
                    onChange={(e) => onTargetInput(e.target.value)}
                    placeholder={placeholderFor(targetType)}
                  />
                </div>

                {/* Real-Time Normalization Feedback Pill */}
                {targetValue.trim() && (
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    <div
                      className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-mono ${
                        validation.valid
                          ? 'bg-safe-500/10 border-safe-500/30 text-safe-400'
                          : 'bg-warn-500/10 border-warn-500/30 text-warn-400'
                      }`}
                    >
                      <i className={`bi ${validation.valid ? 'bi-check-circle-fill' : 'bi-info-circle-fill'}`}></i>
                      <span>{validation.message}</span>
                    </div>
                    <span className="text-[10px] text-white/45 font-medium">Hệ thống chuẩn hóa tự động trước khi lưu</span>
                  </div>
                )}

                {/* Bank Selection row when target_type is 'account' */}
                {targetType === 'account' && (
                  <div className="space-y-3 pt-2">
                    <div className="flex items-center justify-between">
                      <label className="text-[11px] font-black text-white/60 uppercase tracking-wider">Ngân hàng phát hành thẻ/tài khoản</label>
                      <span className="text-[10px] text-brand-400 font-bold">
                        {scammerBankName ? 'Đã chọn: ' + scammerBankName : 'Chọn nhanh hoặc tìm kiếm'}
                      </span>
                    </div>

                    {/* Quick Popular Bank Chips */}
                    <div className="flex flex-wrap gap-2">
                      {POPULAR_BANKS.map((pb) => (
                        <button
                          key={pb.shortName}
                          type="button"
                          onClick={() => selectBank(pb.shortName)}
                          className={`px-3 py-1.5 rounded-lg text-xs font-bold border transition-all ${
                            scammerBankName === pb.shortName
                              ? 'bg-brand-500/20 border-brand-500 text-brand-300 shadow-sm'
                              : 'bg-white/[0.03] border-white/10 text-white/60 hover:text-white hover:bg-white/5'
                          }`}
                        >
                          {pb.shortName}
                        </button>
                      ))}
                      <button
                        type="button"
                        onClick={() => setShowBankDropdown(!showBankDropdown)}
                        className="px-3 py-1.5 rounded-lg text-xs font-bold border border-brand-500/30 bg-brand-500/10 text-brand-400 hover:bg-brand-500/20 transition-all flex items-center gap-1"
                      >
                        <i className="bi bi-search text-[10px]"></i>
                        <span>Ngân hàng khác...</span>
                      </button>
                    </div>

                    {/* Searchable Bank Dropdown Panel */}
                    {showBankDropdown && (
                      <div className="p-4 rounded-2xl bg-black/60 border border-white/10 space-y-3">
                        <div className="flex items-center w-full px-4 py-2.5 rounded-xl bg-white/[0.04] border border-white/10 focus-within:border-brand-500/50 transition-all">
                          <i className="bi bi-search text-white/55 text-xs mr-3 shrink-0 pointer-events-none"></i>
                          <input
                            type="text"
                            value={bankSearch}
                            onChange={(e) => setBankSearch(e.target.value)}
                            placeholder="Tìm kiếm theo tên ngân hàng hoặc mã viết tắt..."
                            className="bg-transparent border-0 outline-none text-white text-xs w-full p-0 placeholder:text-white/45 font-medium focus:ring-0"
                          />
                        </div>
                        <div className="max-h-48 overflow-y-auto space-y-1 custom-scrollbar pr-1">
                          {filteredBanks().map((b) => (
                            <button
                              key={b.code || b.shortName}
                              type="button"
                              onClick={() => selectBank(b.shortName || b.name || '')}
                              className={`w-full text-left px-3 py-2 rounded-xl text-xs flex items-center justify-between hover:bg-white/10 transition-colors ${
                                scammerBankName === b.shortName ? 'bg-brand-500/20 text-brand-300 font-bold' : 'text-white/80'
                              }`}
                            >
                              <span className="truncate">{(b.shortName || '') + ' - ' + (b.name || '')}</span>
                              {b.logo && (
                                <img src={mediaUrl(b.logo)} alt="" className="w-5 h-5 object-contain bg-white/10 rounded p-0.5 ml-2 shrink-0" />
                              )}
                            </button>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>

            {/* STEP 2: SCAM METHOD & SEVERITY */}
            <div className="space-y-4 pt-4 border-t border-white/5">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-black text-brand-400 uppercase tracking-widest flex items-center gap-2">
                  <span className="w-5 h-5 rounded-full bg-brand-500/20 text-brand-400 flex items-center justify-center text-[10px]">2</span>
                  Phương thức & Mức độ
                </span>
              </div>

              {/* Scam Type Selector */}
              <div className="space-y-2">
                <label className="text-[11px] font-black text-white/60 uppercase tracking-wider">Phương thức lừa đảo</label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {SCAM_TYPES.map((s) => (
                    <button
                      key={s.v}
                      type="button"
                      onClick={() => setScamType(s.v)}
                      className={`p-3 rounded-xl text-xs font-bold border text-left transition-all flex items-center gap-3 ${
                        scamType === s.v ? s.active : 'bg-white/[0.02] border-white/5 text-white/60 hover:bg-white/5'
                      }`}
                    >
                      <i className={`bi ${s.icon} text-base ${s.iconColor}`}></i>
                      <span>{s.label}</span>
                    </button>
                  ))}
                </div>

                {/* Specific description if scam_type is 'other' */}
                {scamType === 'other' && (
                  <div className="p-4 rounded-2xl bg-white/[0.03] border border-brand-500/30 space-y-2 mt-3 shadow-lg shadow-brand-500/5">
                    <label className="text-[11px] font-black text-brand-400 uppercase tracking-wider flex items-center gap-2">
                      <i className="bi bi-pencil-square"></i>
                      <span>Mô tả cụ thể phương thức lừa đảo khác:</span>
                    </label>
                    <input
                      type="text"
                      value={scamTypeOther}
                      onChange={(e) => setScamTypeOther(e.target.value)}
                      placeholder="VD: Bắt cóc tống tiền online, Thôi miên qua điện thoại, Giả mạo trúng thưởng vé máy bay..."
                      className="liquid-input w-full py-3 px-4 text-xs font-bold text-white placeholder:text-white/45 border-brand-500/30 focus:border-brand-400"
                    />
                    <p className="text-[10px] text-white/55">Ghi rõ phương thức giúp hệ thống phân loại chính xác và cảnh báo sớm cho cộng đồng.</p>
                  </div>
                )}
              </div>

              {/* Severity Buttons */}
              <div className="space-y-2 pt-2">
                <label className="text-[11px] font-black text-white/60 uppercase tracking-wider">Mức độ nghiêm trọng</label>
                <div className="grid grid-cols-4 gap-2">
                  {SEVERITIES.map((s) => (
                    <button
                      key={s.v}
                      type="button"
                      onClick={() => setSeverity(s.v)}
                      className={`py-2.5 rounded-xl text-xs font-black tracking-wider uppercase border transition-all ${
                        severity === s.v ? s.active : 'bg-white/[0.02] border-white/5 text-white/55 hover:bg-white/5'
                      }`}
                    >
                      {s.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* STEP 3: INCIDENT DETAILS & EVIDENCE */}
            <div className="space-y-4 pt-4 border-t border-white/5">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-black text-brand-400 uppercase tracking-widest flex items-center gap-2">
                  <span className="w-5 h-5 rounded-full bg-brand-500/20 text-brand-400 flex items-center justify-center text-[10px]">3</span>
                  Mô tả & Bằng chứng
                </span>
                <span className="text-[10px] text-white/55 font-mono">{description.length + ' ký tự'}</span>
              </div>

              {/* Quick Template Chips */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <label className="text-[11px] font-black text-white/60 uppercase tracking-wider">Bấm để chèn cấu trúc gợi ý:</label>
                </div>
                <div className="flex flex-wrap gap-2">
                  {TEMPLATES.map((t) => (
                    <button
                      key={t.tag}
                      type="button"
                      onClick={() => insertTemplate(t.tag)}
                      className={`px-2.5 py-1 rounded-lg text-[11px] font-medium bg-white/[0.03] border border-white/10 text-white/70 transition-all flex items-center gap-1.5 ${t.hover}`}
                    >
                      <i className={`bi ${t.icon} ${t.iconColor}`}></i>
                      <span>{t.label}</span>
                    </button>
                  ))}
                </div>
              </div>

              {/* Description Textarea */}
              <div className="space-y-1">
                <textarea
                  ref={descRef}
                  className="liquid-input w-full p-4 text-xs sm:text-sm font-medium leading-relaxed resize-none transition-all placeholder:text-white/45"
                  rows={5}
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  onInput={autoResize}
                  placeholder="Mô tả cụ thể diễn biến: kẻ gian xưng danh là ai, liên hệ qua ứng dụng nào, đưa ra yêu cầu gì..."
                ></textarea>
              </div>

              {/* Unified Evidence Upload Dropzone */}
              <div className="space-y-3 pt-2">
                <div className="flex items-center justify-between">
                  <label className="text-[11px] font-black text-white/60 uppercase tracking-wider flex items-center gap-2">
                    <span>Ảnh chụp màn hình bằng chứng</span>
                    <span className="text-[10px] text-white/45 font-normal">(Tối đa 5 ảnh)</span>
                  </label>
                  <span className="text-[10px] font-mono text-brand-400">{images.length + '/5 ảnh'}</span>
                </div>

                {/* Dropzone Box */}
                <div
                  className={`border-2 border-dashed rounded-2xl p-6 text-center transition-all cursor-pointer group ${
                    dragOver ? 'border-brand-400 bg-brand-500/10' : 'border-white/10 bg-white/[0.01] hover:border-white/20 hover:bg-white/[0.02]'
                  }`}
                  onDragOver={(e) => {
                    e.preventDefault();
                    setDragOver(true);
                  }}
                  onDragLeave={(e) => {
                    e.preventDefault();
                    setDragOver(false);
                  }}
                  onDrop={handleFileDrop}
                  onClick={() => fileInputRef.current?.click()}
                >
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept="image/jpeg,image/png,image/webp"
                    multiple
                    className="hidden"
                    onChange={handleFileInput}
                  />

                  <div className="space-y-2">
                    <div className="w-12 h-12 rounded-xl bg-white/5 flex items-center justify-center mx-auto text-white/55 group-hover:text-brand-400 group-hover:scale-110 transition-all">
                      <i className="bi bi-cloud-arrow-up text-2xl"></i>
                    </div>
                    <p className="text-xs font-bold text-white/80">Kéo thả ảnh vào đây hoặc click để duyệt tệp</p>
                    <p className="text-[10px] text-white/55">
                      Hỗ trợ JPG, PNG, WEBP (Tối đa 8MB/ảnh). Bạn cũng có thể nhấn{' '}
                      <kbd className="px-1.5 py-0.5 rounded bg-white/10 text-white font-mono text-[9px]">Ctrl+V</kbd> để dán trực tiếp ảnh chụp màn hình.
                    </p>
                  </div>
                </div>

                {/* Thumbnails Grid */}
                {images.length > 0 && (
                  <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 pt-2">
                    {images.map((img, idx) => (
                      <div key={idx} className="relative aspect-square rounded-xl overflow-hidden border border-white/10 group bg-black/40">
                        <img src={URL.createObjectURL(img)} alt="" className="w-full h-full object-cover" />

                        {/* Primary Image Badge */}
                        {idx === 0 ? (
                          <div className="absolute top-1.5 left-1.5 px-2 py-0.5 rounded bg-brand-500 text-black text-[9px] font-black tracking-wider uppercase shadow-md">
                            Ảnh chính (OCR)
                          </div>
                        ) : (
                          <div className="absolute top-1.5 left-1.5 px-1.5 py-0.5 rounded bg-black/60 text-white/80 text-[9px] font-mono">
                            #{idx + 1}
                          </div>
                        )}

                        {/* Delete Overlay Button */}
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            removeImage(idx);
                          }}
                          className="absolute top-1.5 right-1.5 w-6 h-6 rounded-full bg-danger-500/80 text-white flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity hover:bg-danger-500"
                        >
                          <i className="bi bi-x text-base font-bold"></i>
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* STEP 4: OPTIONAL AUXILIARY PERPETRATOR DETAILS */}
            <div className="space-y-4 pt-4 border-t border-white/5">
              <button
                type="button"
                onClick={() => setShowAdvanced(!showAdvanced)}
                className="w-full flex items-center justify-between p-4 rounded-2xl bg-white/[0.02] border border-white/5 hover:bg-white/[0.04] transition-all"
              >
                <div className="flex items-center gap-3 text-left">
                  <div className="w-8 h-8 rounded-xl bg-brand2-500/10 text-brand2-400 flex items-center justify-center text-sm">
                    <i className="bi bi-person-badge"></i>
                  </div>
                  <div>
                    <h4 className="text-xs font-black text-white uppercase tracking-wider">Thông tin bổ sung về kẻ gian</h4>
                    <p className="text-[10px] text-white/55">Tùy chọn: Tên đối tượng, tài khoản ngân hàng hoặc số điện thoại liên kết</p>
                  </div>
                </div>
                <i className={`bi text-white/55 text-sm transition-transform ${showAdvanced ? 'bi-chevron-up' : 'bi-chevron-down'}`}></i>
              </button>

              {showAdvanced && (
                <div className="p-4 rounded-2xl bg-black/20 border border-white/5 space-y-4">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div className="space-y-1.5">
                      <label className="text-[11px] font-bold text-white/60">Họ tên đối tượng mạo danh</label>
                      <input
                        type="text"
                        value={scammerName}
                        onChange={(e) => setScammerName(e.target.value)}
                        placeholder="VD: Nguyễn Văn A hoặc Đại úy Trần..."
                        className="liquid-input w-full py-3 px-4 text-xs font-medium"
                      />
                    </div>

                    {/* Scammer Phone (context-aware) */}
                    <div className="space-y-1.5">
                      <label className="text-[11px] font-bold text-white/60">Số điện thoại liên hệ</label>
                      {targetType === 'phone' ? (
                        <div className="py-3 px-4 rounded-xl bg-brand-500/10 border border-brand-500/20 text-brand-300 text-xs font-mono flex items-center gap-2">
                          <i className="bi bi-check2"></i>
                          <span>Đã liên kết tự động với mục tiêu ở Bước 1</span>
                        </div>
                      ) : (
                        <input
                          type="text"
                          value={scammerPhone}
                          onChange={(e) => setScammerPhone(e.target.value)}
                          placeholder="VD: 0987654321"
                          className="liquid-input w-full py-3 px-4 text-xs font-medium"
                        />
                      )}
                    </div>

                    {/* Scammer Bank Account (context-aware) */}
                    {targetType !== 'account' && (
                      <div className="space-y-1.5">
                        <label className="text-[11px] font-bold text-white/60">Ngân hàng yêu cầu chuyển tiền</label>
                        <input
                          type="text"
                          value={scammerBankName}
                          onChange={(e) => setScammerBankName(e.target.value)}
                          placeholder="VD: Techcombank, MBBank..."
                          className="liquid-input w-full py-3 px-4 text-xs font-medium"
                        />
                      </div>
                    )}
                    {targetType !== 'account' && (
                      <div className="space-y-1.5">
                        <label className="text-[11px] font-bold text-white/60">Số tài khoản nhận tiền</label>
                        <input
                          type="text"
                          value={scammerBankAccount}
                          onChange={(e) => setScammerBankAccount(e.target.value)}
                          placeholder="Nhập số tài khoản..."
                          className="liquid-input w-full py-3 px-4 text-xs font-medium"
                        />
                      </div>
                    )}
                    <div className="space-y-1.5 sm:col-span-2">
                      <label className="text-[11px] font-bold text-white/60">Kênh MXH của kẻ lừa đảo (Telegram / Zalo / FB)</label>
                      <input
                        type="text"
                        value={scammerSocial}
                        onChange={(e) => setScammerSocial(e.target.value)}
                        placeholder="VD: t.me/..., nhóm Zalo..., facebook.com/..."
                        className="liquid-input w-full py-3 px-4 text-xs font-medium"
                      />
                    </div>
                  </div>

                  {/* Custom detail fields */}
                  <div className="pt-3 border-t border-white/5 space-y-3">
                    <p className="text-[11px] font-black text-brand-400 uppercase tracking-wider">Thông tin chi tiết tuỳ biến</p>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      <div className="space-y-1.5">
                        <label className="text-[11px] font-bold text-white/60">Số tiền thiệt hại (VNĐ)</label>
                        <input
                          type="text"
                          value={lossAmount}
                          onChange={(e) => setLossAmount(e.target.value)}
                          placeholder="VD: 5000000"
                          className="liquid-input w-full py-3 px-4 text-xs font-medium"
                        />
                      </div>
                      <div className="space-y-1.5">
                        <label className="text-[11px] font-bold text-white/60">Tổ chức bị mạo danh</label>
                        <input
                          type="text"
                          value={impersonatedOrg}
                          onChange={(e) => setImpersonatedOrg(e.target.value)}
                          placeholder="VD: Cục Thuế, VNeID, Vietcombank, Shopee..."
                          className="liquid-input w-full py-3 px-4 text-xs font-medium"
                        />
                      </div>
                      <div className="space-y-1.5">
                        <label className="text-[11px] font-bold text-white/60">Ví Crypto / Mã băm file</label>
                        <input
                          type="text"
                          value={cryptoWallet}
                          onChange={(e) => setCryptoWallet(e.target.value)}
                          placeholder="Địa chỉ ví (nếu có)"
                          className="liquid-input w-full py-3 px-4 text-xs font-medium"
                        />
                      </div>
                      <div className="space-y-1.5">
                        <label className="text-[11px] font-bold text-white/60">SHA256 / ClamAV signature</label>
                        <input
                          type="text"
                          value={fileHash}
                          onChange={(e) => setFileHash(e.target.value)}
                          placeholder="Hash file độc hại (nếu có)"
                          className="liquid-input w-full py-3 px-4 text-xs font-medium"
                        />
                      </div>
                    </div>
                    <div className="space-y-2">
                      {customPairs.map((p, idx) => (
                        <div key={idx} className="flex items-center gap-2 text-xs">
                          <span className="px-2.5 py-1.5 rounded-lg bg-white/5 border border-white/10 text-white/80 font-bold">{p.key}</span>
                          <span className="flex-1 px-2.5 py-1.5 rounded-lg bg-black/40 border border-white/10 text-white/70 truncate">{p.value}</span>
                          <button
                            type="button"
                            onClick={() => removeCustomPair(idx)}
                            className="px-2 py-1 rounded-lg bg-danger-500/10 border border-danger-500/20 text-danger-400 font-bold"
                          >
                            ✕
                          </button>
                        </div>
                      ))}
                      <div className="grid grid-cols-1 sm:grid-cols-[1fr_1fr_auto] gap-2">
                        <input
                          type="text"
                          value={newCustomKey}
                          onChange={(e) => setNewCustomKey(e.target.value)}
                          placeholder="Tên trường (VD: kênh tiếp cận)"
                          className="liquid-input py-2.5 px-3 text-xs"
                        />
                        <input
                          type="text"
                          value={newCustomValue}
                          onChange={(e) => setNewCustomValue(e.target.value)}
                          placeholder="Giá trị..."
                          className="liquid-input py-2.5 px-3 text-xs"
                        />
                        <button
                          type="button"
                          onClick={addCustomPair}
                          className="px-4 py-2.5 rounded-xl bg-brand-500/10 border border-brand-500/30 text-brand-300 text-xs font-black whitespace-nowrap"
                        >
                          + Thêm trường
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* STEP 5: TURNSTILE & SUBMIT ACTION */}
            <div className="pt-6 space-y-4 border-t border-white/5">
              <TurnstileWidget />

              {/* Error Banner */}
              {error && (
                <div className="p-4 rounded-2xl bg-danger-500/10 border border-danger-500/20 flex items-start gap-3">
                  <i className="bi bi-exclamation-octagon-fill text-danger-500 text-lg shrink-0 mt-0.5"></i>
                  <div className="space-y-1">
                    <p className="text-xs font-bold text-danger-400">Không thể gửi báo cáo</p>
                    <p className="text-[11px] text-danger-300/80 leading-relaxed">{error}</p>
                  </div>
                </div>
              )}

              {/* Submit Button */}
              <button
                type="button"
                onClick={submitReport}
                disabled={loading}
                className="liquid-btn w-full py-5 bg-danger-500 text-black font-black text-base sm:text-lg hover:bg-danger-400 active:scale-[0.98] transition-all shadow-xl shadow-danger-500/20 uppercase tracking-wider flex items-center justify-center gap-3 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? (
                  <span className="flex items-center gap-3">
                    <span className="spinner w-5 h-5 border-black border-2 border-t-transparent rounded-full animate-spin"></span>
                    <span>ĐANG XỬ LÝ DỮ LIỆU...</span>
                  </span>
                ) : (
                  <span className="flex items-center gap-2">
                    <i className="bi bi-shield-fill-check text-xl"></i>
                    <span>XÁC NHẬN GỬI BÁO CÁO</span>
                  </span>
                )}
              </button>
              <p className="text-[10px] text-white/45 text-center font-medium">
                Mọi thông tin người báo cáo được mã hóa và bảo mật tuyệt đối theo chính sách bảo vệ nguồn tin.
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Scan & Report Guide Sidebar */}
      <ReportGuide />
    </div>
  );
}
