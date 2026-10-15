'use client';
import Link from 'next/link';

type Accent = 'cyan' | 'amber' | 'violet' | 'red';

interface ErrButton {
  label: string;
  icon?: string;
  action?: 'back' | 'reload';
  href?: string;
  accent?: boolean;
}

interface ErrConfig {
  icon: string;
  iconAnim?: string;
  wrap: string;
  accent: Accent;
  title: string;
  message: string;
  buttons: ErrButton[];
}

const THEME: Record<
  Accent,
  {
    btn: string;
    glow: string;
    pill: string;
    dot: string;
  }
> = {
  cyan: {
    btn: 'bg-brand-500 text-black shadow-brand-500/25 hover:bg-brand-400',
    glow: 'bg-brand-500/20',
    pill: 'bg-brand-500/10 text-brand-300 border-brand-500/30',
    dot: 'bg-brand-400',
  },
  amber: {
    btn: 'bg-warn-500 text-black shadow-warn-500/25 hover:bg-warn-400',
    glow: 'bg-warn-500/20',
    pill: 'bg-warn-500/10 text-warn-300 border-warn-500/30',
    dot: 'bg-warn-400',
  },
  violet: {
    btn: 'bg-brand2-500 text-white shadow-brand2-500/25 hover:bg-brand2-400',
    glow: 'bg-brand2-500/20',
    pill: 'bg-brand2-500/10 text-brand2-300 border-brand2-500/30',
    dot: 'bg-brand2-400',
  },
  red: {
    btn: 'bg-danger-500 text-white shadow-danger-500/25 hover:bg-danger-400',
    glow: 'bg-danger-500/20',
    pill: 'bg-danger-500/10 text-danger-300 border-danger-500/30',
    dot: 'bg-danger-400',
  },
};

const GHOST_BTN =
  'liquid-btn py-3 px-8 text-xs font-bold bg-white/5 text-white/85 border-white/10 hover:bg-white/10 uppercase tracking-wider transition-all cursor-pointer';

const CONFIG: Record<string, ErrConfig> = {
  '400': {
    icon: 'bi-exclamation-triangle-fill',
    wrap: 'bg-warn-500/10 text-warn-400 border-warn-500/30',
    accent: 'amber',
    title: 'Yêu cầu chưa hợp lệ',
    message: 'Vui lòng kiểm tra lại thông tin và thử lại trong giây lát.',
    buttons: [{ label: 'Quay lại', action: 'back' }, { label: 'Trang chủ', accent: true }],
  },
  '403': {
    icon: 'bi-shield-lock-fill',
    wrap: 'bg-brand2-500/10 text-brand2-400 border-brand2-500/30',
    accent: 'violet',
    title: 'Không có quyền truy cập',
    message: 'Tài nguyên này yêu cầu quyền cao hơn. Vui lòng liên hệ quản trị viên.',
    buttons: [{ label: 'Quay lại', action: 'back' }, { label: 'Trang chủ', accent: true }],
  },
  '404': {
    icon: 'bi-compass',
    iconAnim: 'animate-spin-slow',
    wrap: 'bg-brand-500/10 text-brand-400 border-brand-500/30',
    accent: 'cyan',
    title: 'Oops! Bạn lạc đường rồi',
    message: 'Trang bạn đang tìm kiếm không tồn tại hoặc đã bị di chuyển sang địa chỉ khác.',
    buttons: [{ label: 'Quay lại', icon: 'bi-arrow-left mr-2', action: 'back' }, { label: 'Trang chủ', accent: true }],
  },
  '500': {
    icon: 'bi-cpu-fill',
    iconAnim: 'animate-pulse',
    wrap: 'bg-danger-500/10 text-danger-400 border-danger-500/30',
    accent: 'red',
    title: 'Lỗi hệ thống',
    message: 'Đã có lỗi phía máy chủ. Quản trị viên đã nhận được cảnh báo và đang xử lý.',
    buttons: [
      {
        label: 'Báo lỗi',
        icon: 'bi-envelope-fill mr-2',
        href: `mailto:${process.env.NEXT_PUBLIC_SUPPORT_EMAIL || 'admin@fptoj.com'}`,
      },
      { label: 'Về trang chủ', accent: true },
    ],
  },
  '502': {
    icon: 'bi-diagram-3-fill',
    wrap: 'bg-brand-500/10 text-brand-400 border-brand-500/30',
    accent: 'cyan',
    title: 'Gateway tạm thời lỗi',
    message: 'Kết nối dịch vụ gián đoạn. Vui lòng chờ một chút để máy chủ cân bằng tải khôi phục.',
    buttons: [{ label: 'Thử lại', action: 'reload', accent: true }, { label: 'Trang chủ' }],
  },
  '503': {
    icon: 'bi-tools',
    wrap: 'bg-brand-500/10 text-brand-400 border-brand-500/30',
    accent: 'cyan',
    title: 'Hệ thống đang bảo trì',
    message: 'Hệ thống đang nâng cấp phiên bản định kỳ để bảo đảm an toàn. Sẽ quay lại ngay.',
    buttons: [{ label: 'Thử lại', action: 'reload' }, { label: 'Trang chủ', accent: true }],
  },
  '504': {
    icon: 'bi-clock-history',
    iconAnim: 'animate-pulse',
    wrap: 'bg-warn-500/10 text-warn-400 border-warn-500/30',
    accent: 'amber',
    title: 'Yêu cầu bị timeout',
    message: 'Hệ thống phản hồi chậm bất thường. Vui lòng chờ một chút rồi thử lại.',
    buttons: [{ label: 'Thử lại', action: 'reload', accent: true }, { label: 'Trang chủ' }],
  },
};

const FALLBACK: ErrConfig = CONFIG['404'];

export default function ErrorPage({
  code = 404,
  title,
  message,
}: {
  code?: number | string;
  title?: string;
  message?: string;
}) {
  const cfg = CONFIG[String(code)] || FALLBACK;
  const theme = THEME[cfg.accent];
  const displayTitle = title || cfg.title;
  const displayMessage = message || cfg.message;

  function goBack(): void {
    if (typeof window !== 'undefined') window.history.back();
  }
  function reload(): void {
    if (typeof window !== 'undefined') window.location.reload();
  }

  function renderButton(btn: ErrButton, idx: number) {
    const cls = btn.accent
      ? `liquid-btn py-3 px-8 text-xs font-black shadow-lg uppercase tracking-wider transition-all cursor-pointer ${theme.btn}`
      : GHOST_BTN;
    const inner = (
      <>
        {btn.icon && <i className={`bi ${btn.icon}`}></i>}
        <span>{btn.label}</span>
      </>
    );
    if (btn.href) {
      return (
        <a key={idx} href={btn.href} className={cls}>
          {inner}
        </a>
      );
    }
    if (btn.action === 'back') {
      return (
        <button key={idx} type="button" onClick={goBack} className={cls}>
          {inner}
        </button>
      );
    }
    if (btn.action === 'reload') {
      return (
        <button key={idx} type="button" onClick={reload} className={cls}>
          {inner}
        </button>
      );
    }
    return (
      <Link key={idx} href="/" className={cls}>
        {inner}
      </Link>
    );
  }

  return (
    <div className="animate-fadein flex items-center justify-center min-h-[75vh] px-4 py-12 sm:py-16">
      <div className="liquid-card w-full max-w-xl p-8 sm:p-12 relative overflow-hidden text-center space-y-7 shadow-2xl">
        {/* Ambient backlight glow */}
        <div
          className={`absolute -top-24 left-1/2 -translate-x-1/2 w-72 h-72 rounded-full blur-3xl pointer-events-none opacity-30 ${theme.glow}`}
        ></div>

        {/* Status Badge */}
        <div className="relative z-10 flex justify-center">
          <div
            className={`inline-flex items-center gap-2 px-4 py-1.5 rounded-full border text-xs font-mono font-bold tracking-wider uppercase ${theme.pill}`}
          >
            <span className={`w-2 h-2 rounded-full animate-ping ${theme.dot}`}></span>
            <span>ERROR {code}</span>
          </div>
        </div>

        {/* Center Icon */}
        <div className="relative z-10 flex justify-center">
          <div
            className={`w-24 h-24 rounded-3xl border shadow-xl flex items-center justify-center ${cfg.wrap}`}
          >
            <i className={`bi ${cfg.icon} text-5xl ${cfg.iconAnim || ''}`}></i>
          </div>
        </div>

        {/* Headline & Description */}
        <div className="space-y-3 relative z-10">
          <h1 className="text-2xl sm:text-3xl font-black text-white tracking-tight leading-snug">
            {displayTitle}
          </h1>
          <p className="text-white/80 text-sm sm:text-base font-normal leading-relaxed max-w-md mx-auto">
            {displayMessage}
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center justify-center gap-3 pt-2 relative z-10">
          {cfg.buttons.map(renderButton)}
        </div>

        {/* Diagnostics & Brand Footer */}
        <div className="pt-6 border-t border-white/5 text-[11px] text-white/40 flex items-center justify-between relative z-10">
          <span className="font-mono">HTTP {code}</span>
          <span className="font-medium">ShieldCall VN Security System</span>
        </div>
      </div>

      <style>{`
        @keyframes spin-slow {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        .animate-spin-slow {
          animation: spin-slow 12s linear infinite;
        }
      `}</style>
    </div>
  );
}
