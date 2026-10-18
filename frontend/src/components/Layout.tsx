'use client';
import { useState } from 'react';
import type { ReactNode } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useAuth } from './AuthContext';
import { changeLanguage } from './ClientInit';
import NotificationBell from './NotificationBell';
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
} from './ui/dropdown-menu';
import { Button } from './ui/button';
import { SITE_CONFIG } from '../lib/site-config';
import { cn } from '../lib/utils';
import { mediaUrl } from '../lib/api';
import type { Me } from '../lib/api';

const LANGS = [
  { code: 'vi', label: 'Tiếng Việt', short: 'VN', bg: 'rgba(239,68,68,0.1)' },
  { code: 'en', label: 'English', short: 'EN', bg: 'rgba(59,130,246,0.1)' },
  { code: 'zh-CN', label: '中文', short: 'CN', bg: 'rgba(245,158,11,0.1)' },
  { code: 'ja', label: '日本語', short: 'JP', bg: 'rgba(236,72,153,0.1)' },
  { code: 'ko', label: '한국어', short: 'KR', bg: 'rgba(167,139,250,0.1)' },
];

function LanguagePicker() {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          className="flex items-center gap-2.5 px-4 py-2.5 rounded-xl bg-white/5 border border-white/10 text-white/90 text-xs font-bold hover:bg-white/10 transition-all cursor-pointer outline-none focus-visible:ring-1 focus-visible:ring-brand-400"
        >
          <i className="bi bi-translate text-brand-400"></i>
          <span>Chọn ngôn ngữ</span>
          <i className="bi bi-chevron-up text-[10px] opacity-60"></i>
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent
        side="top"
        align="start"
        sideOffset={8}
        className="w-48 p-1.5 bg-slate-900/90 backdrop-blur-md border border-white/10 rounded-2xl shadow-2xl"
      >
        {LANGS.map((l) => (
          <DropdownMenuItem
            key={l.code}
            onClick={() => changeLanguage(l.code)}
            className="flex items-center gap-3 px-3 py-2 text-xs font-bold text-slate-200 hover:text-white rounded-xl cursor-pointer hover:bg-white/10 transition-colors"
          >
            <span
              className="w-6 h-6 rounded-md flex items-center justify-center text-[10px] font-black shrink-0"
              style={{ background: l.bg }}
            >
              {l.short}
            </span>{' '}
            {l.label}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

interface MenuItem {
  to: string;
  icon: string;
  title: string;
  desc: string;
  isDanger?: boolean;
}

/* Menu "Kiểm tra" — thống nhất bảng màu nhận diện Brand Cyan / Slate */
const SCAN_MENU: MenuItem[] = [
  { to: '/scan/phone/', icon: 'bi-phone', title: 'Số điện thoại', desc: 'Tra cứu SĐT rủi ro' },
  { to: '/scan/message/', icon: 'bi-chat-left-dots', title: 'Văn bản / Tin nhắn', desc: 'Phân tích nội dung chữ bằng AI' },
  { to: '/scan/website/', icon: 'bi-globe2', title: 'Website', desc: 'Phát hiện Phishing' },
  { to: '/scan/bank/', icon: 'bi-bank2', title: 'Tài khoản', desc: 'Tra cứu bank lừa đảo' },
  { to: '/scan/email/', icon: 'bi-envelope-check', title: 'Email', desc: 'Phát hiện Email Scam' },
  { to: '/scan/qr/', icon: 'bi-qr-code-scan', title: 'QR / Ảnh', desc: 'OCR + Phân tích ảnh' },
  { to: '/scan/image/', icon: 'bi-image', title: 'Ảnh / Chứng từ', desc: 'Đọc ảnh chuyển khoản, hoá đơn' },
  { to: '/scan/file/', icon: 'bi-file-earmark-check', title: 'Quét File', desc: 'Phân tích Docker Sandbox' },
  { to: '/scan/audio/', icon: 'bi-mic', title: 'Âm Thanh', desc: 'Phân tích hội thoại lừa đảo' },
];

const REPORT_MENU: MenuItem[] = [
  { to: '/report/', icon: 'bi-flag-fill', title: 'Gửi báo cáo', desc: 'Khai báo hành vi lừa đảo', isDanger: true },
  { to: '/reports/', icon: 'bi-shield-check', title: 'Tra cứu báo cáo', desc: 'Danh sách báo cáo cộng đồng' },
  { to: '/my-reports/', icon: 'bi-journal-text', title: 'Báo cáo của tôi', desc: 'Lịch sử báo cáo đã gửi' },
];

function UserMenu({ user }: { user: Me }) {
  const { logout } = useAuth();
  const itemCls =
    "flex items-center gap-2.5 px-3 py-2 text-xs font-semibold text-slate-300 hover:text-white rounded-xl cursor-pointer hover:bg-white/[0.08] w-full transition-colors no-underline";

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          className="h-9 pl-1.5 pr-2 sm:pr-3.5 rounded-full inline-flex items-center gap-2 sm:gap-2.5 bg-white/[0.06] border border-white/15 hover:border-cyan-500/40 hover:bg-white/[0.10] transition-all outline-none cursor-pointer shadow-sm backdrop-blur-md data-[state=open]:border-cyan-400 data-[state=open]:bg-white/[0.10] shrink-0"
        >
          <span className="w-6 h-6 rounded-full bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-300 text-xs shrink-0 overflow-hidden relative">
            {user.avatar ? (
              <>
                <i className="bi bi-person-fill leading-none absolute"></i>
                <img
                  src={mediaUrl(user.avatar)}
                  alt={user.username}
                  className="w-full h-full object-cover relative z-10"
                  onError={(e) => {
                    e.currentTarget.style.display = 'none';
                  }}
                />
              </>
            ) : (
              <i className="bi bi-person-fill leading-none"></i>
            )}
          </span>
          <span className="font-bold text-slate-100 text-xs max-w-[120px] truncate leading-normal hidden sm:inline">
            {user.username}
          </span>
          <i className="bi bi-chevron-down text-[10px] text-slate-400 opacity-70 leading-none hidden sm:inline"></i>
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent
        align="end"
        sideOffset={8}
        className="w-64 p-1.5 border border-border bg-popover/98 backdrop-blur-xl rounded-2xl shadow-[0_20px_60px_rgba(0,0,0,0.7)]"
      >
        <div className="px-3 py-2.5 border-b border-white/10 mb-1 flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-full bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-300 text-sm shrink-0 overflow-hidden relative">
            {user.avatar ? (
              <>
                <i className="bi bi-person-fill leading-none absolute"></i>
                <img
                  src={mediaUrl(user.avatar)}
                  alt={user.username}
                  className="w-full h-full object-cover relative z-10"
                  onError={(e) => {
                    e.currentTarget.style.display = 'none';
                  }}
                />
              </>
            ) : (
              <i className="bi bi-person-fill leading-none"></i>
            )}
          </div>
          <div className="min-w-0 flex-1">
            <div className="text-xs font-bold text-white truncate leading-tight">{user.username}</div>
            <div className="text-[10px] text-cyan-400 font-semibold truncate mt-0.5">
              {user.is_superuser ? 'Super Admin' : user.is_staff ? 'Admin' : 'Thành viên'}
            </div>
          </div>
        </div>
        <DropdownMenuItem asChild>
          <Link href="/dashboard/" className={itemCls}>
            <i className="bi bi-speedometer2 text-cyan-400 text-sm leading-none"></i> Bảng điều khiển
          </Link>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <Link href="/profile/" className={itemCls}>
            <i className="bi bi-person-gear text-slate-400 text-sm leading-none"></i> Trang cá nhân
          </Link>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <Link href="/profile/inbox/" className={itemCls}>
            <i className="bi bi-envelope text-slate-400 text-sm leading-none"></i> Hộp thư
          </Link>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <Link href="/my-reports/" className={itemCls}>
            <i className="bi bi-journal-text text-slate-400 text-sm leading-none"></i> Báo cáo của tôi
          </Link>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <Link href="/scam-iq-exam/" className={itemCls}>
            <i className="bi bi-patch-question text-brand2-400 text-sm leading-none"></i> Scam IQ Exam
          </Link>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <Link href="/ai-assistant/" className={itemCls}>
            <i className="bi bi-robot text-cyan-400 text-sm leading-none"></i> Hỏi AI Assistant
          </Link>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <Link href="/mcp/" className={itemCls}>
            <i className="bi bi-plug text-cyan-300 text-sm leading-none"></i> MCP Server
          </Link>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <Link href="/helps/" className={itemCls}>
            <i className="bi bi-question-circle text-slate-400 text-sm leading-none"></i> Trợ giúp & Hướng dẫn
          </Link>
        </DropdownMenuItem>
        {(user.is_staff || user.is_superuser) && (
          <>
            <DropdownMenuSeparator className="border-t border-white/5 my-1" />
            <DropdownMenuItem asChild>
              <Link href="/admin-cp/" className={`${itemCls} text-amber-400 hover:text-amber-300`}>
                <i className="bi bi-shield-lock text-sm leading-none"></i> Admin Control Panel
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <a href="/admin/" className={`${itemCls} text-amber-300 hover:text-amber-200`}>
                <i className="bi bi-gear text-sm leading-none"></i> Django Admin
              </a>
            </DropdownMenuItem>
          </>
        )}
        <DropdownMenuSeparator className="border-t border-white/5 my-1" />
        <DropdownMenuItem
          onClick={async () => {
            await logout();
            window.location.href = '/login/?logged_out=1';
          }}
          className={`${itemCls} text-rose-400 hover:text-rose-300 hover:bg-rose-500/10`}
        >
          <i className="bi bi-box-arrow-right text-sm leading-none"></i> Đăng xuất
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function DropMenu({
  label,
  icon,
  items,
  active = false,
}: {
  label: string;
  icon: string;
  items: MenuItem[];
  active?: boolean;
}) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          className={cn(
            "h-8 px-2.5 xl:px-3 rounded-full inline-flex items-center gap-1.5 text-xs transition-all outline-none cursor-pointer select-none",
            active
              ? "bg-cyan-500/15 text-cyan-300 border border-cyan-500/35 font-bold shadow-sm shadow-cyan-500/10"
              : "text-slate-300 hover:text-white hover:bg-white/[0.08] font-semibold border border-transparent data-[state=open]:bg-white/[0.1] data-[state=open]:text-cyan-400"
          )}
        >
          <i className={`bi ${icon} text-xs leading-none`}></i>
          <span>{label}</span>
          <i className="bi bi-chevron-down text-[10px] opacity-60 leading-none"></i>
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent
        align="start"
        sideOffset={8}
        className="w-68 p-1.5 border border-border bg-popover/98 backdrop-blur-xl rounded-2xl shadow-[0_20px_60px_rgba(0,0,0,0.7)]"
      >
        {items.map((it) => (
          <DropdownMenuItem key={it.to} asChild className="p-0 cursor-pointer rounded-xl overflow-hidden focus:bg-transparent">
            <Link
              href={it.to}
              className="group flex items-center gap-3 p-2 rounded-xl hover:bg-accent transition-colors w-full no-underline"
            >
              <div
                className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 border transition-all ${
                  it.isDanger
                    ? 'bg-rose-500/10 border-rose-500/25 text-rose-400 group-hover:bg-rose-500/20 group-hover:border-rose-500/40'
                    : 'bg-white/[0.06] border-border text-cyan-400 group-hover:bg-cyan-500/15 group-hover:border-cyan-500/35 group-hover:text-cyan-300'
                }`}
              >
                <i className={`bi ${it.icon} text-sm leading-none`}></i>
              </div>
              <div className="min-w-0 flex-1">
                <div className="text-xs font-bold text-slate-100 group-hover:text-cyan-300 transition-colors truncate leading-tight">
                  {it.title}
                </div>
                <div className="text-[11px] text-slate-400 group-hover:text-slate-300 transition-colors truncate mt-0.5">
                  {it.desc}
                </div>
              </div>
            </Link>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export function Navbar() {
  const { user, logout } = useAuth();
  const [mobile, setMobile] = useState(false);
  const pathname = usePathname() || '';

  const isScanActive = pathname.startsWith('/scan');
  const isReportActive = pathname.startsWith('/report');
  const isRadarActive = pathname.startsWith('/scam-radar');
  const isForumActive = pathname.startsWith('/forum');
  const isLearnActive = pathname.startsWith('/learn') || pathname.startsWith('/helps');
  const isElderActive = pathname.startsWith('/nguoi-cao-tuoi');

  const navLinkCls = (active: boolean) =>
    cn(
      "h-8 px-2.5 xl:px-3 rounded-full inline-flex items-center gap-1.5 text-xs transition-all outline-none no-underline select-none",
      active
        ? "bg-cyan-500/15 text-cyan-300 border border-cyan-500/35 font-bold shadow-sm shadow-cyan-500/10"
        : "text-slate-300 hover:text-white hover:bg-white/[0.08] font-semibold border border-transparent"
    );

  return (
    <nav className="nav-premium">
      <div className="max-w-[1400px] mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 sm:h-[72px] gap-4">
          {/* 1. Left: Brand Logo */}
          <div className="flex items-center shrink-0">
            <Link href="/" className="flex items-center gap-3 group shrink-0 no-underline">
              <img
                src="/logo.png"
                className="w-9 h-9 sm:w-10 sm:h-10 object-contain drop-shadow-[0_0_12px_rgba(6,182,212,0.35)] group-hover:scale-105 transition-transform shrink-0"
                alt="ShieldCall VN"
              />
              <div className="hidden sm:flex flex-col justify-center">
                <h2 className="text-[17px] sm:text-lg font-black text-white leading-none tracking-tight">
                  ShieldCall <span className="text-brand-400">VN</span>
                </h2>
                <p className="text-[9px] sm:text-[10px] text-white/45 font-bold uppercase tracking-widest mt-1">Community Guard</p>
              </div>
            </Link>
          </div>

          {/* 2. Center: Navigation Capsule (Centered & Balanced) */}
          <div className="hidden lg:flex items-center justify-center flex-1 max-w-3xl mx-auto px-2">
            <div className="flex items-center gap-1 p-1 rounded-full bg-white/[0.035] border border-white/[0.08] backdrop-blur-md shadow-[inset_0_1px_1px_rgba(255,255,255,0.06)]">
              <DropMenu label="Kiểm tra" icon="bi-shield-check" items={SCAN_MENU} active={isScanActive} />
              <DropMenu label="Báo cáo" icon="bi-flag" items={REPORT_MENU} active={isReportActive} />
              <Link href="/scam-radar/" className={navLinkCls(isRadarActive)}>
                <i className="bi bi-radar text-xs leading-none"></i>
                <span>Radar</span>
              </Link>
              <Link href="/forum/" className={navLinkCls(isForumActive)}>
                <i className="bi bi-chat-left-text text-xs leading-none"></i>
                <span>Diễn đàn</span>
              </Link>
              <Link href="/learn/" className={navLinkCls(isLearnActive)}>
                <i className="bi bi-journal-bookmark text-xs leading-none"></i>
                <span>Kiến thức</span>
              </Link>
              <Link
                href="/nguoi-cao-tuoi/"
                className={cn(
                  "h-8 px-2.5 xl:px-3 rounded-full inline-flex items-center gap-1.5 text-xs transition-all outline-none no-underline select-none",
                  isElderActive
                    ? "bg-emerald-500/20 text-emerald-200 border border-emerald-500/40 font-bold shadow-sm shadow-emerald-500/15"
                    : "text-emerald-400/90 hover:text-emerald-200 hover:bg-emerald-500/10 font-semibold border border-emerald-500/20 hover:border-emerald-500/35"
                )}
              >
                <i className="bi bi-person-hearts text-xs leading-none text-emerald-400"></i>
                <span>Người cao tuổi</span>
              </Link>
            </div>
          </div>

          {/* 3. Right: Action Controls */}
          <div className="flex items-center gap-2 sm:gap-2.5 shrink-0">
            <Link
              href="/emergency/"
              className="hidden sm:inline-flex items-center gap-1.5 h-9 px-3.5 rounded-full text-xs font-bold text-rose-300 bg-rose-500/15 border border-rose-500/35 hover:bg-rose-500/25 hover:border-rose-500/50 hover:text-white transition-all shadow-sm shadow-rose-500/10 no-underline shrink-0"
            >
              <i className="bi bi-exclamation-triangle-fill text-xs text-rose-400 leading-none"></i>
              <span>Hỗ trợ khẩn cấp</span>
            </Link>
            {user && <NotificationBell />}
            {user ? (
              <UserMenu user={user} />
            ) : (
              <div className="hidden sm:flex items-center gap-2">
                <Button asChild variant="ghost" className="h-9 px-4 text-xs font-semibold text-white/70 hover:text-white rounded-full">
                  <Link href="/login/">Đăng nhập</Link>
                </Button>
                <Button asChild variant="cyber" className="h-9 px-5 text-xs font-bold rounded-full">
                  <Link href="/register/">Đăng ký</Link>
                </Button>
              </div>
            )}
            <button
              className="lg:hidden p-2 rounded-full hover:bg-white/5 text-white/70 flex items-center justify-center cursor-pointer"
              onClick={() => setMobile(!mobile)}
              aria-label="Menu"
            >
              <i className={`bi ${mobile ? 'bi-x-lg' : 'bi-list'} text-xl`}></i>
            </button>
          </div>
        </div>
      </div>
      {mobile && (
        <div className="lg:hidden px-4 pb-4 space-y-1 border-t border-white/5 pt-2 sc-slide-down">
          <Link href="/" className="flex items-center gap-3 p-2.5 rounded-xl text-white/70 hover:bg-white/5">
            <i className="bi bi-house-door text-brand-400"></i>
            <span className="text-sm font-bold">Trang chủ</span>
          </Link>
          {/* Người cao tuổi: đặt ngay dưới Trang chủ để dễ tìm trên điện thoại */}
          <Link
            href="/nguoi-cao-tuoi/"
            className="flex items-center gap-3 p-2.5 rounded-xl bg-safe-500/10 border border-safe-500/25 text-safe-300"
          >
            <i className="bi bi-person-hearts"></i>
            <span className="text-sm font-bold">Người cao tuổi</span>
          </Link>
          {SCAN_MENU.map((it) => (
            <Link
              key={it.to}
              href={it.to}
              className="flex items-center gap-3 p-2.5 rounded-xl text-slate-300 hover:text-white hover:bg-white/5 transition-colors group"
            >
              <div className="w-7 h-7 rounded-lg bg-white/[0.04] border border-white/10 flex items-center justify-center text-slate-400 group-hover:text-brand-300 group-hover:border-brand-500/30">
                <i className={`bi ${it.icon} text-xs`}></i>
              </div>
              <span className="text-sm font-semibold">{it.title}</span>
            </Link>
          ))}
          <div className="flex gap-2 pt-2">
            <Link href="/scam-radar/" className="flex-1 text-center p-2.5 rounded-xl bg-white/5 text-sm font-bold text-white/70">Radar</Link>
            <Link href="/forum/" className="flex-1 text-center p-2.5 rounded-xl bg-white/5 text-sm font-bold text-white/70">Diễn đàn</Link>
            <Link href="/learn/" className="flex-1 text-center p-2.5 rounded-xl bg-white/5 text-sm font-bold text-white/70">Kiến thức</Link>
          </div>
          <div className="flex gap-2 pt-2">
            <Link href="/ai-assistant/" className="flex-1 text-center p-2.5 rounded-xl bg-brand-500/10 text-sm font-bold text-brand-300">Hỏi AI</Link>
            <Link href="/mcp/" className="flex-1 text-center p-2.5 rounded-xl bg-white/5 text-sm font-bold text-white/70">MCP</Link>
            <Link href="/scam-iq-exam/" className="flex-1 text-center p-2.5 rounded-xl bg-white/5 text-sm font-bold text-white/70">Scam IQ</Link>
            <Link href="/emergency/" className="flex-1 text-center p-2.5 rounded-xl bg-danger-500/10 text-sm font-bold text-danger-400">Khẩn cấp</Link>
          </div>
          <div className="flex gap-2 pt-2">
            {user ? (
              <>
                <Link href="/my-reports/" className="flex-1 text-center p-2.5 rounded-xl bg-white/5 text-sm font-bold text-white/70">Báo cáo</Link>
                <Link href="/helps/" className="flex-1 text-center p-2.5 rounded-xl bg-white/5 text-sm font-bold text-white/70">Trợ giúp</Link>
                {(user.is_staff || user.is_superuser) && (
                  <Link href="/admin-cp/" className="flex-1 text-center p-2.5 rounded-xl bg-warn-500/10 text-sm font-bold text-warn-400">Admin</Link>
                )}
                <a
                  href="/logout/"
                  onClick={async (e) => {
                    e.preventDefault();
                    await logout();
                    window.location.href = '/login/?logged_out=1';
                  }}
                  className="flex-1 text-center p-2.5 rounded-xl bg-danger-500/10 text-sm font-bold text-danger-400 cursor-pointer"
                >
                  Đăng xuất
                </a>
              </>
            ) : (
              <>
                <Link href="/login/" className="flex-1 text-center p-2.5 rounded-xl bg-white/5 text-sm font-bold text-white/70">Đăng nhập</Link>
                <Link href="/register/" className="flex-1 text-center p-2.5 rounded-xl bg-brand-500/10 text-sm font-bold text-brand-400">Đăng ký</Link>
              </>
            )}
          </div>
        </div>
      )}
    </nav>
  );
}

const FOOT_SCAN = [
  { to: '/scan/phone/', label: 'Scan Số điện thoại' },
  { to: '/scan/message/', label: 'Scan Văn bản / Tin nhắn' },
  { to: '/scan/website/', label: 'Scan Website' },
  { to: '/scan/bank/', label: 'Scan Tài khoản' },
];

const FOOT_HELP = [
  { to: '/helps/', label: 'Trang Hướng dẫn', accent: true },
  { to: '/mcp/', label: 'Tích hợp MCP Server', accent: true },
  { to: '/trust/', label: 'Nguồn & độ tin cậy' },
  { to: '/report/', label: 'Báo cáo lừa đảo' },
  { to: '/learn/', label: 'Kiến thức phòng tránh', spa: true },
  { to: '/emergency/', label: 'Hỗ trợ khẩn cấp' },
];

export function Footer() {
  const year = new Date().getFullYear();
  return (
    <footer className="border-t border-white/10 mt-16 bg-black/15">
      <div className="max-w-7xl mx-auto px-6 py-16">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-12 mb-12">
          <div>
            <div className="flex items-center gap-3 mb-5">
              <img
                src="/logo.png"
                className="w-9 h-9 object-contain drop-shadow-[0_0_12px_rgba(6,182,212,0.35)] shrink-0"
                alt={SITE_CONFIG.name}
              />
              <span className="font-extrabold text-xl glow-text">{SITE_CONFIG.name}</span>
            </div>
            <p className="text-sm text-white/60 leading-relaxed">
              Bảo vệ người dùng Việt Nam khỏi các hình thức lừa đảo số bằng công nghệ AI tiên tiến.
            </p>
          </div>
          <div>
            <h4 className="font-semibold mb-3 text-sm text-white/70">Scan</h4>
            <div className="flex flex-col gap-1.5 text-sm">
              {FOOT_SCAN.map((l) => (
                <Link key={l.to} href={l.to} className="text-white/60 hover:text-cyan-400 transition-colors">
                  {l.label}
                </Link>
              ))}
            </div>
          </div>
          <div>
            <h4 className="font-semibold mb-3 text-sm text-white/70">Hỗ trợ</h4>
            <div className="flex flex-col gap-1.5 text-sm">
              {FOOT_HELP.map((l) => (
                <Link
                  key={l.to}
                  href={l.to}
                  className={l.accent ? 'text-cyan-400 font-bold hover:text-cyan-300' : 'text-white/60 hover:text-cyan-400 transition-colors'}
                >
                  {l.label}
                </Link>
              ))}
            </div>
          </div>
          <div>
            <h4 className="font-semibold mb-3 text-sm text-white/70">Ngôn ngữ</h4>
            <LanguagePicker />
            <div id="google_translate_element" className="hidden"></div>
          </div>
        </div>
        <div className="border-t border-white/10 pt-6 flex flex-wrap items-center justify-between gap-4">
          <p className="text-xs text-white/40">© {year} {SITE_CONFIG.name}. Bảo vệ cộng đồng bằng công nghệ.</p>
          <div className="flex items-center gap-6 text-xs text-white/40">
            <Link href="/helps/" className="text-white/60 font-semibold hover:text-white transition-colors">Hỗ trợ</Link>
            <Link href="/legal/disclaimer/#terms" className="hover:text-white transition-colors">Điều khoản</Link>
            <Link href="/legal/disclaimer/#data" className="hover:text-white transition-colors">Chính sách</Link>
            <a href="/api/docs/" className="hover:text-white transition-colors">API Docs</a>
            {SITE_CONFIG.repoUrl && (
              <a
                href={SITE_CONFIG.repoUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="hover:text-white transition-colors inline-flex items-center gap-1.5 text-white/60"
              >
                <i className="bi bi-github"></i> GitHub
              </a>
            )}
          </div>
        </div>
      </div>
    </footer>
  );
}

export function Layout({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen flex flex-col">
      <div className="mesh-bg"></div>
      <Navbar />
      <main className="flex-1">{children}</main>
      <Footer />
    </div>
  );
}
