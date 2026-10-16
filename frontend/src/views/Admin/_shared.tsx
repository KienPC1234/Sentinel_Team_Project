'use client';
import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { api } from '../../lib/api';
import { useAuth } from '../../components/AuthContext';

/* Khung chung cụm Admin ShieldCall VN */

/* Chặn non-staff ngay phía client: trước đây ai mở /admin-cp/* cũng thấy khung
 * admin + form broadcast (dù API 403), gây hiểu nhầm và lộ cấu trúc quản trị. */
export function RequireStaff({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <div className="container mx-auto px-4 py-24 max-w-7xl text-center text-slate-400 text-sm">
        <div className="inline-block w-6 h-6 border-2 border-brand-500 border-t-transparent rounded-full animate-spin mb-3"></div>
        <p>Đang kiểm tra quyền quản trị...</p>
      </div>
    );
  }
  if (!user?.is_staff) {
    return (
      <div className="container mx-auto px-4 py-24 max-w-7xl">
        <div className="max-w-md mx-auto rounded-3xl border border-danger-500/30 bg-slate-900/90 p-10 text-center space-y-4 shadow-2xl backdrop-blur-xl">
          <div className="w-16 h-16 rounded-2xl bg-danger-500/15 border border-danger-500/30 flex items-center justify-center text-danger-400 text-3xl mx-auto">
            <i className="bi bi-shield-lock-fill"></i>
          </div>
          <h1 className="text-xl font-black text-white">Khu vực quản trị viên</h1>
          <p className="text-sm text-slate-400">Bạn không có quyền truy cập trang quản trị này.</p>
          <Link href="/" className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-white/5 border border-white/10 text-brand-400 font-bold hover:bg-white/10 hover:text-white transition-all text-xs">
            <i className="bi bi-arrow-left"></i> Về trang chủ
          </Link>
        </div>
      </div>
    );
  }
  return <>{children}</>;
}

export const ADMIN_LINKS: Array<{ to: string; label: string; icon: string }> = [
  { to: '/admin-cp/', label: 'Dashboard', icon: 'bi-speedometer2' },
  { to: '/admin-cp/reports/', label: 'Báo cáo', icon: 'bi-flag' },
  { to: '/admin-cp/users/', label: 'Người dùng', icon: 'bi-people' },
  { to: '/admin-cp/articles/', label: 'Tin tức & Cảnh báo', icon: 'bi-newspaper' },
  { to: '/admin-cp/scenarios/', label: 'Kịch bản lừa đảo', icon: 'bi-diagram-3' },
  { to: '/admin-cp/learn/', label: 'Bài học', icon: 'bi-mortarboard' },
  { to: '/admin-cp/rag/', label: 'RAG & AI', icon: 'bi-cpu' },
  { to: '/admin-cp/forum/', label: 'Diễn đàn', icon: 'bi-chat-square-dots' },
  { to: '/admin-cp/tickets/', label: 'Hỗ trợ (Tickets)', icon: 'bi-ticket-detailed' },
];

export function AdminNavbar() {
  const pathname = usePathname() || '';

  const isActive = (to: string) => {
    if (to === '/admin-cp/') {
      return pathname === '/admin-cp' || pathname === '/admin-cp/';
    }
    return pathname.startsWith(to.replace(/\/$/, ''));
  };

  return (
    <div className="mb-8">
      {/* Scrollable pill container with clean high contrast */}
      <div className="flex items-center gap-1.5 p-1.5 rounded-2xl bg-slate-900/90 border border-white/10 backdrop-blur-xl overflow-x-auto custom-scrollbar shadow-lg">
        {ADMIN_LINKS.map((l) => {
          const active = isActive(l.to);
          return (
            <Link
              key={l.to}
              href={l.to}
              className={`shrink-0 flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-bold transition-all ${
                active
                  ? 'bg-gradient-to-r from-brand-500 to-brand-600 text-black shadow-md shadow-brand-500/25 font-black'
                  : 'text-slate-300 hover:text-white hover:bg-white/5'
              }`}
            >
              <i className={`bi ${l.icon} text-sm ${active ? 'text-black' : 'text-slate-400'}`}></i>
              <span>{l.label}</span>
            </Link>
          );
        })}
      </div>
    </div>
  );
}

export function AdminShell({
  breadcrumbs,
  title,
  subtitle,
  children,
  actions,
}: {
  breadcrumbs?: Array<{ label: string; href?: string }>;
  title: string;
  subtitle?: string;
  children: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="container mx-auto px-4 py-8 mt-16 max-w-7xl">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 gap-4 pb-6 border-b border-white/10">
        <div>
          {breadcrumbs && breadcrumbs.length > 0 ? (
            <nav className="flex items-center gap-1.5 text-xs text-slate-400 mb-2">
              <Link href="/admin-cp/" className="hover:text-brand-400 transition">
                Admin
              </Link>
              {breadcrumbs.map((b, idx) => (
                <span key={idx} className="flex items-center gap-1.5">
                  <i className="bi bi-chevron-right text-[9px] text-slate-600"></i>
                  {b.href ? (
                    <Link href={b.href} className="hover:text-brand-400 transition">
                      {b.label}
                    </Link>
                  ) : (
                    <span className="text-brand-400 font-semibold">{b.label}</span>
                  )}
                </span>
              ))}
            </nav>
          ) : (
            <div className="flex items-center gap-2 mb-1.5">
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-brand-400">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-brand-400 opacity-75"></span>
              </span>
              <span className="text-[11px] uppercase font-black tracking-[0.2em] text-brand-400">
                Trung tâm Quản trị ShieldCall VN
              </span>
            </div>
          )}
          <h1 className="text-3xl font-black text-white tracking-tight">{title}</h1>
          {subtitle && <p className="text-sm text-slate-300 mt-1">{subtitle}</p>}
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          {actions}
          <Link
            href="/"
            className="px-4 py-2.5 rounded-xl bg-slate-900/80 border border-white/10 text-xs font-bold text-slate-300 hover:text-white hover:border-white/20 transition-all flex items-center gap-1.5"
            title="Mở trang chủ người dùng"
          >
            <i className="bi bi-box-arrow-up-right text-xs"></i>
            <span>Xem website</span>
          </Link>
          <Link
            href="/admin-cp/"
            className="px-4 py-2.5 rounded-xl bg-brand-500/10 border border-brand-500/30 text-xs font-bold text-brand-300 hover:bg-brand-500/20 hover:text-white transition-all flex items-center gap-1.5"
          >
            <i className="bi bi-speedometer2"></i>
            <span>Dashboard</span>
          </Link>
        </div>
      </div>

      {/* Unified Tab Navigation Bar */}
      <AdminNavbar />

      {/* Main Content Area */}
      {children}
    </div>
  );
}

export function StatBox({
  icon,
  label,
  value,
  grad,
  subtext,
}: {
  icon: string;
  label: string;
  value: string | number;
  grad: string;
  subtext?: string;
}) {
  return (
    <div className="relative overflow-hidden p-6 rounded-2xl bg-slate-900/80 border border-white/10 backdrop-blur-xl group hover:border-brand-500/40 transition-all shadow-lg">
      <div className="flex justify-between items-start mb-3">
        <div
          className={`w-12 h-12 rounded-xl bg-gradient-to-br ${grad} flex items-center justify-center text-white shadow-lg`}
        >
          <i className={`bi ${icon} text-xl`}></i>
        </div>
        <div className="text-right">
          <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">{label}</div>
          <div className="text-3xl font-black text-white tracking-tight mt-0.5">{value}</div>
        </div>
      </div>
      {subtext && <div className="text-[11px] text-slate-400 pt-2 border-t border-white/5">{subtext}</div>}
    </div>
  );
}

export function useAdminGet<T>(path: string | null) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(!!path);
  const [error, setError] = useState('');
  const [tick, setTick] = useState(0);
  const refetch = () => setTick((t) => t + 1);

  useEffect(() => {
    if (!path) return;
    let alive = true;
    setLoading(true);
    api
      .get<T>(path)
      .then((d) => {
        if (alive) setData(d);
      })
      .catch((e: Error) => {
        if (alive) setError(e.message);
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [path, tick]);

  return { data, loading, error, refetch };
}
