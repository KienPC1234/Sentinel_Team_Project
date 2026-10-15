'use client';
import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import Link from 'next/link';
import { api } from '../../lib/api';

/* Khung chung cụm Admin (port từ PKV/templates/Admin/*). */

export const ADMIN_LINKS: Array<{ to: string; label: string; icon: string }> = [
  { to: '/admin-cp/', label: 'Dashboard', icon: 'bi-speedometer2' },
  { to: '/admin-cp/reports/', label: 'Báo cáo', icon: 'bi-flag' },
  { to: '/admin-cp/users/', label: 'Người dùng', icon: 'bi-people' },
  { to: '/admin-cp/articles/', label: 'Bài viết', icon: 'bi-journal-text' },
  { to: '/admin-cp/scenarios/', label: 'Kịch bản', icon: 'bi-diagram-3' },
  { to: '/admin-cp/learn/', label: 'Bài học', icon: 'bi-mortarboard' },
  { to: '/admin-cp/forum/', label: 'Diễn đàn', icon: 'bi-chat-square-dots' },
  { to: '/admin-cp/tickets/', label: 'Tickets', icon: 'bi-ticket' },
];

export function AdminShell({ title, subtitle, children }: { title: string; subtitle?: string; children: ReactNode }) {
  return (
    <div className="container mx-auto px-4 py-8 mt-16 max-w-7xl">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-8 gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="relative inline-flex rounded-full h-2 w-2 bg-brand-500"></span>
            <span className="text-[10px] uppercase font-black tracking-[0.2em] text-brand-500/60">Quản trị ShieldCall VN</span>
          </div>
          <h1 className="text-3xl font-black text-white tracking-tight">{title}</h1>
          {subtitle && <p className="text-sm text-white/55 mt-1">{subtitle}</p>}
        </div>
        <Link href="/admin-cp/" className="px-4 py-2 rounded-xl bg-white/5 border border-white/10 text-xs font-bold text-white/70 hover:text-white">← Dashboard</Link>
      </div>
      <div className="flex flex-wrap gap-2 mb-8">
        {ADMIN_LINKS.map((l) => (
          <Link key={l.to} href={l.to} className="px-3 py-1.5 rounded-lg bg-white/[0.03] border border-white/10 text-[11px] font-bold text-white/60 hover:text-brand-300 hover:border-brand-500/30 transition-all"><i className={`bi ${l.icon} mr-1.5`}></i>{l.label}</Link>
        ))}
      </div>
      {children}
    </div>
  );
}

export function StatBox({ icon, label, value, grad }: { icon: string; label: string; value: string | number; grad: string }) {
  return (
    <div className="relative overflow-hidden p-6 rounded-[2rem] bg-slate-900/40 border border-white/5 backdrop-blur-xl group">
      <div className="flex justify-between items-start mb-4">
        <div className={`w-12 h-12 rounded-2xl bg-gradient-to-br ${grad} flex items-center justify-center text-white shadow-lg`}><i className={`bi ${icon} text-xl`}></i></div>
        <div className="text-right">
          <div className="text-[10px] font-black text-white/45 uppercase tracking-[0.1em]">{label}</div>
          <div className="text-4xl font-black text-white tracking-tighter">{value}</div>
        </div>
      </div>
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
    api.get<T>(path)
      .then((d) => { if (alive) setData(d); })
      .catch((e: Error) => { if (alive) setError(e.message); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [path, tick]);

  return { data, loading, error, refetch };
}
