'use client';
/* Port từ PKV/templates/Scan/scan_lookup.html — Trung tâm Scan + tra cứu lịch sử.
 * API: GET /api/v1/scan/lookup/?q=&type=&risk=&page= → {results, total, page, per_page, has_next}.
 * Lưu ý: API không trả type_counts nên chip lọc không kèm số lượng như bản gốc.
 */
import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { api } from '../../lib/api';

import { Spinner } from '../../components/ui';
import { parseSafeDate } from '../../lib/date';

interface LookupItem {
  id: number;
  kind?: string;
  type?: string;
  type_display?: string;
  target?: string;
  risk_score?: number;
  risk_level?: string;
  risk_display?: string;
  verdict_tone?: string;
  created_at?: string;
  time_ago?: string;
  url?: string;
}

interface LookupPayload {
  results?: LookupItem[];
  total?: number;
  page?: number;
  per_page?: number;
  has_next?: boolean;
}

const TYPE_CHIPS: { code: string; label: string }[] = [
  { code: 'all', label: 'Tất cả' },
  { code: 'phone', label: 'Số điện thoại' },
  { code: 'account', label: 'Tài khoản NH' },
  { code: 'domain', label: 'Website/URL' },
  { code: 'email', label: 'Email' },
  { code: 'message', label: 'Tin nhắn' },
  { code: 'audio', label: 'Âm thanh' },
  { code: 'file', label: 'Tệp tin' },
  { code: 'qr', label: 'QR / Ảnh' },
];

const HUB_CARDS: { to: string; icon: string; color: string; border: string; label: string }[] = [
  { to: '/scan/phone/', icon: 'bi-telephone', color: 'text-brand-400', border: 'border-brand-500/20', label: 'Số điện thoại' },
  { to: '/scan/bank/', icon: 'bi-bank2', color: 'text-warn-400', border: 'border-warn-500/20', label: 'Tài khoản NH' },
  { to: '/scan/website/', icon: 'bi-globe2', color: 'text-brand-400', border: 'border-brand-500/20', label: 'Website/URL' },
  { to: '/scan/email/', icon: 'bi-envelope', color: 'text-brand2-400', border: 'border-brand2-500/20', label: 'Email' },
  { to: '/scan/message/', icon: 'bi-chat-left-text', color: 'text-safe-400', border: 'border-safe-500/20', label: 'Tin nhắn' },
  { to: '/scan/audio/', icon: 'bi-soundwave', color: 'text-brand2-400', border: 'border-brand2-500/20', label: 'Âm thanh' },
  { to: '/scan/file/', icon: 'bi-file-earmark-zip', color: 'text-warn-400', border: 'border-warn-500/20', label: 'Tệp tin' },
  { to: '/scan/qr/', icon: 'bi-qr-code', color: 'text-danger-400', border: 'border-danger-500/20', label: 'QR / Ảnh' },
];

function riskClass(level?: string): string {
  if (level === 'RED') return 'text-danger-400';
  if (level === 'YELLOW') return 'text-warn-400';
  if (level === 'GREEN' || level === 'SAFE') return 'text-safe-400';
  if (level === 'UNVERIFIED') return 'text-slate-300';
  return 'text-brand-300';
}

function fmtDate(iso?: string): string {
  const d = parseSafeDate(iso);
  if (!d) return '';
  const p = (n: number): string => String(n).padStart(2, '0');
  return `${p(d.getDate())}/${p(d.getMonth() + 1)}/${d.getFullYear()} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

export default function Lookup() {
  const [q, setQ] = useState('');
  const [type, setType] = useState('all');
  const [page, setPage] = useState(1);
  const [items, setItems] = useState<LookupItem[]>([]);
  const [total, setTotal] = useState(0);
  const [hasNext, setHasNext] = useState(false);
  const [loading, setLoading] = useState(true);
  const [hydrated, setHydrated] = useState(false);

  // Đọc query string sau mount (SSR-safe) rồi mới fetch.
  useEffect(() => {
    const sp = new URLSearchParams(window.location.search);
    setQ(sp.get('q') || '');
    setType(sp.get('type') || 'all');
    setHydrated(true);
  }, []);

  const fetchLookup = useCallback((query: string, t: string, p: number) => {
    setLoading(true);
    const params = new URLSearchParams();
    if (query.trim()) params.set('q', query.trim());
    if (t && t !== 'all') params.set('type', t);
    params.set('page', String(p));
    api
      .get<LookupPayload>(`/scan/lookup/?${params.toString()}`)
      .then((data) => {
        setItems(Array.isArray(data.results) ? data.results : []);
        setTotal(typeof data.total === 'number' ? data.total : 0);
        setHasNext(data.has_next === true);
        setLoading(false);
      })
      .catch(() => {
        setItems([]);
        setTotal(0);
        setHasNext(false);
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    if (!hydrated) return;
    fetchLookup(q, type, page);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hydrated]);

  const submitSearch = (e: React.FormEvent): void => {
    e.preventDefault();
    setPage(1);
    fetchLookup(q, type, 1);
  };

  const pickType = (code: string): void => {
    setType(code);
    setPage(1);
    fetchLookup(q, code, 1);
  };

  const clearFilter = (): void => {
    setQ('');
    setType('all');
    setPage(1);
    fetchLookup('', 'all', 1);
  };

  const goPage = (p: number): void => {
    setPage(p);
    fetchLookup(q, type, p);
  };

  return (
    <div className="max-w-6xl mx-auto px-4 space-y-8 animate-fadein">
      <div className="text-center space-y-4">
        <div className="relative inline-block">
          <div className="absolute inset-0 bg-brand-500 blur-3xl opacity-20 rounded-full scale-150"></div>
          <div className="relative inline-flex items-center justify-center w-20 h-20 rounded-[2rem] bg-brand-500/10 text-brand-400 border border-brand-500/20 shadow-lg shadow-brand-500/10">
            <i className="bi bi-grid-3x3-gap-fill text-4xl"></i>
          </div>
        </div>
        <h1 className="text-4xl font-black text-white tracking-tight leading-none">
          Trung tâm <span className="glow-text text-brand-400">Scan</span>
        </h1>
        <p className="text-white/55 max-w-lg mx-auto text-sm leading-relaxed">
          Chọn nhanh tính năng bạn cần để quét và phân tích rủi ro lừa đảo.
        </p>
      </div>

      <div className="space-y-6 pt-4">
        <h3 className="text-[10px] font-black text-white/35 uppercase tracking-[0.2em] text-center">Tính năng scan</h3>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {HUB_CARDS.map((c) => (
            <Link key={c.to} href={c.to} className="liquid-card p-5 text-center hover:bg-white/[0.04] transition-all group">
              <div className={`w-12 h-12 rounded-xl bg-brand-500/10 flex items-center justify-center ${c.color} border ${c.border} mx-auto mb-3 group-hover:scale-110 transition-transform`}>
                <i className={`bi ${c.icon} text-xl`}></i>
              </div>
              <div className="text-xs font-black text-white/70 group-hover:text-white transition-colors">{c.label}</div>
            </Link>
          ))}
        </div>
        <div className="pt-2 flex flex-col sm:flex-row items-center justify-center gap-3">
          <Link href="/scan/lookup/" className="text-xs font-black uppercase tracking-widest text-brand-400 hover:text-brand-300 transition-colors">
            Mở tra cứu lịch sử scan
          </Link>
          <span className="hidden sm:inline text-white/35">•</span>
          <Link href="/scam-radar/" className="text-xs font-black uppercase tracking-widest text-white/55 hover:text-white/70 transition-colors">
            Xem Scam Radar
          </Link>
        </div>
      </div>


      <div className="liquid-card p-6 space-y-5">
        <form onSubmit={submitSearch} className="grid grid-cols-1 sm:grid-cols-[1fr_auto] gap-3">
          <div className="relative">
            <i className="bi bi-search absolute left-3.5 top-1/2 -translate-y-1/2 text-white/35 pointer-events-none z-10"></i>
            <input
              type="text"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Nhập từ khóa để tra cứu lịch sử scan..."
              className="w-full h-11 pl-10 pr-3 rounded-xl bg-white/[0.03] border border-white/10 text-white text-sm placeholder:text-white/35 focus:outline-none focus:border-brand-500/40"
            />
          </div>
          <button type="submit" className="h-11 px-5 rounded-xl bg-brand-500 text-black text-sm font-black hover:bg-brand-400 transition-colors">
            Tra cứu
          </button>
        </form>

        <div className="flex flex-wrap items-center justify-between gap-3">
          <h3 className="text-sm font-black text-white uppercase tracking-wider">Bảng tra cứu scan theo loại</h3>
          <button type="button" onClick={clearFilter} className="text-[11px] font-bold text-brand-300 hover:text-brand-200">
            Xóa bộ lọc
          </button>
        </div>

        <div className="flex flex-wrap gap-2">
          {TYPE_CHIPS.map((t) => (
            <button
              key={t.code}
              type="button"
              onClick={() => pickType(t.code)}
              className={`px-3 py-1.5 rounded-lg text-[11px] font-black border ${
                type === t.code || (t.code === 'all' && !type)
                  ? 'bg-brand-500/20 text-brand-300 border-brand-500/30'
                  : 'bg-white/5 text-white/60 border-white/10 hover:border-brand-500/30'
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        <div className="overflow-x-auto rounded-2xl border border-white/10">
          <table className="w-full text-sm">
            <thead className="bg-white/[0.03]">
              <tr>
                <th className="px-4 py-3 text-left text-[10px] font-black uppercase tracking-widest text-white/45">Thời gian</th>
                <th className="px-4 py-3 text-left text-[10px] font-black uppercase tracking-widest text-white/45">Loại scan</th>
                <th className="px-4 py-3 text-left text-[10px] font-black uppercase tracking-widest text-white/45">Nội dung</th>
                <th className="px-4 py-3 text-left text-[10px] font-black uppercase tracking-widest text-white/45">Rủi ro</th>
                <th className="px-4 py-3 text-left text-[10px] font-black uppercase tracking-widest text-white/45">Chi tiết</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={5} className="px-4 py-8">
                    <Spinner />
                  </td>
                </tr>
              ) : items.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-white/55 text-sm">
                    Chưa có dữ liệu scan cho bộ lọc hiện tại.
                  </td>
                </tr>
              ) : (
                items.map((s) => (
                  <tr key={`${s.kind || 'scan'}-${s.id}`} className="border-t border-white/5 hover:bg-white/[0.02] transition-colors">
                    <td className="px-4 py-3 text-white/60 text-[12px]">{s.time_ago || fmtDate(s.created_at)}</td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-1 rounded-lg bg-white/5 border border-white/10 text-[11px] font-bold text-white/75">
                        {s.type_display || s.type}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-white/75 max-w-[320px] truncate" title={s.target || ''}>
                      {s.target || '(trống)'}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-[11px] font-black ${riskClass(s.verdict_tone || s.risk_level)}`}>
                        {s.risk_display || s.risk_level} • {s.risk_score ?? 0}/100
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      {s.kind === 'report' ? (
                        <Link href={s.url || '/scam-radar/'} className="text-brand-300 text-[11px] font-black hover:text-brand-200">
                          Mở kết quả
                        </Link>
                      ) : (

                        <Link href={`/scan/status/${s.id}/`} className="text-brand-300 text-[11px] font-black hover:text-brand-200">
                          Mở kết quả
                        </Link>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {!loading && total > 0 && (
          <div className="flex items-center justify-between gap-3 text-xs text-white/55">
            <span>Tổng {total} kết quả — trang {page}</span>
            <div className="flex gap-2">
              <button
                type="button"
                disabled={page <= 1}
                onClick={() => goPage(page - 1)}
                className="px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 font-bold disabled:opacity-40 hover:border-brand-500/30"
              >
                Trước
              </button>
              <button
                type="button"
                disabled={!hasNext}
                onClick={() => goPage(page + 1)}
                className="px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 font-bold disabled:opacity-40 hover:border-brand-500/30"
              >
                Sau
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
