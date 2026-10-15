'use client';
import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { api } from '../../lib/api';
import type { Paged } from '../../lib/api';
import { Spinner } from '../../components/ui';

interface MyReport {
  id: number;
  target_type: string;
  target_value: string;
  status?: string;
  scam_type?: string;
  scam_type_display?: string;
  severity?: string;
  description?: string;
  created_at?: string;
  moderation_note?: string;
}

type StatusFilter = '' | 'pending' | 'approved' | 'rejected';

export default function MyReports() {
  const [reports, setReports] = useState<MyReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('');

  useEffect(() => {
    api
      .get<Paged<MyReport> | MyReport[]>('/user/reports/')
      .then((r) => setReports(Array.isArray(r) ? r : r.results || []))
      .catch(() => setReports([]))
      .finally(() => setLoading(false));
  }, []);

  const filtered = useMemo(() => (statusFilter ? reports.filter((r) => r.status === statusFilter) : reports), [reports, statusFilter]);
  const stats = useMemo(
    () => ({
      total: reports.length,
      pending: reports.filter((r) => r.status === 'pending').length,
      approved: reports.filter((r) => r.status === 'approved').length,
      rejected: reports.filter((r) => r.status === 'rejected').length,
    }),
    [reports],
  );

  const iconFor = (t: string): string => {
    if (t === 'phone') return 'bi-telephone-fill';
    if (t === 'domain') return 'bi-globe';
    if (t === 'account') return 'bi-bank';
    if (t === 'email') return 'bi-envelope-fill';
    if (t === 'file') return 'bi-file-earmark-binary';
    if (t === 'social') return 'bi-telegram';
    if (t === 'crypto') return 'bi-coin';
    if (t === 'audio') return 'bi-mic-fill';
    return 'bi-chat-dots-fill';
  };

  return (
    <div className="max-w-6xl mx-auto px-4 py-10 space-y-8">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div className="flex items-center gap-5">
          <div className="w-16 h-16 rounded-2xl bg-danger-500/10 border border-danger-500/20 flex items-center justify-center">
            <i className="bi bi-flag-fill text-danger-500 text-2xl"></i>
          </div>
          <div>
            <h1 className="text-3xl font-black text-white tracking-tight">Báo cáo của tôi</h1>
            <p className="text-[10px] font-bold text-white/35 uppercase tracking-widest mt-1">Theo dõi trạng thái các báo cáo lừa đảo bạn đã gửi</p>
          </div>
        </div>
        <Link href="/report/" className="inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-danger-500 text-black font-black text-xs uppercase tracking-widest hover:bg-danger-400 transition-all">
          <i className="bi bi-plus-lg"></i> Gửi báo cáo mới
        </Link>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { v: stats.total, l: 'Tổng báo cáo', icon: 'bi-file-earmark-text', cls: 'text-white' },
          { v: stats.pending, l: 'Chờ duyệt', icon: 'bi-clock', cls: 'text-warn-400' },
          { v: stats.approved, l: 'Đã duyệt', icon: 'bi-check-circle', cls: 'text-safe-400' },
          { v: stats.rejected, l: 'Từ chối', icon: 'bi-x-circle', cls: 'text-danger-400' },
        ].map((s) => (
          <div key={s.l} className="rounded-2xl border border-white/10 bg-white/[0.02] p-5 text-center space-y-2">
            <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center mx-auto">
              <i className={`bi ${s.icon} text-white/55`}></i>
            </div>
            <p className={`text-2xl font-black ${s.cls}`}>{s.v}</p>
            <p className="text-[9px] font-bold text-white/45 uppercase tracking-widest">{s.l}</p>
          </div>
        ))}
      </div>

      <div className="flex items-center gap-2 flex-wrap">
        {[
          { v: '' as StatusFilter, l: 'Tất cả', i: '' },
          { v: 'pending' as StatusFilter, l: 'Chờ duyệt', i: 'bi-clock' },
          { v: 'approved' as StatusFilter, l: 'Đã duyệt', i: 'bi-check-circle' },
          { v: 'rejected' as StatusFilter, l: 'Từ chối', i: 'bi-x-circle' },
        ].map((f) => (
          <button key={f.l} onClick={() => setStatusFilter(f.v)}
            className={`px-4 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all border ${statusFilter === f.v ? 'bg-white/10 text-white border-white/20' : 'text-white/55 border-transparent hover:bg-white/5'}`}>
            {f.i && <i className={`bi ${f.i} mr-1`}></i>}{f.l}
          </button>
        ))}
      </div>

      {loading ? (
        <Spinner />
      ) : (
        <div className="space-y-4">
          {filtered.map((report) => (
            <div key={report.id} className="rounded-2xl border border-white/10 bg-white/[0.02] p-6 hover:border-white/15 transition-all group">
              <div className="flex flex-col lg:flex-row lg:items-center gap-4">
                <div className="flex-1 min-w-0 space-y-3">
                  <div className="flex items-center gap-3 flex-wrap">
                    <span className={`text-[9px] font-black uppercase tracking-widest px-2 py-1 rounded-lg border ${report.status === 'pending' ? 'bg-warn-500/10 text-warn-500 border-warn-500/20' : report.status === 'approved' ? 'bg-safe-500/10 text-safe-400 border-safe-500/20' : 'bg-danger-500/10 text-danger-400 border-danger-500/20'}`}>
                      {report.status === 'pending' ? 'Chờ duyệt' : report.status === 'approved' ? 'Đã duyệt' : 'Từ chối'}
                    </span>
                    <span className="inline-flex items-center gap-1.5 text-[8px] font-black text-white/60 uppercase tracking-widest px-2 py-1 bg-white/5 rounded-lg border border-white/10">
                      <i className={`bi ${iconFor(report.target_type)} text-brand-400`}></i> {report.target_type}
                    </span>
                    <span className="text-[9px] font-bold text-white/35">{report.created_at ? new Date(report.created_at).toLocaleDateString('vi-VN') : ''}</span>
                  </div>
                  <div className="text-lg font-black text-white tracking-tight">{report.target_value}</div>
                  <p className="text-xs text-white/55 line-clamp-2 leading-relaxed">{(report.description || '').replace(/<[^>]*>/g, '').slice(0, 200)}</p>
                  {(report.scam_type_display || report.severity) && (
                    <div className="flex items-center gap-2">
                      <span className="text-[9px] font-bold text-brand-400/60 uppercase tracking-widest">{report.scam_type_display || report.severity}</span>
                      {report.severity && <span className="text-[8px] font-bold px-2 py-0.5 rounded bg-white/5 text-white/60">{report.severity.toUpperCase()}</span>}
                    </div>
                  )}
                </div>
              </div>
              {report.moderation_note && (
                <div className="mt-4 p-4 rounded-xl bg-white/[0.02] border border-white/5">
                  <p className="text-[9px] font-black text-white/35 uppercase tracking-widest mb-1">Ghi chú kiểm duyệt</p>
                  <p className="text-xs text-white/60">{report.moderation_note}</p>
                </div>
              )}
            </div>
          ))}
          {filtered.length === 0 && (
            <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-16 text-center space-y-4">
              <div className="w-20 h-20 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center mx-auto">
                <i className="bi bi-inbox text-3xl text-white/20"></i>
              </div>
              <p className="text-white/35 font-bold">Bạn chưa gửi báo cáo nào{statusFilter ? ' với trạng thái này' : ''}.</p>
              <Link href="/report/" className="inline-flex items-center gap-2 text-brand-400 text-sm font-bold hover:text-white transition-colors">
                <i className="bi bi-plus-circle"></i> Gửi báo cáo đầu tiên
              </Link>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
