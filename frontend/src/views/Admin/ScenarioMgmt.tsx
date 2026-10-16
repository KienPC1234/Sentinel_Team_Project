'use client';
import { useState } from 'react';
import Link from 'next/link';
import { api } from '../../lib/api';
import { AdminShell, useAdminGet } from './_shared';

interface ScenarioItem {
  id: number;
  title: string;
  description: string;
  article_id: number | null;
  article_title: string | null;
  lesson_id: number | null;
  lesson_title: string | null;
  steps_count: number;
  created_at: string;
}

export function ScenarioMgmt() {
  const { data, loading, refetch } = useAdminGet<ScenarioItem[]>('/admin/scenarios/');
  const [deletingId, setDeletingId] = useState<number | null>(null);
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null);

  const list = data || [];

  const handleDelete = async (id: number, title: string) => {
    if (!window.confirm(`Bạn có chắc chắn muốn xóa kịch bản "${title}"?`)) return;
    setDeletingId(id);
    setMsg(null);
    try {
      await api.del(`/admin/scenarios/${id}/`);
      setMsg({ text: `Đã xóa kịch bản "${title}"`, ok: true });
      refetch();
    } catch (err: unknown) {
      const e = err as { message?: string };
      setMsg({ text: e.message || 'Xóa kịch bản thất bại', ok: false });
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <AdminShell
      title="Kịch Bản Mô Phỏng"
      subtitle="Thiết kế và quản lý các tình huống giả định Scam IQ tương tác cho người dùng"
      actions={
        <Link
          href="/admin-cp/scenarios/add/"
          className="px-4 py-2.5 rounded-xl bg-brand-500 text-black text-xs font-black uppercase tracking-wider hover:bg-brand-400 transition-all shadow-md shadow-brand-500/20 flex items-center gap-1.5"
        >
          <i className="bi bi-plus-lg"></i> Thêm kịch bản mới
        </Link>
      }
    >
      {msg && (
        <div className={`p-4 rounded-xl mb-6 text-xs font-bold border ${msg.ok ? 'bg-safe-500/15 border-safe-500/30 text-safe-300' : 'bg-danger-500/15 border-danger-500/30 text-danger-300'}`}>
          {msg.text}
        </div>
      )}

      <div className="overflow-x-auto rounded-3xl border border-white/10 bg-slate-900/90 shadow-2xl">
        <table className="w-full text-sm text-left border-separate border-spacing-0">
          <thead className="bg-white/[0.03]">
            <tr>
              <th className="px-6 py-4 text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-white/10">Kịch bản</th>
              <th className="px-6 py-4 text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-white/10">Liên kết</th>
              <th className="px-6 py-4 text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-white/10">Số bước</th>
              <th className="px-6 py-4 text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-white/10">Ngày tạo</th>
              <th className="px-6 py-4 text-right text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-white/10">Thao tác</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {list.map((s) => (
              <tr key={s.id} className="hover:bg-white/[0.04] transition-all">
                <td className="px-6 py-4">
                  <div className="font-bold text-white text-base tracking-tight">{s.title}</div>
                  <div className="text-xs text-slate-400 line-clamp-1 mt-0.5">{s.description || 'Không có mô tả'}</div>
                </td>
                <td className="px-6 py-4 text-xs whitespace-nowrap">
                  {s.lesson_title ? (
                    <span className="px-2.5 py-1 rounded-lg bg-brand-500/10 border border-brand-500/20 text-brand-300 font-bold">
                      Bài học: {s.lesson_title}
                    </span>
                  ) : s.article_title ? (
                    <span className="px-2.5 py-1 rounded-lg bg-purple-500/10 border border-purple-500/20 text-purple-300 font-bold">
                      Tin tức: {s.article_title}
                    </span>
                  ) : (
                    <span className="px-2.5 py-1 rounded-lg bg-slate-800 text-slate-400 font-medium">Độc lập</span>
                  )}
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className="px-2.5 py-1 rounded-lg bg-slate-800 border border-white/10 text-slate-200 text-xs font-bold">
                    {s.steps_count} bước
                  </span>
                </td>
                <td className="px-6 py-4 text-xs text-slate-400 whitespace-nowrap">{s.created_at}</td>
                <td className="px-6 py-4 text-right whitespace-nowrap">
                  <div className="inline-flex gap-2">
                    <Link
                      href={`/admin-cp/scenarios/${s.id}/edit/`}
                      className="px-3 py-1.5 rounded-lg bg-white/10 border border-white/15 text-xs font-bold text-slate-200 hover:bg-brand-500 hover:text-black transition-all"
                    >
                      <i className="bi bi-pencil mr-1"></i> Sửa
                    </Link>
                    <button
                      disabled={deletingId === s.id}
                      onClick={() => void handleDelete(s.id, s.title)}
                      className="px-3 py-1.5 rounded-lg bg-danger-500/15 border border-danger-500/30 text-xs font-bold text-danger-300 hover:bg-danger-500 hover:text-white transition-all disabled:opacity-50"
                    >
                      <i className="bi bi-trash mr-1"></i> Xóa
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {list.length === 0 && (
              <tr>
                <td colSpan={5} className="px-8 py-16 text-center text-slate-400 font-bold text-xs">
                  {loading ? 'Đang tải danh sách kịch bản...' : 'Chưa có kịch bản mô phỏng nào được tạo.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </AdminShell>
  );
}
