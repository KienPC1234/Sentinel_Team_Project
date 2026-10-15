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
    <AdminShell title="Quản Lý Kịch Bản" subtitle="Tình huống mô phỏng Scam IQ tương tác">
      {msg && (
        <div className={`p-4 rounded-xl mb-4 text-xs font-bold border ${msg.ok ? 'bg-safe-500/10 border-safe-500/20 text-safe-300' : 'bg-danger-500/10 border-danger-500/20 text-danger-300'}`}>
          {msg.text}
        </div>
      )}

      <div className="flex flex-wrap gap-2 mb-6">
        <Link href="/admin-cp/scenarios/add/" className="px-4 py-2.5 rounded-xl bg-brand-500 text-black text-xs font-black uppercase tracking-wider hover:bg-brand-400 transition-all">
          <i className="bi bi-plus-lg mr-1.5"></i> Thêm kịch bản mới
        </Link>
      </div>

      <div className="overflow-x-auto rounded-2xl border border-white/10">
        <table className="w-full text-sm">
          <thead className="bg-white/[0.03]">
            <tr>
              <th className="px-4 py-3 text-left text-[11px] font-black text-white/60 uppercase">Kịch bản</th>
              <th className="px-4 py-3 text-left text-[11px] font-black text-white/60 uppercase">Liên kết</th>
              <th className="px-4 py-3 text-left text-[11px] font-black text-white/60 uppercase">Số bước</th>
              <th className="px-4 py-3 text-left text-[11px] font-black text-white/60 uppercase">Ngày tạo</th>
              <th className="px-4 py-3 text-right text-[11px] font-black text-white/60 uppercase">Thao tác</th>
            </tr>
          </thead>
          <tbody>
            {list.map((s) => (
              <tr key={s.id} className="border-t border-white/5 hover:bg-white/[0.02]">
                <td className="px-4 py-3">
                  <div className="font-bold text-white">{s.title}</div>
                  <div className="text-xs text-white/55 line-clamp-1">{s.description || 'Không có mô tả'}</div>
                </td>
                <td className="px-4 py-3 text-xs text-white/60">
                  {s.lesson_title ? (
                    <span className="text-brand-300 font-bold">Bài học: {s.lesson_title}</span>
                  ) : s.article_title ? (
                    <span className="text-brand2-300 font-bold">Tin tức: {s.article_title}</span>
                  ) : (
                    <span className="text-white/45">Độc lập</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  <span className="px-2.5 py-1 rounded-lg bg-white/5 border border-white/10 text-white/70 text-xs font-bold">
                    {s.steps_count} bước
                  </span>
                </td>
                <td className="px-4 py-3 text-xs text-white/55">{s.created_at}</td>
                <td className="px-4 py-3 text-right">
                  <div className="inline-flex gap-2">
                    <Link
                      href={`/admin-cp/scenarios/${s.id}/edit/`}
                      className="px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-xs font-bold text-brand-300 hover:bg-white/10 transition-all"
                    >
                      <i className="bi bi-pencil mr-1"></i> Sửa
                    </Link>
                    <button
                      disabled={deletingId === s.id}
                      onClick={() => void handleDelete(s.id, s.title)}
                      className="px-3 py-1.5 rounded-lg bg-danger-500/15 border border-danger-500/30 text-xs font-bold text-danger-300 hover:bg-danger-500/25 transition-all disabled:opacity-50"
                    >
                      <i className="bi bi-trash mr-1"></i> Xóa
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {loading && <p className="text-white/55 text-sm mt-4">Đang tải danh sách kịch bản...</p>}
      {!loading && list.length === 0 && (
        <div className="liquid-card p-8 text-center text-white/35 text-sm mt-4">
          Chưa có kịch bản nào được tạo.
        </div>
      )}
    </AdminShell>
  );
}
