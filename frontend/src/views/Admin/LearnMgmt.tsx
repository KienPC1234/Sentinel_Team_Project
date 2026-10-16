'use client';
import { useState } from 'react';
import Link from 'next/link';
import { api } from '../../lib/api';
import { AdminShell, useAdminGet } from './_shared';

interface LessonItem {
  id: number;
  title: string;
  slug: string;
  category: string;
  summary: string;
  is_published: boolean;
  quizzes_count: number;
  scenarios_count: number;
  created_at: string;
}

export default function LearnMgmt() {
  const { data, loading, refetch } = useAdminGet<LessonItem[]>('/admin/learn/');
  const [notifyingId, setNotifyingId] = useState<number | null>(null);
  const [deletingId, setDeletingId] = useState<number | null>(null);
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null);

  const list = data || [];

  const handleNotify = async (id: number, title: string) => {
    if (!window.confirm(`Gửi thông báo email và push đến tất cả người dùng về bài học "${title}"?`)) return;
    setNotifyingId(id);
    setMsg(null);
    try {
      const res = await api.post<{ status: string; message: string }>(`/admin/learn/${id}/notify/`);
      setMsg({ text: res.message || 'Đã phát thông báo thành công.', ok: true });
    } catch (err: unknown) {
      const e = err as { message?: string };
      setMsg({ text: e.message || 'Gửi thông báo thất bại.', ok: false });
    } finally {
      setNotifyingId(null);
    }
  };

  const handleDelete = async (id: number, title: string) => {
    if (!window.confirm(`Bạn có chắc muốn xóa bài học "${title}"?`)) return;
    setDeletingId(id);
    setMsg(null);
    try {
      await api.del(`/admin/learn/${id}/`);
      setMsg({ text: `Đã xóa bài học "${title}".`, ok: true });
      refetch();
    } catch (err: unknown) {
      const e = err as { message?: string };
      setMsg({ text: e.message || 'Xóa bài học thất bại.', ok: false });
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <AdminShell
      title="Quản Lý Bài Học"
      subtitle="Nội dung giáo dục an toàn số, bài học trắc nghiệm và tình huống phòng chống lừa đảo"
      actions={
        <div className="flex items-center gap-2">
          <Link
            href="/admin-cp/learn/magic-create/"
            className="px-4 py-2.5 rounded-xl bg-purple-500/20 border border-purple-500/35 text-purple-200 text-xs font-bold hover:bg-purple-500/30 transition-all shadow-md flex items-center gap-1.5"
          >
            <i className="bi bi-stars"></i> Tạo bằng AI
          </Link>
          <Link
            href="/admin-cp/learn/add/"
            className="px-4 py-2.5 rounded-xl bg-brand-500 text-black text-xs font-black uppercase tracking-wider hover:bg-brand-400 transition-all shadow-md shadow-brand-500/20 flex items-center gap-1.5"
          >
            <i className="bi bi-plus-lg"></i> Thêm bài học mới
          </Link>
        </div>
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
              <th className="px-6 py-4 text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-white/10">Bài học</th>
              <th className="px-6 py-4 text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-white/10">Chuyên mục</th>
              <th className="px-6 py-4 text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-white/10">Trạng thái</th>
              <th className="px-6 py-4 text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-white/10">Nội dung kèm</th>
              <th className="px-6 py-4 text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-white/10">Ngày tạo</th>
              <th className="px-6 py-4 text-right text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-white/10">Thao tác</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {list.map((l) => (
              <tr key={l.id} className="hover:bg-white/[0.04] transition-all">
                <td className="px-6 py-4">
                  <div className="font-bold text-white text-base tracking-tight">{l.title}</div>
                  <div className="text-xs text-slate-400 line-clamp-1 mt-0.5">{l.summary || 'Không có tóm tắt'}</div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className="px-2.5 py-1 rounded-lg bg-slate-800 border border-white/10 text-slate-300 text-xs font-bold">
                    {l.category}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  {l.is_published ? (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-safe-500/10 border border-safe-500/20 text-xs text-safe-400 font-bold">
                      <span className="w-1.5 h-1.5 rounded-full bg-safe-400 shadow-[0_0_6px_rgba(34,197,94,0.6)]"></span> Đã xuất bản
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-white/5 border border-white/10 text-xs text-warn-400 font-bold">
                      <span className="w-1.5 h-1.5 rounded-full bg-warn-400"></span> Bản nháp
                    </span>
                  )}
                </td>
                <td className="px-6 py-4 text-xs text-slate-300 whitespace-nowrap">
                  <span className="font-bold text-white">{l.quizzes_count}</span> quiz · <span className="font-bold text-white">{l.scenarios_count}</span> kịch bản
                </td>
                <td className="px-6 py-4 text-xs text-slate-400 whitespace-nowrap">{l.created_at}</td>
                <td className="px-6 py-4 text-right whitespace-nowrap">
                  <div className="inline-flex gap-2">
                    <button
                      disabled={notifyingId === l.id}
                      onClick={() => void handleNotify(l.id, l.title)}
                      className="px-3 py-1.5 rounded-lg bg-brand-500/15 border border-brand-500/30 text-xs font-bold text-brand-300 hover:bg-brand-500 hover:text-black transition-all"
                      title="Gửi email và WebPush thông báo bài học mới"
                    >
                      <i className="bi bi-broadcast mr-1"></i> Thông báo
                    </button>
                    <Link
                      href={`/admin-cp/learn/${l.id}/edit/`}
                      className="px-3 py-1.5 rounded-lg bg-white/10 border border-white/15 text-xs font-bold text-slate-200 hover:bg-white/20 hover:text-white transition-all"
                    >
                      <i className="bi bi-pencil mr-1"></i> Sửa
                    </Link>
                    <button
                      disabled={deletingId === l.id}
                      onClick={() => void handleDelete(l.id, l.title)}
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
                <td colSpan={6} className="px-8 py-16 text-center text-slate-400 font-bold text-xs">
                  {loading ? 'Đang tải danh sách bài học...' : 'Chưa có bài học nào. Hãy tạo bài học mới hoặc dùng Magic Create AI.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </AdminShell>
  );
}
