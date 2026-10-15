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
    <AdminShell title="Quản Lý Bài Học" subtitle="Nội dung giáo dục an toàn số và tình huống phòng chống lừa đảo">
      {msg && (
        <div className={`p-4 rounded-xl mb-4 text-xs font-bold border ${msg.ok ? 'bg-safe-500/10 border-safe-500/20 text-safe-300' : 'bg-danger-500/10 border-danger-500/20 text-danger-300'}`}>
          {msg.text}
        </div>
      )}

      <div className="flex flex-wrap gap-2 mb-6">
        <Link href="/admin-cp/learn/magic-create/" className="px-4 py-2.5 rounded-xl bg-brand2-500/15 border border-brand2-500/30 text-brand2-200 text-xs font-bold hover:bg-brand2-500/25 transition-all">
          <i className="bi bi-magic mr-1.5"></i> Tạo bằng AI
        </Link>
        <Link href="/admin-cp/learn/add/" className="px-4 py-2.5 rounded-xl bg-brand-500 text-black text-xs font-black uppercase tracking-wider hover:bg-brand-400 transition-all">
          <i className="bi bi-plus-lg mr-1.5"></i> Thêm bài học mới
        </Link>
      </div>

      <div className="overflow-x-auto rounded-2xl border border-white/10">
        <table className="w-full text-sm">
          <thead className="bg-white/[0.03]">
            <tr>
              <th className="px-4 py-3 text-left text-[11px] font-black text-white/60 uppercase">Bài học</th>
              <th className="px-4 py-3 text-left text-[11px] font-black text-white/60 uppercase">Chuyên mục</th>
              <th className="px-4 py-3 text-left text-[11px] font-black text-white/60 uppercase">Trạng thái</th>
              <th className="px-4 py-3 text-left text-[11px] font-black text-white/60 uppercase">Nội dung kèm</th>
              <th className="px-4 py-3 text-left text-[11px] font-black text-white/60 uppercase">Ngày tạo</th>
              <th className="px-4 py-3 text-right text-[11px] font-black text-white/60 uppercase">Thao tác</th>
            </tr>
          </thead>
          <tbody>
            {list.map((l) => (
              <tr key={l.id} className="border-t border-white/5 hover:bg-white/[0.02]">
                <td className="px-4 py-3">
                  <div className="font-bold text-white">{l.title}</div>
                  <div className="text-xs text-white/55 line-clamp-1">{l.summary || 'Không có tóm tắt'}</div>
                </td>
                <td className="px-4 py-3">
                  <span className="px-2.5 py-1 rounded-lg bg-white/5 border border-white/10 text-white/70 text-xs font-bold">
                    {l.category}
                  </span>
                </td>
                <td className="px-4 py-3">
                  {l.is_published ? (
                    <span className="inline-flex items-center gap-1.5 text-xs text-safe-400 font-bold">
                      <span className="w-1.5 h-1.5 rounded-full bg-safe-400"></span> Đã xuất bản
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1.5 text-xs text-warn-400 font-bold">
                      <span className="w-1.5 h-1.5 rounded-full bg-warn-400"></span> Bản nháp
                    </span>
                  )}
                </td>
                <td className="px-4 py-3 text-xs text-white/60">
                  <span>{l.quizzes_count} câu quiz</span> · <span>{l.scenarios_count} kịch bản</span>
                </td>
                <td className="px-4 py-3 text-xs text-white/55">{l.created_at}</td>
                <td className="px-4 py-3 text-right">
                  <div className="inline-flex gap-2">
                    <button
                      disabled={notifyingId === l.id}
                      onClick={() => void handleNotify(l.id, l.title)}
                      className="px-2.5 py-1.5 rounded-lg bg-brand-500/10 border border-brand-500/20 text-xs font-bold text-brand-300 hover:bg-brand-500/20 transition-all"
                      title="Gửi email và push thông báo bài học mới"
                    >
                      <i className="bi bi-broadcast mr-1"></i> Thông báo
                    </button>
                    <Link
                      href={`/admin-cp/learn/${l.id}/edit/`}
                      className="px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-xs font-bold text-white/80 hover:bg-white/10 transition-all"
                    >
                      <i className="bi bi-pencil mr-1"></i> Sửa
                    </Link>
                    <button
                      disabled={deletingId === l.id}
                      onClick={() => void handleDelete(l.id, l.title)}
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

      {loading && <p className="text-white/55 text-sm mt-4">Đang tải danh sách bài học...</p>}
      {!loading && list.length === 0 && (
        <div className="liquid-card p-8 text-center text-white/35 text-sm mt-4">
          Chưa có bài học nào được tạo.
        </div>
      )}
    </AdminShell>
  );
}
