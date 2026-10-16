'use client';
import { useState } from 'react';
import Link from 'next/link';
import { api, mediaUrl } from '../../lib/api';
import { AdminShell, useAdminGet } from './_shared';

/* Port 1-1 từ PKV/templates/Admin/article_management.html.
 * API: GET /admin/articles/ -> [{id,title,slug,category,category_display,summary,is_published,cover_image,author_name,created_at}] */

interface AdminArticle {
  id: number;
  title: string;
  slug: string;
  category: string;
  category_display?: string;
  summary: string;
  is_published: boolean;
  cover_image: string | null;
  author_name?: string;
  created_at: string;
  source_type?: string;
  source_type_display?: string;
  source_url?: string;
}

export default function ArticleMgmt() {
  const { data, loading, refetch } = useAdminGet<AdminArticle[]>('/admin/articles/');
  const [deletingId, setDeletingId] = useState<number | null>(null);
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null);

  const articles = data || [];

  const handleDelete = async (id: number) => {
    if (!window.confirm('Bạn có chắc chắn muốn xóa bài viết này?')) return;
    setDeletingId(id);
    setMsg(null);
    try {
      await api.del(`/admin/articles/${id}/`);
      setMsg({ text: 'Đã xóa bài viết thành công.', ok: true });
      refetch();
    } catch (err: unknown) {
      const e = err as { message?: string };
      setMsg({ text: e.message || 'Xóa bài viết thất bại.', ok: false });
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <AdminShell
      title="Tin Tức & Cảnh Báo"
      subtitle="Quản lý bài viết cảnh báo an ninh mạng, biên tập nội dung và nguồn tin Tín nhiệm mạng"
      actions={
        <div className="flex items-center gap-2">
          <Link
            href="/admin-cp/articles/magic-create/"
            className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-brand2-600 to-brand-600 text-white font-bold text-xs uppercase tracking-wider hover:opacity-95 transition-all shadow-md flex items-center gap-1.5"
          >
            <i className="bi bi-stars"></i>
            <span>Magic Create</span>
          </Link>
          <Link
            href="/admin-cp/articles/add/"
            className="px-4 py-2.5 rounded-xl bg-brand-500 text-black font-black text-xs uppercase tracking-wider hover:bg-brand-400 transition-all shadow-md shadow-brand-500/20 flex items-center gap-1.5"
          >
            <i className="bi bi-plus-lg"></i>
            <span>Bài viết mới</span>
          </Link>
        </div>
      }
    >
      {msg && (
        <div
          className={`p-4 rounded-xl mb-6 text-xs font-bold border ${
            msg.ok ? 'bg-safe-500/15 border-safe-500/30 text-safe-300' : 'bg-danger-500/15 border-danger-500/30 text-danger-300'
          }`}
        >
          {msg.text}
        </div>
      )}

      {/* Articles List */}
      <div className="grid grid-cols-1 gap-4">
        {articles.map((article) => (
          <div
            key={article.id}
            className="group relative overflow-hidden p-6 rounded-2xl bg-slate-900/90 border border-white/10 backdrop-blur-xl hover:border-brand-500/40 transition-all shadow-lg"
          >
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
              <div className="flex items-start md:items-center gap-5 flex-1">
                <div className="w-20 h-20 rounded-xl bg-slate-800 overflow-hidden shrink-0 border border-white/15 group-hover:border-brand-500/40 transition-all shadow-md">
                  {article.cover_image ? (
                    // eslint-disable-next-line @next/next/no-img-element
                    <img
                      src={mediaUrl(article.cover_image)}
                      alt={article.title}
                      className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500"
                    />
                  ) : (
                    <div className="w-full h-full flex items-center justify-center text-slate-500">
                      <i className="bi bi-image text-3xl"></i>
                    </div>
                  )}
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-2 flex-wrap">
                    <span className="px-2.5 py-0.5 rounded-md bg-brand-500/15 text-brand-300 text-[10px] font-bold uppercase tracking-wider border border-brand-500/20">
                      {article.category_display || article.category}
                    </span>
                    {article.source_type === 'tinnhiemmang' && (
                      <span className="px-2.5 py-0.5 rounded-md bg-emerald-500/15 text-emerald-300 text-[10px] font-bold uppercase tracking-wider border border-emerald-500/20">
                        Tín nhiệm mạng
                      </span>
                    )}
                    {article.is_published ? (
                      <span className="px-2.5 py-0.5 rounded-md bg-safe-500/15 text-safe-300 text-[10px] font-bold uppercase tracking-wider border border-safe-500/20">
                        Công khai
                      </span>
                    ) : (
                      <span className="px-2.5 py-0.5 rounded-md bg-white/5 text-slate-400 text-[10px] font-bold uppercase tracking-wider border border-white/10">
                        Bản nháp
                      </span>
                    )}
                    <span className="text-[11px] text-slate-400 ml-auto">
                      {article.created_at}
                    </span>
                  </div>
                  <h3 className="text-lg font-black text-white group-hover:text-brand-300 transition-colors tracking-tight mb-1.5">
                    {article.title}
                  </h3>
                  <p className="text-xs text-slate-300 leading-relaxed line-clamp-2">{article.summary || ''}</p>
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0 self-end md:self-center">
                <Link
                  href={`/admin-cp/articles/${article.id}/edit/`}
                  className="px-3.5 py-2 rounded-xl bg-white/10 border border-white/15 text-xs font-bold text-slate-200 hover:bg-brand-500 hover:text-black hover:border-brand-500 transition-all flex items-center gap-1.5 shadow"
                  title="Chỉnh sửa bài viết"
                >
                  <i className="bi bi-pencil-square"></i>
                  <span>Sửa</span>
                </Link>
                <button
                  type="button"
                  disabled={deletingId === article.id}
                  onClick={() => void handleDelete(article.id)}
                  className="px-3.5 py-2 rounded-xl bg-danger-500/15 border border-danger-500/30 text-xs font-bold text-danger-300 hover:bg-danger-500 hover:text-white hover:border-danger-500 transition-all flex items-center gap-1.5 shadow disabled:opacity-50"
                  title="Xóa bài viết"
                >
                  <i className="bi bi-trash3"></i>
                  <span>Xóa</span>
                </button>
              </div>
            </div>
          </div>
        ))}

        {articles.length === 0 && (
          <div className="py-20 text-center rounded-3xl bg-slate-900/60 border border-dashed border-white/10">
            <div className="w-16 h-16 rounded-full bg-white/5 flex items-center justify-center text-slate-400 mx-auto mb-4">
              <i className="bi bi-newspaper text-3xl"></i>
            </div>
            <h3 className="text-base font-black text-slate-300 uppercase tracking-wider">
              {loading ? 'Đang tải danh sách bài viết...' : 'Chưa có bài viết nào'}
            </h3>
            <p className="text-xs text-slate-400 mt-1">Cập nhật tin tức an ninh mạng cảnh báo cho cộng đồng.</p>
          </div>
        )}
      </div>
    </AdminShell>
  );
}
