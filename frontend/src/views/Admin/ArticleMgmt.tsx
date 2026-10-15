'use client';
import { useState } from 'react';
import Link from 'next/link';
import { api, mediaUrl } from '../../lib/api';
import { useAdminGet } from './_shared';

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
}

export default function ArticleMgmt() {
  const { data, loading, refetch } = useAdminGet<AdminArticle[]>('/admin/articles/');
  const [deletingId, setDeletingId] = useState<number | null>(null);
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null);

  const articles = data || [];

  const handleDelete = async (id: number) => {
    if (!window.confirm('Bạn có chắc chắn muốn xóa tin tức này?')) return;
    setDeletingId(id);
    setMsg(null);
    try {
      await api.del(`/admin/articles/${id}/`);
      setMsg({ text: 'Đã xóa tin tức thành công.', ok: true });
      refetch();
    } catch (err: unknown) {
      const e = err as { message?: string };
      setMsg({ text: e.message || 'Xóa tin tức thất bại.', ok: false });
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <div className="container mx-auto px-4 py-10 mt-16 max-w-6xl">
      <div className="flex items-center justify-between mb-12">
        <div className="flex items-center gap-6">
          <div className="w-14 h-14 rounded-2xl bg-brand-500/10 border border-brand-500/20 flex items-center justify-center text-brand-400 shadow-lg shadow-brand-500/5">
            <i className="bi bi-newspaper text-2xl"></i>
          </div>
          <div>
            <h1 className="text-3xl font-black text-white tracking-tight">Tin Tức / Cảnh Báo</h1>
            <p className="text-[10px] font-bold text-white/35 uppercase tracking-widest mt-1">
              Quản lý bài viết &amp; cảnh báo an ninh mạng
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <Link
            href="/admin-cp/"
            className="px-5 py-3.5 rounded-2xl bg-white/5 border border-white/10 text-white/70 font-black uppercase tracking-widest hover:border-brand-500/30 hover:text-brand-300 transition-all flex items-center gap-2"
          >
            <i className="bi bi-arrow-left"></i>
            Về Admin
          </Link>
          <Link
            href="/admin-cp/articles/magic-create/"
            className="px-6 py-3.5 rounded-2xl bg-gradient-to-r from-brand2-600 to-brand-600 text-white font-black uppercase tracking-widest hover:from-brand2-500 hover:to-brand-500 transition-all shadow-xl shadow-brand2-500/20 flex items-center gap-2"
          >
            <i className="bi bi-stars text-lg"></i>
            Magic Create
          </Link>
          <Link
            href="/admin-cp/articles/add/"
            className="px-8 py-3.5 rounded-2xl bg-brand-500 text-white font-black uppercase tracking-widest hover:bg-brand-400 hover:text-black transition-all shadow-xl shadow-brand-500/20 flex items-center gap-2"
          >
            <i className="bi bi-plus-lg text-lg"></i>
            Tin tức mới
          </Link>
        </div>
      </div>

      {msg && (
        <div
          className={`p-4 rounded-xl mb-6 text-xs font-bold border ${
            msg.ok ? 'bg-safe-500/10 border-safe-500/20 text-safe-300' : 'bg-danger-500/10 border-danger-500/20 text-danger-300'
          }`}
        >
          {msg.text}
        </div>
      )}

      {/* Articles List */}
      <div className="grid grid-cols-1 gap-6">
        {articles.map((article) => (
          <div
            key={article.id}
            className="group relative overflow-hidden p-8 rounded-[2.5rem] bg-slate-900/40 border border-white/5 backdrop-blur-xl hover:border-brand-500/30 transition-all duration-500"
          >
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-8">
              <div className="flex items-center gap-8 flex-1">
                <div className="w-24 h-24 rounded-[2rem] bg-slate-800 overflow-hidden shrink-0 border border-white/10 group-hover:border-brand-500/30 transition-all shadow-2xl">
                  {article.cover_image ? (
                    // eslint-disable-next-line @next/next/no-img-element
                    <img
                      src={mediaUrl(article.cover_image)}
                      alt={article.title}
                      className="w-full h-full object-cover group-hover:scale-110 transition-transform duration-700"
                    />
                  ) : (
                    <div className="w-full h-full flex items-center justify-center text-white/20">
                      <i className="bi bi-image text-4xl"></i>
                    </div>
                  )}
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-3">
                    <span className="px-2 py-0.5 rounded-md bg-brand-500/10 text-brand-400 text-[9px] font-black uppercase tracking-widest border border-brand-500/10">
                      {article.category}
                    </span>
                    {article.is_published ? (
                      <span className="px-2 py-0.5 rounded-md bg-safe-500/10 text-safe-400 text-[9px] font-black uppercase tracking-widest border border-safe-500/10">
                        Public
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded-md bg-white/5 text-white/45 text-[9px] font-black uppercase tracking-widest border border-white/5">
                        Draft
                      </span>
                    )}
                    <span className="text-[10px] font-bold text-white/35 uppercase tracking-widest ml-auto">
                      {article.created_at}
                    </span>
                  </div>
                  <h3 className="text-2xl font-black text-white group-hover:text-brand-400 transition-colors tracking-tight mb-2">
                    {article.title}
                  </h3>
                  <p className="text-xs text-white/55 leading-relaxed line-clamp-2">{article.summary || ''}</p>
                </div>
              </div>

              <div className="flex items-center gap-3 shrink-0">
                <Link
                  href={`/admin-cp/articles/${article.id}/edit/`}
                  className="w-12 h-12 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center text-white/60 hover:bg-brand-500 hover:text-white hover:border-brand-500 transition-all shadow-lg"
                  title="Sửa bài viết"
                >
                  <i className="bi bi-pencil-square text-lg"></i>
                </Link>
                <button
                  type="button"
                  disabled={deletingId === article.id}
                  onClick={() => void handleDelete(article.id)}
                  className="w-12 h-12 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center text-white/60 hover:bg-danger-500 hover:text-white hover:border-danger-500 transition-all shadow-lg disabled:opacity-50"
                  title="Xóa"
                >
                  <i className="bi bi-trash3 text-lg"></i>
                </button>
              </div>
            </div>
          </div>
        ))}

        {articles.length === 0 && (
          <div className="py-20 text-center rounded-[3rem] bg-white/[0.02] border border-dashed border-white/10">
            <div className="w-20 h-20 rounded-full bg-white/5 flex items-center justify-center text-white/20 mx-auto mb-6">
              <i className="bi bi-newspaper text-4xl"></i>
            </div>
            <h3 className="text-lg font-black text-white/55 uppercase tracking-widest">
              {loading ? 'Đang tải...' : 'Chưa có bài viết nào'}
            </h3>
            <p className="text-xs text-white/35 mt-2">Cập nhật tin tức an ninh mạng cho cộng đồng.</p>
          </div>
        )}
      </div>
    </div>
  );
}
