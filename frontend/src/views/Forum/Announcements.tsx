'use client';
import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import {api, mediaUrl} from '../../lib/api';
import { useAuth } from '../../components/AuthContext';
import { Spinner } from '../../components/ui';
import { sanitizeHtml } from '../../lib/chat/markdown';
import RichEditor, { getEditorData } from '../../components/RichEditor';

interface Announcement {
  id: number;
  title: string;
  content: string;
  author_name?: string;
  author_username?: string;
  author_avatar?: string | null;
  author_is_staff?: boolean;
  likes_count?: number;
  user_liked?: boolean;
  views_count?: number;
  is_pinned?: boolean;
  created_at?: string;
}

function timeAgo(dt?: string): string {
  if (!dt) return '';
  const diff = (Date.now() - new Date(dt).getTime()) / 1000;
  if (Number.isNaN(diff)) return '';
  if (diff < 60) return 'Vừa xong';
  if (diff < 3600) return `${Math.floor(diff / 60)} phút trước`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} giờ trước`;
  if (diff < 604800) return `${Math.floor(diff / 86400)} ngày trước`;
  return new Date(dt).toLocaleDateString('vi-VN');
}

export default function Announcements() {
  const { user } = useAuth();
  const isAdmin = Boolean(user?.is_staff);
  const [announcements, setAnnouncements] = useState<Announcement[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [showCreate, setShowCreate] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newContent, setNewContent] = useState('');
  const [newPinned, setNewPinned] = useState(false);
  const [createLoading, setCreateLoading] = useState(false);
  const [msg, setMsg] = useState('');

  const fetchAnns = (p: number) => {
    setLoading(true);
    api
      .get<{ results?: Announcement[]; pages?: number } | Announcement[]>(`/announcements/?page=${p}`)
      .then((d) => {
        if (Array.isArray(d)) {
          setAnnouncements(d);
          setTotalPages(1);
        } else {
          setAnnouncements(d.results || []);
          setTotalPages(d.pages || 1);
        }
      })
      .catch(() => setAnnouncements([]))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchAnns(page);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page]);

  const editorRef = useRef<unknown | null>(null);
  const submitAnnouncement = () => {
    const html = getEditorData(editorRef.current).trim();
    if (!newTitle.trim() || !html) {
      setMsg('Vui lòng điền đầy đủ tiêu đề và nội dung');
      return;
    }
    setCreateLoading(true);
    api
      .post('/announcements/', { title: newTitle, content: html, is_pinned: newPinned })
      .then(() => {
        setMsg('Đã tạo thông báo!');
        setNewTitle('');
        setNewContent('');
        setNewPinned(false);
        setShowCreate(false);
        fetchAnns(1);
        setPage(1);
      })
      .catch(() => setMsg('Tạo thông báo thất bại'))
      .finally(() => setCreateLoading(false));
  };

  const toggleLike = (ann: Announcement) => {
    api
      .post<{ likes_count?: number; action?: string }>(`/announcements/${ann.id}/reaction/`, { reaction_type: 'like' })
      .then((d) => {
        setAnnouncements(announcements.map((a) => (a.id === ann.id ? { ...a, likes_count: d.likes_count ?? a.likes_count, user_liked: d.action === 'added' } : a)));
      })
      .catch(() => {});
  };

  return (
    <div className="max-w-4xl mx-auto px-4 py-8">
      <nav className="flex items-center gap-2 text-sm mb-5 text-white/55">
        <Link href="/" className="hover:text-brand-400 transition"><i className="bi bi-house-door"></i> Trang chủ</Link>
        <i className="bi bi-chevron-right text-[10px]"></i>
        <Link href="/forum/" className="hover:text-brand-400 transition">Diễn đàn</Link>
        <i className="bi bi-chevron-right text-[10px]"></i>
        <span className="text-white/60">Thông báo</span>
      </nav>

      <div className="flex items-center justify-between mb-8">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-warn-500/20 to-warn-500/20 flex items-center justify-center border border-warn-500/20">
            <i className="bi bi-megaphone-fill text-xl text-warn-400"></i>
          </div>
          <div>
            <h1 className="text-2xl font-black text-white">Thông báo</h1>
            <p className="text-xs text-white/55">Thông báo chính thức từ ban quản trị</p>
          </div>
        </div>
        {isAdmin && (
          <button onClick={() => setShowCreate(!showCreate)} className="bg-gradient-to-r from-warn-400 to-warn-500 text-black px-5 py-2.5 rounded-xl font-bold text-sm hover:scale-105 transition-all shadow-lg shadow-warn-500/20 flex items-center gap-2">
            <i className="bi bi-plus-lg"></i> Tạo thông báo
          </button>
        )}
      </div>

      {msg && <div className="mb-4 p-3 rounded-xl bg-brand-500/10 border border-brand-500/20 text-brand-300 text-xs font-bold">{msg}</div>}

      {showCreate && (
        <div className="rounded-[1.25rem] border border-white/10 bg-white/[0.02] p-6 mb-6">
          <h3 className="text-sm font-bold text-white/70 mb-4">Tạo thông báo mới</h3>
          <div className="space-y-4">
            <input type="text" value={newTitle} onChange={(e) => setNewTitle(e.target.value)} placeholder="Tiêu đề thông báo..."
              className="w-full bg-white/5 border border-white/10 rounded-xl px-5 py-3 text-white font-semibold focus:outline-none focus:border-brand-400/30 transition" />
            <RichEditor editorRef={editorRef} initialData={newContent} placeholder="Viết nội dung thông báo..." />
            <label className="flex items-center gap-2 text-sm text-white/60 cursor-pointer">
              <input type="checkbox" checked={newPinned} onChange={(e) => setNewPinned(e.target.checked)} className="rounded bg-white/10 border-white/20 text-brand-400" />
              <span>Ghim thông báo</span>
            </label>
            <div className="flex items-center justify-end gap-3">
              <button onClick={() => setShowCreate(false)} className="text-sm font-bold text-white/45 hover:text-white transition">Hủy</button>
              <button onClick={submitAnnouncement} disabled={createLoading}
                className="bg-warn-400 text-black px-6 py-2.5 rounded-xl font-bold text-sm hover:scale-105 transition-all disabled:opacity-50">
                {createLoading ? 'Đang đăng...' : 'Đăng thông báo'}
              </button>
            </div>
          </div>
        </div>
      )}

      {loading ? (
        <Spinner />
      ) : (
        <div className="space-y-4">
          {announcements.map((ann) => (
            <div key={ann.id} className={`rounded-[1.25rem] border border-white/10 bg-white/[0.02] p-6 hover:border-brand-400/20 transition-all ${ann.is_pinned ? 'border-warn-500/20' : ''}`}>
              <div className="flex items-start gap-4">
                <div className="w-10 h-10 rounded-full bg-white/5 border border-white/10 overflow-hidden flex items-center justify-center shrink-0">
                  {ann.author_avatar ? <img src={mediaUrl(ann.author_avatar)} className="w-full h-full object-cover rounded-full" alt="" /> : <span className="text-xs font-bold text-brand-400">{(ann.author_name || '?')[0].toUpperCase()}</span>}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    {ann.is_pinned && <span className="text-warn-500 text-xs"><i className="bi bi-pin-angle-fill"></i></span>}
                    <h3 className="text-base font-bold text-white">{ann.title}</h3>
                  </div>
                  <div className="flex items-center gap-2 text-[10px] text-white/45 mb-4">
                    <span className="flex items-center gap-1">
                      <span>{ann.author_name}</span>
                      {ann.author_is_staff && <i className="bi bi-patch-check-fill text-brand-400"></i>}
                    </span>
                    <span>·</span><span>{timeAgo(ann.created_at)}</span>
                    <span>·</span><span><i className="bi bi-eye mr-0.5"></i>{ann.views_count}</span>
                  </div>
                  <div className="text-sm text-white/60 leading-relaxed richtext-content" dangerouslySetInnerHTML={{ __html: sanitizeHtml(ann.content) }} />
                  <div className="flex items-center gap-4 mt-4 pt-3 border-t border-white/5">
                    <button onClick={() => toggleLike(ann)} className={`flex items-center gap-1.5 text-sm transition ${ann.user_liked ? 'text-danger-400' : 'text-white/45 hover:text-danger-400'}`}>
                      <i className={`bi ${ann.user_liked ? 'bi-heart-fill' : 'bi-heart'}`}></i>
                      <span className="font-bold">{ann.likes_count}</span>
                    </button>
                  </div>
                </div>
              </div>
            </div>
          ))}
          {announcements.length === 0 && (
            <div className="text-center py-16">
              <i className="bi bi-megaphone text-4xl text-white/20 mb-3 block"></i>
              <p className="text-white/45 text-sm font-bold">Chưa có thông báo nào</p>
            </div>
          )}
          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-2 mt-6">
              <button onClick={() => setPage(Math.max(1, page - 1))} disabled={page <= 1} className="px-3 py-2 bg-white/5 border border-white/10 rounded-lg text-xs text-white/55 disabled:opacity-30"><i className="bi bi-chevron-left"></i></button>
              <span className="text-xs text-white/45">Trang {page} / {totalPages}</span>
              <button onClick={() => setPage(Math.min(totalPages, page + 1))} disabled={page >= totalPages} className="px-3 py-2 bg-white/5 border border-white/10 rounded-lg text-xs text-white/55 disabled:opacity-30"><i className="bi bi-chevron-right"></i></button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
