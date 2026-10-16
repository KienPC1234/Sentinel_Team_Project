'use client';
import { useCallback, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { api, mediaUrl } from '../../lib/api';
import type { Paged } from '../../lib/api';
import { Spinner } from '../../components/ui';
import { wsBase } from '../../components/ScanWidgets';

/* Port từ PKV/templates/Forum/forum.html — tái tạo 1-1 markup/class/text/icon.
 * Alpine.data('forumApp') đã chuyển sang React state/hooks/handler: viewMode
 * (categories/threads), filter/sort/search + pagination, realtime WS
 * /ws/forum/. Giữ endpoint hiện có GET /forum/posts/. */


export interface RankInfo {
  name?: string;
  level?: string;
  icon?: string;
  color?: string;
}

export interface ForumPost {
  id: number;
  title: string;
  category: string;
  content?: string;
  likes_count?: number;
  comments_count?: number;
  views_count?: number;
  created_at?: string;
  author_name?: string;
  author_username?: string;
  author_avatar?: string | null;
  author_rank?: RankInfo | null;
  is_pinned?: boolean;
  is_locked?: boolean;
  last_comment_author?: { name?: string; username?: string; avatar?: string | null } | null;
  last_comment_at?: string | null;
}

interface CatStat {
  value: string;
  label: string;
  threads_count: number;
  messages_count: number;
  latest_post?: { id: number; title: string; author_name?: string; author_avatar?: string | null; created_at?: string } | null;
}

interface CategoryMeta {
  label: string;
  desc: string;
  color: string;
  iconBg: string;
  icon: string;
  textColor: string;
}

/* /forum/stats/ — số liệu thật của toàn diễn đàn. Trước đây mọi thống kê suy ra
 * từ danh sách tối đa 50 bài nên luôn sai khi diễn đàn có nhiều hơn 50 bài. */
interface ForumStats {
  total_posts?: number;
  total_comments?: number;
  total_members?: number;
  posts_today?: number;
  category_stats?: Array<{ category?: string; count?: number }>;
}

const CATS: Record<string, CategoryMeta> = {
  warning: { label: 'Cảnh báo', desc: 'Cảnh báo lừa đảo mới nhất', color: 'bg-danger-500/20 text-danger-500', iconBg: 'bg-danger-500/15 border-danger-500/30', icon: 'bi-shield-fill-exclamation', textColor: 'text-danger-400' },
  discussion: { label: 'Thảo luận', desc: 'Thảo luận về an ninh mạng', color: 'bg-brand-500/20 text-brand-500', iconBg: 'bg-brand-500/15 border-brand-500/30', icon: 'bi-chat-dots-fill', textColor: 'text-brand-400' },
  experience: { label: 'Kinh nghiệm', desc: 'Chia sẻ kinh nghiệm phòng chống', color: 'bg-brand2-500/20 text-brand2-500', iconBg: 'bg-brand2-500/15 border-brand2-500/30', icon: 'bi-lightbulb-fill', textColor: 'text-brand2-400' },
  question: { label: 'Hỏi đáp', desc: 'Đặt câu hỏi, nhận giải đáp', color: 'bg-warn-500/20 text-warn-500', iconBg: 'bg-warn-500/15 border-warn-500/30', icon: 'bi-question-diamond-fill', textColor: 'text-warn-400' },
};

function catInfo(cat: string): CategoryMeta {
  return CATS[cat] || { label: cat, desc: '', color: 'bg-white/10 text-white/60', iconBg: 'bg-white/10 border-white/20', icon: 'bi-hash', textColor: 'text-white/60' };
}

function timeAgo(dt?: string | null): string {
  if (!dt) return '';
  const diff = (Date.now() - new Date(dt).getTime()) / 1000;
  if (Number.isNaN(diff)) return '';
  if (diff < 60) return 'Vừa xong';
  if (diff < 3600) return `${Math.floor(diff / 60)} phút trước`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} giờ trước`;
  if (diff < 604800) return `${Math.floor(diff / 86400)} ngày trước`;
  return new Date(dt).toLocaleDateString('vi-VN');
}

function stripHtml(html?: string): string {
  if (!html) return '';
  return html.replace(/<[^>]*>/g, '');
}

function initial(name?: string): string {
  return name ? name.charAt(0).toUpperCase() : '?';
}

const TAB_FILTERS = [
  { v: 'all', l: 'Tất cả', active: 'bg-brand-400/10 text-brand-400 border-brand-500/30' },
  { v: 'warning', l: 'Cảnh báo', active: 'bg-danger-500/10 text-danger-400 border-danger-500/30' },
  { v: 'discussion', l: 'Thảo luận', active: 'bg-brand-500/10 text-brand-400 border-brand-500/30' },
  { v: 'experience', l: 'Kinh nghiệm', active: 'bg-brand2-500/10 text-brand2-400 border-brand2-500/30' },
  { v: 'question', l: 'Hỏi đáp', active: 'bg-warn-500/10 text-warn-400 border-warn-500/30' },
];

const SORTS = [
  { v: 'newest', l: 'Mới', i: 'bi-clock', active: 'text-brand-400' },
  { v: 'popular', l: 'Hot', i: 'bi-heart', active: 'text-danger-400' },
  { v: 'discussed', l: 'Thảo luận', i: 'bi-chat-left-text', active: 'text-brand2-400' },
  { v: 'views', l: 'Xem', i: 'bi-eye', active: 'text-warn-400' },
];



export default function Forum() {
  const [posts, setPosts] = useState<ForumPost[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [sortBy, setSortBy] = useState('newest');
  const [viewMode, setViewMode] = useState<'categories' | 'threads'>('categories');
  const [currentPage, setCurrentPage] = useState(1);
  const [stats, setStats] = useState<ForumStats | null>(null);
  const [serverTotal, setServerTotal] = useState<number | null>(null);
  const postsPerPage = 20;

  const refresh = useCallback(
    () =>
      api
        .get<Paged<ForumPost> | ForumPost[]>('/forum/posts/?page_size=100')
        .then((r) => {
          setPosts(Array.isArray(r) ? r : r.results || []);
          if (!Array.isArray(r) && typeof r.count === 'number') setServerTotal(r.count);
        })
        .catch(() => setPosts([])),
    [],
  );

  useEffect(() => {
    void refresh().finally(() => setLoading(false));
  }, [refresh]);

  /* Thống kê tổng: lấy riêng từ endpoint thống kê, có fallback về số liệu suy
   * ra từ danh sách khi endpoint lỗi. */
  useEffect(() => {
    api
      .get<ForumStats>('/forum/stats/')
      .then(setStats)
      .catch(() => setStats(null));
  }, []);

  /* Realtime: post_created / comment_created -> tải lại danh sách. */
  useEffect(() => {
    let ws: WebSocket | null = null;
    let reconnect: ReturnType<typeof setTimeout> | null = null;
    let ping: ReturnType<typeof setInterval> | null = null;
    let closed = false;
    const connect = () => {
      try {
        ws = new WebSocket(`${wsBase()}/ws/forum/`);
        ws.onopen = () => {
          ping = setInterval(() => {
            if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'ping' }));
          }, 30000);
        };
        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(String(event.data || '{}')) as { type?: string; event?: string };
            if (data.type !== 'forum_live_event') return;
            if (data.event === 'post_created' || data.event === 'comment_created') void refresh();
          } catch {
            /* ignore malformed frame */
          }
        };
        ws.onclose = () => {
          if (ping) {
            clearInterval(ping);
            ping = null;
          }
          if (!closed) reconnect = setTimeout(connect, 2000);
        };
      } catch {
        /* WebSocket không khả dụng */
      }
    };
    connect();
    return () => {
      closed = true;
      if (reconnect) clearTimeout(reconnect);
      if (ping) clearInterval(ping);
      if (ws) ws.close();
    };
  }, [refresh]);

  const categoryStats: CatStat[] = useMemo(() => {
    const order = ['warning', 'discussion', 'experience', 'question'];
    const counts = new Map<string, number>();
    for (const row of stats?.category_stats || []) {
      if (row?.category) counts.set(row.category, Number(row.count || 0));
    }
    return order.map((v) => {
      const rows = posts.filter((p) => p.category === v);
      const latest = [...rows].sort((a, b) => +new Date(b.created_at || 0) - +new Date(a.created_at || 0))[0];
      return {
        value: v,
        label: catInfo(v).label,
        threads_count: counts.get(v) ?? rows.length,
        messages_count: rows.reduce((a, b) => a + (b.comments_count || 0), 0),
        latest_post: latest
          ? { id: latest.id, title: latest.title, author_name: latest.author_name, author_avatar: latest.author_avatar, created_at: latest.created_at }
          : null,
      };
    });
  }, [posts, stats]);

  const filtered = useMemo(() => {
    let f = [...posts];
    if (activeTab !== 'all') f = f.filter((p) => p.category === activeTab);
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      f = f.filter((p) => (p.title || '').toLowerCase().includes(q) || stripHtml(p.content).toLowerCase().includes(q));
    }
    if (sortBy === 'popular') f.sort((a, b) => (b.likes_count || 0) - (a.likes_count || 0));
    else if (sortBy === 'discussed') f.sort((a, b) => (b.comments_count || 0) - (a.comments_count || 0));
    else if (sortBy === 'views') f.sort((a, b) => (b.views_count || 0) - (a.views_count || 0));
    else f.sort((a, b) => (b.is_pinned ? 1 : 0) - (a.is_pinned ? 1 : 0) || +new Date(b.created_at || 0) - +new Date(a.created_at || 0));
    return f;
  }, [posts, activeTab, searchQuery, sortBy]);

  const trending = useMemo(
    () =>
      [...posts]
        .sort((a, b) => (b.likes_count || 0) + (b.comments_count || 0) + (b.views_count || 0) - ((a.likes_count || 0) + (a.comments_count || 0) + (a.views_count || 0)))
        .slice(0, 5),
    [posts],
  );

  const pinned = posts.filter((p) => p.is_pinned);
  const recentThreads = posts.filter((p) => !p.is_pinned).slice(0, 10);
  const totalPages = Math.max(1, Math.ceil(filtered.length / postsPerPage));

  /* Lọc/sắp xếp lại có thể làm trang hiện tại vượt quá tổng số trang -> trang trắng. */
  useEffect(() => {
    if (currentPage > totalPages) setCurrentPage(totalPages);
  }, [currentPage, totalPages]);

  const paginated = filtered.slice((currentPage - 1) * postsPerPage, currentPage * postsPerPage);
  const totalPosts = stats?.total_posts ?? serverTotal ?? posts.length;
  const totalComments = stats?.total_comments ?? posts.reduce((a, b) => a + (b.comments_count || 0), 0);
  const totalViews = posts.reduce((a, b) => a + (b.views_count || 0), 0);

  const pickTab = (t: string) => {
    setActiveTab(t);
    setCurrentPage(1);
  };

  const openCategory = (cat: string) => {
    setActiveTab(cat);
    setViewMode('threads');
    setCurrentPage(1);
  };

  const goToPage = (p: number) => {
    if (p >= 1 && p <= totalPages) {
      setCurrentPage(p);
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  };

  const pageNumbers = (): (number | string)[] => {
    const pages: (number | string)[] = [];
    const start = Math.max(1, currentPage - 2);
    const end = Math.min(totalPages, currentPage + 2);
    if (start > 1) pages.push(1);
    if (start > 2) pages.push('...');
    for (let i = start; i <= end; i++) pages.push(i);
    if (end < totalPages - 1) pages.push('...');
    if (end < totalPages) pages.push(totalPages);
    return pages;
  };

  return (
    <>
      <div className="max-w-7xl mx-auto px-4 pt-10 sm:pt-14 pb-16">
        {/* Breadcrumb */}
        <nav className="flex items-center gap-2 text-sm mb-5 text-white/55">
          <Link href="/" className="hover:text-brand-400 transition"><i className="bi bi-house-door"></i> Trang chủ</Link>
          <i className="bi bi-chevron-right text-[10px]"></i>
          <span className="text-white/60">Diễn đàn</span>
        </nav>

        {/* Header */}
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-8">
          <div>
            <h1 className="text-3xl font-black text-white mb-1">Diễn đàn <span className="text-brand-400">Cộng đồng</span></h1>
            <p className="text-white/55 text-sm">Nơi người dân chung tay đẩy lùi tội phạm công nghệ cao</p>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center bg-white/5 rounded-xl border border-white/10 overflow-hidden">
              <button onClick={() => setViewMode('categories')} className={`px-3 py-2 text-xs font-bold transition-all ${viewMode === 'categories' ? 'bg-brand-400/10 text-brand-400' : 'text-white/55'}`} title="Xem theo danh mục">
                <i className="bi bi-grid-3x3-gap-fill"></i>
              </button>
              <button onClick={() => setViewMode('threads')} className={`px-3 py-2 text-xs font-bold transition-all ${viewMode === 'threads' ? 'bg-brand-400/10 text-brand-400' : 'text-white/55'}`} title="Xem chủ đề">
                <i className="bi bi-list-ul"></i>
              </button>
            </div>
            <Link href="/forum/create/" className="bg-gradient-to-r from-brand-400 to-brand-600 text-[var(--sc-night-1)] px-5 py-2.5 rounded-xl font-bold flex items-center gap-2 hover:scale-105 transition-all shadow-lg shadow-brand-500/20 text-sm">
              <i className="bi bi-pencil-fill"></i> Tạo chủ đề
            </Link>
          </div>
        </div>

        {loading ? (
          <Spinner />
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Main Content Area */}
            <div className="lg:col-span-9 space-y-6">
              {/* =================== VIEW MODE: CATEGORIES (VOZ-style) =================== */}
              {viewMode === 'categories' && (
                <div className="space-y-4">
                  {/* VOZ-Style Category Section */}
                  <div className="voz-section rounded-2xl overflow-hidden">
                    {/* Section Header */}
                    <div className="px-5 py-3 bg-gradient-to-r from-brand-500/10 to-brand2-500/5 border-b border-white/5">
                      <h2 className="text-xs font-black text-brand-400 uppercase tracking-widest flex items-center gap-2">
                        <i className="bi bi-shield-fill-check"></i> ShieldCall VN | Diễn đàn
                      </h2>
                    </div>

                    {/* Column Headers (desktop only) */}
                    <div className="hidden md:grid grid-cols-12 gap-4 px-5 py-2 bg-white/[0.02] border-b border-white/5 text-[9px] font-black text-white/55 uppercase tracking-widest">
                      <div className="col-span-6">Danh mục</div>
                      <div className="col-span-1 text-center">Chủ đề</div>
                      <div className="col-span-1 text-center">Tin nhắn</div>
                      <div className="col-span-4 text-right">Bài viết mới nhất</div>
                    </div>

                    {/* Category Rows */}
                    {categoryStats.map((cat) => (
                      <div
                        key={cat.value}
                        className="voz-row grid grid-cols-1 md:grid-cols-12 gap-3 md:gap-4 px-5 py-4 border-b border-white/5 items-center cursor-pointer"
                        onClick={() => openCategory(cat.value)}
                      >
                        {/* Category Info */}
                        <div className="md:col-span-6 flex items-center gap-4">
                          <div className={`category-icon border ${catInfo(cat.value).iconBg}`}>
                            <i className={`${catInfo(cat.value).icon} ${catInfo(cat.value).textColor}`}></i>
                          </div>
                          <div className="min-w-0">
                            <h3 className="text-sm font-bold text-white hover:text-brand-400 transition-colors">{cat.label}</h3>
                            <p className="text-[10px] text-white/45 mt-0.5">{catInfo(cat.value).desc}</p>
                          </div>
                        </div>

                        {/* Thread Count */}
                        <div className="md:col-span-1 text-center hidden md:block">
                          <span className="text-sm font-black text-white/60">{cat.threads_count}</span>
                          <div className="text-[8px] text-white/35 uppercase">Chủ đề</div>
                        </div>

                        {/* Messages Count */}
                        <div className="md:col-span-1 text-center hidden md:block">
                          <span className="text-sm font-black text-white/60">{cat.messages_count}</span>
                          <div className="text-[8px] text-white/35 uppercase">Tin nhắn</div>
                        </div>

                        {/* Latest Post */}
                        <div className="md:col-span-4" onClick={(e) => e.stopPropagation()}>
                          {cat.latest_post ? (
                            <Link href={`/forum/${cat.latest_post.id}/`} className="flex items-center gap-3 group/lp justify-end">
                              <div className="text-right min-w-0 hidden md:block">
                                <p className="text-[11px] font-bold text-white/60 group-hover/lp:text-brand-400 transition-colors truncate max-w-[200px]">{cat.latest_post.title}</p>
                                <div className="flex items-center gap-1.5 justify-end mt-0.5">
                                  <span className="text-[9px] text-white/55">{cat.latest_post.author_name}</span>
                                  <span className="text-[9px] text-white/15">·</span>
                                  <span className="text-[9px] text-white/35">{timeAgo(cat.latest_post.created_at)}</span>
                                </div>
                              </div>
                              <div className="w-9 h-9 rounded-lg bg-white/5 border border-white/10 overflow-hidden flex items-center justify-center shrink-0">
                                {cat.latest_post.author_avatar ? (
                                  <img src={mediaUrl(cat.latest_post.author_avatar)} className="w-full h-full object-cover" alt="" />
                                ) : (
                                  <span className="text-[10px] font-bold text-brand-400">{initial(cat.latest_post.author_name)}</span>
                                )}
                              </div>
                            </Link>
                          ) : (
                            <span className="text-[10px] text-white/15 italic block text-right">Chưa có bài viết</span>
                          )}
                        </div>

                        {/* Mobile Stats */}
                        <div className="md:hidden flex items-center gap-4 text-[10px] text-white/45">
                          <span><i className="bi bi-file-earmark-text mr-1"></i><span>{cat.threads_count}</span> chủ đề</span>
                          <span><i className="bi bi-chat-left-text mr-1"></i><span>{cat.messages_count}</span> tin nhắn</span>
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Pinned Posts */}
                  {pinned.length > 0 && (
                    <div className="voz-section rounded-2xl overflow-hidden">
                      <div className="px-5 py-3 bg-gradient-to-r from-warn-500/10 to-transparent border-b border-white/5">
                        <h2 className="text-xs font-black text-warn-400 uppercase tracking-widest flex items-center gap-2">
                          <i className="bi bi-pin-angle-fill"></i> Bài viết được ghim
                        </h2>
                      </div>
                      {pinned.map((post) => (
                        <Link key={`pinned-${post.id}`} href={`/forum/${post.id}/`} className="voz-row flex items-center gap-4 px-5 py-3 border-b border-white/5 group/pin">
                          <div className="w-8 h-8 rounded-lg bg-warn-500/10 border border-warn-500/20 flex items-center justify-center shrink-0">
                            <i className="bi bi-pin-angle-fill text-warn-500 text-xs"></i>
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className={`px-2 py-0.5 text-[8px] font-black rounded border uppercase ${catInfo(post.category).color}`}>{catInfo(post.category).label}</span>
                              <h3 className="text-sm font-bold text-white group-hover/pin:text-brand-400 transition-colors truncate">{post.title}</h3>
                            </div>
                          </div>
                          <div className="hidden sm:flex items-center gap-4 text-[10px] text-white/55 shrink-0">
                            <span><i className="bi bi-chat-left-text mr-1"></i><span>{post.comments_count}</span></span>
                            <span><i className="bi bi-eye mr-1"></i><span>{post.views_count || 0}</span></span>
                          </div>
                          <div className="w-7 h-7 rounded-md bg-white/5 border border-white/10 overflow-hidden flex items-center justify-center shrink-0">
                            {post.author_avatar ? (
                              <img src={mediaUrl(post.author_avatar)} className="w-full h-full object-cover" alt="" />
                            ) : (
                              <span className="text-[9px] font-bold text-brand-400">{initial(post.author_name)}</span>
                            )}
                          </div>
                        </Link>
                      ))}
                    </div>
                  )}

                  {/* Recent Threads */}
                  <div className="voz-section rounded-2xl overflow-hidden">
                    <div className="px-5 py-3 bg-gradient-to-r from-white/5 to-transparent border-b border-white/5">
                      <h2 className="text-xs font-black text-white/60 uppercase tracking-widest flex items-center gap-2">
                        <i className="bi bi-clock-history"></i> Chủ đề mới nhất
                      </h2>
                    </div>
                    {recentThreads.map((post) => (
                      <Link key={`recent-${post.id}`} href={`/forum/${post.id}/`} className="voz-row grid grid-cols-12 gap-3 px-5 py-3 border-b border-white/5 items-center group/thread">
                        <div className="col-span-12 sm:col-span-7 flex items-center gap-3 min-w-0">
                          <div className="w-8 h-8 rounded-full bg-white/5 border border-white/10 overflow-hidden flex items-center justify-center shrink-0">
                            {post.author_avatar ? (
                              <img src={mediaUrl(post.author_avatar)} className="w-full h-full object-cover" alt="" />
                            ) : (
                              <span className="text-[10px] font-bold text-brand-400">{initial(post.author_name)}</span>
                            )}
                          </div>
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-2">
                              <span className={`px-1.5 py-0.5 text-[7px] font-black rounded border uppercase shrink-0 ${catInfo(post.category).color}`}>{catInfo(post.category).label}</span>
                              {post.is_locked && <span className="text-danger-400 text-[8px]"><i className="bi bi-lock-fill"></i></span>}
                              <h3 className="text-[13px] font-bold text-white/80 group-hover/thread:text-brand-400 transition-colors truncate">{post.title}</h3>
                            </div>
                            <div className="flex items-center gap-2 mt-0.5 text-[9px] text-white/55">
                              <span>{post.author_name}</span>
                              <span>·</span>
                              <span>{timeAgo(post.created_at)}</span>
                            </div>
                          </div>
                        </div>
                        <div className="col-span-5 hidden sm:flex items-center justify-end gap-6 text-[10px] text-white/55">
                          <div className="text-center">
                            <span className="block font-black text-white/55">{post.comments_count}</span>
                            <span className="text-[8px]">trả lời</span>
                          </div>
                          <div className="text-center">
                            <span className="block font-black text-white/55">{post.views_count || 0}</span>
                            <span className="text-[8px]">xem</span>
                          </div>
                          {post.last_comment_author && (
                            <div className="flex items-center gap-2 min-w-0">
                              <div className="w-6 h-6 rounded-md bg-white/5 border border-white/5 overflow-hidden flex items-center justify-center shrink-0">
                                {post.last_comment_author.avatar ? (
                                  <img src={mediaUrl(post.last_comment_author.avatar)} className="w-full h-full object-cover" alt="" />
                                ) : (
                                  <span className="text-[8px] font-bold text-brand-400">{initial(post.last_comment_author.name)}</span>
                                )}
                              </div>
                              <div className="min-w-0">
                                <span className="text-[9px] text-white/45 truncate block max-w-[80px]">{post.last_comment_author.name}</span>
                                <span className="text-[8px] text-white/15">{timeAgo(post.last_comment_at)}</span>
                              </div>
                            </div>
                          )}
                        </div>
                      </Link>
                    ))}
                  </div>
                </div>
              )}

              {/* =================== VIEW MODE: THREADS (traditional list) =================== */}
              {viewMode === 'threads' && (
                <div className="space-y-4">
                  {/* Search Bar */}
                  <div className="relative group">
                    <i className="bi bi-search absolute left-5 top-1/2 -translate-y-1/2 text-white/45 group-focus-within:text-brand-400 transition-colors pointer-events-none z-10"></i>
                    <input
                      type="text"
                      value={searchQuery}
                      onChange={(e) => {
                        setSearchQuery(e.target.value);
                        setCurrentPage(1);
                      }}
                      placeholder="Tìm kiếm kinh nghiệm, cảnh báo giả mạo..."
                      className="w-full bg-white/5 border border-white/10 rounded-2xl py-3.5 pl-14 pr-6 text-white focus:outline-none focus:border-brand-400/30 transition-all font-medium text-sm"
                    />
                  </div>

                  {/* Sort & Filter Bar */}
                  <div className="flex items-center gap-2 flex-wrap">
                    {TAB_FILTERS.map((t) => (
                      <button
                        key={t.v}
                        onClick={() => pickTab(t.v)}
                        className={`px-3 py-1.5 rounded-lg text-[10px] font-bold border transition-all ${activeTab === t.v ? t.active : 'bg-white/5 text-white/55 border-white/10'}`}
                      >
                        {t.l}
                      </button>
                    ))}
                    <div className="h-4 w-px bg-white/10 mx-1"></div>
                    {SORTS.map((s) => (
                      <button
                        key={s.v}
                        onClick={() => {
                          setSortBy(s.v);
                          setCurrentPage(1);
                        }}
                        className={`px-2 py-1.5 text-[10px] font-bold transition-all ${sortBy === s.v ? s.active : 'text-white/45'}`}
                      >
                        <i className={`bi ${s.i} mr-1`}></i>{s.l}
                      </button>
                    ))}
                  </div>

                  {/* Thread List (VOZ table-style) */}
                  <div className="voz-section rounded-2xl overflow-hidden">
                    <div className="hidden md:grid grid-cols-12 gap-4 px-5 py-2 bg-white/[0.02] border-b border-white/5 text-[9px] font-black text-white/55 uppercase tracking-widest">
                      <div className="col-span-7">Chủ đề</div>
                      <div className="col-span-1 text-center">Trả lời</div>
                      <div className="col-span-1 text-center">Xem</div>
                      <div className="col-span-3 text-right">Hoạt động</div>
                    </div>

                    {paginated.map((post) => (
                      <Link key={post.id} href={`/forum/${post.id}/`} className="voz-row grid grid-cols-1 md:grid-cols-12 gap-3 md:gap-4 px-5 py-3.5 border-b border-white/5 items-center group/t">
                        <div className="md:col-span-7 flex items-center gap-3 min-w-0">
                          <div className="w-10 h-10 rounded-full bg-white/5 border border-white/10 overflow-hidden flex items-center justify-center shrink-0" data-usercard={post.author_username}>
                            {post.author_avatar ? (
                              <img src={mediaUrl(post.author_avatar)} className="w-full h-full object-cover" alt="" />
                            ) : (
                              <span className="text-xs font-bold text-brand-400">{initial(post.author_name)}</span>
                            )}
                          </div>
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-2 flex-wrap">
                              {post.is_pinned && <span className="text-warn-500 text-[8px]"><i className="bi bi-pin-angle-fill"></i></span>}
                              {post.is_locked && <span className="text-danger-400 text-[8px]"><i className="bi bi-lock-fill"></i></span>}
                              <span className={`px-1.5 py-0.5 text-[7px] font-black rounded border uppercase shrink-0 ${catInfo(post.category).color}`}>{catInfo(post.category).label}</span>
                              <h3 className="text-[13px] font-bold text-white/80 group-hover/t:text-brand-400 transition-colors truncate">{post.title}</h3>
                            </div>
                            <div className="flex items-center gap-2 mt-1 text-[9px] text-white/55">
                              <span>{post.author_name}</span>
                              <span>·</span>
                              <span>{timeAgo(post.created_at)}</span>
                              {post.author_rank && (
                                <span className={`rank-badge-sm rank-${post.author_rank.level || ''}`}>{post.author_rank.name}</span>
                              )}
                            </div>
                          </div>
                        </div>
                        <div className="md:col-span-1 text-center hidden md:block">
                          <span className="text-sm font-black text-white/55">{post.comments_count}</span>
                        </div>
                        <div className="md:col-span-1 text-center hidden md:block">
                          <span className="text-sm font-black text-white/45">{post.views_count || 0}</span>
                        </div>
                        <div className="md:col-span-3 hidden md:block">
                          {post.last_comment_author ? (
                            <div className="flex items-center gap-2 justify-end">
                              <div className="text-right min-w-0">
                                <span className="text-[9px] text-white/45 block truncate max-w-[100px]">{post.last_comment_author.name}</span>
                                <span className="text-[8px] text-white/15">{timeAgo(post.last_comment_at)}</span>
                              </div>
                              <div className="w-7 h-7 rounded-md bg-white/5 border border-white/5 overflow-hidden flex items-center justify-center shrink-0">
                                {post.last_comment_author.avatar ? (
                                  <img src={mediaUrl(post.last_comment_author.avatar)} className="w-full h-full object-cover" alt="" />
                                ) : (
                                  <span className="text-[8px] font-bold text-brand-400">{initial(post.last_comment_author.name)}</span>
                                )}
                              </div>
                            </div>
                          ) : (
                            <div className="text-right">
                              <span className="text-[9px] text-white/15">{timeAgo(post.created_at)}</span>
                            </div>
                          )}
                        </div>
                        {/* Mobile stats */}
                        <div className="md:hidden flex items-center gap-4 text-[10px] text-white/55">
                          <span><i className="bi bi-chat-left-text mr-1"></i><span>{post.comments_count}</span></span>
                          <span><i className="bi bi-eye mr-1"></i><span>{post.views_count || 0}</span></span>
                          <span><i className="bi bi-heart mr-1"></i><span>{post.likes_count}</span></span>
                        </div>
                      </Link>
                    ))}

                    {filtered.length === 0 && (
                      <div className="p-12 text-center">
                        <i className="bi bi-search text-3xl text-white/20 mb-3 block"></i>
                        <p className="text-white/45 text-sm font-bold">Không tìm thấy bài viết</p>
                      </div>
                    )}

                    {/* Backend trả tối đa LIST_LIMIT bài/lần — nói rõ khi còn bài chưa tải. */}
                    {totalPosts > posts.length && (
                      <div className="px-5 py-3 text-[10px] text-white/40 flex items-center gap-2">
                        <i className="bi bi-info-circle"></i>
                        <span>{`Đang hiển thị ${posts.length} chủ đề mới nhất. Tổng số chủ đề: ${totalPosts}.`}</span>
                      </div>
                    )}
                  </div>

                  {/* Pagination */}
                  {totalPages > 1 && (
                    <div className="flex items-center justify-center gap-1 mt-4">
                      <button
                        onClick={() => goToPage(currentPage - 1)}
                        disabled={currentPage <= 1}
                        className="w-8 h-8 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center text-xs text-white/55 hover:text-white hover:bg-white/10 transition disabled:opacity-30 disabled:cursor-not-allowed"
                      >
                        <i className="bi bi-chevron-left"></i>
                      </button>
                      {pageNumbers().map((p, i) => (
                        <button
                          key={`pg-${i}-${p}`}
                          onClick={() => typeof p === 'number' && goToPage(p)}
                          disabled={p === '...'}
                          className={`w-8 h-8 rounded-lg border flex items-center justify-center text-xs font-bold transition disabled:cursor-default ${p === currentPage ? 'bg-brand-500/20 text-brand-400 border-brand-500/30' : 'bg-white/5 text-white/55 border-white/10 hover:text-white hover:bg-white/10'}`}
                        >
                          {p}
                        </button>
                      ))}
                      <button
                        onClick={() => goToPage(currentPage + 1)}
                        disabled={currentPage >= totalPages}
                        className="w-8 h-8 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center text-xs text-white/55 hover:text-white hover:bg-white/10 transition disabled:opacity-30 disabled:cursor-not-allowed"
                      >
                        <i className="bi bi-chevron-right"></i>
                      </button>
                      <span className="ml-2 text-[10px] text-white/35">{`Trang ${currentPage}/${totalPages} · ${filtered.length} chủ đề`}</span>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* RIGHT Sidebar */}
            <div className="lg:col-span-3 space-y-4">
              {/* Community Stats */}
              <div className="voz-section rounded-2xl overflow-hidden">
                <div className="px-4 py-3 bg-gradient-to-r from-brand-500/10 to-transparent border-b border-white/5">
                  <h4 className="text-[10px] font-black text-brand-400 uppercase tracking-widest flex items-center gap-2">
                    <i className="bi bi-graph-up"></i> Thống kê
                  </h4>
                </div>
                <div className="p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] text-white/55 font-bold">Tổng chủ đề</span>
                    <span className="text-sm font-black text-white/70">{totalPosts}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] text-white/55 font-bold">Tổng bình luận</span>
                    <span className="text-sm font-black text-white/70">{totalComments}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] text-white/55 font-bold">Lượt xem (50 bài mới)</span>
                    <span className="text-sm font-black text-white/70">{totalViews}</span>
                  </div>
                  {typeof stats?.total_members === 'number' && (
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] text-white/55 font-bold">Thành viên</span>
                      <span className="text-sm font-black text-white/70">{stats.total_members}</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Trending Posts */}
              <div className="voz-section rounded-2xl overflow-hidden">
                <div className="px-4 py-3 bg-gradient-to-r from-warn-500/10 to-transparent border-b border-white/5">
                  <h4 className="text-[10px] font-black text-warn-400 uppercase tracking-widest flex items-center gap-2">
                    <i className="bi bi-fire"></i> Xu hướng
                  </h4>
                </div>
                <div className="py-2">
                  {trending.map((tp, idx) => (
                    <Link key={`t${tp.id}`} href={`/forum/${tp.id}/`} className="flex items-start gap-3 group/t hover:bg-white/[0.03] px-4 py-2.5 transition-all">
                      <span className="text-lg font-black text-white/20 group-hover/t:text-brand-400/30 w-5 text-center shrink-0 leading-tight">{idx + 1}</span>
                      <div className="min-w-0 flex-1">
                        <p className="text-[11px] font-bold text-white/60 group-hover/t:text-brand-400 transition-colors line-clamp-2 leading-snug">{tp.title}</p>
                        <div className="flex items-center gap-3 mt-1 text-[9px] text-white/35">
                          <span><i className="bi bi-heart-fill text-danger-500/40 mr-0.5"></i><span>{tp.likes_count}</span></span>
                          <span><i className="bi bi-chat-left-text mr-0.5"></i><span>{tp.comments_count}</span></span>
                          <span><i className="bi bi-eye mr-0.5"></i><span>{tp.views_count || 0}</span></span>
                        </div>
                      </div>
                    </Link>
                  ))}
                </div>
              </div>

              {/* Quick Links */}
              <div className="voz-section rounded-2xl overflow-hidden">
                <div className="px-4 py-3 border-b border-white/5">
                  <h4 className="text-[10px] font-black text-white/55 uppercase tracking-widest">Liên kết nhanh</h4>
                </div>
                <div className="py-1">
                  <Link href="/forum/announcements/" className="w-full flex items-center gap-3 px-4 py-2.5 hover:bg-white/[0.03] transition-all text-left text-white/60 hover:text-warn-400">
                    <i className="bi bi-megaphone-fill text-xs text-warn-400/60"></i>
                    <span className="text-[11px] font-bold">Thông báo</span>
                  </Link>
                  <Link href="/profile/tickets/" className="w-full flex items-center gap-3 px-4 py-2.5 hover:bg-white/[0.03] transition-all text-left text-white/60 hover:text-brand-400">
                    <i className="bi bi-ticket-detailed text-xs text-brand-400/60"></i>
                    <span className="text-[11px] font-bold">Báo lỗi / Góp ý</span>
                  </Link>
                </div>
              </div>

              {/* Quick Category Navigation */}
              <div className="voz-section rounded-2xl overflow-hidden">
                <div className="px-4 py-3 border-b border-white/5">
                  <h4 className="text-[10px] font-black text-white/55 uppercase tracking-widest">Danh mục</h4>
                </div>
                <div className="py-1">
                  <button
                    onClick={() => openCategory('all')}
                    className={`w-full flex items-center gap-3 px-4 py-2.5 hover:bg-white/[0.03] transition-all text-left ${activeTab === 'all' && viewMode === 'threads' ? 'bg-white/[0.05] text-brand-400' : 'text-white/60'}`}
                  >
                    <i className="bi bi-grid-fill text-xs"></i>
                    <span className="text-[11px] font-bold">Tất cả</span>
                  </button>
                  {categoryStats.map((cat) => {
                    const meta = catInfo(cat.value);
                    const isActive = activeTab === cat.value && viewMode === 'threads';
                    return (
                      <button
                        key={`nav-${cat.value}`}
                        onClick={() => openCategory(cat.value)}
                        className={`w-full flex items-center justify-between px-4 py-2.5 hover:bg-white/[0.03] transition-all text-left ${isActive ? 'bg-white/[0.05]' : ''}`}
                      >
                        <div className="flex items-center gap-3">
                          <i className={`${meta.icon} ${meta.textColor} text-xs`}></i>
                          <span className={`text-[11px] font-bold ${isActive ? meta.textColor : 'text-white/60'}`}>{cat.label}</span>
                        </div>
                        <span className="text-[9px] font-bold text-white/35">{cat.threads_count}</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
