'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { api, ApiError, mediaUrl } from '../../lib/api';

import { renderMd } from '../../lib/chat/markdown';
import { MarkdownView, Spinner } from '../../components/ui';

interface RankInfo {
  name?: string;
  level?: string;
  color?: string;
  icon?: string;
}

interface PublicUser {
  username: string;
  display_name?: string;
  avatar?: string | null;
  about?: string | null;
  bio?: string | null;
  messenger_link?: string;
  date_joined?: string;
  is_staff?: boolean;
  rank_info?: RankInfo | null;
  rank_points?: number;
}

interface ForumPost {
  id: number;
  title: string;
  category?: string;
  created_at?: string;
  comments_count?: number;
}

interface PublicResp {
  user: PublicUser;
  posts?: ForumPost[];
  stats?: { total_posts?: number; total_reports?: number };
}

/* Port từ PKV/templates/Auth/public_profile.html. API: GET /user/profile/<username>/. */
export default function PublicProfile({ usernameProp }: { usernameProp?: string } = {}) {
  const { username: routeUsername } = useParams<{ username: string }>();
  const username = usernameProp || routeUsername;
  const [data, setData] = useState<PublicResp | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!username) return;
    let alive = true;
    api
      .get<PublicResp>(`/user/profile/${encodeURIComponent(username)}/`)
      .then((d) => {
        if (alive) setData(d);
      })
      .catch((e: unknown) => {
        if (!alive) return;
        if (e instanceof ApiError && e.status === 404) setError('Người dùng không tồn tại.');
        else setError('Không tải được hồ sơ.');
      });
    return () => {
      alive = false;
    };
  }, [username]);

  function copyLink(): void {
    void navigator.clipboard.writeText(window.location.href);
  }

  if (error) {
    return (
      <div className="animate-fadein max-w-6xl mx-auto px-4 py-20 text-center space-y-6">
        <p className="text-white/55 font-black uppercase tracking-widest text-sm">{error}</p>
        <Link href="/learn" className="text-brand-400 text-xs font-black uppercase tracking-widest">
          Về trang kiến thức
        </Link>
      </div>
    );
  }
  if (!data) return <Spinner />;

  const u = data.user;
  const posts = data.posts || [];
  const about = (u.about as string) || '';
  const rankPoints = u.rank_points ?? 0;
  const progress = Math.min(100, Math.floor(((rankPoints % 1000) / 10) * 10) / 10);
  const remain = 1000 - (rankPoints % 1000);
  const trust = Math.min(100, Math.floor(rankPoints / 20));
  const messenger = (u.messenger_link || '').trim();
  const hasMessenger = !!messenger && !['none', 'null', 'undefined', 'nan', 'false', '0'].includes(messenger.toLowerCase());

  return (
    <div className="animate-fadein max-w-6xl mx-auto space-y-8 px-4">
      <div className="relative rounded-[2.5rem] overflow-hidden shadow-2xl bg-[var(--sc-ink-deep)] border border-white/5">
        <div className="absolute inset-0 bg-gradient-to-br from-brand-500/20 via-brand2-500/10 to-transparent -z-10"></div>
        <div className="absolute top-0 right-0 w-full h-full bg-[radial-gradient(circle_at_top_right,rgba(0,229,255,0.15),transparent_50%)]"></div>

        <div className="p-8 sm:p-12 flex flex-col md:flex-row items-center md:items-end gap-10">
          <div className="relative group">
            <div className="absolute inset-0 bg-brand-400 blur-3xl opacity-20 group-hover:opacity-40 transition-opacity"></div>
            {u.avatar ? (
              <img
                src={mediaUrl(u.avatar)}
                alt={u.username}
                className="relative w-32 h-32 md:w-48 md:h-48 rounded-[2rem] object-cover border-4 border-white/10 shadow-2xl transition-transform group-hover:scale-[1.02]"
              />
            ) : (
              <div className="relative w-32 h-32 md:w-48 md:h-48 rounded-[2rem] bg-gradient-to-br from-brand-400 to-brand2-600 flex items-center justify-center text-6xl font-black text-white border-4 border-white/10 shadow-2xl group-hover:scale-[1.02] transition-transform">
                <span>{(u.username || '?').charAt(0).toUpperCase()}</span>
              </div>
            )}

            <div
              className={`absolute -bottom-4 -right-4 p-4 rounded-3xl bg-slate-900/90 border-2 border-white/10 shadow-2xl backdrop-blur-xl group-hover:translate-y-[-4px] transition-transform ${u.rank_info?.color || ''}`}
            >
              <i className={`bi text-3xl ${u.rank_info?.icon || 'bi-star-fill'}`}></i>
            </div>
          </div>

          <div className="flex-1 space-y-6 text-center md:text-left">
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-center md:justify-start gap-4">
                <h1 className="text-4xl md:text-6xl font-black text-white tracking-tight leading-none">
                  {u.display_name || u.username}
                </h1>
                {u.is_staff && (
                  <div className="flex items-center gap-2 px-4 py-2 rounded-2xl bg-brand-500/10 border border-brand-500/20 text-brand-400">
                    <i className="bi bi-patch-check-fill text-xl"></i>
                    <span className="text-[10px] font-black uppercase tracking-widest">Quản trị viên</span>
                  </div>
                )}
              </div>

              <div className="flex flex-wrap items-center justify-center md:justify-start gap-4 text-white/55 font-bold uppercase tracking-[0.2em] text-[11px]">
                <span className="text-white/60">@{u.username}</span>
                <span className="w-1.5 h-1.5 rounded-full bg-white/10"></span>
                <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-white/5 border border-white/5">
                  <i className="bi bi-stars text-warn-400"></i>
                  <span>{u.rank_info?.name || 'Thành viên'}</span>
                </div>
                <span className="w-1.5 h-1.5 rounded-full bg-white/10"></span>
                <div className="flex items-center gap-2">
                  <i className="bi bi-calendar3"></i>
                  Gia nhập <span>{u.date_joined ? new Date(u.date_joined).toLocaleDateString('vi-VN') : ''}</span>
                </div>
              </div>
            </div>

            <div className="flex flex-wrap justify-center md:justify-start gap-3">
              <button
                type="button"
                onClick={copyLink}
                className="liquid-btn py-3 px-8 text-[11px] bg-brand-500 text-black hover:bg-brand-400 shadow-lg shadow-brand-500/20"
              >
                <i className="bi bi-send-fill mr-2"></i> CHIA SẺ HỒ SƠ
              </button>
              {hasMessenger && (
                <a
                  href={messenger}
                  target="_blank"
                  rel="noreferrer"
                  className="liquid-btn py-3 px-8 text-[11px] bg-white/5 border-white/10 hover:bg-white/10"
                >
                  <i className="bi bi-chat-dots-fill mr-2"></i> NHẮN TIN
                </a>
              )}
            </div>
          </div>
        </div>

        <div className="bg-white/[0.02] border-t border-white/5 grid grid-cols-2 sm:grid-cols-4 divide-x divide-white/5">
          <div className="p-6 text-center group">
            <div className="text-[10px] font-black text-white/35 uppercase tracking-widest mb-1 group-hover:text-brand-400 transition-colors">
              Đóng góp
            </div>
            <div className="text-3xl font-black text-white">
              {data.stats?.total_posts ?? posts.length} <span className="text-xs text-white/45 font-bold">BÀI</span>
            </div>
          </div>
          <div className="p-6 text-center group">
            <div className="text-[10px] font-black text-white/35 uppercase tracking-widest mb-1 group-hover:text-danger-400 transition-colors">
              Báo cáo
            </div>
            <div className="text-3xl font-black text-white">
              {data.stats?.total_reports ?? 0} <span className="text-xs text-white/45 font-bold">TIN</span>
            </div>
          </div>
          <div className="p-6 text-center group">
            <div className="text-[10px] font-black text-white/35 uppercase tracking-widest mb-1 group-hover:text-warn-400 transition-colors">
              Hạng hiệu
            </div>
            <div className="text-3xl font-black text-white">{(u.rank_info?.level || '—').toUpperCase()}</div>
          </div>
          <div className="p-6 text-center group">
            <div className="text-[10px] font-black text-white/35 uppercase tracking-widest mb-1 group-hover:text-brand2-400 transition-colors">
              Uy tín
            </div>
            <div className="text-3xl font-black text-white">{trust}%</div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 pb-20">
        <div className="space-y-8 lg:sticky lg:top-24 h-fit">
          <div className="liquid-card p-6 space-y-6">
            <h4 className="text-[10px] font-black text-white/55 uppercase tracking-[0.3em] flex items-center gap-2">
              <i className="bi bi-bar-chart-fill"></i> Tiến trình uy tín
            </h4>
            <div className="space-y-4">
              <div className="flex justify-between items-end">
                <span className="text-xs font-black text-white uppercase tracking-wider">
                  {u.rank_info?.name || 'Thành viên'}
                </span>
                <span className="text-[10px] font-black text-white/55 uppercase">{rankPoints} ĐIỂM</span>
              </div>
              <div className="h-2 rounded-full bg-white/5 border border-white/5 overflow-hidden p-[2px]">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-brand-400 to-brand2-500 shadow-[0_0_10px_rgba(0,229,255,0.5)]"
                  style={{ width: `${progress}%` }}
                ></div>
              </div>
              <p className="text-[10px] text-center text-white/45 font-medium">
                Bạn cần thêm <span className="text-white/60">{remain}</span> điểm để lên hạng tiếp theo.
              </p>
            </div>
          </div>

          <div className="liquid-card p-6 space-y-6">
            <h4 className="text-[10px] font-black text-white/55 uppercase tracking-[0.3em] flex items-center gap-2">
              <i className="bi bi-info-circle-fill"></i> Thông tin thêm
            </h4>
            <div className="space-y-4">
              {u.bio && (
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg bg-white/5 flex items-center justify-center text-white/55">
                    <i className="bi bi-chat-quote"></i>
                  </div>
                  <div>
                    <p className="text-[9px] font-black text-white/35 uppercase tracking-widest">DANH NGÔN</p>
                    <p className="text-xs font-bold text-white/80 italic">&quot;{u.bio}&quot;</p>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="lg:col-span-2 space-y-8">
          <div className="liquid-card p-8 sm:p-10 space-y-8">
            <div className="flex items-center justify-between">
              <h2 className="text-2xl font-black text-white tracking-tight flex items-center gap-4">
                <span className="w-10 h-1 rounded-full bg-brand-400"></span>
                Về tôi
              </h2>
              <i className="bi bi-quote text-4xl text-white/5"></i>
            </div>

            <div className="prose prose-invert max-w-none prose-p:text-white/70 prose-headings:text-white prose-strong:text-brand-400">
              <MarkdownView html={renderMd(about || '*Người dùng chưa cập nhật thông tin giới thiệu.*')} />
            </div>
          </div>

          <div className="space-y-6">
            <h3 className="text-xs font-black text-white uppercase tracking-[0.3em] flex items-center gap-3 ml-4">
              <i className="bi bi-lightning-charge-fill text-warn-500"></i>
              Hoạt động cộng đồng gần đây
            </h3>

            <div className="space-y-4">
              {posts.map((post) => (
                <Link
                  key={post.id}
                  href={`/forum/${post.id}/`}
                  className="liquid-card p-6 flex items-center gap-6 hover:translate-x-1 hover:border-brand-400/30 transition-all group"
                >
                  <div className="w-14 h-14 rounded-2xl bg-white/5 flex items-center justify-center shrink-0 group-hover:bg-brand-500/10 transition-colors">
                    <i className="bi bi-journal-text text-2xl text-white/35 group-hover:text-brand-400 transition-colors"></i>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 mb-1">
                      {post.category && (
                        <span className="px-2 py-0.5 rounded-lg bg-brand-500/10 text-brand-400 text-[9px] font-black uppercase tracking-widest">
                          {post.category}
                        </span>
                      )}
                      <span className="text-[10px] font-black text-white/35">
                        {post.created_at ? new Date(post.created_at).toLocaleDateString('vi-VN') : ''}
                      </span>
                    </div>
                    <h4 className="text-lg font-bold text-white truncate group-hover:text-brand-400 transition-colors">
                      {post.title}
                    </h4>
                  </div>
                  <div className="flex items-center gap-2 text-white/45 text-xs font-black">
                    <i className="bi bi-chat-dots-fill"></i>
                    <span>{post.comments_count ?? 0}</span>
                  </div>
                </Link>
              ))}


              {posts.length === 0 && (
                <div className="p-20 text-center liquid-card bg-white/[0.01] border-dashed border-white/5">
                  <i className="bi bi-journals text-5xl text-white/5 mb-6 block"></i>
                  <p className="text-white/35 font-black uppercase tracking-widest text-xs">
                    Chưa tham gia thảo luận nào
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
