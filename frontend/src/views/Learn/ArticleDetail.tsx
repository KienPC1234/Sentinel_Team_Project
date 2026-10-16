'use client';
import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import {api, ApiError, mediaUrl} from '../../lib/api';
import { useAuth } from '../../components/AuthContext';
import { renderMd } from '../../lib/chat/markdown';
import { MarkdownView, Spinner } from '../../components/ui';
import { TurnstileWidget, getTsToken, resetTurnstile } from '../../components/ScanWidgets';
import { fmtDate } from '../../lib/date';

interface RelatedArticle {
  id: number;
  title: string;
  slug: string;
  category: string;
  category_display?: string;
  cover_image?: string | null;
  created_at: string;
  summary?: string;
}

interface ArticleDetail {
  id: number;
  title: string;
  content: string;
  category: string;
  category_display?: string;
  source_type?: string;
  source_type_display?: string;
  source_url?: string | null;
  cover_image?: string | null;
  author_name?: string;
  created_at: string;
  reaction_counts?: ReactionCounts;
  reactions_count?: number;
  my_reaction?: string | null;
  related_articles?: RelatedArticle[];
}

interface ReactionCounts {
  like: number;
  helpful: number;
  insightful: number;
}

interface ReactResp {
  my_reaction?: string | null;
  counts?: ReactionCounts;
  error?: string;
}

interface CommentItem {
  id: number;
  parent_id?: number | null;
  author_username: string;
  author_name: string;
  author_avatar?: string | null;
  content: string;
  created_at: string;
  upvotes_count: number;
  downvotes_count: number;
  my_vote?: string | null;
  replies: CommentItem[];
}

interface CommentListResp {
  results: CommentItem[];
  count: number;
}

const TURNSTILE_SITEKEY = (process.env.NEXT_PUBLIC_TURNSTILE_SITEKEY as string | undefined) || '';

/* Port từ PKV/templates/Learning/article_detail.html.
 * API: GET /articles/:slug/, POST /learn/articles/:slug/reaction/,
 * GET+POST /learn/articles/:slug/comments/, POST .../comments/:id/reaction/ (upvote/downvote). */
export default function ArticleDetail() {
  const { slug } = useParams<{ slug: string }>();
  const { user } = useAuth();
  const [article, setArticle] = useState<ArticleDetail | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [my, setMy] = useState<string | null>(null);
  const [counts, setCounts] = useState<ReactionCounts>({ like: 0, helpful: 0, insightful: 0 });
  const [comments, setComments] = useState<CommentItem[]>([]);
  const [commentCount, setCommentCount] = useState(0);
  const [body, setBody] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [replyToId, setReplyToId] = useState<number | null>(null);
  const [replyToName, setReplyToName] = useState('');
  const [commentError, setCommentError] = useState('');

  useEffect(() => {
    if (!slug) return;
    let alive = true;
    api
      .get<ArticleDetail>(`/articles/${slug}/`)
      .then((d) => {
        if (alive) {
          setArticle(d);
          if (d.reaction_counts) setCounts(d.reaction_counts);
          if (d.my_reaction) setMy(d.my_reaction);
        }
      })
      .catch((e: unknown) => {
        if (alive && e instanceof ApiError && e.status === 404) setNotFound(true);
      });
    api
      .get<CommentListResp>(`/learn/articles/${slug}/comments/`)
      .then((d) => {
        if (!alive) return;
        setComments(d.results || []);
        setCommentCount(Number(d.count || 0));
      })
      .catch(() => {
        /* ignore */
      });
    return () => {
      alive = false;
    };
  }, [slug]);

  useEffect(() => {
    if (!TURNSTILE_SITEKEY) return;
    if (document.querySelector('script[data-turnstile]')) return;
    const s = document.createElement('script');
    s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
    s.async = true;
    s.defer = true;
    s.setAttribute('data-turnstile', '1');
    document.body.appendChild(s);
  }, []);

  async function react(type: string): Promise<void> {
    if (!slug) return;
    if (!user) {
      window.location.href = `/login/?next=${encodeURIComponent(`/learn/${slug}/`)}`;
      return;
    }
    try {
      const data = await api.post<ReactResp>(`/learn/articles/${slug}/reaction/`, { reaction_type: type });
      setMy(data.my_reaction || null);
      if (data.counts) setCounts(data.counts);
    } catch {
      /* ignore */
    }
  }

  function totalReactions(): number {
    return counts.like + counts.helpful + counts.insightful;
  }

  function findComment(id: number): CommentItem | undefined {
    const root = comments.find((c) => Number(c.id) === Number(id));
    if (root) return root;
    for (const c of comments) {
      const r = (c.replies || []).find((x) => Number(x.id) === Number(id));
      if (r) return r;
    }
    return undefined;
  }

  async function voteComment(c: CommentItem, reactionType: string): Promise<void> {
    if (!slug) return;
    if (!user) {
      window.location.href = `/login/?next=${encodeURIComponent(`/learn/${slug}/`)}`;
      return;
    }
    try {
      const data = await api.post<{
        upvotes_count?: number;
        downvotes_count?: number;
        my_vote?: string | null;
      }>(`/learn/articles/${slug}/comments/${c.id}/reaction/`, { reaction_type: reactionType });
      const target = findComment(c.id);
      if (!target) return;
      target.upvotes_count = data.upvotes_count ?? target.upvotes_count;
      target.downvotes_count = data.downvotes_count ?? target.downvotes_count;
      target.my_vote = data.my_vote ?? null;
      setComments([...comments]);
    } catch {
      /* ignore */
    }
  }

  async function submitComment(e: FormEvent): Promise<void> {
    e.preventDefault();
    if (!slug || submitting || !body.trim()) return;
    /* Dùng widget Turnstile dùng chung (tự nạp script + render). Trước đây form
     * chỉ có div.cf-turnstile chết mà không nạp script nên token luôn rỗng và
     * mọi bình luận đều 400. */
    const ts = getTsToken();
    if (TURNSTILE_SITEKEY && !ts) {
      setCommentError('Vui lòng hoàn thành xác minh bảo mật (Anti-Spam).');
      return;
    }
    if (!TURNSTILE_SITEKEY) {
      setCommentError('Chưa cấu hình xác minh anti-spam (NEXT_PUBLIC_TURNSTILE_SITEKEY).');
      return;
    }
    setCommentError('');
    setSubmitting(true);
    try {
      const data = await api.post<CommentItem>(`/learn/articles/${slug}/comments/`, {
        content: body.trim(),
        parent_id: replyToId,
        'cf-turnstile-response': ts,
      });
      if (replyToId) {
        const parent = comments.find((c) => Number(c.id) === Number(replyToId));
        if (parent) parent.replies = [...(parent.replies || []), data];
        else setComments([...comments, data]);
      } else {
        setComments([...comments, data]);
      }
      setCommentCount((n) => n + 1);
      setBody('');
      setReplyToId(null);
      setReplyToName('');
      try {
        resetTurnstile();
      } catch {
        /* ignore */
      }
    } catch (e: unknown) {
      setCommentError(e instanceof Error ? e.message : 'Không gửi được bình luận.');
    } finally {
      setSubmitting(false);
    }
  }

  if (notFound) {
    return (
      <div className="animate-fadein max-w-4xl mx-auto py-20 px-4 text-center space-y-6">
        <p className="text-white/55 font-black uppercase tracking-widest text-sm">Bài viết không tồn tại.</p>
        <Link href="/learn" className="text-brand-400 text-xs font-black uppercase tracking-widest">
          Quay lại cẩm nang
        </Link>
      </div>
    );
  }
  if (!article) return <Spinner />;

  const reactBtn = (t: string, activeCls: string, idleCls: string, icon: string, label: string, n: number) => (
    <button
      key={t}
      type="button"
      onClick={() => void react(t)}
      className={`px-4 py-2.5 rounded-xl border text-xs font-bold transition-all flex items-center justify-between ${my === t ? activeCls : idleCls}`}
    >
      <span>
        <i className={`bi ${icon} mr-1.5`}></i>
        {label}
      </span>
      <span className="ml-2 text-[11px]">{n}</span>
    </button>
  );

  return (
    <div className="animate-fadein max-w-4xl mx-auto space-y-12 py-12 px-4 sm:px-0">
      <nav className="flex items-center gap-2 text-[10px] font-black uppercase tracking-widest text-white/35">
        <Link href="/" className="hover:text-brand-400 transition-colors">
          Trang chủ
        </Link>
        <i className="bi bi-chevron-right text-[8px]"></i>
        <Link href="/learn" className="hover:text-brand-400 transition-colors">
          Kiến thức
        </Link>
        <i className="bi bi-chevron-right text-[8px]"></i>
        <span className="text-white/55">{article.title.substring(0, 30)}</span>
      </nav>

      <div className="space-y-8 relative">
        <div className="flex flex-wrap items-center gap-3">
          <span className="px-4 py-1.5 rounded-full bg-brand-500/10 text-brand-400 text-[10px] font-black uppercase tracking-[0.2em] border border-brand-500/10">
            {article.category_display || article.category}
          </span>
          {article.source_type === 'tinnhiemmang' && (
            <span className="px-3 py-1 rounded-full bg-emerald-500/10 text-emerald-400 text-[10px] font-bold uppercase tracking-[0.1em] border border-emerald-500/20 flex items-center gap-1.5">
              <i className="bi bi-shield-check"></i> Tín nhiệm mạng (NCSC)
            </span>
          )}
          {article.source_url && (
            <a
              href={article.source_url}
              target="_blank"
              rel="noopener noreferrer"
              className="px-3 py-1 rounded-full bg-sky-500/10 text-sky-400 text-[10px] font-bold uppercase tracking-[0.1em] border border-sky-500/20 hover:bg-sky-500/20 transition-all flex items-center gap-1.5"
            >
              <span>Xem nguồn gốc</span> <i className="bi bi-box-arrow-up-right text-[8px]"></i>
            </a>
          )}
          <span className="text-[10px] font-bold text-white/45 uppercase tracking-[0.2em] flex items-center gap-2">
            <i className="bi bi-calendar3"></i> {fmtDate(article.created_at)}
          </span>
        </div>

        <h1 className="text-4xl sm:text-6xl font-black text-white tracking-tight leading-[1.1] selection:bg-brand-500/30">
          {article.title}
        </h1>

        <div className="flex items-center gap-5 py-8 border-y border-white/5 group">
          <div className="relative">
            <div className="absolute inset-0 bg-brand-500 blur-xl opacity-20 group-hover:opacity-40 transition-opacity"></div>
            <div className="relative w-12 h-12 rounded-2xl bg-gradient-to-tr from-slate-900 to-slate-800 border border-white/10 flex items-center justify-center text-brand-400 font-black text-lg shadow-2xl">
              {(article.author_name || 'S').charAt(0).toUpperCase()}
            </div>
          </div>
          <div>
            <div className="text-xs font-black text-white uppercase tracking-[0.2em]">
              {article.author_name || 'ShieldCall Admin'}
            </div>
            <div className="text-[9px] font-bold text-white/35 uppercase tracking-[0.2em] mt-1 flex items-center gap-1.5">
              <i className="bi bi-patch-check-fill text-brand-500/50"></i>{' '}
              {article.source_type === 'tinnhiemmang'
                ? 'Trung tâm Giám sát an toàn không gian mạng quốc gia (NCSC)'
                : 'Ban biên tập ShieldCall VN'}
            </div>
          </div>
        </div>
      </div>

      {article.cover_image && !/(<img|!\[[^\]]*\]\()/i.test(article.content || '') && (
        <div className="relative">
          <div className="absolute inset-0 bg-brand-500/10 blur-3xl opacity-30 rounded-full"></div>
          <div className="relative aspect-[21/9] rounded-[2.5rem] overflow-hidden bg-slate-900 border border-white/10 shadow-[0_20px_50px_rgba(0,0,0,0.5)]">
            <img src={mediaUrl(article.cover_image)} className="w-full h-full object-cover transition-transform duration-1000" alt={article.title} />
          </div>
        </div>
      )}

      <div
        className="prose prose-invert prose-cyan max-w-none text-white/85 leading-[1.8] font-medium text-base sm:text-lg selection:bg-brand-500/20 px-2"
      >
        <MarkdownView html={renderMd(article.content || '')} className="rich-text-content" />
      </div>

      <div className="space-y-6">
        <div className="liquid-card p-6 border border-white/5 space-y-4">
          <div className="flex items-center justify-between gap-3">
            <div className="text-[10px] font-black text-white/45 uppercase tracking-[0.2em]">Phản ứng bài viết</div>
            <div className="text-[11px] font-bold text-white/45">{totalReactions()} phản ứng</div>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
            {reactBtn(
              'like',
              'bg-brand-500/20 text-brand-300 border-brand-500/40',
              'bg-white/5 text-white/70 border-white/10 hover:border-brand-500/30',
              'bi-hand-thumbs-up-fill',
              'Thích',
              counts.like,
            )}
            {reactBtn(
              'helpful',
              'bg-safe-500/20 text-safe-300 border-safe-500/40',
              'bg-white/5 text-white/70 border-white/10 hover:border-safe-500/30',
              'bi-patch-check-fill',
              'Hữu ích',
              counts.helpful,
            )}
            {reactBtn(
              'insightful',
              'bg-brand2-500/20 text-brand2-300 border-brand2-500/40',
              'bg-white/5 text-white/70 border-white/10 hover:border-brand2-500/30',
              'bi-lightbulb-fill',
              'Bổ ích',
              counts.insightful,
            )}
          </div>
        </div>

        <div className="liquid-card p-6 border border-white/5 space-y-5">
          <div className="flex items-center justify-between">
            <div className="text-[10px] font-black text-white/45 uppercase tracking-[0.2em]">Bình luận tin tức</div>
            <div className="text-xs font-bold text-white/55">{commentCount} bình luận</div>
          </div>
          {user ? (
            <form onSubmit={submitComment} className="space-y-3">
              <textarea
                value={body}
                onChange={(e) => setBody(e.target.value)}
                rows={4}
                maxLength={1500}
                placeholder="Viết bình luận của bạn..."
                className="liquid-input w-full p-4 text-sm text-white/80 focus:outline-none"
              />
              {replyToId && (
                <div className="px-3 py-2 rounded-xl bg-brand-500/10 border border-brand-500/20 flex items-center justify-between">
                  <div className="text-[11px] text-brand-300">
                    Đang trả lời <span className="font-black">{replyToName || 'bình luận'}</span>
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      setReplyToId(null);
                      setReplyToName('');
                    }}
                    className="text-[10px] font-black text-white/60 hover:text-white"
                  >
                    Hủy
                  </button>
                </div>
              )}
              <TurnstileWidget />
              {commentError && (
                <p className="text-danger-400 text-xs font-bold">{commentError}</p>
              )}
              <div className="flex items-center justify-between gap-3">
                <div className="text-[10px] text-white/45">{body.length}/1500</div>
                <button
                  type="submit"
                  disabled={submitting || !body.trim()}
                  className="px-5 py-2.5 rounded-xl bg-brand-500 text-black text-xs font-black uppercase tracking-widest hover:bg-brand-400 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {submitting ? 'Đang gửi...' : 'Gửi bình luận'}
                </button>
              </div>
            </form>
          ) : (
            <a
              href={`/login/?next=${encodeURIComponent(`/learn/${slug}/`)}`}
              className="inline-flex items-center gap-2 text-xs font-bold text-brand-400 hover:text-brand-300 transition-colors"
            >
              Đăng nhập để bình luận
            </a>
          )}
          <div className="space-y-3">
            {comments.length === 0 && (
              <div className="p-4 rounded-2xl bg-white/[0.03] border border-white/10 text-xs text-white/55 italic">
                Chưa có bình luận nào, hãy mở đầu cuộc thảo luận.
              </div>
            )}
            {comments.map((c) => (
              <CommentCard
                key={c.id}
                comment={c}
                slug={slug || ''}
                onReply={() => {
                  setReplyToId(c.id);
                  setReplyToName(c.author_name);
                }}
                onVote={(t) => void voteComment(c, t)}
              />
            ))}
          </div>
        </div>

        {article.related_articles && article.related_articles.length > 0 && (
          <div className="space-y-4 pt-4">
            <div className="text-[10px] font-black text-white/45 uppercase tracking-[0.2em] flex items-center gap-2">
              <i className="bi bi-grid-fill text-brand-400"></i> BÀI VIẾT LIÊN QUAN
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              {article.related_articles.map((rel) => (
                <Link
                  key={rel.id}
                  href={`/learn/${rel.slug}/`}
                  className="liquid-card p-4 border border-white/5 hover:border-brand-500/30 transition-all group flex flex-col justify-between"
                >
                  <div className="space-y-2">
                    <span className="text-[9px] font-bold text-brand-400 uppercase tracking-widest px-2 py-0.5 rounded-full bg-brand-500/10 border border-brand-500/20">
                      {rel.category_display || rel.category}
                    </span>
                    <h4 className="text-xs font-bold text-white group-hover:text-brand-300 transition-colors line-clamp-2">
                      {rel.title}
                    </h4>
                  </div>
                  <div className="text-[10px] text-white/40 mt-3 pt-2 border-t border-white/5 flex items-center justify-between">
                    <span>{fmtDate(rel.created_at)}</span>
                    <span className="text-brand-400 font-bold group-hover:translate-x-1 transition-transform">
                      Đọc tiếp &rarr;
                    </span>
                  </div>
                </Link>
              ))}
            </div>
          </div>
        )}

        <div className="pt-4">
          <Link
            href="/learn"
            className="liquid-btn py-3 px-8 text-[11px] bg-white/5 border-white/10 hover:bg-white/10 inline-flex items-center gap-2"
          >
            <i className="bi bi-arrow-left"></i> QUAY LẠI CẨM NANG
          </Link>
        </div>
      </div>
    </div>
  );
}

function CommentCard({
  comment,
  slug,
  onReply,
  onVote,
}: {
  comment: CommentItem;
  slug: string;
  onReply: () => void;
  onVote: (t: string) => void;
}) {
  void slug;
  const initial = (comment.author_name || '?').charAt(0).toUpperCase();
  return (
    <div className="rounded-2xl bg-white/[0.04] border border-white/10 p-4 space-y-3">
      <div className="flex items-start gap-3">
        <Link
          href={`/profile/@${comment.author_username}/`}
          data-usercard={comment.author_username}
          className="w-9 h-9 rounded-full bg-brand-500/10 border border-brand-500/20 text-brand-300 text-xs font-black flex items-center justify-center shrink-0 overflow-hidden hover:border-brand-400/40 transition-all"
        >
          {comment.author_avatar ? (
            <img src={mediaUrl(comment.author_avatar)} alt={comment.author_name} className="w-full h-full object-cover" />
          ) : (
            <span>{initial}</span>
          )}
        </Link>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <Link
              href={`/profile/@${comment.author_username}/`}
              data-usercard={comment.author_username}
              className="text-xs font-black text-white/80 hover:text-brand-300 transition-colors"
            >
              {comment.author_name}
            </Link>
            <span className="text-[9px] text-white/55">
              {comment.created_at ? new Date(comment.created_at).toLocaleString('vi-VN') : ''}
            </span>
          </div>
          <div className="text-xs text-white/70 leading-relaxed mt-1">
            <MarkdownView html={renderMd(comment.content || '')} />
          </div>
          <div className="flex items-center gap-3 mt-2">
            <button
              type="button"
              onClick={() => onVote('upvote')}
              className={`text-[10px] font-bold flex items-center gap-1 ${comment.my_vote === 'upvote' ? 'text-brand-300' : 'text-white/45 hover:text-brand-300'}`}
            >
              <i className="bi bi-hand-thumbs-up-fill"></i> {comment.upvotes_count}
            </button>
            <button
              type="button"
              onClick={() => onVote('downvote')}
              className={`text-[10px] font-bold flex items-center gap-1 ${comment.my_vote === 'downvote' ? 'text-danger-300' : 'text-white/45 hover:text-danger-300'}`}
            >
              <i className="bi bi-hand-thumbs-down-fill"></i> {comment.downvotes_count}
            </button>
            <button
              type="button"
              onClick={onReply}
              className="text-[10px] font-bold text-white/45 hover:text-white"
            >
              Trả lời
            </button>
          </div>
        </div>
      </div>
      {(comment.replies || []).length > 0 && (
        <div className="ml-6 pl-3 border-l border-white/10 space-y-3">
          {comment.replies.map((r) => (
            <div key={r.id} className="flex items-start gap-3">
              <Link
                href={`/profile/@${r.author_username}/`}
                data-usercard={r.author_username}
                className="w-7 h-7 rounded-full bg-brand2-500/10 border border-brand2-500/20 text-brand2-300 text-[10px] font-black flex items-center justify-center shrink-0 overflow-hidden hover:border-brand2-400/40 transition-all"
              >
                {r.author_avatar ? (
                  <img src={mediaUrl(r.author_avatar)} alt={r.author_name} className="w-full h-full object-cover" />
                ) : (
                  <span>{(r.author_name || '?').charAt(0).toUpperCase()}</span>
                )}
              </Link>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <Link
                    href={`/profile/@${r.author_username}/`}
                    data-usercard={r.author_username}
                    className="text-[11px] font-black text-white/80 hover:text-brand-300 transition-colors"
                  >
                    {r.author_name}
                  </Link>
                  <span className="text-[9px] text-white/55">
                    {r.created_at ? new Date(r.created_at).toLocaleString('vi-VN') : ''}
                  </span>
                </div>
                <div className="text-xs text-white/70 leading-relaxed mt-1">
                  <MarkdownView html={renderMd(r.content || '')} />
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
