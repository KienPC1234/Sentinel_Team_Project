'use client';
/* Port 1-1 từ PKV/templates/Forum/forum_detail.html (VOZ-style thread).
 * Chuyển Alpine.data('forumDetail') → React state/hooks/handler. Giữ nguyên
 * tầng API: /forum/posts/<id>/ (detail, PATCH lock), /forum/posts/<id>/comment/,
 * /forum/posts/<id>/like/mutual/, /forum/posts/<id>/reaction/mutual/,
 * /forum/comments/<id>/reaction/, /forum/posts|comments/<id>/report/,
 * /user/scan-picker/, /scan/status/<id>/, /admin-cp/forum/ban/, WS /ws/forum/.
 */
import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import Swal from 'sweetalert2';
import { api, ApiError, mediaUrl } from '../../lib/api';
import { EmptyState, Spinner } from '../../components/ui';
import RichEditor, { getEditorData, setEditorData } from '../../components/RichEditor';
import { TurnstileWidget, getTsToken, resetTurnstile, wsBase } from '../../components/ScanWidgets';
import { guardrailTone, guardrailLabel } from '../../components/ScanWidgets';
import { showToast } from '../../lib/ui/feedback';
import { useAuth } from '../../components/AuthContext';
import { sanitizeHtml } from '../../lib/chat/markdown';
import type { ForumPost } from './Forum';

const MAX_REPLY_DEPTH = 5;

interface RankInfo {
  name?: string;
  level?: string;
  icon?: string;
  color?: string;
}

interface ForumComment {
  id: number;
  content: string;
  author_name?: string;
  author_username?: string;
  author_avatar?: string | null;
  author_is_staff?: boolean;
  author_rank?: RankInfo | null;
  author_posts_count?: number;
  parent_author_name?: string | null;
  created_at?: string;
  likes_count?: number;
  dislikes_count?: number;
  helpful_count?: number;
  user_liked?: boolean;
  user_disliked?: boolean;
  user_helpful?: boolean;
  depth?: number;
  replies?: ForumComment[];
}

interface PostDetail extends ForumPost {
  image?: string | null;
  author_is_staff?: boolean;
  author_rank?: RankInfo | null;
  author_posts_count?: number;
  author_comments_count?: number;
  author_joined?: string;
  likes_count: number;
  dislikes_count?: number;
  helpful_count?: number;
  shares_count?: number;
  unique_views_count?: number;
  user_liked?: boolean;
  user_helpful?: boolean;
  user_shared?: boolean;
  user_disliked?: boolean;
  scan_reference?: { scan_id?: number } | null;
  last_comment_author?: { name?: string; username?: string; avatar?: string | null } | null;
  last_comment_at?: string | null;
  comments?: ForumComment[];
}

interface PickScan {
  id: number;
  scan_type?: string;
  status?: string;
  risk_score?: number;
  risk_level?: string;
  verdict_tone?: string;
  verdict_label?: string;
  preview?: string;
  is_owner?: boolean;
}

interface RefScan {
  id: number;
  status: string;
  scan_type: string;
  risk_score: number;
  risk_level: string;
  result?: Record<string, unknown>;
}

interface PickerFilters {
  scope: string;
  type: string;
  riskLevel: string;
  q: string;
  manualId: string;
}

interface PickerTarget {
  type: 'comment' | 'reply';
  commentId: number | null;
}

interface ReactionResp {
  likes_count?: number;
  dislikes_count?: number;
  helpful_count?: number;
  shares_count?: number;
  liked?: boolean;
  reacted?: boolean;
  user_liked?: boolean;
  user_disliked?: boolean;
  user_helpful?: boolean;
}

function timeAgo(dt?: string | null): string {
  if (!dt) return '';
  const diff = (Date.now() - new Date(dt).getTime()) / 1000;
  if (Number.isNaN(diff)) return '';
  if (diff < 60) return 'Vừa xong';
  if (diff < 3600) return `${Math.floor(diff / 60)} phút`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} giờ`;
  return `${Math.floor(diff / 86400)} ngày`;
}

function formatDate(dt?: string | null): string {
  if (!dt) return '';
  const d = new Date(dt);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleDateString('vi-VN', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function categoryLabel(cat?: string): string {
  const map: Record<string, string> = { warning: 'Cảnh báo', discussion: 'Thảo luận', experience: 'Kinh nghiệm', question: 'Hỏi đáp' };
  return map[cat || ''] || cat || '';
}

function categoryBadgeClass(cat?: string): string {
  switch (cat) {
    case 'warning':
      return 'bg-danger-500/10 text-danger-500 border-danger-500/20';
    case 'discussion':
      return 'bg-brand-500/10 text-brand-400 border-brand-500/20';
    case 'experience':
      return 'bg-brand2-500/10 text-brand2-400 border-brand2-500/20';
    case 'question':
      return 'bg-warn-500/10 text-warn-400 border-warn-500/20';
    default:
      return '';
  }
}

function levelClass(level?: string | null): string {
  const v = String(level || '').toUpperCase();
  if (v === 'RED') return 'text-danger-300 border-danger-400/30 bg-danger-500/10';
  if (v === 'YELLOW') return 'text-warn-300 border-warn-400/30 bg-warn-500/10';
  if (v === 'GREEN' || v === 'SAFE') return 'text-safe-300 border-safe-400/30 bg-safe-500/10';
  if (v === 'UNVERIFIED') return 'text-slate-300 border-slate-400/30 bg-slate-500/10';
  return 'text-brand-300 border-brand-400/30 bg-brand-500/10';
}

function scanTypeLabel(scan: { scan_type?: string } | null | undefined): string {
  const type = (scan?.scan_type || 'scan').toUpperCase();
  const map: Record<string, string> = {
    PHONE: 'Số điện thoại', MESSAGE: 'Tin nhắn', DOMAIN: 'Domain', ACCOUNT: 'Tài khoản',
    QR: 'QR/Ảnh', EMAIL: 'Email', FILE: 'Tệp', AUDIO: 'Âm thanh',
  };
  return map[type] || type;
}

function getInitial(name?: string): string {
  return name ? name.charAt(0).toUpperCase() : '?';
}

function avatarFallbackStyle(name?: string): { background: string; color: string } {
  const value = String(name || '').trim().toLowerCase();
  let hash = 0;
  for (let index = 0; index < value.length; index += 1) {
    hash = (hash * 31 + value.charCodeAt(index)) % 360;
  }
  const hue = Number.isFinite(hash) ? hash : 180;
  return { background: `hsl(${hue}, 68%, 38%)`, color: 'rgba(255,255,255,0.95)' };
}

function findCommentById(nodes: ForumComment[] | undefined, commentId: number): ForumComment | null {
  for (const node of nodes || []) {
    if (node.id === commentId) return node;
    const found = findCommentById(node.replies, commentId);
    if (found) return found;
  }
  return null;
}

function addReply(nodes: ForumComment[], parentId: number, comment: ForumComment): ForumComment[] {
  return nodes.map((x) => {
    if (x.id === parentId) return { ...x, replies: [...(x.replies || []), comment] };
    return { ...x, replies: addReply(x.replies || [], parentId, comment) };
  });
}

function patchComment(nodes: ForumComment[], commentId: number, patch: Partial<ForumComment>): ForumComment[] {
  return nodes.map((x) => (x.id === commentId ? { ...x, ...patch } : { ...x, replies: patchComment(x.replies || [], commentId, patch) }));
}

function removeComment(nodes: ForumComment[], target: number, state: { removed: boolean }): ForumComment[] {
  const out: ForumComment[] = [];
  for (const node of nodes) {
    if (Number(node.id) === target) {
      state.removed = true;
      continue;
    }
    out.push({ ...node, replies: removeComment(node.replies || [], target, state) });
  }
  return out;
}

function flattenComments(nodes: ForumComment[] | undefined): ForumComment[] {
  const out: ForumComment[] = [];
  const walk = (list: ForumComment[]): void => {
    for (const node of list || []) {
      out.push(node);
      if (node.replies && node.replies.length) walk(node.replies);
    }
  };
  walk(nodes || []);
  return out;
}

async function adminPost(path: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
  const m = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]*)/);
  const csrf = m ? decodeURIComponent(m[1]) : '';
  const res = await fetch(path, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...(csrf ? { 'X-CSRFToken': csrf } : {}) },
    body: JSON.stringify(body),
  });
  return (await res.json()) as Record<string, unknown>;
}

export default function ForumDetail() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const { user } = useAuth();

  const [post, setPost] = useState<PostDetail | null>(null);
  const [comments, setComments] = useState<ForumComment[]>([]);
  const [loadingInit, setLoadingInit] = useState(true);
  const [notFound, setNotFound] = useState(false);
  const [sending, setSending] = useState(false);

  const [commentScanId, setCommentScanId] = useState<number | ''>('');
  const [replyTo, setReplyTo] = useState<number | null>(null);
  const [replyAuthorName, setReplyAuthorName] = useState('');
  const [repliesContent, setRepliesContent] = useState<Record<number, string>>({});
  const [replyScanId, setReplyScanIdState] = useState<Record<number, number | ''>>({});

  const [scanPickerOpen, setScanPickerOpen] = useState(false);
  const [scanPickerLoading, setScanPickerLoading] = useState(false);
  const [scanPickerResults, setScanPickerResults] = useState<PickScan[]>([]);
  const [scanPickerTarget, setScanPickerTarget] = useState<PickerTarget>({ type: 'comment', commentId: null });
  const [scanPickerFilters, setScanPickerFilters] = useState<PickerFilters>({ scope: 'mine', type: '', riskLevel: '', q: '', manualId: '' });

  const [referencedScan, setReferencedScan] = useState<RefScan | null>(null);
  const [referencedScanLoading, setReferencedScanLoading] = useState(false);
  const [shareUrl, setShareUrl] = useState('');

  const [commentPage, setCommentPage] = useState(1);
  const commentsPerPage = 15;

  const commentEditorRef = useRef<unknown | null>(null);
  const replyEditorRef = useRef<unknown | null>(null);
  const commentsRef = useRef<ForumComment[]>([]);
  const replyScanIdRef = useRef<Record<number, number | ''>>({});
  const commentScanIdRef = useRef<number | ''>('');
  const postIdRef = useRef<string | undefined>(undefined);

  useEffect(() => { commentsRef.current = comments; }, [comments]);
  useEffect(() => { replyScanIdRef.current = replyScanId; }, [replyScanId]);
  useEffect(() => { commentScanIdRef.current = commentScanId; }, [commentScanId]);
  useEffect(() => { postIdRef.current = id; }, [id]);
  useEffect(() => { setShareUrl(window.location.href); }, [id]);

  const loadReferencedScan = (scanId: number): void => {
    if (!scanId) {
      setReferencedScan(null);
      return;
    }
    setReferencedScanLoading(true);
    api
      .get<RefScan>(`/scan/status/${scanId}/`)
      .then((payload) => {
        setReferencedScan({
          id: Number(payload.id || scanId),
          status: String(payload.status || 'unknown'),
          scan_type: String(payload.scan_type || 'unknown'),
          risk_score: Number(payload.risk_score || 0),
          risk_level: String(payload.risk_level || 'N/A'),
          result: payload.result || {},
        });
      })
      .catch(() => {
        setReferencedScan({ id: scanId, status: 'unknown', scan_type: 'unknown', risk_score: 0, risk_level: 'N/A' });
      })
      .finally(() => setReferencedScanLoading(false));
  };

  const refreshPostDetail = (): void => {
    const postId = postIdRef.current;
    if (!postId) return;
    api
      .get<PostDetail>(`/forum/posts/${postId}/`)
      .then((data) => {
        setPost(data);
        setComments(data.comments || []);
        loadReferencedScan(Number(data.scan_reference?.scan_id || 0));
      })
      .catch(() => {});
  };

  /* Initial load (thay cho json_script #forum-post-data / #forum-comments-data). */
  useEffect(() => {
    if (!id) return;
    let alive = true;
    api
      .get<PostDetail>(`/forum/posts/${id}/`)
      .then((data) => {
        if (!alive) return;
        setPost(data);
        setComments(data.comments || []);
        setNotFound(false);
        loadReferencedScan(Number(data.scan_reference?.scan_id || 0));
      })
      .catch(() => { if (alive) setNotFound(true); })
      .finally(() => { if (alive) setLoadingInit(false); });
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  /* Realtime WS /ws/forum/ (giữ nguyên reconnect + ping như bản gốc). */
  useEffect(() => {
    if (!id) return;
    let ws: WebSocket | null = null;
    let pingTimer: number | null = null;
    let reconnectTimer: number | null = null;
    let closed = false;

    const connect = (): void => {
      if (closed) return;
      try {
        ws = new WebSocket(`${wsBase()}/ws/forum/`);
      } catch {
        return;
      }
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(String(event.data || '{}')) as { type?: string; event?: string; payload?: Record<string, unknown> };
          if (data.type !== 'forum_live_event') return;
          const payload = data.payload || {};
          if (Number(payload.post_id) !== Number(id)) return;
          if (data.event === 'comment_created' || data.event === 'post_created') {
            refreshPostDetail();
          } else if (data.event === 'comment_moderated') {
            refreshPostDetail();
            showToast('Một bình luận đã bị tạm ẩn để chờ Admin xử lý', 'info');
          } else if (data.event === 'post_moderated') {
            refreshPostDetail();
            showToast('Bài viết đã bị tạm ẩn để chờ Admin xử lý', 'warning');
          } else if (data.event === 'comment_deleted') {
            const deletedId = Number(payload.comment_id || 0);
            const state = { removed: false };
            const next = removeComment(commentsRef.current, deletedId, state);
            if (deletedId && state.removed) {
              commentsRef.current = next;
              setComments(next);
              setPost((prev) => (prev ? { ...prev, comments_count: Math.max(0, Number(prev.comments_count || 0) - 1) } : prev));
              showToast('Một bình luận đã bị gỡ do vi phạm', 'info');
            }
          } else if (data.event === 'post_deleted') {
            showToast('Bài viết đã bị gỡ do vi phạm', 'warning');
            window.setTimeout(() => router.push('/forum/'), 700);
          }
        } catch {
          /* ignore */
        }
      };
      ws.onopen = () => {
        pingTimer = window.setInterval(() => {
          if (ws && ws.readyState === WebSocket.OPEN) {
            try { ws.send(JSON.stringify({ type: 'ping' })); } catch { /* ignore */ }
          }
        }, 30000);
      };
      ws.onclose = () => {
        if (pingTimer != null) { window.clearInterval(pingTimer); pingTimer = null; }
        if (closed) return;
        reconnectTimer = window.setTimeout(connect, 2000);
      };
    };
    connect();
    return () => {
      closed = true;
      if (pingTimer != null) window.clearInterval(pingTimer);
      if (reconnectTimer != null) window.clearTimeout(reconnectTimer);
      try { ws?.close(); } catch { /* ignore */ }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  const flattenedComments = (): ForumComment[] => flattenComments(comments);

  const participantUsers = (): Array<{ username?: string; name?: string; avatar?: string | null; role: string }> => {
    const users: Array<{ username?: string; name?: string; avatar?: string | null; role: string }> = [];
    const seen = new Set<string>();
    const postAuthor = String(post?.author_username || '').trim().toLowerCase();
    const addUser = (username?: string, name?: string, avatar?: string | null): void => {
      const key = String(username || '').trim().toLowerCase();
      if (!key || seen.has(key)) return;
      seen.add(key);
      users.push({ username, name, avatar, role: key === postAuthor ? 'Chủ post' : 'Người comment' });
    };
    addUser(post?.author_username, post?.author_name, post?.author_avatar);
    for (const comment of flattenedComments()) addUser(comment.author_username, comment.author_name, comment.author_avatar);
    return users;
  };

  const visibleParticipants = (): ReturnType<typeof participantUsers> => participantUsers().slice(0, 8);
  const remainingParticipantsCount = (): number => {
    const total = participantUsers().length;
    return total > 8 ? total - 8 : 0;
  };

  const canReply = (commentId: number): boolean => {
    const target = findCommentById(comments, commentId);
    if (!target) return false;
    return (target.depth || 1) < MAX_REPLY_DEPTH;
  };

  const commentTotalPages = (): number => Math.max(1, Math.ceil(flattenedComments().length / commentsPerPage));
  const paginatedComments = (): ForumComment[] => {
    const flat = flattenedComments();
    const start = (commentPage - 1) * commentsPerPage;
    return flat.slice(start, start + commentsPerPage);
  };
  const commentPageNumbers = (): Array<number | string> => {
    const total = commentTotalPages();
    const cur = commentPage;
    const pages: Array<number | string> = [];
    const start = Math.max(1, cur - 2);
    const end = Math.min(total, cur + 2);
    if (start > 1) pages.push(1);
    if (start > 2) pages.push('...');
    for (let i = start; i <= end; i++) pages.push(i);
    if (end < total - 1) pages.push('...');
    if (end < total) pages.push(total);
    return pages;
  };
  const goToCommentPage = (p: number): void => {
    if (p >= 1 && p <= commentTotalPages()) {
      setCommentPage(p);
      document.getElementById('comments-section')?.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const fetchScanPicker = async (filters: PickerFilters, extra: { scanId?: string } = {}): Promise<PickScan[]> => {
    setScanPickerLoading(true);
    try {
      const params = new URLSearchParams();
      params.set('scope', filters.scope || 'mine');
      if (filters.type) params.set('type', filters.type);
      if (filters.riskLevel) params.set('risk_level', filters.riskLevel);
      if (filters.q && filters.q.trim()) params.set('q', filters.q.trim());
      if (extra.scanId) params.set('scan_id', String(extra.scanId));
      const payload = await api.get<PickScan[] | { results?: PickScan[] }>(`/user/scan-picker/?${params.toString()}`);
      const rows = Array.isArray(payload) ? payload : (payload.results || []);
      setScanPickerResults(rows);
      return rows;
    } catch {
      setScanPickerResults([]);
      return [];
    } finally {
      setScanPickerLoading(false);
    }
  };

  const commitPickedScan = (scan: PickScan, target: PickerTarget): void => {
    if (!scan || !scan.id) return;
    const parsed = parseInt(String(scan.id), 10);
    if (!Number.isFinite(parsed) || parsed < 1) {
      showToast('Scan ID không hợp lệ', 'warning');
      return;
    }
    if (target.type === 'reply' && target.commentId) {
      const cid = target.commentId;
      setReplyScanIdState((prev) => ({ ...prev, [cid]: parsed }));
      showToast(`Đã gắn Scan ID #${parsed} cho phản hồi`, 'success');
    } else {
      setCommentScanId(parsed);
      showToast(`Đã gắn Scan ID #${parsed} cho bình luận`, 'success');
    }
    setScanPickerFilters((f) => ({ ...f, manualId: String(parsed) }));
    setScanPickerOpen(false);
  };

  const clearPickedScan = (target: PickerTarget = scanPickerTarget): void => {
    if (target.type === 'reply' && target.commentId) {
      const cid = target.commentId;
      setReplyScanIdState((prev) => ({ ...prev, [cid]: '' }));
      showToast('Đã xóa Scan ID tham chiếu', 'info');
      return;
    }
    setCommentScanId('');
    showToast('Đã xóa Scan ID tham chiếu', 'info');
  };

  const applyManualScanId = async (raw: string, target: PickerTarget, filters: PickerFilters): Promise<void> => {
    const digits = String(raw || '').replace(/\D/g, '');
    if (!digits) {
      showToast('Vui lòng nhập Scan ID', 'warning');
      return;
    }
    const rows = await fetchScanPicker(filters, { scanId: digits });
    if (!rows.length) {
      showToast('Scan ID không thuộc bạn hoặc chưa được public refer bởi chủ scan', 'error');
      return;
    }
    commitPickedScan(rows[0], target);
  };

  const openScanPickerDialog = async (targetType: 'comment' | 'reply', commentId: number | null = null): Promise<void> => {
    const target: PickerTarget = { type: targetType, commentId };
    const filters: PickerFilters = {
      ...scanPickerFilters,
      manualId: String(targetType === 'reply' ? (replyScanIdRef.current[commentId || 0] || '') : (commentScanIdRef.current || '')),
    };
    setScanPickerTarget(target);
    setScanPickerFilters(filters);
    const rows = await fetchScanPicker(filters);
    if (!rows.length) {
      const manual = await Swal.fire({
        title: 'Không có scan phù hợp',
        text: 'Bạn có thể nhập Scan ID thủ công',
        input: 'text',
        inputPlaceholder: 'Nhập Scan ID...',
        showCancelButton: true,
        confirmButtonText: 'Dùng Scan ID',
        cancelButtonText: 'Hủy',
        background: 'var(--sc-night-2)',
        color: 'var(--sc-white)',
      });
      if (!manual.isConfirmed) return;
      await applyManualScanId(String(manual.value || ''), target, filters);
      return;
    }

    const result = await Swal.fire({
      title: 'Chọn scan tham chiếu',
      html: `
        <div class="space-y-3 text-left">
          <label for="scan-picker-select" class="text-[10px] font-black uppercase tracking-widest text-white/45">Scan khả dụng</label>
          <select id="scan-picker-select" class="liquid-input w-full py-3 px-4 text-sm font-bold">
            <option value="">-- Chọn 1 scan --</option>
            ${rows.slice(0, 100).map((scan) => {
              const text = `#${scan.id} · ${scanTypeLabel(scan)} · ${(scan.verdict_label || scan.risk_level || 'N/A')}`;
              return `<option value="${scan.id}">${text.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</option>`;
            }).join('')}
          </select>
        </div>
      `,
      showCancelButton: true,
      showDenyButton: true,
      denyButtonText: 'Nhập ID',
      confirmButtonText: 'Gắn scan',
      cancelButtonText: 'Hủy',
      background: 'var(--sc-night-2)',
      color: 'var(--sc-white)',
      customClass: { popup: 'liquid-card border border-white/10 !rounded-2xl' },
      preConfirm: () => {
        const selected = (document.getElementById('scan-picker-select') as HTMLSelectElement | null)?.value || '';
        if (!selected) {
          Swal.showValidationMessage('Vui lòng chọn scan');
          return null;
        }
        return selected;
      },
    });

    if (result.isDenied) {
      const manual = await Swal.fire({
        title: 'Nhập Scan ID',
        input: 'text',
        inputPlaceholder: 'VD: 123',
        showCancelButton: true,
        confirmButtonText: 'Dùng ID này',
        cancelButtonText: 'Hủy',
        background: 'var(--sc-night-2)',
        color: 'var(--sc-white)',
        customClass: { popup: 'liquid-card border border-white/10 !rounded-2xl' },
      });
      if (manual.isConfirmed) {
        await applyManualScanId(String(manual.value || ''), target, filters);
      }
      return;
    }

    if (result.isConfirmed && result.value) {
      commitPickedScan({ id: Number(result.value) }, target);
    }
  };

  const patchFilters = (patch: Partial<PickerFilters>): PickerFilters => {
    const next = { ...scanPickerFilters, ...patch };
    setScanPickerFilters(next);
    return next;
  };

  const submitComment = async (parentId: number | null = null): Promise<void> => {
    if (!post) return;
    const content = parentId ? getEditorData(replyEditorRef.current) : getEditorData(commentEditorRef.current);
    if (!content || !content.trim()) return;

    if (parentId && !canReply(parentId)) {
      showToast(`Chỉ cho phép trả lời tối đa ${MAX_REPLY_DEPTH} tầng`, 'warning');
      return;
    }

    const tsToken = getTsToken();
    const siteKey = (process.env.NEXT_PUBLIC_TURNSTILE_SITEKEY as string | undefined) || '';
    if (siteKey && !tsToken) {
      showToast('Vui lòng hoàn thành xác minh anti-spam', 'warning');
      return;
    }

    const scanId = parentId ? replyScanIdRef.current[parentId] : commentScanIdRef.current;
    setSending(true);
    try {
      const created = await api.post<ForumComment>(`/forum/posts/${post.id}/comment/`, {
        content,
        parent: parentId,
        scan_id: scanId ? Number(scanId) : null,
        ...(tsToken ? { 'cf-turnstile-response': tsToken } : {}),
      });
      if (parentId) {
        setComments((prev) => addReply(prev, parentId, created));
        setRepliesContent((prev) => ({ ...prev, [parentId]: '' }));
        setReplyScanIdState((prev) => ({ ...prev, [parentId]: '' }));
        setReplyTo(null);
      } else {
        setComments((prev) => [...prev, created]);
        setEditorData(commentEditorRef.current, '');
        setCommentScanId('');
      }
      setPost((prev) => (prev ? { ...prev, comments_count: (prev.comments_count || 0) + 1 } : prev));
      showToast('Bình luận đã được đăng!', 'success');
    } catch (e) {
      showToast(e instanceof Error ? e.message : 'Lỗi khi gửi bình luận', 'error');
    } finally {
      setSending(false);
      try { resetTurnstile(); } catch { /* ignore */ }
    }
  };

  const toggleLike = async (): Promise<void> => {
    if (!post) return;
    try {
      const d = await api.post<ReactionResp>(`/forum/posts/${post.id}/like/mutual/`);
      setPost((prev) => (prev ? {
        ...prev,
        likes_count: d.likes_count ?? prev.likes_count,
        dislikes_count: d.dislikes_count ?? prev.dislikes_count,
        user_liked: d.liked ?? !prev.user_liked,
        user_disliked: d.user_disliked ?? prev.user_disliked,
      } : prev));
    } catch { /* ignore */ }
  };

  const toggleReaction = async (type: string): Promise<void> => {
    if (!post) return;
    try {
      const d = await api.post<ReactionResp>(`/forum/posts/${post.id}/reaction/mutual/`, { reaction_type: type });
      setPost((prev) => (prev ? {
        ...prev,
        helpful_count: d.helpful_count ?? prev.helpful_count,
        shares_count: d.shares_count ?? prev.shares_count,
        dislikes_count: d.dislikes_count ?? prev.dislikes_count,
        likes_count: d.likes_count ?? prev.likes_count,
        user_helpful: d.user_helpful ?? prev.user_helpful,
        user_disliked: d.user_disliked ?? prev.user_disliked,
        user_liked: d.user_liked ?? prev.user_liked,
      } : prev));
    } catch { /* ignore */ }
  };

  const toggleCommentReaction = async (comment: ForumComment, reactionType: string): Promise<void> => {
    try {
      const d = await api.post<ReactionResp>(`/forum/comments/${comment.id}/reaction/`, { reaction_type: reactionType });
      setComments((prev) => patchComment(prev, comment.id, {
        likes_count: d.likes_count,
        dislikes_count: d.dislikes_count,
        helpful_count: d.helpful_count,
        user_liked: d.user_liked,
        user_disliked: d.user_disliked,
        user_helpful: d.user_helpful,
      }));
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) showToast('Vui lòng đăng nhập để tương tác', 'info');
    }
  };

  const reportComment = async (comment: ForumComment): Promise<void> => {
    const { value: reason } = await Swal.fire({
      title: 'Báo cáo bình luận vi phạm',
      input: 'textarea',
      inputPlaceholder: 'Lý do báo cáo...',
      showCancelButton: true,
      confirmButtonColor: 'var(--sc-risk-red)',
      background: 'var(--sc-night-2)',
      color: 'var(--sc-white)',
    });
    if (!reason) return;
    try {
      await api.post(`/forum/comments/${comment.id}/report/`, { reason });
      showToast('Báo cáo bình luận đã được gửi!', 'success');
    } catch { /* ignore */ }
  };

  const shareComment = (comment: ForumComment): void => {
    const url = `${window.location.origin}/forum/${post?.id || ''}/#comment-${comment.id}`;
    navigator.clipboard.writeText(url).then(() => {
      showToast('Đã sao chép liên kết bình luận!', 'success');
    }).catch(() => {});
  };

  const reportThread = async (): Promise<void> => {
    if (!post) return;
    const { value: reason } = await Swal.fire({
      title: 'Báo cáo vi phạm',
      input: 'textarea',
      inputPlaceholder: 'Lý do báo cáo...',
      showCancelButton: true,
      confirmButtonColor: 'var(--sc-risk-red)',
      background: 'var(--sc-night-2)',
      color: 'var(--sc-white)',
    });
    if (!reason) return;
    try {
      await api.post(`/forum/posts/${post.id}/report/`, { reason });
      showToast('Cảm ơn đóng góp của bạn!', 'success');
    } catch { /* ignore */ }
  };

  const shareThread = (): void => {
    if (!post) return;
    const url = window.location.href;
    navigator.clipboard.writeText(url).then(() => {
      showToast('Đã sao chép liên kết bài viết!', 'success');
      api
        .post<ReactionResp>(`/forum/posts/${post.id}/reaction/`, { reaction_type: 'share' })
        .then((data) => {
          if (data && data.shares_count !== undefined) {
            setPost((prev) => (prev ? { ...prev, shares_count: data.shares_count } : prev));
          }
        })
        .catch(() => {});
    }).catch(() => {
      void Swal.fire({
        title: 'Chia sẻ chủ đề',
        html: `
          <div class="mt-4">
            <p class="text-white/60 text-sm mb-4">Sao chép liên kết:</p>
            <input type="text" value="${url}" readonly
              class="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2 text-white text-sm focus:outline-none"
              onclick="this.select()">
          </div>
        `,
        showConfirmButton: false,
        background: 'var(--sc-night-2)',
        color: 'var(--sc-white)',
        showCloseButton: true,
      });
    });
  };

  const toggleThreadLock = async (): Promise<void> => {
    if (!post) return;
    const nextState = !post.is_locked;
    const actionLabel = nextState ? 'khóa' : 'mở khóa';
    const confirm = await Swal.fire({
      title: `${nextState ? 'Khóa' : 'Mở khóa'} chủ đề?`,
      text: nextState ? 'Thành viên sẽ không thể bình luận cho tới khi mở khóa lại.' : 'Thành viên có thể bình luận trở lại.',
      showCancelButton: true,
      confirmButtonText: nextState ? 'Khóa chủ đề' : 'Mở khóa',
      cancelButtonText: 'Hủy',
      background: 'var(--sc-night-2)',
      color: 'var(--sc-white)',
    });
    if (!confirm.isConfirmed) return;
    try {
      await api.patch(`/forum/posts/${post.id}/`, { is_locked: nextState });
      setPost((prev) => (prev ? { ...prev, is_locked: nextState } : prev));
      showToast(`Đã ${actionLabel} chủ đề`, 'success');
    } catch (e) {
      showToast(e instanceof Error ? e.message : `Không thể ${actionLabel} chủ đề`, 'error');
    }
  };

  const banUser = async (username?: string, displayName?: string): Promise<void> => {
    const result = await Swal.fire({
      title: `Cấm ${displayName || ''} khỏi diễn đàn?`,
      html: `
        <div class="space-y-3 text-left mt-4">
          <div>
            <label class="text-[10px] text-white/55 font-bold uppercase block mb-1">Lý do</label>
            <textarea id="ban-reason" class="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2 text-white text-sm min-h-[60px]" placeholder="Vi phạm nội quy..."></textarea>
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="text-[10px] text-white/55 font-bold uppercase block mb-1">Loại</label>
              <select id="ban-type" class="w-full bg-white/5 border border-white/10 rounded-xl px-3 py-2 text-white text-sm">
                <option value="temporary">Tạm thời</option>
                <option value="permanent">Vĩnh viễn</option>
              </select>
            </div>
            <div>
              <label class="text-[10px] text-white/55 font-bold uppercase block mb-1">Số ngày</label>
              <input type="number" id="ban-days" value="7" min="1" max="365" class="w-full bg-white/5 border border-white/10 rounded-xl px-3 py-2 text-white text-sm">
            </div>
          </div>
        </div>
      `,
      showCancelButton: true,
      confirmButtonColor: 'var(--sc-danger-500)',
      cancelButtonText: 'Hủy',
      confirmButtonText: 'Cấm',
      background: 'var(--sc-night-2)',
      color: 'var(--sc-white)',
      preConfirm: () => ({
        reason: (document.getElementById('ban-reason') as HTMLTextAreaElement | null)?.value || 'Vi phạm nội quy diễn đàn',
        ban_type: (document.getElementById('ban-type') as HTMLSelectElement | null)?.value || 'temporary',
        days: parseInt((document.getElementById('ban-days') as HTMLInputElement | null)?.value || '7', 10) || 7,
      }),
    });
    if (!result.isConfirmed) return;
    const value = result.value as { reason: string; ban_type: string; days: number };
    try {
      const data = await adminPost('/api/v1/admin/forum/ban/', { action: 'ban', username, ...value });
      if (data.status === 'ok') showToast(String(data.message || 'Đã cấm'), 'success');
      else showToast(String(data.error || 'Lỗi'), 'error');
    } catch {
      showToast('Lỗi kết nối', 'error');
    }
  };

  const openReplyEditor = (commentId: number, authorName = ''): void => {
    if (replyTo === commentId) {
      setReplyTo(null);
      return;
    }
    setReplyAuthorName(authorName);
    setReplyTo(commentId);
  };

  if (loadingInit) return <div className="max-w-7xl mx-auto px-4 py-8"><Spinner /></div>;
  if (notFound || !post) return <div className="max-w-7xl mx-auto px-4 py-8"><EmptyState text="Không tìm thấy bài viết." /></div>;

  const isOwner = Boolean(user && post.author_username && user.username === post.author_username);
  const isStaff = Boolean(user?.is_staff);
  const pageComments = paginatedComments();

  return (
    <div className="max-w-7xl mx-auto px-4 py-8">
      {/* Breadcrumb */}
      <nav className="flex items-center gap-2 text-sm mb-5 text-white/55">
        <Link href="/" className="hover:text-brand-400 transition"><i className="bi bi-house-door"></i> Trang chủ</Link>
        <i className="bi bi-chevron-right text-[10px]"></i>
        <Link href="/forum/" className="hover:text-brand-400 transition">Diễn đàn</Link>
        <i className="bi bi-chevron-right text-[10px]"></i>
        <span className="text-white/60 truncate max-w-[250px]">{post.title}</span>
      </nav>

      <div className="flex items-center justify-between mb-6">
        <div></div>
        <div className="flex items-center gap-3">
          {post.is_pinned && (
            <span className="px-3 py-1 bg-warn-500/10 text-warn-500 text-[9px] font-black rounded-full border border-warn-500/20 uppercase">
              <i className="bi bi-pin-angle-fill"></i> Ghim
            </span>
          )}
          {post.is_locked && (
            <span className="px-3 py-1 bg-danger-500/10 text-danger-400 text-[9px] font-black rounded-full border border-danger-500/20 uppercase">
              <i className="bi bi-lock-fill"></i> Khóa
            </span>
          )}
        </div>
      </div>

      {/* Thread Title Bar */}
      <div className="voz-thread rounded-2xl overflow-hidden mb-1 animate-fadeInUp">
        <div className="px-6 py-5 bg-gradient-to-r from-brand-500/10 via-brand2-500/5 to-transparent border-b border-white/5 relative overflow-hidden">
          <div className="absolute top-0 right-0 w-40 h-40 bg-brand-400/5 blur-3xl rounded-full -mr-20 -mt-20"></div>
          <div className="relative">
            <div className="flex items-center gap-3 mb-3">
              <span className={`px-3 py-1 text-[9px] font-black rounded-full border uppercase ${categoryBadgeClass(post.category)}`}>{categoryLabel(post.category)}</span>
              <span className="text-[9px] text-white/35 font-bold">{timeAgo(post.created_at)} trước</span>
            </div>
            <h1 className="text-2xl md:text-3xl font-black text-white leading-tight tracking-tight">{post.title}</h1>
          </div>
        </div>
      </div>

      {/* VOZ-Style: Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-0 lg:gap-6">
        {/* LEFT + CENTER: Post Area */}
        <div className="lg:col-span-9">
          {/* Original Post (VOZ-style: author left, content right) */}
          <div className="voz-thread rounded-b-2xl lg:rounded-2xl overflow-hidden mb-6">
            <div className="flex flex-col md:flex-row">
              {/* Author Card (LEFT) */}
              <div className="voz-author-card w-full md:w-52 shrink-0 p-5 flex flex-row md:flex-col items-center md:items-center gap-4 md:gap-2 text-center">
                <Link href={`/profile/@${post.author_username || ''}/`} data-usercard={post.author_username || ''} className="author-avatar relative w-20 h-20 rounded-full bg-gradient-to-br from-brand-400/20 to-brand2-500/20 border-2 border-white/10 overflow-hidden flex items-center justify-center shrink-0 hover:border-brand-400/40 transition-all shadow-lg shadow-brand-500/10">
                  {post.author_avatar ? (
                    <img src={mediaUrl(post.author_avatar)} className="w-full h-full object-cover" alt="" />
                  ) : (
                    <span className="text-2xl font-black text-brand-400">{getInitial(post.author_name)}</span>
                  )}
                </Link>
                <div className="flex flex-col items-center md:items-center gap-1 min-w-0">
                  <Link href={`/profile/@${post.author_username || ''}/`} className="text-sm font-black text-white hover:text-brand-400 transition-colors truncate max-w-[160px]">{post.author_name}</Link>
                  <div className="flex items-center gap-1.5">
                    {post.author_is_staff && <i className="bi bi-patch-check-fill verified-badge text-sm" title="Quản trị viên"></i>}
                    {post.author_rank && (
                      <span className={`rank-badge rank-${post.author_rank.level || ''}`}>
                        <i className={`${post.author_rank.icon || ''} mr-0.5`}></i>
                        <span>{post.author_rank.name}</span>
                      </span>
                    )}
                  </div>
                  <div className="hidden md:flex flex-col items-center gap-1 mt-2 text-[10px] text-white/45 font-bold">
                    <div className="flex items-center gap-1.5">
                      <i className="bi bi-file-earmark-text"></i>
                      <span>Bài viết: <span className="text-white/60">{post.author_posts_count || 0}</span></span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <i className="bi bi-chat-square-text"></i>
                      <span>Bình luận: <span className="text-white/60">{post.author_comments_count || 0}</span></span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <i className="bi bi-calendar3"></i>
                      <span>Tham gia: <span className="text-white/60">{post.author_joined}</span></span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Content (CENTER) */}
              <div className="flex-1 min-w-0">
                {/* Post metadata */}
                <div className="px-6 py-3 bg-white/[0.02] border-b border-white/5 flex items-center justify-between">
                  <span className="text-[10px] text-white/45 font-bold">{formatDate(post.created_at)}</span>
                  <span className="text-[9px] font-bold text-white/15 uppercase tracking-widest">#1</span>
                </div>

                <div className="p-6 md:p-8">
                  {post.image && (
                    <div className="mb-6 rounded-2xl overflow-hidden border border-white/10 shadow-lg">
                      <img src={mediaUrl(post.image)} className="w-full hover:scale-105 transition-transform duration-700" alt="" />
                    </div>
                  )}

                  <div className="text-white/70 leading-relaxed text-[15px] space-y-4 richtext-content" dangerouslySetInnerHTML={{ __html: sanitizeHtml(post.content || '') }} />
                </div>

                {/* Reactions Row */}
                <div className="px-6 py-4 bg-white/[0.02] border-t border-white/5 flex flex-wrap items-center justify-between gap-4">
                  <div className="flex items-center gap-2 flex-wrap">
                    <button onClick={() => void toggleLike()} className={`reaction-btn px-4 py-2 rounded-xl border border-white/5 flex items-center gap-2 text-sm ${post.user_liked ? 'active-red' : 'text-white/55'}`}>
                      <i className={`bi ${post.user_liked ? 'bi-heart-fill' : 'bi-heart'}`}></i>
                      <span className="font-bold">{post.likes_count}</span>
                    </button>
                    <button onClick={() => void toggleReaction('helpful')} className={`reaction-btn px-4 py-2 rounded-xl border border-white/5 flex items-center gap-2 text-sm ${post.user_helpful ? 'active-cyan' : 'text-white/55'}`}>
                      <i className={`bi ${post.user_helpful ? 'bi-patch-check-fill' : 'bi-patch-check'}`}></i>
                      <span className="font-bold">{post.helpful_count}</span>
                      <span className="text-[9px] font-bold ml-0.5 uppercase opacity-60 hidden sm:inline">Hữu ích</span>
                    </button>
                    <button onClick={() => void toggleReaction('dislike')} className={`reaction-btn px-4 py-2 rounded-xl border border-white/5 flex items-center gap-2 text-sm ${post.user_disliked ? 'active-red' : 'text-white/55'}`}>
                      <i className={`bi ${post.user_disliked ? 'bi-hand-thumbs-down-fill' : 'bi-hand-thumbs-down'}`}></i>
                      <span className="font-bold">{post.dislikes_count || 0}</span>
                    </button>
                    <button onClick={shareThread} className={`reaction-btn px-4 py-2 rounded-xl border border-white/5 flex items-center gap-2 text-sm ${post.user_shared ? 'active-cyan' : 'text-white/55'}`}>
                      <i className="bi bi-share-fill"></i>
                      <span className="font-bold">{post.shares_count}</span>
                    </button>
                  </div>
                  <div className="flex items-center gap-3">
                    {user && isOwner && (
                      <Link href={`/forum/${post.id}/edit/`} className="text-[10px] font-black text-white/35 hover:text-brand-400 transition-all uppercase tracking-widest flex items-center gap-1.5">
                        <i className="bi bi-pencil-square"></i> Sửa
                      </Link>
                    )}
                    {user && (isOwner || isStaff) && (
                      <button onClick={() => void toggleThreadLock()} className="text-[10px] font-black text-white/35 hover:text-warn-400 transition-all uppercase tracking-widest flex items-center gap-1.5">
                        <i className={`bi ${post.is_locked ? 'bi-unlock-fill' : 'bi-lock-fill'}`}></i>
                        <span>{post.is_locked ? 'Mở khóa' : 'Khóa chủ đề'}</span>
                      </button>
                    )}
                    {user && isStaff && !isOwner && (
                      <button onClick={() => void banUser(post.author_username, post.author_name)} className="text-[10px] font-black text-white/35 hover:text-danger-500 transition-all uppercase tracking-widest flex items-center gap-1.5">
                        <i className="bi bi-slash-circle"></i> Cấm
                      </button>
                    )}
                    <button onClick={() => void reportThread()} className="text-[10px] font-black text-white/35 hover:text-danger-500 transition-all uppercase tracking-widest flex items-center gap-1.5">
                      <i className="bi bi-flag"></i> Báo cáo
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Comments Section */}
          <div className="mb-6">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-lg font-black text-white flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-brand-500/10 border border-brand-500/20 flex items-center justify-center">
                  <i className="bi bi-chat-left-quote text-brand-400"></i>
                </div>
                Bình luận
                <span className="w-8 h-8 rounded-lg bg-brand-500/10 flex items-center justify-center text-xs font-bold text-brand-400 border border-brand-500/20">{post.comments_count || 0}</span>
              </h3>
              <div className="text-[9px] font-bold text-white/35 uppercase tracking-widest">
                <span>{flattenedComments().length}</span> bình luận
              </div>
            </div>

            {/* Comments List (VOZ-style: author left, content right) */}
            <div className="space-y-3" id="comments-section">
              {pageComments.map((comment, cIdx) => {
                const replyOpen = replyTo === comment.id;
                const depth = comment.depth || 1;
                const marginLeft = Math.max(0, depth - 1) * 20;
                const replyScan = replyScanId[comment.id] || '';
                return (
                  <div key={`comment-${comment.id}`} className="space-y-3">
                    <div className="comment-card rounded-2xl overflow-hidden" id={`comment-${comment.id}`} style={{ marginLeft: `${marginLeft}px` }}>
                      <div className="flex flex-col sm:flex-row">
                        {/* Comment Author (LEFT) */}
                        <div className="sm:w-40 shrink-0 p-4 border-b sm:border-b-0 sm:border-r border-white/5 bg-white/[0.01] flex flex-row sm:flex-col items-center gap-3 sm:gap-2 text-center">
                          <Link href={`/profile/@${comment.author_username || ''}/`} data-usercard={comment.author_username || ''} className="w-12 h-12 rounded-full bg-gradient-to-br from-brand-400/10 to-brand2-500/10 border border-white/10 overflow-hidden flex items-center justify-center shrink-0 hover:border-brand-400/30 transition-all">
                            {comment.author_avatar ? (
                              <img src={mediaUrl(comment.author_avatar)} className="w-full h-full object-cover" alt="" />
                            ) : (
                              <span className="text-sm font-bold text-brand-400">{getInitial(comment.author_name)}</span>
                            )}
                          </Link>
                          <div className="flex flex-col items-center gap-0.5 min-w-0">
                            <div className="flex items-center gap-1">
                              <Link href={`/profile/@${comment.author_username || ''}/`} className="text-xs font-bold text-white/80 hover:text-brand-400 transition-colors truncate max-w-[100px]">{comment.author_name}</Link>
                              {comment.author_is_staff && <i className="bi bi-patch-check-fill verified-badge text-xs" title="Quản trị viên"></i>}
                            </div>
                            {comment.author_rank && (
                              <span className={`rank-badge text-[8px] rank-${comment.author_rank.level || ''}`}>
                                <i className={`${comment.author_rank.icon || ''} mr-0.5`}></i>
                                <span>{comment.author_rank.name}</span>
                              </span>
                            )}
                            <div className="hidden sm:block text-[9px] text-white/35 mt-1">
                              <span>{`Bài viết: ${comment.author_posts_count || 0}`}</span>
                            </div>
                          </div>
                        </div>

                        {/* Comment Content (RIGHT) */}
                        <div className="flex-1 min-w-0">
                          <div className="px-4 py-2 bg-white/[0.01] border-b border-white/5 flex items-center justify-between">
                            <span className="text-[10px] text-white/55 font-bold">{formatDate(comment.created_at)}</span>
                            <span className="text-[9px] font-bold text-white/20 uppercase tracking-widest">{`#${(commentPage - 1) * commentsPerPage + cIdx + 2}`}</span>
                          </div>
                          <div className="p-4">
                            {comment.parent_author_name && (
                              <div className="mb-2 inline-flex items-center gap-2 px-2.5 py-1 rounded-lg bg-danger-500/10 border border-danger-500/30 text-[10px] font-black tracking-wide">
                                <span className="inline-flex items-center justify-center w-4 h-4 rounded bg-danger-500/20 text-danger-300 leading-none">↳</span>
                                <span className="text-danger-200">{`Trả lời @${comment.parent_author_name}`}</span>
                              </div>
                            )}
                            <div className="text-sm text-white/70 leading-relaxed richtext-content" dangerouslySetInnerHTML={{ __html: sanitizeHtml(comment.content || '') }} />
                          </div>
                          {/* Comment reactions */}
                          <div className="px-4 py-2 bg-white/[0.01] border-t border-white/5 flex items-center justify-between">
                            <div className="flex items-center gap-3">
                              <button onClick={() => void toggleCommentReaction(comment, 'upvote')} className={`text-[10px] font-black transition-all flex items-center gap-1 ${comment.user_liked ? 'text-safe-400' : 'text-white/35 hover:text-safe-400'}`}>
                                <i className={`bi ${comment.user_liked ? 'bi-caret-up-fill' : 'bi-caret-up'}`}></i>
                                <span>{comment.likes_count || 0}</span>
                              </button>
                              <button onClick={() => void toggleCommentReaction(comment, 'downvote')} className={`text-[10px] font-black transition-all flex items-center gap-1 ${comment.user_disliked ? 'text-danger-400' : 'text-white/35 hover:text-danger-400'}`}>
                                <i className={`bi ${comment.user_disliked ? 'bi-caret-down-fill' : 'bi-caret-down'}`}></i>
                                <span>{comment.dislikes_count || 0}</span>
                              </button>
                              <button onClick={() => void toggleCommentReaction(comment, 'helpful')} className={`text-[10px] font-black transition-all flex items-center gap-1 ${comment.user_helpful ? 'text-brand-400' : 'text-white/35 hover:text-brand-400'}`}>
                                <i className={`bi ${comment.user_helpful ? 'bi-patch-check-fill' : 'bi-patch-check'}`}></i>
                                <span>{comment.helpful_count || 0}</span>
                              </button>
                            </div>
                            <div className="flex items-center gap-2">
                              {!post.is_locked && canReply(comment.id) && (
                                <button onClick={() => openReplyEditor(comment.id, comment.author_name)} className="text-[10px] font-black text-white/35 hover:text-brand-400 transition-all flex items-center gap-1">
                                  <i className="bi bi-reply-fill"></i> Trả lời
                                </button>
                              )}
                              {!canReply(comment.id) && (
                                <span className="text-[9px] font-black text-white/35 uppercase tracking-widest">Đã đạt tầng tối đa</span>
                              )}
                              <button onClick={() => shareComment(comment)} className="text-[10px] font-black text-white/35 hover:text-white/60 transition-all">
                                <i className="bi bi-share"></i>
                              </button>
                              <button onClick={() => void reportComment(comment)} className="text-[10px] font-black text-white/35 hover:text-danger-400 transition-all">
                                <i className="bi bi-flag"></i>
                              </button>
                            </div>
                          </div>

                          {/* Reply Input */}
                          {replyOpen && (
                            <div className="mx-4 mb-4 p-4 rounded-xl bg-white/[0.03] border border-brand-500/10">
                              <h4 className="text-[10px] font-black text-brand-400 uppercase tracking-widest mb-2">{`Phản hồi ${comment.author_name || ''}`}</h4>
                              <div className={`overflow-hidden bg-black/20 rounded-xl border border-white/5 w-full ${sending ? 'opacity-50 pointer-events-none' : ''}`}>
                                <RichEditor
                                  key={comment.id}
                                  editorRef={replyEditorRef}
                                  initialData={repliesContent[comment.id] || ''}
                                  placeholder={`Phản hồi @${replyAuthorName || 'thành viên'}...`}
                                  minLines={4}
                                  onChangeData={(html) => setRepliesContent((prev) => ({ ...prev, [comment.id]: html }))}
                                />
                              </div>
                              <div className="flex justify-end gap-2 mt-2">
                                <button onClick={() => void openScanPickerDialog('reply', comment.id)} className="text-[10px] font-bold text-brand-400/70 hover:text-brand-300 px-3 py-1.5 uppercase tracking-widest transition-colors border border-brand-500/20 rounded-lg">
                                  <i className="bi bi-search"></i>
                                  <span>{replyScan ? `Scan #${replyScan}` : 'Scan ID'}</span>
                                </button>
                                <button onClick={() => setReplyTo(null)} className="text-[10px] font-bold text-white/45 hover:text-white px-3 py-1.5 uppercase tracking-widest transition-colors">Hủy</button>
                                <button onClick={() => void submitComment(comment.id)} disabled={sending}
                                  className="bg-brand-500/20 text-brand-400 border border-brand-500/20 px-5 py-1.5 rounded-lg text-[10px] font-black hover:bg-brand-400 hover:text-black transition-all uppercase tracking-widest">
                                  {!sending && <span>Gửi</span>}
                                  {sending && <span className="w-3 h-3 border-2 border-brand-400 border-t-transparent rounded-full animate-spin inline-block"></span>}
                                </button>
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Comment Pagination */}
            {commentTotalPages() > 1 && (
              <div className="flex items-center justify-center gap-1 mt-4">
                <button onClick={() => goToCommentPage(commentPage - 1)} disabled={commentPage <= 1}
                  className="w-8 h-8 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center text-xs text-white/55 hover:text-white hover:bg-white/10 transition disabled:opacity-30 disabled:cursor-not-allowed">
                  <i className="bi bi-chevron-left"></i>
                </button>
                {commentPageNumbers().map((p, i) => (
                  <button key={`cpg-${p}-${i}`} onClick={() => { if (typeof p === 'number') goToCommentPage(p); }} disabled={p === '...'}
                    className={`w-8 h-8 rounded-lg border flex items-center justify-center text-xs font-bold transition disabled:cursor-default ${p === commentPage ? 'bg-brand-500/20 text-brand-400 border-brand-500/30' : 'bg-white/5 text-white/55 border-white/10 hover:text-white hover:bg-white/10'}`}>
                    {p}
                  </button>
                ))}
                <button onClick={() => goToCommentPage(commentPage + 1)} disabled={commentPage >= commentTotalPages()}
                  className="w-8 h-8 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center text-xs text-white/55 hover:text-white hover:bg-white/10 transition disabled:opacity-30 disabled:cursor-not-allowed">
                  <i className="bi bi-chevron-right"></i>
                </button>
                <span className="ml-2 text-[10px] text-white/35">{`Trang ${commentPage}/${commentTotalPages()} · ${comments.length} bình luận`}</span>
              </div>
            )}

            {/* Locked Thread Banner */}
            {post.is_locked && (
              <div className="mt-8 voz-thread rounded-2xl p-6 text-center border border-danger-500/20 bg-danger-500/5">
                <i className="bi bi-lock-fill text-danger-400 text-2xl"></i>
                <p className="text-danger-400/80 mt-2 font-bold text-sm">Bài viết này đã bị khóa bởi quản trị viên.</p>
                <p className="text-white/45 text-xs mt-1">Không thể bình luận hoặc trả lời trong bài viết đã khóa.</p>
              </div>
            )}

            {/* New Comment Box */}
            {user ? (
              !post.is_locked && (
                <div className="mt-8 voz-thread rounded-2xl overflow-hidden">
                  <div className="px-6 py-3 bg-white/[0.02] border-b border-white/5">
                    <h4 className="text-xs font-black text-white/60 uppercase tracking-widest flex items-center gap-2">
                      <i className="bi bi-pencil-fill text-brand-400"></i> Viết bình luận
                    </h4>
                  </div>
                  <div className="p-6">
                    <div className="flex gap-4">
                      <div className="w-12 h-12 rounded-xl bg-gradient-to-tr from-brand-400 to-brand-500 flex items-center justify-center text-white font-black text-lg shrink-0 shadow-lg shadow-brand-500/20">
                        {(user.username || '?').charAt(0).toUpperCase()}
                      </div>
                      <div className="flex-1 min-w-0 space-y-4">
                        <div className={`overflow-hidden bg-black/20 rounded-xl border border-white/5 w-full ${sending ? 'opacity-50 pointer-events-none' : ''}`}>
                          <RichEditor
                            editorRef={commentEditorRef}
                            placeholder="Chia sẻ suy nghĩ của bạn..."
                            minLines={5}
                            enableScanReferenceButton
                            getCurrentScanId={() => commentScanId}
                            onScanIdChange={(v) => setCommentScanId(v)}
                            onScanIdRender={(_editor, v) => setCommentScanId(v)}
                          />
                        </div>
                        {commentScanId !== '' && (
                          <div className="inline-flex items-center gap-2 px-3 py-2 rounded-xl border border-brand-400/30 bg-brand-500/10 text-brand-200 text-xs font-bold">
                            <i className="bi bi-link-45deg"></i>
                            <span>{`Đang tham chiếu Scan #${commentScanId}`}</span>
                          </div>
                        )}
                        <p className="text-[10px] text-white/35 mt-1">Mẹo: gõ <span className="text-brand-400 font-bold">@username</span> để mention người dùng.</p>
                        <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
                          <button onClick={() => void openScanPickerDialog('comment')} type="button" className="w-full sm:w-auto text-[10px] font-bold text-brand-400/80 hover:text-brand-300 px-4 py-2 uppercase tracking-widest transition-colors border border-brand-500/20 rounded-xl bg-brand-500/5">
                            <i className="bi bi-search mr-1"></i>
                            <span>{commentScanId !== '' ? `Scan #${commentScanId}` : 'Chọn scan tham chiếu'}</span>
                          </button>
                          <div className="flex-shrink-0">
                            <TurnstileWidget />
                          </div>
                          <button onClick={() => void submitComment()} disabled={sending}
                            className="w-full sm:w-auto bg-brand-400 text-[var(--sc-night-1)] px-8 py-3 rounded-xl font-black hover:bg-white transition-all hover:scale-105 active:scale-95 flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed shadow-lg shadow-brand-400/20">
                            {!sending && (
                              <span className="flex items-center gap-2">
                                <i className="bi bi-send-fill text-sm"></i> ĐĂNG BÌNH LUẬN
                              </span>
                            )}
                            {sending && (
                              <span className="flex items-center gap-2">
                                <span className="w-4 h-4 border-2 border-[var(--sc-night-1)]/30 border-t-[var(--sc-night-1)] rounded-full animate-spin"></span>
                                ĐANG ĐĂNG...
                              </span>
                            )}
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )
            ) : (
              <div className="mt-8 voz-thread rounded-2xl p-8 text-center border-dashed">
                <p className="text-white/55 mb-3">Vui lòng đăng nhập để tham gia thảo luận</p>
                <Link href="/login/" className="inline-flex items-center gap-2 text-brand-400 font-bold hover:text-white transition-colors">
                  Đăng nhập ngay <i className="bi bi-arrow-right"></i>
                </Link>
              </div>
            )}
          </div>
        </div>

        {/* RIGHT Sidebar: Thread Statistics */}
        <div className="lg:col-span-3 space-y-4">
          {/* Thread Statistics */}
          <div className="voz-stat-card rounded-2xl overflow-hidden">
            <div className="px-5 py-4 bg-gradient-to-r from-brand-500/10 via-brand-500/5 to-transparent border-b border-white/5 relative overflow-hidden">
              <div className="absolute top-0 right-0 w-20 h-20 bg-brand-500/10 blur-2xl rounded-full -mr-10 -mt-10"></div>
              <h4 className="text-[10px] font-black text-brand-400 uppercase tracking-widest flex items-center gap-2 relative">
                <i className="bi bi-bar-chart-fill"></i> Thống kê chủ đề
              </h4>
            </div>
            <div className="p-5 space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-white/55 font-bold uppercase">Ngày tạo</span>
                <span className="text-xs font-bold text-white/70">{formatDate(post.created_at)}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-white/55 font-bold uppercase">Trả lời</span>
                <span className="text-xs font-black text-brand-400">{post.comments_count || 0}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-white/55 font-bold uppercase">Lượt xem</span>
                <span className="text-xs font-black text-white/70">{post.views_count || 0}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-white/55 font-bold uppercase">Người xem</span>
                <span className="text-xs font-bold text-white/60">{post.unique_views_count || 0}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-white/55 font-bold uppercase">Thích</span>
                <span className="text-xs font-bold text-danger-400">{post.likes_count || 0}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-white/55 font-bold uppercase">Hữu ích</span>
                <span className="text-xs font-bold text-brand-400">{post.helpful_count || 0}</span>
              </div>

              {post.scan_reference && (
                <div className="pt-4 mt-1 border-t border-white/5 space-y-2">
                  <div className="text-[10px] text-white/55 font-bold uppercase flex items-center gap-1.5">
                    <i className="bi bi-shield-check text-brand-500/40"></i> Scan tham chiếu
                  </div>
                  <div className="rounded-xl border border-brand-500/20 bg-brand-500/5 p-3 space-y-2">
                    {referencedScanLoading && (
                      <div className="text-[11px] text-white/45">Đang tải chi tiết scan...</div>
                    )}
                    {!referencedScanLoading && referencedScan && (
                      <div>
                        <div className="flex items-center justify-between gap-2">
                          <Link href={`/scan/status/${referencedScan.id}/`} className="text-xs font-black text-brand-300 hover:text-white transition-colors">{`#${referencedScan.id} · ${scanTypeLabel(referencedScan)}`}</Link>
                          <span className={`px-2 py-0.5 rounded-lg border text-[9px] font-black ${levelClass(guardrailTone(referencedScan.result))}`}>{guardrailLabel(referencedScan.result)}</span>
                        </div>
                        <div className="mt-1 text-[10px] text-white/60">{`Risk score: ${referencedScan.risk_score || 0}/100`}</div>
                      </div>
                    )}
                    {!referencedScanLoading && !referencedScan && (
                      <div className="text-[11px] text-white/45">Không tải được chi tiết scan.</div>
                    )}
                  </div>
                </div>
              )}

              <div className="pt-4 mt-1 border-t border-white/5 space-y-2">
                <div className="text-[10px] text-white/55 font-bold uppercase flex items-center gap-1.5">
                  <i className="bi bi-people-fill text-brand-500/40"></i> Người tham gia
                </div>
                <div className="flex items-center -space-x-1.5">
                  {visibleParticipants().map((member) => (
                    <Link key={`participant-${member.username}`} href={`/profile/@${member.username || ''}/`}
                      className="w-7 h-7 rounded-full border border-white/20 bg-white/5 p-[1px] overflow-hidden hover:scale-105 transition"
                      title={`${member.name || member.username} · ${member.role || 'Người comment'}`}>
                      <div className="w-full h-full rounded-full overflow-hidden flex items-center justify-center">
                        {member.avatar ? (
                          <img src={mediaUrl(member.avatar)} className="w-full h-full object-cover rounded-full" alt="" />
                        ) : (
                          <span className="w-full h-full rounded-full flex items-center justify-center text-[9px] font-black"
                            style={avatarFallbackStyle(member.name || member.username)}>
                            {getInitial(member.name || member.username)}
                          </span>
                        )}
                      </div>
                    </Link>
                  ))}
                  {remainingParticipantsCount() > 0 && (
                    <div className="w-7 h-7 rounded-full border border-white/15 bg-white/10 flex items-center justify-center text-[9px] font-black text-white/70"
                      title={`${remainingParticipantsCount()} thành viên khác`}>
                      <span>{`+${remainingParticipantsCount()}`}</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Last Reply Info */}
              {post.last_comment_author && (
                <div className="pt-4 mt-1 border-t border-white/5">
                  <div className="text-[10px] text-white/55 font-bold uppercase mb-3 flex items-center gap-1.5"><i className="bi bi-reply-fill text-brand-500/40"></i> Trả lời cuối</div>
                  <div className="flex items-center gap-3">
                    <div className="w-6 h-6 rounded-md bg-white/5 border border-white/10 overflow-hidden flex items-center justify-center shrink-0">
                      {post.last_comment_author.avatar ? (
                        <img src={mediaUrl(post.last_comment_author.avatar)} className="w-full h-full object-cover" alt="" />
                      ) : (
                        <span className="text-[8px] font-bold text-brand-400">{getInitial(post.last_comment_author.name)}</span>
                      )}
                    </div>
                    <div className="min-w-0">
                      <Link href={`/profile/@${post.last_comment_author.username || ''}/`} className="text-[10px] font-bold text-white/60 hover:text-brand-400 transition-colors block truncate">{post.last_comment_author.name}</Link>
                      <span className="text-[9px] text-white/35">{`${timeAgo(post.last_comment_at)} trước`}</span>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Share Section */}
            <div className="px-5 py-3 border-t border-white/5">
              <div className="text-[10px] text-white/45 font-bold uppercase mb-2">Chia sẻ</div>
              <div className="flex items-center gap-2">
                <button onClick={shareThread} className="w-8 h-8 rounded-lg bg-white/5 hover:bg-brand-400/10 border border-white/5 flex items-center justify-center text-white/55 hover:text-brand-400 transition-all" title="Sao chép liên kết">
                  <i className="bi bi-link-45deg text-sm"></i>
                </button>
                <a href={`https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(shareUrl)}`} target="_blank" rel="noopener noreferrer" className="w-8 h-8 rounded-lg bg-white/5 hover:bg-brand-500/10 border border-white/5 flex items-center justify-center text-white/55 hover:text-brand-400 transition-all" title="Facebook">
                  <i className="bi bi-facebook text-sm"></i>
                </a>
                <a href={`https://twitter.com/intent/tweet?url=${encodeURIComponent(shareUrl)}&text=${encodeURIComponent(post.title)}`} target="_blank" rel="noopener noreferrer" className="w-8 h-8 rounded-lg bg-white/5 hover:bg-brand-500/10 border border-white/5 flex items-center justify-center text-white/55 hover:text-brand-400 transition-all" title="Twitter">
                  <i className="bi bi-twitter-x text-sm"></i>
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Scan Picker Modal */}
      {scanPickerOpen && (
        <div onKeyDown={(e) => { if (e.key === 'Escape') setScanPickerOpen(false); }} className="fixed inset-0 z-[120] flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={() => setScanPickerOpen(false)}></div>
          <div className="relative w-full max-w-4xl max-h-[80vh] overflow-hidden rounded-3xl border border-white/10 bg-[var(--sc-panel)] shadow-2xl shadow-brand-500/10 flex flex-col">
            <div className="px-6 py-4 border-b border-white/10 flex items-center justify-between">
              <div>
                <h3 className="text-white font-black text-lg">Scan Picker</h3>
                <p className="text-white/45 text-xs">Chọn scan tham chiếu cho bình luận/phản hồi</p>
              </div>
              <button onClick={() => setScanPickerOpen(false)} className="w-9 h-9 rounded-xl border border-white/10 text-white/60 hover:text-white hover:bg-white/10 transition"><i className="bi bi-x-lg"></i></button>
            </div>

            <div className="p-5 border-b border-white/10 space-y-3">
              <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
                <select value={scanPickerFilters.scope} onChange={(e) => { const next = patchFilters({ scope: e.target.value }); void fetchScanPicker(next); }} className="bg-[var(--sc-night-1)]/60 border border-white/10 rounded-xl px-4 py-2 text-sm font-bold text-white focus:outline-none focus:ring-1 focus:ring-brand-500/40">
                  <option value="mine">Scan của tôi</option>
                  <option value="public">Scan public referable</option>
                  <option value="all">Tất cả scan có quyền</option>
                </select>
                <select value={scanPickerFilters.type} onChange={(e) => { const next = patchFilters({ type: e.target.value }); void fetchScanPicker(next); }} className="bg-[var(--sc-night-1)]/60 border border-white/10 rounded-xl px-4 py-2 text-sm font-bold text-white focus:outline-none focus:ring-1 focus:ring-brand-500/40">
                  <option value="">Mọi loại scan</option>
                  <option value="phone">Phone</option>
                  <option value="message">Message</option>
                  <option value="domain">Domain</option>
                  <option value="account">Account</option>
                  <option value="qr">QR/Image</option>
                  <option value="email">Email</option>
                  <option value="file">File</option>
                  <option value="audio">Audio</option>
                </select>
                <select value={scanPickerFilters.riskLevel} onChange={(e) => { const next = patchFilters({ riskLevel: e.target.value }); void fetchScanPicker(next); }} className="bg-[var(--sc-night-1)]/60 border border-white/10 rounded-xl px-4 py-2 text-sm font-bold text-white focus:outline-none focus:ring-1 focus:ring-brand-500/40">
                  <option value="">Mọi mức độ</option>
                  <option value="RED">RED</option>
                  <option value="YELLOW">YELLOW</option>
                  <option value="GREEN">GREEN</option>
                  <option value="SAFE">SAFE</option>
                </select>
                <div className="flex gap-2">
                  <input type="text" value={scanPickerFilters.q} onChange={(e) => { const next = patchFilters({ q: e.target.value }); void fetchScanPicker(next); }} placeholder="Từ khóa..." className="bg-[var(--sc-night-1)]/60 border border-white/10 rounded-xl flex-1 px-4 py-2 text-sm font-bold text-white placeholder-white/30 focus:outline-none focus:ring-1 focus:ring-brand-500/40" />
                  <button onClick={() => void fetchScanPicker(scanPickerFilters)} type="button" className="px-4 py-2 rounded-xl bg-brand-500/20 border border-brand-400/30 text-brand-300 hover:bg-brand-500/30 transition text-sm font-black"><i className="bi bi-funnel"></i></button>
                </div>
              </div>
              <div className="flex gap-2">
                <input type="text" value={scanPickerFilters.manualId} onChange={(e) => patchFilters({ manualId: e.target.value })} placeholder="Nhập Scan ID thủ công..." className="bg-[var(--sc-night-1)]/60 border border-white/10 rounded-xl flex-1 px-4 py-2 text-sm font-bold text-white placeholder-white/30 focus:outline-none focus:ring-1 focus:ring-brand-500/40" />
                <button onClick={() => void applyManualScanId(scanPickerFilters.manualId, scanPickerTarget, scanPickerFilters)} type="button" className="px-4 py-2 rounded-xl bg-brand2-500/20 border border-brand2-400/30 text-brand2-300 hover:bg-brand2-500/30 transition text-sm font-black">Dùng ID này</button>
                <button onClick={() => clearPickedScan()} type="button" className="px-4 py-2 rounded-xl bg-white/5 border border-white/10 text-white/60 hover:bg-white/10 transition text-sm font-black">Bỏ chọn</button>
              </div>
            </div>

            <div className="p-5 overflow-y-auto overscroll-contain flex-1 min-h-0">
              {scanPickerLoading && <div className="text-center py-10 text-white/60 text-sm">Đang tải danh sách scan...</div>}
              {!scanPickerLoading && !scanPickerResults.length && (
                <div className="text-center py-10 text-white/55 text-sm">Không có scan phù hợp bộ lọc.</div>
              )}

              {!scanPickerLoading && scanPickerResults.length > 0 && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {scanPickerResults.map((scan) => (
                    <button key={`picker-${scan.id}`} onClick={() => commitPickedScan(scan, scanPickerTarget)} type="button" className="text-left rounded-2xl border border-white/10 bg-white/[0.03] hover:bg-white/[0.06] hover:border-brand-400/30 transition-all p-4">
                      <div className="flex items-start justify-between gap-2">
                        <div>
                          <div className="text-white font-black text-sm">{`#${scan.id} · ${scanTypeLabel(scan)}`}</div>
                          <div className="text-white/55 text-[11px]">{scan.preview || 'Không có mô tả'}</div>
                        </div>
                        <span className={`px-2 py-1 rounded-lg border text-[10px] font-black ${levelClass(scan.verdict_tone || scan.risk_level)}`}>{scan.verdict_label || scan.risk_level || 'N/A'}</span>
                      </div>
                      <div className="mt-3 flex items-center flex-wrap gap-2 text-[10px]">
                        <span className="px-2 py-1 rounded-lg bg-white/5 border border-white/10 text-white/60">{`Risk ${scan.risk_score || 0}/100`}</span>
                        <span className="px-2 py-1 rounded-lg bg-white/5 border border-white/10 text-white/60">{scan.is_owner ? 'Mine' : 'Public'}</span>
                        <span className="px-2 py-1 rounded-lg bg-white/5 border border-white/10 text-white/60">{(scan.status || 'unknown').toUpperCase()}</span>
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
