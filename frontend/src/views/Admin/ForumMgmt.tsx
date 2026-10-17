'use client';
import { useEffect, useMemo, useRef, useState } from 'react';
import Link from 'next/link';
import Swal from 'sweetalert2';
import type { Chart as ChartType } from 'chart.js';
import { api, mediaUrl } from '../../lib/api';
import { escapeHtml } from '../../lib/chat/markdown';
import { showToast } from '../../lib/ui/feedback';
import { AdminShell, useAdminGet } from './_shared';

/* Port 1-1 từ PKV/templates/Admin/forum_management.html (Alpine forumAdmin()).
 *
 * Dữ liệu đọc:
 *   - GET /forum/posts/                    -> tab Bài viết
 *   - GET /admin/users/                    -> tab Thành viên + Kiểm duyệt
 *   - GET /admin/forum/reports/            -> tab Báo cáo bài viết
 *   - GET /admin/forum/comment-reports/    -> tab Báo cáo bình luận
 *   - GET /admin/forum/bans/               -> tab Cấm
 * Thao tác:
 *   - Ghim/Khóa/Xóa bài viết  -> PATCH/DELETE /forum/posts/<id>/
 *   - Duyệt/Từ chối/AI báo cáo-> POST /admin/forum/{reports|comment-reports}/<id>/action/
 *   - Cấm/Gỡ cấm              -> POST /admin/forum/ban/
 *   - Bổ nhiệm/Gỡ KDV          -> POST /admin/users/<id>/action/ (toggle_staff)
 * Thống kê / biểu đồ được suy ra cục bộ từ dữ liệu. */

type TabId = 'posts' | 'post_reports' | 'comment_reports' | 'members' | 'bans' | 'moderators';

interface ForumApiPost {
  id: number;
  title?: string;
  category?: string;
  author_name?: string;
  author_username?: string;
  likes_count?: number;
  comments_count?: number;
  views_count?: number;
  is_pinned?: boolean;
  is_locked?: boolean;
  created_at?: string;
}
interface ApiUser {
  id: number;
  username: string;
  full_name?: string;
  is_staff: boolean;
  is_active: boolean;
  is_superuser: boolean;
  posts_count: number;
  comments_count: number;
  date_joined: string;
}
interface PostRow {
  id: number;
  title: string;
  author_name: string;
  category: string;
  likes_count: number;
  comments_count: number;
  views_count: number;
  is_pinned: boolean;
  is_locked: boolean;
  created_at_display: string;
}
interface MemberRow {
  id: number;
  username: string;
  display_name: string;
  avatar: string | null;
  rank: { level: string; name: string } | null;
  posts_count: number;
  comments_count: number;
  is_staff: boolean;
  is_banned: boolean;
  is_superuser: boolean;
  date_joined: string;
}
interface ModeratorRow {
  id: number;
  username: string;
  display_name: string;
  avatar: string | null;
  is_superuser: boolean;
  date_joined: string;
}
interface ReportRow {
  id: number;
  created_at_display: string;
  reporter_name: string;
  post_title?: string;
  comment_content?: string;
  reason: string;
  status: string;
  ai_status: 'analyzing' | 'none' | 'done';
  ai_violation: boolean | null;
  ai_confidence: string | number | null;
}
interface BanRow {
  id: number;
  username: string;
  is_active: boolean;
  display_name: string;
  banned_by: string;
  reason: string;
  ban_type: string;
  expires_at: string;
  is_expired: boolean;
  created_at_display: string;
}

interface ApiUserBrief {
  id: number;
  username: string;
  email?: string;
  is_staff?: boolean;
}
interface ApiPostReport {
  id: number;
  post_id: number;
  post_title: string;
  post_author: string;
  reporter: ApiUserBrief | null;
  reason: string;
  status: string;
  is_resolved: boolean;
  created_at: string;
}
interface ApiCommentReport {
  id: number;
  comment_id: number;
  comment_content: string;
  comment_author: string;
  post_id: number;
  post_title: string;
  reporter: ApiUserBrief | null;
  reason: string;
  status: string;
  is_resolved: boolean;
  created_at: string;
}
interface ApiBan {
  id: number;
  user: ApiUserBrief | null;
  banned_by: ApiUserBrief | null;
  reason: string;
  ban_type: string;
  expires_at: string | null;
  is_active: boolean;
  is_expired: boolean;
  created_at: string;
}

function mapPostReport(r: ApiPostReport): ReportRow {
  return {
    id: r.id,
    created_at_display: r.created_at,
    reporter_name: r.reporter?.username || '',
    post_title: r.post_title,
    reason: r.reason,
    status: r.status,
    ai_status: 'none',
    ai_violation: null,
    ai_confidence: null,
  };
}
function mapCommentReport(r: ApiCommentReport): ReportRow {
  return {
    id: r.id,
    created_at_display: r.created_at,
    reporter_name: r.reporter?.username || '',
    comment_content: r.comment_content,
    post_title: r.post_title,
    reason: r.reason,
    status: r.status,
    ai_status: 'none',
    ai_violation: null,
    ai_confidence: null,
  };
}
function mapBan(b: ApiBan): BanRow {
  return {
    id: b.id,
    username: b.user?.username || '',
    /* Giữ is_active: trước đây bỏ qua field này nên user đã gỡ cấm vẫn hiện
     * "đang bị cấm" và thống kê đếm cả lịch sử. */
    is_active: !!b.is_active,
    display_name: b.user?.username || '',
    banned_by: b.banned_by?.username || '',
    reason: b.reason,
    ban_type: b.ban_type,
    expires_at: b.expires_at || (b.ban_type === 'permanent' ? 'Vĩnh viễn' : ''),
    is_expired: b.is_expired,
    created_at_display: b.created_at,
  };
}

const CAT_COLORS: Record<string, string> = {
  warning: '#ef4444',
  discussion: '#06b6d4',
  experience: '#a855f7',
  question: '#f59e0b',
  news: '#10b981',
  guide: '#3b82f6',
  alert: '#f43f5e',
};

const CAT_LABELS: Record<string, string> = {
  warning: 'Cảnh báo',
  discussion: 'Thảo luận',
  experience: 'Chia sẻ kinh nghiệm',
  question: 'Hỏi đáp',
  news: 'Tin tức',
  guide: 'Hướng dẫn',
  alert: 'Khẩn cấp',
};

function timeAgo(iso?: string): string {
  if (!iso) return '';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return '';
  const mins = Math.floor(Math.max(0, Date.now() - t) / 60000);
  if (mins < 1) return 'vừa xong';
  if (mins < 60) return `${mins} phút trước`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours} giờ trước`;
  return `${Math.floor(hours / 24)} ngày trước`;
}

export default function ForumMgmt() {
  const { data: postsData, refetch: refetchPosts } = useAdminGet<ForumApiPost[] | { results?: ForumApiPost[] }>('/forum/posts/?page_size=100');
  const { data: usersData, refetch: refetchUsers } = useAdminGet<{ count: number; results: ApiUser[] }>('/admin/users/');

  const [tab, setTab] = useState<TabId>('posts');
  const [postSearch, setPostSearch] = useState('');
  const [memberSearch, setMemberSearch] = useState('');
  const [modSearch, setModSearch] = useState('');
  const [postReports, setPostReports] = useState<ReportRow[]>([]);
  const [commentReports, setCommentReports] = useState<ReportRow[]>([]);
  const [bans, setBans] = useState<BanRow[]>([]);

  const loadModeration = async () => {
    try {
      const [pr, cr, bs] = await Promise.all([
        api.get<ApiPostReport[]>('/admin/forum/reports/?status=all'),
        api.get<ApiCommentReport[]>('/admin/forum/comment-reports/?status=all'),
        api.get<ApiBan[]>('/admin/forum/bans/'),
      ]);
      setPostReports((pr || []).map(mapPostReport));
      setCommentReports((cr || []).map(mapCommentReport));
      setBans((bs || []).map(mapBan));
    } catch {
      /* tab kiểm duyệt hiển thị rỗng nếu lỗi */
    }
  };

  useEffect(() => {
    void loadModeration();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const posts = useMemo<PostRow[]>(() => {
    const list = Array.isArray(postsData) ? postsData : postsData?.results || [];
    return list.map((p) => ({
      id: p.id,
      title: p.title || '',
      author_name: p.author_name || p.author_username || '',
      category: p.category || '',
      likes_count: p.likes_count || 0,
      comments_count: p.comments_count || 0,
      views_count: p.views_count || 0,
      is_pinned: !!p.is_pinned,
      is_locked: !!p.is_locked,
      created_at_display: timeAgo(p.created_at),
    }));
  }, [postsData]);

  /* Chỉ tính lệnh cấm còn hiệu lực (bỏ qua bản ghi đã gỡ/hết hạn). */
  const bannedSet = useMemo(
    () => new Set(bans.filter((b) => b.is_active && !b.is_expired).map((b) => b.username)),
    [bans],
  );

  const allMembers = useMemo<MemberRow[]>(() => {
    const list = usersData?.results || [];
    return list.map((u) => ({
      id: u.id,
      username: u.username,
      display_name: u.full_name || u.username,
      avatar: null,
      rank: null,
      posts_count: u.posts_count || 0,
      comments_count: u.comments_count || 0,
      is_staff: !!u.is_staff,
      is_banned: bannedSet.has(u.username),
      is_superuser: !!u.is_superuser,
      date_joined: u.date_joined || '',
    }));
  }, [usersData, bannedSet]);

  /* Thành viên diễn đàn = user đã từng đăng bài/bình luận (giống manage_forum). */
  const members = useMemo(
    () => allMembers.filter((m) => m.posts_count > 0 || m.comments_count > 0),
    [allMembers],
  );

  /* Kiểm duyệt viên = tất cả user is_staff (giống moderators_json). */
  const moderators = useMemo<ModeratorRow[]>(
    () => allMembers.filter((m) => m.is_staff).map((m) => ({
      id: m.id, username: m.username, display_name: m.display_name,
      avatar: m.avatar, is_superuser: m.is_superuser, date_joined: m.date_joined,
    })),
    [allMembers],
  );

  const stats = useMemo(() => {
    const list = Array.isArray(postsData) ? postsData : postsData?.results || [];
    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    const todayMs = todayStart.getTime();
    const postsToday = list.filter((p) => {
      const t = p.created_at ? new Date(p.created_at).getTime() : NaN;
      return t >= todayMs;
    }).length;
    return {
      total_posts: posts.length,
      total_comments: posts.reduce((a, p) => a + p.comments_count, 0),
      total_members: members.length,
      total_bans: bans.filter((b) => b.is_active && !b.is_expired).length,
      pending_reports: postReports.filter((r) => r.status === 'pending').length
        + commentReports.filter((r) => r.status === 'pending').length,
      posts_today: postsToday,
    };
  }, [posts, members, bans, postReports, commentReports, postsData]);

  /* Chart data — suy ra cục bộ từ danh sách bài viết. */
  const dailyData = useMemo(() => {
    const list = Array.isArray(postsData) ? postsData : postsData?.results || [];
    const out: Array<{ date: string; count: number }> = [];
    const today = new Date();
    for (let i = 13; i >= 0; i--) {
      const d = new Date(today.getFullYear(), today.getMonth(), today.getDate() - i);
      const start = d.getTime();
      const end = start + 86400000;
      const label = `${String(d.getDate()).padStart(2, '0')}/${String(d.getMonth() + 1).padStart(2, '0')}`;
      const count = list.filter((p) => {
        const t = p.created_at ? new Date(p.created_at).getTime() : NaN;
        return t >= start && t < end;
      }).length;
      out.push({ date: label, count });
    }
    return out;
  }, [postsData]);

  const categoryData = useMemo(() => {
    const list = Array.isArray(postsData) ? postsData : postsData?.results || [];
    const map = new Map<string, number>();
    list.forEach((p) => {
      const key = p.category || 'Khác';
      map.set(key, (map.get(key) || 0) + 1);
    });
    return Array.from(map.entries()).map(([category, count]) => ({ category, count }));
  }, [postsData]);

  const reportData = useMemo(() => ({
    pending: postReports.filter((r) => r.status === 'pending').length + commentReports.filter((r) => r.status === 'pending').length,
    approved: postReports.filter((r) => r.status === 'approved').length + commentReports.filter((r) => r.status === 'approved').length,
    rejected: postReports.filter((r) => r.status === 'rejected').length + commentReports.filter((r) => r.status === 'rejected').length,
    ai_flagged: postReports.filter((r) => r.status === 'ai_flagged').length + commentReports.filter((r) => r.status === 'ai_flagged').length,
  }), [postReports, commentReports]);

  /* Charts — Chart.js nạp động trong browser (SSR-safe). */
  const dailyRef = useRef<HTMLCanvasElement | null>(null);
  const categoryRef = useRef<HTMLCanvasElement | null>(null);
  const reportRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    let cancelled = false;
    const charts: ChartType[] = [];
    void (async () => {
      const mod = await import('chart.js');
      if (cancelled) return;
      const { Chart, registerables } = mod;
      Chart.register(...registerables);
      Chart.defaults.color = 'rgba(255,255,255,0.4)';
      Chart.defaults.borderColor = 'rgba(255,255,255,0.05)';

      if (dailyRef.current && dailyData.length) {
        charts.push(new Chart(dailyRef.current, {
          type: 'line',
          data: {
            labels: dailyData.map((d) => d.date),
            datasets: [{
              label: 'Bài viết',
              data: dailyData.map((d) => d.count),
              borderColor: '#06b6d4',
              backgroundColor: 'rgba(6,182,212,0.15)',
              borderWidth: 2,
              fill: true,
              tension: 0.4,
              pointBackgroundColor: '#06b6d4',
              pointRadius: 3,
              pointHoverRadius: 5,
            }],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
              y: { beginAtZero: true, ticks: { stepSize: 1, font: { size: 9 } }, grid: { color: 'rgba(255,255,255,0.03)' } },
              x: { ticks: { font: { size: 8 } }, grid: { display: false } },
            },
          },
        }));
      }

      if (categoryRef.current && categoryData.length) {
        charts.push(new Chart(categoryRef.current, {
          type: 'doughnut',
          data: {
            labels: categoryData.map((d) => CAT_LABELS[d.category] || d.category || 'Khác'),
            datasets: [{
              data: categoryData.map((d) => d.count),
              backgroundColor: categoryData.map((d) => CAT_COLORS[d.category] || '#64748b'),
              borderWidth: 0,
              hoverOffset: 6,
            }],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '60%',
            plugins: { legend: { position: 'bottom', labels: { boxWidth: 8, padding: 8, font: { size: 9, weight: 'bold' } } } },
          },
        }));
      }

      if (reportRef.current) {
        charts.push(new Chart(reportRef.current, {
          type: 'doughnut',
          data: {
            labels: ['Chờ', 'Duyệt', 'Từ chối', 'AI Flag'],
            datasets: [{
              data: [reportData.pending, reportData.approved, reportData.rejected, reportData.ai_flagged],
              backgroundColor: ['#f59e0b', '#10b981', '#ef4444', '#06b6d4'],
              borderWidth: 0,
            }],
          },
          options: { responsive: true, maintainAspectRatio: false, cutout: '70%', plugins: { legend: { display: false } } },
        }));
      }
    })();
    return () => { cancelled = true; charts.forEach((c) => c.destroy()); };
  }, [dailyData, categoryData, reportData]);

  const filteredPosts = () => {
    if (!postSearch.trim()) return posts;
    const q = postSearch.toLowerCase();
    return posts.filter((p) => (p.title || '').toLowerCase().includes(q) || (p.author_name || '').toLowerCase().includes(q));
  };
  const filteredMembers = () => {
    if (!memberSearch.trim()) return members;
    const q = memberSearch.toLowerCase();
    return members.filter((m) => (m.display_name || '').toLowerCase().includes(q) || (m.username || '').toLowerCase().includes(q));
  };
  const promotableMembersFiltered = () => {
    if (!modSearch.trim()) return [];
    const q = modSearch.toLowerCase();
    return members.filter((m) => !m.is_staff && ((m.display_name || '').toLowerCase().includes(q) || (m.username || '').toLowerCase().includes(q))).slice(0, 10);
  };

  const categoryColor = (cat: string) => {
    const map: Record<string, string> = {
      warning: 'bg-danger-500/20 text-danger-500',
      discussion: 'bg-brand-500/20 text-brand-500',
      experience: 'bg-brand2-500/20 text-brand2-500',
      question: 'bg-warn-500/20 text-warn-500',
    };
    return map[cat] || 'bg-white/10 text-white/55';
  };
  const canReviewReport = (report: ReportRow) => report.status === 'pending' || report.status === 'ai_flagged';
  const statusLabel = (status: string) => {
    if (status === 'pending') return 'Chờ xử lý';
    if (status === 'approved') return 'Vi phạm';
    if (status === 'rejected') return 'Không vi phạm';
    if (status === 'ai_flagged') return 'AI gắn cờ';
    return status || '-';
  };
  const statusBadgeClass = (status: string) => {
    if (status === 'approved') return 'bg-safe-500/10 text-safe-500 border-safe-500/20';
    if (status === 'rejected') return 'bg-danger-500/10 text-danger-500 border-danger-500/20';
    if (status === 'ai_flagged') return 'bg-warn-500/10 text-warn-400 border-warn-500/20';
    return 'bg-white/5 text-white/55 border-white/10';
  };

  const postAction = async (postId: number, action: 'pin' | 'lock' | 'delete') => {
    const post = posts.find((p) => p.id === postId);
    try {
      if (action === 'delete') {
        await api.del(`/forum/posts/${postId}/`);
        showToast('Đã xóa bài viết', 'success');
      } else if (action === 'pin') {
        await api.patch(`/forum/posts/${postId}/`, { is_pinned: !(post?.is_pinned) });
        showToast(post?.is_pinned ? 'Đã bỏ ghim bài viết' : 'Đã ghim bài viết', 'success');
      } else {
        await api.patch(`/forum/posts/${postId}/`, { is_locked: !(post?.is_locked) });
        showToast(post?.is_locked ? 'Đã mở khóa bài viết' : 'Đã khóa bài viết', 'success');
      }
      refetchPosts();
    } catch (e) {
      showToast(e instanceof Error ? e.message : 'Lỗi', 'error');
    }
  };

  const confirmDeletePost = async (post: PostRow) => {
    const ok = await Swal.fire({
      title: 'Xóa bài viết?',
      html: `<p class="text-white/60 text-sm">${escapeHtml(post.title)}</p>`,
      icon: 'warning',
      showCancelButton: true,
      confirmButtonColor: 'var(--sc-danger-500)',
      cancelButtonText: 'Hủy',
      confirmButtonText: 'Xóa',
      background: 'var(--sc-night-2)',
      color: 'var(--sc-white)',
    });
    if (ok.isConfirmed) void postAction(post.id, 'delete');
  };

  const reportAction = async (type: 'post' | 'comment', reportId: number, action: 'analyze' | 'approve' | 'reject') => {
    const setList = type === 'post' ? setPostReports : setCommentReports;
    if (action === 'analyze') setList((prev) => prev.map((r) => (r.id === reportId ? { ...r, ai_status: 'analyzing' } : r)));
    const path =
      type === 'post'
        ? `/admin/forum/reports/${reportId}/action/`
        : `/admin/forum/comment-reports/${reportId}/action/`;
    try {
      const data = await api.post<{
        status?: string;
        message?: string;
        error?: string;
        ai?: { verdict?: string; reason?: string };
      }>(path, { action });
      if (data.status === 'ok') {
        showToast(data.message || 'Thành công', 'success');
        if (action === 'approve' || action === 'reject') {
          const status = action === 'approve' ? 'approved' : 'rejected';
          setList((prev) => prev.map((r) => (r.id === reportId ? { ...r, status } : r)));
        } else {
          const v = data.ai?.verdict;
          setList((prev) =>
            prev.map((r) =>
              r.id === reportId
                ? { ...r, ai_status: 'done', ai_violation: v ? v !== 'allow' : null, ai_confidence: data.ai?.reason || null }
                : r,
            ),
          );
        }
      } else {
        showToast(data.error || 'Lỗi', 'error');
        if (action === 'analyze') setList((prev) => prev.map((r) => (r.id === reportId ? { ...r, ai_status: 'none' } : r)));
      }
    } catch (e) {
      showToast(e instanceof Error ? e.message : 'Lỗi kết nối', 'error');
      if (action === 'analyze') setList((prev) => prev.map((r) => (r.id === reportId ? { ...r, ai_status: 'none' } : r)));
    }
  };

  const unbanByUsername = async (username: string) => {
    /* Ưu tiên bản ghi còn hiệu lực — trước đây find() lấy bản ghi đầu tiên nên
     * có thể gỡ nhầm lệnh đã hết hiệu lực trong khi lệnh mới vẫn còn. */
    const ban = bans.find((b) => b.username === username && b.is_active && !b.is_expired)
      || bans.find((b) => b.username === username);
    if (!ban) return;
    try {
      const data = await api.post<{ status?: string; message?: string; error?: string }>('/admin/forum/ban/', {
        action: 'unban',
        ban_id: ban.id,
      });
      if (data.status === 'ok') {
        showToast(data.message || 'Đã gỡ cấm', 'success');
        setBans((prev) => prev.filter((b) => b.id !== ban.id));
      } else {
        showToast(data.error || 'Lỗi', 'error');
      }
    } catch (e) {
      showToast(e instanceof Error ? e.message : 'Lỗi kết nối', 'error');
    }
  };

  const banUser = async (member: MemberRow) => {
    const result = await Swal.fire({
      title: `Cấm ${escapeHtml(member.display_name)}?`,
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
      const data = await api.post<{ status?: string; message?: string; error?: string }>('/admin/forum/ban/', {
        user_id: member.id,
        reason: value.reason,
        ban_type: value.ban_type,
        days: value.days,
      });
      if (data.status === 'ok') {
        showToast(data.message || 'Đã cấm', 'success');
        void loadModeration();
      } else {
        showToast(data.error || 'Lỗi', 'error');
      }
    } catch (e) {
      showToast(e instanceof Error ? e.message : 'Lỗi kết nối', 'error');
    }
  };

  const unbanUser = async (member: MemberRow) => {
    await unbanByUsername(member.username);
  };

  const promoteModerator = async (member: MemberRow) => {
    const ok = await Swal.fire({
      title: 'Bổ nhiệm Kiểm duyệt viên?',
      html: `<p class="text-white/60 text-sm">Bạn muốn bổ nhiệm <strong class="text-brand-400">${escapeHtml(member.display_name)}</strong> (@${escapeHtml(member.username)}) làm Kiểm duyệt viên?</p>`,
      icon: 'question',
      showCancelButton: true,
      confirmButtonColor: 'var(--sc-safe-500)',
      cancelButtonText: 'Hủy',
      confirmButtonText: 'Bổ nhiệm',
      background: 'var(--sc-night-2)',
      color: 'var(--sc-white)',
    });
    if (!ok.isConfirmed) return;
    try {
      const res = await api.post<{ status?: string; message?: string }>(`/admin/users/${member.id}/action/`, { action: 'toggle_staff' });
      showToast(res.message || 'Đã bổ nhiệm Kiểm duyệt viên', 'success');
      setModSearch('');
      refetchUsers();
    } catch (e) {
      showToast(e instanceof Error ? e.message : 'Lỗi', 'error');
    }
  };

  const demoteModerator = async (mod: ModeratorRow) => {
    const ok = await Swal.fire({
      title: 'Gỡ quyền Kiểm duyệt?',
      html: `<p class="text-white/60 text-sm">Bạn muốn gỡ quyền Kiểm duyệt viên của <strong class="text-danger-400">${escapeHtml(mod.display_name)}</strong>?</p>`,
      icon: 'warning',
      showCancelButton: true,
      confirmButtonColor: 'var(--sc-danger-500)',
      cancelButtonText: 'Hủy',
      confirmButtonText: 'Gỡ quyền',
      background: 'var(--sc-night-2)',
      color: 'var(--sc-white)',
    });
    if (!ok.isConfirmed) return;
    try {
      const res = await api.post<{ status?: string; message?: string }>(`/admin/users/${mod.id}/action/`, { action: 'toggle_staff' });
      showToast(res.message || 'Đã gỡ quyền Kiểm duyệt viên', 'success');
      refetchUsers();
    } catch (e) {
      showToast(e instanceof Error ? e.message : 'Lỗi', 'error');
    }
  };

  const refetchAll = async () => {
    refetchPosts();
    refetchUsers();
    await loadModeration();
    showToast('Đã làm mới dữ liệu diễn đàn', 'success');
  };

  return (
    <AdminShell
      breadcrumbs={[{ label: 'Diễn đàn' }]}
      title="Điều phối Diễn đàn"
      subtitle="Quản lý bài viết, báo cáo vi phạm, thành viên và kỷ luật cộng đồng"
      actions={
        <div className="flex items-center gap-2">
          <Link
            href="/forum/"
            target="_blank"
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-white/5 border border-white/10 text-brand-400 hover:bg-white/10 hover:text-white transition-all text-xs font-bold"
          >
            <i className="bi bi-box-arrow-up-right"></i> Xem diễn đàn
          </Link>
          <button
            type="button"
            onClick={refetchAll}
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-white/5 border border-white/10 text-white hover:bg-white/10 hover:border-brand-500/30 transition-all text-xs font-bold"
          >
            <i className="bi bi-arrow-clockwise"></i> Làm mới
          </button>
        </div>
      }
    >
      {/* Dashboard Stats */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-6">
        <div className="bg-slate-900/60 border border-white/10 rounded-2xl p-4 text-center backdrop-blur-xl shadow-lg">
          <div className="text-2xl font-black text-brand-400">{stats.total_posts}</div>
          <div className="text-xs font-bold text-slate-400 uppercase tracking-wider mt-1">Bài viết</div>
        </div>
        <div className="bg-slate-900/60 border border-white/10 rounded-2xl p-4 text-center backdrop-blur-xl shadow-lg">
          <div className="text-2xl font-black text-cyan-400">{stats.total_comments}</div>
          <div className="text-xs font-bold text-slate-400 uppercase tracking-wider mt-1">Bình luận</div>
        </div>
        <div className="bg-slate-900/60 border border-white/10 rounded-2xl p-4 text-center backdrop-blur-xl shadow-lg">
          <div className="text-2xl font-black text-white">{stats.total_members}</div>
          <div className="text-xs font-bold text-slate-400 uppercase tracking-wider mt-1">Thành viên</div>
        </div>
        <div className="bg-slate-900/60 border border-white/10 rounded-2xl p-4 text-center backdrop-blur-xl shadow-lg">
          <div className="text-2xl font-black text-rose-400">{stats.total_bans}</div>
          <div className="text-xs font-bold text-slate-400 uppercase tracking-wider mt-1">Đang cấm</div>
        </div>
        <div className="bg-slate-900/60 border border-white/10 rounded-2xl p-4 text-center backdrop-blur-xl shadow-lg">
          <div className="text-2xl font-black text-amber-400">{stats.pending_reports}</div>
          <div className="text-xs font-bold text-slate-400 uppercase tracking-wider mt-1">Báo cáo chờ</div>
        </div>
        <div className="bg-slate-900/60 border border-white/10 rounded-2xl p-4 text-center backdrop-blur-xl shadow-lg">
          <div className="text-2xl font-black text-emerald-400">{stats.posts_today}</div>
          <div className="text-xs font-bold text-slate-400 uppercase tracking-wider mt-1">Hôm nay</div>
        </div>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="md:col-span-2 bg-slate-900/60 border border-white/10 rounded-2xl p-5 backdrop-blur-xl shadow-lg">
          <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-4 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-brand-500"></span> Bài viết 14 ngày qua
          </h3>
          <div className="h-48">
            <canvas ref={dailyRef} id="dailyPostsChart"></canvas>
          </div>
        </div>
        <div className="bg-slate-900/60 border border-white/10 rounded-2xl p-5 backdrop-blur-xl shadow-lg">
          <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-4 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-500"></span> Theo danh mục
          </h3>
          <div className="h-48">
            <canvas ref={categoryRef} id="categoryChart"></canvas>
          </div>
        </div>
      </div>

      {/* Report Status Mini Chart */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-slate-900/60 border border-white/10 rounded-2xl p-4 backdrop-blur-xl flex items-center gap-4 shadow-lg">
          <div className="w-20 h-20 shrink-0"><canvas ref={reportRef} id="reportStatusChart"></canvas></div>
          <div className="text-xs space-y-1.5 font-medium">
            <div className="flex items-center gap-2"><span className="w-2 h-2 rounded-full bg-amber-400"></span><span className="text-slate-300">Chờ: <span className="text-white font-bold">{reportData.pending}</span></span></div>
            <div className="flex items-center gap-2"><span className="w-2 h-2 rounded-full bg-emerald-400"></span><span className="text-slate-300">Duyệt: <span className="text-white font-bold">{reportData.approved}</span></span></div>
            <div className="flex items-center gap-2"><span className="w-2 h-2 rounded-full bg-rose-400"></span><span className="text-slate-300">Từ chối: <span className="text-white font-bold">{reportData.rejected}</span></span></div>
            <div className="flex items-center gap-2"><span className="w-2 h-2 rounded-full bg-amber-400"></span><span className="text-slate-300">AI Flag: <span className="text-white font-bold">{reportData.ai_flagged}</span></span></div>
          </div>
        </div>
        {/* Moderators quick overview */}
        <div className="md:col-span-3 bg-slate-900/60 border border-white/10 rounded-2xl p-4 backdrop-blur-xl shadow-lg">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-500"></span> Kiểm duyệt viên
            </h3>
            <button onClick={() => setTab('moderators')} className="text-xs font-bold text-brand-400 hover:text-white transition-colors">Quản lý →</button>
          </div>
          <div className="flex flex-wrap gap-2">
            {moderators.map((mod) => (
              <div key={mod.id} className="flex items-center gap-2 bg-slate-800/80 border border-white/10 rounded-xl px-3 py-1.5 shadow-sm">
                <div className="w-6 h-6 rounded-full overflow-hidden bg-white/5 border border-white/10 flex items-center justify-center shrink-0">
                  {mod.avatar ? (
                    // eslint-disable-next-line @next/next/no-img-element
                    <img src={mediaUrl(mod.avatar)} className="w-full h-full object-cover" alt="" />
                  ) : (
                    <span className="text-[10px] font-bold text-brand-400">{mod.display_name?.charAt(0)?.toUpperCase()}</span>
                  )}
                </div>
                <span className="text-xs font-bold text-slate-200">{mod.display_name}</span>
                {mod.is_superuser && (
                  <span className="text-[9px] font-black text-amber-400 bg-amber-400/10 px-1.5 py-0.5 rounded uppercase border border-amber-400/20">SA</span>
                )}
              </div>
            ))}
            {moderators.length === 0 && (
              <span className="text-xs text-slate-500 italic">Chưa có kiểm duyệt viên</span>
            )}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 p-1.5 rounded-2xl bg-slate-900/80 border border-white/10 backdrop-blur-xl mb-6 w-full overflow-x-auto custom-scrollbar shadow-lg">
        <button
          onClick={() => setTab('posts')}
          className={`px-4 py-2 rounded-xl text-xs font-bold transition-all shrink-0 ${
            tab === 'posts'
              ? 'bg-gradient-to-r from-brand-500 to-brand-600 text-black font-black shadow-md'
              : 'text-slate-300 hover:text-white hover:bg-white/5'
          }`}
        >
          <i className="bi bi-chat-square-text mr-1.5"></i> Bài viết ({posts.length})
        </button>
        <button
          onClick={() => setTab('post_reports')}
          className={`px-4 py-2 rounded-xl text-xs font-bold transition-all shrink-0 ${
            tab === 'post_reports'
              ? 'bg-rose-500 text-white font-black shadow-md'
              : 'text-slate-300 hover:text-white hover:bg-white/5'
          }`}
        >
          <i className="bi bi-flag mr-1.5"></i> Báo cáo bài ({postReports.length})
        </button>
        <button
          onClick={() => setTab('comment_reports')}
          className={`px-4 py-2 rounded-xl text-xs font-bold transition-all shrink-0 ${
            tab === 'comment_reports'
              ? 'bg-amber-500 text-black font-black shadow-md'
              : 'text-slate-300 hover:text-white hover:bg-white/5'
          }`}
        >
          <i className="bi bi-chat-left-dots mr-1.5"></i> Báo cáo BL ({commentReports.length})
        </button>
        <button
          onClick={() => setTab('members')}
          className={`px-4 py-2 rounded-xl text-xs font-bold transition-all shrink-0 ${
            tab === 'members'
              ? 'bg-gradient-to-r from-brand-500 to-brand-600 text-black font-black shadow-md'
              : 'text-slate-300 hover:text-white hover:bg-white/5'
          }`}
        >
          <i className="bi bi-people mr-1.5"></i> Thành viên ({members.length})
        </button>
        <button
          onClick={() => setTab('bans')}
          className={`px-4 py-2 rounded-xl text-xs font-bold transition-all shrink-0 ${
            tab === 'bans'
              ? 'bg-rose-600 text-white font-black shadow-md'
              : 'text-slate-300 hover:text-white hover:bg-white/5'
          }`}
        >
          <i className="bi bi-slash-circle mr-1.5"></i> Đang cấm ({bans.length})
        </button>
        <button
          onClick={() => setTab('moderators')}
          className={`px-4 py-2 rounded-xl text-xs font-bold transition-all shrink-0 ${
            tab === 'moderators'
              ? 'bg-emerald-500 text-black font-black shadow-md'
              : 'text-slate-300 hover:text-white hover:bg-white/5'
          }`}
        >
          <i className="bi bi-shield-check mr-1.5"></i> Kiểm duyệt ({moderators.length})
        </button>
      </div>

      {/* ═══════ Tab: Posts Management ═══════ */}
      {tab === 'posts' && (
        <div>
          <div className="rounded-2xl bg-slate-900/40 border border-white/5 backdrop-blur-xl overflow-hidden shadow-2xl">
            <div className="p-6 border-b border-white/5 flex items-center justify-between">
              <h3 className="text-xs font-black text-white/80 uppercase tracking-widest flex items-center gap-3">
                <span className="w-2 h-2 rounded-full bg-brand-500 shadow-[0_0_10px_rgba(6,182,212,0.5)]"></span>
                Tất cả bài viết
              </h3>
              <input type="text" value={postSearch} onChange={(e) => setPostSearch(e.target.value)} placeholder="Tìm bài viết..." className="bg-white/5 border border-white/10 rounded-xl px-4 py-2 text-sm text-white placeholder-white/30 focus:outline-none focus:border-brand-500/30 w-56" />
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="bg-white/[0.02]">
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Bài viết</th>
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Tác giả</th>
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Danh mục</th>
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Tương tác</th>
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Trạng thái</th>
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5 text-right">Hành động</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.02]">
                  {filteredPosts().map((post) => (
                    <tr key={post.id} className="group hover:bg-white/[0.03] transition-all">
                      <td className="px-5 py-4 max-w-xs">
                        <Link href={`/forum/${post.id}/`} target="_blank" className="text-sm font-bold text-white/80 hover:text-brand-400 transition-colors line-clamp-2">{post.title}</Link>
                        <div className="text-[10px] text-white/45 mt-1">{post.created_at_display}</div>
                      </td>
                      <td className="px-5 py-4">
                        <div className="flex items-center gap-2">
                          <div className="w-7 h-7 rounded-full bg-brand-500/10 border border-brand-500/20 flex items-center justify-center text-brand-400 font-bold text-[10px]">{post.author_name?.charAt(0)?.toUpperCase()}</div>
                          <span className="text-xs font-bold text-white/60">{post.author_name}</span>
                        </div>
                      </td>
                      <td className="px-5 py-4">
                        <span className={`px-2 py-0.5 rounded text-[8px] font-black uppercase ${categoryColor(post.category)}`}>{post.category}</span>
                      </td>
                      <td className="px-5 py-4">
                        <div className="flex items-center gap-3 text-[10px] text-white/55">
                          <span><i className="bi bi-heart-fill text-danger-400/50 mr-1"></i><span>{post.likes_count || 0}</span></span>
                          <span><i className="bi bi-chat-left mr-1"></i><span>{post.comments_count || 0}</span></span>
                          <span><i className="bi bi-eye mr-1"></i><span>{post.views_count || 0}</span></span>
                        </div>
                      </td>
                      <td className="px-5 py-4">
                        <div className="flex flex-wrap gap-1">
                          {post.is_pinned && <span className="px-2 py-0.5 rounded bg-warn-500/15 text-warn-500 text-[8px] font-black uppercase">Ghim</span>}
                          {post.is_locked && <span className="px-2 py-0.5 rounded bg-danger-500/15 text-danger-500 text-[8px] font-black uppercase">Khóa</span>}
                          {!post.is_pinned && !post.is_locked && <span className="px-2 py-0.5 rounded bg-safe-500/15 text-safe-500 text-[8px] font-black uppercase">OK</span>}
                        </div>
                      </td>
                      <td className="px-5 py-4">
                        <div className="flex justify-end gap-1.5 transition-all">
                          <button onClick={() => void postAction(post.id, 'pin')} className="h-7 px-2.5 rounded-lg bg-white/5 text-[10px] font-bold border border-white/10 hover:border-amber-500/30 hover:text-amber-400 transition-all" title={post.is_pinned ? 'Bỏ ghim' : 'Ghim'}>
                            <i className={`bi ${post.is_pinned ? 'bi-pin-angle-fill text-amber-400' : 'bi-pin-angle text-slate-300'}`}></i>
                          </button>
                          <button onClick={() => void postAction(post.id, 'lock')} className="h-7 px-2.5 rounded-lg bg-white/5 text-[10px] font-bold border border-white/10 hover:border-amber-500/30 hover:text-amber-400 transition-all" title={post.is_locked ? 'Mở khóa' : 'Khóa'}>
                            <i className={`bi ${post.is_locked ? 'bi-lock-fill text-amber-400' : 'bi-unlock text-slate-300'}`}></i>
                          </button>
                          <button onClick={() => void confirmDeletePost(post)} className="h-7 px-2.5 rounded-lg bg-white/5 text-slate-300 text-[10px] font-bold border border-white/10 hover:border-rose-500/30 hover:text-rose-400 transition-all" title="Xóa">
                            <i className="bi bi-trash3"></i>
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                  {filteredPosts().length === 0 && (
                    <tr><td colSpan={6} className="px-6 py-12 text-center text-white/35 italic text-xs font-bold">Không có bài viết.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ═══════ Tab: Post Reports ═══════ */}
      {tab === 'post_reports' && (
        <div>
          <div className="rounded-2xl bg-slate-900/40 border border-white/5 backdrop-blur-xl overflow-hidden shadow-2xl">
            <div className="p-6 border-b border-white/5">
              <h3 className="text-xs font-black text-white/80 uppercase tracking-widest flex items-center gap-3">
                <span className="w-2 h-2 rounded-full bg-danger-500 shadow-[0_0_10px_rgba(239,68,68,0.5)]"></span>
                Báo cáo bài viết
              </h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="bg-white/[0.02]">
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Thời gian</th>
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Người báo cáo</th>
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Bài viết / Lý do</th>
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">AI</th>
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Trạng thái</th>
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5 text-right">Hành động</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.02]">
                  {postReports.map((r) => (
                    <tr key={r.id} className="group hover:bg-white/[0.03] transition-all">
                      <td className="px-5 py-4 text-[11px] font-bold text-white/60 whitespace-nowrap">{r.created_at_display}</td>
                      <td className="px-5 py-4"><span className="text-xs font-bold text-white/70">{r.reporter_name}</span></td>
                      <td className="px-5 py-4 max-w-xs">
                        <div className="text-xs font-bold text-white/80 mb-1">{r.post_title}</div>
                        <div className="text-[10px] text-white/45 italic">{'Lý do: ' + (r.reason || '-')}</div>
                      </td>
                      <td className="px-5 py-4">
                        {r.ai_status === 'analyzing' && (
                          <span className="text-warn-400 text-[10px] font-black"><i className="bi bi-cpu animate-pulse"></i> Đang...</span>
                        )}
                        {r.ai_violation === true && (
                          <div>
                            <span className="text-danger-500 text-[10px] font-black"><i className="bi bi-exclamation-triangle-fill"></i> Vi phạm</span>
                            <div className="text-[8px] text-white/35">{'Conf: ' + (r.ai_confidence || '-')}</div>
                          </div>
                        )}
                        {r.ai_violation === false && (
                          <span className="text-safe-500 text-[10px] font-black"><i className="bi bi-shield-check"></i> An toàn</span>
                        )}
                        {r.ai_status === 'none' && (
                          <span className="text-white/35 text-[10px]"><i className="bi bi-dash-circle"></i> Chưa quét</span>
                        )}
                      </td>
                      <td className="px-5 py-4">
                        <span className={`px-2 py-0.5 rounded text-[8px] font-black uppercase border ${statusBadgeClass(r.status)}`}>{statusLabel(r.status)}</span>
                      </td>
                      <td className="px-5 py-4">
                        <div className={`flex justify-end gap-1.5 ${canReviewReport(r) ? '' : 'opacity-30 pointer-events-none'}`}>
                          <button onClick={() => void reportAction('post', r.id, 'analyze')} className="h-7 px-2.5 rounded-lg bg-white/5 text-white/55 text-[10px] border border-white/10 hover:border-brand-500/30 hover:text-brand-400 transition-all" title="AI"><i className="bi bi-cpu"></i></button>
                          <button onClick={() => void reportAction('post', r.id, 'approve')} className="h-7 px-2.5 rounded-lg bg-white/5 text-white/55 text-[10px] border border-white/10 hover:border-safe-500/30 hover:text-safe-400 transition-all" title="Duyệt"><i className="bi bi-check-circle"></i></button>
                          <button onClick={() => void reportAction('post', r.id, 'reject')} className="h-7 px-2.5 rounded-lg bg-white/5 text-white/55 text-[10px] border border-white/10 hover:border-danger-500/30 hover:text-danger-400 transition-all" title="Từ chối"><i className="bi bi-x-circle"></i></button>
                        </div>
                      </td>
                    </tr>
                  ))}
                  {postReports.length === 0 && (
                    <tr><td colSpan={6} className="px-6 py-12 text-center text-white/35 italic text-xs">Không có báo cáo.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ═══════ Tab: Comment Reports ═══════ */}
      {tab === 'comment_reports' && (
        <div>
          <div className="rounded-2xl bg-slate-900/40 border border-white/5 backdrop-blur-xl overflow-hidden shadow-2xl">
            <div className="p-6 border-b border-white/5">
              <h3 className="text-xs font-black text-white/80 uppercase tracking-widest flex items-center gap-3">
                <span className="w-2 h-2 rounded-full bg-brand-500"></span>
                Báo cáo bình luận
              </h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="bg-white/[0.02]">
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Thời gian</th>
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Người báo cáo</th>
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Nội dung</th>
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Trạng thái</th>
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5 text-right">Hành động</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.02]">
                  {commentReports.map((r) => (
                    <tr key={r.id} className="group hover:bg-white/[0.03] transition-all">
                      <td className="px-5 py-4 text-[11px] font-bold text-white/60 whitespace-nowrap">{r.created_at_display}</td>
                      <td className="px-5 py-4"><span className="text-xs font-bold text-white/70">{r.reporter_name}</span></td>
                      <td className="px-5 py-4 max-w-sm">
                        <div className="text-[11px] text-white/60 italic line-clamp-2">{r.comment_content}</div>
                        <div className="text-[9px] text-white/35 mt-1">{'Lý do: ' + (r.reason || '-')}</div>
                      </td>
                      <td className="px-5 py-4">
                        <span className={`px-2 py-0.5 rounded text-[8px] font-black uppercase border ${statusBadgeClass(r.status)}`}>{statusLabel(r.status)}</span>
                      </td>
                      <td className="px-5 py-4">
                        <div className={`flex justify-end gap-1.5 ${canReviewReport(r) ? '' : 'opacity-30 pointer-events-none'}`}>
                          <button onClick={() => void reportAction('comment', r.id, 'analyze')} className="h-7 px-2.5 rounded-lg bg-white/5 text-white/55 text-[10px] border border-white/10 hover:border-brand-500/30 hover:text-brand-400 transition-all" title="AI"><i className="bi bi-cpu"></i></button>
                          <button onClick={() => void reportAction('comment', r.id, 'approve')} className="h-7 px-2.5 rounded-lg bg-white/5 text-white/55 text-[10px] border border-white/10 hover:border-safe-500/30 hover:text-safe-400 transition-all" title="Duyệt"><i className="bi bi-check-circle"></i></button>
                          <button onClick={() => void reportAction('comment', r.id, 'reject')} className="h-7 px-2.5 rounded-lg bg-white/5 text-white/55 text-[10px] border border-white/10 hover:border-danger-500/30 hover:text-danger-400 transition-all" title="Từ chối"><i className="bi bi-x-circle"></i></button>
                        </div>
                      </td>
                    </tr>
                  ))}
                  {commentReports.length === 0 && (
                    <tr><td colSpan={5} className="px-6 py-12 text-center text-white/35 italic text-xs">Không có báo cáo bình luận.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ═══════ Tab: Members Management ═══════ */}
      {tab === 'members' && (
        <div>
          <div className="rounded-2xl bg-slate-900/40 border border-white/5 backdrop-blur-xl overflow-hidden shadow-2xl">
            <div className="p-6 border-b border-white/5 flex items-center justify-between">
              <h3 className="text-xs font-black text-white/80 uppercase tracking-widest flex items-center gap-3">
                <span className="w-2 h-2 rounded-full bg-brand-500"></span>
                Thành viên diễn đàn
              </h3>
              <input type="text" value={memberSearch} onChange={(e) => setMemberSearch(e.target.value)} placeholder="Tìm thành viên..." className="bg-white/5 border border-white/10 rounded-xl px-4 py-2 text-sm text-white placeholder-white/30 focus:outline-none focus:border-brand-500/30 w-56" />
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="bg-white/[0.02]">
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Thành viên</th>
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Hạng</th>
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Bài viết</th>
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Bình luận</th>
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Tham gia</th>
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Trạng thái</th>
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5 text-right">Hành động</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.02]">
                  {filteredMembers().map((m) => (
                    <tr key={m.id} className="group hover:bg-white/[0.03] transition-all">
                      <td className="px-5 py-4">
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 rounded-lg overflow-hidden bg-white/5 border border-white/10 flex items-center justify-center shrink-0">
                            {m.avatar ? (
                              // eslint-disable-next-line @next/next/no-img-element
                              <img src={mediaUrl(m.avatar)} className="w-full h-full object-cover" alt="" />
                            ) : (
                              <span className="text-[10px] font-bold text-brand-400">{m.display_name?.charAt(0)?.toUpperCase()}</span>
                            )}
                          </div>
                          <div>
                            <Link href={`/profile/@${m.username}/`} target="_blank" className="text-xs font-bold text-white/80 hover:text-brand-400 transition-colors">{m.display_name}</Link>
                            <div className="text-[9px] text-white/55">{'@' + m.username}</div>
                          </div>
                        </div>
                      </td>
                      <td className="px-5 py-4">
                        {m.rank && (
                          <span
                            className={`px-2 py-0.5 rounded text-[8px] font-black uppercase ${m.rank.level === 'diamond' ? 'bg-brand-400/15 text-brand-400' : m.rank.level === 'platinum' ? 'bg-brand2-400/15 text-brand2-400' : m.rank.level === 'gold' ? 'bg-warn-400/15 text-warn-400' : m.rank.level === 'silver' ? 'bg-slate-300/15 text-slate-300' : 'bg-warn-400/15 text-warn-400'}`}
                          >{m.rank.name}</span>
                        )}
                      </td>
                      <td className="px-5 py-4 text-sm font-bold text-white/60">{m.posts_count}</td>
                      <td className="px-5 py-4 text-sm font-bold text-white/60">{m.comments_count}</td>
                      <td className="px-5 py-4 text-[10px] font-bold text-white/55">{m.date_joined}</td>
                      <td className="px-5 py-4">
                        {m.is_banned && (
                          <span className="px-2 py-0.5 rounded bg-danger-500/15 text-danger-400 text-[8px] font-black uppercase">Đang cấm</span>
                        )}
                        {m.is_staff && !m.is_banned && (
                          <span className="px-2 py-0.5 rounded bg-brand-500/15 text-brand-400 text-[8px] font-black uppercase">Admin</span>
                        )}
                        {!m.is_staff && !m.is_banned && (
                          <span className="px-2 py-0.5 rounded bg-safe-500/15 text-safe-400 text-[8px] font-black uppercase">Hoạt động</span>
                        )}
                      </td>
                      <td className="px-5 py-4">
                        <div className="flex justify-end gap-1.5 transition-all">
                          {!m.is_banned && !m.is_staff && (
                            <button onClick={() => void promoteModerator(m)} className="h-7 px-3 rounded-lg bg-safe-500/10 text-safe-400/70 text-[10px] font-bold border border-safe-500/20 hover:bg-safe-500/20 hover:text-safe-400 transition-all" title="Bổ nhiệm KDV">
                              <i className="bi bi-shield-plus mr-1"></i> KDV
                            </button>
                          )}
                          {!m.is_banned && !m.is_staff && (
                            <button onClick={() => void banUser(m)} className="h-7 px-3 rounded-lg bg-danger-500/10 text-danger-400/70 text-[10px] font-bold border border-danger-500/20 hover:bg-danger-500/20 hover:text-danger-400 transition-all" title="Cấm">
                              <i className="bi bi-slash-circle mr-1"></i> Cấm
                            </button>
                          )}
                          {m.is_banned && (
                            <button onClick={() => void unbanUser(m)} className="h-7 px-3 rounded-lg bg-safe-500/10 text-safe-400/70 text-[10px] font-bold border border-safe-500/20 hover:bg-safe-500/20 hover:text-safe-400 transition-all" title="Gỡ cấm">
                              <i className="bi bi-check-circle mr-1"></i> Gỡ cấm
                            </button>
                          )}
                          {m.is_staff && !m.is_banned && (
                            <button onClick={() => void demoteModerator(m)} className="h-7 px-3 rounded-lg bg-warn-500/10 text-warn-400/70 text-[10px] font-bold border border-warn-500/20 hover:bg-warn-500/20 hover:text-warn-400 transition-all" title="Gỡ quyền KDV">
                              <i className="bi bi-shield-minus mr-1"></i> Gỡ KDV
                            </button>
                          )}
                          <Link href={`/profile/@${m.username}/`} target="_blank" className="h-7 px-3 rounded-lg bg-brand-500/10 text-brand-400/70 text-[10px] font-bold border border-brand-500/20 hover:bg-brand-500/20 hover:text-brand-400 transition-all flex items-center" title="Xem hồ sơ">
                            <i className="bi bi-person"></i>
                          </Link>
                        </div>
                      </td>
                    </tr>
                  ))}
                  {filteredMembers().length === 0 && (
                    <tr><td colSpan={7} className="px-6 py-12 text-center text-white/35 italic text-xs">Không tìm thấy thành viên.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ═══════ Tab: Banned Users ═══════ */}
      {tab === 'bans' && (
        <div>
          <div className="rounded-2xl bg-slate-900/40 border border-white/5 backdrop-blur-xl overflow-hidden shadow-2xl">
            <div className="p-6 border-b border-white/5">
              <h3 className="text-xs font-black text-white/80 uppercase tracking-widest flex items-center gap-3">
                <span className="w-2 h-2 rounded-full bg-warn-500"></span>
                Tài khoản bị cấm
              </h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="bg-white/[0.02]">
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Thành viên</th>
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Cấm bởi</th>
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Lý do</th>
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Loại</th>
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Hết hạn</th>
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Ngày cấm</th>
                    <th className="px-5 py-4 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5 text-right">Hành động</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.02]">
                  {bans.map((b) => (
                    <tr key={b.id} className="group hover:bg-white/[0.03] transition-all">
                      <td className="px-5 py-4">
                        <div className="flex items-center gap-2">
                          <div className="w-7 h-7 rounded-lg bg-danger-500/10 border border-danger-500/20 flex items-center justify-center">
                            <span className="text-[10px] font-bold text-danger-400">{b.display_name?.charAt(0)?.toUpperCase()}</span>
                          </div>
                          <div>
                            <span className="text-xs font-bold text-white/70">{b.display_name}</span>
                            <div className="text-[9px] text-white/55">{'@' + b.username}</div>
                          </div>
                        </div>
                      </td>
                      <td className="px-5 py-4 text-xs font-bold text-white/60">{b.banned_by}</td>
                      <td className="px-5 py-4 max-w-xs">
                        <div className="text-[11px] text-white/60 line-clamp-2">{b.reason}</div>
                      </td>
                      <td className="px-5 py-4">
                        <span className={`px-2 py-0.5 rounded text-[8px] font-black uppercase ${b.ban_type === 'permanent' ? 'bg-danger-500/15 text-danger-400' : 'bg-warn-500/15 text-warn-400'}`}>{b.ban_type === 'permanent' ? 'Vĩnh viễn' : 'Tạm thời'}</span>
                      </td>
                      <td className={`px-5 py-4 text-[10px] font-bold ${b.is_expired ? 'text-safe-400' : 'text-white/55'}`}>{b.is_expired ? 'Đã hết hạn' : b.expires_at}</td>
                      <td className="px-5 py-4 text-[10px] font-bold text-white/55">{b.created_at_display}</td>
                      <td className="px-5 py-4">
                        <div className="flex justify-end">
                          <button onClick={() => void unbanByUsername(b.username)} className="h-7 px-3 rounded-lg bg-white/5 text-white/55 text-[10px] font-bold border border-white/10 hover:border-safe-500/30 hover:text-safe-400 transition-all" title="Gỡ cấm">
                            <i className="bi bi-check-circle mr-1"></i> Gỡ cấm
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                  {bans.length === 0 && (
                    <tr><td colSpan={7} className="px-6 py-12 text-center text-white/35 italic text-xs">Không có tài khoản bị cấm.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ═══════ Tab: Moderators Management ═══════ */}
      {tab === 'moderators' && (
        <div>
          <div className="rounded-2xl bg-slate-900/40 border border-white/5 backdrop-blur-xl overflow-hidden shadow-2xl">
            <div className="p-6 border-b border-white/5 flex items-center justify-between">
              <h3 className="text-xs font-black text-white/80 uppercase tracking-widest flex items-center gap-3">
                <span className="w-2 h-2 rounded-full bg-safe-500 shadow-[0_0_10px_rgba(16,185,129,0.5)]"></span>
                Quản lý Kiểm duyệt viên
              </h3>
              <p className="text-[10px] text-white/45">Bổ nhiệm hoặc gỡ quyền kiểm duyệt cho thành viên diễn đàn</p>
            </div>

            {/* Current Moderators */}
            <div className="p-6 border-b border-white/5">
              <h4 className="text-[10px] font-black text-safe-400/70 uppercase tracking-widest mb-4">Kiểm duyệt viên hiện tại</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {moderators.map((mod) => (
                  <div key={mod.id} className="bg-white/[0.03] border border-white/5 rounded-xl p-4 flex items-center justify-between group hover:border-safe-500/20 transition-all">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-xl overflow-hidden bg-white/5 border border-white/10 flex items-center justify-center shrink-0">
                        {mod.avatar ? (
                          // eslint-disable-next-line @next/next/no-img-element
                          <img src={mediaUrl(mod.avatar)} className="w-full h-full object-cover" alt="" />
                        ) : (
                          <span className="text-sm font-bold text-safe-400">{mod.display_name?.charAt(0)?.toUpperCase()}</span>
                        )}
                      </div>
                      <div>
                        <div className="text-xs font-bold text-white/80">{mod.display_name}</div>
                        <div className="text-[9px] text-white/45">{'@' + mod.username}</div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {mod.is_superuser && (
                        <span className="px-2 py-0.5 rounded text-[8px] font-black uppercase bg-warn-400/10 text-warn-400 border border-warn-400/20">Super Admin</span>
                      )}
                      {!mod.is_superuser && (
                        <button onClick={() => void demoteModerator(mod)} className="h-7 px-3 rounded-lg bg-white/5 text-slate-300 text-[10px] font-bold border border-white/10 hover:border-danger-500/30 hover:text-danger-400 transition-all" title="Gỡ quyền">
                          <i className="bi bi-person-dash mr-1"></i> Gỡ quyền
                        </button>
                      )}
                    </div>
                  </div>
                ))}
                {moderators.length === 0 && (
                  <div className="col-span-full text-center py-8 text-white/35 italic text-xs">Chưa có kiểm duyệt viên</div>
                )}
              </div>
            </div>

            {/* Promote New Moderator */}
            <div className="p-6">
              <h4 className="text-[10px] font-black text-brand-400/70 uppercase tracking-widest mb-4">Bổ nhiệm kiểm duyệt viên mới</h4>
              <div className="flex gap-3 mb-4">
                <input type="text" value={modSearch} onChange={(e) => setModSearch(e.target.value)} placeholder="Tìm thành viên để bổ nhiệm..." className="flex-1 bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-white placeholder-white/30 focus:outline-none focus:border-brand-500/30" />
              </div>
              <div className="space-y-2 max-h-64 overflow-y-auto">
                {promotableMembersFiltered().map((m) => (
                  <div key={m.id} className="flex items-center justify-between bg-white/[0.02] border border-white/5 rounded-xl px-4 py-3 hover:border-brand-500/20 transition-all">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-lg overflow-hidden bg-white/5 border border-white/10 flex items-center justify-center shrink-0">
                        {m.avatar ? (
                          // eslint-disable-next-line @next/next/no-img-element
                          <img src={mediaUrl(m.avatar)} className="w-full h-full object-cover" alt="" />
                        ) : (
                          <span className="text-[10px] font-bold text-brand-400">{m.display_name?.charAt(0)?.toUpperCase()}</span>
                        )}
                      </div>
                      <div>
                        <span className="text-xs font-bold text-white/80">{m.display_name}</span>
                        <span className="text-[9px] text-white/55 ml-2">{'@' + m.username}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-[9px] text-white/55">{m.posts_count + ' bài'}</span>
                      <button onClick={() => void promoteModerator(m)} className="h-7 px-3 rounded-lg bg-safe-500/10 text-safe-400 text-[10px] font-bold border border-safe-500/20 hover:bg-safe-500/20 transition-all">
                        <i className="bi bi-shield-plus mr-1"></i> Bổ nhiệm
                      </button>
                    </div>
                  </div>
                ))}
                {modSearch.trim() && promotableMembersFiltered().length === 0 && (
                  <div className="text-center py-6 text-white/35 italic text-xs">Không tìm thấy thành viên phù hợp</div>
                )}
                {!modSearch.trim() && (
                  <div className="text-center py-6 text-white/35 italic text-xs">Nhập tên để tìm kiếm thành viên</div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </AdminShell>
  );
}
