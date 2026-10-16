'use client';
import { useEffect, useMemo, useState } from 'react';
import Swal from 'sweetalert2';
import { api, mediaUrl } from '../../lib/api';
import { escapeHtml } from '../../lib/chat/markdown';
import { showToast, scConfirm } from '../../lib/ui/feedback';
import { LiquidSelect } from '../../components/ui';
import type { SelectOption } from '../../components/ui';
import { useAuth } from '../../components/AuthContext';
import { AdminShell, useAdminGet } from './_shared';

/* Port 1-1 từ PKV/templates/Admin/users.html (Alpine userManagement()).
 *
 * Lọc theo từ khoá / vai trò / trạng thái được thực hiện cục bộ (x-show bản gốc)
 * trên dữ liệu GET /admin/users/ (API trả tối đa 100 user + count).
 * Thao tác:
 *   - Cấp/Gỡ quyền   -> POST /admin/users/<id>/action/ (toggle_staff)
 *   - Khóa/Mở tài khoản -> POST /admin/users/<id>/action/ (toggle_active)
 *   - Reset điểm uy tín -> POST /admin/users/<id>/action/ (reset_rank)
 *   - Cấm Forum      -> POST /admin/forum/ban/ (user_id + reason + ban_type + days)
 *
 * Lưu ý field thiếu từ API (giữ markup + fallback):
 *   - profile.avatar: AdminUsersView không trả avatar -> luôn hiển thị icon person.
 *   - last_login    : không trả -> hiển thị “Chưa có”.
 */

type RoleKey = 'super_admin' | 'admin' | 'member';
type RoleFilter = 'all' | RoleKey;
type StatusFilter = 'all' | 'active' | 'inactive';

interface AdminUser {
  id: number;
  username: string;
  email: string;
  full_name: string;
  is_staff: boolean;
  is_active: boolean;
  is_superuser: boolean;
  rank_points: number;
  posts_count: number;
  comments_count: number;
  date_joined: string;
  last_login?: string | null;
  avatar?: string | null;
}

interface BanValue {
  reason: string;
  ban_type: string;
  days: number;
}

const PAGE_SIZE = 30;

const ROLE_OPTIONS: SelectOption[] = [
  { value: 'all', label: 'Tất cả vai trò' },
  { value: 'super_admin', label: 'Super Admin' },
  { value: 'admin', label: 'Administrator' },
  { value: 'member', label: 'Member' },
];

const STATUS_OPTIONS: SelectOption[] = [
  { value: 'all', label: 'Tất cả trạng thái' },
  { value: 'active', label: 'Hoạt động' },
  { value: 'inactive', label: 'Vô hiệu hóa' },
];

function roleOf(u: AdminUser): RoleKey {
  if (u.is_superuser) return 'super_admin';
  if (u.is_staff) return 'admin';
  return 'member';
}

export default function Users() {
  const { user } = useAuth();
  const [searchInput, setSearchInput] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [roleFilter, setRoleFilter] = useState<RoleFilter>('all');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [page, setPage] = useState(1);
  const [actingId, setActingId] = useState<number | null>(null);

  /* x-model.debounce.200ms="searchQuery" */
  useEffect(() => {
    const t = setTimeout(() => {
      setSearchQuery(searchInput);
      setPage(1);
    }, 200);
    return () => clearTimeout(t);
  }, [searchInput]);

  /* Tìm kiếm/lọc/phân trang server-side (trước đây lọc client trên 30 user đầu
   * nên tìm user cũ không bao giờ ra). Backend hỗ trợ ?q=&role=&status=&page=. */
  const listPath = useMemo(() => {
    const params = new URLSearchParams({
      page: String(page),
      page_size: String(PAGE_SIZE),
    });
    if (searchQuery.trim()) params.set('q', searchQuery.trim());
    if (roleFilter === 'admin') params.set('role', 'staff');
    else if (roleFilter === 'super_admin') params.set('role', 'super');
    else if (roleFilter === 'member') params.set('role', 'user');
    if (statusFilter === 'active') params.set('status', 'active');
    else if (statusFilter === 'inactive') params.set('status', 'inactive');
    return `/admin/users/?${params.toString()}`;
  }, [page, searchQuery, roleFilter, statusFilter]);

  const { data, refetch } = useAdminGet<{ count: number; results: AdminUser[] }>(listPath);
  const users = useMemo(() => data?.results ?? [], [data]);
  const total = data?.count ?? users.length;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const pageUsers = users;

  const toggleRole = async (u: AdminUser) => {
    setActingId(u.id);
    try {
      const res = await api.post<{ status: string; message: string }>(`/admin/users/${u.id}/action/`, {
        action: 'toggle_staff',
      });
      showToast(res.message || 'Thành công', 'success');
      refetch();
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Thao tác thất bại', 'error');
    } finally {
      setActingId(null);
    }
  };

  const runUserAction = async (u: AdminUser, action: 'toggle_active' | 'reset_rank') => {
    const labelMap: Record<string, string> = {
      toggle_active: 'thay đổi trạng thái tài khoản',
      reset_rank: 'reset điểm uy tín',
    };
    const ok = await scConfirm(`Tài khoản: ${u.username}`, {
      title: `Xác nhận ${labelMap[action] || 'thao tác'}?`,
      icon: 'question',
      confirmButtonText: 'Xác nhận',
      cancelButtonText: 'Hủy',
    });
    if (!ok) return;

    setActingId(u.id);
    try {
      const res = await api.post<{ status: string; message: string }>(`/admin/users/${u.id}/action/`, { action });
      showToast(res.message || 'Thành công', 'success');
      refetch();
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Thao tác thất bại', 'error');
    } finally {
      setActingId(null);
    }
  };

  const banUser = async (u: AdminUser) => {
    const result = await Swal.fire({
      title: escapeHtml(`Cấm ${u.username} khỏi diễn đàn?`),
      html: `
        <div class="space-y-3 text-left mt-4">
          <div>
            <label class="text-[10px] text-white/55 font-bold uppercase block mb-1">Lý do</label>
            <textarea id="ban-reason" class="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2 text-white text-sm min-h-[60px]" placeholder="Vi phạm nội quy..."></textarea>
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="text-[10px] text-white/55 font-bold uppercase block mb-1">Loại</label>
              <select id="ban-type" class="liquid-select-native w-full bg-white/5 border border-white/10 rounded-xl px-3 py-2 text-white text-sm appearance-none">
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
      confirmButtonText: '<i class="bi bi-slash-circle mr-1"></i> Cấm',
      background: 'var(--sc-night-2)',
      color: 'var(--sc-white)',
      preConfirm: (): BanValue => ({
        reason: (document.getElementById('ban-reason') as HTMLTextAreaElement | null)?.value || 'Vi phạm nội quy diễn đàn',
        ban_type: (document.getElementById('ban-type') as HTMLSelectElement | null)?.value || 'temporary',
        days: parseInt((document.getElementById('ban-days') as HTMLInputElement | null)?.value || '7', 10) || 7,
      }),
    });

    if (!result.isConfirmed) return;
    const value = result.value as BanValue;

    try {
      const res = await api.post<{ status?: string; message?: string; error?: string }>('/admin/forum/ban/', {
        action: 'ban',
        user_id: u.id,
        ...value,
      });
      if (res.status === 'ok') {
        showToast(res.message || 'Đã cấm người dùng', 'success');
      } else {
        showToast(res.error || 'Lỗi khi cấm người dùng', 'error');
      }
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Lỗi kết nối', 'error');
    }
  };

  return (
    <AdminShell
      title="Người Dùng & Phân Quyền"
      subtitle="Quản lý tài khoản, cấp quyền Admin, khóa tài khoản và xử lý vi phạm"
    >
      <div className="mb-6 p-4 rounded-2xl bg-slate-900/90 border border-white/10 backdrop-blur-xl relative z-[220] shadow-lg">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <input
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            type="text"
            placeholder="Tìm theo username hoặc email..."
            className="w-full bg-slate-950/80 border border-white/15 rounded-xl px-4 py-2.5 text-xs text-white placeholder-slate-400 focus:outline-none focus:border-brand-400 focus:ring-2 focus:ring-brand-500/20 transition-all font-medium"
          />
          <LiquidSelect
            value={roleFilter}
            options={ROLE_OPTIONS}
            onChange={(v) => {
              setRoleFilter(v as RoleFilter);
              setPage(1);
            }}
            placeholder="Tất cả vai trò"
          />
          <LiquidSelect
            value={statusFilter}
            options={STATUS_OPTIONS}
            onChange={(v) => {
              setStatusFilter(v as StatusFilter);
              setPage(1);
            }}
            placeholder="Tất cả trạng thái"
          />
        </div>
      </div>

      <div className="p-1 rounded-3xl bg-slate-900/90 border border-white/10 backdrop-blur-xl overflow-hidden shadow-2xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-separate border-spacing-0">
            <thead>
              <tr className="bg-white/[0.03]">
                <th className="px-6 py-4 text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-white/10">Người dùng</th>
                <th className="px-6 py-4 text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-white/10 whitespace-nowrap">Vai trò</th>
                <th className="px-6 py-4 text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-white/10">Điểm Uy tín</th>
                <th className="px-6 py-4 text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-white/10 whitespace-nowrap">Trạng thái</th>
                <th className="px-6 py-4 text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-white/10 text-right">Hành động</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {data && pageUsers.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-8 py-16 text-center text-slate-400 font-bold tracking-wider text-xs">
                    <i className="bi bi-people text-3xl block mb-2 text-slate-500"></i>
                    Không tìm thấy người dùng nào phù hợp với bộ lọc.
                  </td>
                </tr>
              )}
              {pageUsers.map((u) => {
                const role = roleOf(u);
                const isSelf = user?.username === u.username;
                return (
                  <tr
                    key={u.id}
                    className="hover:bg-white/[0.04] transition-all duration-200"
                  >
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3.5">
                        <div className="w-11 h-11 rounded-xl bg-slate-800 border border-white/15 flex items-center justify-center text-slate-300 overflow-hidden relative group/avatar shrink-0">
                          {u.avatar ? (
                            // eslint-disable-next-line @next/next/no-img-element
                            <img
                              src={mediaUrl(u.avatar)}
                              alt={u.username}
                              className="w-full h-full object-cover group-hover/avatar:scale-110 transition-transform duration-500"
                            />
                          ) : (
                            <i className="bi bi-person-fill text-xl"></i>
                          )}
                        </div>
                        <div className="flex flex-col">
                          <span className="text-sm font-black text-white tracking-tight">{u.username}</span>
                          <span className="text-xs text-slate-400 font-medium">{u.email}</span>
                          <span className="text-[11px] text-slate-400 mt-0.5">
                            Tham gia: {u.date_joined} · Bài viết: {u.posts_count} · Bình luận: {u.comments_count}
                          </span>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {role === 'super_admin' ? (
                        <span className="px-2.5 py-1 rounded-lg bg-danger-500/15 text-danger-400 text-[10px] font-black uppercase border border-danger-500/30 tracking-wider">Super Admin</span>
                      ) : role === 'admin' ? (
                        <span className="px-2.5 py-1 rounded-lg bg-brand-500/15 text-brand-300 text-[10px] font-black uppercase border border-brand-500/30 tracking-wider">Administrator</span>
                      ) : (
                        <span className="px-2.5 py-1 rounded-lg bg-slate-800 text-slate-300 text-[10px] font-bold uppercase border border-white/10 tracking-wider">Member</span>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <span className="text-sm font-black text-white">{u.rank_points}</span>
                        <i className="bi bi-star-fill text-xs text-warn-400"></i>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {u.is_active ? (
                        <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-safe-500/10 border border-safe-500/20 text-safe-400">
                          <div className="w-1.5 h-1.5 rounded-full bg-safe-400 shadow-[0_0_6px_rgba(34,197,94,0.6)]"></div>
                          <span className="text-[10px] font-bold uppercase tracking-wider">Hoạt động</span>
                        </div>
                      ) : (
                        <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-white/5 border border-white/10 text-slate-400">
                          <div className="w-1.5 h-1.5 rounded-full bg-slate-400"></div>
                          <span className="text-[10px] font-bold uppercase tracking-wider">Vô hiệu hóa</span>
                        </div>
                      )}
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex justify-end gap-1.5 flex-wrap max-w-[420px] ml-auto">
                        <button
                          type="button"
                          disabled={actingId === u.id}
                          onClick={() => void toggleRole(u)}
                          className="h-8 px-3 rounded-lg bg-white/10 text-slate-200 text-[10px] font-bold uppercase tracking-wider border border-white/15 hover:border-brand-400 hover:text-brand-300 hover:bg-brand-500/10 transition-all flex items-center justify-center disabled:opacity-50"
                        >
                          {u.is_staff ? 'Gỡ Quyền' : 'Cấp Quyền'}
                        </button>
                        {!isSelf && (
                          <>
                            <button
                              type="button"
                              disabled={actingId === u.id}
                              onClick={() => void runUserAction(u, 'toggle_active')}
                              className="h-8 px-3 rounded-lg bg-white/10 text-slate-200 text-[10px] font-bold uppercase tracking-wider border border-white/15 hover:border-warn-400 hover:text-warn-300 hover:bg-warn-500/10 transition-all flex items-center justify-center disabled:opacity-50"
                            >
                              {u.is_active ? 'Khóa TK' : 'Mở TK'}
                            </button>
                            <button
                              type="button"
                              disabled={actingId === u.id}
                              onClick={() => void runUserAction(u, 'reset_rank')}
                              className="h-8 px-3 rounded-lg bg-white/10 text-slate-200 text-[10px] font-bold uppercase tracking-wider border border-white/15 hover:border-warn-400 hover:text-warn-300 hover:bg-warn-500/10 transition-all flex items-center justify-center disabled:opacity-50"
                              title="Reset điểm uy tín về 0"
                            >
                              Reset điểm
                            </button>
                          </>
                        )}
                        {!u.is_staff && (
                          <button
                            type="button"
                            onClick={() => void banUser(u)}
                            className="h-8 px-3 rounded-lg bg-danger-500/15 text-danger-300 text-[10px] font-bold uppercase tracking-wider border border-danger-500/30 hover:bg-danger-500 hover:text-white transition-all flex items-center justify-center gap-1"
                            title="Cấm khỏi diễn đàn"
                          >
                            <i className="bi bi-slash-circle"></i> Cấm Forum
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {totalPages > 1 && (
        <div className="mt-6 flex flex-col sm:flex-row items-center justify-between gap-3 px-2">
          <p className="text-xs text-slate-400 font-bold uppercase tracking-wider">
            Trang {page}/{totalPages} · Tổng {total} người dùng
          </p>
          <div className="flex items-center gap-2">
            <button
              disabled={page <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className="px-4 py-2 rounded-xl bg-slate-900 border border-white/10 text-xs font-bold text-slate-300 hover:text-white disabled:opacity-30 transition-all"
            >
              ← Trước
            </button>
            <span className="text-xs font-bold text-white px-2">{page}</span>
            <button
              disabled={page >= totalPages}
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              className="px-4 py-2 rounded-xl bg-slate-900 border border-white/10 text-xs font-bold text-slate-300 hover:text-white disabled:opacity-30 transition-all"
            >
              Sau →
            </button>
          </div>
        </div>
      )}
    </AdminShell>
  );
}
