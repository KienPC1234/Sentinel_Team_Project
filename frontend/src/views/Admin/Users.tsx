'use client';
import { useEffect, useMemo, useState } from 'react';
import Swal from 'sweetalert2';
import { api, mediaUrl } from '../../lib/api';
import { escapeHtml } from '../../lib/chat/markdown';
import { showToast, scConfirm } from '../../lib/ui/feedback';
import { AdminPageHeader, LiquidSelect } from '../../components/ui';
import type { SelectOption } from '../../components/ui';
import { useAuth } from '../../components/AuthContext';
import { useAdminGet } from './_shared';

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

  const { data, refetch } = useAdminGet<{ count: number; results: AdminUser[] }>('/admin/users/');
  const users = useMemo(() => data?.results ?? [], [data]);
  const total = data?.count ?? users.length;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const pageUsers = users.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const rowVisible = (u: AdminUser): boolean => {
    const key = (searchQuery || '').trim().toLowerCase();
    const text = `${u.username} ${u.email}`.toLowerCase();
    const role = roleOf(u);
    const statusKey = u.is_active ? 'active' : 'inactive';
    return (
      (roleFilter === 'all' || role === roleFilter) &&
      (statusFilter === 'all' || statusKey === statusFilter) &&
      (!key || text.includes(key))
    );
  };

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
    <div className="container mx-auto px-4 py-10 mt-16 max-w-6xl">
      <AdminPageHeader title="Người dùng & Phân quyền" subtitle="Quản lý tài khoản và quyền hạn hệ thống" />

      <div className="mb-6 p-4 rounded-2xl bg-white/[0.02] border border-white/10 backdrop-blur-xl relative z-[220]">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <input
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            type="text"
            placeholder="Tìm username / email..."
            className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-xs text-white placeholder-white/25 focus:outline-none focus:border-brand-500/30 transition-all"
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

      <div className="p-1 rounded-[3rem] bg-slate-900/40 border border-white/5 backdrop-blur-xl overflow-hidden shadow-2xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-separate border-spacing-0">
            <thead>
              <tr className="bg-white/[0.02]">
                <th className="px-8 py-6 text-[10px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Người dùng</th>
                <th className="px-8 py-6 text-[10px] font-black text-white/55 uppercase tracking-widest border-b border-white/5 whitespace-nowrap">Vai trò</th>
                <th className="px-8 py-6 text-[10px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Điểm Uy tín</th>
                <th className="px-8 py-6 text-[10px] font-black text-white/55 uppercase tracking-widest border-b border-white/5 whitespace-nowrap">Trạng thái</th>
                <th className="px-8 py-6 text-[10px] font-black text-white/55 uppercase tracking-widest border-b border-white/5 text-right">Hành động</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.02]">
              {data && pageUsers.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-8 py-20 text-center text-white/35 font-bold tracking-widest uppercase text-xs italic">
                    No participants found in the system grid.
                  </td>
                </tr>
              )}
              {pageUsers.map((u) => {
                const role = roleOf(u);
                const isSelf = user?.username === u.username;
                return (
                  <tr
                    key={u.id}
                    className="group hover:bg-white/[0.03] transition-all duration-300"
                    style={{ display: rowVisible(u) ? undefined : 'none' }}
                  >
                    <td className="px-8 py-7">
                      <div className="flex items-center gap-4">
                        <div className="w-12 h-12 rounded-[1.25rem] bg-white/5 border border-white/10 flex items-center justify-center text-white/35 overflow-hidden relative group/avatar">
                          {u.avatar ? (
                            // eslint-disable-next-line @next/next/no-img-element
                            <img
                              src={mediaUrl(u.avatar)}
                              alt={u.username}
                              className="w-full h-full object-cover group-hover/avatar:scale-110 transition-transform duration-700"
                            />
                          ) : (
                            <i className="bi bi-person-fill text-2xl"></i>
                          )}
                          <div className="absolute inset-0 bg-brand-500/20 opacity-0 group-hover/avatar:opacity-100 transition-opacity"></div>
                        </div>
                        <div className="flex flex-col">
                          <span className="text-sm font-black text-white tracking-tight">{u.username}</span>
                          <span className="text-[10px] font-bold text-white/45">{u.email}</span>
                          <span className="text-[10px] text-white/35 mt-1">
                            Tham gia: {u.date_joined} · Bài viết: {u.posts_count} · Bình luận: {u.comments_count}
                          </span>
                          <span className="text-[10px] text-white/35 mt-1">
                            Đăng nhập gần nhất: {u.last_login || 'Chưa có'}
                          </span>
                        </div>
                      </div>
                    </td>
                    <td className="px-8 py-7 whitespace-nowrap">
                      {role === 'super_admin' ? (
                        <span className="px-3 py-1 rounded-lg bg-danger-500/10 text-danger-500 text-[9px] font-black uppercase border border-danger-500/20 tracking-widest">Super Admin</span>
                      ) : role === 'admin' ? (
                        <span className="px-3 py-1 rounded-lg bg-brand-500/10 text-brand-400 text-[9px] font-black uppercase border border-brand-500/20 tracking-widest">Administrator</span>
                      ) : (
                        <span className="px-3 py-1 rounded-lg bg-white/5 text-white/45 text-[9px] font-black uppercase border border-white/10 tracking-widest">Member</span>
                      )}
                    </td>
                    <td className="px-8 py-7 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-black text-white/80">{u.rank_points}</span>
                        <i className="bi bi-star-fill text-[10px] text-warn-500/50"></i>
                      </div>
                    </td>
                    <td className="px-8 py-7">
                      {u.is_active ? (
                        <div className="flex items-center gap-2 text-safe-500">
                          <div className="w-2 h-2 rounded-full bg-safe-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]"></div>
                          <span className="text-[10px] font-black uppercase tracking-widest">Hoạt động</span>
                        </div>
                      ) : (
                        <div className="flex items-center gap-2 text-white/35">
                          <div className="w-2 h-2 rounded-full bg-white/10"></div>
                          <span className="text-[10px] font-black uppercase tracking-widest italic">Vô hiệu hóa</span>
                        </div>
                      )}
                    </td>
                    <td className="px-8 py-7">
                      <div className="flex justify-end gap-2 opacity-0 group-hover:opacity-100 transition-all translate-x-4 group-hover:translate-x-0 flex-wrap max-w-[430px] ml-auto">
                        <button
                          type="button"
                          disabled={actingId === u.id}
                          onClick={() => void toggleRole(u)}
                          className="h-9 px-4 rounded-xl bg-white/5 text-white/60 text-[10px] font-black uppercase tracking-widest border border-white/10 hover:border-brand-500/30 hover:text-brand-400 hover:bg-brand-500/5 transition-all flex items-center justify-center"
                        >
                          {u.is_staff ? 'Gỡ Quyền' : 'Cấp Quyền'}
                        </button>
                        {!isSelf && (
                          <>
                            <button
                              type="button"
                              disabled={actingId === u.id}
                              onClick={() => void runUserAction(u, 'toggle_active')}
                              className="h-9 px-3 rounded-xl bg-white/5 text-white/60 text-[10px] font-black uppercase tracking-widest border border-white/10 hover:border-warn-500/30 hover:text-warn-300 hover:bg-warn-500/5 transition-all flex items-center justify-center"
                            >
                              {u.is_active ? 'Khóa TK' : 'Mở TK'}
                            </button>
                            <button
                              type="button"
                              disabled={actingId === u.id}
                              onClick={() => void runUserAction(u, 'reset_rank')}
                              className="h-9 px-3 rounded-xl bg-white/5 text-white/60 text-[10px] font-black uppercase tracking-widest border border-white/10 hover:border-warn-500/30 hover:text-warn-300 hover:bg-warn-500/5 transition-all flex items-center justify-center"
                            >
                              Reset điểm
                            </button>
                          </>
                        )}
                        {!u.is_staff && (
                          <button
                            type="button"
                            onClick={() => void banUser(u)}
                            className="h-9 px-4 rounded-xl bg-danger-500/10 text-danger-500 text-[10px] font-black uppercase tracking-widest border border-danger-500/20 hover:bg-danger-500 hover:text-white transition-all flex items-center justify-center gap-1.5"
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
        <div className="mt-6 flex items-center justify-between gap-3 px-2">
          <p className="text-[10px] text-white/45 font-bold uppercase tracking-widest">
            Trang {page}/{totalPages} · Tổng {total} người dùng
          </p>
          <div className="flex items-center gap-2">
            {page > 1 && (
              <button
                type="button"
                onClick={() => setPage(page - 1)}
                className="px-3 py-2 rounded-xl bg-white/5 border border-white/10 text-white/60 hover:text-brand-400 hover:border-brand-500/30 text-xs font-bold"
              >
                Trước
              </button>
            )}
            {page < totalPages && (
              <button
                type="button"
                onClick={() => setPage(page + 1)}
                className="px-3 py-2 rounded-xl bg-white/5 border border-white/10 text-white/60 hover:text-brand-400 hover:border-brand-500/30 text-xs font-bold"
              >
                Sau
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
