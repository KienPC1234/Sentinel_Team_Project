'use client';
import { useEffect, useRef, useState } from 'react';
import type { ChangeEvent, FormEvent } from 'react';
import Link from 'next/link';
import { api, ApiError, mediaUrl } from '../../lib/api';



import { Spinner } from '../../components/ui';
import { sanitizeHtml } from '../../lib/chat/markdown';
import RichEditor, { getEditorData } from '../../components/RichEditor';
import { showToast } from '../../lib/ui/feedback';
import { fmtDate } from '../../lib/date';

/* Types khớp UserSerializer + MeView (api/core/serializers.py, views/auth_views.py). */
interface RankInfo {
  name?: string;
  level?: string;
  color?: string;
  icon?: string;
}

interface ProfileUser {
  id?: number;
  username: string;
  email?: string;
  first_name?: string;
  last_name?: string;
  display_name?: string;
  gender?: string;
  gender_label?: string;
  avatar?: string | null;
  about?: string | null;
  bio?: string | null;
  messenger_link?: string;
  date_joined?: string;
  is_staff?: boolean;
  rank_info?: RankInfo | null;
  rank_points?: number;
  accolade_title?: string;
  accolade_description?: string;
}

interface MeStats {
  total_scans?: number;
  total_reports?: number;
  saved_alerts?: number;
  total_posts?: number;
}

interface MeResp {
  user: ProfileUser;
  stats?: MeStats;
}

interface MfaStatus {
  has_2fa: boolean;
  preferred_method?: string | null;
  methods?: { totp?: boolean; email?: boolean };
  recovery_codes?: { total?: number; remaining?: number };
}

function errMsg(e: unknown, fallback: string): string {
  if (e instanceof ApiError) {
    const d = e.data as { error?: string; message?: string; details?: Record<string, unknown> } | null;
    let msg = (d && (d.error || d.message)) || e.message || fallback;
    if (d?.details && typeof d.details === 'object') {
      const extra = Object.entries(d.details)
        .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : String(v)}`)
        .join('\n');
      if (extra) msg += '\n' + extra;
    }
    return msg;
  }
  if (e instanceof Error) return e.message || fallback;
  return fallback;
}

function toast(msg: string): void {
  showToast(msg, 'info');
}

function toastOk(msg: string): void {
  showToast(msg, 'success');
}

function toastErr(msg: string): void {
  showToast(msg, 'error');
}

const GENDERS: Array<{ value: string; label: string }> = [
  { value: 'male', label: 'Nam' },
  { value: 'female', label: 'Nữ' },
  { value: 'prefer_not_to_say', label: 'Tôi không muốn tiết lộ' },
  { value: 'non_binary', label: 'Phi nhị nguyên giới (Non-binary)' },
  { value: 'transgender', label: 'Người chuyển giới (Transgender)' },
  { value: 'gender_fluid', label: 'Linh hoạt giới (Genderfluid)' },
  { value: 'bigender', label: 'Song giới (Bigender)' },
  { value: 'genderqueer', label: 'Giới phi chuẩn (Genderqueer)' },
  { value: 'agender', label: 'Vô giới (Agender)' },
  { value: 'intersex', label: 'Liên giới tính (Intersex)' },
  { value: 'other', label: 'Khác' },
];

/* Port từ PKV/templates/Auth/profile.html (1148 dòng). about dùng CKEditor y bản gốc. */
export default function Profile() {
  const [user, setUser] = useState<ProfileUser | null>(null);
  const [stats, setStats] = useState<MeStats>({});
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const aboutEditorRef = useRef<unknown | null>(null);
  const [form, setForm] = useState({
    display_name: '',
    gender: '',
    first_name: '',
    last_name: '',
    bio: '',
    about: '',
    messenger_link: '',
  });

  useEffect(() => {
    let alive = true;
    api
      .get<MeResp>('/auth/me/')
      .then((d) => {
        if (!alive) return;
        setUser(d.user);
        setStats(d.stats || {});
        setForm({
          display_name: d.user.display_name || '',
          gender: d.user.gender || '',
          first_name: d.user.first_name || '',
          last_name: d.user.last_name || '',
          bio: (d.user.bio as string) || '',
          about: (d.user.about as string) || '',
          messenger_link: d.user.messenger_link || '',
        });
      })
      .catch((e: unknown) => {
        if (!alive) return;
        toastErr(errMsg(e, 'Không tải được hồ sơ. Vui lòng đăng nhập lại.'));
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, []);

  function applyUser(u: ProfileUser): void {
    setUser((prev) => ({ ...(prev as ProfileUser), ...u }));
  }

  async function uploadAvatar(e: ChangeEvent<HTMLInputElement>): Promise<void> {
    const file = e.target.files?.[0];
    if (!file) return;
    const fd = new FormData();
    fd.append('avatar', file);
    try {
      const d = await api.upload<MeResp>('/auth/me/', fd);
      applyUser(d.user);
      toastOk('Đã cập nhật ảnh đại diện');
    } catch (err) {
      toastErr(errMsg(err, 'Lỗi upload ảnh'));
    }
  }

  function copyPublicLink(): void {
    if (!user) return;
    const url = `${window.location.origin}/profile/@${user.username}/`;
    void navigator.clipboard.writeText(url).then(() => toastOk('Đã sao chép liên kết hồ sơ công khai!'));
  }

  async function saveProfile(): Promise<void> {
    const norm = (form.messenger_link || '').trim();
    const messenger_link = ['none', 'null', 'undefined', 'nan', 'false', '0'].includes(norm.toLowerCase())
      ? ''
      : norm;
    setSaving(true);
    const aboutHtml = getEditorData(aboutEditorRef.current);
    try {
      const d = await api.patch<MeResp>('/auth/me/', {
        first_name: form.first_name,
        last_name: form.last_name,
        display_name: form.display_name,
        gender: form.gender,
        bio: form.bio,
        about: aboutHtml,
        messenger_link,
      });
      applyUser(d.user);
      setForm((f) => ({ ...f, about: (d.user.about as string) || aboutHtml }));
      setEditing(false);
      toastOk('Đã lưu thông tin hồ sơ');
    } catch (err) {
      toastErr(errMsg(err, 'Lỗi cập nhật'));
    } finally {
      setSaving(false);
    }
  }

  if (loading) return <Spinner />;
  if (!user) return <div className="liquid-card p-8 text-center text-white/55 text-sm">Không tải được hồ sơ.</div>;

  const disabledCls = !editing ? 'opacity-50 cursor-not-allowed' : '';
  const initial = ((user.display_name || user.first_name || user.username || '?') as string)
    .charAt(0)
    .toUpperCase();

  return (
    <div className="animate-fadein max-w-2xl mx-auto space-y-10 pt-12 sm:pt-16 pb-20 px-4">
      <div className="space-y-2">
        <h1 className="text-4xl font-black text-white tracking-tight leading-none">
          <span className="glow-text">Hồ sơ cá nhân</span>
        </h1>
        <p className="text-white/55 text-sm font-medium tracking-wide prose-sm">
          Quản lý và bảo mật thông tin định danh của bạn.
        </p>
      </div>

      <div className="liquid-card rounded-3xl p-8 sm:p-10 space-y-8 shadow-2xl">
        <div className="flex flex-col sm:flex-row items-center gap-8 text-center sm:text-left">
          <div className="relative group">
            <label className="cursor-pointer block">
              {user.avatar ? (
                <img
                  src={mediaUrl(user.avatar)}
                  alt={user.username}
                  className="w-24 h-24 rounded-3xl object-cover shadow-2xl shadow-brand-500/20 ring-4 ring-white/5 group-hover:scale-105 transition-transform"
                />
              ) : (
                <div className="w-24 h-24 rounded-3xl bg-gradient-to-br from-brand-400 to-brand2-500 flex items-center justify-center text-3xl font-black text-white shadow-2xl shadow-brand-500/20 ring-4 ring-white/5 group-hover:scale-105 transition-transform">
                  <span>{initial}</span>
                </div>
              )}
              <div className="absolute inset-0 bg-black/40 rounded-3xl opacity-0 group-hover:opacity-100 flex items-center justify-center transition-opacity">
                <i className="bi bi-camera-fill text-white text-xl"></i>
              </div>
              <input type="file" className="hidden" accept="image/*" onChange={uploadAvatar} />
            </label>
            <div className="absolute -bottom-1 -right-1 w-8 h-8 rounded-xl bg-slate-900 border-2 border-white/10 flex items-center justify-center text-brand-400 shadow-xl">
              <i className="bi bi-patch-check-fill text-sm"></i>
            </div>
          </div>
          <div className="space-y-1">
            <div className="flex items-center gap-3 justify-center sm:justify-start">
              <h2 className="text-2xl font-black text-white/90">{user.display_name || user.username}</h2>
              {user.rank_info?.name && (
                <div
                  className={`px-2 py-0.5 rounded-lg bg-white/5 border border-white/10 text-[9px] font-black uppercase tracking-widest flex items-center gap-1.5 ${user.rank_info.color || ''}`}
                >
                  <i className={`bi ${user.rank_info.icon || 'bi-star-fill'}`}></i>
                  <span>{user.rank_info.name}</span>
                </div>
              )}
            </div>

            {user.gender_label && (
              <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-lg bg-brand2-500/10 border border-brand2-500/20 text-[9px] font-bold text-brand2-400 uppercase tracking-wider mb-2">
                <i className="bi bi-gender-ambiguous"></i>
                <span>{user.gender_label}</span>
              </div>
            )}

            <p className="text-brand-400/80 font-bold tracking-[0.2em] text-[10px]">@{user.username}</p>
            <div className="inline-flex flex-wrap items-center gap-2 mt-2 justify-center sm:justify-start">
              <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-white/5 border border-white/10 text-[10px] text-white/55 font-black uppercase tracking-widest">
                <i className="bi bi-calendar3"></i> Đã tham gia: {fmtDate(user.date_joined)}
              </div>
              <button
                type="button"
                onClick={copyPublicLink}
                className="flex items-center gap-2 px-3 py-1 rounded-full bg-brand-400/10 border border-brand-400/20 text-[10px] text-brand-400 font-black uppercase tracking-widest hover:bg-brand-400/20 transition-all"
              >
                <i className="bi bi-share"></i> Chia sẻ hồ sơ công khai
              </button>
            </div>
          </div>
        </div>

        {user.accolade_title && (
          <div className="p-6 rounded-3xl bg-gradient-to-r from-brand2-500/10 to-brand2-500/10 border border-brand2-500/20 animate-pulse-subtle">
            <div className="flex items-start gap-4">
              <div className="w-12 h-12 rounded-2xl bg-brand2-500/20 flex items-center justify-center text-brand2-400 text-xl shadow-lg shadow-brand2-500/20">
                <i className="bi bi-patch-check-fill"></i>
              </div>
              <div className="space-y-1">
                <h4 className="text-sm font-black text-brand2-300 uppercase tracking-widest">{user.accolade_title}</h4>
                <p className="text-xs text-white/60 font-medium leading-relaxed">{user.accolade_description}</p>
              </div>
            </div>
          </div>
        )}

        <div className="grid grid-cols-3 gap-4">
          <div className="p-4 rounded-3xl bg-white/[0.03] border border-white/5 text-center group hover:bg-white/[0.05] transition-all">
            <div className="text-[10px] font-black text-brand-400/60 uppercase tracking-widest mb-1">Scans</div>
            <div className="text-2xl font-black text-white">{stats.total_scans ?? 0}</div>
          </div>
          <div className="p-4 rounded-3xl bg-white/[0.03] border border-white/5 text-center group hover:bg-white/[0.05] transition-all">
            <div className="text-[10px] font-black text-warn-400/60 uppercase tracking-widest mb-1">Reports</div>
            <div className="text-2xl font-black text-white">{stats.total_reports ?? 0}</div>
          </div>
          <div className="p-4 rounded-3xl bg-white/[0.03] border border-white/5 text-center group hover:bg-white/[0.05] transition-all">
            <div className="text-[10px] font-black text-brand2-400/60 uppercase tracking-widest mb-1">Posts</div>
            <div className="text-2xl font-black text-white">{stats.total_posts ?? '—'}</div>
          </div>
        </div>

        <div className="space-y-6 pt-4 border-t border-white/5">
          <div className="space-y-2">
            <label className="text-[11px] font-black text-white/45 uppercase tracking-[0.2em] ml-2">
              Tên hiển thị (Nickname)
            </label>
            <input
              type="text"
              value={form.display_name}
              onChange={(e) => setForm({ ...form, display_name: e.target.value })}
              className={`liquid-input w-full py-4 px-6 text-sm font-bold ${disabledCls}`}
              placeholder="Nhập nickname bạn muốn hiển thị..."
              disabled={!editing}
            />
          </div>

          <div className="space-y-2">
            <label className="text-[11px] font-black text-white/45 uppercase tracking-[0.2em] ml-2">
              Giới tính & Định danh
            </label>
            <select
              value={form.gender}
              onChange={(e) => setForm({ ...form, gender: e.target.value })}
              className={`liquid-input w-full py-4 px-6 text-sm font-bold appearance-none ${disabledCls}`}
              disabled={!editing}
            >
              <option value="" className="bg-slate-900 text-white">
                — Chọn —
              </option>
              {GENDERS.map((g) => (
                <option key={g.value} value={g.value} className="bg-slate-900 text-white">
                  {g.label}
                </option>
              ))}
            </select>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
            <div className="space-y-2">
              <label className="text-[11px] font-black text-white/45 uppercase tracking-[0.2em] ml-2">Họ</label>
              <input
                type="text"
                value={form.first_name}
                onChange={(e) => setForm({ ...form, first_name: e.target.value })}
                className={`liquid-input w-full py-4 px-6 text-sm font-bold ${disabledCls}`}
                disabled={!editing}
              />
            </div>
            <div className="space-y-2">
              <label className="text-[11px] font-black text-white/45 uppercase tracking-[0.2em] ml-2">Tên</label>
              <input
                type="text"
                value={form.last_name}
                onChange={(e) => setForm({ ...form, last_name: e.target.value })}
                className={`liquid-input w-full py-4 px-6 text-sm font-bold ${disabledCls}`}
                disabled={!editing}
              />
            </div>
          </div>

          <div className="space-y-2">
            <label className="text-[11px] font-black text-white/45 uppercase tracking-[0.2em] ml-2">
              Tài khoản Email
            </label>
            <div className="relative">
              <input
                type="email"
                className="liquid-input has-icon-right w-full py-4 pl-6 pr-14 text-sm font-bold opacity-30 cursor-not-allowed"
                value={user.email || ''}
                disabled
              />
              <i className="bi bi-lock absolute right-6 top-1/2 -translate-y-1/2 text-white/55 pointer-events-none z-10"></i>
            </div>
            <p className="text-[9px] text-white/35 font-bold uppercase tracking-widest ml-2">
              Đổi email ở mục Bảo mật & Thiết lập bên dưới
            </p>
          </div>

          <div className="space-y-2">
            <label className="text-[11px] font-black text-white/45 uppercase tracking-[0.2em] ml-2">
              Tiểu sử ngắn / Trạng thái
            </label>
            <input
              type="text"
              value={form.bio}
              onChange={(e) => setForm({ ...form, bio: e.target.value })}
              className={`liquid-input w-full py-4 px-6 text-sm font-bold ${disabledCls}`}
              placeholder="Một câu ngắn gọn về bạn..."
              disabled={!editing}
            />
          </div>

          <div className="space-y-2">
            <label className="text-[11px] font-black text-white/45 uppercase tracking-[0.2em] ml-2">
              Liên kết nhắn tin (Messenger/Zalo/Telegram)
            </label>
            <div className="relative">
              <input
                type="url"
                value={form.messenger_link}
                onChange={(e) => setForm({ ...form, messenger_link: e.target.value })}
                className={`liquid-input has-icon-right w-full py-4 pl-6 pr-14 text-sm font-bold ${disabledCls}`}
                placeholder="https://m.me/yourusername..."
                disabled={!editing}
              />
              <i className="bi bi-chat-dots-fill absolute right-6 top-1/2 -translate-y-1/2 text-white/55 pointer-events-none z-10"></i>
            </div>
            <p className="text-[9px] text-white/35 font-bold uppercase tracking-widest ml-2">
              Nếu để trống hoặc nhập &quot;none&quot;, hồ sơ công khai sẽ tự ẩn nút nhắn tin.
            </p>
          </div>

          <div className="space-y-2">
            <label className="text-[11px] font-black text-white/45 uppercase tracking-[0.2em] ml-2">
              Giới thiệu chi tiết (Rich Text)
            </label>
            {editing ? (
              <RichEditor
                key={user?.username || 'about'}
                editorRef={aboutEditorRef}
                initialData={form.about}
                placeholder="Viết gì đó về bản thân bạn..."
                minLines={6}
              />
            ) : (
              <div
                className="ai-markdown liquid-input w-full py-4 px-6 text-sm font-medium opacity-70 min-h-[120px]"
                dangerouslySetInnerHTML={{ __html: sanitizeHtml(form.about || '<span class="text-white/45">Chưa có giới thiệu.</span>') }}
              />
            )}
            {editing && (
              <p className="text-[9px] text-white/35 font-bold uppercase tracking-widest ml-1 mt-2 flex items-center gap-1.5 leading-none">
                <i className="bi bi-magic text-brand-500"></i>
                Soạn thảo văn bản, hỗ trợ HTML cơ bản (thay CKEditor bản gốc).
              </p>
            )}
          </div>

          <div className="flex flex-wrap gap-4 pt-4">
            <button
              type="button"
              className="liquid-btn flex-1 py-4 text-[11px] font-black tracking-widest uppercase bg-white/5 border-white/10 hover:bg-white/10 transition-all"
              onClick={() => setEditing(!editing)}
            >
              {!editing ? (
                <span>
                  <i className="bi bi-pencil-square mr-2"></i> CHỈNH SỬA HỒ SƠ
                </span>
              ) : (
                <span className="text-danger-400">
                  <i className="bi bi-x-circle mr-2"></i> HỦY THAY ĐỔI
                </span>
              )}
            </button>
            {editing && (
              <button
                type="button"
                onClick={saveProfile}
                className="liquid-btn flex-1 py-4 text-[11px] font-black tracking-widest uppercase bg-brand-500 text-black shadow-lg shadow-brand-500/20 hover:bg-brand-400"
                disabled={saving}
              >
                {!saving ? (
                  <span>
                    <i className="bi bi-check2-circle mr-2"></i> LƯU THÔNG TIN
                  </span>
                ) : (
                  <span className="spinner w-4 h-4 border-black"></span>
                )}
              </button>
            )}
          </div>
        </div>
      </div>

      <div className="liquid-card overflow-hidden">
        <div className="p-6 bg-white/[0.02] border-b border-white/5">
          <h3 className="text-xs font-black text-white uppercase tracking-widest flex items-center gap-2">
            <i className="bi bi-shield-lock text-brand-400"></i>
            Bảo mật & Thiết lập
          </h3>
        </div>
        <div className="divide-y divide-white/5">
          <UsernameRow
            current={user.username}
            onDone={(u) => {
              applyUser({ ...user, username: u });
              toastOk('Đã cập nhật username thành công');
            }}
          />
          <EmailChangeRow
            current={user.email || ''}
            onDone={(em) => {
              applyUser({ ...user, email: em });
              toastOk('Đổi email thành công.');
            }}
          />
          <Link
            href="/change-password/"
            className="flex items-center justify-between p-6 hover:bg-white/[0.04] transition-all group"
          >
            <div className="flex items-center gap-4">
              <div className="w-10 h-10 rounded-xl bg-danger-500/10 flex items-center justify-center text-danger-500 group-hover:scale-110 transition-transform">
                <i className="bi bi-key-fill"></i>
              </div>
              <div>
                <div className="text-sm font-black text-white uppercase tracking-wide">Đổi mật khẩu</div>
                <p className="text-[10px] text-white/45 font-bold uppercase tracking-widest mt-1">
                  Mở trang đổi mật khẩu bảo mật
                </p>
              </div>
            </div>
            <i className="bi bi-chevron-right text-white/35 transition-transform group-hover:translate-x-1"></i>
          </Link>
          <MfaRow />
          <DeleteAccountRow />
          <Link
            href="/dashboard/"
            className="flex items-center justify-between p-6 hover:bg-white/[0.04] transition-all group"
          >
            <div className="flex items-center gap-4">
              <div className="w-10 h-10 rounded-xl bg-brand-500/10 flex items-center justify-center text-brand-400 group-hover:scale-110 transition-transform">
                <i className="bi bi-activity"></i>
              </div>
              <div>
                <div className="text-sm font-black text-white uppercase tracking-wide">Trung tâm điều khiển</div>
                <p className="text-[10px] text-white/45 font-bold uppercase tracking-widest mt-1">
                  Xem chi tiết hoạt động scan và report
                </p>
              </div>
            </div>
            <i className="bi bi-chevron-right text-white/35 transition-transform group-hover:translate-x-1"></i>
          </Link>
          <Link
            href="/profile/inbox/"
            className="flex items-center justify-between p-6 hover:bg-white/[0.04] transition-all group"
          >
            <div className="flex items-center gap-4">
              <div className="w-10 h-10 rounded-xl bg-brand-500/10 flex items-center justify-center text-brand-400 group-hover:scale-110 transition-transform">
                <i className="bi bi-envelope-fill"></i>
              </div>
              <div>
                <div className="text-sm font-black text-white uppercase tracking-wide">Hộp thư</div>
                <p className="text-[10px] text-white/45 font-bold uppercase tracking-widest mt-1">
                  Quản lý thông báo của bạn
                </p>
              </div>
            </div>
            <i className="bi bi-chevron-right text-white/35 transition-transform group-hover:translate-x-1"></i>
          </Link>
          <Link
            href="/profile/tickets/"
            className="flex items-center justify-between p-6 hover:bg-white/[0.04] transition-all group"
          >
            <div className="flex items-center gap-4">
              <div className="w-10 h-10 rounded-xl bg-warn-500/10 flex items-center justify-center text-warn-400 group-hover:scale-110 transition-transform">
                <i className="bi bi-bug-fill"></i>
              </div>
              <div>
                <div className="text-sm font-black text-white uppercase tracking-wide">Báo lỗi & Phản hồi</div>
                <p className="text-[10px] text-white/45 font-bold uppercase tracking-widest mt-1">
                  Gửi báo cáo lỗi hoặc góp ý cho quản trị viên
                </p>
              </div>
            </div>
            <i className="bi bi-chevron-right text-white/35 transition-transform group-hover:translate-x-1"></i>
          </Link>
          <Link
            href="/scam-iq-exam/"
            className="flex items-center justify-between p-6 hover:bg-white/[0.04] transition-all group"
          >
            <div className="flex items-center gap-4">
              <div className="w-10 h-10 rounded-xl bg-brand2-500/10 flex items-center justify-center text-brand2-300 group-hover:scale-110 transition-transform">
                <i className="bi bi-patch-question-fill"></i>
              </div>
              <div>
                <div className="text-sm font-black text-white uppercase tracking-wide">Scam IQ Exam</div>
                <p className="text-[10px] text-white/45 font-bold uppercase tracking-widest mt-1">
                  30 câu từ dễ đến cực khó • tối đa 300 điểm
                </p>
              </div>
            </div>
            <i className="bi bi-chevron-right text-white/35 transition-transform group-hover:translate-x-1"></i>
          </Link>

        </div>
      </div>
    </div>
  );
}

function UsernameRow({ current, onDone }: { current: string; onDone: (u: string) => void }) {
  const [val, setVal] = useState(current);
  const [loading, setLoading] = useState(false);

  useEffect(() => setVal(current), [current]);

  async function submit(): Promise<void> {
    const candidate = val.trim();
    if (!candidate) return toastErr('Username không được để trống.');
    if (candidate.length < 3) return toastErr('Username phải có ít nhất 3 ký tự.');
    if (candidate === current) return;
    setLoading(true);
    try {
      const d = await api.patch<MeResp>('/auth/me/', { username: candidate });
      onDone(d.user.username);
    } catch (e) {
      toastErr(errMsg(e, 'Lỗi cập nhật username'));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="p-6 bg-white/[0.01]">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="w-10 h-10 rounded-xl bg-brand-500/10 flex items-center justify-center text-brand-400">
            <i className="bi bi-at"></i>
          </div>
          <div>
            <div className="text-sm font-black text-white uppercase tracking-wide">Đổi username</div>
            <p className="text-[10px] text-white/45 font-bold uppercase tracking-widest mt-1">
              Username hiện tại: <span className="text-brand-400">@{current}</span>
            </p>
          </div>
        </div>
        <div className="w-full sm:w-auto sm:min-w-[360px] flex gap-2">
          <input
            type="text"
            value={val}
            maxLength={150}
            onChange={(e) => setVal(e.target.value)}
            className="liquid-input flex-1 py-3 px-4 text-xs font-bold"
            placeholder="Nhập username mới"
          />
          <button
            type="button"
            onClick={submit}
            className="liquid-btn py-3 px-4 text-[10px] font-black uppercase tracking-widest bg-brand-500 text-black hover:bg-brand-400 disabled:opacity-60 disabled:cursor-not-allowed"
            disabled={loading || !val.trim() || val.trim() === current}
          >
            {!loading ? <span>Cập nhật</span> : <span className="spinner w-4 h-4 border-black"></span>}
          </button>
        </div>
      </div>
    </div>
  );
}

function EmailChangeRow({ current, onDone }: { current: string; onDone: (e: string) => void }) {
  const [expanded, setExpanded] = useState(false);
  const [loading, setLoading] = useState(false);
  const [otpRequested, setOtpRequested] = useState(false);
  const [cur, setCur] = useState(current);
  const [newEmail, setNewEmail] = useState('');
  const [password, setPassword] = useState('');
  const [otp, setOtp] = useState('');
  const [cooldown, setCooldown] = useState(0);

  useEffect(() => setCur(current), [current]);
  useEffect(() => {
    if (cooldown <= 0) return;
    const t = setInterval(() => setCooldown((c) => (c <= 1 ? 0 : c - 1)), 1000);
    return () => clearInterval(t);
  }, [cooldown]);

  async function requestOtp(): Promise<void> {
    const em = newEmail.trim().toLowerCase();
    if (!em) return toastErr('Vui lòng nhập email mới.');
    if (!password) return toastErr('Vui lòng nhập mật khẩu hiện tại.');
    setLoading(true);
    try {
      const d = await api.post<{ message?: string }>('/auth/email-change/request/', {
        new_email: em,
        password,
      });
      setNewEmail(em);
      setOtpRequested(true);
      setOtp('');
      setCooldown(60);
      toastOk(d.message || 'OTP đã được gửi.');
    } catch (e) {
      toastErr(errMsg(e, 'Không thể gửi OTP.'));
    } finally {
      setLoading(false);
    }
  }

  async function verifyOtp(): Promise<void> {
    if (!otpRequested) return;
    if (!/^\d{6}$/.test(otp.trim())) return toastErr('OTP phải gồm đúng 6 chữ số.');
    setLoading(true);
    try {
      const d = await api.post<{ message?: string; user?: { email?: string } }>('/auth/email-change/verify/', {
        new_email: newEmail,
        otp: otp.trim(),
      });
      const em = d.user?.email || newEmail;
      setCur(em);
      setNewEmail('');
      setPassword('');
      setOtp('');
      setOtpRequested(false);
      setExpanded(false);
      onDone(em);
    } catch (e) {
      toastErr(errMsg(e, 'Xác thực OTP thất bại.'));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="p-6 bg-white/[0.01]">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="w-10 h-10 rounded-xl bg-brand-500/10 flex items-center justify-center text-brand-300">
            <i className="bi bi-envelope-at-fill"></i>
          </div>
          <div>
            <div className="text-sm font-black text-white uppercase tracking-wide">Đổi email đăng nhập</div>
            <p className="text-[10px] text-white/45 font-bold uppercase tracking-widest mt-1">
              Email hiện tại: <span className="text-brand-300">{cur}</span>
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={() => setExpanded(!expanded)}
          className="liquid-btn py-2.5 px-4 text-[10px] font-black uppercase tracking-widest bg-white/5 border border-white/10 hover:bg-white/10"
        >
          <i className="bi bi-arrow-repeat mr-1"></i> Mở đổi email
        </button>
      </div>

      {expanded && (
        <div className="mt-6 rounded-3xl border border-brand-400/20 bg-brand-500/[0.04] p-5 space-y-4 animate-fadein">
          <div className="space-y-2">
            <label className="text-[10px] font-black text-white/45 uppercase tracking-widest ml-1">Email mới</label>
            <input
              type="email"
              value={newEmail}
              onChange={(e) => setNewEmail(e.target.value)}
              className="liquid-input w-full py-3.5 px-5 text-sm font-bold"
              placeholder="new-email@example.com"
            />
          </div>
          <div className="space-y-2">
            <label className="text-[10px] font-black text-white/45 uppercase tracking-widest ml-1">
              Mật khẩu hiện tại
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="liquid-input w-full py-3.5 px-5 text-sm font-bold"
              placeholder="••••••••"
            />
          </div>

          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={requestOtp}
              disabled={loading || cooldown > 0}
              className="liquid-btn py-2.5 px-4 text-[10px] font-black uppercase tracking-widest bg-brand-500 text-black hover:bg-brand-400 disabled:opacity-60"
            >
              {cooldown <= 0 ? <span>Gửi OTP đến email mới</span> : <span>{`Gửi lại sau ${cooldown}s`}</span>}
            </button>
            <p className="text-[10px] text-white/35 font-bold uppercase tracking-widest self-center">
              OTP chỉ có hiệu lực 10 phút.
            </p>
          </div>

          {otpRequested && (
            <div className="space-y-2">
              <label className="text-[10px] font-black text-white/45 uppercase tracking-widest ml-1">
                Mã OTP (6 số)
              </label>
              <input
                type="text"
                value={otp}
                maxLength={6}
                onChange={(e) => setOtp(e.target.value)}
                className="liquid-input w-full py-3.5 px-5 text-center text-xl font-black tracking-[0.45em]"
                placeholder="••••••"
              />
            </div>
          )}

          {otpRequested && (
            <button
              type="button"
              onClick={verifyOtp}
              disabled={loading}
              className="liquid-btn w-full py-4 text-[11px] font-black uppercase tracking-[0.2em] bg-brand-500 text-white hover:bg-brand-400 shadow-lg shadow-brand-500/20 disabled:opacity-60"
            >
              {!loading ? <span>XÁC THỰC OTP & ĐỔI EMAIL</span> : <span className="spinner w-4 h-4 border-white"></span>}
            </button>
          )}
        </div>
      )}
    </div>
  );
}

function MfaRow() {
  const [status, setStatus] = useState<MfaStatus | null>(null);
  const [loadingStatus, setLoadingStatus] = useState(true);
  const [setupMode, setSetupMode] = useState<'totp' | 'email' | null>(null);
  const [showDeactivate, setShowDeactivate] = useState(false);
  const [qrCode, setQrCode] = useState('');
  const [otpSecret, setOtpSecret] = useState('');
  const [verifyToken, setVerifyToken] = useState('');
  const [dePass, setDePass] = useState('');
  const [deToken, setDeToken] = useState('');
  const [codes, setCodes] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [otpLoading, setOtpLoading] = useState(false);
  const [countdown, setCountdown] = useState(0);

  useEffect(() => {
    let alive = true;
    api
      .get<MfaStatus>('/auth/mfa/status/')
      .then((d) => {
        if (alive) setStatus(d);
      })
      .catch(() => {
        /* ignore */
      })
      .finally(() => {
        if (alive) setLoadingStatus(false);
      });
    return () => {
      alive = false;
    };
  }, []);

  useEffect(() => {
    if (countdown <= 0) return;
    const t = setInterval(() => setCountdown((c) => (c <= 1 ? 0 : c - 1)), 1000);
    return () => clearInterval(t);
  }, [countdown]);

  async function fetchStatus(): Promise<void> {
    try {
      setStatus(await api.get<MfaStatus>('/auth/mfa/status/'));
    } catch {
      /* ignore */
    }
  }

  async function startSetup(method: 'totp' | 'email'): Promise<void> {
    setSetupMode(method);
    setVerifyToken('');
    if (method === 'totp') {
      try {
        const d = await api.get<{ qr_code?: string; secret?: string }>('/auth/mfa/setup/totp/');
        if (d.qr_code) {
          setQrCode(d.qr_code);
          setOtpSecret(d.secret || '');
        } else {
          toastErr('Không thể tạo mã QR');
          setSetupMode(null);
        }
      } catch (e) {
        toastErr(errMsg(e, 'Không thể tạo mã QR'));
        setSetupMode(null);
      }
    } else {
      if (countdown > 0) return;
      setOtpLoading(true);
      try {
        await api.get('/auth/mfa/setup/email/');
        toast('Đã gửi mã OTP đến email của bạn');
        setCountdown(120);
      } catch (e) {
        toastErr(errMsg(e, 'Không thể gửi email OTP'));
        setSetupMode(null);
      } finally {
        setOtpLoading(false);
      }
    }
  }

  async function confirmSetup(): Promise<void> {
    if (verifyToken.length < 6) return toastErr('Vui lòng nhập đủ 6 chữ số');
    if (!setupMode) return;
    const url = setupMode === 'totp' ? '/auth/mfa/setup/totp/' : '/auth/mfa/setup/email/';
    try {
      const d = await api.post<{ recovery_codes?: string[] }>(url, { token: verifyToken });
      if (setupMode === 'totp' && Array.isArray(d.recovery_codes)) setCodes(d.recovery_codes);
      toastOk('Cấu hình 2FA thành công!');
      setSetupMode(null);
      void fetchStatus();
    } catch (e) {
      toastErr(errMsg(e, 'Xác nhận thất bại'));
    }
  }

  async function sendDeactivateOtp(): Promise<void> {
    if (countdown > 0) return;
    setOtpLoading(true);
    try {
      await api.get('/auth/mfa/setup/email/');
      toast('Đã gửi mã OTP đến email để vô hiệu hóa 2FA');
      setCountdown(120);
    } catch (e) {
      toastErr(errMsg(e, 'Không thể gửi mã OTP'));
    } finally {
      setOtpLoading(false);
    }
  }

  async function confirmDeactivate(): Promise<void> {
    if (!dePass || deToken.length < 6) return toastErr('Vui lòng nhập đầy đủ mật khẩu và mã OTP');
    setLoading(true);
    try {
      await api.post('/auth/mfa/deactivate/', {
        password: dePass,
        token: deToken,
        method: status?.preferred_method,
      });
      toastOk('Đã vô hiệu hóa 2FA thành công!');
      setShowDeactivate(false);
      setDePass('');
      setDeToken('');
      void fetchStatus();
    } catch (e) {
      toastErr(errMsg(e, 'Xác nhận thất bại'));
    } finally {
      setLoading(false);
    }
  }

  async function regenerateRecovery(): Promise<void> {
    if (!window.confirm('Tạo bộ recovery code mới sẽ làm vô hiệu hóa bộ cũ. Tiếp tục?')) return;
    try {
      const d = await api.post<{ codes?: string[]; message?: string }>('/auth/mfa/recovery/', {});
      setCodes(d.codes || []);
      toastOk(d.message || 'Đã tạo recovery codes mới');
      void fetchStatus();
    } catch (e) {
      toastErr(errMsg(e, 'Không thể tạo recovery codes'));
    }
  }

  const has2fa = !!status?.has_2fa;
  const activeMethod = status?.preferred_method || (status?.methods?.totp ? 'totp' : 'email');

  return (
    <div className="p-6 bg-white/[0.01]">
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div
            className={`w-10 h-10 rounded-xl flex items-center justify-center transition-colors ${
              has2fa ? 'bg-safe-500/10 text-safe-500' : 'bg-warn-500/10 text-warn-500'
            }`}
          >
            <i className={`bi ${has2fa ? 'bi-shield-fill-check' : 'bi-shield-exclamation'}`}></i>
          </div>
          <div>
            <div className="text-xs font-black text-white uppercase tracking-widest">Xác thực 2 lớp (2FA)</div>
            <p
              className={`text-[10px] font-bold uppercase tracking-widest mt-1 ${
                has2fa ? 'text-safe-500/60' : 'text-warn-500/60'
              }`}
            >
              {has2fa ? 'Đã kích hoạt bảo mật' : 'Tài khoản chưa được bảo mật'}
            </p>
            {has2fa && (
              <p className="text-[10px] text-brand-300/70 font-bold uppercase tracking-widest mt-1">
                {activeMethod === 'totp' ? 'Đang dùng: Authenticator (TOTP)' : 'Đang dùng: OTP qua Email'}
              </p>
            )}
          </div>
        </div>
        <div className="flex gap-2">
          {loadingStatus ? (
            <div className="spinner w-5 h-5 border-white/20"></div>
          ) : !has2fa ? (
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => void startSetup('totp')}
                className="liquid-btn py-2 px-4 text-[10px] font-black bg-brand-500 text-black hover:bg-brand-400"
              >
                <i className="bi bi-phone mr-1"></i> BẬT TOTP
              </button>
              <button
                type="button"
                onClick={() => void startSetup('email')}
                className="liquid-btn py-2 px-4 text-[10px] font-black bg-white/5 border border-white/10 hover:bg-white/10"
              >
                <i className="bi bi-envelope mr-1"></i> BẬT EMAIL
              </button>
            </div>
          ) : (
            <button
              type="button"
              onClick={() => setShowDeactivate(true)}
              className="liquid-btn py-2 px-4 text-[10px] font-black bg-danger-500/20 text-danger-500 border border-danger-500/30 hover:bg-danger-500/40"
            >
              <i className="bi bi-slash-circle mr-1"></i> VÔ HIỆU HÓA
            </button>
          )}
        </div>
      </div>

      {showDeactivate && (
        <div className="mt-6 p-6 rounded-3xl bg-danger-500/[0.03] border border-danger-500/10 space-y-6 animate-fadein">
          <div className="flex items-start justify-between">
            <div className="space-y-1">
              <h4 className="text-xs font-black text-danger-500 uppercase tracking-widest">Vô hiệu hóa Bảo vệ 2 lớp</h4>
              <p className="text-[11px] text-white/55 font-medium">
                {activeMethod === 'totp'
                  ? 'Nhập mật khẩu + mã TOTP (hoặc recovery code) để xác nhận.'
                  : 'Hành động này yêu cầu mật khẩu và mã OTP Email để xác nhận.'}
              </p>
            </div>
            <button type="button" onClick={() => setShowDeactivate(false)} className="text-white/35 hover:text-white">
              <i className="bi bi-x-lg"></i>
            </button>
          </div>

          <div className="max-w-[400px] mx-auto space-y-4">
            <div className="space-y-2">
              <label className="text-[10px] font-black text-white/45 uppercase tracking-widest ml-2">
                Mật khẩu hiện tại
              </label>
              <input
                type="password"
                value={dePass}
                onChange={(e) => setDePass(e.target.value)}
                className="liquid-input w-full py-4 px-6 text-sm font-bold"
                placeholder="••••••••"
              />
            </div>

            <div className="space-y-2">
              <div className="flex justify-between items-center ml-2">
                <label className="text-[10px] font-black text-white/45 uppercase tracking-widest">
                  {activeMethod === 'totp' ? 'Mã TOTP hoặc Recovery code' : 'Mã xác nhận Email'}
                </label>
                {activeMethod === 'email' && (
                  <button
                    type="button"
                    onClick={sendDeactivateOtp}
                    className="text-[9px] font-black text-brand-400 uppercase tracking-widest hover:underline disabled:opacity-50 disabled:cursor-not-allowed disabled:no-underline"
                    disabled={otpLoading || countdown > 0}
                  >
                    {!otpLoading ? (
                      <span>
                        {countdown > 0
                          ? `Gửi lại sau ${Math.floor(countdown / 60)}:${String(countdown % 60).padStart(2, '0')}`
                          : 'Gửi mã OTP'}
                      </span>
                    ) : (
                      <span>Đang gửi...</span>
                    )}
                  </button>
                )}
              </div>
              <input
                type="text"
                value={deToken}
                maxLength={activeMethod === 'totp' ? 9 : 6}
                onChange={(e) => setDeToken(e.target.value)}
                className="liquid-input w-full py-4 text-center text-xl font-black tracking-[0.5em]"
                placeholder={activeMethod === 'totp' ? '123456 hoặc ABCD-EFGH' : '••••••'}
              />
            </div>

            <button
              type="button"
              onClick={confirmDeactivate}
              className="liquid-btn w-full py-4 bg-danger-500 text-white font-black hover:bg-danger-600 shadow-lg shadow-danger-500/20"
              disabled={loading}
            >
              {!loading ? <span>XÁC NHẬN VÔ HIỆU HÓA</span> : <span className="spinner w-4 h-4 border-white"></span>}
            </button>
          </div>
        </div>
      )}

      {setupMode === 'totp' && (
        <div className="mt-6 p-6 rounded-3xl bg-white/[0.03] border border-white/5 space-y-6 animate-fadein">
          <div className="flex items-start justify-between">
            <div className="space-y-1">
              <h4 className="text-xs font-black text-brand-400 uppercase tracking-widest">Xác thực bằng ứng dụng</h4>
              <p className="text-[11px] text-white/55 font-medium">Sử dụng Google/Microsoft Authenticator để quét mã.</p>
            </div>
            <button type="button" onClick={() => setSetupMode(null)} className="text-white/35 hover:text-white">
              <i className="bi bi-x-lg"></i>
            </button>
          </div>

          <div className="flex flex-col items-center justify-center py-4 space-y-6">
            {qrCode && (
              <div className="p-4 bg-white rounded-[2rem] shadow-2xl shadow-brand-500/20">
                <img src={qrCode} alt="TOTP QR" className="w-64 h-64 object-contain" style={{ imageRendering: 'pixelated' }} />
              </div>
            )}

            {otpSecret && (
              <div className="bg-white/5 border border-white/10 rounded-2xl p-4 w-full max-w-[320px] text-center">
                <p className="text-[10px] font-black text-white/45 uppercase tracking-widest mb-2">
                  Nhập mã thủ công (nếu không quét được)
                </p>
                <code className="text-brand-400 font-mono font-bold tracking-widest text-sm break-all">{otpSecret}</code>
              </div>
            )}

            <div className="w-full max-w-[240px] space-y-4">
              <div className="space-y-2">
                <label className="text-[10px] font-black text-white/45 uppercase tracking-widest ml-2">
                  Mã xác nhận 6 số
                </label>
                <input
                  type="text"
                  value={verifyToken}
                  maxLength={6}
                  onChange={(e) => setVerifyToken(e.target.value)}
                  className="liquid-input w-full py-4 text-center text-xl font-black tracking-[0.5em] placeholder:tracking-normal"
                  placeholder="••••••"
                />
              </div>
              <button
                type="button"
                onClick={confirmSetup}
                className="liquid-btn w-full py-4 bg-brand-500 text-black font-black hover:bg-brand-400"
              >
                KÍCH HOẠT NGAY
              </button>
            </div>
          </div>
        </div>
      )}

      {setupMode === 'email' && (
        <div className="mt-6 p-6 rounded-3xl bg-white/[0.03] border border-white/5 space-y-6 animate-fadein">
          <div className="flex items-start justify-between">
            <div className="space-y-1">
              <h4 className="text-xs font-black text-white uppercase tracking-widest">Xác thực bằng Email</h4>
              <p className="text-[11px] text-white/55 font-medium">Đã gửi mã bảo mật đến hòm thư của bạn.</p>
            </div>
            <button type="button" onClick={() => setSetupMode(null)} className="text-white/35 hover:text-white">
              <i className="bi bi-x-lg"></i>
            </button>
          </div>

          <div className="max-w-[320px] mx-auto space-y-4">
            <div className="space-y-2">
              <label className="text-[10px] font-black text-white/45 uppercase tracking-widest ml-2">
                Nhập mã từ hòm thư
              </label>
              <input
                type="text"
                value={verifyToken}
                maxLength={6}
                onChange={(e) => setVerifyToken(e.target.value)}
                className="liquid-input w-full py-4 text-center text-xl font-black tracking-[0.5em]"
                placeholder="••••••"
              />
            </div>
            <button
              type="button"
              onClick={confirmSetup}
              className="liquid-btn w-full py-4 bg-safe-500 text-black font-black hover:bg-safe-400 shadow-lg shadow-safe-500/20"
            >
              XÁC MINH & BẬT
            </button>
          </div>
        </div>
      )}

      {has2fa && activeMethod === 'totp' && (
        <div className="mt-6 p-6 rounded-3xl bg-brand-500/[0.04] border border-brand-500/20 space-y-4 animate-fadein">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h4 className="text-xs font-black text-brand-300 uppercase tracking-widest">Recovery codes dự phòng</h4>
              <p className="text-[11px] text-white/60 font-medium mt-1">
                Tạo 10 mã dự phòng và lưu ở nơi bảo mật để dùng khi mất thiết bị Authenticator.
              </p>
              <p className="text-[10px] text-warn-300/80 font-bold uppercase tracking-widest mt-2">
                {`Còn lại: ${status?.recovery_codes?.remaining ?? 0}/${status?.recovery_codes?.total ?? 0} mã chưa dùng`}
              </p>
            </div>
            <button
              type="button"
              onClick={regenerateRecovery}
              className="liquid-btn py-2 px-4 text-[10px] font-black bg-brand-500 text-black hover:bg-brand-400 shrink-0"
            >
              TẠO MỚI 10 MÃ
            </button>
          </div>

          {codes.length > 0 && (
            <div className="rounded-2xl border border-white/10 bg-black/20 p-4 space-y-3">
              <p className="text-[10px] text-warn-300/90 font-black uppercase tracking-widest">
                Lưu ngay các mã này. Hệ thống sẽ không hiện lại lần nữa.
              </p>
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
                {codes.map((c) => (
                  <div
                    key={c}
                    className="px-2 py-2 rounded-lg bg-white/5 border border-white/10 text-center text-[11px] font-black text-brand-200 tracking-widest"
                  >
                    {c}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function DeleteAccountRow() {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [password, setPassword] = useState('');
  const [confirmationText, setConfirmationText] = useState('');

  async function submitDelete(e: FormEvent): Promise<void> {
    e.preventDefault();
    const norm = confirmationText.trim().toUpperCase();
    if (!password) return toastErr('Vui lòng nhập mật khẩu hiện tại.');
    if (norm !== 'XOA TAI KHOAN' && norm !== 'XÓA TÀI KHOẢN')
      return toastErr('Bạn phải nhập chính xác cụm từ xác nhận (XÓA TÀI KHOẢN).');
    if (!window.confirm('Bạn chắc chắn muốn xóa tài khoản vĩnh viễn? Hành động này không thể khôi phục.')) return;
    setLoading(true);
    try {
      const d = await api.post<{ message?: string }>('/auth/account/delete/', {
        password,
        confirmation_text: confirmationText,
      });
      toastOk(d.message || 'Tài khoản đã được xóa.');
      setTimeout(() => {
        window.location.href = '/';
      }, 800);
    } catch (e) {
      toastErr(errMsg(e, 'Không thể xóa tài khoản.'));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="p-6 bg-danger-500/[0.03]">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="w-10 h-10 rounded-xl bg-danger-500/20 border border-danger-500/30 flex items-center justify-center text-danger-400">
            <i className="bi bi-trash3-fill"></i>
          </div>
          <div>
            <div className="text-sm font-black text-danger-300 uppercase tracking-wide">Xóa tài khoản vĩnh viễn</div>
            <p className="text-[10px] text-danger-200/70 font-bold uppercase tracking-widest mt-1">
              Hành động không thể hoàn tác, dữ liệu sẽ bị xóa khỏi hệ thống.
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={() => setOpen(!open)}
          className="liquid-btn py-2.5 px-4 text-[10px] font-black uppercase tracking-widest bg-danger-500/20 text-danger-300 border border-danger-500/30 hover:bg-danger-500/30"
        >
          <i className="bi bi-exclamation-triangle-fill mr-1"></i> Mở xác nhận
        </button>
      </div>

      {open && (
        <form
          onSubmit={submitDelete}
          className="mt-6 rounded-3xl border border-danger-500/20 bg-black/20 p-5 space-y-4 animate-fadein"
        >
          <p className="text-[11px] text-danger-200/80 font-semibold leading-relaxed">
            Nhập mật khẩu hiện tại và gõ chính xác cụm từ <span className="font-black text-danger-300">XÓA TÀI KHOẢN</span>{' '}
            (hoặc <span className="font-bold text-danger-300">XOA TAI KHOAN</span>) để xác nhận xóa tài khoản.
          </p>
          <div className="space-y-2">
            <label className="text-[10px] font-black text-white/45 uppercase tracking-widest ml-1">
              Mật khẩu hiện tại
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="liquid-input w-full py-3.5 px-5 text-sm font-bold"
              placeholder="••••••••"
            />
          </div>
          <div className="space-y-2">
            <label className="text-[10px] font-black text-white/45 uppercase tracking-widest ml-1">
              Cụm từ xác nhận
            </label>
            <input
              type="text"
              value={confirmationText}
              onChange={(e) => setConfirmationText(e.target.value)}
              className="liquid-input w-full py-3.5 px-5 text-sm font-black tracking-[0.15em] uppercase"
              placeholder="XÓA TÀI KHOẢN"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="liquid-btn w-full py-4 text-[11px] font-black uppercase tracking-[0.2em] bg-danger-500 text-white hover:bg-danger-600 shadow-lg shadow-danger-500/20 disabled:opacity-60"
          >
            {!loading ? <span>XÓA TÀI KHOẢN NGAY</span> : <span className="spinner w-4 h-4 border-white"></span>}
          </button>
        </form>
      )}
    </div>
  );
}
