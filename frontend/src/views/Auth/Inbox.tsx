'use client';
import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { api } from '../../lib/api';
import { renderMd } from '../../lib/chat/markdown';
import { MarkdownView } from '../../components/ui';

interface Notif {
  id: number;
  title: string;
  message: string;
  notification_type: string;
  url?: string;
  is_read: boolean;
  created_at: string;
}

interface NotifResp {
  results: Notif[];
  count: number;
  pages: number;
  page: number;
  unread_count: number;
}

type Filter = 'all' | 'unread' | 'info' | 'success' | 'warning' | 'error';

function stripMd(text: string): string {
  if (!text) return '';
  return text
    .replace(/#{1,6}\s+/g, '')
    .replace(/\*\*(.+?)\*\*/g, '$1')
    .replace(/\*(.+?)\*/g, '$1')
    .replace(/__(.+?)__/g, '$1')
    .replace(/_(.+?)_/g, '$1')
    .replace(/~~(.+?)~~/g, '$1')
    .replace(/`{1,3}([^`]+)`{1,3}/g, '$1')
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    .replace(/^\s*[-*+]\s+/gm, '• ')
    .replace(/^\s*\d+\.\s+/gm, '')
    .replace(/^>\s?/gm, '')
    .replace(/---+/g, '')
    .trim();
}

function timeAgo(dt: string): string {
  if (!dt) return '';
  const diff = (Date.now() - new Date(dt).getTime()) / 1000;
  if (diff < 60) return 'Vừa xong';
  if (diff < 3600) return `${Math.floor(diff / 60)} phút trước`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} giờ trước`;
  if (diff < 604800) return `${Math.floor(diff / 86400)} ngày trước`;
  return new Date(dt).toLocaleDateString('vi-VN');
}

function formatDate(dt: string): string {
  if (!dt) return '';
  return new Date(dt).toLocaleString('vi-VN', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function typeIcon(type: string): string {
  const icons: Record<string, string> = {
    info: 'bi-info-circle-fill',
    success: 'bi-check-circle-fill',
    warning: 'bi-exclamation-triangle-fill',
    error: 'bi-x-circle-fill',
  };
  return icons[type] || 'bi-bell-fill';
}

function typeColor(type: string): string {
  const colors: Record<string, string> = {
    info: 'text-brand-400 bg-brand-400/10',
    success: 'text-safe-400 bg-safe-400/10',
    warning: 'text-warn-400 bg-warn-400/10',
    error: 'text-danger-400 bg-danger-400/10',
  };
  return colors[type] || 'text-brand-400 bg-brand-400/10';
}

function typeLabel(type: string): string {
  const labels: Record<string, string> = {
    info: 'Thông tin',
    success: 'Thành công',
    warning: 'Cảnh báo',
    error: 'Lỗi',
  };
  return labels[type] || type;
}

/* Port từ PKV/templates/Auth/inbox.html.
 * API: GET /notifications/?page&per_page, POST /notifications/:id/read/, POST /notifications/read-all/. */
export default function Inbox() {
  const [notifications, setNotifications] = useState<Notif[]>([]);
  const [loading, setLoading] = useState(false);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const [unreadCount, setUnreadCount] = useState(0);
  const [filter, setFilter] = useState<Filter>('all');
  const [selected, setSelected] = useState<Notif | null>(null);

  const fetchNotifications = useCallback(async (p: number) => {
    setLoading(true);
    try {
      const data = await api.get<NotifResp>(`/notifications/?page=${p}&per_page=20`);
      setNotifications(data.results || []);
      setTotalPages(Math.max(1, data.pages || 1));
      setTotalCount(data.count || 0);
      setUnreadCount(data.unread_count || 0);
      setPage(data.page || p);
    } catch {
      /* ignore — y bản gốc chỉ toast */
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchNotifications(1);
  }, [fetchNotifications]);

  const filtered =
    filter === 'all'
      ? notifications
      : filter === 'unread'
        ? notifications.filter((n) => !n.is_read)
        : notifications.filter((n) => n.notification_type === filter);

  async function markRead(n: Notif): Promise<void> {
    if (n.is_read) return;
    try {
      await api.post(`/notifications/${n.id}/read/`, {});
      setNotifications((prev) => prev.map((x) => (x.id === n.id ? { ...x, is_read: true } : x)));
      setUnreadCount((c) => Math.max(0, c - 1));
    } catch {
      /* ignore */
    }
  }

  async function openNotification(n: Notif): Promise<void> {
    await markRead(n);
    setSelected({ ...n, is_read: true });
  }

  async function markAllRead(): Promise<void> {
    try {
      await api.post('/notifications/read-all/', {});
      setNotifications((prev) => prev.map((n) => ({ ...n, is_read: true })));
      setUnreadCount(0);
    } catch {
      /* ignore */
    }
  }

  function goPage(p: number): void {
    if (p < 1 || p > totalPages) return;
    void fetchNotifications(p);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  const filters: Array<{ key: Filter; label: string; cls: string; icon?: string }> = [
    { key: 'all', label: 'Tất cả', cls: 'text-white/60' },
    { key: 'unread', label: 'Chưa đọc', cls: 'text-white/60' },
    { key: 'info', label: 'Thông tin', cls: 'text-brand-400/50', icon: 'bi-info-circle' },
    { key: 'success', label: 'Thành công', cls: 'text-safe-400/50', icon: 'bi-check-circle' },
    { key: 'warning', label: 'Cảnh báo', cls: 'text-warn-400/50', icon: 'bi-exclamation-triangle' },
    { key: 'error', label: 'Lỗi', cls: 'text-danger-400/50', icon: 'bi-x-circle' },
  ];

  const urlOk = selected?.url ? /^(https?:\/\/|\/(?!\/))/i.test(selected.url) : false;

  return (
    <div className="max-w-4xl mx-auto px-4 py-8">
      <nav className="flex items-center gap-2 text-sm mb-5 text-white/55">
        <Link href="/" className="hover:text-brand-400 transition">
          <i className="bi bi-house-door"></i> Trang chủ
        </Link>
        <i className="bi bi-chevron-right text-[10px]"></i>
        <Link href="/profile/" className="hover:text-brand-400 transition">
          Hồ sơ
        </Link>
        <i className="bi bi-chevron-right text-[10px]"></i>
        <span className="text-white/60">Thông báo</span>
      </nav>

      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-brand-500/20 to-brand-500/20 flex items-center justify-center border border-brand-500/20">
            <i className="bi bi-bell-fill text-xl text-brand-400"></i>
          </div>
          <div>
            <h1 className="text-2xl font-black text-white">Thông báo</h1>
            <p className="text-xs text-white/55">
              <span>{totalCount}</span> thông báo · <span className="text-brand-400">{unreadCount}</span> chưa đọc
            </p>
          </div>
        </div>
        {unreadCount > 0 && (
          <button
            type="button"
            onClick={markAllRead}
            className="liquid-btn text-[11px] py-2 px-4 bg-brand-500/10 text-brand-400 border border-brand-500/20 rounded-xl hover:bg-brand-500/20 transition"
          >
            <i className="bi bi-check2-all mr-1"></i> Đánh dấu tất cả đã đọc
          </button>
        )}
      </div>

      <div className="flex items-center gap-2 mb-4 flex-wrap">
        {filters.map((f) => (
          <button
            key={f.key}
            type="button"
            onClick={() => setFilter(f.key)}
            className={`filter-btn text-[10px] font-bold px-3 py-1.5 rounded-lg border border-white/10 ${f.cls} ${filter === f.key ? 'active' : ''}`}
          >
            {f.icon && <i className={`bi ${f.icon} mr-1`}></i>}
            {f.label}
            {f.key === 'unread' && unreadCount > 0 && (
              <span className="ml-1 px-1.5 py-0.5 rounded-full bg-danger-500/20 text-danger-400 text-[8px]">
                {unreadCount}
              </span>
            )}
          </button>
        ))}
      </div>

      <div className="notif-card overflow-hidden">
        {loading && (
          <div className="p-8 text-center">
            <div className="w-6 h-6 border-2 border-brand-400 border-t-transparent rounded-full animate-spin mx-auto mb-2"></div>
            <p className="text-[10px] text-white/45">Đang tải...</p>
          </div>
        )}

        {!loading && filtered.length === 0 && (
          <div className="p-12 text-center">
            <i className="bi bi-bell-slash text-4xl text-white/20 mb-3 block"></i>
            <p className="text-white/45 text-sm font-bold">Không có thông báo</p>
            <p className="text-white/15 text-xs mt-1">
              {filter !== 'all' ? 'Thử bộ lọc khác' : 'Bạn sẽ nhận thông báo khi có cập nhật mới'}
            </p>
          </div>
        )}

        {filtered.map((n) => (
          <div
            key={n.id}
            onClick={() => void openNotification(n)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') void openNotification(n);
            }}
            role="button"
            tabIndex={0}
            className={`notif-item flex items-start gap-4 px-5 py-4 border-b border-white/5 ${n.is_read ? 'read' : 'unread'}`}
          >
            <div
              className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 ${typeColor(n.notification_type)}`}
            >
              <i className={`bi text-lg ${typeIcon(n.notification_type)}`}></i>
            </div>

            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-0.5">
                <h3 className="text-sm font-bold text-white/80 truncate">{n.title}</h3>
                <span
                  className={`text-[8px] font-bold px-1.5 py-0.5 rounded-md uppercase tracking-wider shrink-0 ${typeColor(n.notification_type)}`}
                >
                  {typeLabel(n.notification_type)}
                </span>
                {!n.is_read && <div className="w-2 h-2 rounded-full bg-brand-400 shrink-0 animate-pulse"></div>}
              </div>
              <p className="text-xs text-white/55 leading-relaxed">{stripMd(n.message)}</p>
              <div className="flex items-center gap-3 mt-2">
                <span className="text-[9px] text-white/35">
                  <i className="bi bi-clock mr-1"></i>
                  {timeAgo(n.created_at)}
                </span>
                <span className="text-[9px] text-white/15">{formatDate(n.created_at)}</span>
                {n.url && (
                  <span className="text-[9px] text-brand-400/50">
                    <i className="bi bi-box-arrow-up-right mr-0.5"></i>Nhấn để xem
                  </span>
                )}
              </div>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              {!n.is_read && (
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    void markRead(n);
                  }}
                  className="p-1.5 rounded-lg hover:bg-white/5 text-white/45 hover:text-brand-400 transition"
                  title="Đánh dấu đã đọc"
                >
                  <i className="bi bi-check2"></i>
                </button>
              )}
            </div>
          </div>
        ))}
      </div>

      {selected && (
        <div className="liquid-card p-6 mt-6 space-y-4">
          <div className="flex items-start justify-between gap-4">
            <h3 className="text-base font-black text-white">{selected.title}</h3>
            <button
              type="button"
              onClick={() => setSelected(null)}
              className="p-1.5 rounded-lg hover:bg-white/5 text-white/45 hover:text-white transition shrink-0"
            >
              <i className="bi bi-x-lg"></i>
            </button>
          </div>
          <MarkdownView html={renderMd(selected.message)} className="notif-md-content text-sm" />
          {urlOk && selected.url && (
            <a href={selected.url} className="text-brand-400 text-xs inline-flex items-center gap-1">
              <i className="bi bi-box-arrow-up-right"></i> {selected.url}
            </a>
          )}
          <p className="text-[10px] text-white/45">{formatDate(selected.created_at)}</p>
        </div>
      )}

      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2 mt-6">
          <button
            type="button"
            onClick={() => goPage(page - 1)}
            disabled={page <= 1}
            className="px-3 py-1.5 rounded-lg text-xs font-bold border border-white/10 text-white/55 hover:text-white hover:border-brand-400/30 transition disabled:opacity-30"
          >
            <i className="bi bi-chevron-left"></i>
          </button>
          {Array.from({ length: totalPages }, (_, i) => i + 1).map((p) => (
            <button
              key={p}
              type="button"
              onClick={() => goPage(p)}
              className={`w-8 h-8 rounded-lg text-xs font-bold border transition ${
                p === page
                  ? 'bg-brand-400/10 text-brand-400 border-brand-400/30'
                  : 'border-white/10 text-white/55 hover:text-white'
              }`}
            >
              <span>{p}</span>
            </button>
          ))}
          <button
            type="button"
            onClick={() => goPage(page + 1)}
            disabled={page >= totalPages}
            className="px-3 py-1.5 rounded-lg text-xs font-bold border border-white/10 text-white/55 hover:text-white hover:border-brand-400/30 transition disabled:opacity-30"
          >
            <i className="bi bi-chevron-right"></i>
          </button>
        </div>
      )}
    </div>
  );
}
