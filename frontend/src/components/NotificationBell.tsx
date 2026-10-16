'use client';
import { useCallback, useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { api } from '../lib/api';
import { showToast } from '../lib/ui/feedback';
import type { ToastType } from '../lib/ui/feedback';
import { ensurePushSubscription } from '../lib/push';
import { wsBase } from './ScanWidgets';

/* Port notificationBell() từ PKV/templates/base.html + NotificationManager
 * (PKV/static/js/notifications.js): chuông thông báo ở navbar.
 * - WS  /ws/notifications/  ({type:'notification'|'notification_count'|'ping'})
 * - REST /notifications/, /notifications/unread-count/,
 *        /notifications/<id>/read/, /notifications/read-all/
 */

interface Notif {
  id: number;
  title: string;
  message: string;
  notification_type: string;
  url?: string | null;
  is_read: boolean;
  created_at: string;
}

const TYPE_STYLE: Record<string, { bg: string; icon: string; toast: ToastType }> = {
  info: { bg: 'bg-brand-400/10 text-brand-400', icon: 'bi-info-circle-fill', toast: 'info' },
  success: { bg: 'bg-safe-400/10 text-safe-400', icon: 'bi-check-circle-fill', toast: 'success' },
  warning: { bg: 'bg-warn-400/10 text-warn-400', icon: 'bi-exclamation-triangle-fill', toast: 'warning' },
  error: { bg: 'bg-danger-400/10 text-danger-400', icon: 'bi-x-circle-fill', toast: 'error' },
};

function timeAgo(iso: string): string {
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return '';
  const secs = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (secs < 60) return 'vừa xong';
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins} phút trước`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours} giờ trước`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days} ngày trước`;
  return new Date(iso).toLocaleDateString('vi-VN');
}

export default function NotificationBell() {
  const [open, setOpen] = useState(false);
  const [notes, setNotes] = useState<Notif[]>([]);
  const [unread, setUnread] = useState(0);
  const [loading, setLoading] = useState(false);
  const hideTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const [pushPerm, setPushPerm] = useState<'default' | 'granted' | 'denied'>(
    typeof Notification !== 'undefined' ? Notification.permission : 'denied',
  );

  const fetchUnread = useCallback(async () => {
    try {
      const d = await api.get<{ unread_count: number }>('/notifications/unread-count/');
      setUnread(d.unread_count || 0);
    } catch {
      /* chưa đăng nhập / lỗi mạng */
    }
  }, []);

  const fetchNotes = useCallback(async () => {
    setLoading(true);
    try {
      const d = await api.get<{ results: Notif[]; unread_count: number }>('/notifications/?per_page=10');
      setNotes(d.results || []);
      setUnread(d.unread_count || 0);
    } catch {
      /* ignore */
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    void fetchUnread();
    // Đăng ký web push nếu trình duyệt đã cấp quyền (y NotificationManager gốc).
    void ensurePushSubscription();
  }, [fetchUnread]);

  const enablePush = async () => {
    if (typeof Notification === 'undefined') return;
    try {
      const perm = await Notification.requestPermission();
      setPushPerm(perm);
      if (perm === 'granted') {
        const ok = await ensurePushSubscription();
        showToast(ok ? 'Đã bật thông báo trình duyệt' : 'Không thể đăng ký thông báo', ok ? 'success' : 'error');
      }
    } catch {
      /* ignore */
    }
  };

  /* WS /ws/notifications/ — reconnect 5s, trả pong cho ping. */
  useEffect(() => {
    let closed = false;
    let reconnect: ReturnType<typeof setTimeout> | null = null;

    const connect = () => {
      let ws: WebSocket;
      try {
        ws = new WebSocket(`${wsBase()}/ws/notifications/`);
      } catch {
        return;
      }
      wsRef.current = ws;

      ws.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data) as {
            type?: string;
            id?: number;
            title?: string;
            message?: string;
            notification_type?: string;
            url?: string | null;
            created_at?: string;
            unread_count?: number;
          };
          if (data.type === 'ping') {
            ws.send(JSON.stringify({ type: 'pong' }));
            return;
          }
          if (data.type === 'notification') {
            setUnread((c) => (typeof data.unread_count === 'number' ? data.unread_count : c + 1));
            const style = TYPE_STYLE[data.notification_type || 'info'] || TYPE_STYLE.info;
            showToast(data.title || 'Bạn có thông báo mới', style.toast);

            if (
              typeof window !== 'undefined' &&
              typeof Notification !== 'undefined' &&
              Notification.permission === 'granted' &&
              document.visibilityState === 'hidden'
            ) {
              try {
                if ('serviceWorker' in navigator) {
                  void navigator.serviceWorker.ready.then((reg) => {
                    void reg.showNotification(data.title || 'ShieldCall VN', {
                      body: data.message || 'Bạn có thông báo mới',
                      icon: '/web-app-manifest-192x192.png',
                      badge: '/favicon-96x96.png',
                      tag: `sc-bell-${data.id || Date.now()}`,
                      data: { url: data.url || '/profile/inbox/' },
                    });
                  });
                }
              } catch {
                /* fallback gracefully */
              }
            }

            setNotes((list) =>
              [
                {
                  id: data.id || Date.now(),
                  title: data.title || '',
                  message: data.message || '',
                  notification_type: data.notification_type || 'info',
                  url: data.url || null,
                  is_read: false,
                  created_at: data.created_at || new Date().toISOString(),
                },
                ...list,
              ].slice(0, 10),
            );
          } else if (data.type === 'notification_count' && typeof data.unread_count === 'number') {
            setUnread(data.unread_count);
          }
        } catch {
          /* bỏ qua message lỗi */
        }
      };
      ws.onclose = () => {
        if (!closed) reconnect = setTimeout(connect, 5000);
      };
      ws.onerror = () => {
        try {
          ws.close();
        } catch {
          /* ignore */
        }
      };
    };

    connect();
    return () => {
      closed = true;
      if (reconnect) clearTimeout(reconnect);
      try {
        wsRef.current?.close();
      } catch {
        /* ignore */
      }
    };
  }, []);

  const show = () => {
    if (hideTimer.current) {
      clearTimeout(hideTimer.current);
      hideTimer.current = null;
    }
    setOpen(true);
    void fetchNotes();
  };
  const hide = () => {
    hideTimer.current = setTimeout(() => setOpen(false), 350);
  };

  const openNotification = async (n: Notif) => {
    if (!n.is_read) {
      try {
        await api.post(`/notifications/${n.id}/read/`);
        setNotes((l) => l.map((x) => (x.id === n.id ? { ...x, is_read: true } : x)));
        setUnread((c) => Math.max(0, c - 1));
      } catch {
        /* ignore */
      }
    }
    if (n.url) window.location.href = n.url;
  };

  const markAllRead = async () => {
    try {
      await api.post('/notifications/read-all/');
      setNotes((l) => l.map((x) => ({ ...x, is_read: true })));
      setUnread(0);
    } catch {
      /* ignore */
    }
  };

  return (
    <div className="relative flex items-center" onMouseEnter={show} onMouseLeave={hide}>
      <button
        onClick={() => (open ? setOpen(false) : show())}
        className="relative h-9 w-9 rounded-full flex items-center justify-center bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 text-slate-300 hover:text-white transition-all cursor-pointer outline-none focus-visible:ring-1 focus-visible:ring-cyan-400 shrink-0"
        aria-label="Thông báo"
      >
        <i className="bi bi-bell-fill text-sm leading-none"></i>
        {unread > 0 && (
          <span className="absolute -top-1 -right-1 min-w-[18px] h-[18px] rounded-full bg-rose-500 flex items-center justify-center text-[9px] font-black text-white border-2 border-[var(--sc-night-1)] px-1 shadow-sm leading-none">
            {unread > 99 ? '99+' : unread}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-2 w-80 border border-border bg-popover/98 backdrop-blur-xl rounded-2xl z-50 overflow-hidden shadow-[0_20px_60px_rgba(0,0,0,0.7)] sc-pop-in">
          <div className="px-4 py-3 border-b border-white/10 flex items-center justify-between">
            <div>
              <p className="text-xs font-black text-white">Thông báo</p>
              <p className="text-[9px] text-white/45">{unread} chưa đọc</p>
            </div>
            {unread > 0 && (
              <button
                onClick={() => void markAllRead()}
                className="text-[10px] font-bold text-brand-400 hover:text-white transition-colors"
              >
                Đánh dấu tất cả đã đọc
              </button>
            )}
          </div>

          {pushPerm === 'default' && (
            <button
              onClick={() => void enablePush()}
              className="w-full px-4 py-2 text-[10px] font-bold text-warn-300 bg-warn-500/10 hover:bg-warn-500/20 transition-colors text-left"
            >
              <i className="bi bi-bell-plus mr-1.5"></i> Bật thông báo đẩy trên trình duyệt
            </button>
          )}

          <div className="max-h-[360px] overflow-y-auto">
            {loading ? (
              <div className="p-6 text-center">
                <div className="w-5 h-5 border-2 border-brand-400 border-t-transparent rounded-full animate-spin mx-auto"></div>
              </div>
            ) : notes.length === 0 ? (
              <div className="p-8 text-center">
                <i className="bi bi-bell-slash text-2xl text-white/20 mb-2 block"></i>
                <p className="text-[10px] text-white/35">Chưa có thông báo</p>
              </div>
            ) : (
              notes.map((n) => {
                const style = TYPE_STYLE[n.notification_type] || TYPE_STYLE.info;
                return (
                  <div
                    key={n.id}
                    onClick={() => void openNotification(n)}
                    className={`flex items-start gap-3 px-4 py-3 border-b border-white/5 cursor-pointer transition-colors ${
                      n.is_read ? 'hover:bg-white/3' : 'bg-brand-400/[0.03] hover:bg-brand-400/[0.06]'
                    }`}
                  >
                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 mt-0.5 ${style.bg}`}>
                      <i className={`bi ${style.icon}`}></i>
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <p className="text-[11px] font-bold text-white/80 truncate">{n.title}</p>
                        {!n.is_read && <div className="w-1.5 h-1.5 rounded-full bg-brand-400 shrink-0"></div>}
                      </div>
                      <p className="text-[10px] text-white/55 line-clamp-2 mt-0.5">{n.message}</p>
                      <p className="text-[9px] text-white/35 mt-1">{timeAgo(n.created_at)}</p>
                    </div>
                  </div>
                );
              })
            )}
          </div>

          <Link
            href="/profile/inbox/"
            className="block px-4 py-3 text-center text-[11px] font-bold text-brand-400 hover:bg-white/3 border-t border-white/5 transition-colors"
          >
            Xem tất cả thông báo <i className="bi bi-arrow-right ml-1"></i>
          </Link>
        </div>
      )}
    </div>
  );
}
