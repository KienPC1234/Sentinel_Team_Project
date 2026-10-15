import { api } from './api';

/* Web Push subscription (port từ PKV/static/js/notifications.js).
 * Dùng API sẵn có: GET /push/public-key/, POST /push/subscribe/.
 * Service worker (public/sw.js) đã có handler 'push'/'notificationclick'. */

function urlBase64ToUint8Array(base64String: string): Uint8Array {
  const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64);
  const arr = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) arr[i] = raw.charCodeAt(i);
  return arr;
}

/** Đăng ký push nếu trình duyệt đã cấp quyền; bỏ qua lặng lẽ nếu chưa/kém hỗ trợ. */
export async function ensurePushSubscription(): Promise<boolean> {
  if (typeof window === 'undefined') return false;
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) return false;
  if (typeof Notification === 'undefined' || Notification.permission !== 'granted') return false;
  try {
    const reg = await navigator.serviceWorker.ready;
    let sub = await reg.pushManager.getSubscription();
    if (!sub) {
      const data = await api.get<{ public_key?: string }>('/push/public-key/');
      const key = data.public_key;
      if (!key) return false;
      sub = await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(key) as unknown as BufferSource,
      });
    }
    const json = sub.toJSON();
    if (!json.endpoint || !json.keys) return false;
    await api.post('/push/subscribe/', { endpoint: json.endpoint, keys: json.keys });
    return true;
  } catch {
    return false;
  }
}

/** Gỡ đăng ký push (khi đăng xuất hoặc tắt thông báo). */
export async function unsubscribePush(): Promise<void> {
  if (typeof window === 'undefined' || !('serviceWorker' in navigator)) return;
  try {
    const reg = await navigator.serviceWorker.ready;
    const sub = await reg.pushManager.getSubscription();
    if (sub) {
      try {
        await api.post('/push/unsubscribe/', { endpoint: sub.endpoint });
      } catch {
        /* ignore */
      }
      await sub.unsubscribe();
    }
  } catch {
    /* ignore */
  }
}
