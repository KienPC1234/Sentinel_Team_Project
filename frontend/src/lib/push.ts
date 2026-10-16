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
    try {
      await api.post('/push/subscribe/', { endpoint: json.endpoint, keys: json.keys });
      return true;
    } catch {
      // Neu subscription cu bi loi / 410 tren backend hoac sai VAPID key, thu renew
      try {
        await sub.unsubscribe();
        const data = await api.get<{ public_key?: string }>('/push/public-key/');
        const key = data.public_key;
        if (!key) return false;
        const freshSub = await reg.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: urlBase64ToUint8Array(key) as unknown as BufferSource,
        });
        const freshJson = freshSub.toJSON();
        if (!freshJson.endpoint || !freshJson.keys) return false;
        await api.post('/push/subscribe/', { endpoint: freshJson.endpoint, keys: freshJson.keys });
        return true;
      } catch {
        return false;
      }
    }
  } catch {
    return false;
  }
}

/** Yêu cầu quyền thông báo và kích hoạt WebPush trên thiết bị hiện tại. */
export async function requestAndSubscribePush(): Promise<{
  success: boolean;
  permission: NotificationPermission;
  message?: string;
}> {
  if (typeof window === 'undefined' || typeof Notification === 'undefined') {
    return { success: false, permission: 'denied', message: 'Trình duyệt không hỗ trợ thông báo.' };
  }
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
    return { success: false, permission: Notification.permission, message: 'Trình duyệt không hỗ trợ WebPush Service Worker.' };
  }

  try {
    const permission = await Notification.requestPermission();
    if (permission !== 'granted') {
      return {
        success: false,
        permission,
        message: permission === 'denied' ? 'Bạn đã chặn quyền thông báo.' : 'Bạn chưa cấp quyền thông báo.',
      };
    }
    const ok = await ensurePushSubscription();
    return {
      success: ok,
      permission,
      message: ok ? 'Đã kích hoạt WebPush thành công trên trình duyệt này!' : 'Đã cấp quyền nhưng chưa thể lưu subscription lên server.',
    };
  } catch (err) {
    return {
      success: false,
      permission: Notification.permission,
      message: err instanceof Error ? err.message : 'Lỗi yêu cầu quyền thông báo.',
    };
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
