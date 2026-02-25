self.__SC_SW_VERSION__ = '2026-03-02-v2';

self.addEventListener('install', event => {
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('push', event => {
  let payload = {};
  try {
    payload = event.data ? event.data.json() : {};
  } catch (e) {
    payload = { message: event.data ? event.data.text() : '' };
  }

  const title = payload.title || 'ShieldCall VN';
  const body = payload.body || payload.message || 'Bạn có thông báo mới';
  const url = payload.url || '/dashboard/';
  const tag = payload.tag || 'shieldcall-push';
  const icon = payload.icon || '/static/logo.png';

  event.waitUntil(
    self.registration.showNotification(title, {
      body,
      icon,
      badge: '/static/logo.png',
      data: { url },
      tag,
      renotify: false,
      requireInteraction: false,
    })
  );
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const targetUrl = (event.notification.data && event.notification.data.url) || '/dashboard/';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(windowClients => {
      for (const client of windowClients) {
        if ('focus' in client) {
          client.postMessage({ type: 'push_click', url: targetUrl });
          return client.focus();
        }
      }
      if (clients.openWindow) return clients.openWindow(targetUrl);
      return null;
    })
  );
});
