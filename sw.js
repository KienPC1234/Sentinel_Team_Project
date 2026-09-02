self.__SC_SW_VERSION__ = '2026-09-01-v4';

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

self.addEventListener('fetch', event => {
  const url = event.request.url;

  // Do not intercept non-GET requests (e.g. POST, SSE streams, etc.)
  if (event.request.method !== 'GET') {
    return;
  }

  // Do NOT intercept API endpoints, OAuth callbacks, SSE streams, or external domains
  if (url.includes('/api/v1/') ||
      url.includes('/accounts/') ||
      url.includes('googleapis.com') ||
      url.includes('google.com') ||
      url.includes('cloudflareinsights.com') ||
      url.includes('challenges.cloudflare.com') ||
      url.includes('youtube.com') ||
      url.includes('google-analytics.com')) {
    return;
  }

  // Navigation requests (HTML pages)
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request).catch(() => {
        return caches.match(event.request).then(cached => cached || caches.match('/'));
      })
    );
    return;
  }

  // Assets: Cache-first with safe Network fallback
  event.respondWith(
    caches.match(event.request).then(cachedResponse => {
      if (cachedResponse) {
        return cachedResponse;
      }
      return fetch(event.request).catch(err => {
        return new Response('', { status: 404, statusText: 'Resource Not Found' });
      });
    })
  );
});
