self.__SC_SW_VERSION__ = '2026-03-28-v3';

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
  
  // Do NOT intercept third-party trackers, analytics, or Google APIs.
  // Letting the browser handle these natively avoids Uncaught Promise rejections in the SW
  // when they are blocked by AdBlockers or fail due to SRI checks.
  if (url.includes('googleapis.com') || 
      url.includes('cloudflareinsights.com') || 
      url.includes('youtube.com') || 
      url.includes('google-analytics.com')) {
      return; 
  }

  // Filter for navigation requests (HTML pages) to ensure basic offline/loading support
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request).catch(error => {
        console.log('[SW] Fetch failed; returning cached offline page if available.');
        return caches.match(event.request);
      })
    );
  } else {
    // For other assets, try cache then network
    event.respondWith(
      caches.match(event.request).then(response => {
        if (response) return response;
        return fetch(event.request);
      })
    );
  }
});
