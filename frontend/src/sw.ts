/// <reference lib="webworker" />

/**
 * ShieldCall VN - Modernized Service Worker (TypeScript)
 * Features:
 * - Network-First for navigation with rich offline fallback page.
 * - Cache-First for versioned static assets & icons.
 * - Strict bypass for Next.js HMR, WebSocket (/ws/*), SSE streams, APIs, & Cloudflare Turnstile.
 * - Web Push notification handler with action buttons and tab-focusing click routing.
 * - Cache lifecycle management with automatic cleanup of outdated versions.
 */

const sw = self as unknown as ServiceWorkerGlobalScope;

const SW_VERSION = '2026-10-16-v4';
const STATIC_CACHE = `sc-static-${SW_VERSION}`;
const PAGES_CACHE = `sc-pages-${SW_VERSION}`;
const ALL_ACTIVE_CACHES = [STATIC_CACHE, PAGES_CACHE];

const PRECACHE_ASSETS = [
  '/logo.png',
  '/web-app-manifest-192x192.png',
  '/favicon.svg',
  '/favicon-96x96.png',
  '/icons.svg',
  '/manifest.json',
  '/site.webmanifest',
];

const OFFLINE_HTML = `<!DOCTYPE html>
<html lang="vi" class="dark">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Mất kết nối - ShieldCall VN</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 1.5rem;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #090d16;
      color: #f1f5f9;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      text-align: center;
    }
    .card {
      max-width: 440px;
      width: 100%;
      padding: 2.5rem 2rem;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 1.5rem;
      backdrop-filter: blur(16px);
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.6);
    }
    .icon {
      width: 64px;
      height: 64px;
      margin: 0 auto 1.5rem;
      display: flex;
      align-items: center;
      justify-content: center;
      border-radius: 1.25rem;
      background: rgba(239, 68, 68, 0.12);
      border: 1px solid rgba(239, 68, 68, 0.25);
      color: #ef4444;
      font-size: 2rem;
    }
    h1 {
      margin: 0 0 0.5rem;
      font-size: 1.5rem;
      font-weight: 800;
      letter-spacing: -0.025em;
    }
    p {
      margin: 0 0 1.75rem;
      font-size: 0.9rem;
      color: rgba(255, 255, 255, 0.6);
      line-height: 1.6;
    }
    button {
      padding: 0.75rem 2rem;
      background: #06b6d4;
      color: #000;
      border: none;
      border-radius: 0.75rem;
      font-weight: 800;
      font-size: 0.875rem;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      cursor: pointer;
      transition: all 0.2s ease;
      box-shadow: 0 0 24px rgba(6, 182, 212, 0.3);
    }
    button:hover {
      background: #22d3ee;
      transform: translateY(-2px);
      box-shadow: 0 0 32px rgba(34, 211, 238, 0.5);
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <line x1="1" y1="1" x2="23" y2="23"></line>
        <path d="M16.72 11.06A10.94 10.94 0 0 1 19 12.55"></path>
        <path d="M5 12.55a10.94 10.94 0 0 1 5.17-2.39"></path>
        <path d="M10.71 5.05A16 16 0 0 1 22.58 9"></path>
        <path d="M1.42 9a15.91 15.91 0 0 1 4.7-2.88"></path>
        <path d="M8.53 16.11a6 6 0 0 1 6.95 0"></path>
        <line x1="12" y1="20" x2="12.01" y2="20"></line>
      </svg>
    </div>
    <h1>Mất kết nối Internet</h1>
    <p>Không thể kết nối đến máy chủ ShieldCall VN. Vui lòng kiểm tra lại đường truyền internet của bạn.</p>
    <button onclick="window.location.reload()">Thử lại</button>
  </div>
</body>
</html>`;

interface PushNotificationData {
  url?: string;
  [key: string]: unknown;
}

interface PushPayload {
  title?: string;
  body?: string;
  message?: string;
  url?: string;
  tag?: string;
  icon?: string;
  badge?: string;
  data?: PushNotificationData;
  actions?: Array<{
    action: string;
    title: string;
    icon?: string;
  }>;
  requireInteraction?: boolean;
  renotify?: boolean;
}

interface ExtendedNotificationOptions extends NotificationOptions {
  renotify?: boolean;
  actions?: Array<{
    action: string;
    title: string;
    icon?: string;
  }>;
}

// 1. Lifecycle: Install
sw.addEventListener('install', (event: ExtendableEvent) => {
  event.waitUntil(
    (async () => {
      try {
        const cache = await caches.open(STATIC_CACHE);
        await cache.addAll(PRECACHE_ASSETS);
      } catch {
        // Precache fail does not abort install
      }
      await sw.skipWaiting();
    })()
  );
});

// 2. Lifecycle: Activate (Cache Cleanup)
sw.addEventListener('activate', (event: ExtendableEvent) => {
  event.waitUntil(
    (async () => {
      const keys = await caches.keys();
      await Promise.all(
        keys.map((key) => {
          if (!ALL_ACTIVE_CACHES.includes(key)) {
            return caches.delete(key);
          }
          return Promise.resolve(true);
        })
      );
      await sw.clients.claim();
    })()
  );
});

// 3. Web Push Notifications
sw.addEventListener('push', (event: PushEvent) => {
  let payload: PushPayload = {};
  if (event.data) {
    try {
      payload = event.data.json();
    } catch {
      payload = { message: event.data.text() };
    }
  }

  const title = payload.title || 'ShieldCall VN';
  const body = payload.body || payload.message || 'Bạn có thông báo mới từ hệ thống bảo mật.';
  const url = payload.url || (payload.data && payload.data.url) || '/dashboard/';
  const tag = payload.tag || 'shieldcall-push';
  const icon = payload.icon || '/web-app-manifest-192x192.png';
  const badge = payload.badge || '/favicon-96x96.png';

  const notificationOptions: ExtendedNotificationOptions = {
    body,
    icon,
    badge,
    tag,
    data: { url },
    renotify: payload.renotify ?? false,
    requireInteraction: payload.requireInteraction ?? false,
    actions: payload.actions || [
      { action: 'open', title: 'Xem chi tiết' },
      { action: 'dismiss', title: 'Đóng' },
    ],
  };

  event.waitUntil(sw.registration.showNotification(title, notificationOptions));
});

// 4. Notification Click & Action Handling
sw.addEventListener('notificationclick', (event: NotificationEvent) => {
  event.notification.close();

  if (event.action === 'dismiss') {
    return;
  }

  const data = event.notification.data as PushNotificationData | undefined;
  const targetUrl = data?.url || '/dashboard/';

  event.waitUntil(
    sw.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(async (windowClients: readonly Client[]) => {
      for (const client of windowClients) {
        const winClient = client as WindowClient;
        if (winClient.url === targetUrl && 'focus' in winClient) {
          return winClient.focus();
        }
      }
      for (const client of windowClients) {
        const winClient = client as WindowClient;
        if ('navigate' in winClient) {
          winClient.postMessage({ type: 'push_click', url: targetUrl });
          const navigated = await winClient.navigate(targetUrl);
          if (navigated && 'focus' in navigated) {
            return navigated.focus();
          }
          if ('focus' in winClient) {
            return winClient.focus();
          }
        }
      }
      if (sw.clients.openWindow) {
        return sw.clients.openWindow(targetUrl);
      }
      return null;
    })
  );
});

// 5. Client Messages (SKIP_WAITING, GET_VERSION, CLEAR_CACHE)
sw.addEventListener('message', (event: ExtendableMessageEvent) => {
  const data = event.data as { type?: string } | undefined;
  if (!data?.type) return;

  if (data.type === 'SKIP_WAITING') {
    void sw.skipWaiting();
  } else if (data.type === 'GET_VERSION') {
    event.ports?.[0]?.postMessage({ version: SW_VERSION });
  } else if (data.type === 'CLEAR_CACHE') {
    event.waitUntil(
      (async () => {
        const keys = await caches.keys();
        await Promise.all(keys.map((k) => caches.delete(k)));
        event.ports?.[0]?.postMessage({ cleared: true });
      })()
    );
  }
});

// 6. Fetch Interceptor & Caching Engine
sw.addEventListener('fetch', (event: FetchEvent) => {
  const req = event.request;

  // Strict bypass: Only intercept GET
  if (req.method !== 'GET') {
    return;
  }

  const url = new URL(req.url);

  // Strict bypass: non-HTTP protocols
  if (!url.protocol.startsWith('http')) {
    return;
  }

  // Strict bypass: Next.js dev HMR, WebSockets, SSE streams
  if (
    url.pathname.includes('/ws/') ||
    url.pathname.includes('/analyze-sse/') ||
    url.pathname.includes('/_next/webpack-hmr') ||
    url.pathname.includes('/_next/turbopack-hmr') ||
    url.pathname.includes('__nextjs_original-stack-frame') ||
    req.headers.get('accept')?.includes('text/event-stream')
  ) {
    return;
  }

  // Strict bypass: Next.js dynamic internals, WebSockets, API, Backend auth, admin, media
  if (
    (url.pathname.startsWith('/_next/') && !url.pathname.startsWith('/_next/static/')) ||
    url.pathname.startsWith('/ws/') ||
    url.pathname.startsWith('/api/') ||
    url.pathname.startsWith('/accounts/') ||
    url.pathname.startsWith('/admin-cp/') ||
    url.pathname.startsWith('/media/') ||
    url.pathname.startsWith('/ai-assistant/')
  ) {
    return;
  }

  // Strict bypass: 3rd party providers (Cloudflare Turnstile, Google, YouTube)
  if (
    url.hostname.includes('challenges.cloudflare.com') ||
    url.hostname.includes('cloudflareinsights.com') ||
    url.hostname.includes('googleapis.com') ||
    url.hostname.includes('gstatic.com') ||
    url.hostname.includes('google.com') ||
    url.hostname.includes('youtube.com') ||
    url.hostname.includes('google-analytics.com')
  ) {
    return;
  }

  // Strategy A: Navigation requests (HTML) -> Network-First with Offline Fallback
  if (req.mode === 'navigate') {
    event.respondWith(
      (async () => {
        try {
          const networkRes = await fetch(req);
          if (networkRes.ok && networkRes.status === 200 && networkRes.type === 'basic') {
            try {
              const cache = await caches.open(PAGES_CACHE);
              await cache.put(req, networkRes.clone());
            } catch {
              // Cache.put có thể lỗi (NetworkError / body bị cắt) — bỏ qua, không làm hỏng trang
            }
          }
          return networkRes;
        } catch {
          const cached = await caches.match(req);
          if (cached) return cached;
          return new Response(OFFLINE_HTML, {
            status: 503,
            headers: { 'Content-Type': 'text/html; charset=utf-8' },
          });
        }
      })()
    );
    return;
  }

  // Strategy B: Static assets -> Cache-First with Network Fallback
  const isStatic =
    url.pathname.startsWith('/_next/static/') ||
    url.pathname.startsWith('/static/') ||
    /\.(?:js|css|png|jpg|jpeg|svg|webp|ico|woff|woff2|ttf|json|webmanifest)$/i.test(url.pathname);

  if (isStatic) {
    event.respondWith(
      (async () => {
        const cached = await caches.match(req);
        if (cached) return cached;

        try {
          const networkRes = await fetch(req);
          if (networkRes.ok && networkRes.status === 200 && networkRes.type === 'basic') {
            try {
              const cache = await caches.open(STATIC_CACHE);
              await cache.put(req, networkRes.clone());
            } catch {
              // Bỏ qua lỗi cache (tránh "Cache.put() encountered a network error")
            }
          }
          return networkRes;
        } catch {
          return new Response(null, { status: 404, statusText: 'Not Found' });
        }
      })()
    );
    return;
  }
});
