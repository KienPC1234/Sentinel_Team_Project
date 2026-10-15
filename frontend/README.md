# ShieldCall VN — Frontend Next.js (tách riêng)

Giao diện Next.js 16 (App Router) + Tailwind v4, port 1-1 từ template Django
(`PKV/templates/`). Bản HTML gốc được **giữ nguyên để đối chiếu** — component
ở đây map trực tiếp từ class/markup bản gốc (xem `PORT_MAP`).

## Chạy dev

```bash
cd frontend
npm install
npm run dev          # http://127.0.0.1:3000, /api/* rewrite về Django
```

Django chạy ở `http://127.0.0.1:8001` (đổi qua biến `API_TARGET`).
Biến client (`NEXT_PUBLIC_*`): `NEXT_PUBLIC_API_BASE_URL` (mặc định `/api/v1`),
`NEXT_PUBLIC_DJANGO_URL` (link sang bản gốc cho trang ngoài), `NEXT_PUBLIC_TURNSTILE_SITEKEY`.

## Build / chạy production

```bash
npm run build
npm run start        # hoặc deploy Vercel / Node + Nginx
```

## Cấu trúc

```
app/                  # App Router — URL giữ nguyên path Django (trailingSlash)
  page.tsx            # /
  scan/phone|.../     # 9 trang scan + lookup + status/[id]
  ai-assistant/       # chat full + [sessionId]
  forum/ report/ ...  # forum, report, radar, learn, auth, admin-cp (60 routes)
  layout.tsx          # Navbar + Footer + ChatWidget toàn cục
  not-found.tsx       # trang 404
src/
  views/              # page components (client), 1 file ~ 1 template gốc
  components/         # ui.tsx, Layout.tsx (Navbar/Footer), ChatWidget.tsx,
                      # ScanWidgets.tsx, AuthContext.tsx, RouteShell.tsx
  lib/
    api.ts            # client DRF (/api/v1) + token + djangoUrl()
    chat/markdown.ts  # port từ PKV/static/js/chat/markdown.js
    chat/stream.ts    # port từ PKV/static/js/chat/stream.js (SSE)
  app/globals.css     # tokens + .liquid-* (port từ liquid-glass.css)
```

`next.config.ts`: `trailingSlash: true` (khớp URL Django) + rewrite
`/media/*` về Django. Riêng `/api/*` đi qua route handler
`app/api/[...path]/route.ts` (giữ nguyên trailing slash để không vướng
APPEND_SLASH 301 của Django, forward token/cookie, stream SSE nguyên vẹn).

## Quy ước port trang mới

1. Đọc template gốc, giữ nguyên class Tailwind + text tiếng Việt.
2. Đặt component vào `src/views/`, route vào `app/<path-django>/page.tsx` bọc `<RouteShell>`.
3. Mọi component dùng hook đều cần `'use client'` ở dòng đầu.
4. Link nội bộ: `next/link` với `href` = path Django. Trang ngoài dùng `djangoUrl()`.
5. `{{ var }}` từ view -> fetch API, fallback giống `|default` bản gốc.
6. `window.renderMd` -> `renderMd()` từ `lib/chat/markdown`, render qua `MarkdownView`.
7. Không chạm `window/document/localStorage` lúc render (chỉ trong `useEffect`/handler) — Next prerender sẽ gãy build.
8. Query string: đọc trong `useEffect` (xem `Scan/Phone.tsx`), dynamic segment qua `useParams()` từ `next/navigation`.
