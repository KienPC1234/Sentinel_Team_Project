import type { NextRequest } from 'next/server';

/* BFF proxy /api/* -> Django. Giữ nguyên path + query (kể cả trailing slash)
 * để không vướng APPEND_SLASH 301 của Django. Forward Authorization/Cookies,
 * stream nguyên response (kể cả SSE) về client.
 */

const API_TARGET = process.env.API_TARGET || 'http://127.0.0.1:8001';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

const HOP_BY_HOP = new Set([
  'host',
  'connection',
  'keep-alive',
  'transfer-encoding',
  'upgrade',
  'content-length',
]);

async function proxy(req: NextRequest, path: string[]): Promise<Response> {
  const url = new URL(req.url);
  // Giữ nguyên trailing slash (Django APPEND_SLASH sẽ 301 loop nếu mất).
  const slash = url.pathname.endsWith('/') ? '/' : '';
  const target = `${API_TARGET}/api/${path.join('/')}${slash}${url.search}`;
  const headers = new Headers();
  req.headers.forEach((v, k) => {
    if (!HOP_BY_HOP.has(k.toLowerCase())) headers.set(k, v);
  });

  const hostHeader = req.headers.get('x-forwarded-host') || req.headers.get('host') || 'sc.fptoj.com';
  headers.set('x-forwarded-host', hostHeader);
  headers.set(
    'x-forwarded-proto',
    req.headers.get('x-forwarded-proto') || req.nextUrl.protocol.replace(':', ''),
  );
  const clientIp = req.headers.get('x-forwarded-for') || req.headers.get('cf-connecting-ip');
  if (clientIp) {
    headers.set('x-forwarded-for', clientIp);
  }

  const hasBody = req.method !== 'GET' && req.method !== 'HEAD';
  const acceptsSse = (req.headers.get('accept') || '').includes('text/event-stream');
  const isStream = acceptsSse || /(?:^|\/)(?:stream|sse)(?:\/|$)|-sse(?:\/|$)/.test(`/${path.join('/')}`);

  // Stream request bodies instead of buffering 100 MB uploads in the Next
  // process. SSE/long-running scans get no client-side abort; normal JSON
  // requests keep a generous 10-minute safety timeout.
  const init: RequestInit & { duplex?: 'half' } = {
    method: req.method,
    headers,
    body: hasBody ? req.body : undefined,
    redirect: 'manual',
    cache: 'no-store',
    signal: isStream ? undefined : AbortSignal.timeout(10 * 60_000),
  };
  if (hasBody) init.duplex = 'half';

  try {
    const upstream = await fetch(target, init);
    const out = new Headers();
    upstream.headers.forEach((v, k) => {
      if (!HOP_BY_HOP.has(k.toLowerCase())) out.set(k, v);
    });
    return new Response(upstream.body, { status: upstream.status, headers: out });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[API Proxy Error] Failed to proxy to ${target}:`, msg);
    return new Response(JSON.stringify({ error: 'Backend service unavailable', code: 'UPSTREAM_UNAVAILABLE' }), {
      status: 502,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

function handler(path: string[]) {
  return (req: NextRequest) => proxy(req, path);
}

export function GET(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  return ctx.params.then((p) => handler(p.path)(req));
}
export function HEAD(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  return ctx.params.then((p) => handler(p.path)(req));
}
export function POST(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  return ctx.params.then((p) => handler(p.path)(req));
}
export function PUT(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  return ctx.params.then((p) => handler(p.path)(req));
}
export function PATCH(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  return ctx.params.then((p) => handler(p.path)(req));
}
export function DELETE(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  return ctx.params.then((p) => handler(p.path)(req));
}
export function OPTIONS(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  return ctx.params.then((p) => handler(p.path)(req));
}
