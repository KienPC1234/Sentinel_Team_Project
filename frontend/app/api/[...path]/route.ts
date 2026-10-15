import type { NextRequest } from 'next/server';

/* BFF proxy /api/* -> Django. Giữ nguyên path + query (kể cả trailing slash)
 * để không vướng APPEND_SLASH 301 của Django. Forward Authorization/Cookies,
 * stream nguyên response (kể cả SSE) về client.
 */

const API_TARGET = process.env.API_TARGET || 'http://127.0.0.1:8001';

export const dynamic = 'force-dynamic';

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
  headers.set('x-forwarded-proto', req.headers.get('x-forwarded-proto') || 'https');
  const clientIp = req.headers.get('x-forwarded-for') || req.headers.get('cf-connecting-ip');
  if (clientIp) {
    headers.set('x-forwarded-for', clientIp);
  }

  const hasBody = req.method !== 'GET' && req.method !== 'HEAD';
  const body = hasBody ? Buffer.from(await req.arrayBuffer()) : undefined;
  if (body) {
    headers.set('content-length', String(body.byteLength));
  }

  try {
    const upstream = await fetch(target, {
      method: req.method,
      headers,
      body,
      redirect: 'manual',
    });
    const out = new Headers();
    upstream.headers.forEach((v, k) => {
      if (!HOP_BY_HOP.has(k.toLowerCase())) out.set(k, v);
    });
    return new Response(upstream.body, { status: upstream.status, headers: out });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[API Proxy Error] Failed to proxy to ${target}:`, msg);
    return new Response(JSON.stringify({ error: 'Backend service unavailable', details: msg }), {
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
