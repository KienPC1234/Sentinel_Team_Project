import type { NextRequest } from 'next/server';

/* Proxy Django admin (/admin/**) sang backend, giữ nguyên đường dẫn + query + method.
 * Dùng route handler (không dùng rewrite) vì Next chuẩn hoá mất dấu '/' cuối khi rewrite,
 * khiến Django APPEND_SLASH trả 301 về chính nó → vòng lặp. */

const API_TARGET = process.env.API_TARGET || 'http://127.0.0.1:8001';

async function proxy(req: NextRequest, ctx: { params: Promise<{ path?: string[] }> }) {
  const { path } = await ctx.params;
  const seg = (path || []).join('/');
  const target = `${API_TARGET}/admin/${seg ? `${seg}/` : ''}${req.nextUrl.search}`;

  const headers = new Headers(req.headers);
  headers.set('host', new URL(API_TARGET).host);
  headers.set('accept-encoding', 'identity');
  headers.delete('content-length');
  headers.delete('connection');

  const hasBody = !['GET', 'HEAD'].includes(req.method);
  const body = hasBody ? await req.arrayBuffer() : undefined;

  const upstream = await fetch(target, {
    method: req.method,
    headers,
    body,
    redirect: 'manual',
  });

  const out = new Headers(upstream.headers);
  out.delete('content-length');
  out.delete('transfer-encoding');

  return new Response(upstream.body, { status: upstream.status, headers: out });
}

export const GET = proxy;
export const POST = proxy;
export const PUT = proxy;
export const PATCH = proxy;
export const DELETE = proxy;
export const HEAD = proxy;
export const dynamic = 'force-dynamic';
