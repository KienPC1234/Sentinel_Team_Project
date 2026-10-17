/* ShieldCall SSE stream reader.
 *
 * Giao thức: mỗi dòng `data:` là một JSON có `type` do backend phát ra:
 *   delta | thinking | status | metadata | tool_calls | tool_result | image
 *   | title | guardrail | error | done | debug_prompt
 *
 * Mọi consumer chỉ cần xử lý union StreamEvent ở dưới.
 */
import { getToken } from '../api';

export type StreamEvent =
  | { type: 'delta'; text: string }
  | { type: 'thinking'; text: string }
  | { type: 'status'; value: string }
  | { type: 'metadata'; metadata: Record<string, unknown> }
  | { type: 'tool_calls'; calls: unknown[] }
  | { type: 'tool_result'; tool: string; status?: string; args?: unknown; result?: unknown }
  | { type: 'image'; annotated_image: string }
  | { type: 'title'; value: string }
  | { type: 'guardrail'; guardrail: Record<string, unknown> }
  | { type: 'error'; message: string }
  | { type: 'done'; session_id?: string | null; title?: string; action_suggested?: string }
  | { type: 'debug_prompt'; messages: unknown };

export interface SseOptions {
  url: string;
  body?: unknown;
  signal?: AbortSignal;
  headers?: Record<string, string>;
  onEvent: (event: StreamEvent) => void;
  onParseError?: (err: unknown, line: string) => void;
}

function getCsrf(): string {
  const m = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]*)/);
  return m ? decodeURIComponent(m[1]) : '';
}

export class StreamHttpError extends Error {
  status: number;
  constructor(status: number) {
    super(`Stream request failed (HTTP ${status})`);
    this.status = status;
  }
}

function str(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

/** Chuẩn hoá 1 payload JSON của SSE thành StreamEvent. */
export function normalizeStreamEvent(raw: Record<string, unknown>): StreamEvent | null {
  if (typeof raw.type !== 'string') return null;
  switch (raw.type) {
    case 'delta': return { type: 'delta', text: str(raw.text) };
    case 'thinking': return { type: 'thinking', text: str(raw.text) };
    case 'status': return { type: 'status', value: str(raw.value) };
    case 'metadata': return { type: 'metadata', metadata: (raw.metadata as Record<string, unknown>) || {} };
    case 'tool_calls': return { type: 'tool_calls', calls: Array.isArray(raw.calls) ? raw.calls : [] };
    case 'tool_result':
      return { type: 'tool_result', tool: str(raw.tool), status: str(raw.status) || undefined, args: raw.args, result: raw.result };
    case 'image': return { type: 'image', annotated_image: str(raw.annotated_image) };
    case 'title': return { type: 'title', value: str(raw.value) };
    case 'guardrail': return { type: 'guardrail', guardrail: (raw.guardrail as Record<string, unknown>) || {} };
    case 'error': return { type: 'error', message: str(raw.message) || 'Lỗi không xác định' };
    case 'debug_prompt': return { type: 'debug_prompt', messages: raw.messages };
    case 'done':
      return {
        type: 'done',
        session_id: (raw.session_id as string) ?? null,
        title: str(raw.title) || undefined,
        action_suggested: str(raw.action_suggested) || undefined,
      };
    default: return null;
  }
}

export async function openSseStream(opts: SseOptions): Promise<void> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-CSRFToken': getCsrf(),
    ...(opts.headers || {}),
  };
  const token = getToken();
  if (token && !headers['Authorization']) headers['Authorization'] = `Token ${token}`;

  const response = await fetch(opts.url, {
    method: 'POST',
    headers,
    credentials: 'include',
    cache: 'no-store',
    signal: opts.signal,
    body: opts.body != null ? JSON.stringify(opts.body) : undefined,
  });
  if (!response.ok) throw new StreamHttpError(response.status);
  if (!response.body || typeof response.body.getReader !== 'function') {
    throw new Error('Streaming is not supported by this browser/response');
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  for (;;) {
    const { value, done } = await reader.read();
    if (done) {
      if (buffer.trim()) buffer += '\n';
    } else {
      buffer += decoder.decode(value, { stream: true });
    }
    const lines = buffer.split('\n');
    buffer = done ? '' : (lines.pop() as string);
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      if (trimmed.charAt(0) === ':') continue; // SSE comment / keep-alive
      if (trimmed.indexOf('data:') !== 0) continue;
      const raw = trimmed.slice(5).replace(/^\s+/, '');
      try {
        const parsed = JSON.parse(raw) as Record<string, unknown>;
        const event = normalizeStreamEvent(parsed);
        if (event) opts.onEvent(event);
      } catch (parseErr) {
        if (opts.onParseError) {
          try {
            opts.onParseError(parseErr, trimmed);
          } catch {
            /* ignore */
          }
        } else {
          console.warn('SSE parse error', parseErr);
        }
      }
    }
    if (done) break;
  }
}
