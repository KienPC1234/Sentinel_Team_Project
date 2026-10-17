'use client';
/* ShieldCall Scan — shared widgets port từ PKV/templates/Scan/_osint_section.html,
 * _scan_guide.html + logic dùng chung (Turnstile, WS/polling tracker, toast).
 * Giao diện giữ y class Tailwind + text tiếng Việt bản Django gốc.
 */
import { useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import Link from 'next/link';
import { api } from '../lib/api';

import { renderMd } from '../lib/chat/markdown';
import { MarkdownView } from './ui';

/* ============ Kiểu dữ liệu chung ============ */

export type AnyRec = Record<string, unknown>;

export interface ScanResult extends AnyRec {
  risk_score?: number;
  risk_level?: string;
  explanation?: string;
  ai_insight?: string;
  web_context?: string;
  web_sources?: string[];
  searched_urls?: string[];
  patterns_found?: unknown[];
  scam_type?: string;
  status?: string;
}

export type WsState =
  | 'idle'
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  | 'disconnected'
  | 'completed'
  | 'failed';

export interface ProgressItem {
  message: string;
  step: string;
}

export function asStr(v: unknown, fallback = ''): string {
  return typeof v === 'string' ? v : fallback;
}

export function asNum(v: unknown, fallback = 0): number {
  return typeof v === 'number' && Number.isFinite(v) ? v : fallback;
}

export function asArr<T>(v: unknown): T[] {
  return Array.isArray(v) ? (v as T[]) : [];
}

/* ============ Guardrail verdict helpers (góp ý hội đồng #1) ============
 * Ưu tiên NHÃN GUARDRAIL thay vì risk_level thô, để UI KHÔNG hiển thị
 * "An toàn"/"GREEN" khi hệ thống CHƯA ĐỦ CƠ SỞ XÁC MINH. */
const GUARDRAIL_TONE: Record<string, string> = {
  CONFIRMED_RISK: 'RED',
  HIGH_RISK: 'RED',
  SUSPICIOUS: 'YELLOW',
  LIKELY_SAFE: 'SAFE',
  INSUFFICIENT: 'UNVERIFIED',
};

export function guardrailTone(result: ScanResult | null | undefined): string {
  const g = (result?.['guardrail'] || {}) as Record<string, unknown>;
  const tier = asStr(g['tier']);
  if (tier && GUARDRAIL_TONE[tier]) return GUARDRAIL_TONE[tier];
  // Không có guardrail (dữ liệu cũ): KHÔNG coi GREEN/SAFE là đã xác minh.
  const level = asStr(result?.['risk_level']).toUpperCase();
  if (level === 'RED' || level === 'HIGH' || level === 'CRITICAL') return 'RED';
  if (level === 'YELLOW' || level === 'MEDIUM') return 'YELLOW';
  if (level === 'GREEN' || level === 'SAFE' || level === '') return 'UNVERIFIED';
  return level;
}

const RAW_LEVEL_VI: Record<string, string> = {
  RED: 'Nguy cơ cao',
  CRITICAL: 'Nguy hiểm',
  HIGH: 'Nguy cơ cao',
  YELLOW: 'Cần thận trọng',
  MEDIUM: 'Cần thận trọng',
};

export function guardrailLabel(result: ScanResult | null | undefined): string {
  const g = (result?.['guardrail'] || {}) as Record<string, unknown>;
  const label = asStr(g['label']);
  if (label) return label;
  // Không guardrail (dữ liệu cũ): KHÔNG trả về nhãn tiếng Anh thô như "SAFE"/"GREEN"
  // (dễ gây hiểu nhầm là đã xác minh an toàn). Mức thấp -> "CHƯA ĐỦ CƠ SỞ XÁC MINH".
  const level = asStr(result?.['risk_level']).toUpperCase();
  return RAW_LEVEL_VI[level] || 'CHƯA ĐỦ CƠ SỞ XÁC MINH';
}

export function apiBase(): string {
  return (process.env.NEXT_PUBLIC_API_BASE_URL as string | undefined) || '/api/v1';
}

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '0.0.0.0']);

export function wsBase(): string {
  const envWs = process.env.NEXT_PUBLIC_WS_BASE_URL as string | undefined;
  if (envWs && envWs.trim()) return envWs.trim().replace(/\/+$/, '');
  const djangoBase = process.env.NEXT_PUBLIC_DJANGO_URL as string | undefined;
  if (djangoBase && /^https?:\/\//i.test(djangoBase)) {
    return djangoBase.replace(/^http/i, 'ws').replace(/\/+$/, '');
  }
  if (typeof window === 'undefined') return 'ws://127.0.0.1:8001';
  const { protocol, hostname, port, host } = window.location;
  const proto = protocol === 'https:' ? 'wss:' : 'ws:';
  // Dev: `next start` (3000) không nâng cấp được WebSocket -> nối thẳng Daphne (8001).
  // Production nên đặt NEXT_PUBLIC_WS_BASE_URL hoặc để reverse proxy route /ws/.
  if (LOOPBACK_HOSTS.has(hostname) || port === '3000') {
    return `${proto}//${hostname}:8001`;
  }
  return `${proto}//${host}`;
}

/* Styles are loaded statically via liquid-glass.css */
export function ensureScanStyles(): void {
  /* no-op: styles are loaded statically */
}

import { showToast } from '../lib/ui/feedback';
export { showToast };
export type { ToastType } from '../lib/ui/feedback';

export function copyText(text: string, okMsg = 'Đã sao chép!'): void {
  if (!text) return;
  try {
    void navigator.clipboard.writeText(text).then(
      () => showToast(okMsg, 'success'),
      () => showToast('Không thể sao chép.', 'error'),
    );
  } catch {
    showToast('Không thể sao chép.', 'error');
  }
}

/** Giữ tương thích event chat của base.html (trang React chưa có widget chat). */
export function dispatchChat(context: string): void {
  try {
    window.dispatchEvent(new CustomEvent('start-contextual-chat', { detail: { context } }));
  } catch {
    /* bỏ qua */
  }
}

/* ============ Turnstile INVISIBLE, explicit render ============
 * Chạy ngầm, không hiện checkbox. Luồng:
 * - script nạp lazy (?render=explicit) khi form mount,
 * - turnstile.execute() sinh token dùng-một-lần (sống 5 phút),
 * - token hết hạn / lỗi / đã submit -> reset + execute lại để cấp token mới.
 * Backend verify qua siteverify (api/utils/security.py đã có).
 */

declare global {
  interface Window {
    turnstile?: {
      render: (el: HTMLElement, opts: Record<string, unknown>) => string;
      execute: (el: HTMLElement | string, opts?: Record<string, unknown>) => string | undefined;
      reset: (widget?: string | HTMLElement) => void;
      remove: (widget?: string | HTMLElement) => void;
    };
    onloadTurnstileCallback?: () => void;
  }
}

let tsScriptPromise: Promise<void> | null = null;
function loadTsScript(): Promise<void> {
  if (typeof document === 'undefined') return Promise.resolve();
  if (window.turnstile) return Promise.resolve();
  if (!tsScriptPromise) {
    tsScriptPromise = new Promise<void>((resolve) => {
      const s = document.createElement('script');
      s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
      s.async = true;
      s.defer = true;
      s.onload = () => resolve();
      s.onerror = () => resolve();
      document.head.appendChild(s);
      // Fallback: đừng treo form nếu script bị chặn
      window.setTimeout(() => resolve(), 8000);
    });
  }
  return tsScriptPromise;
}

const tsWidgets = new Map<string, HTMLElement>();

/** Reset + cấp token mới (token chỉ dùng 1 lần / sống 5 phút).
 * Gọi sau mỗi lần submit (kể cả lỗi) để lần gửi sau có token tươi. */
export function resetTurnstile(): void {
  try {
    if (!window.turnstile) return;
    if (tsWidgets.size === 0) {
      window.turnstile.reset();
      return;
    }
    tsWidgets.forEach((_el, id) => {
      try {
        window.turnstile?.reset(id);
      } catch {
        /* ignore */
      }
    });
  } catch {
    /* bỏ qua */
  }
}

export function TurnstileWidget({ onToken }: { onToken?: (token: string) => void }): ReactNode {
  const boxRef = useRef<HTMLDivElement>(null);
  const [token, setToken] = useState('');
  const [expired, setExpired] = useState(false);
  const siteKey = (process.env.NEXT_PUBLIC_TURNSTILE_SITEKEY as string | undefined) || '';

  useEffect(() => {
    if (!siteKey) return;
    let alive = true;
    let wid = '';
    const push = (tok: string) => {
      if (!alive) return;
      setToken(tok);
      if (tok) setExpired(false);
      if (onToken) onToken(tok);
    };
    void loadTsScript().then(() => {
      if (!alive || !boxRef.current || !window.turnstile) return;
      try {
        const id = window.turnstile.render(boxRef.current, {
          sitekey: siteKey,
          theme: 'dark',
          callback: (t: unknown) => push(typeof t === 'string' ? t : ''),
          'expired-callback': () => {
            /* Token sống ~5 phút. Tự reset để hiện thử thách mới ngay thay vì
             * để form kẹt ở trạng thái "chưa xác minh" mà không rõ lý do. */
            push('');
            setExpired(true);
            try {
              window.turnstile?.reset(wid || undefined);
            } catch {
              /* ignore */
            }
          },
          'error-callback': () => push(''),
        });
        wid = typeof id === 'string' ? id : '';
        if (wid) tsWidgets.set(wid, boxRef.current);
      } catch (e) {
        console.error('Turnstile render error', e);
      }
    });
    return () => {
      alive = false;
      try {
        if (wid) {
          tsWidgets.delete(wid);
          window.turnstile?.remove?.(wid);
        }
      } catch {
        /* ignore */
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [siteKey]);

  if (!siteKey) {
    return (
      <div className="mt-4 flex justify-center">
        <p className="text-white/55 text-xs italic">
          Xác minh anti-spam chưa được cấu hình (thiếu NEXT_PUBLIC_TURNSTILE_SITEKEY).
        </p>
        <input type="hidden" name="cf-turnstile-response" value="" readOnly />
      </div>
    );
  }

  return (
    <div className="mt-4 flex flex-col items-center gap-1 min-h-[65px]">
      <div ref={boxRef} className="cf-turnstile" />
      {expired && !token && (
        <p className="text-warn-400 text-[11px] font-bold">Xác minh đã hết hạn — vui lòng xác minh lại.</p>
      )}
      <input type="hidden" name="cf-turnstile-response" value={token} readOnly />
    </div>
  );
}

/** Đọc token anti-spam y cách bản gốc (querySelector input ẩn). */
export function getTsToken(): string {
  try {
    const el = document.querySelector<HTMLInputElement>('[name=cf-turnstile-response]');
    return el?.value || '';
  } catch {
    return '';
  }
}

/* ============ Tracker WS + polling (port logic Alpine bản gốc) ============ */

export interface TrackerDone {
  result: ScanResult;
  risk_score: number;
  risk_level: string;
  scan_type: string;
}

function toDone(data: AnyRec): TrackerDone {
  const inner = (data['result'] as AnyRec | null) || data;
  const rec = (typeof inner === 'object' && inner !== null ? inner : data) as ScanResult;
  return {
    result: { ...rec },
    risk_score: asNum(data['risk_score'] ?? rec.risk_score),
    risk_level: asStr(data['risk_level'] ?? rec.risk_level),
    scan_type: asStr(data['scan_type'] ?? rec.scan_type),
  };
}

interface StatusPayload {
  status?: string;
  scan_type?: string;
  risk_score?: number;
  risk_level?: string;
  result?: ScanResult | null;
}

export function useScanTracker(
  scanId: number | null,
  opts: {
    enabled: boolean;
    pollMs?: number;
    onDone?: (d: TrackerDone) => void;
    onError?: (msg: string) => void;
    onTranscript?: (text: string) => void;
  },
): { progress: ProgressItem[]; wsState: WsState; push: (message: string, step?: string) => void; clear: () => void } {
  const [progress, setProgress] = useState<ProgressItem[]>([]);
  const [wsState, setWsState] = useState<WsState>('idle');
  const cbRef = useRef(opts);
  cbRef.current = opts;

  const push = (message: string, step = ''): void => {
    setProgress((p) => [...p, { message, step }]);
  };
  const clear = (): void => {
    setProgress([]);
    setWsState('idle');
  };

  useEffect(() => {
    if (!opts.enabled || scanId == null) return;
    let alive = true;
    let finished = false;
    let ws: WebSocket | null = null;
    let pollTimer: number | null = null;
    let reconnectTimer: number | null = null;
    let attempts = 0;
    const maxAttempts = 6;
    const pollMs = opts.pollMs ?? 4000;

    let clientPingTimer: number | null = null;

    const stopTimers = (): void => {
      if (pollTimer != null) window.clearInterval(pollTimer);
      if (reconnectTimer != null) window.clearTimeout(reconnectTimer);
      if (clientPingTimer != null) window.clearInterval(clientPingTimer);
      pollTimer = null;
      reconnectTimer = null;
      clientPingTimer = null;
    };
    const finishOk = (data: AnyRec): void => {
      if (finished || !alive) return;
      finished = true;
      stopTimers();
      setWsState('completed');
      try {
        ws?.close();
      } catch {
        /* bỏ qua */
      }
      cbRef.current.onDone?.(toDone(data));
    };
    const finishErr = (msg: string): void => {
      if (finished || !alive) return;
      finished = true;
      stopTimers();
      setWsState('failed');
      try {
        ws?.close();
      } catch {
        /* bỏ qua */
      }
      cbRef.current.onError?.(msg);
    };
    let pollFailures = 0;
    const maxPollFailures = 8;
    const pollOnce = (): void => {
      if (finished || !alive) return;
      api
        .get<StatusPayload>(`/scan/status/${scanId}/`)
        .then((data) => {
          if (finished || !alive || !data) return;
          pollFailures = 0;
          const st = asStr(data.status).toLowerCase();
          if (st === 'completed' && data.result) {
            finishOk({ ...data, result: data.result });
          } else if (st === 'failed') {
            finishErr('Phân tích thất bại.');
          }
        })
        .catch((e: unknown) => {
          if (finished || !alive) return;
          // 403/404: không có quyền / không tồn tại -> dừng ngay, không poll vô hạn.
          const statusCode = (e as { status?: number } | null)?.status;
          if (statusCode === 403 || statusCode === 404) {
            finishErr('Không tìm thấy hoặc không có quyền xem phiên quét này.');
            return;
          }
          pollFailures += 1;
          if (pollFailures >= maxPollFailures) {
            finishErr('Không thể lấy trạng thái phân tích. Vui lòng thử lại sau.');
          }
        });
    };
    const scheduleReconnect = (): void => {
      if (finished || !alive) return;
      if (attempts >= maxAttempts) {
        setWsState('disconnected');
        push('Mất kết nối thời gian thực. Đang chuyển sang chế độ đồng bộ trạng thái.', 'warning');
        return;
      }
      attempts += 1;
      setWsState('reconnecting');
      const delay = Math.min(10000, 1000 * Math.pow(2, attempts - 1));
      if (reconnectTimer != null) window.clearTimeout(reconnectTimer);
      reconnectTimer = window.setTimeout(() => connect(true), delay);
    };
    const connect = (isReconnect: boolean): void => {
      if (finished || !alive) return;
      setWsState(isReconnect ? 'reconnecting' : 'connecting');
      if (!isReconnect) push('Đang kết nối với máy chủ...', 'init');
      let sock: WebSocket;
      try {
        sock = new WebSocket(`${wsBase()}/ws/scan/${scanId}/`);
      } catch {
        scheduleReconnect();
        return;
      }
      ws = sock;
      sock.onopen = () => {
        if (!alive || finished) return;
        setWsState('connected');
        attempts = 0;
        if (reconnectTimer != null) window.clearTimeout(reconnectTimer);
        if (isReconnect) push('Kết nối thời gian thực đã được khôi phục.', 'reconnected');
        try {
          sock.send(JSON.stringify({ type: 'get_status' }));
        } catch {
          /* bỏ qua */
        }
        if (clientPingTimer != null) window.clearInterval(clientPingTimer);
        clientPingTimer = window.setInterval(() => {
          if (sock && sock.readyState === WebSocket.OPEN) {
            try {
              sock.send(JSON.stringify({ type: 'ping' }));
            } catch {
              /* ignore */
            }
          }
        }, 20000);
      };
      sock.onmessage = (e: MessageEvent) => {
        if (!alive || finished) return;
        let data: AnyRec | null = null;
        try {
          data = JSON.parse(asStr((e as MessageEvent<string>).data)) as AnyRec;
        } catch {
          return;
        }
        if (!data) return;
        const step = asStr(data['step']);
        if (step === 'ping' || asStr(data['type']) === 'pong') return;
        const msg = asStr(data['message']);
        if (msg) push(msg, step);
        const inner = data['data'] as AnyRec | undefined;
        if (step === 'transcribed' && inner) {
          const t = asStr(inner['transcript']);
          if (t) cbRef.current.onTranscript?.(t);
        }
        if (step === 'completed' && inner) {
          finishOk(inner);
        } else if (step === 'error') {
          finishErr(msg || 'Phân tích thất bại.');
        }
      };
      sock.onerror = () => {
        /* chờ onclose xử lý */
      };
      sock.onclose = () => {
        if (clientPingTimer != null) {
          window.clearInterval(clientPingTimer);
          clientPingTimer = null;
        }
        if (!alive || finished) return;
        setWsState('disconnected');
        scheduleReconnect();
      };
    };

    connect(false);
    pollTimer = window.setInterval(pollOnce, pollMs);

    return () => {
      alive = false;
      stopTimers();
      try {
        ws?.close();
      } catch {
        /* bỏ qua */
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId, opts.enabled]);

  return { progress, wsState, push, clear };
}

/* ============ Khung trạng thái WS (badge + log) ============ */

const WS_OK: Record<string, string> = {
  connected: 'text-safe-400 border-safe-500/30 bg-safe-500/10',
  reconnecting: 'text-warn-400 border-warn-500/30 bg-warn-500/10',
  connecting: 'text-warn-400 border-warn-500/30 bg-warn-500/10',
};

export function WsBadge({ state, connectedLabel = 'WS Connected' }: { state: WsState; connectedLabel?: string }): ReactNode {
  const label =
    state === 'connected'
      ? connectedLabel
      : state === 'reconnecting'
        ? 'Reconnecting'
        : state === 'connecting'
          ? 'Connecting'
          : 'Disconnected';
  const cls = WS_OK[state] || 'text-danger-400 border-danger-500/30 bg-danger-500/10';
  return (
    <div className={`text-[10px] font-black uppercase tracking-wider px-2 py-1 rounded border ${cls}`}>{label}</div>
  );
}

const PROGRESS_ACCENT: Record<string, string> = {
  purple: 'border-brand2-500/20 bg-brand2-500/[0.02] text-brand2-400',
  blue: 'border-brand-500/20 bg-brand-500/[0.02] text-brand-400',
  cyan: 'border-brand-500/20 bg-brand-500/[0.02] text-brand-400',
  pink: 'border-brand2-500/20 bg-brand2-500/[0.02] text-brand2-400',
  violet: 'border-brand2-500/20 bg-brand2-500/[0.02] text-brand2-400',
};

export function ProgressConsole({
  title,
  progress,
  wsState,
  accent = 'cyan',
}: {
  title: string;
  progress: ProgressItem[];
  wsState: WsState;
  accent?: 'purple' | 'blue' | 'cyan' | 'pink' | 'violet';
}): ReactNode {
  const tone = PROGRESS_ACCENT[accent] || PROGRESS_ACCENT['cyan'];
  const [box, bar, label] = tone.split(' ');
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [progress]);

  return (
    <div className={`liquid-card p-6 ${box} ${bar} animate-fadein`}>
      <div className="mb-4 flex items-center justify-between gap-3">
        <h4 className={`text-[10px] font-black ${label} uppercase tracking-widest`}>{title}</h4>
        <div className="flex items-center gap-3">
          <span className="text-[10px] text-white/45 font-mono">{progress.length} bước</span>
          <WsBadge state={wsState} />
        </div>
      </div>
      <div className="w-full h-1 bg-white/5 rounded-full overflow-hidden mb-4">
        <div
          className="h-full bg-current opacity-50 transition-all duration-500 rounded-full"
          style={{ width: `${Math.min(95, progress.length * 12)}%` }}
        ></div>
      </div>
      <div ref={logRef} className="space-y-2.5 font-mono text-[11px] max-h-[300px] overflow-y-auto custom-scrollbar">
        {progress.map((item, index) => (
          <div key={index} className="flex items-start gap-3 animate-fadein">
            <span
              className={`flex-shrink-0 mt-0.5 ${
                item.step === 'completed'
                  ? 'text-safe-500'
                  : item.step.includes('warning')
                    ? 'text-warn-500'
                    : item.step === 'error'
                      ? 'text-danger-500'
                      : item.step.includes('ok') || item.step.includes('done')
                        ? 'text-safe-400'
                        : label
              }`}
            >
              <i
                className={`bi ${
                  item.step === 'completed'
                    ? 'bi-check-circle-fill'
                    : item.step.includes('warning')
                      ? 'bi-exclamation-triangle-fill'
                      : item.step === 'error'
                        ? 'bi-x-circle-fill'
                        : item.step.includes('ok') || item.step.includes('done')
                          ? 'bi-check2'
                          : index === progress.length - 1
                            ? 'bi-arrow-right'
                            : 'bi-dot'
                }`}
              ></i>
            </span>
            <span className="text-white/80 flex-1">{item.message}</span>
            {index === progress.length - 1 && item.step !== 'completed' && !item.step.includes('ok') && !item.step.includes('done') && (
              <i className={`bi bi-three-dots animate-pulse ${label} flex-shrink-0`}></i>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

/* ============ OsintSection (port _osint_section.html) ============ */

interface OsintSource {
  title: string;
  html: string;
}

function normalizeTitle(t: unknown): string {
  let c = asStr(t).trim().replace(/^\[+|\]+$/g, '');
  const lowered = c.toLowerCase();
  const marker = " cho '";
  const idx = lowered.indexOf(marker);
  if (idx > -1 && c.endsWith("'")) c = c.slice(0, idx);
  c = c.replace(/\]\s*$/, '');
  c = c.replace(/^Nguồn\s*:\s*/i, '').replace(/\s+/g, ' ').trim();
  return c || 'TỔNG HỢP TÌNH BÁO';
}

function isSummaryTitle(title: string): boolean {
  const n = title.toLowerCase();
  return n.includes('kết luận') || n.includes('tổng kết') || n.includes('tổng hợp');
}

function uniqList(items: string[]): string[] {
  const seen = new Set<string>();
  return items.filter((item) => {
    if (!item) return false;
    const key = item.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function parseOsintContext(raw: unknown, fallbackSources: unknown): { sources: OsintSource[]; badges: string[] } {
  const fb = asArr<string>(fallbackSources).map((s) => normalizeTitle(s)).filter((s) => !isSummaryTitle(s));
  const text = asStr(raw).replace(/<think>[\s\S]*?<\/think>/g, '').trim();
  if (!text) return { sources: [], badges: uniqList(fb) };

  const headerRe = /^###\s+(.+)$/gm;
  const headers: { title: string; end: number; nextIdx: number }[] = [];
  let m: RegExpExecArray | null;
  const matches: { title: string; index: number; length: number }[] = [];
  while ((m = headerRe.exec(text)) !== null) {
    matches.push({ title: m[1].replace(/^\[|\]$/g, '').trim(), index: m.index, length: m[0].length });
  }
  matches.forEach((h, i) => {
    headers.push({ title: h.title, end: h.index + h.length, nextIdx: i + 1 < matches.length ? matches[i + 1].index : text.length });
  });

  const conclusionRe = /(?:^|\n)([ \t]*\*{1,2}[ \t]*(?:Kết luận|Tổng kết)(?:[^\n*]*)\*{0,2}[ \t]*:[\s\S]*)$/im;
  const sources: OsintSource[] = [];
  const parsedBadges: string[] = [];
  let conclusionText = '';

  if (headers.length > 0) {
    for (const h of headers) {
      const title = normalizeTitle(h.title);
      if (title) parsedBadges.push(title);
      let content = text.slice(h.end, h.nextIdx).trim();
      if (content) {
        const cm = conclusionRe.exec(content);
        if (cm && cm[1]) {
          const extracted = cm[1].trim();
          conclusionText = conclusionText ? `${conclusionText}\n\n${extracted}` : extracted;
          content = content.replace(conclusionRe, '').trim();
        }
      }
      if (title && content) sources.push({ title, html: renderMd(content) });
    }
  } else {
    let rest = text;
    const cm = conclusionRe.exec(rest);
    if (cm && cm[1]) {
      conclusionText = cm[1].trim();
      rest = rest.replace(conclusionRe, '').trim();
    }
    if (rest) sources.push({ title: 'TỔNG HỢP TÌNH BÁO', html: renderMd(rest) });
  }
  if (conclusionText) sources.push({ title: 'KẾT LUẬN TỔNG THỂ', html: renderMd(conclusionText) });

  const filtered = uniqList(parsedBadges.filter((s) => !isSummaryTitle(s)));
  return { sources, badges: filtered.length > 0 ? filtered : uniqList(fb) };
}

function shortUrl(u: string): string {
  if (u.startsWith('search:')) return u.slice(7);
  if (u.startsWith('http')) {
    try {
      const url = new URL(u);
      return url.hostname + url.pathname.slice(0, 30);
    } catch {
      return u;
    }
  }
  return u;
}

function urlIcon(u: string): string {
  if (u.startsWith('search:')) return 'bi bi-search';
  if (u.includes(':') && !u.startsWith('http')) return 'bi bi-database';
  return 'bi bi-link-45deg';
}

export function OsintSection({ result }: { result: ScanResult }): ReactNode {
  const [expanded, setExpanded] = useState(false);
  const webContext = asStr(result['web_context']);
  const webSources = asArr<string>(result['web_sources']);
  const searchedUrls = asArr<string>(result['searched_urls']);
  if (!webContext && webSources.length === 0) return null;

  const parsed = parseOsintContext(webContext, webSources);
  const visible = expanded ? parsed.sources : parsed.sources.slice(0, 6);

  return (
    <div className="p-8 border-t border-white/5 bg-white/[0.01]">
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 rounded-xl bg-brand-500/20 flex items-center justify-center text-brand-400">
          <i className="bi bi-search"></i>
        </div>
        <div className="flex-1">
          <h4 className="text-sm font-black text-white uppercase tracking-wider">Thông tin tình báo (OSINT)</h4>
          <p className="text-[10px] text-white/55 font-bold uppercase tracking-widest">Grounded Proofs &amp; Sources</p>
        </div>
        <div className="flex items-center gap-2">
          {parsed.badges.length > 0 && (
            <span className="px-3 py-1.5 rounded-xl bg-brand-500/10 text-brand-400 text-[10px] font-black border border-brand-500/20">
              <i className="bi bi-database-check mr-1"></i>{parsed.badges.length} nguồn
            </span>
          )}
          {searchedUrls.length > 0 && (
            <span className="px-3 py-1.5 rounded-xl bg-brand2-500/10 text-brand2-400 text-[10px] font-black border border-brand2-500/20">
              <i className="bi bi-globe2 mr-1"></i>{searchedUrls.length} tra cứu
            </span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6">
        {parsed.badges.length > 0 && (
          <div className="flex flex-wrap gap-2 mb-2">
            {parsed.badges.map((source) => (
              <span key={source} className="px-3 py-1 rounded-full bg-brand-500/10 text-brand-400 text-[10px] font-black border border-brand-500/20 uppercase">
                {source}
              </span>
            ))}
          </div>
        )}

        {searchedUrls.length > 0 && (
          <div className="p-4 rounded-xl bg-white/[0.02] border border-white/[0.06] mb-2">
            <h5 className="text-[10px] font-black text-white/45 uppercase tracking-widest mb-2">
              <i className="bi bi-globe2 me-1"></i>AI đã tra cứu
            </h5>
            <div className="flex flex-wrap gap-1.5">
              {searchedUrls.map((surl, si) => (
                <span
                  key={si}
                  className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-white/5 text-[10px] text-white/60 font-mono border border-white/[0.06] max-w-[260px] truncate"
                  title={surl}
                >
                  <i className={`${urlIcon(surl)} text-brand-500/60 flex-shrink-0`}></i>
                  <span className="truncate">{shortUrl(surl)}</span>
                </span>
              ))}
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {visible.map((item, i) => (
            <div key={i} className="p-5 rounded-xl bg-black/40 border border-white/10 hover:border-brand-500/30 transition-all group relative overflow-hidden">
              <div className="flex items-center gap-3 mb-3 border-b border-white/5 pb-3">
                <div className="p-1.5 rounded-lg bg-brand-500/20 text-brand-400">
                  <i className="bi bi-shield-check text-xs"></i>
                </div>
                <h4 className="text-xs font-black text-brand-100 uppercase tracking-wider">{item.title}</h4>
              </div>
              <MarkdownView html={item.html} className="prose prose-invert prose-sm text-xs text-gray-400 leading-relaxed font-mono" />
              <div className="absolute top-0 right-0 p-3 opacity-0 group-hover:opacity-10 transition-opacity">
                <i className="bi bi-crosshair text-4xl text-brand-500"></i>
              </div>
            </div>
          ))}
          {parsed.sources.length === 0 && !webContext && (
            <div className="col-span-full p-6 text-center border dashed border-white/10 rounded-xl">
              <p className="text-white/45 text-xs italic">Đang chờ dữ liệu tình báo...</p>
            </div>
          )}
        </div>

        {parsed.sources.length > 6 && (
          <div className="flex justify-center pt-2">
            <button
              type="button"
              onClick={() => setExpanded(!expanded)}
              className="liquid-btn py-2 px-6 text-xs bg-brand-500/10 text-brand-400 border-brand-500/20 hover:bg-brand-500/20 transition-all font-bold flex items-center gap-2"
            >
              <i className={`bi ${expanded ? 'bi-chevron-up' : 'bi-chevron-down'}`}></i>
              <span>{expanded ? 'Thu gọn' : `Xem thêm ${parsed.sources.length - 6} nguồn`}</span>
            </button>
          </div>
        )}

        <div className="flex items-center justify-center gap-4 pt-3 border-t border-white/5">
          <span className="text-[9px] text-white/35 font-bold uppercase tracking-widest">
            <i className="bi bi-patch-check-fill text-brand-500/40 mr-1"></i>Dữ liệu xác minh bởi ShieldCall AI
          </span>
          <span className="w-1 h-1 rounded-full bg-white/10"></span>
          <span className="text-[9px] text-white/35 font-bold uppercase tracking-widest">
            {new Date().toLocaleDateString('vi-VN')}
          </span>
        </div>
      </div>
    </div>
  );
}

/* ============ TrustGuardrailPanel (guardrail + evidence — góp ý hội đồng #1/#4) ============ */

export interface GuardrailData {
  tier?: string;
  label?: string;
  confidence?: number;
  is_conclusive?: boolean;
  requires_verification?: boolean;
  cautions?: string[];
  disclaimer?: string;
  refusal_script?: string;
  official_channels?: Array<{ name?: string; phone?: string; url?: string; description?: string }>;
  evidence_count?: number;
  sources_used?: string[];
  evidence?: EvidenceItem[];
  answer_asserts_absolute_safety?: boolean;
  kind?: string;
}

interface EvidenceItem {
  source?: string;
  source_name?: string;
  reliability?: string;
  severity?: string;
  detail?: string;
  url?: string | null;
  limits?: string;
}

const RELIABILITY_META: Record<string, { label: string; cls: string }> = {
  high: { label: 'Tin cậy cao', cls: 'bg-safe-500/10 text-safe-400 border-safe-500/20' },
  medium: { label: 'Tin cậy vừa', cls: 'bg-warn-500/10 text-warn-400 border-warn-500/20' },
  low: { label: 'Tham khảo (AI)', cls: 'bg-danger-500/10 text-danger-400 border-danger-500/20' },
};

const TIER_META: Record<string, { cls: string; ring: string; icon: string }> = {
  CONFIRMED_RISK: { cls: 'text-danger-400', ring: 'bg-danger-500/10 border-danger-500/30', icon: 'bi-shield-fill-x' },
  HIGH_RISK: { cls: 'text-danger-400', ring: 'bg-danger-500/10 border-danger-500/30', icon: 'bi-exclamation-octagon-fill' },
  SUSPICIOUS: { cls: 'text-warn-400', ring: 'bg-warn-500/10 border-warn-500/30', icon: 'bi-exclamation-triangle-fill' },
  INSUFFICIENT: { cls: 'text-slate-300', ring: 'bg-slate-500/10 border-slate-400/30', icon: 'bi-question-circle-fill' },
  LIKELY_SAFE: { cls: 'text-safe-400', ring: 'bg-safe-500/10 border-safe-500/30', icon: 'bi-shield-check' },
};

const SEVERITY_CLS: Record<string, string> = {
  CRITICAL: 'text-danger-400',
  HIGH: 'text-danger-300',
  MEDIUM: 'text-warn-400',
  LOW: 'text-white/60',
  INFO: 'text-white/55',
};

export function TrustGuardrailPanel({ result }: { result: ScanResult }): ReactNode {
  const [showAll, setShowAll] = useState(false);
  const g = (result['guardrail'] || {}) as GuardrailData;
  const evidence = asArr<EvidenceItem>(result['evidence']);
  if (!g.tier && evidence.length === 0 && !g.disclaimer) return null;

  const tier = g.tier || 'INSUFFICIENT';
  const meta = TIER_META[tier] || TIER_META.INSUFFICIENT;
  const conf = typeof g.confidence === 'number' ? Math.round(g.confidence * 100) : null;
  const channels = g.official_channels || [];
  const visible = showAll ? evidence : evidence.slice(0, 4);

  return (
    <div className="p-8 border-t border-white/5 bg-white/[0.01] space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-brand-500/20 flex items-center justify-center text-brand-400">
          <i className="bi bi-patch-check"></i>
        </div>
        <div className="flex-1">
          <h4 className="text-sm font-black text-white uppercase tracking-wider">Kết luận &amp; Bằng chứng</h4>
          <p className="text-[10px] text-white/55 font-bold uppercase tracking-widest">
            Evidence-based verdict · {evidence.length} bằng chứng
          </p>
        </div>
      </div>

      {/* Verdict banner */}
      <div className={`rounded-2xl border p-5 ${meta.ring}`}>
        <div className="flex flex-wrap items-center gap-3">
          <i className={`bi ${meta.icon} text-xl ${meta.cls}`}></i>
          <span className={`text-sm font-black uppercase tracking-wide ${meta.cls}`}>{g.label || tier}</span>
          {conf !== null && (
            <span className="px-2.5 py-0.5 rounded-full bg-white/5 text-white/60 text-[10px] font-black border border-white/10">
              độ tin cậy {conf}%
            </span>
          )}
          <span
            className={`px-2.5 py-0.5 rounded-full text-[10px] font-black border ${
              g.is_conclusive
                ? 'bg-danger-500/10 text-danger-400 border-danger-500/20'
                : 'bg-white/5 text-white/60 border-white/10'
            }`}
          >
            {g.is_conclusive ? 'Kết luận có bằng chứng xác thực' : 'Cần xác minh thêm'}
          </span>
        </div>

        {tier === 'INSUFFICIENT' && (
          <p className="mt-3 text-xs text-white/60 leading-relaxed">
            Hệ thống <b className="text-white/80">chưa thu thập đủ bằng chứng để kết luận</b>. Kết quả này{' '}
            <b className="text-white/80">không đồng nghĩa “an toàn”</b> — hãy xác minh qua kênh chính thức trước khi
            giao dịch hoặc chia sẻ thông tin.
          </p>
        )}

        {(g.cautions || []).length > 0 && (
          <ul className="mt-3 space-y-1.5">
            {(g.cautions || []).map((c, i) => (
              <li key={i} className="flex items-start gap-2 text-xs text-white/60">
                <i className="bi bi-dot text-brand-400 mt-0.5"></i>
                <span>{c}</span>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* Evidence */}
      {evidence.length > 0 && (
        <div className="space-y-3">
          <h5 className="text-[10px] font-black text-white/45 uppercase tracking-widest">
            <i className="bi bi-list-check me-1"></i>Bằng chứng theo nguồn
          </h5>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {visible.map((e, i) => {
              const rel = RELIABILITY_META[String(e.reliability || 'medium')] || RELIABILITY_META.medium;
              return (
                <div key={i} className="p-4 rounded-xl bg-white/[0.02] border border-white/[0.06] space-y-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-[11px] font-black text-white/80">{e.source_name || e.source}</span>
                    <span className={`px-2 py-0.5 rounded-full text-[9px] font-black border ${rel.cls}`}>{rel.label}</span>
                    {e.severity && e.severity !== 'INFO' && (
                      <span className={`text-[9px] font-black uppercase ${SEVERITY_CLS[e.severity] || 'text-white/55'}`}>
                        {e.severity}
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-white/60 leading-relaxed">{e.detail}</p>
                  {e.url && (
                    <a
                      href={e.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-[10px] font-black text-brand-400 hover:text-brand-300"
                    >
                      <i className="bi bi-box-arrow-up-right"></i> Nguồn tham chiếu
                    </a>
                  )}
                  {e.limits && (
                    <p className="text-[10px] text-white/45 italic">Giới hạn: {e.limits}</p>
                  )}
                </div>
              );
            })}
          </div>
          {evidence.length > 4 && (
            <div className="flex justify-center">
              <button
                type="button"
                onClick={() => setShowAll(!showAll)}
                className="liquid-btn py-2 px-6 text-xs bg-brand-500/10 text-brand-400 border-brand-500/20 hover:bg-brand-500/20 font-bold flex items-center gap-2"
              >
                <i className={`bi ${showAll ? 'bi-chevron-up' : 'bi-chevron-down'}`}></i>
                {showAll ? 'Thu gọn' : `Xem thêm ${evidence.length - 4} bằng chứng`}
              </button>
            </div>
          )}
        </div>
      )}

      {/* Official channels */}
      {channels.length > 0 && (
        <div className="space-y-3">
          <h5 className="text-[10px] font-black text-white/45 uppercase tracking-widest">
            <i className="bi bi-telephone-outbound me-1"></i>Kênh xác minh / trình báo chính thức
          </h5>
          <div className="flex flex-wrap gap-2">
            {channels.map((c, i) => (
              <span key={i} className="inline-flex items-center gap-2 px-3 py-1.5 rounded-xl bg-brand-500/[0.06] border border-brand-500/20 text-[11px]">
                <i className="bi bi-building-check text-brand-400"></i>
                <span className="text-white/70 font-bold">{c.name}</span>
                {c.phone && (
                  <a href={`tel:${String(c.phone).replace(/[^0-9+]/g, '')}`} className="text-brand-400 font-black">
                    {c.phone}
                  </a>
                )}
                {c.url && (
                  <a href={c.url} target="_blank" rel="noopener noreferrer" className="text-brand-400">
                    <i className="bi bi-box-arrow-up-right"></i>
                  </a>
                )}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Disclaimer + AI caveat + refusal script */}
      <div className="rounded-xl bg-white/[0.02] border border-white/[0.06] p-4 space-y-2">
        <p className="text-[11px] text-white/45 leading-relaxed">
          <i className="bi bi-info-circle me-1 text-brand-400"></i>
          {g.disclaimer ||
            'Kết quả phân tích tự động chỉ mang tính tham khảo, không thay thế kết luận của cơ quan chức năng.'}
        </p>
        <p className="text-[11px] text-warn-400/80 leading-relaxed">
          <i className="bi bi-robot me-1"></i>Mô hình AI có thể nhận diện sai. Mọi kết luận nên dựa trên bằng chứng dữ
          liệu ở trên và được xác minh qua kênh chính thức khi quan trọng.
        </p>
        {g.refusal_script && (
          <details className="text-[11px] text-white/60">
            <summary className="cursor-pointer font-bold text-white/60">Kịch bản từ chối an toàn</summary>
            <p className="mt-1.5 italic">“{g.refusal_script}”</p>
          </details>
        )}
      </div>
    </div>
  );
}

/* ============ ChatGuardrailNote (guardrail cấu trúc cho chat — góp ý hội đồng #1) ============
 * Bản compact của TrustGuardrailPanel, dùng trong bong bóng chat (Assistant/ChatWidget/ElderChat):
 * kết luận guardrail + cảnh báo AI có thể sai + bằng chứng + kênh xác minh chính thức. */
export function ChatGuardrailNote({ guardrail }: { guardrail?: GuardrailData | null }): ReactNode {
  const [openEvidence, setOpenEvidence] = useState(false);
  const g = guardrail || {};
  if (!g.tier) return null;

  const tier = g.tier;
  const meta = TIER_META[tier] || TIER_META.INSUFFICIENT;
  const evidence = asArr<EvidenceItem>(g.evidence);
  const channels = g.official_channels || [];
  const visible = openEvidence ? evidence : evidence.slice(0, 3);
  const conf = typeof g.confidence === 'number' ? Math.round(g.confidence * 100) : null;

  return (
    <div className={`mt-2 rounded-xl border p-3 space-y-2 ${meta.ring}`}>
      <div className="flex flex-wrap items-center gap-2">
        <i className={`bi ${meta.icon} text-sm ${meta.cls}`}></i>
        <span className={`text-[11px] font-black uppercase tracking-wide ${meta.cls}`}>{g.label || tier}</span>
        {conf !== null && (
          <span className="px-2 py-0.5 rounded-full bg-white/5 text-white/50 text-[9px] font-black border border-white/10">
            {conf}%
          </span>
        )}
        <span className="px-2 py-0.5 rounded-full bg-white/5 text-white/50 text-[9px] font-black border border-white/10">
          {g.is_conclusive ? 'Có bằng chứng xác thực' : 'Cần xác minh thêm'}
        </span>
      </div>

      {g.answer_asserts_absolute_safety && (
        <p className="text-[10px] text-warn-400/90 leading-relaxed">
          <i className="bi bi-exclamation-triangle-fill me-1"></i>
          Câu trả lời có khẳng định chắc chắn — hệ thống không xác nhận mức độ an toàn tuyệt đối.
        </p>
      )}

      {(g.cautions || []).length > 0 && (
        <ul className="space-y-1">
          {(g.cautions || []).slice(0, 3).map((c, i) => (
            <li key={i} className="flex items-start gap-1.5 text-[10px] text-white/55 leading-relaxed">
              <i className="bi bi-dot text-brand-400 mt-0.5"></i>
              <span>{c}</span>
            </li>
          ))}
        </ul>
      )}

      {evidence.length > 0 && (
        <div className="pt-1 border-t border-white/5">
          <div className="flex items-center justify-between gap-2">
            <span className="text-[9px] font-black text-white/40 uppercase tracking-widest">
              <i className="bi bi-list-check me-1"></i>{evidence.length} bằng chứng
            </span>
            {evidence.length > 3 && (
              <button
                type="button"
                onClick={() => setOpenEvidence(!openEvidence)}
                className="text-[9px] font-black text-brand-400 hover:text-brand-300"
              >
                {openEvidence ? 'Thu gọn' : 'Xem thêm'}
              </button>
            )}
          </div>
          <div className="mt-1.5 space-y-1">
            {visible.map((e, i) => (
              <div key={i} className="text-[10px] text-white/55 leading-relaxed">
                <span className="font-bold text-white/75">{e.source_name || e.source}</span>
                {e.reliability && (
                  <span className="ml-1 text-white/35">
                    [{RELIABILITY_META[String(e.reliability)]?.label || e.reliability}]
                  </span>
                )}
                {' — '}
                {e.detail}
                {e.url && (
                  <a href={e.url} target="_blank" rel="noopener noreferrer" className="ml-1 text-brand-400">
                    <i className="bi bi-box-arrow-up-right text-[9px]"></i>
                  </a>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {channels.length > 0 && (
        <div className="flex flex-wrap gap-1.5 pt-1 border-t border-white/5">
          {channels.slice(0, 4).map((c, i) => (
            <span key={i} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-lg bg-brand-500/[0.06] border border-brand-500/20 text-[9px]">
              <i className="bi bi-building-check text-brand-400"></i>
              <span className="text-white/65 font-bold">{c.name}</span>
              {c.phone && (
                <a href={`tel:${String(c.phone).replace(/[^0-9+]/g, '')}`} className="text-brand-400 font-black">
                  {c.phone}
                </a>
              )}
            </span>
          ))}
        </div>
      )}

      <p className="text-[9px] text-white/35 leading-relaxed">
        <i className="bi bi-info-circle me-1"></i>
        {g.disclaimer || 'Kết quả phân tích tự động chỉ mang tính tham khảo, không thay thế kết luận của cơ quan chức năng.'}
      </p>
    </div>
  );
}

/* ============ ScanGuide (port _scan_guide.html) ============ */

export type ScanGuideType = 'phone' | 'bank' | 'email' | 'file' | 'message' | 'website' | 'qr' | 'audio';

interface GuideStep {
  html: ReactNode;
}

const GUIDE_ACCENT: Record<ScanGuideType, { num: string; cta: string; check: string }> = {
  phone: { num: 'bg-brand-500/20 text-brand-400', cta: 'text-brand-400', check: 'text-brand-500/60' },
  bank: { num: 'bg-warn-500/20 text-warn-400', cta: 'text-warn-400', check: 'text-warn-500/60' },
  email: { num: 'bg-brand-500/20 text-brand-400', cta: 'text-brand-400', check: 'text-brand-500/60' },
  file: { num: 'bg-brand2-500/20 text-brand2-400', cta: 'text-brand2-400', check: 'text-brand2-500/60' },
  message: { num: 'bg-brand2-500/20 text-brand2-400', cta: 'text-brand2-400', check: 'text-brand2-500/60' },
  website: { num: 'bg-safe-500/20 text-safe-400', cta: 'text-safe-400', check: 'text-safe-500/60' },
  qr: { num: 'bg-brand-500/20 text-brand-400', cta: 'text-brand-400', check: 'text-brand-500/60' },
  audio: { num: 'bg-brand2-500/20 text-brand2-400', cta: 'text-brand2-400', check: 'text-brand2-500/60' },
};

function guideSteps(t: ScanGuideType): ReactNode[] {
  switch (t) {
    case 'phone':
      return [
        <>Nhập <strong className="text-white">số điện thoại</strong> cần kiểm tra. Nhớ thêm mã quốc gia phía trước (ví dụ: <strong className="text-brand-400">+84</strong> cho Việt Nam).</>,
        <>Hoàn thành <strong className="text-white">xác minh bảo mật</strong> (ô vuông phía dưới).</>,
        <>Nhấn nút <strong className="text-brand-400">SCAN</strong> và chờ kết quả.</>,
      ];
    case 'bank':
      return [
        <>Nhấn vào ô <strong className="text-white">chọn ngân hàng</strong> và tìm tên ngân hàng bạn cần kiểm tra.</>,
        <>Nhập <strong className="text-white">số tài khoản</strong> cần kiểm tra vào ô bên dưới.</>,
        <>Nhấn <strong className="text-warn-400">KIỂM TRA</strong> và chờ hệ thống tra cứu.</>,
      ];
    case 'email':
      return [
        <>Chọn chế độ: <strong className="text-white">Nhập tay</strong> (gõ email + nội dung) hoặc <strong className="text-white">Tải file .eml</strong> (chính xác hơn).</>,
        <>Nhập <strong className="text-white">địa chỉ email</strong> người gửi và nội dung email đáng ngờ (hoặc tải file .eml).</>,
        <>Nhấn <strong className="text-brand-400">PHÂN TÍCH</strong> và chờ kết quả.</>,
      ];
    case 'file':
      return [
        <><strong className="text-white">Kéo thả</strong> file cần kiểm tra vào ô phía trên hoặc <strong className="text-white">nhấn vào ô</strong> để chọn file.</>,
        <>Kiểm tra tên file và kích thước. Hỗ trợ tối đa <strong className="text-brand2-400">500MB</strong>.</>,
        <>Nhấn <strong className="text-brand2-400">BẮT ĐẦU KIỂM TRA</strong> và chờ hệ thống quét virus, mã độc.</>,
      ];
    case 'message':
      return [
        <>Nhập hoặc dán <strong className="text-white">nội dung tin nhắn</strong> đáng ngờ vào ô bên trái.</>,
        <>Bạn cũng có thể <strong className="text-white">tải ảnh chụp màn hình</strong> tin nhắn để hệ thống đọc chữ tự động (OCR).</>,
        <>Nhấn <strong className="text-brand2-400">PHÂN TÍCH</strong> và chờ AI đánh giá.</>,
      ];
    case 'website':
      return [
        <>Nhập <strong className="text-white">đường link website</strong> cần kiểm tra (ví dụ: example.com hoặc https://...).</>,
        <>Bật <strong className="text-safe-400">Deep Scan</strong> nếu bạn muốn phân tích sâu hơn (mất thêm thời gian).</>,
        <>Nhấn <strong className="text-safe-400">SCAN</strong> và chờ kết quả.</>,
      ];
    case 'qr':
      return [
        <><strong className="text-white">Chụp ảnh</strong> mã QR hoặc ảnh chứa nội dung đáng ngờ, rồi tải lên.</>,
        <>Bạn có thể tải <strong className="text-white">nhiều ảnh cùng lúc</strong>. Hỗ trợ JPG, PNG, GIF, WebP.</>,
        <>Nhấn <strong className="text-brand-400">PHÂN TÍCH</strong> và chờ AI nhận diện.</>,
      ];
    case 'audio':
      return [
        <>Chọn chế độ: <strong className="text-white">Tải File</strong> (MP3, WAV, M4A, OGG, WebM, FLAC, AAC, tối đa 50MB) hoặc <strong className="text-white">Ghi Âm</strong> trực tiếp qua microphone.</>,
        <>Nếu chọn <strong className="text-white">Ghi Âm</strong>: nhấn nút micro để bắt đầu, nhấn lại để dừng. Ghi âm tối thiểu <strong className="text-brand2-400">2 giây</strong>, tối đa <strong className="text-brand2-400">5 phút</strong>.</>,
        <>Hoàn thành <strong className="text-white">xác minh bảo mật</strong> rồi nhấn <strong className="text-brand2-400">PHÂN TÍCH ÂM THANH</strong>.</>,
        <>Hệ thống sẽ: <strong className="text-white">nhận diện giọng nói → chuyển thành văn bản → AI phân tích nội dung lừa đảo</strong>. Kết quả hiển thị theo thời gian thực.</>,
      ];
  }
}

function guideTips(t: ScanGuideType): string[] {
  switch (t) {
    case 'phone':
      return [
        'Nếu nhận cuộc gọi lạ, kiểm tra số ở đây trước khi gọi lại.',
        'Số bắt đầu bằng +84 là số Việt Nam.',
        'Kết quả "An toàn" không có nghĩa 100% không lừa đảo, hãy luôn cẩn thận.',
      ];
    case 'bank':
      return [
        'Luôn kiểm tra số tài khoản trước khi chuyển tiền cho người lạ.',
        'Nếu bị lừa, hãy báo ngay cho ngân hàng và gọi 113.',
        'Không chuyển tiền khi bị giục gấp, đó có thể là chiêu trò.',
      ];
    case 'email':
      return [
        'Email lừa đảo thường giả mạo ngân hàng, cơ quan nhà nước.',
        'Không nhấp vào link trong email nghi ngờ.',
        'Xuất file .eml để quét chính xác nhất.',
      ];
    case 'file':
      return [
        'Không mở file .exe, .apk từ người lạ gửi.',
        'File PDF, Word cũng có thể chứa mã độc.',
        'Quét file ở đây trước khi mở sẽ giúp bạn an toàn hơn.',
      ];
    case 'message':
      return [
        'Tin nhắn trúng thưởng, nhận quà: hầu hết là lừa đảo.',
        'Hãy chụp ảnh màn hình tin nhắn đáng ngờ để quét.',
        'Không nhấn vào đường link trong tin nhắn lạ.',
      ];
    case 'website':
      return [
        'Trang web lừa đảo thường giả mạo giao diện giống thật.',
        'Kiểm tra tên miền có chính xác không (ví dụ: vietcombank.com.vn).',
        'Dùng Deep Scan để kiểm tra nội dung website chi tiết hơn.',
      ];
    case 'qr':
      return [
        'QR Code giả có thể dẫn đến web lừa đảo hoặc cài mã độc.',
        'Không quét QR từ nguồn không rõ ràng.',
        'Chụp ảnh QR và tải lên đây để kiểm tra trước khi quét bằng điện thoại.',
      ];
    case 'audio':
      return [
        'Cuộc gọi từ "công an", "ngân hàng" yêu cầu chuyển tiền: hầu hết là lừa đảo.',
        'Nếu bị đe dọa qua điện thoại, hãy ghi âm lại và quét ở đây.',
        'AI hỗ trợ nhận diện tiếng Việt và nhiều ngôn ngữ khác.',
        'Cấp quyền microphone trong trình duyệt để sử dụng chức năng ghi âm.',
      ];
  }
}

export function ScanGuide({ scanType }: { scanType: ScanGuideType }): ReactNode {
  const [guideOpen, setGuideOpen] = useState<boolean>(
    () => typeof window === 'undefined' || window.innerWidth >= 1024,
  );
  const accent = GUIDE_ACCENT[scanType];
  const steps: GuideStep[] = guideSteps(scanType).map((html) => ({ html }));
  const tips = guideTips(scanType);

  return (
    <aside className="lg:sticky lg:top-24 h-fit">
      <button
        type="button"
        onClick={() => setGuideOpen(!guideOpen)}
        className="lg:hidden w-full flex items-center justify-between liquid-card p-4 mb-4 text-left group"
      >
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-brand-500/10 flex items-center justify-center text-brand-400">
            <i className="bi bi-question-circle text-xl"></i>
          </div>
          <span className="text-white font-bold">Hướng dẫn sử dụng</span>
        </div>
        <i className={`bi text-white/55 transition-transform ${guideOpen ? 'bi-chevron-up' : 'bi-chevron-down'}`}></i>
      </button>

      {guideOpen && (
        <div className="liquid-card p-6 space-y-5 border border-brand-500/10">
          <div className="flex items-center gap-3 pb-4 border-b border-white/5">
            <div className="w-10 h-10 rounded-xl bg-brand-500/10 flex items-center justify-center text-brand-400 shrink-0">
              <i className="bi bi-book text-lg"></i>
            </div>
            <div>
              <h3 className="text-white font-bold text-sm">Hướng dẫn sử dụng</h3>
              <p className="text-white/45 text-xs">Dành cho mọi người</p>
            </div>
          </div>

          <div className="space-y-3">
            {steps.map((s, i) => (
              <div key={i} className="flex gap-3">
                <div className={`w-7 h-7 rounded-lg ${accent.num} flex items-center justify-center text-xs font-black shrink-0`}>
                  {i + 1}
                </div>
                <p className="text-white/70 text-sm leading-relaxed">{s.html}</p>
              </div>
            ))}

            {scanType === 'email' && (
              <div className="mt-3 p-3.5 rounded-xl bg-brand-500/5 border border-brand-500/10 space-y-2">
                <h5 className="text-brand-400 text-[10px] font-black uppercase tracking-widest flex items-center gap-1.5">
                  <i className="bi bi-download"></i> Cách tải file .eml
                </h5>
                <div className="space-y-1.5 text-white/60 text-xs leading-relaxed">
                  <p><strong className="text-white/70">Gmail:</strong> Mở email → nhấn <strong className="text-white/70">⋮</strong> (góc phải) → chọn <strong className="text-brand-400">Tải thư xuống</strong>.</p>
                  <p><strong className="text-white/70">Outlook:</strong> Mở email → <strong className="text-white/70">File</strong> → <strong className="text-brand-400">Save As</strong> → lưu định dạng .eml.</p>
                  <p><strong className="text-white/70">Apple Mail:</strong> Mở email → kéo thả email ra Desktop hoặc <strong className="text-brand-400">File → Save As</strong>.</p>
                </div>
                <p className="text-brand-400/60 text-[10px] mt-1"><i className="bi bi-info-circle"></i> File .eml chứa đầy đủ header gốc, giúp phân tích chính xác hơn nhiều so với nhập tay.</p>
              </div>
            )}

            {scanType === 'audio' && (
              <div className="mt-3 p-3.5 rounded-xl bg-brand2-500/5 border border-brand2-500/10 space-y-2">
                <h5 className="text-brand2-400 text-[10px] font-black uppercase tracking-widest flex items-center gap-1.5">
                  <i className="bi bi-mic"></i> Mẹo ghi âm tốt
                </h5>
                <div className="space-y-1.5 text-white/60 text-xs leading-relaxed">
                  <p><strong className="text-white/70">Môi trường yên tĩnh:</strong> Tránh nơi ồn ào để AI nhận diện chính xác hơn.</p>
                  <p><strong className="text-white/70">Bật loa ngoài:</strong> Nếu muốn ghi lại cuộc gọi, bật loa ngoài và đặt gần micro máy tính.</p>
                  <p><strong className="text-white/70">File ghi âm sẵn:</strong> Nếu đã có file ghi âm cuộc gọi, chọn chế độ <strong className="text-brand2-400">Tải File</strong> cho kết quả tốt nhất.</p>
                </div>
              </div>
            )}
          </div>

          <div className="border-t border-white/5"></div>

          <div>
            <h4 className="text-white font-bold text-xs uppercase tracking-wider mb-3 flex items-center gap-2">
              <i className="bi bi-palette text-white/55"></i>
              Hiểu kết quả
            </h4>
            <div className="space-y-2">
              <div className="flex items-center gap-3 p-2.5 rounded-lg bg-danger-500/5 border border-danger-500/10">
                <div className="w-3 h-3 rounded-full bg-danger-500 shrink-0"></div>
                <div>
                  <span className="text-danger-400 text-xs font-bold">ĐỎ: Nguy hiểm</span>
                  <p className="text-white/55 text-[11px]">Có dấu hiệu lừa đảo rõ ràng</p>
                </div>
              </div>
              <div className="flex items-center gap-3 p-2.5 rounded-lg bg-warn-500/5 border border-warn-500/10">
                <div className="w-3 h-3 rounded-full bg-warn-500 shrink-0"></div>
                <div>
                  <span className="text-warn-400 text-xs font-bold">VÀNG: Cẩn thận</span>
                  <p className="text-white/55 text-[11px]">Có dấu hiệu đáng ngờ, cần cảnh giác</p>
                </div>
              </div>
              <div className="flex items-center gap-3 p-2.5 rounded-lg bg-safe-500/5 border border-safe-500/10">
                <div className="w-3 h-3 rounded-full bg-safe-500 shrink-0"></div>
                <div>
                  <span className="text-safe-400 text-xs font-bold">XANH: An toàn</span>
                  <p className="text-white/55 text-[11px]">Không phát hiện dấu hiệu lừa đảo</p>
                </div>
              </div>
            </div>
          </div>

          <div className="border-t border-white/5"></div>

          <div>
            <h4 className="text-white font-bold text-xs uppercase tracking-wider mb-3 flex items-center gap-2">
              <i className="bi bi-lightbulb text-white/55"></i>
              Mẹo hay
            </h4>
            <ul className="space-y-2 text-white/60 text-xs leading-relaxed">
              {tips.map((tip, i) => (
                <li key={i} className="flex gap-2">
                  <i className={`bi bi-check-circle ${accent.check} shrink-0 mt-0.5`}></i>{tip}
                </li>
              ))}
            </ul>
          </div>

          <div className="pt-3 border-t border-white/5">
            <Link href="/report/" className="flex items-center gap-2 text-xs text-brand-400/70 hover:text-brand-400 transition-colors">
              <i className="bi bi-flag"></i>
              <span>Phát hiện lừa đảo? <strong>Tố cáo ngay</strong></span>
            </Link>
          </div>

        </div>
      )}
    </aside>
  );
}

/* ============ Liên kết chéo nội bộ cụm scan ============ */

export function ScanLink({ to, className = '', children }: { to: string; className?: string; children: ReactNode }): ReactNode {
  return (
    <Link href={to} className={className}>
      {children}
    </Link>
  );
}
