'use client';

import { useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { showToast } from '../lib/ui/feedback';

export const TURNSTILE_SITEKEY =
  (process.env.NEXT_PUBLIC_TURNSTILE_SITEKEY as string | undefined) || '';

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
      s.setAttribute('data-turnstile', '1');
      s.onload = () => resolve();
      s.onerror = () => resolve();
      document.head.appendChild(s);
      window.setTimeout(() => resolve(), 8000);
    });
  }
  return tsScriptPromise;
}

const tsWidgets = new Map<string, HTMLElement>();

/** Reset toàn bộ widget Turnstile đang mount để cấp token tươi cho lượt gửi kế tiếp. */
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

  useEffect(() => {
    if (!TURNSTILE_SITEKEY) return;
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
          sitekey: TURNSTILE_SITEKEY,
          theme: 'dark',
          callback: (t: unknown) => push(typeof t === 'string' ? t : ''),
          'expired-callback': () => {
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
  }, []);

  if (!TURNSTILE_SITEKEY) {
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
        <p className="text-warn-400 text-[11px] font-bold">Xác minh đã hết hạn - vui lòng xác minh lại.</p>
      )}
      <input type="hidden" name="cf-turnstile-response" value={token} readOnly />
    </div>
  );
}

/** Đọc token Turnstile từ input ẩn do widget quản lý. */
export function getTsToken(): string {
  try {
    const el = document.querySelector<HTMLInputElement>('[name=cf-turnstile-response]');
    return el?.value || '';
  } catch {
    return '';
  }
}

/** Lấy token Turnstile, hiển thị cảnh báo nếu thiếu và tự reset cho lượt kế tiếp. */
export function consumeTurnstileToken(missingMsg = 'Vui lòng hoàn thành xác minh anti-spam'): string | null {
  const tsToken = getTsToken();
  if (!tsToken) {
    showToast(missingMsg, 'warning');
    return null;
  }
  resetTurnstile();
  return tsToken;
}
