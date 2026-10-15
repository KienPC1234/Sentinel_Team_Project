'use client';
/* Hook kết nối WebSocket tiến trình task dùng chung.
 * Backend: api/core/consumers.py::TaskProgressConsumer -> /ws/task/<task_id>/
 * Message: { type:'task_progress', status, message, step, data }
 * Dùng cho ScamIQ (tạo đề / AI chấm điểm); có thể tái sử dụng cho task khác.
 *
 * Nguyên tắc: WS chỉ là kênh realtime phụ trợ. Hook không tự polling —
 * caller vẫn phải giữ REST polling làm fallback khi WS lỗi/không kết nối.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { wsBase } from '../components/ScanWidgets';

export interface TaskSocketMessage {
  type?: string;
  status?: string;
  message?: string;
  step?: string | number | null;
  data?: Record<string, unknown> | null;
}

export type TaskSocketState =
  | 'idle'
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  | 'disconnected'
  | 'closed';

export interface UseTaskSocketOptions {
  /** Bật/tắt kết nối. Mặc định bật khi có taskId. */
  enabled?: boolean;
  /** Gọi mỗi khi nhận message JSON hợp lệ (đã lọc ping/pong). */
  onMessage?: (msg: TaskSocketMessage) => void;
  onOpen?: () => void;
  /** WS hết lượt thử kết nối — caller nên dựa hoàn toàn vào polling fallback. */
  onUnavailable?: () => void;
  /** Số lần thử kết nối lại tối đa. Mặc định 5. */
  maxAttempts?: number;
  /** Chu kỳ gửi ping giữ kết nối (ms). Mặc định 20000. */
  pingMs?: number;
}

export function useTaskSocket(
  taskId: string | null,
  opts: UseTaskSocketOptions = {},
): { state: TaskSocketState; close: () => void } {
  const [state, setState] = useState<TaskSocketState>('idle');
  const cbRef = useRef(opts);
  cbRef.current = opts;
  const closeRef = useRef<() => void>(() => {});

  useEffect(() => {
    if (!taskId || opts.enabled === false) {
      setState('idle');
      return;
    }
    let alive = true;
    let manual = false;
    let attempts = 0;
    let ws: WebSocket | null = null;
    let reconnectTimer: number | null = null;
    let pingTimer: number | null = null;
    const maxAttempts = opts.maxAttempts ?? 5;

    function clearTimers(): void {
      if (reconnectTimer != null) window.clearTimeout(reconnectTimer);
      if (pingTimer != null) window.clearInterval(pingTimer);
      reconnectTimer = null;
      pingTimer = null;
    }

    function shutdown(): void {
      clearTimers();
      const sock = ws;
      ws = null;
      if (sock) {
        try {
          sock.close();
        } catch {
          /* bỏ qua */
        }
      }
    }

    function scheduleReconnect(): void {
      if (!alive || manual) return;
      if (attempts >= maxAttempts) {
        setState('disconnected');
        cbRef.current.onUnavailable?.();
        return;
      }
      attempts += 1;
      setState('reconnecting');
      const delay = Math.min(8000, 1000 * Math.pow(2, attempts - 1));
      reconnectTimer = window.setTimeout(connect, delay);
    }

    function connect(): void {
      if (!alive || manual) return;
      setState(attempts > 0 ? 'reconnecting' : 'connecting');
      let sock: WebSocket;
      try {
        sock = new WebSocket(`${wsBase()}/ws/task/${encodeURIComponent(taskId as string)}/`);
      } catch {
        scheduleReconnect();
        return;
      }
      ws = sock;
      sock.onopen = () => {
        if (!alive || manual) return;
        attempts = 0;
        setState('connected');
        cbRef.current.onOpen?.();
        if (pingTimer != null) window.clearInterval(pingTimer);
        const pingMs = cbRef.current.pingMs ?? 20000;
        pingTimer = window.setInterval(() => {
          if (sock.readyState === WebSocket.OPEN) {
            try {
              sock.send(JSON.stringify({ type: 'ping' }));
            } catch {
              /* bỏ qua */
            }
          }
        }, pingMs);
      };
      sock.onmessage = (e: MessageEvent<string>) => {
        if (!alive || manual) return;
        const raw = typeof e.data === 'string' ? e.data : '';
        if (!raw) return;
        let msg: TaskSocketMessage;
        try {
          const parsed: unknown = JSON.parse(raw);
          if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return;
          msg = parsed as TaskSocketMessage;
        } catch {
          return;
        }
        if (msg.type === 'ping' || msg.type === 'pong' || msg.step === 'ping') return;
        cbRef.current.onMessage?.(msg);
      };
      sock.onerror = () => {
        /* onclose sẽ xử lý reconnect */
      };
      sock.onclose = () => {
        if (pingTimer != null) {
          window.clearInterval(pingTimer);
          pingTimer = null;
        }
        if (!alive || manual) return;
        setState('disconnected');
        scheduleReconnect();
      };
    }

    closeRef.current = () => {
      manual = true;
      shutdown();
    };

    connect();

    return () => {
      alive = false;
      shutdown();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [taskId, opts.enabled]);

  const close = useCallback((): void => {
    closeRef.current();
    setState('closed');
  }, []);

  return { state, close };
}
