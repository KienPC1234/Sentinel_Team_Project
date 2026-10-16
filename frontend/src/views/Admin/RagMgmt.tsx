'use client';
import { useEffect, useRef, useState } from 'react';
import { api } from '../../lib/api';
import { useAuth } from '../../components/AuthContext';
import { wsBase, WsBadge } from '../../components/ScanWidgets';
import type { WsState } from '../../components/ScanWidgets';
import { AdminShell, useAdminGet } from './_shared';
import { scConfirm, showToast } from '../../lib/ui/feedback';

/* Port 1-1 từ PKV/templates/Admin/rag_management.html.
 * API: GET  /admin/rag/?json=1 (&query= để test context) → { stats, logs, test_results }
 *      POST /admin/rag/rebuild/      (AdminRAGRebuildView)
 *      POST /admin/rag/clear-logs/   (AdminRAGClearLogsView)
 * WS:  /ws/rag/ (RagStatusConsumer) → { type:'rag_status', status, message, count, error }
 *      Cập nhật realtime; polling REST phía trên vẫn giữ làm fallback. */

interface RagStats {
  total_items?: number;
  last_sync?: string | null;
  is_ready?: boolean;
  model_name?: string;
  is_running?: boolean;
  running_since?: string | null;
  beat_interval?: number;
}

interface RagLog {
  id: string;
  status?: string;
  trigger?: string;
  documents_count?: number;
  error_message?: string;
  started_at?: string;
  completed_at?: string;
  duration?: string;
}

interface TestResult {
  type?: string;
  title?: string;
  score?: number;
  text?: string;
  url?: string;
}

interface RagResponse {
  stats?: RagStats;
  logs?: RagLog[];
  test_results?: TestResult[];
}

/* Payload realtime từ /ws/rag/ (RagStatusConsumer.rag_status_update). */
interface RagLive {
  status: string;
  message: string;
  count: number | null;
  error: string | null;
}

function asList(data: RagResponse | null): RagResponse {
  return data || {};
}

function formatDate(dateStr?: string | null): string {
  if (!dateStr) return 'Chưa có';
  const d = new Date(dateStr);
  if (Number.isNaN(d.getTime())) return dateStr;
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${pad(d.getDate())}/${pad(d.getMonth() + 1)} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function truncate(text: string | undefined, len: number): string {
  const t = text || '';
  return t.length > len ? `${t.slice(0, len - 1)}…` : t;
}

function countdown(lastSync: string | null | undefined, beatInterval: number, nowMs: number): string {
  if (!lastSync) return 'Theo lịch trình';
  const last = new Date(lastSync).getTime();
  if (Number.isNaN(last)) return '-';
  const nextRun = last + beatInterval * 1000;
  const diff = Math.max(0, Math.floor((nextRun - nowMs) / 1000));
  if (diff <= 0) return 'Sắp chạy...';
  const h = Math.floor(diff / 3600);
  const m = Math.floor((diff % 3600) / 60);
  const s = diff % 60;
  return `${h > 0 ? `${h}h ` : ''}${String(m).padStart(2, '0')}m ${String(s).padStart(2, '0')}s`;
}

export default function RagMgmt() {
  const { user } = useAuth();
  const isStaff = Boolean(user?.is_staff);
  const [qInput, setQInput] = useState('');
  const [query, setQuery] = useState('');
  const [reindexing, setReindexing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [now, setNow] = useState(0);
  const [wsState, setWsState] = useState<WsState>('idle');
  const [live, setLive] = useState<RagLive | null>(null);

  const path = `/admin/rag/?json=1${query ? `&query=${encodeURIComponent(query)}` : ''}`;
  const { data, refetch } = useAdminGet<RagResponse>(path);
  const info = asList(data);
  const stats = info.stats || {};
  const logs = info.logs || [];
  const results = info.test_results || [];
  /* WS ưu tiên khi có tín hiệu mới; polling REST là fallback. */
  const liveRunning = live?.status === 'RUNNING';
  const liveDone = live?.status === 'SUCCESS' || live?.status === 'FAILED';
  const running = liveDone ? false : Boolean(stats.is_running) || liveRunning;
  const totalItems =
    live?.status === 'SUCCESS' && live.count != null ? live.count : (stats.total_items ?? 0);
  const beatInterval = stats.beat_interval || 3600;
  /* 5s bình thường, 1.5s khi đang chạy (port startPolling/poll). */
  const pollMs = running ? 1500 : 5000;

  const refetchRef = useRef(refetch);
  useEffect(() => {
    refetchRef.current = refetch;
  });

  /* Đồng hồ đếm ngược 1s/lần (port updateCountdown). */
  useEffect(() => {
    const tick = () => setNow(Date.now());
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  /* Poll theo pollMs ở trên (port startPolling/poll). */
  useEffect(() => {
    const id = setInterval(() => refetchRef.current(), pollMs);
    return () => clearInterval(id);
  }, [pollMs]);

  /* WS /ws/rag/ — chỉ khi là staff (backend cũng chặn non-staff); reconnect 5s,
   * ping/pong, đóng khi unmount. Polling phía trên vẫn chạy song song. */
  useEffect(() => {
    if (!isStaff || typeof window === 'undefined') return;
    let alive = true;
    let ws: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

    const scheduleReconnect = () => {
      if (!alive) return;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      reconnectTimer = setTimeout(connect, 5000);
    };

    const connect = () => {
      if (!alive) return;
      setWsState('connecting');
      let sock: WebSocket;
      try {
        sock = new WebSocket(`${wsBase()}/ws/rag/`);
      } catch {
        setWsState('disconnected');
        scheduleReconnect();
        return;
      }
      ws = sock;

      sock.onopen = () => {
        if (!alive) return;
        setWsState('connected');
      };

      sock.onmessage = (e: MessageEvent) => {
        if (!alive || typeof e.data !== 'string') return;
        let parsed: unknown;
        try {
          parsed = JSON.parse(e.data);
        } catch {
          return;
        }
        if (typeof parsed !== 'object' || parsed === null) return;
        const rec = parsed as Record<string, unknown>;
        const type = typeof rec.type === 'string' ? rec.type : '';
        if (type === 'ping') {
          /* Consumer gửi heartbeat mỗi 15s — trả pong để giữ kết nối. */
          try {
            sock.send(JSON.stringify({ type: 'pong' }));
          } catch {
            /* ignore */
          }
          return;
        }
        if (type !== 'rag_status') return;

        const status = typeof rec.status === 'string' ? rec.status : '';
        const message = typeof rec.message === 'string' ? rec.message : '';
        const count = typeof rec.count === 'number' && Number.isFinite(rec.count) ? rec.count : null;
        const error = typeof rec.error === 'string' ? rec.error : null;
        setLive({ status, message, count, error });

        if (status === 'RUNNING') {
          showToast(message || 'Đang đồng bộ kiến thức...', 'info');
        } else if (status === 'SUCCESS') {
          showToast(message || 'Đồng bộ kiến thức hoàn tất.', 'success');
          refetchRef.current();
        } else if (status === 'FAILED') {
          showToast(error || message || 'Đồng bộ kiến thức thất bại.', 'error');
          refetchRef.current();
        }
      };

      sock.onerror = () => {
        try {
          sock.close();
        } catch {
          /* ignore */
        }
      };

      sock.onclose = () => {
        if (!alive) return;
        setWsState('reconnecting');
        scheduleReconnect();
      };
    };

    connect();
    return () => {
      alive = false;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      try {
        ws?.close();
      } catch {
        /* ignore */
      }
    };
  }, [isStaff]);

  const reindex = async () => {
    if (reindexing) return;
    const ok = await scConfirm('Quá trình này sẽ quét lại toàn bộ kiến thức và cập nhật Vector Database.', {
      title: 'Bắt đầu Re-index?',
      icon: 'question',
      confirmButtonText: 'Bắt đầu ngay',
      cancelButtonText: 'Hủy',
    });
    if (!ok) return;
    setReindexing(true);
    try {
      const res = await api.post<{ message?: string; error?: string }>('/admin/rag/rebuild/');
      showToast(res.message || 'Đã lên lịch xây dựng lại chỉ mục Vector.', 'success');
      refetch();
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Lỗi kết nối', 'error');
    } finally {
      setReindexing(false);
    }
  };

  const clearLogs = async () => {
    const ok = await scConfirm('Tất cả lịch sử đồng bộ (trừ job đang chạy) sẽ bị xóa.', {
      title: 'Dọn lịch sử đồng bộ?',
      icon: 'warning',
      confirmButtonText: 'Xóa',
      cancelButtonText: 'Hủy',
    });
    if (!ok) return;
    setBusy(true);
    try {
      const res = await api.post<{ message?: string; error?: string }>('/admin/rag/clear-logs/');
      showToast(res.message || 'Đã xóa lịch sử đồng bộ', 'success');
      refetch();
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Lỗi kết nối', 'error');
    } finally {
      setBusy(false);
    }
  };

  return (
    <AdminShell
      title="RAG & Tri Thức AI"
      subtitle="Quản lý Vector Index, FAISS Embeddings và đồng bộ hóa kiến thức AI"
      actions={
        <div className="flex items-center gap-3">
          <WsBadge state={wsState} connectedLabel="RAG trực tiếp" />
          <button
            type="button"
            disabled={reindexing}
            onClick={() => void reindex()}
            className="px-5 py-2.5 rounded-xl bg-brand-500 text-black font-black text-xs uppercase tracking-wider hover:bg-brand-400 transition-all shadow-md shadow-brand-500/20 flex items-center gap-2 group disabled:opacity-50"
          >
            <i
              id="reindex-icon"
              className={`bi bi-arrow-repeat text-base group-hover:rotate-180 transition-transform duration-500${reindexing ? ' animate-spin' : ''}`}
            ></i>
            <span>Quét lại kiến thức</span>
          </button>
        </div>
      }
    >

      {/* Running Status Banner */}
      {running && (
        <div className="mb-8 p-6 rounded-[2rem] bg-brand-500/5 border border-brand-500/20 animate-pulse">
          <div className="flex items-center gap-4">
            <i className="bi bi-arrow-repeat text-2xl text-brand-400 animate-spin"></i>
            <div>
              <div className="text-sm font-black text-brand-400">
                {liveRunning && live?.message ? live.message : 'Đang đồng bộ kiến thức...'}
              </div>
              {stats.running_since && (
                <div className="text-[10px] text-white/45 font-bold mt-1">
                  Bắt đầu lúc: <span>{formatDate(stats.running_since)}</span>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Failed Banner — realtime từ WS rag_status FAILED */}
      {live?.status === 'FAILED' && !running && (
        <div className="mb-8 p-6 rounded-[2rem] bg-danger-500/5 border border-danger-500/20">
          <div className="flex items-center gap-4">
            <i className="bi bi-exclamation-octagon text-2xl text-danger-400"></i>
            <div>
              <div className="text-sm font-black text-danger-400">Đồng bộ kiến thức thất bại</div>
              <div className="text-[10px] text-white/55 font-bold mt-1">
                {live.error || live.message || 'Vui lòng kiểm tra log đồng bộ.'}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Stats Banner */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-12">
        <div className="group p-8 rounded-[2.5rem] bg-slate-900/40 border border-white/5 backdrop-blur-xl relative overflow-hidden">
          <div className="absolute top-0 right-0 p-6 opacity-10 text-brand-400">
            <i className="bi bi-files text-4xl"></i>
          </div>
          <div className="text-[10px] font-black text-brand-500/50 uppercase tracking-widest mb-2">Tổng số tài liệu</div>
          <div className="text-4xl font-black text-white tabular-nums tracking-tighter">{totalItems}</div>
          <div className="mt-4 text-[10px] font-bold text-white/35 uppercase tracking-widest">Vectorized items</div>
        </div>

        <div className="group p-8 rounded-[2.5rem] bg-slate-900/40 border border-white/5 backdrop-blur-xl relative overflow-hidden">
          <div className="absolute top-0 right-0 p-6 opacity-10 text-brand2-400">
            <i className="bi bi-clock-history text-4xl"></i>
          </div>
          <div className="text-[10px] font-black text-brand2-500/50 uppercase tracking-widest mb-2">Cập nhật lần cuối</div>
          <div className="text-2xl font-black text-white">{formatDate(stats.last_sync)}</div>
          <div className="mt-4 text-[10px] font-bold text-white/35 uppercase tracking-widest">Last synchronization</div>
        </div>

        <div className="group p-8 rounded-[2.5rem] bg-slate-900/40 border border-white/5 backdrop-blur-xl relative overflow-hidden">
          <div className="absolute top-0 right-0 p-6 opacity-10 text-safe-400">
            <i className="bi bi-cpu text-4xl"></i>
          </div>
          <div className="text-[10px] font-black text-safe-500/50 uppercase tracking-widest mb-2">Trạng thái VectorDB</div>
          <div className="flex items-center gap-3">
            <span
              className={`w-2.5 h-2.5 rounded-full transition-all duration-500 ${
                stats.is_ready ? 'bg-safe-500 shadow-[0_0_15px_rgba(16,185,129,0.5)] animate-pulse' : 'bg-danger-500'
              }`}
            ></span>
            <span className="text-2xl font-black text-white">{stats.is_ready ? 'Sẵn sàng' : 'Lỗi'}</span>
          </div>
          <div className="mt-4 text-[9px] font-bold text-white/35 uppercase tracking-widest truncate">
            Model: {stats.model_name || 'Unknown'}
          </div>
        </div>

        <div className="group p-8 rounded-[2.5rem] bg-slate-900/40 border border-white/5 backdrop-blur-xl relative overflow-hidden">
          <div className="absolute top-0 right-0 p-6 opacity-10 text-warn-400">
            <i className="bi bi-hourglass-split text-4xl"></i>
          </div>
          <div className="text-[10px] font-black text-warn-500/50 uppercase tracking-widest mb-2">Job kế tiếp</div>
          <div className="text-2xl font-black text-white tabular-nums">{countdown(stats.last_sync, beatInterval, now)}</div>
          <div className="mt-4 text-[10px] font-bold text-white/35 uppercase tracking-widest">
            Mỗi <span>{Math.round(beatInterval / 60)}</span> phút
          </div>
        </div>
      </div>

      {/* Context Testing Section */}
      <div className="p-10 rounded-[3rem] bg-slate-900/40 border border-white/5 backdrop-blur-xl mb-12">
        <div className="flex items-center gap-4 mb-8">
          <div className="w-10 h-10 rounded-xl bg-warn-500/10 flex items-center justify-center text-warn-400">
            <i className="bi bi-search text-lg"></i>
          </div>
          <h2 className="text-2xl font-black text-white tracking-tight">Kiểm tra Context</h2>
        </div>

        <form
          className="relative mb-10"
          onSubmit={(e) => {
            e.preventDefault();
            setQuery(qInput.trim());
          }}
        >
          <input
            type="text"
            name="query"
            value={qInput}
            onChange={(e) => setQInput(e.target.value)}
            placeholder="Nhập câu hỏi để test tìm kiếm ngữ cảnh..."
            className="w-full bg-black/40 border border-white/10 rounded-3xl pl-8 pr-32 py-5 text-white focus:outline-none focus:border-brand-500/50 transition-all font-medium text-lg placeholder:text-white/20"
          />
          <button
            type="submit"
            className="absolute right-3 top-3 px-8 py-2.5 bg-white/5 hover:bg-brand-500 hover:text-black border border-white/10 rounded-2xl text-white font-black uppercase tracking-widest text-xs transition-all"
          >
            Search
          </button>
        </form>

        {query && (
          <div className="space-y-6">
            <h3 className="text-[10px] font-black text-white/55 uppercase tracking-widest ml-2 mb-4">
              Top matches for: &quot;{query}&quot;
            </h3>
            {results.map((res, i) => (
              <div
                key={`${res.url || res.title || 'res'}-${i}`}
                className="p-6 rounded-[2rem] bg-white/[0.02] border border-white/5 hover:border-brand-500/20 hover:bg-white/[0.04] transition-all group"
              >
                <div className="flex justify-between items-start gap-4 mb-4">
                  <div className="flex items-center gap-3">
                    <span className="px-3 py-1 rounded-lg bg-brand-500/10 text-brand-400 text-[9px] font-black uppercase border border-brand-500/20 tracking-widest">
                      {res.type}
                    </span>
                    <h4 className="font-black text-white group-hover:text-brand-400 transition-colors tracking-tight text-lg">{res.title}</h4>
                  </div>
                  <div className="px-4 py-2 rounded-xl bg-black/40 border border-white/5 text-center shrink-0">
                    <div className="text-[8px] font-black text-white/35 uppercase tracking-widest mb-0.5">Similarity</div>
                    <div className="text-sm font-black text-brand-400 tabular-nums">{Number(res.score || 0).toFixed(4)}</div>
                  </div>
                </div>
                <div className="text-sm text-white/55 leading-relaxed font-medium italic border-l-2 border-white/5 pl-4 ml-2">
                  {truncate(res.text, 400)}
                </div>
                <div className="mt-6 flex justify-end">
                  <a
                    href={res.url || '#'}
                    target="_blank"
                    rel="noreferrer"
                    className="px-5 py-2 rounded-xl bg-white/5 text-[10px] font-black text-white/55 hover:text-brand-400 hover:bg-brand-500/10 transition-all uppercase tracking-widest flex items-center gap-2 border border-white/5"
                  >
                    Deep dive <i className="bi bi-box-arrow-up-right"></i>
                  </a>
                </div>
              </div>
            ))}
            {results.length === 0 && (
              <div className="py-16 text-center border border-dashed border-white/10 rounded-[2rem]">
                <p className="text-[10px] font-black text-white/35 uppercase tracking-widest">No matching context found</p>
                <p className="text-xs text-white/20 mt-2">Try adjusting your search query or re-indexing your documents.</p>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Sync History */}
      <div className="p-10 rounded-[3rem] bg-slate-900/40 border border-white/5 backdrop-blur-xl overflow-hidden">
        <div className="flex items-center justify-between mb-8">
          <h2 className="text-2xl font-black text-white tracking-tight">Lịch sử đồng bộ</h2>
          <button
            type="button"
            disabled={busy}
            onClick={() => void clearLogs()}
            className="px-5 py-2.5 rounded-2xl bg-danger-500/10 text-danger-400 text-[10px] font-black uppercase tracking-widest border border-danger-500/20 hover:bg-danger-500/20 transition-all flex items-center gap-2 disabled:opacity-50"
          >
            <i className="bi bi-trash3"></i> Dọn lịch sử
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-white/5">
                <th className="px-4 py-4 text-[10px] font-black text-white/55 uppercase tracking-widest">Timestamp</th>
                <th className="px-4 py-4 text-[10px] font-black text-white/55 uppercase tracking-widest text-center">Status</th>
                <th className="px-4 py-4 text-[10px] font-black text-white/55 uppercase tracking-widest">Trigger</th>
                <th className="px-4 py-4 text-[10px] font-black text-white/55 uppercase tracking-widest text-center">Docs</th>
                <th className="px-4 py-4 text-[10px] font-black text-white/55 uppercase tracking-widest">Diagnostic Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.02]">
              {logs.map((log) => (
                <tr key={log.id} className="group hover:bg-white/[0.02] transition-colors">
                  <td className="px-4 py-5 text-[11px] font-bold text-white/60">{log.started_at}</td>
                  <td className="px-4 py-5">
                    <div className="flex justify-center">
                      {log.status === 'SUCCESS' && (
                        <span className="px-2.5 py-1 rounded-lg bg-safe-500/10 text-safe-400 text-[9px] font-black uppercase border border-safe-500/20">
                          Success
                        </span>
                      )}
                      {log.status === 'RUNNING' && (
                        <span className="px-2.5 py-1 rounded-lg bg-brand-500/10 text-brand-400 text-[9px] font-black uppercase border border-brand-500/20 animate-pulse">
                          Syncing...
                        </span>
                      )}
                      {log.status === 'FAILED' && (
                        <span className="px-2.5 py-1 rounded-lg bg-danger-500/10 text-danger-400 text-[9px] font-black uppercase border border-danger-500/20">
                          Failed
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-5 text-[10px] font-black text-white/35 uppercase tracking-widest">{log.trigger}</td>
                  <td className="px-4 py-5 text-sm font-black text-white text-center tabular-nums">{log.documents_count}</td>
                  <td className="px-4 py-5 text-[11px] text-white/45 italic font-medium">
                    <span>{log.error_message}</span>
                    {log.duration && <span className="text-white/20 ml-2">({log.duration})</span>}
                  </td>
                </tr>
              ))}
              {logs.length === 0 && (
                <tr>
                  <td colSpan={5} className="py-20 text-center text-white/20 font-black uppercase tracking-widest text-xs italic">
                    No sync logs available
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Educational Footer */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mt-12">
        <div className="p-8 rounded-[2.5rem] bg-gradient-to-br from-brand-500/5 to-transparent border border-brand-500/10">
          <h3 className="text-xs font-black text-brand-400 uppercase tracking-widest mb-4">Tại sao cần Re-index?</h3>
          <p className="text-xs text-white/55 leading-relaxed font-medium">
            Vector Database (FAISS) chuyển hóa kiến thức thành không gian vector đa chiều. Khi dữ liệu thay đổi, Re-index đảm bảo
            AI có được &quot;trí nhớ&quot; mới nhất và chính xác nhất về các kịch bản lừa đảo hiện nay.
          </p>
        </div>
        <div className="p-8 rounded-[2.5rem] bg-gradient-to-br from-brand2-500/5 to-transparent border border-brand2-500/10">
          <h3 className="text-xs font-black text-brand2-400 uppercase tracking-widest mb-4">Về Celery Workers</h3>
          <p className="text-xs text-white/55 leading-relaxed font-medium">
            Quá trình nhúng (embedding) hàng trăm tài liệu có thể tốn tài nguyên. Hệ thống sử dụng Celery để xử lý ngầm, đảm bảo
            trang quản trị luôn mượt mà trong khi AI đang bận rộn &quot;học tập&quot;.
          </p>
        </div>
      </div>
    </AdminShell>
  );
}
