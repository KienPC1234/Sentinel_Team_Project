'use client';
/* Port từ PKV/templates/Scan/scan_status.html — Kết quả quét #id.
 * API: GET /api/v1/scan/status/<id>/ (poll 5s khi pending) + WS /ws/scan/<id>/,
 *      POST /api/v1/scan/<id>/report-admin/ {reason} (cần đăng nhập).
 */
import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';

import { useParams } from 'next/navigation';
import { api } from '../../lib/api';



import { renderMd } from '../../lib/chat/markdown';
import { MarkdownView } from '../../components/ui';
import { showToast, wsBase, TrustGuardrailPanel, guardrailTone, guardrailLabel } from '../../components/ScanWidgets';
import type { ScanResult } from '../../components/ScanWidgets';
import { asStr, asNum, asArr } from '../../components/ScanWidgets';

type StatusState = 'pending' | 'processing' | 'completed' | 'failed';

const TYPE_LABELS: Record<string, string> = {
  phone: 'Số điện thoại',
  message: 'Tin nhắn',
  domain: 'Website/URL',
  account: 'Tài khoản ngân hàng',
  qr: 'QR / Ảnh',
  email: 'Email',
  file: 'Tệp tin',
  audio: 'Âm thanh',
};

const PAGE_MAP: Record<string, string> = {
  phone: '/scan/phone/',
  message: '/scan/message/',
  domain: '/scan/website/',
  account: '/scan/bank/',
  qr: '/scan/qr/',
  email: '/scan/email/',
  file: '/scan/file/',
  audio: '/scan/audio/',
};

interface StatusPayload {
  status?: string;
  scan_type?: string;
  risk_score?: number;
  risk_level?: string;
  result?: ScanResult | null;
}

function riskBadge(level: string): string {
  if (level === 'RED') return 'bg-danger-500/20 text-danger-500 border border-danger-500/30';
  if (level === 'YELLOW') return 'bg-warn-500/20 text-warn-500 border border-warn-500/30';
  if (level === 'UNVERIFIED') return 'bg-slate-500/20 text-slate-300 border border-slate-400/30';
  return 'bg-safe-500/20 text-safe-500 border border-safe-500/30';
}

function riskGlow(level: string): string {
  if (level === 'RED') return 'bg-danger-500';
  if (level === 'YELLOW') return 'bg-warn-500';
  if (level === 'UNVERIFIED') return 'bg-slate-500';
  return 'bg-safe-500';
}

export default function Status() {
  const { id } = useParams<{ id: string }>();
  const [status, setStatus] = useState<StatusState>('pending');
  const [result, setResult] = useState<ScanResult>({});
  const [scanType, setScanType] = useState('');
  const [progress, setProgress] = useState<{ message: string; step: string }[]>([]);
  const [wsState, setWsState] = useState<'connected' | 'connecting' | 'disconnected'>('disconnected');
  const wsRef = useRef<WebSocket | null>(null);
  const pollRef = useRef<number | null>(null);

  useEffect(() => {
    if (!id) return;
    let alive = true;

    const fetchStatus = (): void => {
      api
        .get<StatusPayload>(`/scan/status/${id}/`)
        .then((data) => {
          if (!alive) return;
          const st = asStr(data.status).toLowerCase();
          if (st === 'completed') {
            setStatus('completed');
            setResult({
              ...(data.result || {}),
              risk_score: asNum(data.risk_score),
              risk_level: asStr(data.risk_level),
            });
            if (data.scan_type) setScanType(data.scan_type);
            if (pollRef.current != null) window.clearInterval(pollRef.current);
            try {
              wsRef.current?.close();
            } catch {
              /* bỏ qua */
            }
          } else if (st === 'failed') {
            setStatus('failed');
            if (pollRef.current != null) window.clearInterval(pollRef.current);
          } else {
            setStatus(st === 'processing' ? 'processing' : 'pending');
            if (data.scan_type) setScanType(data.scan_type);
          }
        })
        .catch(() => {
          /* giữ trạng thái, lần poll sau thử lại */
        });
    };

    const connectWs = (): void => {
      try {
        const ws = new WebSocket(`${wsBase()}/ws/scan/${id}/`);
        wsRef.current = ws;
        setWsState('connecting');
        const pingInterval = setInterval(() => {
          try {
            if (ws.readyState === WebSocket.OPEN) {
              ws.send(JSON.stringify({ type: 'ping' }));
            }
          } catch {
            /* ignore */
          }
        }, 20000);
        ws.onopen = () => {
          if (!alive) return;
          setWsState('connected');
          try {
            ws.send(JSON.stringify({ type: 'get_status' }));
          } catch {
            /* bỏ qua */
          }
        };
        ws.onmessage = (e: MessageEvent) => {
          if (!alive) return;
          try {
            const data = JSON.parse(String(e.data)) as Record<string, unknown>;
            const msg = asStr(data['message']);
            if (msg) setProgress((p) => [...p, { message: msg, step: asStr(data['step']) }]);
            const step = asStr(data['step']);
            const st = asStr(data['status']);
            if (step === 'completed' || st === 'completed') {
              const inner = data['data'] as Record<string, unknown> | undefined;
              if (inner && inner['result']) {
                const r = inner['result'] as ScanResult;
                setResult({
                  ...r,
                  risk_score: asNum(inner['risk_score'] ?? r.risk_score),
                  risk_level: asStr(inner['risk_level'] ?? r.risk_level),
                });
                setStatus('completed');
              } else {
                fetchStatus();
              }
              if (pollRef.current != null) window.clearInterval(pollRef.current);
            }
            if (step === 'error' || st === 'failed') {
              setStatus('failed');
              if (pollRef.current != null) window.clearInterval(pollRef.current);
            }
          } catch {
            /* bỏ qua frame lỗi */
          }
        };
        ws.onclose = () => {
          clearInterval(pingInterval);
          if (!alive) return;
          setWsState('disconnected');
          window.setTimeout(() => {
            if (alive) connectWs();
          }, 3000);
        };
      } catch {
        setWsState('disconnected');
      }
    };

    // Lấy trạng thái ban đầu (kèm scan_type để render nhãn)
    fetchStatus();
    pollRef.current = window.setInterval(fetchStatus, 5000);
    connectWs();

    return () => {
      alive = false;
      if (pollRef.current != null) window.clearInterval(pollRef.current);
      try {
        wsRef.current?.close();
      } catch {
        /* bỏ qua */
      }
    };
  }, [id]);

  const reportToAdmin = (): void => {
    const reason = window.prompt('Gửi admin xác minh — Lý do cần admin verify (tuỳ chọn):');
    if (reason === null) return; // người dùng bấm Hủy
    api
      .post<{ message?: string; error?: string }>(`/scan/${id}/report-admin/`, { reason })
      .then((data) => showToast(data.message || 'Đã gửi yêu cầu xác minh.', 'success'))
      .catch((e: unknown) => showToast(e instanceof Error ? e.message : 'Không thể gửi yêu cầu xác minh.', 'error'));
  };

    const level = guardrailTone(result);
  const verdictLabel = guardrailLabel(result);
  const score = asNum(result['risk_score']);
  const detailItems = (() => {
    const items: string[] = [];
    const pushList = (v: unknown): void => {
      asArr<unknown>(v).forEach((i) => items.push(typeof i === 'string' ? i : JSON.stringify(i)));
    };
    pushList(result['patterns_found']);
    pushList(result['indicators']);
    pushList(result['details']);
    pushList(result['security_checks']);
    pushList(result['analysis_result']);
    return [...new Set(items)].slice(0, 15);
  })();
  const webSources = asArr<string>(result['web_sources']);
  const explanation = asStr(result['explanation']) || asStr(result['ai_insight']);
  const webContext = asStr(result['web_context']);

  return (
    <div className="max-w-4xl mx-auto px-6 py-8 space-y-8">
      <div className="text-center space-y-2">
        <h1 className="text-2xl font-black text-white tracking-wider uppercase">Kết quả quét #{id}</h1>
        <p className="text-xs text-white/55 font-mono">{TYPE_LABELS[scanType] || scanType}</p>
      </div>

      {(status === 'pending' || status === 'processing') && (
        <div className="liquid-card p-8 text-center space-y-6">
          <div className="spinner w-12 h-12 mx-auto text-brand-400"></div>
          <h2 className="text-xl font-black text-white">Đang xử lý...</h2>
          <p className="text-white/60 text-sm">Kết quả sẽ tự động cập nhật khi hoàn tất.</p>

          {progress.length > 0 && (
            <div className="text-left mt-6 p-5 rounded-2xl bg-white/[0.02] border border-white/[0.06]">
              <h4 className="text-[10px] font-black text-brand-400 uppercase tracking-widest mb-3">Tiến trình</h4>
              <div className="space-y-2 font-mono text-[11px] max-h-[250px] overflow-y-auto custom-scrollbar">
                {progress.map((item, index) => (
                  <div key={index} className="flex items-start gap-3 animate-fadein">
                    <span
                      className={`flex-shrink-0 mt-0.5 ${
                        item.step === 'completed' ? 'text-safe-500' : item.step === 'error' ? 'text-danger-500' : 'text-brand-500/50'
                      }`}
                    >
                      <i
                        className={`bi ${
                          item.step === 'completed'
                            ? 'bi-check-circle-fill'
                            : item.step === 'error'
                              ? 'bi-x-circle-fill'
                              : index === progress.length - 1
                                ? 'bi-arrow-right'
                                : 'bi-dot'
                        }`}
                      ></i>
                    </span>
                    <span className="text-white/80 flex-1">{item.message}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div
            className={`text-[10px] font-black uppercase tracking-wider px-3 py-1.5 rounded border inline-block ${
              wsState === 'connected'
                ? 'text-safe-400 border-safe-500/30 bg-safe-500/10'
                : 'text-warn-400 border-warn-500/30 bg-warn-500/10'
            }`}
          >
            {wsState === 'connected' ? 'WebSocket kết nối' : 'Đang kết nối...'}
          </div>
        </div>
      )}

      {status === 'failed' && (
        <div className="liquid-card p-8 text-center space-y-4">
          <div className="w-16 h-16 mx-auto rounded-full bg-danger-500/20 flex items-center justify-center">
            <i className="bi bi-exclamation-triangle-fill text-3xl text-danger-500"></i>
          </div>
          <h2 className="text-xl font-black text-danger-400">Phân tích thất bại</h2>
          <p className="text-white/60 text-sm">Đã xảy ra lỗi trong quá trình phân tích. Vui lòng thử lại.</p>
        </div>
      )}

      {status === 'completed' && (
        <div className="space-y-6 animate-fadein">
          <div className="liquid-card overflow-hidden">
            <div className="p-8 text-center border-b border-white/5 bg-white/[0.02] relative overflow-hidden">
              <div className={`absolute inset-0 opacity-10 -z-10 blur-[80px] ${riskGlow(level)}`}></div>

              <div className="text-[10px] font-black text-white/45 uppercase tracking-widest mb-4">
                {TYPE_LABELS[scanType] || scanType}
              </div>

              <div className={`inline-block px-8 py-3 rounded-full text-xs font-black tracking-[0.3em] uppercase mb-6 ${riskBadge(level)}`}>
                {verdictLabel}
              </div>

              <div className="text-5xl font-black text-white mb-2">{score}/100</div>
              <div className="text-[10px] text-white/45 font-black tracking-widest uppercase mb-6">Điểm rủi ro</div>

              <div className="w-full h-1.5 bg-white/5 rounded-full overflow-hidden max-w-md mx-auto">
                <div
                  className="h-full transition-all duration-1000"
                  style={{ width: `${score}%`, background: score >= 70 ? 'var(--sc-danger-500)' : score >= 40 ? 'var(--sc-warn-500)' : 'var(--sc-safe-500)' }}
                ></div>
              </div>
            </div>

            <div className="p-8 grid grid-cols-1 md:grid-cols-2 gap-6 border-b border-white/5">
              <div className="p-4 rounded-2xl bg-white/[0.03] space-y-1">
                <div className="text-[10px] font-black text-white/35 uppercase tracking-widest">Đối tượng kiểm tra</div>
                <div className="text-sm font-bold text-white/80 truncate">#{id} · {TYPE_LABELS[scanType] || scanType || 'Scan'}</div>
              </div>
              {result['scam_type'] && (
                <div className="p-4 rounded-2xl bg-white/[0.03] space-y-1">
                  <div className="text-[10px] font-black text-white/35 uppercase tracking-widest">Loại hình</div>
                  <div className="text-sm font-bold text-white/80">{asStr(result['scam_type'])}</div>
                </div>
              )}
              {asStr(result['domain']) && (
                <div className="p-4 rounded-2xl bg-white/[0.03] space-y-1">
                  <div className="text-[10px] font-black text-white/35 uppercase tracking-widest">Domain</div>
                  <div className="text-sm font-bold text-white/80 truncate">{asStr(result['domain'])}</div>
                </div>
              )}
              {asStr(result['page_title']) && (
                <div className="p-4 rounded-2xl bg-white/[0.03] space-y-1">
                  <div className="text-[10px] font-black text-white/35 uppercase tracking-widest">Tiêu đề trang</div>
                  <div className="text-sm font-bold text-white/80 truncate">{asStr(result['page_title'])}</div>
                </div>
              )}
            </div>

            {detailItems.length > 0 && (
              <div className="p-8 border-b border-white/5 space-y-3">
                <h4 className="text-xs font-black text-white/55 uppercase tracking-widest">Chi tiết phân tích</h4>
                <div className="space-y-2">
                  {detailItems.map((item, i) => (
                    <div key={i} className="flex items-start gap-2 text-xs text-white/60">
                      <i className="bi bi-dot text-brand-400 mt-0.5 flex-shrink-0"></i>
                      <span>{item}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {explanation && (
              <div className="p-8 bg-brand-500/[0.02]">
                <div className="flex items-center gap-3 mb-6">
                  <div className="w-10 h-10 rounded-xl bg-brand-500/20 flex items-center justify-center text-brand-400">
                    <i className="bi bi-robot"></i>
                  </div>
                  <div>
                    <h4 className="text-sm font-black text-white uppercase tracking-wider">AI Đánh Giá & Hướng Dẫn</h4>
                    <p className="text-[10px] text-white/55 font-bold uppercase tracking-widest">Phân tích dễ hiểu</p>
                  </div>
                </div>
                <MarkdownView html={renderMd(explanation)} className="text-white/70 text-sm leading-relaxed" />
              </div>
            )}

            {(webContext || webSources.length > 0) && (
              <div className="p-8 border-t border-white/5 bg-white/[0.01]">
                <div className="flex items-center gap-3 mb-6">
                  <div className="w-10 h-10 rounded-xl bg-brand-500/20 flex items-center justify-center text-brand-400">
                    <i className="bi bi-search"></i>
                  </div>
                  <div>
                    <h4 className="text-sm font-black text-white uppercase tracking-wider">Thông Tin Đối Soát Nguồn Dữ Liệu</h4>
                    <p className="text-[10px] text-white/55 font-bold uppercase tracking-widest">Dữ liệu tham chiếu</p>
                  </div>
                </div>
                {webSources.length > 0 && (
                  <div className="flex flex-wrap gap-2 mb-4">
                    {webSources.map((source) => (
                      <span key={source} className="px-3 py-1 rounded-full bg-brand-500/10 text-brand-400 text-[10px] font-black border border-brand-500/20 uppercase">
                        {source}
                      </span>
                    ))}
                  </div>
                )}
                {webContext && (
                  <MarkdownView html={renderMd(webContext)} className="text-white/60 text-xs leading-relaxed" />
                )}
              </div>
            )}

            <TrustGuardrailPanel result={result} />

            <div className="p-8 bg-white/[0.02] border-t border-white/5 flex flex-wrap gap-4 justify-center">
              <Link
                href={PAGE_MAP[scanType] || '/scan/phone/'}
                className="liquid-btn py-2 px-6 text-xs bg-brand-500/10 text-brand-400 border-brand-500/20 hover:bg-brand-500/20 font-black"
              >
                <i className="bi bi-arrow-counterclockwise"></i> Quét lại
              </Link>
              <Link
                href="/dashboard/"
                className="liquid-btn py-2 px-6 text-xs bg-white/5 text-white/60 border-white/10 hover:text-white"
              >
                <i className="bi bi-house"></i> Dashboard
              </Link>

              <button
                type="button"
                className="liquid-btn py-2 px-6 text-xs bg-danger-500/10 text-danger-400 border-danger-500/20 hover:bg-danger-500/20 font-black"
                onClick={reportToAdmin}
              >
                <i className="bi bi-flag-fill"></i> Gửi admin verify
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
