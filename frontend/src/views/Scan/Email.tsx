'use client';
/* Port từ PKV/templates/Scan/scan_email.html — Kiểm tra Email Scam.
 * API: POST /api/v1/scan/email/ (JSON {email, content} hoặc FormData {file})
 *      → báo cáo nhanh {scan_id, preliminary_score...} rồi WS/poll deep scan.
 */
import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { api } from '../../lib/api';


import { renderMd } from '../../lib/chat/markdown';
import { MarkdownView } from '../../components/ui';
import {
  OsintSection,
  TrustGuardrailPanel,
  ScanGuide,
  TurnstileWidget,
  dispatchChat,
  getTsToken,
  resetTurnstile,
  showToast,
  useScanTracker,
} from '../../components/ScanWidgets';
import type { ScanResult, TrackerDone } from '../../components/ScanWidgets';
import { asStr, asNum, asArr, guardrailTone, guardrailLabel } from '../../components/ScanWidgets';

interface ExtractedInfo {
  subject?: string;
  from?: string;
  url_count?: number;
  attachment_count?: number;
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

function deepItems(result: ScanResult): string[] {
  const raw = result['analysis_result'];
  if (Array.isArray(raw)) {
    const arr = raw.map((v) => (v ?? '').toString().trim()).filter(Boolean);
    if (arr.length) return arr;
  }
  if (typeof raw === 'string' && raw.trim()) {
    const text = raw.trim();
    try {
      const parsed: unknown = JSON.parse(text);
      if (Array.isArray(parsed)) {
        const arr = parsed.map((v) => (v ?? '').toString().trim()).filter(Boolean);
        if (arr.length) return arr;
      }
    } catch {
      /* không phải JSON, dùng nguyên văn */
    }
    return [text];
  }
  if (raw && typeof raw === 'object') {
    const arr = Object.values(raw as Record<string, unknown>)
      .map((v) => (v ?? '').toString().trim())
      .filter(Boolean);
    if (arr.length) return arr;
  }
  const fallback: string[] = [];
  const explanation = asStr(result['explanation']);
  if (explanation) fallback.push(`AI nhận định: ${explanation}`);
  const weighted = result['eml_weighted_score'];
  if (weighted !== undefined && weighted !== null) {
    fallback.push(`Điểm phân tích chuyên sâu: ${String(weighted)}/100`);
  }
  if (result['web_context']) {
    fallback.push('Đã hoàn tất phân tích chuyên sâu. Chi tiết nguồn nằm trong mục Thông tin tình báo (OSINT).');
  }
  return fallback;
}

export default function Email() {
  const [mode, setMode] = useState<'text' | 'eml'>('text');
  const [email, setEmail] = useState(() => '');
  const [content, setContent] = useState('');
  const [emlFile, setEmlFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [quickReportText, setQuickReportText] = useState('');
  const [deepProcessing, setDeepProcessing] = useState(false);
  const [deepCompleted, setDeepCompleted] = useState(false);
  const [deepStatusMessage, setDeepStatusMessage] = useState('');
  const [scanId, setScanId] = useState<number | null>(null);
  const [trackOn, setTrackOn] = useState(false);
  const [displayEmail, setDisplayEmail] = useState('');
  const emlInputRef = useRef<HTMLInputElement>(null);

  const applyDeepResult = (merged: ScanResult, score?: number, level?: string): void => {
    const next = { ...merged };
    const hasArr = Array.isArray(next['analysis_result']) && (next['analysis_result'] as unknown[]).length > 0;
    const hasStr = typeof next['analysis_result'] === 'string' && (next['analysis_result'] as string).trim().length > 0;
    if (!hasArr && !hasStr && next['web_context']) {
      next['analysis_result'] = ['Đã hoàn tất phân tích chuyên sâu từ AI. Xem chi tiết theo nguồn trong mục Thông tin tình báo (OSINT).'];
    }
    if (score !== undefined) next['risk_score'] = score;
    if (level !== undefined) next['risk_level'] = level;
    setResult(next);
    setDeepProcessing(false);
    setDeepCompleted(true);
    setDeepStatusMessage('Đã hoàn tất phân tích chuyên sâu.');
    showToast('Đã cập nhật kết quả phân tích chuyên sâu.', 'success');
  };

  const tracker = useScanTracker(scanId, {
    enabled: trackOn && scanId != null,
    pollMs: 3000,
    onDone: (d: TrackerDone) => {
      setResult((prev) => {
        const merged = { ...(prev || {}), ...d.result };
        // setTimeout tránh set-state lồng nhau trong render tracker
        window.setTimeout(() => applyDeepResult(merged, d.risk_score, d.risk_level), 0);
        return merged;
      });
      setTrackOn(false);
    },
    onError: (msg: string) => {
      setDeepProcessing(false);
      setDeepStatusMessage(msg);
      showToast(msg, 'warning');
      setTrackOn(false);
    },
  });

  const resetState = (): void => {
    setResult(null);
    setQuickReportText('');
    setDeepProcessing(false);
    setDeepCompleted(false);
    setDeepStatusMessage('');
    setScanId(null);
    setTrackOn(false);
    tracker.clear();
  };

  const handleResult = (data: ScanResult): void => {
    setResult(data);
    setLoading(false);
    const sid = data['scan_id'];
    setScanId(typeof sid === 'number' ? sid : null);
    setDeepCompleted(false);
    setDeepProcessing(true);
    setDeepStatusMessage('Đang chạy phân tích chuyên sâu bằng AI...');
    setQuickReportText(
      [
        'Đây là báo cáo nhanh từ kiểm tra DNS/SPF/DMARC và tín hiệu cơ bản.',
        'Kết quả chuyên sâu sẽ tự động cập nhật khi backend xử lý xong.',
      ].join(' '),
    );
    if (typeof sid === 'number') {
      tracker.push('Đang kết nối WebSocket...', 'init');
      setTrackOn(true);
    } else {
      setDeepProcessing(false);
    }
  };

  const submit = (override?: string): void => {
    const tsToken = getTsToken();
    if (!tsToken) {
      showToast('Vui lòng hoàn thành xác minh anti-spam', 'warning');
      return;
    }
    try {
      resetTurnstile();
    } catch {
      /* bỏ qua */
    }

    if (mode === 'text') {
      const value = (override ?? email).trim();
      if (!value) {
        showToast('Vui lòng nhập địa chỉ Email', 'warning');
        return;
      }
      setDisplayEmail(value);
      setLoading(true);
      resetState();
      api
        .post<ScanResult>('/scan/email/', {
          email: value,
          content: content.trim(),
          'cf-turnstile-response': tsToken,
        })
        .then((data) => handleResult(data))
        .catch((e: unknown) => {
          showToast(e instanceof Error ? e.message : 'Có lỗi xảy ra.', 'error');
          setLoading(false);
        });
    } else {
      if (!emlFile) {
        showToast('Vui lòng chọn file .eml', 'warning');
        return;
      }
      setLoading(true);
      resetState();
      const fd = new FormData();
      fd.append('file', emlFile);
      fd.append('cf-turnstile-response', tsToken);
      api
        .upload<ScanResult>('/scan/email/', fd)
        .then((data) => {
          const info = data['extracted_info'] as ExtractedInfo | undefined;
          setDisplayEmail(asStr(info?.from) || emlFile.name);
          handleResult(data);
        })
        .catch((e: unknown) => {
          showToast(e instanceof Error ? e.message : 'Có lỗi xử lý file.', 'error');
          setLoading(false);
        });
    }
  };

  const setFile = (f: File | undefined, resetInput: () => void): void => {
    if (!f) return;
    if (!f.name.endsWith('.eml')) {
      showToast('Chỉ hỗ trợ file .eml', 'warning');
      resetInput();
      return;
    }
    if (f.size > 10 * 1024 * 1024) {
      showToast('File quá lớn (tối đa 10MB)', 'warning');
      resetInput();
      return;
    }
    setEmlFile(f);
  };

  const clearFile = (): void => {
    setEmlFile(null);
    if (emlInputRef.current) emlInputRef.current.value = '';
  };

    const level = guardrailTone(result);
  const verdictLabel = guardrailLabel(result);
  const score = deepCompleted ? asNum(result?.['risk_score']) : asNum(result?.['preliminary_score'] ?? result?.['risk_score']);
  const securityChecks = asArr<string>(result?.['security_checks']);
  const extracted = (result?.['extracted_info'] as ExtractedInfo | undefined) || null;
  const items = result ? deepItems(result) : [];
  const emlSize = emlFile ? `${(emlFile.size / 1024).toFixed(1)} KB` : '';

  // Deep-link ?email= tự quét sau mount (SSR-safe, y bản gốc).
  useEffect(() => {
    const q = new URLSearchParams(window.location.search).get('email');
    if (q) {
      setEmail(q);
      submit(q);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="max-w-7xl mx-auto px-4 pt-16 sm:pt-20 pb-20 lg:grid lg:grid-cols-[1fr_340px] lg:gap-8 lg:items-start">
      <div className="animate-fadein space-y-10">
        <div className="text-center space-y-4">
          <div className="inline-flex items-center justify-center w-20 h-20 rounded-3xl bg-brand-500/10 text-brand-400 mb-5 border border-brand-500/20 shadow-lg shadow-brand-500/10">
            <i className="bi bi-envelope-exclamation text-4xl"></i>
          </div>
          <h1 className="text-4xl font-black text-white tracking-tight">
            Kiểm tra <span className="glow-text">Email Scam</span>
          </h1>
          <p className="text-white/55 max-w-md mx-auto text-sm leading-relaxed">
            Phát hiện email lừa đảo, giả mạo hoặc chứa nội dung độc hại bằng công nghệ AI.
          </p>
        </div>

        <div className="liquid-card p-6 sm:p-8 space-y-6">
          <div className="flex gap-2 p-1 rounded-2xl bg-white/5 border border-white/10 dropdown-container">
            <button
              type="button"
              className={`flex-1 flex items-center justify-center gap-2 py-3 rounded-xl text-xs font-black uppercase tracking-widest transition-all ${
                mode === 'text' ? 'bg-brand-500 text-black shadow-lg shadow-brand-500/30' : 'text-white/55 hover:text-white/70'
              }`}
              onClick={() => {
                setMode('text');
                resetState();
              }}
            >
              <i className="bi bi-envelope-at text-sm"></i> Nhập Email
            </button>
            <button
              type="button"
              className={`flex-1 flex items-center justify-center gap-2 py-3 rounded-xl text-xs font-black uppercase tracking-widest transition-all ${
                mode === 'eml' ? 'bg-brand-500 text-black shadow-lg shadow-brand-500/30' : 'text-white/55 hover:text-white/70'
              }`}
              onClick={() => {
                setMode('eml');
                resetState();
              }}
            >
              <i className="bi bi-file-earmark-arrow-up text-sm"></i> Tải lên .eml
            </button>
          </div>

          {mode === 'text' && (
            <div className="space-y-4">
              <div className="space-y-1.5">
                <label className="text-[10px] font-black text-white/45 uppercase tracking-[0.2em] ml-2">
                  Địa chỉ Email người gửi <span className="text-brand-500">*</span>
                </label>
                <input
                  type="email"
                  className="liquid-input w-full py-4 px-6 text-lg font-bold"
                  placeholder="sender@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  autoComplete="off"
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-[10px] font-black text-white/45 uppercase tracking-[0.2em] ml-2">
                  Nội dung Email <span className="text-white/35">(không bắt buộc)</span>
                </label>
                <textarea
                  className="liquid-input w-full py-4 px-6 min-h-[130px] text-sm resize-none"
                  placeholder="Dán tiêu đề, nội dung hoặc link trong email tại đây để AI phân tích chuyên sâu hơn..."
                  value={content}
                  onChange={(e) => setContent(e.target.value)}
                ></textarea>
              </div>
            </div>
          )}

          {mode === 'eml' && (
            <div className="space-y-4">
              <div
                className="relative"
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => {
                  e.preventDefault();
                  setFile(e.dataTransfer.files[0], () => undefined);
                }}
              >
                <input
                  type="file"
                  accept=".eml"
                  ref={emlInputRef}
                  className="hidden"
                  onChange={(e) => setFile(e.target.files?.[0], () => {
                    if (emlInputRef.current) emlInputRef.current.value = '';
                  })}
                />

                {!emlFile && (
                  <div
                    className="border-2 border-dashed border-white/10 rounded-2xl p-10 text-center cursor-pointer hover:border-brand-500/40 hover:bg-brand-500/[0.03] transition-all"
                    onClick={() => emlInputRef.current?.click()}
                  >
                    <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-brand-500/10 text-brand-400 mb-4 border border-brand-500/20">
                      <i className="bi bi-cloud-arrow-up text-2xl"></i>
                    </div>
                    <p className="text-white/60 font-bold text-sm mb-1">Kéo thả file .eml vào đây</p>
                    <p className="text-white/55 text-xs mb-4">hoặc nhấn để chọn từ thiết bị</p>
                    <span className="inline-block px-4 py-1.5 rounded-lg bg-white/5 border border-white/10 text-white/55 text-xs font-bold">Chọn file .eml</span>
                  </div>
                )}

                {emlFile && (
                  <div className="flex items-center gap-4 p-5 rounded-2xl border border-brand-500/20 bg-brand-500/[0.04]">
                    <div className="flex-shrink-0 w-12 h-12 rounded-xl bg-brand-500/15 flex items-center justify-center text-brand-400 text-xl border border-brand-500/20">
                      <i className="bi bi-file-earmark-text"></i>
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-white font-bold text-sm truncate">{emlFile.name}</p>
                      <p className="text-white/55 text-xs font-bold mt-0.5">{emlSize}</p>
                    </div>
                    <button
                      type="button"
                      onClick={clearFile}
                      className="flex-shrink-0 w-8 h-8 rounded-lg bg-white/5 hover:bg-danger-500/20 hover:text-danger-400 text-white/45 flex items-center justify-center transition-all text-xs"
                    >
                      <i className="bi bi-x-lg"></i>
                    </button>
                  </div>
                )}
              </div>

              <div className="grid grid-cols-3 gap-3 text-center">
                <div className="p-3 rounded-xl bg-white/[0.03] border border-white/5">
                  <i className="bi bi-person-circle text-brand-400 text-base block mb-1"></i>
                  <span className="text-[10px] text-white/45 font-bold uppercase tracking-wider">Người gửi</span>
                </div>
                <div className="p-3 rounded-xl bg-white/[0.03] border border-white/5">
                  <i className="bi bi-link-45deg text-brand-400 text-base block mb-1"></i>
                  <span className="text-[10px] text-white/45 font-bold uppercase tracking-wider">Đường dẫn</span>
                </div>
                <div className="p-3 rounded-xl bg-white/[0.03] border border-white/5">
                  <i className="bi bi-paperclip text-brand-400 text-base block mb-1"></i>
                  <span className="text-[10px] text-white/45 font-bold uppercase tracking-wider">Đính kèm</span>
                </div>
              </div>
            </div>
          )}

          <div className="space-y-4">
            <TurnstileWidget />
            <button
              type="button"
              className="liquid-btn w-full bg-brand-500 text-black py-5 font-black uppercase tracking-widest hover:bg-brand-400 transition-all"
              disabled={loading}
              onClick={() => submit()}
            >
              {!loading ? (
                <span><i className="bi bi-shield-shaded mr-2"></i>
                  <span>{mode === 'eml' ? 'PHÂN TÍCH FILE .EML' : 'BẮT ĐẦU PHÂN TÍCH'}</span>
                </span>
              ) : (
                <span className="flex items-center justify-center gap-3">
                  <span className="spinner w-5 h-5 border-black"></span>
                  <span className="text-black/70">Đang phân tích...</span>
                </span>
              )}
            </button>
          </div>
        </div>

        {result && (
          <div className="space-y-6">
            <div className="liquid-card overflow-hidden">
              <div className="p-8 text-center border-b border-white/5 bg-white/[0.02] relative overflow-hidden">
                <div className={`absolute inset-0 opacity-10 -z-10 blur-[80px] ${riskGlow(level)}`}></div>
                <div className={`inline-block px-8 py-3 rounded-full text-xs font-black tracking-[0.3em] uppercase mb-6 ${riskBadge(level)}`}>
                  {verdictLabel}
                </div>
                <div className="text-5xl font-black text-white mb-2">{score}/100</div>
                <div className="text-[10px] text-white/45 font-black tracking-widest uppercase mb-4">Chỉ số rủi ro Email</div>

                {deepProcessing && (
                  <div className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-brand-500/10 border border-brand-500/20 text-brand-300 text-xs font-bold">
                    <span className="spinner w-3.5 h-3.5 text-brand-300"></span>
                    <span>{deepStatusMessage}</span>
                  </div>
                )}
                {deepCompleted && (
                  <div className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-safe-500/10 border border-safe-500/20 text-safe-300 text-xs font-bold">
                    <i className="bi bi-check-circle-fill"></i>
                    <span>{deepStatusMessage}</span>
                  </div>
                )}
              </div>

              {deepProcessing && tracker.progress.length > 0 && (
                <div className="mx-8 mt-4 p-5 rounded-2xl border border-brand-500/20 bg-brand-500/[0.02]">
                  <div className="mb-3 flex items-center justify-between gap-3">
                    <h4 className="text-[10px] font-black text-brand-400 uppercase tracking-widest">Tiến trình phân tích thời gian thực</h4>
                    <div
                      className={`text-[10px] font-black uppercase tracking-wider px-2 py-1 rounded border ${
                        tracker.wsState === 'connected'
                          ? 'text-safe-400 border-safe-500/30 bg-safe-500/10'
                          : tracker.wsState === 'reconnecting' || tracker.wsState === 'connecting'
                            ? 'text-warn-400 border-warn-500/30 bg-warn-500/10'
                            : 'text-danger-400 border-danger-500/30 bg-danger-500/10'
                      }`}
                    >
                      {tracker.wsState === 'connected' ? 'WS' : tracker.wsState === 'reconnecting' ? '...' : tracker.wsState === 'connecting' ? '...' : 'Poll'}
                    </div>
                  </div>
                  <div className="w-full h-1 bg-white/5 rounded-full overflow-hidden mb-3">
                    <div
                      className="h-full bg-brand-500/50 transition-all duration-500 rounded-full"
                      style={{ width: `${Math.min(95, tracker.progress.length * 15)}%` }}
                    ></div>
                  </div>
                  <div className="space-y-2 font-mono text-[11px] max-h-[200px] overflow-y-auto custom-scrollbar">
                    {tracker.progress.map((item, index) => (
                      <div key={index} className="flex items-start gap-2.5 animate-fadein">
                        <span
                          className={`flex-shrink-0 mt-0.5 ${
                            item.step === 'completed'
                              ? 'text-safe-500'
                              : item.step.includes('warning')
                                ? 'text-warn-500'
                                : item.step === 'error'
                                  ? 'text-danger-500'
                                  : item.step.includes('done') || item.step.includes('ok')
                                    ? 'text-safe-400'
                                    : 'text-brand-500/50'
                          }`}
                        >
                          <i
                            className={`bi ${
                              item.step === 'completed'
                                ? 'bi-check-circle-fill'
                                : item.step.includes('warning')
                                  ? 'bi-exclamation-triangle'
                                  : item.step === 'error'
                                    ? 'bi-x-circle-fill'
                                    : item.step.includes('done') || item.step.includes('ok')
                                      ? 'bi-check2'
                                      : index === tracker.progress.length - 1
                                        ? 'bi-arrow-right'
                                        : 'bi-dot'
                            }`}
                          ></i>
                        </span>
                        <span className="text-white/80 flex-1">{item.message}</span>
                        {index === tracker.progress.length - 1 && item.step !== 'completed' && (
                          <i className="bi bi-three-dots animate-pulse text-brand-400 flex-shrink-0"></i>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {extracted && (extracted.subject || (extracted.url_count || 0) > 0 || (extracted.attachment_count || 0) > 0) && (
                <div className="flex flex-wrap justify-center gap-3 mx-8 mt-4">
                  {extracted.subject && (
                    <span className="px-3 py-1 rounded-lg bg-white/5 border border-white/10 text-white/60 text-xs font-bold">
                      <i className="bi bi-chat-square-text mr-1 text-brand-400"></i>
                      <span>{extracted.subject}</span>
                    </span>
                  )}
                  {(extracted.url_count || 0) > 0 && (
                    <span className="px-3 py-1 rounded-lg bg-warn-500/10 border border-warn-500/20 text-warn-400 text-xs font-bold">
                      <i className="bi bi-link-45deg mr-1"></i>
                      <span>{extracted.url_count} đường dẫn</span>
                    </span>
                  )}
                  {(extracted.attachment_count || 0) > 0 && (
                    <span className="px-3 py-1 rounded-lg bg-warn-500/10 border border-warn-500/20 text-warn-400 text-xs font-bold">
                      <i className="bi bi-paperclip mr-1"></i>
                      <span>{extracted.attachment_count} tệp đính kèm</span>
                    </span>
                  )}
                </div>
              )}

              {securityChecks.length > 0 && (
                <div className="mx-8 mt-6 p-5 rounded-2xl bg-white/[0.02] border border-white/[0.06]">
                  <h4 className="text-[10px] font-black text-white/45 uppercase tracking-widest mb-3">Kiểm tra bảo mật DNS/SPF/DMARC</h4>
                  <ul className="space-y-2">
                    {securityChecks.map((check, i) => (
                      <li key={i} className="flex items-start gap-2 text-xs text-white/60">
                        <i className="bi bi-shield-check text-brand-400 mt-0.5 flex-shrink-0"></i>
                        <span>{check}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {!deepCompleted && (
                <div className="m-8 p-6 liquid-glass border-white/5 bg-brand-500/[0.02]">
                  <div className="flex items-center gap-3 mb-6">
                    <div className="w-10 h-10 rounded-xl bg-brand-500/20 flex items-center justify-center text-brand-400">
                      <i className="bi bi-clipboard-data"></i>
                    </div>
                    <div>
                      <h4 className="text-sm font-black text-white uppercase tracking-wider">Báo cáo nhanh</h4>
                      <p className="text-[10px] text-white/55 font-bold uppercase tracking-widest">Pre-check Summary</p>
                    </div>
                  </div>
                  <MarkdownView
                    html={renderMd(quickReportText || 'Hệ thống đã hoàn tất báo cáo nhanh và đang chờ phân tích chuyên sâu...')}
                    className="text-white/70 text-sm leading-relaxed"
                  />
                </div>
              )}

              {deepCompleted && items.length > 0 && (
                <div className="m-8 p-6 liquid-glass border-white/5 bg-brand-500/[0.03]">
                  <div className="flex items-center gap-3 mb-5">
                    <div className="w-10 h-10 rounded-xl bg-brand-500/20 flex items-center justify-center text-brand-400">
                      <i className="bi bi-cpu"></i>
                    </div>
                    <div>
                      <h4 className="text-sm font-black text-white uppercase tracking-wider">Phân tích chuyên sâu</h4>
                      <p className="text-[10px] text-white/55 font-bold uppercase tracking-widest">Deep AI + EML Signals</p>
                    </div>
                  </div>
                  <ul className="space-y-2">
                    {items.map((item, idx) => (
                      <li key={idx} className="flex items-start gap-2 text-xs text-white/70">
                        <i className="bi bi-dot text-brand-400 mt-0.5"></i>
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <TrustGuardrailPanel result={result} />
              <OsintSection result={result} />

              <div className="p-8 bg-white/[0.02] border-t border-white/5 flex flex-wrap gap-4 justify-between items-center">
                <div className="flex gap-3 flex-wrap">
                  <button
                    type="button"
                    className="liquid-btn py-2 px-5 text-xs bg-white/5 text-white/60 border-white/10 hover:text-white"
                    onClick={() => {
                      try {
                        void navigator.clipboard.writeText(displayEmail).then(() => showToast('Đã copy!', 'success'));
                      } catch {
                        showToast('Không thể sao chép.', 'error');
                      }
                    }}
                  >
                    <i className="bi bi-copy"></i> Copy Email
                  </button>
                  <button
                    type="button"
                    className="liquid-btn py-2 px-5 text-xs bg-brand-500/10 text-brand-400 border-brand-500/20 hover:bg-brand-500/20 font-black"
                    onClick={() =>
                      dispatchChat(`Email: ${displayEmail}\nAnalysis: ${deepCompleted ? items.join(' | ') : quickReportText}`)
                    }
                  >
                    <i className="bi bi-chat-dots-fill"></i> CHAT VỚI AI
                  </button>
                </div>
                <Link
                  href={`/report/?target_type=email&target_value=${encodeURIComponent(displayEmail)}`}
                  className="liquid-btn py-2 px-8 text-xs bg-danger-500/20 text-danger-500 border-danger-500/30 hover:bg-danger-500/30 font-black"
                >
                  <i className="bi bi-megaphone-fill"></i> TỐ CÁO EMAIL
                </Link>

              </div>
            </div>
          </div>
        )}
      </div>
      <ScanGuide scanType="email" />
    </div>
  );
}
