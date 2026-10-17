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
  ProgressConsole,
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
  to?: string;
  url_count?: number;
  attachment_count?: number;
}

function riskBadge(level: string): string {
  if (level === 'RED') return 'bg-danger-500/20 text-danger-400 border border-danger-500/30';
  if (level === 'YELLOW') return 'bg-warn-500/20 text-warn-400 border border-warn-500/30';
  if (level === 'UNVERIFIED') return 'bg-slate-500/20 text-slate-300 border border-slate-400/30';
  return 'bg-safe-500/20 text-safe-400 border border-safe-500/30';
}

function riskGlow(level: string): string {
  if (level === 'RED') return 'bg-danger-500';
  if (level === 'YELLOW') return 'bg-warn-500';
  if (level === 'UNVERIFIED') return 'bg-slate-500';
  return 'bg-safe-500';
}

function cleanHesitationText(text: string): string {
  if (!text) return '';
  return text
    .replace(/^(?:[⏳\s]*AI cần thêm (?:chút )?thời gian[^.]*\.\s*)+/gi, '')
    .trim();
}

function getEmailExplanation(result: ScanResult | null): string {
  if (!result) return '';
  let exp = asStr(result['explanation']) || asStr(result['ai_insight']);
  if (!exp) {
    const raw = result['analysis_result'];
    if (Array.isArray(raw)) {
      const found = raw.find((v) => typeof v === 'string' && v.startsWith('AI nhận định:'));
      if (found) {
        exp = (found as string).replace(/^AI nhận định:\s*/, '');
      }
    }
  }
  return cleanHesitationText(exp);
}

function getEmailIndicators(result: ScanResult | null): string[] {
  if (!result) return [];
  const ind = asArr<string>(result['indicators']);
  if (ind.length > 0) {
    return ind
      .map((s) => cleanHesitationText(String(s)))
      .filter(Boolean);
  }
  const raw = result['analysis_result'];
  const secChecks = new Set(asArr<string>(result['security_checks']).map((s) => s.toLowerCase().trim()));
  if (Array.isArray(raw)) {
    return raw
      .map((v) => cleanHesitationText(String(v ?? '')))
      .filter((v) => {
        if (!v) return false;
        if (v.startsWith('AI nhận định:')) return false;
        if (secChecks.has(v.toLowerCase())) return false;
        if (v.toLowerCase().includes('dmarc policy:')) return false;
        return true;
      });
  }
  return [];
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
    setDeepStatusMessage('Đang phân tích chuyên sâu...');
    setQuickReportText(
      [
        'Kiểm tra sơ bộ xác thực DNS/SPF/DMARC và định danh địa chỉ người gửi đã hoàn tất.',
        'Hệ thống đang đối chiếu cơ sở dữ liệu lừa đảo và phân tích ngữ nghĩa nội dung.',
      ].join(' '),
    );
    if (typeof sid === 'number') {
      tracker.push('Bắt đầu quy trình kiểm tra bảo mật email...', 'init');
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
    if (f.size > 15 * 1024 * 1024) {
      showToast('File quá lớn (tối đa 15MB)', 'warning');
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
  const explanation = getEmailExplanation(result);
  const indicators = getEmailIndicators(result);
  const advice = asStr(result?.['advice']);
  const prevention = asArr<string>(result?.['prevention_measures']);
  const emlSize = emlFile ? `${(emlFile.size / 1024).toFixed(1)} KB` : '';

  // Deep-link ?email= tự quét sau mount. Chờ Turnstile sẵn sàng (render bất
  // đồng bộ) rồi mới submit, tránh thiếu token dẫn tới không quét được.
  useEffect(() => {
    const q = new URLSearchParams(window.location.search).get('email');
    if (!q) return;
    setEmail(q);
    let tries = 0;
    const timer = window.setInterval(() => {
      tries += 1;
      if (getTsToken()) {
        window.clearInterval(timer);
        submit(q);
      } else if (tries >= 40) {
        window.clearInterval(timer);
        showToast('Chưa xác minh anti-spam xong. Vui lòng bấm kiểm tra để thử lại.', 'warning');
      }
    }, 250);
    return () => window.clearInterval(timer);
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
            Phát hiện email lừa đảo, giả mạo mạo danh và phân tích dấu hiệu tống tiền bằng trí tuệ nhân tạo.
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
                  Nội dung Email <span className="text-white/35">(khuyến nghị dán để AI phân tích chuyên sâu)</span>
                </label>
                <textarea
                  className="liquid-input w-full py-4 px-6 min-h-[140px] text-sm resize-none"
                  placeholder="Dán tiêu đề, nội dung email hoặc tin nhắn đính kèm tại đây..."
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
                  onChange={(e) =>
                    setFile(e.target.files?.[0], () => {
                      if (emlInputRef.current) emlInputRef.current.value = '';
                    })
                  }
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
                    <p className="text-white/55 text-xs mb-4">hoặc nhấn để chọn từ thiết bị (tối đa 15MB)</p>
                    <span className="inline-block px-4 py-1.5 rounded-lg bg-white/5 border border-white/10 text-white/55 text-xs font-bold">
                      Chọn file .eml
                    </span>
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
                  <i className="bi bi-shield-lock text-brand-400 text-base block mb-1"></i>
                  <span className="text-[10px] text-white/45 font-bold uppercase tracking-wider">SPF / DKIM / DMARC</span>
                </div>
                <div className="p-3 rounded-xl bg-white/[0.03] border border-white/5">
                  <i className="bi bi-link-45deg text-brand-400 text-base block mb-1"></i>
                  <span className="text-[10px] text-white/45 font-bold uppercase tracking-wider">Quét URL Nhúng</span>
                </div>
                <div className="p-3 rounded-xl bg-white/[0.03] border border-white/5">
                  <i className="bi bi-paperclip text-brand-400 text-base block mb-1"></i>
                  <span className="text-[10px] text-white/45 font-bold uppercase tracking-wider">Tệp Đính Kèm</span>
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
                <span>
                  <i className="bi bi-shield-shaded mr-2"></i>
                  <span>{mode === 'eml' ? 'PHÂN TÍCH FILE .EML' : 'BẮT ĐẦU PHÂN TÍCH EMAIL'}</span>
                </span>
              ) : (
                <span className="flex items-center justify-center gap-3">
                  <span className="spinner w-5 h-5 border-black"></span>
                  <span className="text-black/70">Đang khởi tạo phiên quét...</span>
                </span>
              )}
            </button>
          </div>
        </div>

        {deepProcessing && tracker.progress.length > 0 && (
          <ProgressConsole
            title="Tiến trình phân tích email thời gian thực"
            progress={tracker.progress}
            wsState={tracker.wsState}
            accent="cyan"
          />
        )}

        {result && (
          <div className="space-y-8 animate-fadein">
            <div className="liquid-card overflow-hidden">
              {/* 1. Header Risk Card */}
              <div className="p-8 text-center border-b border-white/5 bg-white/[0.02] relative overflow-hidden">
                <div className={`absolute inset-0 opacity-15 -z-10 blur-[90px] ${riskGlow(level)}`}></div>
                <div className={`inline-block px-8 py-3 rounded-full text-xs font-black tracking-[0.3em] uppercase mb-6 ${riskBadge(level)}`}>
                  {verdictLabel}
                </div>
                <div className="text-5xl font-black text-white mb-2">{score}/100</div>
                <div className="text-[10px] text-white/45 font-black tracking-widest uppercase mb-4">
                  Chỉ số rủi ro Email (Weighted EML + AI Signals)
                </div>

                {deepProcessing && (
                  <div className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-brand-500/10 border border-brand-500/20 text-brand-300 text-xs font-bold">
                    <span className="spinner w-3.5 h-3.5 text-brand-300"></span>
                    <span>{deepStatusMessage}</span>
                  </div>
                )}
                {deepCompleted && (
                  <div className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-safe-500/10 border border-safe-500/20 text-safe-300 text-xs font-bold">
                    <i className="bi bi-check-circle-fill"></i>
                    <span>Đã hoàn tất phân tích toàn diện</span>
                  </div>
                )}
              </div>

              <div className="p-6 sm:p-8 space-y-8">
                {/* 2. Trích xuất thông tin Email (Email Metadata Header) */}
                <div className="space-y-3">
                  <h4 className="text-[11px] font-black text-white/45 uppercase tracking-[0.2em] flex items-center gap-2">
                    <i className="bi bi-info-circle text-brand-400"></i>
                    Thông tin định danh Email
                  </h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                    <div className="p-4 rounded-2xl bg-white/[0.02] border border-white/10 flex flex-col justify-between">
                      <span className="text-[10px] font-black text-brand-300 uppercase tracking-widest mb-1">Người gửi (From)</span>
                      <p className="text-white text-xs font-mono font-bold truncate" title={displayEmail}>
                        {displayEmail || 'Chưa xác định'}
                      </p>
                    </div>

                    <div className="p-4 rounded-2xl bg-white/[0.02] border border-white/10 flex flex-col justify-between">
                      <span className="text-[10px] font-black text-brand-300 uppercase tracking-widest mb-1">Tiêu đề (Subject)</span>
                      <p className="text-white text-xs font-medium truncate" title={extracted?.subject || 'Không có tiêu đề'}>
                        {extracted?.subject || 'Không có tiêu đề'}
                      </p>
                    </div>

                    <div className="p-4 rounded-2xl bg-white/[0.02] border border-white/10 flex flex-col justify-between">
                      <span className="text-[10px] font-black text-brand-300 uppercase tracking-widest mb-1">Liên kết nhúng (URLs)</span>
                      <div className="flex items-center gap-2">
                        <i className={`bi bi-link-45deg text-sm ${(extracted?.url_count || 0) > 0 ? 'text-warn-400' : 'text-white/40'}`}></i>
                        <span className="text-white text-xs font-bold">{extracted?.url_count || 0} liên kết</span>
                      </div>
                    </div>

                    <div className="p-4 rounded-2xl bg-white/[0.02] border border-white/10 flex flex-col justify-between">
                      <span className="text-[10px] font-black text-brand-300 uppercase tracking-widest mb-1">Tệp đính kèm</span>
                      <div className="flex items-center gap-2">
                        <i className={`bi bi-paperclip text-sm ${(extracted?.attachment_count || 0) > 0 ? 'text-warn-400' : 'text-white/40'}`}></i>
                        <span className="text-white text-xs font-bold">{extracted?.attachment_count || 0} tệp</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* 3. AI Nhận định chuyên sâu */}
                {(explanation || (!deepCompleted && quickReportText)) && (
                  <div className="p-6 rounded-2xl border border-brand-500/20 bg-brand-500/[0.03] space-y-4">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-xl bg-brand-500/20 flex items-center justify-center text-brand-400">
                        <i className="bi bi-robot text-lg"></i>
                      </div>
                      <div>
                        <h4 className="text-sm font-black text-white uppercase tracking-wider">AI Nhận định chuyên sâu</h4>
                        <p className="text-[10px] text-white/55 font-bold uppercase tracking-widest">
                          {deepCompleted ? 'Phân tích ngữ nghĩa & Hành vi tống tiền' : 'Báo cáo kiểm tra sơ bộ'}
                        </p>
                      </div>
                    </div>

                    <div className="text-white/80 text-sm leading-relaxed pl-1">
                      <MarkdownView
                        html={renderMd(
                          explanation || quickReportText || 'Đang tổng hợp thông tin phân tích...',
                        )}
                        className="prose prose-invert max-w-none text-white/85 text-[13px] sm:text-[14px] leading-relaxed"
                      />
                    </div>

                    {advice && (
                      <div className="mt-4 p-4 rounded-xl bg-brand-500/10 border border-brand-500/20 flex items-start gap-3">
                        <i className="bi bi-lightbulb-fill text-brand-300 mt-0.5 text-base shrink-0"></i>
                        <div>
                          <p className="text-[10px] font-black text-brand-300 uppercase tracking-widest mb-0.5">Khuyến nghị tức thì</p>
                          <p className="text-white/90 text-xs font-medium">{advice}</p>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* 4. Dấu hiệu cảnh báo lừa đảo (Threat Indicators) */}
                {indicators.length > 0 && (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <h4 className="text-[11px] font-black text-danger-400 uppercase tracking-[0.2em] flex items-center gap-2">
                        <i className="bi bi-exclamation-octagon-fill"></i>
                        Dấu hiệu cảnh báo nguy hiểm ({indicators.length})
                      </h4>
                      <span className="text-[10px] font-bold text-white/40 uppercase tracking-wider">AI Fraud Flags</span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {indicators.map((ind, i) => (
                        <div
                          key={i}
                          className="p-3.5 rounded-xl bg-danger-500/[0.08] border border-danger-500/25 flex items-start gap-3 hover:bg-danger-500/[0.12] transition-colors"
                        >
                          <i className="bi bi-shield-x text-danger-400 mt-0.5 shrink-0 text-sm"></i>
                          <span className="text-white/90 text-xs font-semibold leading-relaxed">{ind}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* 5. Kiểm tra kỹ thuật giao thức (DNS / SPF / DMARC) */}
                {securityChecks.length > 0 && (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <h4 className="text-[11px] font-black text-white/45 uppercase tracking-[0.2em] flex items-center gap-2">
                        <i className="bi bi-shield-check text-brand-400"></i>
                        Xác thực giao thức & Bản ghi kỹ thuật (DNS/SPF/DMARC)
                      </h4>
                      <span className="text-[10px] font-bold text-white/40 uppercase tracking-wider">Header & Domain Auth</span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {securityChecks.map((check, i) => {
                        const isSafe = check.toLowerCase().includes('an toàn') || check.toLowerCase().includes('hợp lệ') || check.toLowerCase().includes('strict');
                        const isWarn = check.toLowerCase().includes('cảnh báo') || check.toLowerCase().includes('chưa cấu hình') || check.toLowerCase().includes('thiếu');
                        return (
                          <div
                            key={i}
                            className={`p-3.5 rounded-xl border flex items-start gap-3 ${
                              isSafe
                                ? 'bg-safe-500/[0.05] border-safe-500/20'
                                : isWarn
                                  ? 'bg-warn-500/[0.05] border-warn-500/20'
                                  : 'bg-white/[0.02] border-white/10'
                            }`}
                          >
                            <i
                              className={`bi mt-0.5 shrink-0 text-sm ${
                                isSafe
                                  ? 'bi-check-circle-fill text-safe-400'
                                  : isWarn
                                    ? 'bi-exclamation-triangle-fill text-warn-400'
                                    : 'bi-shield-shaded text-brand-400'
                              }`}
                            ></i>
                            <span className="text-white/85 text-xs font-medium leading-relaxed">{check}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* 6. Biện pháp phòng tránh đề xuất */}
                {prevention.length > 0 && (
                  <div className="p-6 rounded-2xl border border-safe-500/20 bg-safe-500/[0.03] space-y-4">
                    <h4 className="text-[11px] font-black text-safe-400 uppercase tracking-[0.2em] flex items-center gap-2">
                      <i className="bi bi-shield-check"></i>
                      Biện pháp phòng vệ khuyến nghị
                    </h4>
                    <ul className="space-y-2">
                      {prevention.map((step, idx) => (
                        <li key={idx} className="flex items-start gap-2.5 text-xs text-white/85">
                          <i className="bi bi-check2 text-safe-400 mt-0.5 shrink-0 text-sm"></i>
                          <span>{step}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* 7. Guardrail & OSINT Sections */}
                <TrustGuardrailPanel result={result} />
                <OsintSection result={result} />

                {/* 8. Quick Actions */}
                <div className="pt-6 border-t border-white/5 flex flex-wrap gap-4 justify-between items-center">
                  <div className="flex gap-3 flex-wrap">
                    <button
                      type="button"
                      className="liquid-btn py-2.5 px-5 text-xs bg-white/5 text-white/70 border-white/10 hover:text-white"
                      onClick={() => {
                        try {
                          void navigator.clipboard.writeText(displayEmail).then(() => showToast('Đã sao chép địa chỉ email!', 'success'));
                        } catch {
                          showToast('Không thể sao chép.', 'error');
                        }
                      }}
                    >
                      <i className="bi bi-copy mr-1.5"></i> Copy Email
                    </button>
                    <button
                      type="button"
                      className="liquid-btn py-2.5 px-5 text-xs bg-brand-500/10 text-brand-300 border-brand-500/20 hover:bg-brand-500/20 font-black"
                      onClick={() =>
                        dispatchChat(
                          `Email: ${displayEmail}\nTiêu đề: ${extracted?.subject || 'Không có'}\nĐánh giá rủi ro: ${score}/100 (${verdictLabel})\nNhận định: ${explanation}`,
                        )
                      }
                    >
                      <i className="bi bi-chat-dots-fill mr-1.5"></i> CHAT VỚI AI VỀ EMAIL NÀY
                    </button>
                  </div>
                  <Link
                    href={`/report/?target_type=email&target_value=${encodeURIComponent(displayEmail)}`}
                    className="liquid-btn py-2.5 px-8 text-xs bg-danger-500/20 text-danger-400 border-danger-500/30 hover:bg-danger-500/30 font-black"
                  >
                    <i className="bi bi-megaphone-fill mr-1.5"></i> TỐ CÁO EMAIL
                  </Link>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
      <ScanGuide scanType="email" />
    </div>
  );
}
