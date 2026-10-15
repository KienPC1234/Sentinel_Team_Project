'use client';
/* Port từ PKV/templates/Scan/scan_file.html — Kiểm tra Tệp tin & Mã độc.
 * API: POST /api/v1/scan/file/ (FormData: file, cf-turnstile-response)
 *      → {scan_id} rồi poll GET /scan/status/<id>/ (90s),
 *      xong stream SSE POST /api/v1/scan/analyze/stream/ để AI giải thích.
 */
import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { ApiError, api } from '../../lib/api';

import { renderMd } from '../../lib/chat/markdown';
import { MarkdownView } from '../../components/ui';
import { openSseStream } from '../../lib/chat/stream';
import {
  ScanGuide,
  TurnstileWidget,
  apiBase,
  getTsToken,
  resetTurnstile,
  showToast,
} from '../../components/ScanWidgets';
import type { ScanResult } from '../../components/ScanWidgets';
import { asStr, asNum, asArr, guardrailTone, guardrailLabel, TrustGuardrailPanel } from '../../components/ScanWidgets';

interface ForensicEvidence {
  severity?: string;
  description?: string;
  evidence?: string;
}

interface FileMeta {
  sha256?: string;
  md5?: string;
  entropy?: number;
}

function getFileIcon(name: string): string {
  const ext = (name.split('.').pop() || '').toLowerCase();
  if (['exe', 'msi', 'bat', 'cmd', 'ps1', 'vbs', 'sh', 'bin'].includes(ext)) return 'bi-file-earmark-binary text-danger-400';
  if (['zip', 'rar', '7z', 'tar', 'gz'].includes(ext)) return 'bi-file-earmark-zip text-warn-400';
  if (['pdf'].includes(ext)) return 'bi-file-earmark-pdf text-danger-400';
  if (['docx', 'xlsx', 'pptx', 'doc', 'xls'].includes(ext)) return 'bi-file-earmark-word text-brand-400';
  if (['apk'].includes(ext)) return 'bi-phone text-safe-400';
  return 'bi-file-earmark-medical text-brand2-400';
}

function formatBytes(bytes: number): string {
  if (!bytes || bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

function entropyLabel(meta: FileMeta | null, fileName: string): string {
  if (!meta || meta.entropy === undefined) return 'Bình thường';
  const ext = (fileName.split('.').pop() || '').toLowerCase();
  const isExec = ['exe', 'dll', 'sys', 'bat', 'cmd', 'ps1', 'vbs', 'bin', 'msi'].includes(ext);
  if (isExec && meta.entropy > 7.2) return 'Nén/Mã hóa cao (Đáng ngờ)';
  if (['pdf', 'zip', 'docx', 'xlsx', 'pptx', 'apk', 'rar', '7z', 'gz', 'tar'].includes(ext)) {
    return 'Nén tài liệu tiêu chuẩn (Bình thường)';
  }
  return meta.entropy > 7.4 ? 'Độ phức tạp cao' : 'Bình thường';
}

function entropyBar(meta: FileMeta | null, fileName: string): string {
  const ext = (fileName.split('.').pop() || '').toLowerCase();
  const isExec = ['exe', 'dll', 'sys', 'bat', 'cmd', 'ps1', 'vbs', 'bin', 'msi'].includes(ext);
  return isExec && meta && (meta.entropy || 0) > 7.2 ? 'bg-danger-500' : 'bg-brand-400';
}

/** Loại bỏ thẻ suy luận trước khi copy. */
function cleanAiText(text: string): string {
  return text
    .replace(/\x3Cthink[\s\S]*?\x3C\/think>/gi, '')
    .replace(/\x3Cthink[\s\S]*/gi, '')
    .trim();
}

export default function File() {
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [statusMsg, setStatusMsg] = useState('');
  const [result, setResult] = useState<ScanResult | null>(null);
  const [scanId, setScanId] = useState<number | null>(null);
  const [aiStreaming, setAiStreaming] = useState(false);
  const [aiExplanation, setAiExplanation] = useState('');
  const [copied, setCopied] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const pollRef = useRef<number | null>(null);

  const stopPoll = (): void => {
    if (pollRef.current != null) {
      window.clearInterval(pollRef.current);
      pollRef.current = null;
    }
  };

  useEffect(() => stopPoll, []);

  const reset = (): void => {
    stopPoll();
    setFile(null);
    setResult(null);
    setLoading(false);
    setScanning(false);
    setProgress(0);
    setAiStreaming(false);
    setAiExplanation('');
    setCopied(false);
    setScanId(null);
  };

  const pickFile = (f: File | undefined): void => {
    if (!f) return;
    if (f.size > 100 * 1024 * 1024) {
      showToast('Tệp quá lớn. Dung lượng tối đa được hỗ trợ tải lên là 100 MB.', 'error');
      return;
    }
    setFile(f);
    setResult(null);
    setAiExplanation('');
  };

  const startAi = (res: ScanResult, sid: number, fileName: string): void => {
    setAiStreaming(true);
    setAiExplanation('');
    void openSseStream({
      url: `${apiBase()}/scan/analyze/stream/`,
      body: {
        scan_id: sid,
        scan_type: 'file',
        scan_data: res,
        raw_input: fileName,
      },
      onEvent: (ev) => {
        if (ev.type === 'delta') setAiExplanation((t) => t + ev.text);
        else if (ev.type === 'done') setAiStreaming(false);
      },
    })
      .catch(() => {
        setAiExplanation(asStr(res['ai_explanation']) || asStr(res['summary']) || 'Không thể tạo báo cáo AI vào lúc này.');
      })
      .finally(() => setAiStreaming(false));
  };

  const startPolling = (sid: number): void => {
    stopPoll();
    let pollAttempts = 0;
    let consecutiveFailures = 0;
    const maxPollAttempts = 60; // 60 * 1.5s = 90s
    let dots = 0;
    pollRef.current = window.setInterval(() => {
      pollAttempts++;
      if (pollAttempts > maxPollAttempts) {
        stopPoll();
        showToast('Quá trình phân tích tệp tin vượt quá thời gian chờ (90s). Vui lòng thử lại.', 'warning');
        reset();
        return;
      }
      api
        .get<{ status?: string; result?: ScanResult }>('/scan/status/' + sid + '/')
        .then((data) => {
          const st = asStr(data.status).toLowerCase();
          if (st === 'completed') {
            setProgress(100);
            const res = (data.result || {}) as ScanResult;
            setResult(res);
            setScanning(false);
            stopPoll();
            startAi(res, sid, file?.name || asStr(res['file_name']) || 'Tệp tin');
          } else if (st === 'failed') {
            stopPoll();
            showToast('Hệ thống gặp lỗi trong quá trình quét mã độc.', 'error');
            reset();
          } else {
            consecutiveFailures = 0;
            setProgress((p) => (p < 90 ? p + 2 : p));
            dots = (dots + 1) % 4;
            setStatusMsg('Hệ thống đang kiểm tra an toàn' + '.'.repeat(dots));
          }
        })
        .catch((err: unknown) => {
          consecutiveFailures++;
          const status = (err as { status?: number })?.status;
          if (consecutiveFailures >= 6) {
            stopPoll();
            showToast(
              status === 404
                ? 'Không tìm thấy phiên quét tệp tin trên máy chủ.'
                : `Máy chủ phản hồi lỗi (${status || '?'}) khi kiểm tra trạng thái file.`,
              'error',
            );
            reset();
          }
        });
    }, 1500);
  };

  const startScan = (): void => {
    if (!file) return;
    const tsToken = getTsToken();
    if (!tsToken) {
      showToast('Vui lòng hoàn thành xác minh anti-spam.', 'warning');
      try {
        resetTurnstile();
      } catch {
        /* bỏ qua */
      }
      return;
    }
    setLoading(true);
    setProgress(15);
    setStatusMsg('Đang tải file lên kiểm tra...');

    const formData = new FormData();
    formData.append('file', file);
    formData.append('cf-turnstile-response', tsToken);
    try {
      resetTurnstile();
    } catch {
      /* bỏ qua */
    }

    api
      .upload<{ scan_id?: number; error?: string }>('/scan/file/', formData)
      .then((data) => {
        if (typeof data.scan_id === 'number') {
          setScanId(data.scan_id);
          setLoading(false);
          setScanning(true);
          setStatusMsg('Hệ thống đang phân tích mã độc...');
          startPolling(data.scan_id);
        } else {
          const msg = data.error || 'Lỗi khi tải file lên.';
          if (msg.includes('anti-spam')) {
            showToast('Phiên xác minh đã hết hạn. Vui lòng xác minh lại.', 'warning');
            try {
              resetTurnstile();
            } catch {
              /* bỏ qua */
            }
          } else {
            showToast(msg, 'error');
          }
          reset();
        }
      })
      .catch((e: unknown) => {
        if (e instanceof ApiError && e.status === 413) {
          showToast('Dung lượng tệp vượt quá giới hạn tải lên (mã lỗi 413 - Tối đa 100 MB). Vui lòng chọn tệp nhỏ hơn.', 'error');
        } else {
          showToast(e instanceof Error ? e.message : 'Lỗi kết nối máy chủ hoặc gián đoạn đường truyền tải file.', 'error');
        }
        reset();
      });
  };

  const copyAi = (): void => {
    if (!aiExplanation) return;
    try {
      void navigator.clipboard.writeText(cleanAiText(aiExplanation)).then(() => {
        setCopied(true);
        window.setTimeout(() => setCopied(false), 2000);
      });
    } catch {
      showToast('Không thể sao chép.', 'error');
    }
  };

  const level = guardrailTone(result);
  const verdictLabel = guardrailLabel(result);
  const score = asNum(result?.['risk_score']);
  const fileName = asStr(result?.['file_name']);
  const meta = (result?.['file_metadata'] as FileMeta | undefined) || null;
  const evidences = asArr<ForensicEvidence>(result?.['forensic_evidence']);
  const clamav = (result?.['clamav'] as Record<string, unknown> | undefined) || {};
  const gauge = 339.3 * (1 - score / 100);

  return (
    <div className="max-w-7xl mx-auto px-4 pt-16 sm:pt-20 pb-20 lg:grid lg:grid-cols-[1fr_340px] lg:gap-8 lg:items-start">
      <div className="space-y-8 min-w-0">
        <div className="text-center mb-10">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-brand2-500/10 border border-brand2-500/20 text-brand2-400 text-xs font-black uppercase tracking-widest mb-5">
            <i className="bi bi-shield-check"></i> Kiểm Tra File An Toàn
          </div>
          <h1 className="text-3xl sm:text-5xl font-black text-white tracking-tight mb-3">
            Kiểm Tra Tệp Tin & Mã Độc
          </h1>
          <p className="text-white/60 text-sm sm:text-base max-w-2xl mx-auto">
            Tự động quét và phát hiện các loại virus, mã độc tống tiền, phần mềm gián điệp và file lừa đảo trước khi mở trên thiết bị của bạn.
          </p>
        </div>

        {!result && (
          <div className="liquid-card p-8 sm:p-12 mb-8 relative group">
            <div className="relative z-10">
              {!file && (
                <div
                  className={`flex flex-col items-center justify-center py-12 border-2 border-dashed border-white/10 rounded-2xl hover:border-brand2-500/30 transition-all cursor-pointer ${dragging ? 'bg-brand2-500/10 border-brand2-500/50 scale-[0.99]' : ''}`}
                  onClick={() => fileInputRef.current?.click()}
                  onDragOver={(e) => {
                    e.preventDefault();
                    setDragging(true);
                  }}
                  onDragLeave={(e) => {
                    e.preventDefault();
                    setDragging(false);
                  }}
                  onDrop={(e) => {
                    e.preventDefault();
                    setDragging(false);
                    pickFile(e.dataTransfer.files[0]);
                  }}
                >
                  <input type="file" ref={fileInputRef} className="hidden" onChange={(e) => pickFile(e.target.files?.[0])} />
                  <i className="bi bi-cloud-arrow-up text-5xl text-white/35 mb-4 group-hover:text-brand2-500/50 transition-colors"></i>
                  <p className="text-white font-bold text-lg mb-2">Click hoặc kéo thả file vào đây</p>
                  <p className="text-white/55 text-sm">Hỗ trợ .exe, .zip, .rar, .pdf, .docx, .xlsx, .apk, .bat, .ps1, .vbs (Tối đa 100MB)</p>
                </div>
              )}

              {file && (
                <div className="bg-black/30 rounded-2xl p-6 border border-white/10 flex items-center gap-4">
                  <div className="w-14 h-14 rounded-xl bg-brand2-500/10 flex items-center justify-center text-brand2-500 text-2xl">
                    <i className={`bi ${getFileIcon(file.name)}`}></i>
                  </div>
                  <div className="flex-1 min-w-0">
                    <h4 className="text-white font-bold truncate">{file.name}</h4>
                    <p className="text-white/55 text-xs">{formatBytes(file.size)}</p>
                  </div>
                  {!loading && !scanning && (
                    <button type="button" onClick={reset} className="text-white/45 hover:text-white transition-colors">
                      <i className="bi bi-x-circle text-xl"></i>
                    </button>
                  )}
                  {loading && <div className="w-8 h-8 rounded-full border-2 border-brand2-500/20 border-t-brand2-500 animate-spin"></div>}
                </div>
              )}

              {file && !loading && !scanning && (
                <div className="mt-8 flex flex-col items-center gap-6">
                  <TurnstileWidget />
                  <button
                    type="button"
                    onClick={startScan}
                    className="liquid-button bg-brand2-500 hover:bg-brand2-400 text-white px-12 py-4 rounded-2xl font-black uppercase tracking-widest shadow-xl shadow-brand2-500/25 flex items-center gap-3"
                  >
                    <i className="bi bi-shield-check"></i> Bắt Đầu Kiểm Tra
                  </button>
                </div>
              )}

              {(loading || scanning) && (
                <div className="mt-8 space-y-4">
                  <div className="flex items-center justify-between text-xs font-bold">
                    <span className="text-brand2-400 uppercase tracking-widest flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-brand2-400 animate-ping"></span>
                      <span>{statusMsg}</span>
                    </span>
                    <span className="text-white/60">{progress}%</span>
                  </div>
                  <div className="overflow-hidden h-2.5 rounded-full bg-white/5 border border-white/5">
                    <div style={{ width: `${progress}%` }} className="h-full bg-gradient-to-r from-brand2-500 via-brand2-500 to-brand-400 transition-all duration-500"></div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {result && (
          <div className="animate__animated animate__fadeInUp space-y-6">
            <div
              className={`p-8 rounded-3xl border shadow-xl ${
                level === 'RED'
                  ? 'bg-danger-500/10 border-danger-500/30 shadow-danger-500/10'
                  : level === 'YELLOW'
                    ? 'bg-warn-500/10 border-warn-500/30 shadow-warn-500/10'
                    : level === 'UNVERIFIED'
                      ? 'bg-slate-500/10 border-slate-400/30 shadow-slate-500/10'
                      : 'bg-safe-500/10 border-safe-500/30 shadow-safe-500/10'
              }`}
            >
              <div className="flex flex-col sm:flex-row items-center gap-8">
                <div className="relative flex-shrink-0">
                  <svg className="w-32 h-32 transform -rotate-90">
                    <circle cx="64" cy="64" r="54" stroke="currentColor" strokeWidth="8" fill="transparent" className="text-white/5" />
                    <circle
                      cx="64" cy="64" r="54" stroke="currentColor" strokeWidth="8" fill="transparent"
                      strokeDasharray={339.3} strokeDashoffset={gauge}
                      className={`transition-all duration-1000 ease-out ${level === 'RED' ? 'text-danger-500' : level === 'YELLOW' ? 'text-warn-400' : level === 'UNVERIFIED' ? 'text-slate-400' : 'text-safe-400'}`}
                    />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className="text-3xl font-black text-white">{score}</span>
                    <span className="text-[9px] uppercase font-bold text-white/55">Mức Rủi Ro</span>
                  </div>
                </div>

                <div className="flex-1 text-center sm:text-left space-y-2">
                  <div className="flex flex-wrap items-center justify-center sm:justify-start gap-2">
                    <span
                      className={`px-3.5 py-1 rounded-full text-xs font-black uppercase tracking-wider ${
                        level === 'RED' ? 'bg-danger-500 text-white' : level === 'YELLOW' ? 'bg-warn-400 text-black' : level === 'UNVERIFIED' ? 'bg-slate-500 text-white' : 'bg-safe-400 text-black'
                      }`}
                    >
                      {verdictLabel}
                    </span>
                    <span className="bg-white/10 text-white/70 px-3 py-1 rounded-full text-xs font-medium border border-white/5 flex items-center gap-1.5">
                      <i className="bi bi-shield-check text-brand2-400"></i> Phòng Cách Ly An Toàn
                    </span>
                  </div>
                  <h2 className="text-2xl font-black text-white">{fileName}</h2>
                  <p className="text-white/60 text-sm">{asStr(result['summary'])}</p>
                </div>
              </div>
            </div>

            <div className="liquid-card p-6 sm:p-8 border border-brand2-500/20 bg-gradient-to-br from-brand2-500/[0.03] to-brand2-500/[0.03] rounded-3xl shadow-2xl relative overflow-hidden">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-white/10">
                <div className="flex items-center gap-3">
                  <div className="w-12 h-12 rounded-2xl bg-gradient-to-tr from-brand2-500 to-brand2-600 flex items-center justify-center text-white text-xl shadow-lg shadow-brand2-500/20 flex-shrink-0">
                    <i className="bi bi-robot"></i>
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="text-lg font-black text-white">AI Đánh Giá & Hướng Dẫn Chi Tiết</h3>
                      <span className="px-2 py-0.5 rounded-full bg-brand2-500/20 text-brand2-300 text-[10px] font-black uppercase">Dễ Hiểu</span>
                    </div>
                    <p className="text-xs text-white/60">Phân tích bản chất tệp tin, nguy cơ tiềm ẩn và cách xử lý an toàn</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {aiExplanation && !aiStreaming && (
                    <button type="button" onClick={copyAi} className="text-xs bg-white/5 hover:bg-white/10 border border-white/10 px-3.5 py-2 rounded-xl text-white/80 hover:text-white transition-all flex items-center gap-1.5">
                      <i className="bi bi-clipboard"></i> <span>{copied ? 'Đã sao chép!' : 'Sao chép'}</span>
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => result && scanId != null && startAi(result, scanId, file?.name || fileName || 'Tệp tin')}
                    disabled={aiStreaming}
                    className="text-xs bg-brand2-500/20 hover:bg-brand2-500/30 border border-brand2-500/30 px-4 py-2 rounded-xl text-brand2-300 font-bold transition-all flex items-center gap-1.5"
                  >
                    <i className={`bi bi-arrow-clockwise ${aiStreaming ? 'animate-spin' : ''}`}></i>
                    <span>{aiStreaming ? 'Đang viết...' : 'Tạo Lại Báo Cáo'}</span>
                  </button>
                </div>
              </div>

              <div className="pt-6">
                {aiStreaming && !aiExplanation && (
                  <div className="flex items-center gap-3 py-6 text-brand2-400 text-sm font-medium">
                    <div className="w-5 h-5 rounded-full border-2 border-brand2-400/20 border-t-brand2-400 animate-spin"></div>
                    <span>AI đang phân tích và chuẩn bị báo cáo dễ hiểu...</span>
                  </div>
                )}
                {aiExplanation && (
                  <MarkdownView html={renderMd(aiExplanation)} />
                )}
                {aiStreaming && aiExplanation && (
                  <span className="inline-block w-2 h-4 bg-brand2-400 animate-pulse ml-1 align-middle"></span>
                )}
                {!aiStreaming && !aiExplanation && (
                  <div className="text-center py-8 space-y-3">
                    <p className="text-white/60 text-sm">Chưa tạo báo cáo giải thích. Nhấn nút bên dưới để AI phân tích chi tiết.</p>
                    <button
                      type="button"
                      onClick={() => result && scanId != null && startAi(result, scanId, file?.name || fileName || 'Tệp tin')}
                      className="px-6 py-2.5 rounded-xl bg-brand2-500 hover:bg-brand2-400 text-white font-bold text-xs uppercase tracking-wider transition-all"
                    >
                      <i className="bi bi-magic mr-1"></i> Nhờ AI Giải Thích File Này
                    </button>
                  </div>
                )}
              </div>
            </div>

            {evidences.length > 0 && (
              <div className="liquid-card p-6 border border-white/10 rounded-2xl">
                <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                  <i className="bi bi-exclamation-octagon text-brand2-400"></i> Dấu Hiệu Bất Thường Phát Hiện Được
                </h3>
                <div className="space-y-3">
                  {evidences.map((evidence, idx) => (
                    <div key={idx} className="bg-black/30 border border-white/10 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span
                            className={`px-2.5 py-0.5 rounded text-[10px] font-black uppercase border ${
                              evidence.severity === 'CRITICAL' || evidence.severity === 'HIGH'
                                ? 'bg-danger-500/20 text-danger-400 border-danger-500/30'
                                : evidence.severity === 'MEDIUM'
                                  ? 'bg-warn-500/20 text-warn-400 border-warn-500/30'
                                  : 'bg-brand-500/20 text-brand-400 border-brand-500/30'
                            }`}
                          >
                            {evidence.severity}
                          </span>
                          <span className="text-white font-semibold text-sm">{evidence.description}</span>
                        </div>
                        {evidence.evidence && (
                          <p className="text-white/55 text-xs font-mono">Dấu hiệu: {evidence.evidence}</p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="liquid-card p-6 border border-white/10 rounded-2xl space-y-3">
                <h3 className="text-sm font-bold uppercase tracking-wider text-white/60 flex items-center gap-2">
                  <i className="bi bi-fingerprint text-brand2-400"></i> Mã Định Danh Tệp (SHA-256 / MD5)
                </h3>
                <div className="space-y-2 text-xs font-mono">
                  <div>
                    <span className="text-white/55">Mã SHA-256:</span>
                    <div className="text-white/80 break-all bg-black/40 p-2 rounded mt-1 border border-white/5">{meta?.sha256 || 'N/A'}</div>
                  </div>
                  <div>
                    <span className="text-white/55">Mã MD5:</span>
                    <div className="text-white/80 break-all bg-black/40 p-2 rounded mt-1 border border-white/5">{meta?.md5 || 'N/A'}</div>
                  </div>
                </div>
              </div>

              <div className="liquid-card p-6 border border-white/10 rounded-2xl space-y-4">
                <h3 className="text-sm font-bold uppercase tracking-wider text-white/60 flex items-center gap-2">
                  <i className="bi bi-shield-check text-brand-400"></i> Trạng Thái Kiểm Tra Diệt Virus
                </h3>
                <div>
                  <div className="flex justify-between text-xs font-bold mb-1">
                    <span className="text-white">Độ phức tạp tệp: <span className="text-brand2-400">{meta?.entropy ?? '0.0'}</span> / 8.0</span>
                    <span className="text-white/55">{entropyLabel(meta, fileName)}</span>
                  </div>
                  <div className="overflow-hidden h-2 rounded-full bg-white/5 border border-white/5">
                    <div
                      style={{ width: `${((meta?.entropy || 0) / 8.0) * 100}%` }}
                      className={`h-full ${entropyBar(meta, fileName)}`}
                    ></div>
                  </div>
                </div>
                <div className="pt-2 border-t border-white/5 space-y-1.5 text-xs">
                  <div className="flex justify-between">
                    <span className="text-white/60">Phần mềm diệt virus:</span>
                    <span className="text-safe-400 font-semibold">
                      {clamav['available'] ? (clamav['infected'] ? 'Phát hiện độc hại' : 'Đã quét (Sạch)') : 'Sẵn sàng'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-white/60">Môi trường kiểm tra:</span>
                    <span className="text-brand-400 font-semibold">Cách ly an toàn 100%</span>
                  </div>
                </div>
              </div>
            </div>

            <TrustGuardrailPanel result={result} />

            <div className="flex flex-wrap gap-4 pt-4">
              <button type="button" onClick={reset} className="bg-white/5 hover:bg-white/10 border border-white/10 px-8 py-3.5 rounded-xl text-white font-bold transition-all">
                <i className="bi bi-arrow-repeat mr-1"></i> Kiểm Tra File Khác
              </button>
              <Link
                href={`/report/?scammer_name=${encodeURIComponent(file?.name || '')}&target_type=file`}
                className="bg-danger-500/20 hover:bg-danger-500/30 border border-danger-500/30 px-8 py-3.5 rounded-xl text-danger-400 font-bold transition-all flex items-center gap-2"
              >
                <i className="bi bi-exclamation-triangle"></i> Báo Cáo Mã Độc Này
              </Link>

            </div>
          </div>
        )}
      </div>
      <ScanGuide scanType="file" />
    </div>
  );
}
