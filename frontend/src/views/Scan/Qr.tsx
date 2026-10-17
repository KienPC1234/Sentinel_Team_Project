'use client';
/* Port từ PKV/templates/Scan/scan_qr.html — Kiểm tra QR / Hình ảnh.
 * API: POST /api/v1/scan/image/ (FormData: image[], cf-turnstile-response)
 *      → {scan_id} rồi WS /ws/scan/<id>/ + poll GET /scan/status/<id>/.
 */
import { useRef, useState } from 'react';
import Link from 'next/link';
import { api } from '../../lib/api';

import { renderMd } from '../../lib/chat/markdown';
import { MarkdownView } from '../../components/ui';
import {
  OsintSection,
  TrustGuardrailPanel,
  ProgressConsole,
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

interface QrEntities {
  phones?: string[];
  urls?: string[];
  bank_accounts?: string[];
  emails?: string[];
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

function patternLabel(p: unknown): string {
  if (typeof p === 'string') return p;
  if (p && typeof p === 'object') {
    const o = p as Record<string, unknown>;
    const l = o['label'] ?? o['pattern'];
    return typeof l === 'string' ? l : JSON.stringify(p);
  }
  return String(p);
}

export default function Qr({ mode = 'qr' }: { mode?: 'qr' | 'image' } = {}) {
  const [files, setFiles] = useState<File[]>([]);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [scanId, setScanId] = useState<number | null>(null);
  const [trackOn, setTrackOn] = useState(false);
  const [previewImage, setPreviewImage] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const qrInputRef = useRef<HTMLInputElement>(null);

  const tracker = useScanTracker(scanId, {
    enabled: trackOn && scanId != null,
    onDone: (d: TrackerDone) => {
      const merged = { ...d.result, risk_score: d.risk_score, risk_level: d.risk_level };
      setResult(merged);
      setLoading(false);
      setTrackOn(false);
    },
    onError: (msg: string) => {
      showToast(msg, 'error');
      setLoading(false);
      setTrackOn(false);
    },
  });

  const addFiles = (incoming: FileList | File[]): void => {
    const list = Array.from(incoming);
    setFiles((prev) => {
      const fresh = list.filter((f) => !prev.some((e) => e.name === f.name && e.size === f.size));
      return [...prev, ...fresh];
    });
  };

  const removeFile = (index: number): void => {
    setFiles((prev) => prev.filter((_, i) => i !== index));
    if (qrInputRef.current) qrInputRef.current.value = '';
  };

  const clearFiles = (): void => {
    setFiles([]);
    if (qrInputRef.current) qrInputRef.current.value = '';
  };

  const handleScan = (): void => {
    if (!files.length) {
      showToast('Vui lòng chọn ảnh', 'warning');
      return;
    }
    const tsToken = getTsToken();
    if (!tsToken) {
      showToast('Vui lòng hoàn thành xác minh anti-spam', 'warning');
      setLoading(false);
      return;
    }
    try {
      resetTurnstile();
    } catch {
      /* bỏ qua */
    }
    setLoading(true);
    setResult(null);
    setScanId(null);
    setTrackOn(false);
    tracker.clear();
    tracker.push('Đang kết nối hệ thống phân tích...', 'init');

    const fd = new FormData();
    fd.append('cf-turnstile-response', tsToken);
    files.forEach((f) => fd.append('image', f));

    api
      .upload<ScanResult>('/scan/image/', fd)
      .then((data) => {
        const sid = data['scan_id'];
        if (typeof sid === 'number') {
          setScanId(sid);
          setTrackOn(true);
        } else {
          showToast('Không nhận được ID scan.', 'error');
          setLoading(false);
        }
      })
      .catch((e: unknown) => {
        showToast(e instanceof Error ? e.message : 'Có lỗi xảy ra.', 'error');
        setLoading(false);
      });
  };

    const level = guardrailTone(result);
  const verdictLabel = guardrailLabel(result);
  const score = asNum(result?.['risk_score']);
  const annotatedImages = asArr<string>(result?.['annotated_images']);
  const annotatedImage = asStr(result?.['annotated_image']);
  const annotatedGallery = asArr<string>(result?.['annotated_gallery']);
  const qrContents = asArr<string>(result?.['qr_contents']);
  const entities = (result?.['entities'] as QrEntities | undefined) || null;
  const patterns = asArr<unknown>(result?.['patterns_found']);
  const explanation = asStr(result?.['explanation']);
  const ocrText = asStr(result?.['ocr_text']);

  return (
    <div className="max-w-7xl mx-auto px-4 pt-16 sm:pt-20 pb-20 lg:grid lg:grid-cols-[1fr_340px] lg:gap-8 lg:items-start">
      <div
        className="space-y-10"
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragging(true);
        }}
        onDragLeave={(e) => {
          e.preventDefault();
          setIsDragging(false);
        }}
        onDrop={(e) => {
          e.preventDefault();
          setIsDragging(false);
          if (e.dataTransfer.files.length) addFiles(e.dataTransfer.files);
        }}
        onPaste={(e) => {
          const items = e.clipboardData?.items;
          if (!items) return;
          const imgs: File[] = [];
          for (let i = 0; i < items.length; i++) {
            if (items[i].type.indexOf('image') !== -1) {
              const f = items[i].getAsFile();
              if (f) imgs.push(f);
            }
          }
          if (imgs.length) addFiles(imgs);
        }}
      >
        <div className="text-center space-y-4">
          <div className="inline-flex items-center justify-center w-20 h-20 rounded-[2rem] bg-brand-500/10 text-brand-400 border border-brand-500/20 shadow-lg shadow-brand-500/10 mb-5">
            <i className={mode === 'image' ? 'bi bi-image text-4xl' : 'bi bi-qr-code-scan text-4xl'}></i>
          </div>
          <h1 className="text-4xl font-black text-white tracking-tight leading-none">
            {mode === 'image' ? (
              <>Kiểm tra <span className="glow-text">Ảnh / Chứng từ</span></>
            ) : (
              <>Kiểm tra <span className="glow-text">QR / Hình ảnh</span></>
            )}
          </h1>
          <p className="text-white/55 max-w-md mx-auto text-sm leading-relaxed">
            {mode === 'image'
              ? 'Tải lên ảnh chụp màn hình chuyển khoản, tin nhắn, hoá đơn, giấy tờ hoặc thông báo nghi giả mạo — hệ thống đọc nội dung (OCR) và phân tích rủi ro.'
              : 'Tải lên hoặc kéo thả ảnh chụp QR code, link lừa đảo hoặc thông báo giả mạo để hệ thống phân tích rủi ro.'}
          </p>
        </div>

        {previewImage && (
          <div
            className="fixed inset-0 z-[200] flex items-center justify-center p-4 bg-black/90 backdrop-blur-sm"
            onClick={() => setPreviewImage(null)}
          >
            <img src={previewImage} className="max-w-full max-h-full object-contain rounded-lg shadow-2xl" alt="" onClick={(e) => e.stopPropagation()} />
            <button type="button" className="absolute top-6 right-6 text-white/60 hover:text-white bg-black/50 w-10 h-10 rounded-full flex items-center justify-center" onClick={() => setPreviewImage(null)}>
              <i className="bi bi-x-lg text-xl"></i>
            </button>
          </div>
        )}

        <div
          className={`liquid-card p-6 sm:p-8 ${isDragging ? 'border-brand-500 border-dashed ring-4 ring-brand-500/20' : ''}`}
        >
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleScan();
            }}
          >
            <div className="flex flex-col sm:flex-row gap-4 items-center">
              <label className="liquid-btn flex-1 py-4 px-8 text-sm font-bold bg-white/5 border-white/10 hover:bg-white/10 cursor-pointer text-center group">
                <span className="flex items-center justify-center gap-3">
                  <i className="bi bi-cloud-upload text-xl group-hover:scale-110 transition-transform"></i>
                  <span>{isDragging ? 'THẢ ẢNH VÀO ĐÂY' : files.length ? `ĐÃ CHỌN ${files.length} ẢNH` : 'CHỌN HOẶC KÉO THẢ ẢNH ĐỂ PHÂN TÍCH'}</span>
                </span>
                <input
                  type="file"
                  ref={qrInputRef}
                  accept="image/*"
                  className="hidden"
                  multiple
                  onChange={(e) => {
                    if (e.target.files) addFiles(e.target.files);
                    e.target.value = '';
                  }}
                />
              </label>
              {files.length > 0 && (
                <button type="button" onClick={clearFiles} className="liquid-btn bg-danger-500/10 text-danger-400 px-6 py-4 font-black hover:bg-danger-500/20">
                  <i className="bi bi-trash mr-2"></i> XÓA TẤT CẢ
                </button>
              )}
              <button type="submit" className="liquid-btn bg-brand-500 text-black px-12 py-4 font-black hover:bg-brand-400" disabled={loading}>
                {!loading ? (
                  <span><i className="bi bi-cpu mr-2"></i> PHÂN TÍCH</span>
                ) : (
                  <span className="spinner w-5 h-5 border-black"></span>
                )}
              </button>
            </div>
            <TurnstileWidget />
          </form>

          {files.length > 0 && (
            <div className="mt-6 w-full overflow-x-auto pb-4 custom-scrollbar">
              <div className="flex gap-3 min-w-min px-1 justify-center">
                {files.map((file, index) => (
                  <div key={index} className="relative shrink-0 w-24 h-24 group cursor-pointer" onClick={() => setPreviewImage(URL.createObjectURL(file))}>
                    <img src={URL.createObjectURL(file)} className="w-full h-full object-cover rounded-xl border border-white/10 group-hover:border-brand-500/50 transition-colors shadow-lg shadow-black/50" alt="" />
                    <div className="absolute top-0 right-0 p-2 z-10">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          removeFile(index);
                        }}
                        className="bg-danger-500/80 hover:bg-danger-600/80 text-white rounded-full w-7 h-7 flex items-center justify-center text-sm shadow-md"
                      >
                        <i className="bi bi-x"></i>
                      </button>
                    </div>
                    <div className="absolute inset-0 bg-black/50 opacity-0 group-hover:opacity-100 transition-opacity rounded-xl flex items-center justify-center">
                      <i className="bi bi-zoom-in text-white text-xl"></i>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {loading && tracker.progress.length > 0 && (
          <ProgressConsole title="Nhật ký phân tích thời gian thực" progress={tracker.progress} wsState={tracker.wsState} accent="cyan" />
        )}

        {result && (
          <div className="space-y-8 animate-fadein">
            <div className="liquid-card overflow-hidden">
              <div className="p-8 text-center border-b border-white/5 bg-white/[0.02] relative overflow-hidden">
                <div className={`absolute inset-0 opacity-10 -z-10 blur-[80px] ${riskGlow(level)}`}></div>

                <div className={`inline-block px-8 py-3 rounded-full text-xs font-black tracking-[0.3em] uppercase mb-6 ${riskBadge(level)}`}>
                  {verdictLabel}
                </div>

                <div className="text-5xl font-black text-white mb-2">{score}/100</div>
                <div className="text-[10px] text-white/45 font-black tracking-widest uppercase mb-8">Tổng quan rủi ro hình ảnh</div>
              </div>

              <div className="p-8 space-y-10">
                {(annotatedImages.length > 0 || annotatedImage) && (
                  <div className="space-y-4">
                    <h4 className="text-xs font-black text-white/55 uppercase tracking-widest flex items-center gap-2">
                      <i className="bi bi-bounding-box"></i> Phân tích vùng text & QR từ ảnh
                    </h4>
                    <div className={`grid gap-4 ${annotatedImages.length > 1 ? 'grid-cols-1 md:grid-cols-2' : 'grid-cols-1'}`}>
                      {annotatedImages.length > 0 ? (
                        annotatedImages.map((img, idx) => (
                          <div key={idx} className="rounded-3xl overflow-hidden border border-white/5 shadow-2xl bg-black/30 flex items-center justify-center p-4 max-h-[400px] overflow-auto custom-scrollbar cursor-pointer" onClick={() => setPreviewImage(img)}>
                            <img src={img} className="max-w-full max-h-[360px] object-contain rounded-xl" alt={`Ảnh phân tích ${idx + 1}`} />
                          </div>
                        ))
                      ) : (
                        <div className="rounded-3xl overflow-hidden border border-white/5 shadow-2xl bg-black/30 flex items-center justify-center p-4 max-h-[400px] overflow-auto custom-scrollbar cursor-pointer" onClick={() => setPreviewImage(annotatedImage)}>
                          <img src={annotatedImage} className="max-w-full max-h-[360px] object-contain rounded-xl" alt="Analyzed Image" />
                        </div>
                      )}
                    </div>
                    <div className="flex items-center gap-4 text-[10px] text-white/45 font-bold">
                      <span className="flex items-center gap-1"><span className="inline-block w-3 h-1 rounded bg-safe-400"></span> Text (high conf)</span>
                      <span className="flex items-center gap-1"><span className="inline-block w-3 h-1 rounded bg-warn-400"></span> Text (medium)</span>
                      <span className="flex items-center gap-1"><span className="inline-block w-3 h-1 rounded bg-danger-400"></span> Text (low)</span>
                      <span className="flex items-center gap-1"><span className="inline-block w-3 h-1 rounded bg-brand-400"></span> QR Code</span>
                    </div>
                  </div>
                )}

                {annotatedImages.length === 0 && !annotatedImage && annotatedGallery.length > 0 && (
                  <div className="space-y-4">
                    <h4 className="text-xs font-black text-white/55 uppercase tracking-widest flex items-center gap-2">
                      <i className="bi bi-image"></i> Hình ảnh đã gán nhãn
                    </h4>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      {annotatedGallery.map((img, idx) => (
                        <div key={idx} className="liquid-glass p-2 border-white/10 group relative cursor-zoom-in" onClick={() => setPreviewImage(img)}>
                          <div className="relative overflow-hidden rounded-lg">
                            <img src={img} className="w-full h-auto rounded-lg shadow-xl group-hover:scale-105 transition-transform duration-500" alt="" />
                          </div>
                          <div className="mt-2 flex justify-between items-center px-2">
                            <span className="text-[10px] font-black text-white/45 uppercase tracking-widest">Ảnh {idx + 1}</span>
                            <i className="bi bi-arrows-fullscreen text-white/35 group-hover:text-white/60 transition-colors text-xs"></i>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {qrContents.length > 0 && (
                  <div className="space-y-4">
                    <h4 className="text-xs font-black text-brand-400 uppercase tracking-widest flex items-center gap-2">
                      <i className="bi bi-qr-code"></i> Nội dung mã QR phát hiện
                    </h4>
                    <div className="space-y-3">
                      {qrContents.map((qr, idx) => (
                        <div key={idx} className="p-4 bg-brand-500/5 border border-brand-500/10 rounded-2xl flex items-center gap-4 group">
                          <div className="w-10 h-10 rounded-xl bg-brand-500/20 flex items-center justify-center text-brand-400">
                            <i className="bi bi-link-45deg text-xl"></i>
                          </div>
                          <div className="flex-1 overflow-hidden">
                            <p className="text-white font-mono text-xs truncate">{qr}</p>
                          </div>
                          <button
                            type="button"
                            onClick={() => {
                              try {
                                void navigator.clipboard.writeText(qr).then(() => showToast('Đã sao chép!', 'success'));
                              } catch {
                                showToast('Không thể sao chép.', 'error');
                              }
                            }}
                            className="liquid-btn p-2 bg-white/5 text-white/55 hover:text-brand-400 border-white/5 transition-all"
                          >
                            <i className="bi bi-copy"></i>
                          </button>
                          <Link
                            href={`/scan/website/?url=${encodeURIComponent(qr)}`}
                            className="liquid-btn p-2 bg-brand-500/10 text-brand-400 border-brand-500/10 hover:bg-brand-500/20"
                          >
                            <i className="bi bi-search"></i>
                          </Link>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {entities && (
                  <div className="space-y-4">
                    <h4 className="text-xs font-black text-white/55 uppercase tracking-widest flex items-center gap-2">
                      <i className="bi bi-search"></i> Thông tin trích xuất (OCR)
                    </h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {(entities.phones?.length || 0) > 0 && (
                        <div className="p-4 rounded-2xl bg-white/[0.02] border border-white/5">
                          <div className="text-[9px] font-black text-white/35 uppercase tracking-widest mb-3">Số điện thoại</div>
                          <div className="flex flex-wrap gap-2">
                            {(entities.phones || []).map((p) => (
                              <Link key={p} href={`/scan/phone/?phone=${encodeURIComponent(p)}`} className="px-3 py-1 rounded bg-brand-500/10 text-brand-400 text-[10px] font-bold border border-brand-500/20 hover:bg-brand-500/20 transition-all">
                                {p}
                              </Link>
                            ))}
                          </div>
                        </div>
                      )}
                      {(entities.urls?.length || 0) > 0 && (
                        <div className="p-4 rounded-2xl bg-white/[0.02] border border-white/5">
                          <div className="text-[9px] font-black text-white/35 uppercase tracking-widest mb-3">Liên kết (Links)</div>
                          <div className="flex flex-wrap gap-2">
                            {(entities.urls || []).map((u) => (
                              <Link key={u} href={`/scan/website/?url=${encodeURIComponent(u)}`} className="px-3 py-1 rounded bg-brand2-500/10 text-brand2-400 text-[10px] font-bold border border-brand2-500/20 hover:bg-brand2-500/20 transition-all truncate max-w-[200px]">
                                {u}
                              </Link>
                            ))}
                          </div>
                        </div>
                      )}
                      {(entities.bank_accounts?.length || 0) > 0 && (
                        <div className="p-4 rounded-2xl bg-white/[0.02] border border-white/5">
                          <div className="text-[9px] font-black text-white/35 uppercase tracking-widest mb-3">Tài khoản ngân hàng</div>
                          <div className="flex flex-wrap gap-2">
                            {(entities.bank_accounts || []).map((b) => (
                              <Link key={b} href={`/scan/bank/?account=${encodeURIComponent(b)}`} className="px-3 py-1 rounded bg-warn-500/10 text-warn-400 text-[10px] font-bold border border-warn-500/20 hover:bg-warn-500/20 transition-all">
                                {b}
                              </Link>
                            ))}
                          </div>
                        </div>
                      )}
                      {(entities.emails?.length || 0) > 0 && (
                        <div className="p-4 rounded-2xl bg-white/[0.02] border border-white/5">
                          <div className="text-[9px] font-black text-white/35 uppercase tracking-widest mb-3">Email</div>
                          <div className="flex flex-wrap gap-2">
                            {(entities.emails || []).map((em) => (
                              <Link key={em} href={`/scan/email/?email=${encodeURIComponent(em)}`} className="px-3 py-1 rounded bg-warn-500/10 text-warn-400 text-[10px] font-bold border border-warn-500/20 hover:bg-warn-500/20 transition-all">
                                {em}
                              </Link>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {ocrText && (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <h4 className="text-xs font-black text-white/55 uppercase tracking-widest flex items-center gap-2">
                        <i className="bi bi-file-earmark-text"></i> Nội dung văn bản trích xuất (OCR)
                      </h4>
                      <span className="text-[10px] text-white/40 font-mono">{ocrText.length} ký tự</span>
                    </div>
                    <div className="p-4 rounded-2xl bg-white/[0.02] border border-white/5 max-h-60 overflow-y-auto custom-scrollbar font-mono text-xs text-white/80 whitespace-pre-wrap leading-relaxed select-all">
                      {ocrText}
                    </div>
                  </div>
                )}

                {patterns.length > 0 && (
                  <div className="space-y-3">
                    <h4 className="text-xs font-black text-white/55 uppercase tracking-widest flex items-center gap-2">
                      <i className="bi bi-exclamation-triangle"></i> Dấu hiệu phát hiện
                    </h4>
                    <div className="flex flex-wrap gap-2">
                      {patterns.map((p, i) => (
                        <span key={i} className="px-4 py-2 rounded-xl bg-danger-500/10 border border-danger-500/20 text-danger-400 text-xs font-bold">
                          {patternLabel(p)}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                <div className="space-y-4">
                  <h4 className="text-xs font-black text-brand-400 uppercase tracking-widest flex items-center gap-2">
                    <i className="bi bi-robot"></i> Nhận định của trí tuệ nhân tạo
                  </h4>
                  <div className="p-6 rounded-[2.5rem] bg-brand-500/[0.03] border border-brand-500/10 shadow-inner">
                    <MarkdownView html={renderMd(explanation)} className="prose prose-invert prose-cyan max-w-none text-white/70 text-sm leading-relaxed" />
                    {!explanation && <p className="text-white/35 text-xs italic">Đang chờ phản hồi từ AI...</p>}
                  </div>
                </div>
              </div>

              <TrustGuardrailPanel result={result} />
              <OsintSection result={result} />

              <div className="p-8 bg-white/[0.02] border-t border-white/5 flex flex-wrap gap-4 justify-between items-center">
                <div className="flex gap-4">
                  <button
                    type="button"
                    className="liquid-btn py-2 px-6 text-xs bg-white/5 text-white/60 border-white/10 hover:text-white"
                    onClick={() => {
                      try {
                        void navigator.clipboard.writeText(JSON.stringify(result, null, 2)).then(() => showToast('Đã copy kết quả!', 'success'));
                      } catch {
                        showToast('Không thể sao chép.', 'error');
                      }
                    }}
                  >
                    <i className="bi bi-clipboard-data"></i> Copy kết quả
                  </button>
                  <button
                    type="button"
                    className="liquid-btn py-2 px-6 text-xs bg-brand-500/10 text-brand-400 border-brand-500/20 hover:bg-brand-500/20 transition-all font-black"
                    onClick={() => dispatchChat(`QR/Image Scan Result\nRisk: ${score}/100\nAnalysis: ${explanation}`)}
                  >
                    <i className="bi bi-chat-dots-fill"></i> CHAT VỚI AI
                  </button>
                </div>
                <Link
                  href="/report/?target_type=qr"
                  className="liquid-btn py-2 px-8 text-xs bg-danger-500/20 text-danger-500 border-danger-500/30 hover:bg-danger-500/30 transition-all font-black"
                >
                  <i className="bi bi-megaphone-fill"></i> BÁO CÁO VI PHẠM
                </Link>

              </div>
            </div>
          </div>
        )}
      </div>
      <ScanGuide scanType="qr" />
    </div>
  );
}
