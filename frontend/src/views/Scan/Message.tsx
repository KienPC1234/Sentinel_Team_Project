'use client';
/* Port từ PKV/templates/Scan/scan_message.html — Kiểm tra Văn bản / Tin nhắn.
 * API: POST /api/v1/scan/message/ (FormData: message, image[], cf-turnstile-response)
 *      → {scan_id, status} rồi WS /ws/scan/<id>/ + poll GET /scan/status/<id>/.
 */
import { useRef, useState } from 'react';
import Link from 'next/link';
import { api } from '../../lib/api';


import { renderMd } from '../../lib/chat/markdown';
import { MarkdownView } from '../../components/ui';
import { Button } from '../../components/ui/button';
import { Card } from '../../components/ui/card';
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

interface OsintEntities {
  urls?: string[];
  phones?: string[];
  bank_accounts?: string[];
  emails?: string[];
  handles?: string[];
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

export default function Message() {
  const [message, setMessage] = useState('');
  const [files, setFiles] = useState<File[]>([]);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [scanId, setScanId] = useState<number | null>(null);
  const [previewImage, setPreviewImage] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [trackOn, setTrackOn] = useState(false);
  const imgInputRef = useRef<HTMLInputElement>(null);

  const tracker = useScanTracker(scanId, {
    enabled: trackOn && scanId != null,
    onDone: (d: TrackerDone) => {
      setResult({ ...d.result, risk_score: d.risk_score, risk_level: d.risk_level });
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
      const fresh = list.filter(
        (f) => !prev.some((e) => e.name === f.name && e.size === f.size),
      );
      return [...prev, ...fresh];
    });
  };

  const removeFile = (index: number): void => {
    setFiles((prev) => prev.filter((_, i) => i !== index));
    if (imgInputRef.current) imgInputRef.current.value = '';
  };

  const clearFiles = (): void => {
    setFiles([]);
    if (imgInputRef.current) imgInputRef.current.value = '';
  };

  const pasteFromClipboard = (): void => {
    navigator.clipboard
      .readText()
      .then((text) => {
        if (text && text.trim()) {
          setMessage((m) => (m ? `${m}\n${text}` : text));
          showToast('Đã dán nội dung từ clipboard!', 'success');
        } else {
          showToast('Clipboard trống hoặc không có văn bản.', 'warning');
        }
      })
      .catch(() => showToast('Không thể truy cập clipboard. Vui lòng dán bằng Ctrl+V.', 'warning'));
  };

  const submit = (e: React.FormEvent): void => {
    e.preventDefault();
    if (!message.trim() && files.length === 0) {
      showToast('Vui lòng nhập tin nhắn hoặc tải ảnh', 'warning');
      return;
    }
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
    setLoading(true);
    setResult(null);
    setScanId(null);
    setTrackOn(false);
    tracker.clear();
    tracker.push('Đang tải nội dung lên hệ thống...', 'init');

    const fd = new FormData();
    if (message.trim()) fd.append('message', message.trim());
    fd.append('cf-turnstile-response', tsToken);
    files.forEach((f) => fd.append('image', f));

    api
      .upload<ScanResult>('/scan/message/', fd)
      .then((data) => {
        const sid = data['scan_id'];
        if (typeof sid === 'number') {
          setScanId(sid);
          setTrackOn(true);
        } else if (data['risk_score'] !== undefined) {
          setResult(data);
          setLoading(false);
        } else {
          showToast('Không nhận được kết quả scan.', 'error');
          setLoading(false);
        }
      })
      .catch((err: unknown) => {
        showToast(err instanceof Error ? err.message : 'Có lỗi xảy ra.', 'error');
        setLoading(false);
      });
  };

    const level = guardrailTone(result);
  const verdictLabel = guardrailLabel(result);
  const score = asNum(result?.['risk_score']);
  const patterns = asArr<unknown>(result?.['patterns_found']);
  const entities = (result?.['osint_entities'] as OsintEntities | undefined) || {};
  const annotatedImages = asArr<string>(result?.['annotated_images']);
  const annotatedImage = asStr(result?.['annotated_image']);
  const hasEntities =
    (entities.urls?.length || 0) > 0 ||
    (entities.phones?.length || 0) > 0 ||
    (entities.bank_accounts?.length || 0) > 0 ||
    (entities.emails?.length || 0) > 0 ||
    (entities.handles?.length || 0) > 0;

  return (
    <div className="max-w-7xl mx-auto px-4 pt-16 sm:pt-20 pb-20 lg:grid lg:grid-cols-[1fr_340px] lg:gap-8 lg:items-start">
      <div
        className="animate-fadein space-y-10"
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
          if (imgs.length) {
            e.preventDefault();
            addFiles(imgs);
          }
        }}
      >
        <div className="text-center space-y-4">
          <div className="inline-flex items-center justify-center w-20 h-20 rounded-3xl bg-brand-500/10 text-brand-400 mb-5 border border-brand-500/20 shadow-lg shadow-brand-500/10">
            <i className="bi bi-chat-left-dots text-4xl"></i>
          </div>
          <h1 className="text-4xl font-black text-white tracking-tight">
            Kiểm tra <span className="glow-text">Văn bản / Tin nhắn Scam</span>
          </h1>
          <p className="text-white/55 max-w-md mx-auto text-sm leading-relaxed">
            Phân tích ngữ nghĩa, nhận diện hành vi lừa đảo qua nội dung chữ (tin nhắn, bài viết Facebook, đoạn chat, mô tả giao dịch...) hoặc ảnh chụp màn hình.
          </p>
        </div>

        <Card
          className={`bg-slate-900/60 backdrop-blur-md border border-white/10 shadow-2xl rounded-3xl p-6 sm:p-8 ${isDragging ? 'border-brand-500 border-dashed ring-4 ring-brand-500/20' : ''}`}
        >
          <form onSubmit={submit}>
            {previewImage && (
              <div
                className="fixed inset-0 z-[200] flex items-center justify-center p-4 bg-black/90 backdrop-blur-sm"
                onClick={() => setPreviewImage(null)}
              >
                <img src={previewImage} className="max-w-full max-h-full object-contain rounded-lg shadow-2xl" alt="" onClick={(e) => e.stopPropagation()} />
                <button type="button" className="absolute top-6 right-6 text-white/60 hover:text-white bg-black/50 w-10 h-10 rounded-full flex items-center justify-center cursor-pointer" onClick={() => setPreviewImage(null)}>
                  <i className="bi bi-x-lg text-xl"></i>
                </button>
              </div>
            )}

            <div className="space-y-6">
              <div className="relative">
                <textarea
                  className="w-full min-h-[160px] p-6 text-base sm:text-lg font-medium leading-relaxed rounded-2xl bg-white/5 border border-white/10 text-white placeholder:text-white/40 focus:outline-none focus:border-brand-400/50 transition-all"
                  placeholder="Dán nội dung cần kiểm tra (tin nhắn, bài viết Facebook, đoạn văn bản bất kỳ)..."
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                ></textarea>

                <button
                  type="button"
                  onClick={pasteFromClipboard}
                  className="absolute top-3 right-3 flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-brand-500/10 text-brand-400 text-[10px] font-black uppercase tracking-wider border border-brand-500/20 hover:bg-brand-500/20 hover:text-brand-300 transition-all z-10 cursor-pointer"
                  title="Dán văn bản từ clipboard"
                >
                  <i className="bi bi-clipboard-plus"></i> DÁN TỪ CLIPBOARD
                </button>

                <div className="absolute bottom-4 right-4 text-[10px] font-black text-white/35 uppercase tracking-widest pointer-events-none">
                  Text Content Analyzer
                </div>
              </div>
              <p className="text-[11px] text-white/45 font-medium leading-relaxed -mt-3">
                Bạn có thể copy trực tiếp từ bài viết Facebook, bình luận, tin nhắn chat, email rút gọn hoặc nhiều nguồn văn bản khác để phân tích.
              </p>

              <div className="flex flex-col sm:flex-row gap-4 items-center">
                <label className="flex-1 w-full py-4 px-6 text-xs sm:text-sm font-bold bg-white/5 border border-white/10 hover:bg-white/10 rounded-2xl cursor-pointer text-center group transition-colors">
                  <span className="flex items-center justify-center gap-3">
                    <i className="bi bi-image text-xl text-brand-400 group-hover:scale-110 transition-transform"></i>
                    <span className="text-white/80">{isDragging ? 'THẢ ẢNH VÀO ĐÂY' : files.length ? `ĐÃ CHỌN ${files.length} ẢNH` : 'HOẶC KÉO THẢ NHIỀU ẢNH CHỤP'}</span>
                  </span>
                  <input
                    type="file"
                    ref={imgInputRef}
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
                  <Button type="button" onClick={clearFiles} variant="destructive" className="h-14 px-6 rounded-2xl font-black text-xs uppercase tracking-wider cursor-pointer">
                    <i className="bi bi-trash mr-1.5"></i> XÓA TẤT CẢ
                  </Button>
                )}
                <Button type="submit" variant="cyber" className="h-14 px-10 rounded-2xl font-black text-sm uppercase tracking-wider cursor-pointer" disabled={loading}>
                  {!loading ? (
                    <span className="inline-flex items-center gap-2"><i className="bi bi-cpu"></i> PHÂN TÍCH</span>
                  ) : (
                    <span className="w-5 h-5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin"></span>
                  )}
                </Button>
              </div>

              {files.length > 0 && (
                <div className="mt-4 w-full overflow-x-auto pb-4 custom-scrollbar">
                  <div className="flex gap-3 min-w-min px-1">
                    {files.map((file, index) => (
                      <div key={index} className="relative shrink-0 w-20 h-20 group cursor-pointer" onClick={() => setPreviewImage(URL.createObjectURL(file))}>
                        <img src={URL.createObjectURL(file)} className="w-full h-full object-cover rounded-xl border border-white/10 group-hover:border-brand2-500/50 transition-colors shadow-lg shadow-black/50" alt="" />
                        <div className="absolute top-0 right-0 p-2 z-10">
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              removeFile(index);
                            }}
                            className="bg-danger-500/80 hover:bg-danger-600/80 text-white rounded-full w-7 h-7 flex items-center justify-center text-xs shadow-md"
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

              <TurnstileWidget />
            </div>
          </form>
        </Card>

        {loading && tracker.progress.length > 0 && (
          <ProgressConsole title="Tiến trình phân tích thời gian thực" progress={tracker.progress} wsState={tracker.wsState} accent="purple" />
        )}

        {result && (
          <div className="space-y-8 animate-fadein">
            <Card className="bg-slate-900/60 backdrop-blur-md border border-white/10 shadow-2xl rounded-3xl overflow-hidden p-0">
              <div className="p-8 text-center border-b border-white/5 bg-white/[0.02] relative overflow-hidden">
                <div className={`absolute inset-0 opacity-10 -z-10 blur-[80px] ${riskGlow(level)}`}></div>

                <div className={`inline-block px-8 py-3 rounded-full text-xs font-black tracking-[0.3em] uppercase mb-6 ${riskBadge(level)}`}>
                  {verdictLabel}
                </div>

                <div className="text-5xl font-black text-white mb-2">{score}/100</div>
                <div className="text-[10px] text-white/45 font-black tracking-widest uppercase mb-8">Chỉ số nghi vấn tin nhắn</div>
              </div>

              <div className="p-8 space-y-8">
                {patterns.length > 0 && (
                  <div className="space-y-3">
                    <h4 className="text-xs font-black text-white/55 uppercase tracking-widest">Dấu hiệu phát hiện</h4>
                    <div className="flex flex-wrap gap-2">
                      {patterns.map((p, i) => (
                        <span key={i} className="px-4 py-2 rounded-xl bg-danger-500/10 border border-danger-500/20 text-danger-400 text-xs font-bold">
                          {patternLabel(p)}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {hasEntities && (
                  <div className="space-y-4">
                    <h4 className="text-xs font-black text-white/55 uppercase tracking-widest">Thực thể OSINT đã trích xuất</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {(entities.urls?.length || 0) > 0 && (
                        <div className="p-4 rounded-2xl bg-white/[0.02] border border-white/10">
                          <p className="text-[10px] font-black text-brand-300 uppercase tracking-widest mb-2">URLs</p>
                          <div className="flex flex-wrap gap-2">
                            {(entities.urls || []).map((u) => (
                              <span key={u} className="px-2 py-1 rounded-lg bg-brand-500/10 border border-brand-500/20 text-brand-200 text-[11px] font-mono">{u}</span>
                            ))}
                          </div>
                        </div>
                      )}
                      {(entities.phones?.length || 0) > 0 && (
                        <div className="p-4 rounded-2xl bg-white/[0.02] border border-white/10">
                          <p className="text-[10px] font-black text-brand-300 uppercase tracking-widest mb-2">Số điện thoại</p>
                          <div className="flex flex-wrap gap-2">
                            {(entities.phones || []).map((p) => (
                              <span key={p} className="px-2 py-1 rounded-lg bg-brand-500/10 border border-brand-500/20 text-brand-200 text-[11px] font-mono">{p}</span>
                            ))}
                          </div>
                        </div>
                      )}
                      {(entities.bank_accounts?.length || 0) > 0 && (
                        <div className="p-4 rounded-2xl bg-white/[0.02] border border-white/10">
                          <p className="text-[10px] font-black text-warn-300 uppercase tracking-widest mb-2">Tài khoản nghi ngờ</p>
                          <div className="flex flex-wrap gap-2">
                            {(entities.bank_accounts || []).map((a) => (
                              <span key={a} className="px-2 py-1 rounded-lg bg-warn-500/10 border border-warn-500/20 text-warn-200 text-[11px] font-mono">{a}</span>
                            ))}
                          </div>
                        </div>
                      )}
                      {((entities.emails?.length || 0) > 0 || (entities.handles?.length || 0) > 0) && (
                        <div className="p-4 rounded-2xl bg-white/[0.02] border border-white/10">
                          <p className="text-[10px] font-black text-safe-300 uppercase tracking-widest mb-2">Email / Handle</p>
                          <div className="flex flex-wrap gap-2">
                            {(entities.emails || []).map((e) => (
                              <span key={e} className="px-2 py-1 rounded-lg bg-safe-500/10 border border-safe-500/20 text-safe-200 text-[11px] font-mono">{e}</span>
                            ))}
                            {(entities.handles || []).map((h) => (
                              <span key={h} className="px-2 py-1 rounded-lg bg-safe-500/10 border border-safe-500/20 text-safe-200 text-[11px] font-mono">{h}</span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {(annotatedImages.length > 0 || annotatedImage) && (
                  <div className="space-y-4">
                    <h4 className="text-xs font-black text-white/55 uppercase tracking-widest">Phân tích vùng text từ ảnh</h4>
                    <div className={`grid gap-4 ${annotatedImages.length > 1 ? 'grid-cols-1 md:grid-cols-2' : 'grid-cols-1'}`}>
                      {annotatedImages.length > 0 ? (
                        annotatedImages.map((img, idx) => (
                          <div key={idx} className="rounded-3xl overflow-hidden border border-white/5 shadow-2xl bg-black/30 flex items-center justify-center p-4 max-h-[400px] overflow-auto custom-scrollbar cursor-pointer" onClick={() => setPreviewImage(img)}>
                            <img src={img} className="max-w-full max-h-[360px] object-contain rounded-xl" alt={`Ảnh phân tích ${idx + 1}`} />
                          </div>
                        ))
                      ) : (
                        <div className="rounded-3xl overflow-hidden border border-white/5 shadow-2xl bg-black/30 flex items-center justify-center p-4 max-h-[400px] overflow-auto custom-scrollbar cursor-pointer" onClick={() => setPreviewImage(annotatedImage)}>
                          <img src={annotatedImage} className="max-w-full max-h-[360px] object-contain rounded-xl" alt="Analyzed Message" />
                        </div>
                      )}
                    </div>
                  </div>
                )}

                <div className="p-6 liquid-glass border-white/5 bg-brand-500/[0.02]">
                  <div className="flex items-center gap-3 mb-6">
                    <div className="w-10 h-10 rounded-xl bg-brand-500/20 flex items-center justify-center text-brand-400">
                      <i className="bi bi-robot"></i>
                    </div>
                    <div>
                      <h4 className="text-sm font-black text-white uppercase tracking-wider">AI Fraud Detection</h4>
                      <p className="text-[10px] text-white/55 font-bold uppercase tracking-widest">Behavioral & Semantic Analysis</p>
                    </div>
                  </div>

                  <MarkdownView html={renderMd(asStr(result['explanation']) || asStr(result['ai_insight']))} className="text-white/70 text-sm leading-relaxed" />
                  {!result['explanation'] && !result['ai_insight'] && (
                    <p className="text-white/35 text-xs italic">Không có phân tích AI.</p>
                  )}
                </div>

                <TrustGuardrailPanel result={result} />
                <OsintSection result={result} />
              </div>

              <div className="p-8 bg-white/[0.02] border-t border-white/5 flex flex-wrap gap-4 justify-between items-center">
                <div className="flex gap-3">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="rounded-xl border-white/10 bg-white/5 text-white/70 hover:text-white"
                    onClick={() => showToast('Đã lưu!', 'success')}
                  >
                    <i className="bi bi-bell mr-1.5"></i> Watchlist
                  </Button>
                  <Button
                    type="button"
                    variant="cyber"
                    size="sm"
                    className="rounded-xl font-bold"
                    onClick={() => dispatchChat(`Message Scan Result\nInput: ${message}\nAnalysis: ${asStr(result['explanation'])}`)}
                  >
                    <i className="bi bi-chat-dots-fill mr-1.5"></i> CHAT VỚI AI
                  </Button>
                </div>
                <Button
                  asChild
                  variant="emergency"
                  size="sm"
                  className="rounded-xl font-black uppercase tracking-wider"
                >
                  <Link href="/report/?target_type=message">
                    <i className="bi bi-shield-exclamation mr-1.5"></i> BÁO CÁO VI PHẠM
                  </Link>
                </Button>
              </div>
            </Card>
          </div>
        )}
      </div>
      <ScanGuide scanType="message" />
    </div>
  );
}
