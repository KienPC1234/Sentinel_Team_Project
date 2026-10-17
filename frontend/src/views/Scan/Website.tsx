'use client';
/* Port từ PKV/templates/Scan/scan_website.html — Kiểm tra Website / URL.
 * API: POST /api/v1/scan/domain/ {url, deep_scan, cf-turnstile-response}
 *      (thường → đồng bộ + SSE giải thích; deep_scan → async qua WS/poll).
 */
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { api } from '../../lib/api';

import { renderMd } from '../../lib/chat/markdown';
import { MarkdownView } from '../../components/ui';
import { openSseStream } from '../../lib/chat/stream';
import {
  OsintSection,
  TrustGuardrailPanel,
  ProgressConsole,
  ScanGuide,
  TurnstileWidget,
  apiBase,
  dispatchChat,
  getTsToken,
  resetTurnstile,
  showToast,
  useScanTracker,
} from '../../components/ScanWidgets';
import type { ScanResult, TrackerDone } from '../../components/ScanWidgets';
import { asStr, asNum, asArr, guardrailTone, guardrailLabel } from '../../components/ScanWidgets';

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

export default function Website() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [aiText, setAiText] = useState('');
  const [aiLoading, setAiLoading] = useState(false);
  const [deepScan, setDeepScan] = useState(false);
  const [scanId, setScanId] = useState<number | null>(null);
  const [trackOn, setTrackOn] = useState(false);

  const tracker = useScanTracker(scanId, {
    enabled: trackOn && scanId != null,
    onDone: (d: TrackerDone) => {
      const merged = { ...d.result, risk_score: d.risk_score, risk_level: d.risk_level };
      setResult(merged);
      setAiText(asStr(merged['explanation']));
      setLoading(false);
      setTrackOn(false);
    },
    onError: (msg: string) => {
      showToast(msg, 'error');
      setLoading(false);
      setTrackOn(false);
    },
  });

  const streamAi = (data: ScanResult, originalUrl: string): void => {
    setAiLoading(true);
    void openSseStream({
      url: `${apiBase()}/scan/analyze-sse/`,
      body: { scan_type: 'domain', scan_data: data, raw_input: originalUrl },
      onEvent: (ev) => {
        if (ev.type === 'delta') setAiText((t) => t + ev.text);
        else if (ev.type === 'done') setAiLoading(false);
      },
    })
      .catch(() => {
        setAiLoading(false);
        showToast('Không thể kết nối AI.', 'warning');
      })
      .finally(() => setAiLoading(false));
  };

  const handleScan = (override?: string): void => {
    const input = (override ?? url).trim();
    if (!input) {
      showToast('Vui lòng nhập URL', 'warning');
      return;
    }
    let normalizedUrl = input;
    if (!normalizedUrl.includes('://')) normalizedUrl = 'https://' + normalizedUrl;

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
    setAiText('');
    setAiLoading(false);
    setScanId(null);
    setTrackOn(false);
    tracker.clear();

    api
      .post<ScanResult>('/scan/domain/', {
        url: normalizedUrl,
        deep_scan: deepScan,
        'cf-turnstile-response': tsToken,
      })
      .then((data) => {
        const sid = data['scan_id'];
        if (deepScan && typeof sid === 'number') {
          setScanId(sid);
          setTrackOn(true);
        } else {
          setResult(data);
          setLoading(false);
          streamAi(data, normalizedUrl);
        }
      })
      .catch((e: unknown) => {
        showToast(e instanceof Error ? e.message : 'Có lỗi xảy ra.', 'error');
        setLoading(false);
      });
  };

  // Deep-link ?url= điền sẵn URL vào ô nhập
  useEffect(() => {
    const q = new URLSearchParams(window.location.search).get('url');
    if (q) {
      setUrl(q);
    }
  }, []);

    const level = guardrailTone(result);
  const verdictLabel = guardrailLabel(result);
  const score = asNum(result?.['risk_score']);
  const networkDetails =
    asArr<string>(result?.['network_details']).length > 0
      ? asArr<string>(result?.['network_details'])
      : asArr<string>(result?.['details']);
  const domain = asStr(result?.['domain']) || asStr(result?.['url']);
  const similarityWarning = asStr(result?.['similarity_warning']);

  return (
    <div className="max-w-7xl mx-auto px-4 pt-16 sm:pt-20 pb-20 lg:grid lg:grid-cols-[1fr_340px] lg:gap-8 lg:items-start">
      <div className="max-w-4xl mx-auto space-y-10">
        <div className="text-center space-y-4">
          <div className="inline-flex items-center justify-center w-20 h-20 rounded-3xl bg-brand-500/10 text-brand-400 mb-5 border border-brand-500/20 shadow-lg shadow-brand-500/10">
            <i className="bi bi-globe2 text-4xl"></i>
          </div>
          <h1 className="text-4xl font-black text-white tracking-tight">
            Kiểm tra <span className="glow-text">Website / URL</span>
          </h1>
          <p className="text-white/55 max-w-md mx-auto text-sm leading-relaxed">
            Phân tích mức độ tin cậy, chứng chỉ bảo mật và nội dung website bằng AI.
          </p>
        </div>

        <div className="liquid-card p-6 sm:p-8">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleScan();
            }}
          >
            <div className="flex flex-col sm:flex-row gap-4">
              <input
                type="text"
                className="liquid-input flex-1 py-4 px-6 text-lg font-bold"
                placeholder="VD: vietcombank-ebanking.com, bit.ly/..."
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                required
              />
              <button
                type="button"
                onClick={() => handleScan()}
                className="liquid-btn bg-brand-500 text-black px-10 py-4 font-black hover:bg-brand-400"
                disabled={loading}
              >
                {!loading ? (
                  <span><i className="bi bi-search mr-2"></i> SCAN</span>
                ) : (
                  <span className="spinner w-5 h-5 border-black"></span>
                )}
              </button>
            </div>
            <TurnstileWidget />
            <div className="mt-4 flex items-center gap-3">
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={deepScan}
                  onChange={(e) => {
                    setDeepScan(e.target.checked);
                    try {
                      resetTurnstile();
                    } catch {
                      /* bỏ qua */
                    }
                  }}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-white/5 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white/20 after:border-white/10 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-brand-500/50"></div>
                <span className="ms-3 text-xs font-black text-white/55 uppercase tracking-widest">Chế độ Quét Sâu (Deep AI Analysis)</span>
              </label>
            </div>
          </form>
        </div>

        {loading && deepScan && tracker.progress.length > 0 && (
          <ProgressConsole title="Tiến trình quét thời gian thực" progress={tracker.progress} wsState={tracker.wsState} accent="blue" />
        )}

        {result && (
          <div className="space-y-6 animate-fadein">
            <div className="liquid-card overflow-hidden">
              <div className="p-8 text-center border-b border-white/5 bg-white/[0.02] relative overflow-hidden">
                <div className={`absolute inset-0 opacity-10 -z-10 blur-[80px] ${riskGlow(level)}`}></div>

                <div className={`inline-block px-8 py-3 rounded-full text-xs font-black tracking-[0.3em] uppercase mb-6 ${riskBadge(level)}`}>
                  {verdictLabel}
                </div>

                <div className="text-5xl font-black text-white mb-2">{score}/100</div>
                <div className="text-[10px] text-white/45 font-black tracking-widest uppercase mb-8">Điểm rủi ro URL</div>

                <div className="w-full h-1.5 bg-white/5 rounded-full overflow-hidden max-w-md mx-auto">
                  <div
                    className="h-full transition-all duration-1000"
                    style={{ width: `${score}%`, background: score >= 70 ? 'var(--sc-danger-500)' : score >= 40 ? 'var(--sc-warn-500)' : 'var(--sc-safe-500)' }}
                  ></div>
                </div>
              </div>

              <div className="p-8 grid grid-cols-1 md:grid-cols-2 gap-6 border-b border-white/5">
                <div className="p-4 rounded-2xl bg-white/[0.03] space-y-1">
                  <div className="text-[10px] font-black text-white/35 uppercase tracking-widest">Tên miền / URL</div>
                  <div className="text-sm font-bold text-white/80 truncate">{domain}</div>
                </div>
                <div className="p-4 rounded-2xl bg-white/[0.03] space-y-1">
                  <div className="text-[10px] font-black text-white/35 uppercase tracking-widest">Loại hình</div>
                  <div className="text-sm font-bold text-white/80">{asStr(result['scam_type']) || 'Chưa xác định'}</div>
                </div>
                {asStr(result['page_title']) && (
                  <div className="p-4 rounded-2xl bg-white/[0.03] space-y-1">
                    <div className="text-[10px] font-black text-white/35 uppercase tracking-widest">Tiêu đề trang</div>
                    <div className="text-sm font-bold text-white/80 truncate">{asStr(result['page_title'])}</div>
                  </div>
                )}
                <div className="p-4 rounded-2xl bg-white/[0.03] space-y-1">
                  <div className="text-[10px] font-black text-white/35 uppercase tracking-widest">Nội dung</div>
                  <div className={`text-sm font-bold ${result['fetch_success'] ? 'text-safe-400' : 'text-danger-400'}`}>
                    {result['fetch_success'] ? `${asNum(result['content_length'])} ký tự` : 'Không truy cập được'}
                  </div>
                </div>
              </div>

              {similarityWarning && (
                <div className="mx-8 mt-6 p-4 rounded-2xl bg-warn-500/10 border border-warn-500/20 flex items-center gap-3">
                  <i className="bi bi-exclamation-triangle-fill text-warn-400 text-lg flex-shrink-0"></i>
                  <span className="text-xs font-bold text-warn-300">{similarityWarning}</span>
                </div>
              )}

              {networkDetails.length > 0 && (
                <div className="mx-8 mt-6 p-5 rounded-2xl bg-white/[0.02] border border-white/[0.06]">
                  <h4 className="text-[10px] font-black text-white/45 uppercase tracking-widest mb-3">Phát hiện từ mạng lưới</h4>
                  <ul className="space-y-2">
                    {networkDetails.map((detail, i) => (
                      <li key={i} className="flex items-start gap-2 text-xs text-white/60">
                        <i className="bi bi-hdd-network text-brand-400 mt-0.5 flex-shrink-0"></i>
                        <span>{detail}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="p-8 bg-brand-500/[0.02]">
                <div className="flex items-center gap-3 mb-6">
                  <div className="w-10 h-10 rounded-xl bg-brand-500/20 flex items-center justify-center text-brand-400">
                    <i className="bi bi-shield-lock"></i>
                  </div>
                  <div>
                    <h4 className="text-sm font-black text-white uppercase tracking-wider">Phân tích An ninh mạng</h4>
                    <p className="text-[10px] text-white/55 font-bold uppercase tracking-widest">Deep Web Analysis</p>
                  </div>
                  {aiLoading && <div className="ml-auto spinner w-4 h-4 text-brand-400"></div>}
                </div>

                <MarkdownView html={renderMd(aiText)} className={`text-white/70 text-sm leading-relaxed ${aiLoading ? 'ai-streaming' : ''}`} />
                {!aiText && !aiLoading && <p className="text-white/35 text-xs italic">Đang chờ phản hồi từ AI...</p>}
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
                        void navigator.clipboard.writeText(asStr(result['url']) || url).then(() => showToast('Đã copy URL!', 'success'));
                      } catch {
                        showToast('Không thể sao chép.', 'error');
                      }
                    }}
                  >
                    <i className="bi bi-link-45deg"></i> Copy Link
                  </button>
                  <button
                    type="button"
                    className="liquid-btn py-2 px-6 text-xs bg-brand-500/10 text-brand-400 border-brand-500/20 hover:bg-brand-500/20 transition-all font-black"
                    onClick={() => dispatchChat(`Website: ${domain}\nAnalysis: ${aiText || asStr(result['explanation'])}`)}
                  >
                    <i className="bi bi-chat-dots-fill"></i> CHAT VỚI AI
                  </button>
                </div>
                <Link
                  href={`/report/?target_type=domain&target_value=${encodeURIComponent(asStr(result['url']) || url)}`}
                  className="liquid-btn py-2 px-8 text-xs bg-danger-500/20 text-danger-500 border-danger-500/30 hover:bg-danger-500/30 transition-all font-black"
                >
                  <i className="bi bi-megaphone-fill"></i> BÁO CÁO WEBSITE
                </Link>

              </div>
            </div>
          </div>
        )}
      </div>
      <ScanGuide scanType="website" />
    </div>
  );
}
