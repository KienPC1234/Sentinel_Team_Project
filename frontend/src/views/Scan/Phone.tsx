'use client';
/* Port từ PKV/templates/Scan/scan_phone.html — Kiểm tra Số điện thoại.
 * API: POST /api/v1/scan/phone/ {phone, cf-turnstile-response} (đồng bộ).
 */
import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { api } from '../../lib/api';

import { renderMd, safeUrl } from '../../lib/chat/markdown';
import { MarkdownView } from '../../components/ui';
import {
  ScanGuide,
  TurnstileWidget,
  copyText,
  dispatchChat,
  getTsToken,
  resetTurnstile,
  showToast,
} from '../../components/ScanWidgets';
import type { ScanResult } from '../../components/ScanWidgets';
import { asStr, asNum, asArr, TrustGuardrailPanel, guardrailTone, guardrailLabel } from '../../components/ScanWidgets';

interface OnlineMatch {
  url?: string;
  title?: string;
  snippet?: string;
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

export default function Phone() {
  const [phone, setPhone] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [aiText, setAiText] = useState('');

  const submit = useCallback((rawPhone: string) => {
    if (!rawPhone.trim()) {
      showToast('Vui lòng nhập số điện thoại', 'warning');
      return;
    }
    let phoneNormalized = rawPhone.trim().replace(/[\s().-]/g, '');
    if (/^0\d{9}$/.test(phoneNormalized)) phoneNormalized = '+84' + phoneNormalized.substring(1);
    if (!/^(\+\d{8,15}|0\d{9})$/.test(phoneNormalized)) {
      showToast('Số điện thoại không hợp lệ. VD: 0978589220 hoặc +84978589220', 'warning');
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
    setAiText('');
    api
      .post<ScanResult>('/scan/phone/', { phone: phoneNormalized, 'cf-turnstile-response': tsToken })
      .then((data) => {
        setResult(data);
        setAiText(asStr(data['analysis_result']) || 'Hệ thống đã hoàn tất phân tích số điện thoại này.');
        setLoading(false);
      })
      .catch((e: unknown) => {
        const msg = e instanceof Error ? e.message : 'Có lỗi xảy ra.';
        showToast(msg, 'error');
        setLoading(false);
      });
  }, []);

  // Tự động quét khi mở link ?phone=. Turnstile render BẤT ĐỒNG BỘ nên phải
  // CHỜ token sẵn sàng rồi mới submit (trước đây submit ngay -> thiếu token ->
  // không bao giờ quét, chỉ hiện toast cảnh báo).
  useEffect(() => {
    const q = new URLSearchParams(window.location.search).get('phone');
    if (!q) return;
    setPhone(q);
    let tries = 0;
    const timer = window.setInterval(() => {
      tries += 1;
      if (getTsToken()) {
        window.clearInterval(timer);
        submit(q);
      } else if (tries >= 40) {
        window.clearInterval(timer);
        showToast('Chưa xác minh anti-spam xong. Vui lòng bấm SCAN để thử lại.', 'warning');
      }
    }, 250);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const metrics = (result?.['metrics'] as Record<string, unknown> | undefined) || {};
  const componentScores = (result?.['component_scores'] as Record<string, unknown> | undefined) || {};
  const onlineLookup = (result?.['online_lookup'] as Record<string, unknown> | undefined) || null;
  const reasons = asArr<unknown>(result?.['reasons']);
  const matches = asArr<OnlineMatch>(onlineLookup?.['matches']);
    const level = guardrailTone(result);
  const verdictLabel = guardrailLabel(result);
  const score = asNum(result?.['risk_score']);

  return (
    <div className="max-w-7xl mx-auto px-4 pt-16 sm:pt-20 pb-20 lg:grid lg:grid-cols-[1fr_340px] lg:gap-8 lg:items-start">
      <div className="animate-fadein space-y-10">
        <div className="text-center space-y-4">
          <div className="inline-flex items-center justify-center w-20 h-20 rounded-3xl bg-brand-500/10 text-brand-400 mb-5 border border-brand-500/20 shadow-lg shadow-brand-500/10">
            <i className="bi bi-phone-vibrate text-4xl"></i>
          </div>
          <h1 className="text-4xl font-black text-white tracking-tight">
            Kiểm tra <span className="glow-text">Số điện thoại</span>
          </h1>
          <p className="text-white/55 max-w-md mx-auto text-sm leading-relaxed">
            Hệ thống sẽ tra cứu số điện thoại này trong cơ sở dữ liệu lừa đảo quốc gia và cộng đồng.
            Hỗ trợ cả số Việt Nam (VD: 0978589220) và định dạng quốc tế (+84..., +1...).
          </p>
        </div>

        <div className="liquid-card p-6 sm:p-8">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              submit(phone);
            }}
          >
            <div className="flex flex-col sm:flex-row gap-4">
              <input
                type="tel"
                className="liquid-input flex-1 py-4 px-6 text-lg font-bold"
                placeholder="VD: 0978589220 hoặc +84379456789"
                value={phone}
                onChange={(e) => setPhone(e.target.value)}
                required
              />
              <button
                type="submit"
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
          </form>
        </div>

        {result && (
          <div className="space-y-6">
            <div className="liquid-card overflow-hidden">
              <div className="p-10 text-center border-b border-white/5 bg-white/[0.02] relative overflow-hidden">
                <div className={`absolute inset-0 opacity-10 -z-10 blur-[100px] ${riskGlow(level)}`}></div>

                <div className={`inline-block px-10 py-3 rounded-full text-[10px] font-black tracking-[0.4em] uppercase mb-8 ${riskBadge(level)}`}>
                  {verdictLabel}
                </div>

                <div className="flex items-center justify-center gap-6 mb-10">
                  <div className="text-7xl font-black text-white">{score}</div>
                  <div className="h-16 w-px bg-white/10"></div>
                  <div className="text-left">
                    <div className="text-xs font-black text-white/55 tracking-widest uppercase mb-1">Risk Score</div>
                    <div className="text-sm font-bold text-white/80">{asStr(result['suggested_action'])}</div>
                  </div>
                </div>

                <div className="w-full h-2 bg-white/5 rounded-full overflow-hidden max-w-xl mx-auto shadow-inner">
                  <div
                    className="h-full transition-all duration-1000 ease-out"
                    style={{ width: `${score}%`, background: score >= 80 ? 'var(--sc-danger-500)' : score >= 50 ? 'var(--sc-warn-500)' : 'var(--sc-safe-500)' }}
                  ></div>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 divide-y md:divide-y-0 md:divide-x divide-white/5 border-b border-white/5">
                <div className="p-8 space-y-4">
                  <div className="flex items-center gap-3 text-white/55 mb-2">
                    <i className="bi bi-info-circle-fill"></i>
                    <span className="text-[10px] font-black uppercase tracking-widest">Metadata</span>
                  </div>
                  <div className="space-y-4">
                    <div className="flex justify-between items-center text-sm">
                      <span className="text-white/55">Quốc gia</span>
                      <span className="font-bold text-white flex items-center gap-2">
                        <span className="text-[10px] text-brand-400 font-black px-1.5 py-0.5 rounded bg-brand-500/10 border border-brand-500/20">
                          {asStr(result['country_code'])}
                        </span>
                        <span>{asStr(result['country_name'])}</span>
                      </span>
                    </div>
                    <div className="flex justify-between items-center text-sm">
                      <span className="text-white/55">Nhà mạng</span>
                      <div className="text-right">
                        <div className="font-bold text-white">{asStr(result['carrier'])}</div>
                        <div className="text-[10px] text-white/45 uppercase tracking-tighter">{asStr(result['line_type'])}</div>
                      </div>
                    </div>
                    <div className="flex justify-between items-center text-sm pt-2">
                      <span className="text-white/55">Tính chất số</span>
                      <span
                        className={`font-black text-[10px] px-2 py-0.5 rounded uppercase ${
                          result['is_virtual']
                            ? 'bg-danger-500/20 text-danger-500 border border-danger-500/30'
                            : 'bg-safe-500/20 text-safe-500 border border-safe-500/30'
                        }`}
                      >
                        {result['is_virtual'] ? 'Số ảo / VoIP' : 'Số viễn thông'}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="p-8 space-y-4">
                  <div className="flex items-center gap-3 text-white/55 mb-2">
                    <i className="bi bi-people-fill"></i>
                    <span className="text-[10px] font-black uppercase tracking-widest">Cộng đồng</span>
                  </div>
                  <div className="space-y-4">
                    <div className="flex justify-between items-center text-sm">
                      <span className="text-white/55">Tổng báo cáo</span>
                      <span className="font-bold text-white">{asNum(result['report_count'])}</span>
                    </div>
                    <div className="flex justify-between items-center text-sm">
                      <span className="text-white/55">Nguồn tin cậy</span>
                      <span className="font-bold text-white">{asNum(result['reports_verified'])}</span>
                    </div>
                    <div className="flex justify-between items-center text-sm">
                      <span className="text-white/55">Tần suất 24h</span>
                      <span className="font-bold text-white">{asNum(metrics['reports_24h'])}</span>
                    </div>
                  </div>
                </div>

                <div className="p-8 space-y-4">
                  <div className="flex items-center gap-3 text-white/55 mb-2">
                    <i className="bi bi-shield-lock-fill"></i>
                    <span className="text-[10px] font-black uppercase tracking-widest">Phân bổ điểm</span>
                  </div>
                  <div className="space-y-3">
                    <div>
                      <div className="flex justify-between text-[10px] mb-1">
                        <span className="text-white/55">UY TÍN</span>
                        <span className="text-white/60">{asNum(componentScores['reputation'])}/45</span>
                      </div>
                      <div className="h-1 bg-white/5 rounded-full overflow-hidden">
                        <div className="h-full bg-brand-400" style={{ width: `${(asNum(componentScores['reputation']) / 45) * 100}%` }}></div>
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between text-[10px] mb-1">
                        <span className="text-white/55">METADATA</span>
                        <span className="text-white/60">{asNum(componentScores['metadata'])}/25</span>
                      </div>
                      <div className="h-1 bg-white/5 rounded-full overflow-hidden">
                        <div className="h-full bg-brand2-400" style={{ width: `${(asNum(componentScores['metadata']) / 25) * 100}%` }}></div>
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between text-[10px] mb-1">
                        <span className="text-white/55">HÀNH VI</span>
                        <span className="text-white/60">{asNum(componentScores['behavior'])}/30</span>
                      </div>
                      <div className="h-1 bg-white/5 rounded-full overflow-hidden">
                        <div className="h-full bg-brand2-400" style={{ width: `${(asNum(componentScores['behavior']) / 30) * 100}%` }}></div>
                      </div>
                    </div>
                  </div>
                </div>

                {onlineLookup && (
                  <div className="p-8 space-y-4 border-t border-white/5 bg-white/[0.01]">
                    <div className="flex items-center justify-between gap-4">
                      <div className="flex items-center gap-3 text-white/55">
                        <i className="bi bi-globe2"></i>
                        <span className="text-[10px] font-black uppercase tracking-widest">Tra cứu Internet</span>
                      </div>
                      <span
                        className={`font-black text-[10px] px-2 py-0.5 rounded uppercase ${
                          onlineLookup['suspected_disposable']
                            ? 'bg-danger-500/20 text-danger-500 border border-danger-500/30'
                            : 'bg-safe-500/20 text-safe-500 border border-safe-500/30'
                        }`}
                      >
                        {onlineLookup['suspected_disposable'] ? 'Có dấu hiệu số miễn phí online' : 'Không phát hiện số miễn phí online'}
                      </span>
                    </div>
                    <p className="text-xs text-white/60">{asStr(onlineLookup['note'])}</p>

                    {matches.length > 0 && (
                      <div className="space-y-2">
                        {matches.map((src, i) => (
                          <div key={i} className="p-3 rounded-xl bg-white/[0.02] border border-white/5">
                            <a href={safeUrl(src.url)} target="_blank" rel="noopener noreferrer" className="text-xs font-bold text-brand-400 hover:text-brand-300 transition-colors">
                              {src.title || src.url}
                            </a>
                            <p className="text-[11px] text-white/55 mt-1 line-clamp-2">{src.snippet}</p>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>

              <div className="p-10 space-y-10">
                <div className="grid grid-cols-1 lg:grid-cols-5 gap-10">
                  <div className="lg:col-span-3 space-y-6">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-xl bg-brand-500/10 flex items-center justify-center text-brand-400 border border-brand-500/20 shadow-lg shadow-brand-500/5">
                        <i className="bi bi-stars"></i>
                      </div>
                      <div>
                        <h4 className="text-sm font-black text-white uppercase tracking-wider">Tóm tắt phân tích</h4>
                        <p className="text-[10px] text-white/55 font-bold uppercase tracking-widest text-glow-cyan">KẾT QUẢ TỪ PKV ENGINE</p>
                      </div>
                    </div>
                    <MarkdownView html={renderMd(aiText)} className="text-white/70 text-sm leading-relaxed bg-white/[0.02] p-6 rounded-2xl border border-white/5 shadow-inner" />
                  </div>

                  <div className="lg:col-span-2 space-y-6">
                    <h4 className="text-[10px] font-black text-white/55 uppercase tracking-[0.2em] flex items-center gap-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-brand-500"></span>
                      Tại sao có kết quả này?
                    </h4>
                    <div className="space-y-4">
                      {reasons.map((reason, i) => (
                        <div key={i} className="flex items-start gap-3 p-4 rounded-xl bg-white/[0.02] border border-white/5 hover:bg-white/[0.04] transition-all group">
                          <div className="mt-1">
                            <i className="bi bi-patch-check-fill text-brand-500/40 group-hover:text-brand-400 transition-colors"></i>
                          </div>
                          <div className="text-sm text-white/70 group-hover:text-white/90 transition-colors">
                            {typeof reason === 'string' ? reason : JSON.stringify(reason)}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              <TrustGuardrailPanel result={result} />

              <div className="p-10 bg-white/[0.02] border-t border-white/5 flex flex-wrap gap-4 justify-between items-center">
                <div className="flex gap-4">
                  <button
                    type="button"
                    className="liquid-btn py-3 px-8 text-xs bg-white/5 text-white/60 border-white/10 hover:border-white/20 hover:text-white transition-all font-black uppercase tracking-widest"
                    onClick={() =>
                      copyText(`${window.location.host}/scan/phone/?phone=${asStr(result['phone'])}`, 'Đã copy link!')
                    }
                  >
                    <i className="bi bi-share-fill mr-2"></i> Chia sẻ
                  </button>
                </div>
                <div className="flex gap-4 items-center">
                  <Link
                    href={`/report/?target_type=phone&target_value=${encodeURIComponent(asStr(result['phone']))}&phone=${encodeURIComponent(asStr(result['phone']))}&scammer_name=${encodeURIComponent(asStr(result['owner_name']))}`}
                    className="liquid-btn py-3 px-10 text-xs bg-danger-600/10 text-danger-500 border-danger-600/20 hover:bg-danger-600/20 transition-all font-black uppercase tracking-widest shadow-lg shadow-danger-600/5"
                  >
                    <i className="bi bi-megaphone-fill mr-2"></i> TỐ CÁO
                  </Link>

                  <button
                    type="button"
                    className="liquid-btn py-3 px-10 text-xs bg-brand-500 text-black border-brand-500/50 hover:bg-brand-400 transition-all font-black uppercase tracking-widest shadow-lg shadow-brand-500/20"
                    onClick={() => dispatchChat(`Phone: ${asStr(result['phone'])}\nAnalysis: ${aiText}`)}
                  >
                    <i className="bi bi-chat-fill mr-2"></i> CHAT VỚI AI
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
      <ScanGuide scanType="phone" />
    </div>
  );
}
