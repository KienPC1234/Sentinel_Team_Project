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
  PrivacyReceiptBadge,
  ScanGuide,
  ScanPrivacyToggle,
  TurnstileWidget,
  consumeTurnstileToken,
  copyText,
  dispatchChat,
  getTsToken,
  riskBadge,
  riskGlow,
  showToast,
  useScanPrivacy,
} from '../../components/ScanWidgets';
import type { ScanResult } from '../../components/ScanWidgets';
import { asStr, asNum, asArr, TrustGuardrailPanel, guardrailTone, guardrailLabel } from '../../components/ScanWidgets';

interface OnlineMatch {
  url?: string;
  title?: string;
  snippet?: string;
}

export default function Phone() {
  const [phone, setPhone] = useState('');
  const [claimedVietnameseEntity, setClaimedVietnameseEntity] = useState(false);
  const [externalLookupConsent, setExternalLookupConsent] = useState(false);
  const [maskPii, setMaskPii] = useScanPrivacy();
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [aiText, setAiText] = useState('');

  const submit = useCallback((rawPhone: string) => {
    if (!rawPhone.trim()) {
      showToast('Vui lòng nhập số điện thoại', 'warning');
      return;
    }
    let phoneNormalized = rawPhone.trim().replace(/[\s().-]/g, '');
    if (phoneNormalized.startsWith('00')) phoneNormalized = '+' + phoneNormalized.substring(2);
    if (/^0\d{9,10}$/.test(phoneNormalized)) phoneNormalized = '+84' + phoneNormalized.substring(1);
    if (!/^(\+\d{8,15}|0\d{9,10})$/.test(phoneNormalized)) {
      showToast('Số điện thoại không hợp lệ. VD: 0978589220 hoặc +84978589220', 'warning');
      return;
    }
    const tsToken = consumeTurnstileToken();
    if (!tsToken) return;
    setLoading(true);
    setResult(null);
    setAiText('');
    api
      .post<ScanResult>('/scan/phone/', {
        phone: phoneNormalized,
        claimed_vietnamese_entity: claimedVietnameseEntity,
        external_lookup_consent: externalLookupConsent,
        mask_pii: maskPii,
        'cf-turnstile-response': tsToken,
      })
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
  }, [claimedVietnameseEntity, externalLookupConsent, maskPii]);

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

  const reputationProvenance = (result?.['reputation_provenance'] as Record<string, unknown> | undefined) || null;
  const numberStructure = (result?.['phone_structure'] as Record<string, unknown> | undefined) || null;
  const structureWarnings = asArr<string>(numberStructure?.['warnings']);
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
            Kiểm tra cấu trúc kho số Việt Nam, các báo cáo trong hệ thống và dấu hiệu rủi ro.
            Kết quả không xác thực danh tính chủ thuê bao; hỗ trợ số cố định, di động và quốc tế.
          </p>
        </div>

        <div className="liquid-card p-6 sm:p-8">
          <form
            data-tour="scan-form"
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
                data-tour="scan-submit"
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
            <label className="flex items-center gap-3 text-sm text-white/75 mt-4">
              <input
                type="checkbox"
                checked={claimedVietnameseEntity}
                onChange={(e) => setClaimedVietnameseEntity(e.target.checked)}
                className="h-4 w-4 accent-amber-400"
              />
              Người gọi tự xưng là cơ quan hoặc doanh nghiệp tại Việt Nam
            </label>
            <label className="flex items-center gap-3 text-sm text-white/75 mt-2">
              <input
                type="checkbox"
                checked={externalLookupConsent}
                onChange={(e) => setExternalLookupConsent(e.target.checked)}
                className="h-4 w-4 accent-amber-400"
              />
              Tôi đồng ý gửi số điện thoại tới công cụ tìm kiếm bên ngoài để tra cứu bổ sung
            </label>
            <div className="mt-4">
              <ScanPrivacyToggle scanType="phone" checked={maskPii} onChange={setMaskPii} compact />
            </div>
            <TurnstileWidget />
          </form>
        </div>

        {result && (
          <div className="space-y-6">
            <div className="liquid-card overflow-hidden">
              <div className="p-8 sm:p-10 text-center border-b border-white/5 bg-white/[0.02] relative overflow-hidden">
                <div className={`absolute inset-0 opacity-10 -z-10 blur-[100px] ${riskGlow(level)}`}></div>

                <div className={`inline-block px-8 py-3 rounded-full text-xs font-black tracking-[0.3em] uppercase mb-6 ${riskBadge(level)}`}>
                  {verdictLabel}
                </div>

                <div className="flex items-center justify-center gap-6 mb-8">
                  <div className="text-6xl sm:text-7xl font-black text-white">{score}</div>
                  <div className="h-14 w-px bg-white/10"></div>
                  <div className="text-left">
                    <div className="text-xs font-black text-white/55 tracking-wider uppercase mb-1">Điểm rủi ro</div>
                    <div className="text-sm font-bold text-white/85">{asStr(result['suggested_action'])}</div>
                  </div>
                </div>

                <div className="w-full h-2 bg-white/5 rounded-full overflow-hidden max-w-xl mx-auto shadow-inner">
                  <div
                    className="h-full transition-all duration-1000 ease-out"
                    style={{ width: `${score}%`, background: score >= 80 ? 'var(--sc-danger-500)' : score >= 50 ? 'var(--sc-warn-500)' : 'var(--sc-safe-500)' }}
                  ></div>
                </div>
                <PrivacyReceiptBadge result={result} />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 divide-y md:divide-y-0 md:divide-x divide-white/5 border-b border-white/5">
                <div className="p-6 sm:p-8 space-y-4">
                  <div className="flex items-center gap-2.5 text-white/60 mb-2">
                    <i className="bi bi-info-circle-fill"></i>
                    <span className="text-xs font-black uppercase tracking-wider">Thông tin số</span>
                  </div>
                  <div className="space-y-3.5">
                    <div className="flex justify-between items-center text-sm">
                      <span className="text-white/55">Quốc gia</span>
                      <span className="font-bold text-white flex items-center gap-2">
                        <span className="text-[11px] text-brand-400 font-black px-1.5 py-0.5 rounded bg-brand-500/10 border border-brand-500/20">
                          {asStr(result['country_code'])}
                        </span>
                        <span>{asStr(result['country_name'])}</span>
                      </span>
                    </div>
                    <div className="flex justify-between items-center text-sm">
                      <span className="text-white/55">Nhà mạng</span>
                      <div className="text-right">
                        <div className="font-bold text-white">{asStr(result['carrier'])}</div>
                        <div className="text-[11px] text-white/45 uppercase tracking-tight">{asStr(result['line_type'])}</div>
                      </div>
                    </div>
                    <div className="flex justify-between items-center text-sm pt-1">
                      <span className="text-white/55">Tính chất số</span>
                      <span
                        className={`font-black text-[11px] px-2.5 py-0.5 rounded uppercase ${
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

                <div className="p-6 sm:p-8 space-y-4">
                  <div className="flex items-center gap-2.5 text-white/60 mb-2">
                    <i className="bi bi-people-fill"></i>
                    <span className="text-xs font-black uppercase tracking-wider">Cộng đồng</span>
                  </div>
                  <div className="space-y-3.5">
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

                <div className="p-6 sm:p-8 space-y-4">
                  <div className="flex items-center gap-2.5 text-white/60 mb-2">
                    <i className="bi bi-shield-lock-fill"></i>
                    <span className="text-xs font-black uppercase tracking-wider">Phân bổ điểm</span>
                  </div>
                  <div className="space-y-3">
                    <div>
                      <div className="flex justify-between text-xs mb-1">
                        <span className="text-white/60 font-semibold">Uy tín</span>
                        <span className="text-white/75 font-bold">{asNum(componentScores['reputation'])}/45</span>
                      </div>
                      <div className="h-1.5 bg-white/5 rounded-full overflow-hidden">
                        <div className="h-full bg-brand-400" style={{ width: `${(asNum(componentScores['reputation']) / 45) * 100}%` }}></div>
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between text-xs mb-1">
                        <span className="text-white/60 font-semibold">Định danh số</span>
                        <span className="text-white/75 font-bold">{asNum(componentScores['metadata'])}/25</span>
                      </div>
                      <div className="h-1.5 bg-white/5 rounded-full overflow-hidden">
                        <div className="h-full bg-brand2-400" style={{ width: `${(asNum(componentScores['metadata']) / 25) * 100}%` }}></div>
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between text-xs mb-1">
                        <span className="text-white/60 font-semibold">Hành vi</span>
                        <span className="text-white/75 font-bold">{asNum(componentScores['behavior'])}/30</span>
                      </div>
                      <div className="h-1.5 bg-white/5 rounded-full overflow-hidden">
                        <div className="h-full bg-brand2-400" style={{ width: `${(asNum(componentScores['behavior']) / 30) * 100}%` }}></div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {numberStructure && (
                <section className="p-6 sm:p-8 space-y-2.5 border-b border-white/5 bg-amber-500/[0.03]" aria-label="Kiểm tra cấu trúc số">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="text-sm font-black text-white flex items-center gap-2">
                      <i className="bi bi-diagram-3 text-amber-300"></i>
                      Đối chiếu cấu trúc số điện thoại
                    </h3>
                    <span className="text-xs font-bold text-amber-200 px-2.5 py-1 rounded-lg bg-amber-400/10 border border-amber-400/20">
                      {asStr(numberStructure['label'])}
                    </span>
                  </div>
                  <p className="text-xs sm:text-sm text-white/75">
                    Mã quốc gia: <span className="text-white font-semibold">{asStr(numberStructure['country_calling_code']) || 'Chưa xác định'}</span> ·
                    {' '}Loại số: <span className="text-white font-semibold">{asStr(numberStructure['type'])}</span> ·
                    {' '}Đầu số: <span className="text-white font-semibold">{asStr(numberStructure['national_prefix']) || 'Không áp dụng'}</span>
                  </p>
                  {structureWarnings.map((warning, index) => (
                    <p className="text-xs sm:text-sm text-amber-100/85" key={index}>{warning}</p>
                  ))}
                  {reputationProvenance && (
                    <p className="text-xs text-white/70">
                      Báo cáo cộng đồng nội bộ đã duyệt: {asNum(reputationProvenance['local_approved_reports'])}.
                      Chưa có kết quả xác nhận từ blacklist chính thức.{' '}
                      <a className="underline text-brand-400" href="https://www.trangtrang.com/" target="_blank" rel="noopener noreferrer">
                        Tham khảo Trang Trắng (tra cứu thủ công)
                      </a>
                      . Dữ liệu Trang Trắng chưa được đồng bộ tự động.
                    </p>
                  )}
                  <p className="text-xs text-white/55">
                    Số đúng định dạng không đồng nghĩa người gọi đáng tin; hiển thị số có thể bị giả mạo.
                    {' '}<a className="underline text-brand-400" href="https://mst.gov.vn/bo-tttt-day-manh-dinh-danh-cuoc-goi-de-ngan-ngua-lua-dao-tren-khong-gian-mang-19724111208351436.htm" target="_blank" rel="noopener noreferrer">Nguồn tham khảo</a>
                  </p>
                </section>
              )}

              {onlineLookup && (
                <div className="p-6 sm:p-8 space-y-4 border-b border-white/5 bg-white/[0.01]">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="flex items-center gap-2.5 text-white/60">
                      <i className="bi bi-globe2"></i>
                      <span className="text-xs font-black uppercase tracking-wider">Tra cứu Internet</span>
                    </div>
                    <span
                      className={`font-bold text-xs px-2.5 py-1 rounded-lg ${
                        onlineLookup['suspected_disposable']
                          ? 'bg-danger-500/20 text-danger-400 border border-danger-500/30'
                          : 'bg-safe-500/20 text-safe-400 border border-safe-500/30'
                      }`}
                    >
                      {onlineLookup['suspected_disposable'] ? 'Có dấu hiệu số miễn phí trực tuyến' : 'Không phát hiện số miễn phí trực tuyến'}
                    </span>
                  </div>
                  <p className="text-xs sm:text-sm text-white/65">{asStr(onlineLookup['note'])}</p>

                  {matches.length > 0 && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {matches.map((src, i) => (
                        <div key={i} className="p-3.5 rounded-xl bg-white/[0.02] border border-white/10">
                          <a href={safeUrl(src.url)} target="_blank" rel="noopener noreferrer" className="text-xs font-bold text-brand-400 hover:text-brand-300 transition-colors">
                            {src.title || src.url}
                          </a>
                          <p className="text-xs text-white/55 mt-1 line-clamp-2">{src.snippet}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              <div className="p-6 sm:p-8 space-y-8">
                <div className="grid grid-cols-1 lg:grid-cols-5 gap-8">
                  <div className="lg:col-span-3 space-y-4">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-xl bg-brand-500/10 flex items-center justify-center text-brand-400 border border-brand-500/20 shadow-lg shadow-brand-500/5 shrink-0">
                        <i className="bi bi-stars"></i>
                      </div>
                      <div>
                        <h4 className="text-sm font-black text-white">Tóm tắt phân tích</h4>
                        <p className="text-xs text-white/55">Phân tích tổng hợp từ hệ thống</p>
                      </div>
                    </div>
                    <MarkdownView html={renderMd(aiText)} className="text-white/75 text-sm leading-relaxed bg-white/[0.02] p-6 rounded-2xl border border-white/5 shadow-inner" />
                  </div>

                  <div className="lg:col-span-2 space-y-4">
                    <h4 className="text-xs font-black text-white/60 uppercase tracking-wider flex items-center gap-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-brand-500"></span>
                      Tại sao có kết quả này?
                    </h4>
                    <div className="space-y-3">
                      {reasons.map((reason, i) => (
                        <div key={i} className="flex items-start gap-3 p-4 rounded-xl bg-white/[0.02] border border-white/5 hover:bg-white/[0.04] transition-all group">
                          <div className="mt-0.5">
                            <i className="bi bi-patch-check-fill text-brand-500/50 group-hover:text-brand-400 transition-colors"></i>
                          </div>
                          <div className="text-sm text-white/75 group-hover:text-white/90 transition-colors">
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
