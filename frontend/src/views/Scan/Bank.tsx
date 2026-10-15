'use client';
/* Port từ PKV/templates/Scan/scan_bank.html — Kiểm tra Tài khoản Ngân hàng.
 * API: GET /api/v1/scan/banks/ (danh sách NH) + POST /api/v1/scan/account/ (đồng bộ)
 *      + POST /api/v1/scan/analyze-sse/ (SSE giải thích AI, qua toggle).
 */
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { api } from '../../lib/api';

import { renderMd } from '../../lib/chat/markdown';
import { MarkdownView } from '../../components/ui';
import { Button } from '../../components/ui/button';
import { Card } from '../../components/ui/card';
import { Input } from '../../components/ui/input';
import { openSseStream } from '../../lib/chat/stream';
import {
  ScanGuide,
  TurnstileWidget,
  apiBase,
  dispatchChat,
  getTsToken,
  resetTurnstile,
  showToast,
} from '../../components/ScanWidgets';
import type { ScanResult } from '../../components/ScanWidgets';
import { asStr, asNum, TrustGuardrailPanel, guardrailTone, guardrailLabel } from '../../components/ScanWidgets';

interface BankInfo {
  shortName: string;
  name: string;
  bin?: string;
  logo?: string;
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

export default function Bank() {
  const [bank, setBank] = useState('');
  const [account, setAccount] = useState('');
  const [banks, setBanks] = useState<BankInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [aiText, setAiText] = useState('');
  const [aiLoading, setAiLoading] = useState(false);
  const [aiEnabled, setAiEnabled] = useState(false);

  useEffect(() => {
    api
      .get<BankInfo[]>('/scan/banks/')
      .then((d) => {
        if (Array.isArray(d)) setBanks(d);
      })
      .catch(() => {
        /* giữ select trống như bản gốc khi API lỗi */
      });
    const q = new URLSearchParams(window.location.search);
    const qa = q.get('account');
    if (qa) setAccount(qa);
  }, []);

  const streamAi = (data: ScanResult, bankName: string, acc: string): void => {
    setAiLoading(true);
    setAiText('');
    void openSseStream({
      url: `${apiBase()}/scan/analyze-sse/`,
      body: { scan_type: 'account', scan_data: data, raw_input: `${bankName} - ${acc}` },
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

  const submit = (e: React.FormEvent): void => {
    e.preventDefault();
    if (!bank.trim() || !account.trim()) {
      showToast('Vui lòng điền đầy đủ', 'warning');
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
    setAiLoading(false);
    api
      .post<ScanResult>('/scan/account/', {
        bank: bank.trim(),
        account: account.trim(),
        'cf-turnstile-response': tsToken,
      })
      .then((data) => {
        setResult(data);
        setLoading(false);
        if (aiEnabled) streamAi(data, bank, account);
      })
      .catch((err: unknown) => {
        showToast(err instanceof Error ? err.message : 'Có lỗi xảy ra.', 'error');
        setLoading(false);
      });
  };

  const toggleAi = (): void => {
    const next = !aiEnabled;
    setAiEnabled(next);
    if (next && result && !aiText && !aiLoading) streamAi(result, bank, account);
  };

    const level = guardrailTone(result);
  const verdictLabel = guardrailLabel(result);
  const score = asNum(result?.['risk_score']);
  const bankLogo = banks.find((b) => b.shortName === bank)?.logo;

  return (
    <div className="max-w-7xl mx-auto px-4 pt-16 sm:pt-20 pb-20 lg:grid lg:grid-cols-[1fr_340px] lg:gap-8 lg:items-start">
      <div className="animate-fadein space-y-10">
        <div className="text-center space-y-4">
          <div className="inline-flex items-center justify-center w-20 h-20 rounded-3xl bg-brand-500/10 text-brand-400 mb-5 border border-brand-500/20 shadow-lg shadow-brand-500/10">
            <i className="bi bi-bank2 text-4xl"></i>
          </div>
          <h1 className="text-4xl font-black text-white tracking-tight">
            Kiểm tra <span className="glow-text">Tài khoản Ngân hàng</span>
          </h1>
          <p className="text-white/55 max-w-md mx-auto text-sm leading-relaxed">
            Hệ thống tra cứu chéo dữ liệu ngân hàng để xác định tài khoản có lịch sử nhận tiền lừa đảo.
          </p>
        </div>

        <Card className="bg-slate-900/60 backdrop-blur-md border border-white/10 shadow-2xl rounded-3xl p-6 sm:p-8">
          <form onSubmit={submit}>
            <div className="space-y-4">
              <div className="relative">
                <select
                  className="w-full h-14 px-5 text-sm font-bold rounded-2xl bg-white/5 border border-white/10 text-white focus:outline-none focus:border-brand-400/50 transition-all cursor-pointer"
                  value={bank}
                  onChange={(e) => setBank(e.target.value)}
                  required
                >
                  <option value="" className="bg-slate-900 text-white">-- Chọn ngân hàng --</option>
                  {banks.map((b) => (
                    <option key={b.bin || b.shortName} value={b.shortName} className="bg-slate-900 text-white">
                      {b.shortName} - {b.name}
                    </option>
                  ))}
                </select>
                {bank && bankLogo && (
                  <div className="absolute right-12 top-1/2 -translate-y-1/2 pointer-events-none opacity-40">
                    <img src={bankLogo} className="h-6 w-auto" alt="" />
                  </div>
                )}
              </div>

              <div className="flex flex-col sm:flex-row gap-3">
                <Input
                  type="text"
                  className="flex-1 h-14 px-5 text-base sm:text-lg font-bold tracking-widest uppercase rounded-2xl bg-white/5 border border-white/10 text-white placeholder:text-white/40 focus-visible:border-brand-400/50 focus-visible:ring-brand-400/20"
                  placeholder="SỐ TÀI KHOẢN..."
                  value={account}
                  onChange={(e) => setAccount(e.target.value)}
                  required
                />
                <Button
                  type="submit"
                  variant="cyber"
                  className="h-14 px-8 rounded-2xl font-black text-sm uppercase tracking-wider cursor-pointer"
                  disabled={loading}
                >
                  {!loading ? (
                    <span className="inline-flex items-center gap-2"><i className="bi bi-search"></i> TRA CỨU</span>
                  ) : (
                    <span className="w-5 h-5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin"></span>
                  )}
                </Button>
              </div>
              <TurnstileWidget />
            </div>
          </form>
        </Card>

        {result && (
          <div className="space-y-8 animate-fadein">
            <Card className="bg-slate-900/60 backdrop-blur-md border border-white/10 shadow-2xl rounded-3xl overflow-hidden p-0">
              <div className="p-8 text-center border-b border-white/5 bg-white/[0.02] relative overflow-hidden">
                <div className={`absolute inset-0 opacity-10 -z-10 blur-[80px] ${riskGlow(level)}`}></div>

                <div className={`inline-block px-8 py-3 rounded-full text-xs font-black tracking-[0.3em] uppercase mb-6 ${riskBadge(level)}`}>
                  {verdictLabel}
                </div>

                <div className="text-5xl font-black text-white mb-2">{score}/100</div>
                <div className="text-[10px] text-white/45 font-black tracking-widest uppercase mb-8">Chỉ số rủi ro tài chính</div>
              </div>

              <div className="p-8 grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="p-5 rounded-3xl bg-white/[0.03] border border-white/5 space-y-2">
                  <div className="text-[10px] font-black text-white/35 uppercase tracking-widest">Tên Ngân hàng</div>
                  <div className="text-xl font-bold text-white/90">{asStr(result['bank']) || bank}</div>
                </div>
                <div className="p-5 rounded-3xl bg-white/[0.03] border border-white/5 space-y-2">
                  <div className="text-[10px] font-black text-white/35 uppercase tracking-widest">Số tài khoản</div>
                  <div className="text-xl font-bold text-white/90 tracking-widest">{asStr(result['account']) || account}</div>
                </div>
              </div>

              <div className={`m-8 p-6 liquid-glass border-white/5 ${aiEnabled ? 'bg-brand-500/[0.04]' : 'bg-white/[0.01]'}`}>
                <div className="flex items-center gap-3 mb-4">
                  <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${aiEnabled ? 'bg-brand-500/20 text-brand-400' : 'bg-white/10 text-white/45'}`}>
                    <i className="bi bi-robot"></i>
                  </div>
                  <div className="flex-1">
                    <h4 className="text-sm font-black text-white uppercase tracking-wider">AI Financial Auditor</h4>
                    <p className="text-[10px] text-white/55 font-bold uppercase tracking-widest">Anti-Money Laundering Check</p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer ml-auto">
                    <input type="checkbox" checked={aiEnabled} onChange={toggleAi} className="sr-only peer" />
                    <div className="w-11 h-6 bg-white/5 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white/20 after:border-white/10 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-brand-500/50"></div>
                  </label>
                  {aiLoading && <div className="spinner w-4 h-4 text-brand-400"></div>}
                </div>

                {!aiEnabled && !aiText && (
                  <p className="text-white/35 text-xs italic">Bật toggle để AI phân tích chuyên sâu tài khoản này.</p>
                )}
                {(aiEnabled || aiText) && (
                  <div>
                    <MarkdownView html={renderMd(aiText)} className={`text-white/70 text-sm leading-relaxed ${aiLoading ? 'ai-streaming' : ''}`} />
                    {!aiText && !aiLoading && aiEnabled && (
                      <p className="text-white/35 text-xs italic">Đang phân tích các giao dịch liên quan...</p>
                    )}
                  </div>
                )}
              </div>

              <div className="m-8 p-6 rounded-2xl bg-white/[0.01] border border-white/5">
                <div className="flex items-center gap-3 mb-5">
                  <div className="w-10 h-10 rounded-xl bg-brand-500/10 flex items-center justify-center text-brand-400 border border-brand-500/20">
                    <i className="bi bi-search"></i>
                  </div>
                  <div className="flex-1">
                    <h4 className="text-sm font-black text-white uppercase tracking-wider">Tra cứu Web</h4>
                    <p className="text-[10px] text-white/55 font-bold uppercase tracking-widest">OSINT: Kiểm tra trên Internet</p>
                  </div>
                </div>
                <p className="text-white/45 text-xs mb-4 leading-relaxed">Tìm kiếm thông tin về tài khoản này trên các nguồn công khai để xác minh thêm.</p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <a
                    href={`https://www.google.com/search?q=${encodeURIComponent(`${asStr(result['bank']) || bank} ${asStr(result['account']) || account} lừa đảo`)}`}
                    target="_blank"
                    rel="noopener"
                    className="flex items-center gap-3 p-3.5 rounded-xl bg-white/[0.03] border border-white/5 hover:bg-white/[0.06] hover:border-brand-500/20 transition-all group"
                  >
                    <div className="w-8 h-8 rounded-lg bg-brand-500/10 flex items-center justify-center text-brand-400 shrink-0"><i className="bi bi-google"></i></div>
                    <div className="min-w-0">
                      <div className="text-white/80 text-xs font-black group-hover:text-brand-400 transition-colors">Google Search</div>
                      <div className="text-white/35 text-[10px] truncate">Tìm cảnh báo lừa đảo</div>
                    </div>
                    <i className="bi bi-box-arrow-up-right text-white/20 ml-auto shrink-0"></i>
                  </a>
                  <a
                    href={`https://checkscam.vn/search?q=${encodeURIComponent(asStr(result['account']) || account)}`}
                    target="_blank"
                    rel="noopener"
                    className="flex items-center gap-3 p-3.5 rounded-xl bg-white/[0.03] border border-white/5 hover:bg-white/[0.06] hover:border-brand-500/20 transition-all group"
                  >
                    <div className="w-8 h-8 rounded-lg bg-danger-500/10 flex items-center justify-center text-danger-400 shrink-0"><i className="bi bi-shield-exclamation"></i></div>
                    <div className="min-w-0">
                      <div className="text-white/80 text-xs font-black group-hover:text-brand-400 transition-colors">CheckScam.vn</div>
                      <div className="text-white/35 text-[10px] truncate">Database CSDL lừa đảo VN</div>
                    </div>
                    <i className="bi bi-box-arrow-up-right text-white/20 ml-auto shrink-0"></i>
                  </a>
                  <a
                    href={`https://www.google.com/search?q=${encodeURIComponent(`site:facebook.com ${asStr(result['account']) || account} lừa đảo`)}`}
                    target="_blank"
                    rel="noopener"
                    className="flex items-center gap-3 p-3.5 rounded-xl bg-white/[0.03] border border-white/5 hover:bg-white/[0.06] hover:border-brand-500/20 transition-all group"
                  >
                    <div className="w-8 h-8 rounded-lg bg-brand-500/10 flex items-center justify-center text-brand-400 shrink-0"><i className="bi bi-facebook"></i></div>
                    <div className="min-w-0">
                      <div className="text-white/80 text-xs font-black group-hover:text-brand-400 transition-colors">Facebook</div>
                      <div className="text-white/35 text-[10px] truncate">Tìm bài đăng tố cáo</div>
                    </div>
                    <i className="bi bi-box-arrow-up-right text-white/20 ml-auto shrink-0"></i>
                  </a>
                  <a
                    href={`https://www.google.com/search?q=${encodeURIComponent(`${asStr(result['bank']) || bank} ${asStr(result['account']) || account} scam report`)}`}
                    target="_blank"
                    rel="noopener"
                    className="flex items-center gap-3 p-3.5 rounded-xl bg-white/[0.03] border border-white/5 hover:bg-white/[0.06] hover:border-brand-500/20 transition-all group"
                  >
                    <div className="w-8 h-8 rounded-lg bg-warn-500/10 flex items-center justify-center text-warn-400 shrink-0"><i className="bi bi-globe2"></i></div>
                    <div className="min-w-0">
                      <div className="text-white/80 text-xs font-black group-hover:text-brand-400 transition-colors">Global Search</div>
                      <div className="text-white/35 text-[10px] truncate">Scam report quốc tế</div>
                    </div>
                    <i className="bi bi-box-arrow-up-right text-white/20 ml-auto shrink-0"></i>
                  </a>
                </div>
              </div>

              <TrustGuardrailPanel result={result} />

              <div className="p-8 bg-white/[0.02] border-t border-white/5 flex flex-wrap gap-4 justify-between items-center">
                <div className="flex gap-3">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="rounded-xl border-white/10 bg-white/5 text-white/70 hover:text-white"
                    onClick={() => showToast('Đã lưu!', 'success')}
                  >
                    <i className="bi bi-safe mr-1.5"></i> Archive
                  </Button>
                  <Button
                    type="button"
                    variant="cyber"
                    size="sm"
                    className="rounded-xl font-bold"
                    onClick={() => dispatchChat(`Bank Account: ${asStr(result['bank']) || bank} - ${asStr(result['account']) || account}\nAnalysis: ${aiText}`)}
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
                  <Link
                    href={`/report/?target_type=account&target_value=${encodeURIComponent(asStr(result['account']) || account)}&bank_name=${encodeURIComponent(asStr(result['bank']) || bank)}&bank_account=${encodeURIComponent(asStr(result['account']) || account)}`}
                  >
                    <i className="bi bi-shield-slash mr-1.5"></i> TỐ CÁO TÀI KHOẢN
                  </Link>
                </Button>
              </div>
            </Card>
          </div>
        )}
      </div>
      <ScanGuide scanType="bank" />
    </div>
  );
}
