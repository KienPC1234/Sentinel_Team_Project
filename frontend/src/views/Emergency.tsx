'use client';
import { useEffect, useRef, useState } from 'react';

import type { FormEvent } from 'react';

import Link from 'next/link';

import { renderMd } from '../lib/chat/markdown';

import { openSseStream } from '../lib/chat/stream';
import { MarkdownView } from '../components/ui';

type StepKey = 'stop' | 'bank' | 'police' | 'secure' | 'report';

interface ChatMsg {
  fromUser: boolean;
  text: string;
  html: string;
  time: string;
  status: string;
  isThinking: boolean;
  thinkingContent: string;
  thinkingCollapsed: boolean;
  streaming: boolean;
}

const WELCOME =
  '**Xin chào!** Tôi là ShieldCall AI, trợ lý khẩn cấp của bạn.\n\nHãy mô tả tình huống bạn đang gặp phải, hoặc chọn một trong các nút phía trên để được hướng dẫn xử lý ngay. Tôi luôn sẵn sàng hỗ trợ bạn 24/7.';

const QUICK_PROMPTS: Array<{ text: string; label: string; icon: string; cls: string }> = [
  {
    text: 'Tôi vừa bị lừa chuyển tiền qua mạng, tôi cần làm gì ngay bây giờ?',
    label: 'Bị lừa chuyển tiền',
    icon: 'bi-cash-coin',
    cls: 'bg-danger-500/10 text-danger-400 border-danger-500/20 hover:bg-danger-500/20',
  },
  {
    text: 'Tôi đã cung cấp thông tin cá nhân và OTP cho kẻ lạ, làm sao để bảo vệ tài khoản?',
    label: 'Lộ thông tin cá nhân',
    icon: 'bi-person-exclamation',
    cls: 'bg-warn-500/10 text-warn-400 border-warn-500/20 hover:bg-warn-500/20',
  },
  {
    text: 'Tôi nhận được cuộc gọi từ người tự xưng là công an/ngân hàng yêu cầu chuyển tiền, đây có phải lừa đảo không?',
    label: 'Cuộc gọi giả mạo',
    icon: 'bi-telephone-x',
    cls: 'bg-brand-500/10 text-brand-400 border-brand-500/20 hover:bg-brand-500/20',
  },
  {
    text: 'Tài khoản ngân hàng/mạng xã hội của tôi bị hack, tôi phải làm gì?',
    label: 'Bị hack tài khoản',
    icon: 'bi-shield-exclamation',
    cls: 'bg-brand2-500/10 text-brand2-400 border-brand2-500/20 hover:bg-brand2-500/20',
  },
];

const PRESETS: Record<string, string> = {
  money:
    'Tôi vừa bị lừa chuyển tiền. Số tiền đã chuyển là ...; thời điểm ...; tôi cần các bước xử lý ngay trong 30 phút tới.',
  otp: 'Tôi đã lộ OTP và thông tin tài khoản. Hãy hướng dẫn thứ tự xử lý khẩn cấp để giảm thiệt hại.',
  impersonation:
    'Tôi nhận cuộc gọi giả danh công an/ngân hàng yêu cầu chuyển tiền. Hãy giúp tôi xác minh và xử lý an toàn.',
  account:
    'Tài khoản ngân hàng/mạng xã hội của tôi có dấu hiệu bị chiếm quyền. Tôi cần checklist khẩn cấp ngay.',
};

const BANKS: Array<{ name: string; tel: string; display: string }> = [
  { name: 'Vietcombank', tel: 'tel:1900545413', display: '1900 545 413' },
  { name: 'Techcombank', tel: 'tel:1800588822', display: '1800 588 822' },
  { name: 'BIDV', tel: 'tel:19009247', display: '1900 9247' },
  { name: 'VietinBank', tel: 'tel:1900558868', display: '1900 558 868' },
];

function now(): string {
  return new Date().toLocaleTimeString('vi', { hour: '2-digit', minute: '2-digit' });
}

const STATUS_MAP: Record<string, string> = {
  searching_knowledge: 'Đang tra cứu kiến thức...',
  searching_web: 'Đang tìm kiếm thông tin...',
  checking_safety: 'Đang kiểm tra an toàn...',
  reasoning: 'Đang suy luận...',
  thinking: 'Đang suy luận...',
};

/* Port từ PKV/templates/Emergency/emergency.html.
 * API: POST /api/v1/chat/stream/ (SSE, qua openSseStream đã port). */
export default function Emergency() {
  const [checklist, setChecklist] = useState<Record<StepKey, boolean>>({
    stop: false,
    bank: false,
    police: false,
    secure: false,
    report: false,
  });
  const [input, setInput] = useState('');
  const [typing, setTyping] = useState(false);
  const [lastSent, setLastSent] = useState('');
  const [sessionId, setSessionId] = useState('');
  const [messages, setMessages] = useState<ChatMsg[]>([]);
  const msgBoxRef = useRef<HTMLDivElement>(null);
  const chatCardRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    setMessages([
      {
        fromUser: false,
        text: WELCOME,
        html: renderMd(WELCOME),
        time: now(),
        status: '',
        isThinking: false,
        thinkingContent: '',
        thinkingCollapsed: false,
        streaming: false,
      },
    ]);
    try {
      setSessionId(
        `emergency-${window.crypto?.randomUUID ? window.crypto.randomUUID() : Math.random().toString(36).substring(2)}`,
      );
    } catch {
      setSessionId(`emergency-${Math.random().toString(36).substring(2)}`);
    }
  }, []);

  useEffect(() => {
    const el = msgBoxRef.current;
    if (el) el.scrollTo({ top: el.scrollHeight, behavior: 'smooth' });
  }, [messages, typing]);

  useEffect(() => {
    try {
      const saved = localStorage.getItem('sc_emergency_checklist');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed && typeof parsed === 'object') {
          setChecklist((prev) => ({ ...prev, ...parsed }));
        }
      }
    } catch {
      /* ignore */
    }
  }, []);

  const completedCount = Object.values(checklist).filter(Boolean).length;
  const completionPct = Math.round((completedCount / 5) * 100);

  function toggleStep(key: StepKey): void {
    setChecklist((c) => {
      const next = { ...c, [key]: !c[key] };
      try {
        localStorage.setItem('sc_emergency_checklist', JSON.stringify(next));
      } catch {
        /* ignore */
      }
      return next;
    });
  }

  function applyPreset(type: string): void {
    setInput(PRESETS[type] || '');
    chatCardRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    inputRef.current?.focus({ preventScroll: true });
  }

  function updateLast(patch: Partial<ChatMsg>): void {
    setMessages((prev) => {
      if (prev.length === 0) return prev;
      const next = [...prev];
      next[next.length - 1] = { ...next[next.length - 1], ...patch };
      return next;
    });
  }

  async function send(text?: string): Promise<void> {
    const content = (text ?? input).trim();
    if (!content || typing) return;
    if (content.length < 10 || content === lastSent) return;
    setLastSent(content);
    setMessages((prev) => [...prev, { fromUser: true, text: content, html: content, time: now(), status: '', isThinking: false, thinkingContent: '', thinkingCollapsed: false, streaming: false }]);
    setInput('');
    setTyping(true);
    setMessages((prev) => [...prev, { fromUser: false, text: '', html: '', time: now(), status: '', isThinking: false, thinkingContent: '', thinkingCollapsed: false, streaming: true }]);

    try {
      let acc = '';
      let thinking = '';
      await openSseStream({
        url: '/api/v1/chat/stream/',
        body: {
          user_message: content,
          session_id: sessionId,
          context: 'chat',
          scan_context:
            'EMERGENCY MODE: Người dùng đang ở trang Hỗ trợ khẩn cấp. Họ có thể đang là nạn nhân của lừa đảo. Hãy trả lời bằng tiếng Việt, ngắn gọn, rõ ràng, và đưa ra các bước hành động cụ thể. Ưu tiên an toàn tài chính và bảo mật thông tin cá nhân.',
        },
        onEvent: (ev) => {
          switch (ev.type) {
            case 'delta':
              if (!ev.text) break;
              acc += ev.text;
              updateLast({ text: acc, html: renderMd(acc) });
              break;
            case 'thinking':
              thinking += ev.text;
              updateLast({ isThinking: true, thinkingContent: thinking });
              break;
            case 'status':
              updateLast({
                status: STATUS_MAP[ev.value] || ev.value,
                isThinking: ev.value === 'thinking' || ev.value === 'reasoning' ? true : undefined,
              });
              break;
            case 'done':
              if (ev.session_id) setSessionId(ev.session_id);
              updateLast({ status: '', isThinking: false, thinkingCollapsed: true, streaming: false });
              break;
            default:
              break;
          }
        },
      });
      updateLast({ status: '', streaming: false });
    } catch {
      updateLast({
        text: 'Lỗi kết nối mạng. Vui lòng kiểm tra Internet và thử lại.',
        html: 'Lỗi kết nối mạng. Vui lòng kiểm tra Internet và thử lại.',
        streaming: false,
        status: '',
      });
      setLastSent('');
    } finally {
      setTyping(false);
    }
  }

  function onSubmit(e: FormEvent): void {
    e.preventDefault();
    void send();
  }

  const stepBtn = (key: StepKey, label: string) => (
    <button
      key={key}
      type="button"
      onClick={() => toggleStep(key)}
      className={`px-2.5 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest border transition-all ${
        checklist[key]
          ? 'bg-safe-500/15 text-safe-400 border-safe-500/30'
          : 'bg-white/[0.02] text-white/35 border-white/10'
      }`}
    >
      {label}
    </button>
  );

  return (
    <div className="animate-fadein max-w-3xl mx-auto space-y-10 px-4 pt-16 sm:pt-20 pb-20">
      <div className="text-center space-y-4">
        <div
          className="inline-flex items-center justify-center w-24 h-24 rounded-[2.5rem] bg-danger-500/10 text-danger-500 border border-danger-500/20 shadow-2xl shadow-danger-500/10 mb-5"
        >
          <i className="bi bi-exclamation-octagon-fill text-5xl"></i>
        </div>
        <h1
          className="text-4xl font-black text-danger-500 tracking-tight leading-none uppercase"
        >
          Hỗ trợ khẩn cấp
        </h1>
        <p className="text-white/55 text-sm font-bold tracking-widest uppercase">
          Giữ bình tĩnh và thực hiện ngay các bước bảo vệ dưới đây
        </p>
      </div>

      <div className="space-y-6">
        <div className="liquid-card p-5 border border-brand-500/20 bg-brand-500/[0.03]">
          <div className="flex flex-col gap-4">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
              <div>
                <p className="text-[10px] font-black text-brand-400 uppercase tracking-widest">Bảng điều khiển khẩn cấp</p>
                <p className="text-xs text-white/45">Đánh dấu các bước đã làm để tránh sót thao tác quan trọng.</p>
              </div>
              <div className="text-[10px] font-black uppercase tracking-widest text-white/60">
                Hoàn thành <span className="text-brand-400">{completedCount}</span>/5
              </div>
            </div>
            <div className="h-2 rounded-full bg-white/5 overflow-hidden border border-white/10">
              <div
                className="h-full rounded-full bg-gradient-to-r from-brand-500 to-brand2-500 transition-all duration-500"
                style={{ width: `${completionPct}%` }}
              ></div>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
              {stepBtn('stop', 'Ngừng giao dịch')}
              {stepBtn('bank', 'Gọi ngân hàng')}
              {stepBtn('police', 'Báo cơ quan')}
              {stepBtn('secure', 'Đổi mật khẩu')}
              {stepBtn('report', 'Gửi báo cáo')}
            </div>
            <div className="flex flex-wrap gap-2 items-center">
              <button
                type="button"
                onClick={() => applyPreset('money')}
                className="px-3 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest bg-danger-500/10 text-danger-300 border border-danger-500/20 hover:bg-danger-500/20 transition-all"
              >
                Mất tiền
              </button>
              <button
                type="button"
                onClick={() => applyPreset('otp')}
                className="px-3 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest bg-warn-500/10 text-warn-300 border border-warn-500/20 hover:bg-warn-500/20 transition-all"
              >
                Lộ OTP
              </button>
              <button
                type="button"
                onClick={() => applyPreset('impersonation')}
                className="px-3 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest bg-brand-500/10 text-brand-300 border border-brand-500/20 hover:bg-brand-500/20 transition-all"
              >
                Giả danh công an/ngân hàng
              </button>
              <button
                type="button"
                onClick={() => applyPreset('account')}
                className="px-3 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest bg-brand2-500/10 text-brand2-300 border border-brand2-500/20 hover:bg-brand2-500/20 transition-all"
              >
                Bị chiếm tài khoản
              </button>
            </div>
          </div>
        </div>

        <div className="liquid-card p-8 border-l-8 border-danger-500 bg-danger-500/[0.02] hover:bg-danger-500/[0.04] transition-all">
          <div className="flex flex-col sm:flex-row gap-8 items-start">
            <div className="w-12 h-12 rounded-2xl bg-danger-500 text-black flex items-center justify-center font-black text-lg shrink-0 shadow-lg shadow-danger-500/20">
              01
            </div>
            <div className="space-y-4 flex-1">
              <h2 className="text-xl font-black text-danger-400 uppercase tracking-wide">Ngừng mọi giao dịch ngay lập tức</h2>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {['Không chuyển thêm tiền', 'Không cung cấp OTP', 'Không click link lạ', 'Không tải app lạ'].map((t) => (
                  <div key={t} className="flex items-center gap-3 p-4 rounded-2xl bg-white/[0.03] border border-white/5">
                    <i className="bi bi-x-circle-fill text-danger-500"></i>
                    <span className="text-xs font-black text-white/70 uppercase tracking-widest">{t}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div className="liquid-card p-8 border-l-8 border-warn-500 bg-warn-500/[0.02] hover:bg-warn-500/[0.04] transition-all">
          <div className="flex flex-col sm:flex-row gap-8 items-start">
            <div className="w-12 h-12 rounded-2xl bg-warn-500 text-black flex items-center justify-center font-black text-lg shrink-0 shadow-lg shadow-warn-500/20">
              02
            </div>
            <div className="space-y-5 flex-1 w-full">
              <div className="space-y-1">
                <h2 className="text-xl font-black text-warn-400 uppercase tracking-wide">
                  Gọi Hotline Ngân Hàng để Khoá Thẻ
                </h2>
                <p className="text-xs font-bold text-white/55 uppercase tracking-widest">
                  Liên hệ ngay để tạm ngừng mọi dịch vụ tài chính liên quan
                </p>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {BANKS.map((b) => (
                  <a
                    key={b.name}
                    href={b.tel}
                    className="flex justify-between items-center p-4 rounded-2xl bg-white/[0.04] border border-white/5 hover:bg-white/10 transition-all group"
                  >
                    <span className="text-xs font-black text-white/80 uppercase">{b.name}</span>
                    <span className="text-xs font-black text-brand-400 group-hover:scale-110 transition-transform">
                      <i className="bi bi-telephone-fill mr-1"></i> {b.display}
                    </span>
                  </a>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div className="liquid-card p-8 border-l-8 border-brand-500 bg-brand-500/[0.02] hover:bg-brand-500/[0.04] transition-all">
          <div className="flex flex-col sm:flex-row gap-8 items-start">
            <div className="w-12 h-12 rounded-2xl bg-brand-500 text-black flex items-center justify-center font-black text-lg shrink-0 shadow-lg shadow-brand-500/20">
              03
            </div>
            <div className="space-y-5 flex-1">
              <h2 className="text-xl font-black text-brand-400 uppercase tracking-wide">Trình báo Cơ quan Chức năng</h2>
              <div className="grid grid-cols-1 gap-4">
                <div className="flex items-center gap-6 p-5 rounded-[2rem] bg-white/[0.04] border border-white/5">
                  <div className="w-14 h-14 rounded-[1.25rem] bg-brand-500/10 flex items-center justify-center text-brand-400 text-2xl">
                    <i className="bi bi-megaphone-fill"></i>
                  </div>
                  <div>
                    <div className="text-lg font-black text-white">GỌI 113</div>
                    <p className="text-[10px] font-black text-white/45 uppercase tracking-[0.2em] mt-1">
                      Phòng Cảnh sát Hình sự (24/7)
                    </p>
                  </div>
                </div>
                <a
                  href="https://skhcn.tuyenquang.gov.vn/vi/tin-bai/huong-dan-to-giac-toi-pham-qua-ung-dung-vneid?type=NEWS&id=81623"
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-6 p-5 rounded-[2rem] bg-white/[0.04] border border-white/5 hover:bg-white/10 transition-all group"
                >
                  <div className="w-14 h-14 rounded-[1.25rem] bg-brand-500/10 flex items-center justify-center text-brand-400 text-2xl group-hover:scale-110 transition-transform">
                    <i className="bi bi-globe"></i>
                  </div>
                  <div>
                    <div className="text-lg font-black text-white">Tố giác tội phạm mạng qua VneID</div>
                    <p className="text-[10px] font-black text-brand-400/60 uppercase tracking-[0.2em] mt-1">
                      Ứng dụng VNeID của Bộ Công an <i className="bi bi-arrow-right ml-1"></i>
                    </p>
                  </div>
                </a>
              </div>
            </div>
          </div>
        </div>

        <div className="liquid-card p-8 border-l-8 border-safe-500 bg-safe-500/[0.02] hover:bg-safe-500/[0.04] transition-all">
          <div className="flex flex-col sm:flex-row gap-8 items-start">
            <div className="w-12 h-12 rounded-2xl bg-safe-500 text-black flex items-center justify-center font-black text-lg shrink-0 shadow-lg shadow-safe-500/20">
              04
            </div>
            <div className="space-y-4 flex-1">
              <h2 className="text-xl font-black text-safe-400 uppercase tracking-wide">Lưu bằng chứng & Bảo mật lại</h2>
              <div className="space-y-3">
                {[
                  { icon: 'bi-camera-fill', text: 'Chụp màn hình tin nhắn & giao dịch' },
                  { icon: 'bi-key-fill', text: 'Đổi mật khẩu tài khoản bị rò rỉ' },
                  { icon: 'bi-shield-lock-fill', text: 'Kích hoạt xác thực 2 lớp (2FA)' },
                ].map((r) => (
                  <div key={r.text} className="flex items-center gap-4 p-4 rounded-2xl bg-white/[0.03] border border-white/5">
                    <i className={`bi ${r.icon} text-safe-500 text-xl`}></i>
                    <div className="text-xs font-black text-white/70 uppercase tracking-widest">{r.text}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div className="liquid-card p-8 border-l-8 border-brand2-500 bg-brand2-500/[0.02] hover:bg-brand2-500/[0.04] transition-all">
          <div className="flex flex-col sm:flex-row gap-8 items-start">
            <div className="w-12 h-12 rounded-2xl bg-brand2-500 text-black flex items-center justify-center font-black text-lg shrink-0 shadow-lg shadow-brand2-500/20">
              05
            </div>
            <div className="space-y-5 flex-1">
              <div className="space-y-1">
                <h2 className="text-xl font-black text-brand2-400 uppercase tracking-wide">Báo cáo trên ShieldCall VN</h2>
                <p className="text-xs font-bold text-white/55 uppercase tracking-widest">
                  Chia sẻ trải nghiệm để bảo vệ người khác khỏi kịch bản tương tự
                </p>
              </div>
              <Link
                href="/report/"
                className="liquid-btn inline-flex py-4 px-10 bg-danger-500 text-black font-black uppercase text-xs tracking-widest shadow-xl shadow-danger-500/20 hover:bg-danger-400 transition-all"
              >
                <i className="bi bi-flag-fill mr-2"></i> Gửi Báo Cáo Ngay
              </Link>

            </div>
          </div>
        </div>

        <div
          ref={chatCardRef}
          className="liquid-card p-0 border-l-8 border-brand-500 bg-brand-500/[0.02] overflow-hidden"
        >
          <div className="flex flex-col sm:flex-row gap-8 items-start p-8 pb-0">
            <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-brand-500 to-brand2-500 text-black flex items-center justify-center font-black text-lg shrink-0 shadow-lg shadow-brand-500/20">
              <i className="bi bi-robot"></i>
            </div>
            <div className="space-y-2 flex-1">
              <h2 className="text-xl font-black text-brand-400 uppercase tracking-wide">Trò chuyện với AI hỗ trợ</h2>
              <p className="text-xs font-bold text-white/55 uppercase tracking-widest">
                Mô tả tình huống để nhận hướng dẫn xử lý chi tiết từ ShieldCall AI
              </p>
            </div>
          </div>

          <div className="flex flex-wrap gap-2 px-8 pt-5 pb-3">
            {QUICK_PROMPTS.map((q) => (
              <button
                key={q.label}
                type="button"
                onClick={() => void send(q.text)}
                className={`px-3 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest border transition-all ${q.cls}`}
              >
                <i className={`bi ${q.icon} mr-1`}></i> {q.label}
              </button>
            ))}
          </div>

          <div ref={msgBoxRef} className="emg-chat-window overflow-y-auto px-8 py-4 space-y-4 scroll-smooth bg-black/10 emg-scroll">
            {messages.map((msg, i) =>
              msg.fromUser ? (
                <div key={i} className="flex justify-end">
                  <div className="max-w-[80%]">
                    <div className="bg-gradient-to-br from-brand-500/20 to-brand2-500/20 border border-brand-500/20 rounded-2xl rounded-br-none p-4 emg-chat-bubble">
                      <div className="text-xs sm:text-[13px] leading-relaxed text-white/90">{msg.text}</div>
                    </div>
                    <div className="text-[9px] text-white/35 mt-1 font-bold text-right">{msg.time}</div>
                  </div>
                </div>
              ) : (
                <div key={i} className="flex justify-start">
                  <div className="flex items-start gap-3 max-w-[90%]">
                    <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-brand-500 to-brand2-500 flex items-center justify-center shrink-0 shadow-md">
                      <i className="bi bi-robot text-black text-sm"></i>
                    </div>
                    <div className="flex-1">
                      {(msg.isThinking || msg.thinkingContent) && (
                        <div className="mb-2 p-3 rounded-xl bg-brand-500/5 border border-brand-500/10">
                          <div
                            className="flex items-center gap-2 cursor-pointer"
                            onClick={() =>
                              setMessages((prev) =>
                                prev.map((m, j) => (j === i ? { ...m, thinkingCollapsed: !m.thinkingCollapsed } : m)),
                              )
                            }
                          >
                            <i
                              className={`bi text-[10px] ${msg.isThinking ? 'bi-lightning-charge-fill animate-pulse text-brand-400' : msg.thinkingCollapsed ? 'bi-chevron-right text-white/55' : 'bi-chevron-down text-white/55'}`}
                            ></i>
                            <span
                              className={`text-[9px] font-black uppercase tracking-widest ${msg.isThinking ? 'text-brand-400' : 'text-white/55'}`}
                            >
                              {msg.isThinking ? 'Đang suy luận...' : 'Quá trình suy luận'}
                            </span>
                          </div>
                          {!msg.thinkingCollapsed && (
                            <div className="mt-2 text-[11px] text-white/45 leading-relaxed whitespace-pre-wrap">
                              {msg.thinkingContent}
                            </div>
                          )}
                        </div>
                      )}
                      {msg.status && (
                        <div className="mb-1">
                          <span className="text-[9px] font-black uppercase tracking-widest text-brand-400 animate-pulse">
                            {msg.status}
                          </span>
                        </div>
                      )}
                      <div className="bg-white/5 border border-white/10 rounded-2xl rounded-bl-none p-4 emg-chat-bubble">
                        <div className="text-xs sm:text-[13px] leading-relaxed text-white/80 ai-markdown">
                          <MarkdownView html={msg.html || msg.text} />
                        </div>
                        {msg.streaming && <span className="streaming-cursor"></span>}
                      </div>
                      <div className="text-[9px] text-white/35 mt-1 font-bold">{msg.time}</div>
                    </div>
                  </div>
                </div>
              ),
            )}

            {typing && (
              <div className="flex items-start gap-3">
                <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-brand-500 to-brand2-500 flex items-center justify-center shrink-0">
                  <i className="bi bi-robot text-black text-sm"></i>
                </div>
                <div className="bg-white/5 border border-white/10 rounded-2xl rounded-bl-none px-5 py-3">
                  <div className="flex gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-brand-400/60 animate-bounce" style={{ animationDelay: '0ms' }}></span>
                    <span className="w-2 h-2 rounded-full bg-brand-400/60 animate-bounce" style={{ animationDelay: '150ms' }}></span>
                    <span className="w-2 h-2 rounded-full bg-brand-400/60 animate-bounce" style={{ animationDelay: '300ms' }}></span>
                  </div>
                </div>
              </div>
            )}
          </div>

          <div className="p-4 border-t border-white/5 bg-black/20">
            <form onSubmit={onSubmit} className="flex items-center gap-3">
              <input
                ref={inputRef}
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                disabled={typing}
                placeholder="Mô tả tình huống khẩn cấp của bạn..."
                className="flex-1 px-5 py-3.5 text-sm font-medium bg-white/[0.03] border border-white/10 rounded-2xl focus:border-brand-500/40 focus:bg-white/[0.05] transition-all placeholder:text-white/35 disabled:opacity-50"
              />
              <button
                type="submit"
                disabled={typing || !input.trim()}
                className="w-12 h-12 rounded-2xl bg-gradient-to-br from-brand-500 to-brand2-500 flex items-center justify-center text-black font-bold shadow-lg shadow-brand-500/20 hover:scale-105 transition-all disabled:opacity-30 disabled:hover:scale-100 shrink-0"
              >
                <i className="bi bi-send-fill"></i>
              </button>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
}
