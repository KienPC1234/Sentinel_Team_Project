'use client';
import { useCallback, useEffect, useRef, useState } from 'react';
import { renderMd, safeUrl } from '../lib/chat/markdown';
import { StreamHttpError, openSseStream } from '../lib/chat/stream';
import { MarkdownView } from './ui';
import { ChatGuardrailNote, type GuardrailData } from './ScanWidgets';
import { showToast } from '../lib/ui/feedback';

/* Port đầy đủ từ PKV/templates/ai_chat/chat_widget_inline.html + PKV/static/js/chat/widget.js
 * (Alpine x-data="chatWidget()" -> React useState). Floating widget, tự quản open/state.
 */
interface SrcItem { title?: string; url?: string; }
interface WMeta { web_search?: SrcItem[] | null; internal_knowledge?: SrcItem[] | null; guardrail?: GuardrailData | null; }
interface WMsg {
  from: 'bot' | 'user';
  text: string;
  html: string;
  time: string;
  status?: string;
  thinking?: string;
  isThinking?: boolean;
  thinkingOpen?: boolean;
  streaming?: boolean;
  isSafe?: boolean;
  metadata?: WMeta | null;
}

const now = (): string => new Date().toLocaleTimeString('vi', { hour: '2-digit', minute: '2-digit' });
const GREETING =
  'Xin chào! <i class="bi bi-shield-check"></i> Tôi là **ShieldCall AI**. Hãy gửi số điện thoại hoặc tin nhắn lạ để tôi kiểm tra giúp bạn!\n\nNếu bạn đang gặp sự cố về **an toàn số hoặc bạo lực mạng**, hãy nhấn nút bên dưới để chuyển sang chế độ **SafeTalk**.';
const RESET_GREETING =
  'Xin chào! <i class="bi bi-shield-check"></i> Tôi là **ShieldCall AI**. Hãy gửi số điện thoại hoặc tin nhắn lạ để tôi kiểm tra giúp bạn!';
const FAIRSPACE_GREETING =
  'Chào mừng bạn đến với **FairSpace**. <i class="bi bi-heart-fill text-brand2-400"></i> Tôi là trợ lý thấu cảm, luôn sẵn sàng đồng hành cùng bạn trên không gian mạng.\n\nĐừng ngần ngại chia sẻ nếu bạn đang gặp tình huống quấy rối hoặc định kiến giới nhé.';

const STATUS_MAP: Record<string, string> = {
  searching_knowledge: 'Đang tra cứu kiến thức...',
  searching_web: 'Đang tìm kiếm thông tin...',
  checking_safety: 'Đang kiểm tra an toàn...',
  reasoning: 'Đang suy luận...',
  thinking: 'Đang suy luận...',
  answering: 'Đang trả lời...',
};

function botGreeting(text: string, isSafe = false): WMsg {
  return { from: 'bot', text, html: renderMd(text), time: now(), isSafe };
}

export default function ChatWidget() {
  const [open, setOpen] = useState(false);
  const [interacted, setInteracted] = useState(false);
  const [input, setInput] = useState('');
  const [chatTitle, setChatTitle] = useState('ShieldCall AI');
  const [typing, setTyping] = useState(false);
  const [previews, setPreviews] = useState<string[]>([]);
  const [safeMode, setSafeMode] = useState(false);
  const [messages, setMessages] = useState<WMsg[]>([botGreeting(GREETING)]);
  const [expandedSrc, setExpandedSrc] = useState<Record<number, boolean>>({});
  const abortRef = useRef<AbortController | null>(null);
  const boxRef = useRef<HTMLDivElement | null>(null);
  const rootRef = useRef<HTMLDivElement | null>(null);
  const lastScrollRef = useRef(0);

  const scrollDown = useCallback(() => {
    const t = Date.now();
    if (t - lastScrollRef.current < 150) return;
    lastScrollRef.current = t;
    const el = boxRef.current;
    if (el) el.scrollTo({ top: el.scrollHeight, behavior: 'smooth' });
  }, []);

  useEffect(() => {
    if (window.location.href.toLowerCase().includes('fairspace')) {
      setSafeMode(true);
      setChatTitle('FairSpace AI');
      setMessages([botGreeting(FAIRSPACE_GREETING)]);
    }
  }, []);

  // Click ngoài panel -> đóng (port @click.outside). Chỉ gắn khi đang mở.
  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open]);

  useEffect(() => { scrollDown(); }, [messages, open, scrollDown]);

  // Cho trang scan gọi: window.dispatchEvent(new CustomEvent('start-contextual-chat', {detail:{context}}))
  useEffect(() => {
    const h = (e: Event) => {
      const detail = (e as CustomEvent<{ context?: string }>).detail;
      setOpen(true);
      setInteracted(true);
      if (detail?.context) sessionStorage.setItem('sc_widget_scan_ctx', detail.context);
      const t = '<i class="bi bi-info-circle text-brand-400"></i> **Đã nhận ngữ cảnh scan.** Tôi đã sẵn sàng phân tích kết quả cùng bạn.';
      setMessages((m) => [...m, botGreeting(t)]);
      setInput('Hãy giải thích thêm về kết quả này.');
    };
    window.addEventListener('start-contextual-chat', h);
    return () => window.removeEventListener('start-contextual-chat', h);
  }, []);

  const botStatus = messages.length > 0 && messages[messages.length - 1].status
    ? messages[messages.length - 1].status
    : safeMode ? 'Trợ lý An toàn' : 'Trực tuyến';

  const resetChat = () => {
    abortRef.current?.abort();
    setTyping(false);
    try { localStorage.removeItem('chat_session_id'); } catch { /* ignore */ }
    setSafeMode(false);
    setMessages([botGreeting(RESET_GREETING)]);
    setInteracted(false);
    setInput('');
    setPreviews([]);
    setExpandedSrc({});
    showToast('Đã bắt đầu cuộc trò chuyện mới', 'success');
  };

  const toggleSafe = () => {
    const next = !safeMode;
    setSafeMode(next);
    if (next) {
      const t = '🛡️ **Đã kích hoạt chế độ SafeTalk.**\n\nTôi ở đây để lắng nghe và giúp bạn xử lý các tình huống quấy rối, bạo lực mạng hoặc bạo lực giới. Bạn có ổn không? Hãy chia sẻ với tôi nhé.';
      setMessages((m) => [...m, botGreeting(t, true)]);
      showToast('Đã chuyển sang chế độ SafeTalk', 'info');
    } else {
      showToast('Đã quay lại chế độ ShieldCall', 'info');
    }
    scrollDown();
  };

  const onFiles = (files: FileList | null) => {
    if (!files) return;
    Array.from(files).forEach((f) => {
      if (f.size > 5 * 1024 * 1024) {
        showToast(`File ${f.name} quá lớn (max 5MB)`, 'warning');
        return;
      }
      const r = new FileReader();
      r.onload = (e) => setPreviews((p) => [...p, String(e.target?.result)]);
      r.readAsDataURL(f);
    });
  };

  const sendQuick = (t: string) => {
    if (typing) {
      showToast('AI đang trả lời, vui lòng đợi', 'info');
      return;
    }
    setInput(t);
    setTimeout(() => { void doSend(t); }, 0);
  };

  const doSend = async (preset?: string) => {
    const text = (preset ?? input).trim();
    if ((!text && previews.length === 0) || typing) return;
    setInteracted(true);
    const display = text || `Đã gửi ${previews.length} ảnh`;
    setMessages((m) => [...m, { from: 'user', text: display, html: renderMd(display), time: now() }]);
    const imgs = [...previews];
    const payloadText = text || 'Hãy phân tích các hình ảnh tôi vừa gửi.';
    setInput(''); setPreviews([]);
    setTyping(true);
    let sid: string | null = null;
    try { sid = localStorage.getItem('chat_session_id'); } catch { /* ignore */ }
    if (!sid) sid = window.crypto?.randomUUID ? window.crypto.randomUUID() : Math.random().toString(36).substring(2);
    const botIdx = { i: -1 };
    setMessages((m) => {
      botIdx.i = m.length;
      return [...m, { from: 'bot', text: '', html: '', time: now(), status: '', streaming: true, isThinking: false, thinkingOpen: true, isSafe: safeMode }];
    });
    const patch = (fn: (x: WMsg) => WMsg) => setMessages((m) => m.map((x, i) => (i === botIdx.i ? fn(x) : x)));
    let full = '';
    let think = '';
    const applyStatus = (v: string) => {
      patch((x) => ({
        ...x,
        status: STATUS_MAP[v] || v,
        isThinking: v === 'thinking' || v === 'reasoning' ? true : (v === 'answering' ? false : x.isThinking),
        thinkingOpen: v === 'thinking' || v === 'reasoning' ? true : (v === 'answering' ? false : x.thinkingOpen),
      }));
    };
    try {
      const ctrl = new AbortController();
      abortRef.current = ctrl;
      const scanCtx = sessionStorage.getItem('sc_widget_scan_ctx') || undefined;
      await openSseStream({
        url: '/api/v1/chat/stream/',
        signal: ctrl.signal,
        body: { user_message: payloadText, session_id: sid, context: 'chat', images: imgs, scan_context: scanCtx, safe_mode: safeMode },
        onEvent: (ev) => {
          switch (ev.type) {
            case 'delta': {
              if (!ev.text) break;
              full += ev.text;
              const snap = full;
              patch((x) => ({ ...x, text: snap, html: renderMd(snap) }));
              break;
            }
            case 'thinking':
              think += ev.text;
              { const tt = think; patch((x) => ({ ...x, thinking: tt, isThinking: true, thinkingOpen: true })); }
              break;
            case 'status':
              applyStatus(ev.value);
              break;
            case 'metadata': {
              const md = ev.metadata as WMeta;
              patch((x) => ({
                ...x,
                metadata: {
                  ...(x.metadata || {}),
                  web_search: (md.web_search as SrcItem[] | undefined) ?? (x.metadata?.web_search || null),
                  internal_knowledge: (md.internal_knowledge as SrcItem[] | undefined) ?? (x.metadata?.internal_knowledge || null),
                },
              }));
              break;
            }
            case 'guardrail':
              patch((x) => ({ ...x, metadata: { ...(x.metadata || {}), guardrail: (ev.guardrail as GuardrailData) } }));
              break;
            case 'title':
              if (ev.value && ev.value !== 'Guest Session') setChatTitle(ev.value);
              break;
            case 'error':
              patch((x) => ({ ...x, text: ev.message, html: renderMd(ev.message), streaming: false }));
              break;
            case 'done': {
              const nsid = ev.session_id;
              if (nsid) { try { localStorage.setItem('chat_session_id', String(nsid)); } catch { /* ignore */ } }
              if (ev.title && ev.title !== 'Guest Session') setChatTitle(ev.title);
              patch((x) => ({ ...x, status: '', streaming: false, isThinking: false, thinkingOpen: false }));
              break;
            }
            default:
              break;
          }
        },
      });
      sessionStorage.removeItem('sc_widget_scan_ctx');
    } catch (e) {
      if ((e as Error).name !== 'AbortError') {
        const msg = e instanceof StreamHttpError ? `Lỗi kết nối (HTTP ${e.status})` : 'Lỗi kết nối mạng.';
        patch((x) => ({ ...x, text: msg, html: msg, streaming: false }));
      }
    } finally {
      abortRef.current = null;
      setTyping(false);
      patch((x) => ({ ...x, status: '', streaming: false, isThinking: false }));
      scrollDown();
    }
  };

  return (
    <div ref={rootRef} className="sc-chat-widget fixed bottom-6 right-6 z-[100] flex flex-col items-end gap-4">
      <button
        onClick={() => setOpen(!open)}
        className="transition-all duration-300 hover:scale-110 hover:rotate-[5deg]"
        style={{ width: 56, height: 56, borderRadius: '50%', background: 'linear-gradient(135deg,var(--accent-cyan),var(--accent-purple))', border: '1px solid rgba(255,255,255,0.35)', cursor: 'pointer', boxShadow: '0 6px 16px rgba(0,0,0,0.45), 0 0 14px rgba(24,255,255,0.25)', display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative', transition: 'transform 0.2s ease' }}
        aria-label="Chat"
      >
        {open ? <i className="bi bi-x-lg text-[var(--sc-ink-deep)] text-xl font-black"></i> : <i className="bi bi-chat-dots text-[var(--sc-ink-deep)] text-2xl"></i>}
        {!open && !interacted && (
          <span
            className="animate-pulse-red"
            style={{ position: 'absolute', top: -2, right: -2, width: 12, height: 12, background: 'var(--risk-red)', borderRadius: '50%', border: '2px solid var(--sc-ink-deep)' }}
          />
        )}
      </button>
      {open && (
        <div style={{ position: 'absolute', bottom: 70, right: 0, width: 380, maxWidth: 'calc(100vw - 3rem)', maxHeight: 580, borderRadius: '1.5rem', overflow: 'hidden' }} className="liquid-glass bg-[var(--sc-night-1)]/90 border border-white/10 shadow-2xl sc-pop-in">
          <div style={{ padding: '1.15rem 1.25rem', background: 'var(--subtle-bg)', borderBottom: '1px solid var(--subtle-border)', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div style={safeMode ? { width: 38, height: 38, borderRadius: 12, background: 'linear-gradient(135deg,var(--sc-brand2-500),var(--sc-brand2-500))', display: 'flex', alignItems: 'center', justifyContent: 'center' } : { width: 38, height: 38, borderRadius: 12, background: 'linear-gradient(135deg,var(--accent-cyan),var(--accent-purple))', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <i className={safeMode ? 'bi bi-heart-fill text-[var(--sc-ink-deep)] text-lg' : 'bi bi-robot text-[var(--sc-ink-deep)] text-lg'}></i>
            </div>
            <div className="flex-1">
              <div key={safeMode ? 'safetalk' : chatTitle} className="title-reveal" style={{ fontWeight: 800, fontSize: '0.95rem', color: 'var(--text-primary)' }}>{safeMode ? 'SafeTalk AI' : chatTitle}</div>
              <div style={{ fontSize: '0.65rem', color: 'var(--accent-cyan)', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 4 }}>
                <span className={safeMode ? 'bg-brand2-400 w-1.5 h-1.5 rounded-full' : 'bg-brand-400 w-1.5 h-1.5 rounded-full'}></span><span>{botStatus}</span>
              </div>
            </div>
            <button onClick={resetChat} className="text-white/35 hover:text-brand-400 transition-colors mr-2" title="Cuộc trò chuyện mới"><i className="bi bi-plus-square"></i></button>
            <button onClick={() => setOpen(false)} className="text-white/35 hover:text-white transition-colors"><i className="bi bi-dash-lg"></i></button>
          </div>
          <div ref={boxRef} style={{ height: 340, overflowY: 'auto', padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem', background: 'rgba(0,0,0,0.15)', scrollBehavior: 'smooth' }}>
            {messages.map((msg, i) => (
              <div key={i} className={`flex flex-col gap-1 w-full ${msg.from === 'bot' ? 'items-start' : 'items-end'}`}>
                <div className={`max-w-[88%] border p-3.5 text-xs sm:text-[13px] leading-relaxed ${msg.from === 'bot' ? (msg.isSafe ? 'bg-brand2-500/10 border-brand2-500/20 rounded-2xl rounded-bl-none' : 'bg-white/5 border-white/10 rounded-2xl rounded-bl-none') : 'bg-gradient-to-br from-brand-500/20 to-brand2-500/20 border-brand-500/20 rounded-2xl rounded-br-none'}`}>
                  {msg.from === 'bot' && (msg.isThinking || msg.thinking) && (
                    <div className={`thinking-container ${msg.thinkingOpen === false ? 'collapsed' : ''}`}>
                      <div className="thinking-header" onClick={() => setMessages((m) => m.map((x, xi) => (xi === i ? { ...x, thinkingOpen: x.thinkingOpen === false } : x)))}>
                        <i className={`bi ${msg.isThinking ? 'bi-lightning-charge-fill animate-pulse text-brand-400' : 'bi-chevron-down text-white/55'} text-[10px]`}></i>
                        <span className={`text-[9px] font-black uppercase tracking-widest ${msg.isThinking ? 'text-brand-400' : 'text-white/55'}`}>{msg.isThinking ? 'Đang suy luận...' : 'Quá trình suy luận'}</span>
                      </div>
                      {msg.thinkingOpen !== false && <div className="thinking-content">{msg.thinking}</div>}
                    </div>
                  )}
                  <MarkdownView html={msg.html || msg.text} className="text-xs" />
                  {msg.streaming && <span className="streaming-cursor"></span>}
                  {msg.from === 'bot' && !msg.streaming && msg.metadata?.guardrail?.tier && (
                    <ChatGuardrailNote guardrail={msg.metadata.guardrail} />
                  )}
                  {msg.from === 'bot' && !msg.streaming && msg.metadata && ((msg.metadata.web_search || []).length + (msg.metadata.internal_knowledge || []).length > 0) && (
                    <div className="search-results-container mt-2">
                      <button
                        type="button"
                        onClick={() => setExpandedSrc((e) => ({ ...e, [i]: !e[i] }))}
                        className="w-full flex items-center justify-between text-left gap-2 py-1 select-none hover:opacity-90 transition-opacity"
                      >
                        <span className="flex items-center gap-2 min-w-0 flex-1">
                          <span className="w-5 h-5 rounded bg-brand-500/10 text-brand-400 flex items-center justify-center shrink-0 text-[11px] border border-brand-500/20">
                            <i className="bi bi-globe2"></i>
                          </span>
                          <span className="text-[10px] font-bold text-white/80 uppercase tracking-wider truncate">
                            Nguồn tham khảo
                          </span>
                          <span className="text-[9px] px-2 py-0.5 rounded-full bg-brand-500/15 text-brand-400 font-mono font-medium whitespace-nowrap shrink-0 border border-brand-500/30">
                            {(msg.metadata.internal_knowledge || []).length + (msg.metadata.web_search || []).length} nguồn
                          </span>
                        </span>
                        <span className="flex items-center gap-1 text-[10px] text-slate-400 hover:text-brand-400 transition-colors shrink-0 ml-2 whitespace-nowrap font-medium">
                          <span>{expandedSrc[i] ? 'Thu gọn' : 'Mở rộng'}</span>
                          <i className={`bi bi-chevron-down text-[9px] transition-transform duration-200 ${expandedSrc[i] ? 'rotate-180' : ''}`}></i>
                        </span>
                      </button>
                      {expandedSrc[i] && (
                        <div className="flex flex-col gap-1 mt-2 pt-2 border-t border-white/5">
                          {(msg.metadata.internal_knowledge || []).map((res, k) => (
                            <a key={`rag-${k}`} href={safeUrl(res.url)} target="_blank" rel="noopener noreferrer" className="search-item group">
                              <div className="flex items-center justify-between gap-2 overflow-hidden">
                                <div className="flex items-center gap-2 overflow-hidden">
                                  <div className="w-4 h-4 rounded bg-brand2-500/20 text-brand2-400 flex items-center justify-center shrink-0"><i className="bi bi-shield-check text-[10px]"></i></div>
                                  <div className="font-bold text-slate-200 truncate text-[11px] group-hover:text-brand2-400 transition-colors">{res.title}</div>
                                </div>
                                <i className="bi bi-arrow-up-right text-[8px] text-white/35 group-hover:text-white transition-colors"></i>
                              </div>
                            </a>
                          ))}
                          {(msg.metadata.web_search || []).map((res, k) => (
                            <a key={`web-${k}`} href={safeUrl(res.url)} target="_blank" rel="noopener noreferrer" className="search-item group">
                              <div className="flex items-center justify-between gap-2 overflow-hidden">
                                <div className="flex items-center gap-2 overflow-hidden">
                                  <div className="w-4 h-4 rounded bg-brand-500/20 text-brand-400 flex items-center justify-center shrink-0"><i className="bi bi-globe2 text-[10px]"></i></div>
                                  <div className="font-bold text-slate-200 truncate text-[11px] group-hover:text-brand-400 transition-colors">{res.title}</div>
                                </div>
                                <i className="bi bi-arrow-up-right text-[8px] text-white/35 group-hover:text-white transition-colors"></i>
                              </div>
                            </a>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
                <div className="text-[9px] text-white/35 px-1 font-bold tracking-tight uppercase">{msg.time}</div>
              </div>
            ))}
          </div>
          {messages.length <= 1 && (
            <div className="p-3 flex gap-2 overflow-x-auto bg-black/10 border-t border-white/5">
              <button onClick={toggleSafe} className={`flex-none border rounded-full px-3 py-1.5 text-[10px] font-bold transition-all ${safeMode ? 'bg-brand-500/10 border-brand-500/30 text-brand-400' : 'bg-brand2-500/10 border-brand2-500/30 text-brand2-400'}`}>
                <i className={safeMode ? 'bi bi-robot mr-1' : 'bi bi-heart-pulse-fill mr-1'}></i>{safeMode ? 'Về ShieldCall' : 'Bật SafeTalk'}
              </button>
              {!safeMode ? (
                <div className="flex gap-2">
                  <button onClick={() => sendQuick('Kiểm tra số điện thoại')} className="flex-none bg-white/5 hover:bg-brand-500/10 border border-white/10 hover:border-brand-500/30 rounded-full px-3 py-1.5 text-[10px] font-bold transition-all">Kiểm tra SĐT</button>
                  <button onClick={() => sendQuick('Cách nhận diện lừa đảo')} className="flex-none bg-white/5 hover:bg-brand2-500/10 border border-white/10 hover:border-brand2-500/30 rounded-full px-3 py-1.5 text-[10px] font-bold transition-all">Cách phòng tránh</button>
                </div>
              ) : (
                <div className="flex gap-2">
                  <button onClick={() => sendQuick('Tôi đang bị quấy rối, phải làm sao?')} className="flex-none bg-brand2-500/10 hover:bg-brand2-500/20 border border-brand2-500/30 rounded-full px-3 py-1.5 text-[10px] font-bold transition-all text-brand2-300">Cách xử lý quấy rối</button>
                  <button onClick={() => sendQuick('Tôi cần một người lắng nghe...')} className="flex-none bg-brand2-500/10 hover:bg-brand2-500/20 border border-brand2-500/30 rounded-full px-3 py-1.5 text-[10px] font-bold transition-all text-brand2-300">Cần sự lắng nghe</button>
                  <button onClick={() => sendQuick('Cung cấp cho tôi các hotline hỗ trợ khẩn cấp')} className="flex-none bg-danger-500/10 hover:bg-danger-500/20 border border-danger-500/30 rounded-full px-3 py-1.5 text-[10px] font-bold transition-all text-danger-300">Hotline hỗ trợ</button>
                </div>
              )}
            </div>
          )}
          {previews.length > 0 && (
            <div className="px-4 py-2 flex gap-2 bg-black/20 border-t border-white/5">
              {previews.map((img, idx) => (
                <div key={idx} className="relative w-12 h-12 rounded-lg overflow-hidden border border-white/20 group">
                  <img src={img} alt="" className="w-full h-full object-cover" />
                  <button onClick={() => setPreviews((p) => p.filter((_, x) => x !== idx))} className="absolute inset-0 bg-danger-500/60 opacity-0 group-hover:opacity-100 flex items-center justify-center text-white"><i className="bi bi-trash text-xs"></i></button>
                </div>
              ))}
            </div>
          )}
          <div className="p-4 bg-black/30 border-t border-white/10 flex gap-2 items-center">
            <label className="w-10 h-10 rounded-xl hover:bg-white/5 flex items-center justify-center text-white/55 hover:text-brand-400 transition-all cursor-pointer"><i className="bi bi-plus-circle text-lg"></i><input type="file" multiple accept="image/*" className="hidden" onChange={(e) => { onFiles(e.target.files); e.target.value = ''; }} /></label>
            <input value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') void doSend(); }} placeholder="Nhập câu hỏi..." className="flex-1 bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-[13px] text-white focus:outline-none focus:border-brand-500/50 placeholder:text-white/35" />
            <button onClick={() => void doSend()} disabled={(!input.trim() && previews.length === 0) || typing} className="w-10 h-10 rounded-xl bg-gradient-to-br from-brand-500 to-brand2-600 flex items-center justify-center shadow-lg disabled:opacity-30 disabled:grayscale hover:scale-105 active:scale-95 transition-all"><i className="bi bi-send-fill text-white text-sm"></i></button>
          </div>
        </div>
      )}
    </div>
  );
}
