'use client';
/* Khung "nhắn tin" riêng cho người cao tuổi.
 *
 * Vì sao không dùng lại ChatWidget toàn cục: widget đó chữ nhỏ, dày đặc chi
 * tiết (nguồn, trạng thái, nút nhỏ) — không phù hợp người cao tuổi. Ở đây chỉ
 * có: câu hỏi gợi ý bấm là gửi, một ô nhập to, câu trả lời chữ to, và nút đọc to.
 *
 * Dùng đúng endpoint của hệ thống: POST {apiBase}/chat/stream/ (AllowAny, không
 * cần đăng nhập) với giao thức SSE đã chuẩn hoá ở lib/chat/stream.ts.
 * Chia sẻ `localStorage['chat_session_id']` với widget toàn cục để nối tiếp
 * mạch trò chuyện nếu bác đã hỏi ở chỗ khác.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import { apiBase } from '../../components/ScanWidgets';
import { MarkdownView } from '../../components/ui';
import { renderMd } from '../../lib/chat/markdown';
import { openSseStream } from '../../lib/chat/stream';
import type { StreamEvent } from '../../lib/chat/stream';

interface Msg {
  from: 'user' | 'bot';
  text: string;
}

/* Gửi kèm trong `scan_context`: backend chèn thành system message (KHÔNG lưu vào
 * lịch sử trò chuyện), nên không làm bẩn nội dung bác đã gửi. */
const TONE_HINT =
  'Hướng dẫn cách trả lời cho lượt này: người hỏi là NGƯỜI CAO TUỔI Việt Nam. '
  + 'Hãy xưng "cháu" và gọi người hỏi là "bác". Trả lời thật ngắn, tối đa 4-5 câu, '
  + 'câu đơn giản, tránh thuật ngữ kỹ thuật; nếu buộc phải dùng thì giải thích ngay trong ngoặc. '
  + 'Nêu việc cần làm theo thứ tự 1, 2, 3. Không hù dọa. Khi việc quan trọng, nhắc bác gọi số chính thức '
  + '(156 để báo lừa đảo, 113 khi khẩn cấp) hoặc nhờ con cháu kiểm tra cùng.';

const GREETING =
  'Cháu chào bác. Bác bấm vào một câu hỏi gợi ý bên dưới, hoặc tự viết câu hỏi vào ô — cháu trả lời ngay ạ.';

/* Câu hỏi gợi ý phải TỰ ĐỦ thông tin — nếu hỏi kiểu "số này có lừa đảo không?"
 * thì trợ lý sẽ phải hỏi lại số điện thoại, thành ngõ cụt với người cao tuổi.
 * Viết theo giọng của chính bác (dùng "tôi"), phần xưng hô để trợ lý lo. */
const SUGGESTIONS = [
  'Có người gọi tự xưng là công an và đòi tôi chuyển tiền, tôi phải làm gì?',
  'Có người hỏi xin mã OTP của tôi, tôi có nên cho không?',
  'Tôi nhận được tin nhắn báo trúng thưởng, có phải lừa đảo không?',
];

/** Chuyển câu trả lời thành CHỮ TRƠN — CHỈ dùng cho nút "Đọc to": trình đọc
 *  không được đọc tên thẻ HTML/markdown. Phần HIỂN THỊ thì render markdown đầy đủ
 *  bằng renderMd() + MarkdownView (đã sanitize chống XSS) như các trang khác. */
function toSpeechText(md: string): string {
  let t = String(md || '');
  // 1) HTML: thẻ xuống dòng → '\n', gạch đầu dòng → '• ', rồi bỏ mọi thẻ còn lại
  t = t.replace(/<br\s*\/?>/gi, '\n');
  t = t.replace(/<\/(p|div|li|h[1-6]|tr|ul|ol|blockquote|section)>/gi, '\n');
  t = t.replace(/<li[^>]*>/gi, '• ');
  t = t.replace(/<[^>]+>/g, '');
  // 2) Thực thể HTML
  t = t
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#0?39;/g, "'")
    .replace(/&hellip;/gi, '…');
  // 3) Markdown
  t = t
    .replace(/```[a-zA-Z]*\n?/g, '')
    .replace(/`([^`]*)`/g, '$1')
    .replace(/!\[[^\]]*\]\([^)]*\)/g, '')
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/^\s{0,3}#{1,6}\s*/gm, '')
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/(^|\s)\*([^*]+)\*/g, '$1$2')
    .replace(/^\s*[-*+]\s+/gm, '• ')
    .replace(/^\s*>\s?/gm, '');
  // 4) Gọn khoảng trắng
  return t.replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
}

function BotBubble({ text, canSpeak, speak }: { text: string; canSpeak: boolean; speak: (t: string) => void }) {
  const bodyRef = useRef<HTMLDivElement>(null);
  const [overflowing, setOverflowing] = useState(false);
  const [open, setOpen] = useState(false);

  const html = useMemo(() => renderMd(text), [text]);
  const speech = useMemo(() => toSpeechText(text), [text]);

  /* Đo sau khi render: chỉ khi nội dung vượt mức thu gọn mới hiện nút mở rộng.
   * Thu gọn bằng max-height (CSS) chứ KHÔNG cắt chuỗi — cắt chuỗi sẽ làm vỡ HTML. */
  useEffect(() => {
    const el = bodyRef.current;
    if (!el || open) return;
    setOverflowing(el.scrollHeight > el.clientHeight + 8);
  }, [html, open]);

  return (
    <div className="elder-card space-y-3">
      <p className="elder-note">
        <i className="bi bi-robot" aria-hidden="true"></i> Cháu trả lời
      </p>

      <div ref={bodyRef} className={open ? '' : 'elder-md--clamp'}>
        <MarkdownView html={html} />
      </div>

      {overflowing && !open && (
        <button type="button" className="elder-btn w-full" onClick={() => setOpen(true)}>
          <i className="bi bi-chevron-down elder-icon" aria-hidden="true"></i> Bác bấm để xem phần còn lại
        </button>
      )}

      {canSpeak && speech && (
        <button type="button" className="elder-btn w-full" onClick={() => speak(speech)}>
          <i className="bi bi-volume-up-fill elder-icon" aria-hidden="true"></i> Đọc to câu trả lời
        </button>
      )}
    </div>
  );
}

export default function ElderChat({
  canSpeak,
  speak,
  seed,
}: {
  canSpeak: boolean;
  speak: (t: string) => void;
  /** Câu hỏi mồi từ nơi khác trong trang (kèm số lần để gửi lại được nhiều lần). */
  seed: { text: string; n: number };
}) {
  const [messages, setMessages] = useState<Msg[]>([{ from: 'bot', text: GREETING }]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [waiting, setWaiting] = useState(false);
  const [error, setError] = useState('');

  const abortRef = useRef<AbortController | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const lastSeed = useRef(0);

  /* Câu trả lời mới thì cuộn xuống cuối khung chat. */
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ block: 'nearest' });
  }, [messages, waiting]);

  useEffect(() => () => abortRef.current?.abort(), []);

  const appendToLastBot = useCallback((chunk: string) => {
    setMessages((prev) => {
      const next = [...prev];
      const last = next[next.length - 1];
      if (last && last.from === 'bot') next[next.length - 1] = { ...last, text: last.text + chunk };
      return next;
    });
  }, []);

  const send = useCallback(
    async (raw?: string) => {
      const text = (raw ?? input).trim();
      if (!text || busy) return;

      setError('');
      setInput('');
      setMessages((prev) => [...prev, { from: 'user', text }, { from: 'bot', text: '' }]);
      setBusy(true);
      setWaiting(true);

      const ac = new AbortController();
      abortRef.current = ac;

      let sid = '';
      try {
        sid = localStorage.getItem('chat_session_id') || '';
      } catch {
        /* bỏ qua */
      }
      if (!sid) {
        try {
          sid = crypto.randomUUID();
        } catch {
          sid = '';
        }
      }

      let gotText = false;
      try {
        await openSseStream({
          url: `${apiBase()}/chat/stream/`,
          signal: ac.signal,
          body: {
            user_message: text,
            session_id: sid,
            context: 'chat',
            images: [],
            scan_context: TONE_HINT,
            safe_mode: false,
          },
          onEvent: (ev: StreamEvent) => {
            if (ev.type === 'delta' && ev.text) {
              gotText = true;
              setWaiting(false);
              appendToLastBot(ev.text);
            } else if (ev.type === 'error') {
              appendToLastBot(`\n(Cháu gặp trục trặc: ${ev.message})`);
              setWaiting(false);
            } else if (ev.type === 'done') {
              try {
                if (ev.session_id) localStorage.setItem('chat_session_id', ev.session_id);
              } catch {
                /* bỏ qua */
              }
            }
          },
        });
      } catch {
        appendToLastBot(
          gotText
            ? '\n(Cháu bị ngắt giữa chừng. Bác hỏi lại giúp cháu nhé.)'
            : 'Cháu chưa trả lời được. Bác kiểm tra mạng rồi hỏi lại giúp cháu nhé.',
        );
        setError('Chưa gửi được câu hỏi. Bác kiểm tra mạng rồi bấm GỬI lại nhé.');
      } finally {
        setBusy(false);
        setWaiting(false);
        abortRef.current = null;
      }
    },
    [appendToLastBot, busy, input],
  );

  /* Nhận câu hỏi mồi (ví dụ từ nút "Hỏi trợ lý ảo" ở phần kết quả kiểm tra). */
  useEffect(() => {
    if (seed.n > lastSeed.current) {
      lastSeed.current = seed.n;
      if (seed.text) {
        setInput(seed.text);
        inputRef.current?.focus();
      }
    }
  }, [seed]);

  return (
    <section className="space-y-5" aria-labelledby="elder-chat">
      <h2 id="elder-chat" className="elder-h2">
        <i className="bi bi-chat-dots-fill elder-h-icon text-brand-300" aria-hidden="true"></i>
        Nhắn tin hỏi cháu
      </h2>

      <p className="elder-lead">
        Bác viết câu hỏi như nói chuyện bình thường, ví dụ: &quot;Số 0987… có phải lừa đảo không?&quot;. Cháu là trợ lý
        ảo trả lời tự động, câu trả lời có thể sai — việc quan trọng bác hãy kiểm tra qua số chính thức.
      </p>

      {/* Câu hỏi gợi ý: bấm một lần là gửi luôn, không phải gõ */}
      <div className="space-y-3">
        <p className="elder-h3">Bác không biết viết gì thì bấm vào đây:</p>
        <div className="flex flex-col gap-3">
          {SUGGESTIONS.map((s) => (
            <button
              key={s}
              type="button"
              className="elder-btn elder-btn--choice w-full"
              disabled={busy}
              onClick={() => void send(s)}
            >
              <i className="bi bi-question-circle-fill elder-icon text-brand-300" aria-hidden="true"></i>
              <span className="min-w-0 flex-1 text-left">{s}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Khung trò chuyện */}
      {/* Đang stream thì tắt aria-live để trình đọc màn hình không đọc từng mẩu
          chữ; trả lời xong mới đọc một lần. */}
      <div className="space-y-3" role="log" aria-live={busy ? 'off' : 'polite'} aria-label="Nội dung trò chuyện">
        {messages.map((m, i) =>
          m.from === 'user' ? (
            <div key={i} className="elder-card space-y-2 border-brand-500/30 bg-brand-500/10">
              <p className="elder-note">
                <i className="bi bi-person-fill" aria-hidden="true"></i> Bác hỏi
              </p>
              <p className="elder-body whitespace-pre-wrap break-words font-semibold">{m.text}</p>
            </div>
          ) : m.text ? (
            <BotBubble key={i} text={m.text} canSpeak={canSpeak} speak={speak} />
          ) : (
            <div key={i} className="elder-card flex items-center gap-3">
              <i className="bi bi-hourglass-split elder-icon animate-pulse text-brand-300" aria-hidden="true"></i>
              <p className="elder-body font-semibold">Cháu đang viết câu trả lời… bác chờ chút ạ.</p>
            </div>
          ),
        )}
        <div ref={bottomRef} />
      </div>

      {error && (
        <p className="elder-error">
          <i className="bi bi-exclamation-triangle-fill elder-icon" aria-hidden="true"></i>
          <span>{error}</span>
        </p>
      )}

      {/* Ô nhập + nút gửi, đều to */}
      <form
        className="elder-card space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          void send();
        }}
      >
        <label className="elder-label" htmlFor="elder-chat-input">
          Câu hỏi của bác
        </label>
        <input
          id="elder-chat-input"
          ref={inputRef}
          type="text"
          className="elder-input"
          placeholder="Ví dụ: Số này có phải lừa đảo không?"
          value={input}
          disabled={busy}
          onChange={(e) => setInput(e.target.value)}
          aria-describedby="elder-chat-hint"
        />
        <p id="elder-chat-hint" className="elder-note">
          Bác bấm nút bên dưới để gửi. Không cần đăng nhập.
        </p>

        <button type="submit" className="elder-btn elder-btn--xl elder-btn--brand" disabled={busy || !input.trim()}>
          {busy || waiting ? (
            <>
              <i className="bi bi-hourglass-split elder-icon" aria-hidden="true"></i> Cháu đang trả lời…
            </>
          ) : (
            <>
              <i className="bi bi-send-fill elder-icon" aria-hidden="true"></i> GỬI CÂU HỎI
            </>
          )}
        </button>
      </form>

      <p className="elder-note">
        Trợ lý ảo trả lời tự động nên có thể sai. Bác đừng gửi mật khẩu, mã OTP hay số thẻ cho bất kỳ ai, kể cả cháu.
      </p>
    </section>
  );
}
