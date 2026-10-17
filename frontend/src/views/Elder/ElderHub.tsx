'use client';
/* Trang /nguoi-cao-tuoi/ — Trợ giúp người cao tuổi.
 *
 * Ràng buộc thiết kế (theo năng lực thao tác thật của người cao tuổi):
 *  - Phân chia TAB rõ ràng: Kiểm tra an toàn, Học nhận biết (Learn), Hỏi đáp trợ lý AI, Khẩn cấp.
 *  - Tay run/đau khớp: nút cao ≥3em, khoảng cách rộng, không kéo/vuốt, không hover.
 *  - Mắt kém: chữ lớn, tương phản cao, không dùng chữ mờ cho phần quan trọng.
 *  - Trí nhớ/ xử lý chậm: một việc một lúc; trạng thái LUÔN hiện; lỗi hiện TẠI CHỖ.
 *  - Sợ làm sai: luôn giải thích từng bước.
 *  - Captcha là BẮT BUỘC: giải thích rõ ràng, KHÔNG hỏi thông tin cá nhân.
 */
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';

import { api } from '../../lib/api';
import { warmTts, playAudio, stopAudio, hasBrowserVoice } from '../../lib/tts';
import ElderChat from './ElderChat';
import ElderLearn from './ElderLearn';
import ElderEmergency from './ElderEmergency';
import {
  asArr,
  asStr,
  guardrailTone,
  resetTurnstile,
  showToast,
  TurnstileWidget,
} from '../../components/ScanWidgets';
import type { ScanResult } from '../../components/ScanWidgets';

/* ─────────────────────────── Kiểu & dữ liệu tĩnh ─────────────────────────── */

export type ElderTab = 'check' | 'learn' | 'chat' | 'emergency';
type CheckKind = 'phone' | 'message' | 'website' | 'bank';
type TextSize = 'normal' | 'large' | 'xlarge';
type Tone = 'danger' | 'warn' | 'safe' | 'neutral';

interface BankInfo {
  shortName: string;
  name: string;
  bin?: string;
}

const TEXT_SIZES: { id: TextSize; label: string }[] = [
  { id: 'normal', label: 'Vừa' },
  { id: 'large', label: 'Lớn' },
  { id: 'xlarge', label: 'Rất lớn' },
];

const TABS: { id: ElderTab; title: string; sub: string; icon: string; danger?: boolean }[] = [
  { id: 'check', title: 'Kiểm tra an toàn', sub: 'SĐT, tin nhắn, link, tài khoản', icon: 'bi-search' },
  { id: 'learn', title: 'Học nhận biết', sub: 'Dấu hiệu, tình huống, bài học', icon: 'bi-book-half' },
  { id: 'chat', title: 'Cháu hỗ trợ', sub: 'Hỏi đáp với trợ lý AI', icon: 'bi-chat-dots-fill' },
  { id: 'emergency', title: 'Khẩn cấp', sub: 'Gọi 113, 156, khóa tài khoản', icon: 'bi-lightning-charge-fill', danger: true },
];

const CHECKS: { id: CheckKind; label: string; icon: string; hint: string }[] = [
  { id: 'phone', label: 'Số điện thoại', icon: 'bi-telephone-fill', hint: 'Số gọi đến cho bác' },
  { id: 'message', label: 'Tin nhắn lạ', icon: 'bi-chat-left-text-fill', hint: 'Tin nhắn bác nhận được' },
  { id: 'website', label: 'Đường link', icon: 'bi-link-45deg', hint: 'Link trong tin nhắn' },
  { id: 'bank', label: 'Số tài khoản', icon: 'bi-credit-card-2-front-fill', hint: 'Số người ta gửi để bác chuyển tiền' },
];

const INTRO_SPEECH =
  'Bác cần kiểm tra hay tìm hiểu gì ạ? Cháu chia thành bốn phần: Kiểm tra an toàn, Học nhận biết lừa đảo, Hỏi đáp trợ lý, và Khẩn cấp. '
  + 'Bác bấm vào các ô lớn trên màn hình để chọn phần bác muốn dùng.';

const DISCLAIMER_FALLBACK =
  'Kết quả kiểm tra tự động chỉ để tham khảo, không thay thế kết luận của cơ quan chức năng. '
  + 'Việc quan trọng thì bác gọi số chính thức của ngân hàng hoặc công an để hỏi cho chắc.';

/* ────────────────────────────── Hàm hỗ trợ ────────────────────────────── */

const useIsoLayoutEffect = typeof window !== 'undefined' ? useLayoutEffect : useEffect;

function normalizePhone(raw: string): string {
  let v = raw.trim().replace(/[\s().-]/g, '');
  if (/^0\d{9,10}$/.test(v)) v = '+84' + v.slice(1);
  return /^(\+\d{8,15}|0\d{9,10})$/.test(v) ? v : '';
}

const POPULAR_BANKS = ['Vietcombank', 'Techcombank', 'MBBank', 'BIDV', 'VietinBank', 'ACB', 'Agribank'];

function BankPicker({
  banks,
  value,
  labelledBy,
  invalid,
  onPick,
}: {
  banks: BankInfo[];
  value: string;
  labelledBy: string;
  invalid?: boolean;
  onPick: (v: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState('');
  const [active, setActive] = useState(0);
  const btnRef = useRef<HTMLButtonElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const wrapRef = useRef<HTMLDivElement>(null);

  const norm = (s: string): string =>
    s
      .toLowerCase()
      .normalize('NFD')
      .replace(/[̀-ͯ]/g, '');
  const filtered = banks.filter((b) => {
    const needle = norm(q.trim());
    if (!needle) return true;
    return norm(`${b.shortName} ${b.name}`).includes(needle);
  });

  const selected = banks.find((b) => b.shortName === value);

  const close = useCallback(() => {
    setOpen(false);
    btnRef.current?.focus();
  }, []);

  useEffect(() => {
    if (!open) return;
    setQ('');
    setActive(0);
    searchRef.current?.focus();
    const onDown = (e: MouseEvent): void => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onDown);
    return () => document.removeEventListener('mousedown', onDown);
  }, [open]);

  const pick = useCallback(
    (v: string) => {
      onPick(v);
      setOpen(false);
      btnRef.current?.focus();
    },
    [onPick],
  );

  const onListKey = (e: React.KeyboardEvent): void => {
    if (e.key === 'Escape') {
      e.preventDefault();
      close();
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActive((a) => Math.min(filtered.length - 1, a + 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActive((a) => Math.max(0, a - 1));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const hit = filtered[active];
      if (hit) pick(hit.shortName);
    }
  };

  useEffect(() => {
    const el = document.getElementById(`elder-bank-opt-${active}`);
    el?.scrollIntoView({ block: 'nearest' });
  }, [active]);

  if (banks.length === 0) {
    return (
      <p className="elder-note">
        Chưa tải được danh sách đầy đủ (mạng yếu). Bác bấm tên ngân hàng phổ biến ở trên giúp cháu nhé.
      </p>
    );
  }

  return (
    <div ref={wrapRef}>
      <button
        ref={btnRef}
        type="button"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-labelledby={`${labelledBy} elder-bank-btn-label`}
        aria-invalid={invalid ? true : undefined}
        onClick={() => (open ? close() : setOpen(true))}
        className="elder-input flex items-center justify-between gap-3 text-left"
      >
        <span id="elder-bank-btn-label" className="min-w-0 flex-1 truncate">
          {selected ? `${selected.shortName} — ${selected.name}` : '— Bấm vào đây để mở danh sách ngân hàng —'}
        </span>
        <i className={`bi ${open ? 'bi-chevron-up' : 'bi-chevron-down'} elder-icon shrink-0`} aria-hidden="true"></i>
      </button>

      {open && (
        <div className="elder-card mt-3 space-y-3">
          <label className="elder-note" htmlFor="elder-bank-search">
            Bác gõ vài chữ để tìm cho nhanh (ví dụ: “vietcom”):
          </label>
          <input
            id="elder-bank-search"
            ref={searchRef}
            type="text"
            autoComplete="off"
            className="elder-input"
            placeholder="Gõ tên ngân hàng…"
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setActive(0);
            }}
            onKeyDown={onListKey}
          />
          <div
            role="listbox"
            aria-labelledby={labelledBy}
            tabIndex={-1}
            onKeyDown={onListKey}
            className="max-h-72 overflow-y-auto space-y-2 pr-1"
          >
            {filtered.length === 0 && (
              <p className="elder-note">Không thấy tên nào khớp. Bác thử gõ từ khác nhé.</p>
            )}
            {filtered.map((b, i) => {
              const isSel = b.shortName === value;
              const isActive = i === active;
              return (
                <button
                  id={`elder-bank-opt-${i}`}
                  key={b.bin || b.shortName}
                  type="button"
                  role="option"
                  aria-selected={isSel}
                  onClick={() => pick(b.shortName)}
                  onMouseEnter={() => setActive(i)}
                  className={`elder-btn elder-btn--choice w-full ${isActive ? 'elder-bank-opt--active' : ''}`}
                >
                  <span className="min-w-0 flex-1 text-left">
                    <span className="block font-bold">{b.shortName}</span>
                    <span className="block elder-note">{b.name}</span>
                  </span>
                  {isSel && <i className="bi bi-check-circle-fill elder-icon text-safe-300" aria-hidden="true"></i>}
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

interface EldVerdict {
  tone: Tone;
  label: string;
  plain: string;
  todos: string[];
  icon: string;
}

function verdictOf(tone: string): EldVerdict {
  if (tone === 'RED') {
    return {
      tone: 'danger',
      icon: 'bi-exclamation-octagon-fill',
      label: 'Nguy hiểm — đừng làm theo',
      plain: 'Số này, đường link này hoặc tài khoản này đã có người báo là lừa đảo.',
      todos: [
        'Không chuyển tiền cho số hay tài khoản này.',
        'Không đọc mã OTP, không đưa mật khẩu cho bất kỳ ai.',
        'Gọi ngay cho con cháu trong nhà để cùng xử lý.',
      ],
    };
  }
  if (tone === 'YELLOW') {
    return {
      tone: 'warn',
      icon: 'bi-exclamation-triangle-fill',
      label: 'Cẩn thận — có dấu hiệu lạ',
      plain: 'Có dấu hiệu đáng ngờ. Bác nên kiểm tra lại cho chắc trước khi làm theo.',
      todos: [
        'Chưa chuyển tiền, chưa đọc mã OTP.',
        'Hỏi con cháu, hoặc gọi số chính thức của ngân hàng để hỏi.',
        'Đừng bấm vào đường link trong tin nhắn.',
      ],
    };
  }
  if (tone === 'SAFE') {
    return {
      tone: 'safe',
      icon: 'bi-shield-check',
      label: 'Chưa thấy dấu hiệu xấu',
      plain: 'Trong dữ liệu của cháu chưa thấy dấu hiệu lừa đảo. Nhưng điều này KHÔNG có nghĩa là chắc chắn an toàn.',
      todos: [
        'Vẫn cẩn thận nếu họ đòi tiền hoặc đòi mã OTP.',
        'Cần chắc chắn thì gọi số in trên thẻ ngân hàng để hỏi.',
      ],
    };
  }
  return {
    tone: 'neutral',
    icon: 'bi-question-circle-fill',
    label: 'Chưa có đủ thông tin',
    plain: 'Cháu chưa có đủ dữ liệu để kết luận. Đây KHÔNG phải là đã an toàn.',
    todos: [
      'Đừng vội chuyển tiền hay đọc mã OTP.',
      'Nhờ con cháu kiểm tra cùng.',
      'Gọi tổng đài chính thức để hỏi cho rõ.',
    ],
  };
}

interface Channel {
  name: string;
  phone?: string;
}

function channelsOf(result: ScanResult | null): Channel[] {
  const g = (result?.['guardrail'] || {}) as Record<string, unknown>;
  return asArr<Record<string, unknown>>(g['official_channels'])
    .map((c) => ({ name: asStr(c['name']), phone: asStr(c['phone']) || undefined }))
    .filter((c) => c.phone)
    .slice(0, 3);
}

function disclaimerOf(result: ScanResult | null): string {
  const g = (result?.['guardrail'] || {}) as Record<string, unknown>;
  return asStr(g['disclaimer']) || DISCLAIMER_FALLBACK;
}

/* ─────────────────────────────── Trang chính ─────────────────────────────── */

export default function ElderHub() {
  const [currentTab, setCurrentTab] = useState<ElderTab>('check');
  const [textSize, setTextSize] = useState<TextSize>('large');
  const [kind, setKind] = useState<CheckKind>('phone');
  const [phone, setPhone] = useState('');
  const [url, setUrl] = useState('');
  const [bank, setBank] = useState('');
  const [account, setAccount] = useState('');
  const [message, setMessage] = useState('');
  const [banks, setBanks] = useState<BankInfo[]>([]);
  const [tsToken, setTsToken] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [checkedLabel, setCheckedLabel] = useState('');
  const [error, setError] = useState('');
  const [errorField, setErrorField] = useState('');
  const [copied, setCopied] = useState(false);
  const [ttsMode, setTtsMode] = useState<'probing' | 'server' | 'browser' | 'none'>('probing');
  const [seed, setSeed] = useState<{ text: string; n: number }>({ text: '', n: 0 });

  const resultRef = useRef<HTMLDivElement>(null);
  const errorRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const msgRef = useRef<HTMLTextAreaElement>(null);

  const verified = tsToken !== '';

  useIsoLayoutEffect(() => {
    try {
      const v = localStorage.getItem('elder_text_size');
      if (v === 'normal' || v === 'large' || v === 'xlarge') setTextSize(v);
    } catch {
      /* bỏ qua */
    }
  }, []);

  const pickSize = useCallback((s: TextSize) => {
    setTextSize(s);
    try {
      localStorage.setItem('elder_text_size', s);
    } catch {
      /* bỏ qua */
    }
  }, []);

  useEffect(() => {
    if (kind !== 'bank' || banks.length > 0) return;
    let alive = true;
    api
      .get<BankInfo[]>('/scan/banks/')
      .then((d) => {
        if (alive && Array.isArray(d)) setBanks(d);
      })
      .catch(() => {
        /* lỗi mạng: vẫn cho nhập */
      });
    return () => {
      alive = false;
    };
  }, [kind, banks.length]);

  const viVoiceRef = useRef<SpeechSynthesisVoice | null>(null);
  const speakIdRef = useRef(0);
  const [voiceState, setVoiceState] = useState<'unknown' | 'vi' | 'other'>('unknown');

  const chunkVi = useCallback((text: string): string[] => {
    const parts = String(text || '')
      .split(/(?<=[.!?…:])\s+|\n+/)
      .map((s) => s.trim())
      .filter(Boolean);
    const out: string[] = [];
    let cur = '';
    for (const p of parts) {
      if ((cur + ' ' + p).trim().length > 220 && cur) {
        out.push(cur.trim());
        cur = p;
      } else {
        cur = `${cur} ${p}`.trim();
      }
    }
    if (cur.trim()) out.push(cur.trim());
    return out.length ? out : [String(text || '').trim()].filter(Boolean);
  }, []);

  useEffect(() => {
    const synth = typeof window !== 'undefined' ? window.speechSynthesis : undefined;
    if (!synth) return;
    const pick = (): void => {
      try {
        const voices = synth.getVoices() || [];
        const vi =
          voices.find((v) => /^vi([-_]|$)/i.test(v.lang || '')) ||
          voices.find((v) => /vietnam|tiếng việt/i.test(v.name || ''));
        viVoiceRef.current = vi || null;
        if (voices.length === 0) setVoiceState('unknown');
        else setVoiceState(vi ? 'vi' : 'other');
      } catch {
        /* bỏ qua */
      }
    };
    pick();
    try {
      synth.addEventListener('voiceschanged', pick);
      return () => synth.removeEventListener('voiceschanged', pick);
    } catch {
      return;
    }
  }, []);

  useEffect(
    () => () => {
      speakIdRef.current += 1;
      stopAudio();
      try {
        window.speechSynthesis?.cancel();
      } catch {
        /* bỏ qua */
      }
    },
    [],
  );

  /* Thăm dò năng lực TTS của server (đồng thời warm sẵn câu mở đầu). Server
   * không sẵn sàng → fallback giọng trình duyệt; cả hai đều không có → ẩn nút. */
  useEffect(() => {
    let alive = true;
    warmTts([INTRO_SPEECH]).then((ok) => {
      if (!alive) return;
      setTtsMode(ok ? 'server' : hasBrowserVoice() ? 'browser' : 'none');
    });
    return () => {
      alive = false;
    };
  }, []);

  const browserSpeak = useCallback(
    (text: string) => {
      try {
        const synth = window.speechSynthesis;
        if (!synth || !text.trim()) return;
        const myId = ++speakIdRef.current;
        synth.cancel();
        const chunks = chunkVi(text);
        const queue = (i: number): void => {
          if (speakIdRef.current !== myId) return;
          if (i >= chunks.length) return;
          const u = new SpeechSynthesisUtterance(chunks[i]);
          const voice = viVoiceRef.current;
          if (voice) {
            u.voice = voice;
            u.lang = voice.lang || 'vi-VN';
          } else {
            u.lang = 'vi-VN';
          }
          u.rate = 0.85;
          u.pitch = 1;
          u.onend = () => queue(i + 1);
          u.onerror = () => {
            queue(i + 1);
          };
          synth.speak(u);
        };
        queue(0);
      } catch {
        /* bỏ qua */
      }
    },
    [chunkVi],
  );

  const stopSpeak = useCallback(() => {
    speakIdRef.current += 1;
    stopAudio();
    try {
      window.speechSynthesis?.cancel();
    } catch {
      /* bỏ qua */
    }
  }, []);

  /* Ưu tiên giọng SERVER; nếu không phát được (mạng/503) tự chuyển sang giọng
   * trình duyệt. Nếu server chưa sẵn sàng thì dùng thẳng giọng trình duyệt. */
  const speak = useCallback(
    (text: string) => {
      const t = String(text || '').trim();
      if (!t) return;
      stopSpeak();
      if (ttsMode === 'server') {
        playAudio(t, { onError: () => browserSpeak(t) });
        return;
      }
      browserSpeak(t);
    },
    [browserSpeak, stopSpeak, ttsMode],
  );

  const verdict = verdictOf(guardrailTone(result));
  const channels = channelsOf(result);
  const canSpeak = ttsMode !== 'none';

  const speechForResult = useCallback((): string => {
    const parts = [`Bác đã kiểm tra ${checkedLabel}.`, verdict.label, verdict.plain, ...verdict.todos];
    const first = channels.find((c) => c.phone);
    if (first?.phone) parts.push(`Khi cần, bác gọi số ${first.phone}.`);
    parts.push('Kết quả này chỉ để tham khảo.');
    return parts.join('. ');
  }, [checkedLabel, verdict, channels]);

  useEffect(() => {
    if (error) errorRef.current?.scrollIntoView({ block: 'center', behavior: 'auto' });
  }, [error]);

  useEffect(() => {
    if (!result) return;
    const el = resultRef.current;
    if (!el) return;
    let smooth = true;
    try {
      smooth = !window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    } catch {
      /* bỏ qua */
    }
    el.scrollIntoView({ block: 'start', behavior: smooth ? 'smooth' : 'auto' });
  }, [result]);

  const fail = useCallback((msg: string, field = '') => {
    setError(msg);
    setErrorField(field);
    showToast(msg, 'warning');
  }, []);

  const runCheck = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      if (loading) return;
      setError('');
      stopSpeak();

      if (!verified) {
        fail('Bác chưa làm câu hỏi xác minh. Bác bấm vào ô vuông trong khung "Xác minh bác là người thật" ở trên, rồi bấm lại nút này nhé.');
        return;
      }

      let path = '';
      let payload: Record<string, unknown> = {};
      let label = '';

      if (kind === 'phone') {
        const typed = phone.trim();
        if (!typed) {
          fail('Bác chưa nhập số điện thoại. Bác đánh số cần kiểm tra vào ô trên nhé.', 'elder-phone');
          return;
        }
        const normalized = normalizePhone(typed);
        if (!normalized) {
          fail('Số điện thoại chưa đúng. Số di động có 10 chữ số (ví dụ 0978123456), số bàn có 11 chữ số (ví dụ 02838234567). Bác kiểm tra lại giúp cháu.', 'elder-phone');
          return;
        }
        path = '/scan/phone/';
        payload = { phone: normalized, 'cf-turnstile-response': tsToken };
        label = typed;
      } else if (kind === 'message') {
        const typed = message.trim();
        if (typed.length < 5) {
          fail('Bác chưa dán tin nhắn. Bác chép tin nhắn rồi dán vào ô trên giúp cháu nhé.', 'elder-message');
          return;
        }
        path = '/scan/message/?sync=true';
        payload = { message: typed, sync: true, 'cf-turnstile-response': tsToken };
        label = `Tin nhắn: "${typed.length > 60 ? `${typed.slice(0, 60)}…` : typed}"`;
      } else if (kind === 'website') {
        const typed = url.trim();
        if (!typed) {
          fail('Bác chưa dán đường link. Bác dán đường link trong tin nhắn vào ô trên nhé (đừng bấm vào link đó).', 'elder-url');
          return;
        }
        path = '/scan/domain/';
        payload = { url: typed, deep_scan: false, 'cf-turnstile-response': tsToken };
        label = typed;
      } else {
        if (!bank) {
          fail('Bác chưa chọn ngân hàng. Bác bấm vào ô "Ngân hàng" để chọn tên ngân hàng trong tin nhắn nhé.', 'elder-bank');
          return;
        }
        const typed = account.trim();
        if (!typed) {
          fail('Bác chưa nhập số tài khoản. Bác đánh số tài khoản mà người ta gửi cho bác nhé.', 'elder-account');
          return;
        }
        path = '/scan/account/';
        payload = { bank, account: typed, 'cf-turnstile-response': tsToken };
        label = `${typed} (${bank})`;
      }

      setCheckedLabel(label);
      setCopied(false);
      setLoading(true);
      setResult(null);
      api
        .post<ScanResult>(path, payload)
        .then((data) => {
          setResult(data);
          setTsToken('');
          try {
            resetTurnstile();
          } catch {
            /* bỏ qua */
          }
        })
        .catch(() => {
          fail('Cháu chưa kiểm tra được lúc này. Bác chờ một lát rồi bấm lại, hoặc nhờ con cháu giúp nhé.');
        })
        .finally(() => setLoading(false));
    },
    [account, bank, fail, kind, loading, message, phone, stopSpeak, tsToken, url, verified],
  );

  const askAboutResult = useCallback(() => {
    stopSpeak();
    setSeed((s) => ({
      text: `Cháu vừa kiểm tra ${checkedLabel}, kết quả là "${verdict.label}". Bác cần làm gì bây giờ ạ?`,
      n: s.n + 1,
    }));
    setCurrentTab('chat');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }, [checkedLabel, stopSpeak, verdict.label]);

  const resetCheck = useCallback(() => {
    stopSpeak();
    setResult(null);
    setError('');
    setCopied(false);
    setPhone('');
    setUrl('');
    setAccount('');
    setMessage('');
    if (kind === 'message') msgRef.current?.focus();
    else inputRef.current?.focus();
  }, [kind, stopSpeak]);

  const shareToFamily = useCallback(async () => {
    const text = [
      'Con/cháu xem giúp bố/mẹ. Bố/mẹ vừa kiểm tra trên ShieldCall:',
      `- Đã kiểm tra: ${checkedLabel}`,
      `- Kết quả: ${verdict.label}`,
      `- ${verdict.plain}`,
      ...verdict.todos.map((t, i) => `  ${i + 1}. ${t}`),
      '(Kết quả tự động, chỉ để tham khảo.)',
    ].join('\n');

    const nav = navigator as Navigator & { share?: (d: { title?: string; text?: string }) => Promise<void> };
    if (typeof nav.share === 'function') {
      try {
        await nav.share({ title: 'Kết quả kiểm tra trên ShieldCall', text });
        return;
      } catch {
        /* bỏ qua */
      }
    }
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
    } catch {
      showToast('Chưa chép được. Bác chụp ảnh màn hình gửi cho con cháu nhé.', 'warning');
    }
  }, [checkedLabel, verdict]);

  const fieldProps = (id: string, cls = 'elder-input') => ({
    id,
    className: cls,
    'aria-describedby': `${id}-hint`,
    'aria-invalid': error && errorField === id ? true : undefined,
  });

  /* Giữ MỌI panel luôn mounted, chỉ ẩn/hiện bằng CSS. Nhờ vậy: lịch sử chat,
     tiến trình bài học/quiz và captcha KHÔNG bị xoá mỗi lần bác đổi tab. */
  const panelCls = (t: ElderTab): string => (currentTab === t ? '' : 'hidden');

  const selectTab = useCallback(
    (t: ElderTab) => {
      setCurrentTab(t);
      stopSpeak();
    },
    [stopSpeak],
  );

  /* Điều hướng tab bằng phím mũi tên/Home/End theo chuẩn ARIA (roving tabindex). */
  const onTabKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      const ids = TABS.map((t) => t.id);
      const i = ids.indexOf(currentTab);
      let next = i;
      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') next = (i + 1) % ids.length;
      else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') next = (i - 1 + ids.length) % ids.length;
      else if (e.key === 'Home') next = 0;
      else if (e.key === 'End') next = ids.length - 1;
      else return;
      e.preventDefault();
      selectTab(ids[next]);
      document.getElementById(`tab-${ids[next]}`)?.focus();
    },
    [currentTab, selectTab],
  );

  return (
    <div className={`elder elder-size-${textSize} max-w-3xl mx-auto px-4 pt-6 pb-24 space-y-8`}>
      {/* ── Đầu trang: Tiêu đề, Cỡ chữ & Đọc to ──────────────────────── */}
      <header className="space-y-4 text-center">
        <span className="inline-flex items-center gap-2 rounded-full border border-safe-500/30 bg-safe-500/10 px-3 py-1.5 text-safe-200 elder-note">
          <i className="bi bi-shield-check" aria-hidden="true"></i>
          Dễ dùng · Chữ to · Không cần đăng nhập · Không lưu số trong máy bác
        </span>

        <h1 className="elder-h1">Trợ giúp bác phòng chống lừa đảo</h1>

        <p className="elder-lead max-w-xl mx-auto">
          Cháu giúp bác kiểm tra số lạ, học cách vạch trần kẻ gian và gọi cứu trợ khẩn cấp bất cứ lúc nào.
        </p>

        {ttsMode === 'browser' && voiceState === 'other' && (
          <p className="elder-note max-w-xl mx-auto" role="note">
            Máy của bác chưa có giọng đọc tiếng Việt nên nút “đọc to” có thể khó nghe. Bác nhờ con cháu mở phần Cài đặt
            của máy, thêm giọng tiếng Việt giúp cháu nhé.
          </p>
        )}

        <div className="flex flex-wrap items-center justify-center gap-3 pt-1">
          {canSpeak && (
            <button type="button" className="elder-btn" onClick={() => speak(INTRO_SPEECH)}>
              <i className="bi bi-volume-up-fill elder-icon" aria-hidden="true"></i> Đọc to hướng dẫn
            </button>
          )}

          <div
            role="group"
            aria-label="Chọn cỡ chữ"
            className="inline-flex items-center gap-2 rounded-2xl border border-border bg-card/60 p-1.5"
          >
            <span className="elder-note px-1.5">Cỡ chữ</span>
            {TEXT_SIZES.map((t) => (
              <button
                key={t.id}
                type="button"
                aria-pressed={textSize === t.id}
                onClick={() => pickSize(t.id)}
                className="elder-btn"
              >
                {t.label}
              </button>
            ))}
          </div>
        </div>
      </header>

      {/* ── Băng báo khẩn cấp (Jump to Emergency Tab) ───────────────────── */}
      {currentTab !== 'emergency' && (
        <div className="elder-alert-banner" role="alert">
          <div className="flex items-center gap-3">
            <i className="bi bi-exclamation-octagon-fill elder-icon text-danger-300" aria-hidden="true"></i>
            <div>
              <strong className="elder-small block">Có người đang gọi giục bác chuyển tiền?</strong>
              <span className="elder-small text-danger-200">Bác dừng lại ngay, đừng chuyển tiền.</span>
            </div>
          </div>
          <button
            type="button"
            className="elder-alert-banner__btn"
            onClick={() => {
              selectTab('emergency');
              document.getElementById('tab-emergency')?.focus();
              window.scrollTo({ top: 0, behavior: 'smooth' });
            }}
          >
            <i className="bi bi-lightning-charge-fill" aria-hidden="true"></i>
            Xử lý gấp
          </button>
        </div>
      )}

      {/* ── THANH CHUYỂN TAB CHÍNH ─────────────────────────────────────── */}
      <nav aria-label="Các phần chính" role="tablist" className="elder-nav-tabs" onKeyDown={onTabKeyDown}>
        {TABS.map((t) => {
          const isSelected = currentTab === t.id;
          return (
            <button
              key={t.id}
              role="tab"
              id={`tab-${t.id}`}
              aria-selected={isSelected}
              aria-controls={`panel-${t.id}`}
              tabIndex={isSelected ? 0 : -1}
              type="button"
              className={`elder-tab-btn ${t.danger ? 'elder-tab-btn--danger' : ''}`}
              onClick={() => selectTab(t.id)}
            >
              <i className={`bi ${t.icon} elder-tab-icon`} aria-hidden="true"></i>
              <span className="elder-tab-title">{t.title}</span>
              <span className="elder-tab-sub">{t.sub}</span>
            </button>
          );
        })}
      </nav>

      {/* ══════════════════════════════════════════════════════════════════
          TAB 1: KIỂM TRA AN TOÀN
         ══════════════════════════════════════════════════════════════════ */}
      <div className={`space-y-6 ${panelCls('check')}`} role="tabpanel" id="panel-check" aria-labelledby="tab-check">
          <section className="space-y-5" aria-labelledby="elder-check">
            <h2 id="elder-check" className="elder-h2">
              <i className="bi bi-search elder-h-icon text-brand-300" aria-hidden="true"></i>
              Bác muốn kiểm tra cái gì?
            </h2>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              {CHECKS.map((c) => {
                const active = kind === c.id;
                return (
                  <button
                    key={c.id}
                    type="button"
                    aria-pressed={active}
                    onClick={() => {
                      setKind(c.id);
                      setError('');
                      setResult(null);
                    }}
                    className="elder-btn elder-btn--choice"
                  >
                    <i className={`bi ${c.icon} elder-icon`} aria-hidden="true"></i>
                    <span className="min-w-0 flex-1 text-left">
                      <span className="block font-bold">{c.label}</span>
                      <span className="block elder-note">{c.hint}</span>
                      {active && (
                        <span className="mt-1 inline-flex items-center gap-1 font-bold text-brand-200">
                          <i className="bi bi-check-circle-fill" aria-hidden="true"></i> Bác đang chọn cái này
                        </span>
                      )}
                    </span>
                  </button>
                );
              })}
            </div>

            <form className="elder-card space-y-6" onSubmit={runCheck} noValidate>
              {kind === 'phone' && (
                <div>
                  <label className="elder-label" htmlFor="elder-phone">
                    Số điện thoại cần kiểm tra
                  </label>
                  <input
                    {...fieldProps('elder-phone')}
                    ref={inputRef}
                    type="tel"
                    inputMode="tel"
                    autoComplete="tel"
                    placeholder="Ví dụ: 0978 123 456"
                    value={phone}
                    onChange={(e) => {
                      setPhone(e.target.value);
                      setError('');
                    }}
                  />
                  <p id="elder-phone-hint" className="elder-note mt-2">
                    Bác đánh cả chữ số và khoảng trắng cũng được, cháu tự xử lý.
                  </p>
                </div>
              )}

              {kind === 'message' && (
                <div>
                  <label className="elder-label" htmlFor="elder-message">
                    Tin nhắn bác nhận được
                  </label>
                  <textarea
                    {...fieldProps('elder-message', 'elder-input elder-textarea')}
                    ref={msgRef}
                    rows={4}
                    autoComplete="off"
                    placeholder="Bác chép nguyên tin nhắn rồi dán vào đây cũng được"
                    value={message}
                    onChange={(e) => {
                      setMessage(e.target.value);
                      setError('');
                    }}
                  />
                  <p id="elder-message-hint" className="elder-note mt-2">
                    Bác giữ tay vào tin nhắn rồi chọn &quot;Sao chép&quot;, sau đó dán vào ô này. Đừng bấm vào link trong
                    tin nhắn.
                  </p>
                </div>
              )}

              {kind === 'website' && (
                <div>
                  <label className="elder-label" htmlFor="elder-url">
                    Đường link bác nhận được
                  </label>
                  <input
                    {...fieldProps('elder-url')}
                    ref={inputRef}
                    type="text"
                    inputMode="url"
                    autoComplete="off"
                    autoCapitalize="none"
                    spellCheck={false}
                    placeholder="Ví dụ: vn-bank-kiemtra.com"
                    value={url}
                    onChange={(e) => {
                      setUrl(e.target.value);
                      setError('');
                    }}
                  />
                  <p id="elder-url-hint" className="elder-note mt-2">
                    Bác dán cả đường link dài cũng được. Quan trọng: đừng bấm vào link đó.
                  </p>
                </div>
              )}

              {kind === 'bank' && (
                <>
                  <div>
                    <span className="elder-label" id="elder-bank-label">
                      Ngân hàng
                    </span>
                    <div className="flex flex-wrap gap-2.5" role="group" aria-label="Ngân hàng hay gặp">
                      {POPULAR_BANKS.map((name) => (
                        <button
                          key={name}
                          type="button"
                          aria-pressed={bank === name}
                          onClick={() => {
                            setBank(bank === name ? '' : name);
                            setError('');
                          }}
                          className="elder-btn elder-btn--sm"
                        >
                          {name}
                        </button>
                      ))}
                    </div>
                    <p className="elder-note mt-2">
                      Bấm vào tên ngân hàng ở trên. Không có tên cần tìm thì bác bấm ô bên dưới để chọn trong danh sách đầy đủ.
                    </p>
                    <BankPicker
                      banks={banks}
                      value={bank}
                      labelledBy="elder-bank-label"
                      invalid={!!error && errorField === 'elder-bank'}
                      onPick={(v) => {
                        setBank(v);
                        setError('');
                      }}
                    />
                    <p id="elder-bank-hint" className="elder-note mt-2">
                      Tên ngân hàng thường ghi trong tin nhắn hoặc ảnh người ta gửi cho bác.
                    </p>
                  </div>
                  <div>
                    <label className="elder-label" htmlFor="elder-account">
                      Số tài khoản nhận tiền
                    </label>
                    <input
                      {...fieldProps('elder-account')}
                      ref={inputRef}
                      type="text"
                      inputMode="numeric"
                      autoComplete="off"
                      placeholder="Ví dụ: 0123456789"
                      value={account}
                      onChange={(e) => {
                        setAccount(e.target.value);
                        setError('');
                      }}
                    />
                    <p id="elder-account-hint" className="elder-note mt-2">
                      Là số tài khoản người ta gửi để bác chuyển tiền (không phải số thẻ ATM của bác).
                    </p>
                  </div>
                </>
              )}

              {/* Hộp Captcha */}
              <div className="elder-captcha">
                <h3 className="elder-h3 flex items-center gap-2">
                  <i className="bi bi-shield-lock-fill elder-icon text-brand-300" aria-hidden="true"></i>
                  Xác minh bác là người thật
                </h3>

                <p className="elder-lead">
                  Ô nhỏ bên dưới để chặn máy móc tự động. Bác bấm vào ô vuông nhỏ một lần:
                </p>

                <TurnstileWidget onToken={setTsToken} />

                <p className={`elder-state ${verified ? 'elder-state--done' : 'elder-state--todo'}`} role="status">
                  <i className={`bi ${verified ? 'bi-check-circle-fill' : 'bi-hourglass-split'}`} aria-hidden="true"></i>
                  {verified ? 'Bác đã xác minh xong' : 'Bác chưa xác minh — bấm vào ô vuông ở trên'}
                </p>
              </div>

              {/* Lỗi hiện tại chỗ */}
              <div ref={errorRef} role="alert">
                {error && (
                  <p className="elder-error">
                    <i className="bi bi-exclamation-triangle-fill elder-icon" aria-hidden="true"></i>
                    <span>{error}</span>
                  </p>
                )}
              </div>

              <button type="submit" className="elder-btn elder-btn--xl elder-btn--brand" disabled={loading} aria-busy={loading}>
                {loading ? (
                  <>
                    <i className="bi bi-hourglass-split elder-icon" aria-hidden="true"></i> Cháu đang kiểm tra… bác chờ chút
                  </>
                ) : (
                  <>
                    <i className="bi bi-search elder-icon" aria-hidden="true"></i> Kiểm tra ngay
                  </>
                )}
              </button>
            </form>

            {/* Kết quả */}
            <div ref={resultRef} role="status" aria-live="polite" className="scroll-mt-4">
              {result && (
                <article className={`elder-verdict elder-verdict--${verdict.tone} space-y-5`}>
                  <p className="elder-note">
                    Bác đã kiểm tra: <span className="elder-value">{checkedLabel}</span>
                  </p>

                  <h3 className="flex items-center gap-3">
                    <i className={`bi ${verdict.icon} elder-verdict__icon`} aria-hidden="true"></i>
                    <span className="elder-verdict__label">{verdict.label}</span>
                  </h3>

                  <p className="elder-body font-semibold">{verdict.plain}</p>

                  <div className="space-y-3">
                    <p className="elder-h3">Bác nên làm gì:</p>
                    {verdict.todos.map((t, i) => (
                      <p key={i} className="elder-todo">
                        <span className="elder-todo__num">{i + 1}</span>
                        <span>{t}</span>
                      </p>
                    ))}
                  </div>

                  {channels.length > 0 && (
                    <div className="space-y-3">
                      <p className="elder-h3">Số chính thức để gọi:</p>
                      <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap">
                        {channels.map((c, i) => (
                          <a
                            key={i}
                            href={`tel:${(c.phone || '').replace(/[^0-9+]/g, '')}`}
                            className="elder-btn elder-btn--safe flex-1"
                            aria-label={`Gọi số ${c.phone}`}
                          >
                            <i className="bi bi-telephone-fill elder-icon" aria-hidden="true"></i> Gọi {c.phone}
                          </a>
                        ))}
                      </div>
                      <p className="elder-note">{channels[0]?.name}</p>
                    </div>
                  )}

                  <p className="elder-caveat">{disclaimerOf(result)}</p>

                  <div className="flex flex-col gap-3">
                    {canSpeak && (
                      <button type="button" className="elder-btn elder-btn--xl" onClick={() => speak(speechForResult())}>
                        <i className="bi bi-volume-up-fill elder-icon" aria-hidden="true"></i> Đọc to kết quả
                      </button>
                    )}
                    <button type="button" className="elder-btn elder-btn--xl" onClick={() => void shareToFamily()}>
                      <i className="bi bi-send-fill elder-icon" aria-hidden="true"></i> Gửi cho con cháu xem (Zalo/Tin nhắn)
                    </button>
                    <button type="button" className="elder-btn elder-btn--xl elder-btn--brand" onClick={askAboutResult}>
                      <i className="bi bi-chat-dots-fill elder-icon" aria-hidden="true"></i> Hỏi cháu về kết quả này
                    </button>
                    <button type="button" className="elder-btn elder-btn--xl elder-btn--quiet" onClick={resetCheck}>
                      <i className="bi bi-arrow-counterclockwise elder-icon" aria-hidden="true"></i> Kiểm tra cái khác
                    </button>
                  </div>

                  {copied && (
                    <p className="elder-note">
                      Đã chép sẵn nội dung. Bác mở Zalo (hoặc tin nhắn) và dán vào tin nhắn cho con cháu nhé.
                    </p>
                  )}
                </article>
              )}
            </div>
          </section>
        </div>

      {/* ══════════════════════════════════════════════════════════════════
          TAB 2: HỌC NHẬN BIẾT LỪA ĐẢO (LEARN)
         ══════════════════════════════════════════════════════════════════ */}
      <div className={panelCls('learn')}>
        <ElderLearn canSpeak={canSpeak} speak={speak} />
      </div>

      {/* ══════════════════════════════════════════════════════════════════
          TAB 3: NHẮN TIN HỎI CHÁU (AI CHAT)
         ══════════════════════════════════════════════════════════════════ */}
      <div className={panelCls('chat')} role="tabpanel" id="panel-chat" aria-labelledby="tab-chat">
        <ElderChat canSpeak={canSpeak} speak={speak} stopSpeak={stopSpeak} seed={seed} />
      </div>

      {/* ══════════════════════════════════════════════════════════════════
          TAB 4: KHẨN CẤP & CỨU TRỢ
         ══════════════════════════════════════════════════════════════════ */}
      <div className={panelCls('emergency')}>
        <ElderEmergency canSpeak={canSpeak} speak={speak} />
      </div>

      {/* ── Chân trang ─────────────────────────────────────────────────── */}
      <footer className="pt-6 border-t border-border/60 text-center space-y-2">
        <p className="elder-note">
          Trang Trợ giúp Người cao tuổi ShieldCall — Không cần đăng nhập. Số bác kiểm tra được dùng để tra cứu cảnh báo
          và không gắn với tài khoản nào của bác.
        </p>
        <p className="elder-note">
          Cháu chúc bác luôn bình an và cảnh giác trước mọi thủ đoạn lừa đảo!
        </p>
      </footer>
    </div>
  );
}
