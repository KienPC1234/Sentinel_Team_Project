/* Phát giọng đọc tiếng Việt do SERVER tổng hợp (xem backend api/core/tts_service.py).
 *
 * Vì sao không dùng Web Speech API của trình duyệt: giọng tiếng Việt không phải
 * máy nào cũng có, chất lượng thất thường và hay đọc sai dấu. Ở đây ta gọi
 * GET {apiBase}/tts/?text=... để lấy WAV (server đã cache sẵn), phát bằng thẻ
 * audio. Nếu server chưa sẵn sàng thì nơi gọi tự fallback sang giọng trình duyệt.
 */
import { apiBase } from '../components/ScanWidgets';

let currentAudio: HTMLAudioElement | null = null;

export interface SpeakOptions {
  onEnd?: () => void;
  /** Gọi khi KHÔNG phát được audio server (mạng/503) để nơi gọi fallback. */
  onError?: () => void;
}

/** URL audio cho một đoạn văn bản (server sinh + cache theo nội dung). */
export function ttsUrl(text: string): string {
  return `${apiBase()}/tts/?text=${encodeURIComponent(text)}`;
}

/**
 * Build trước (warm cache) một danh sách câu ở backend.
 * Trả về true nếu server TTS sẵn sàng (dùng luôn như một phép thăm dò năng lực).
 */
export async function warmTts(texts: string[]): Promise<boolean> {
  const list = Array.from(new Set(texts.map((t) => String(t || '').trim()).filter(Boolean)));
  if (list.length === 0) return false;
  try {
    const res = await fetch(`${apiBase()}/tts/warm/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ texts: list }),
      credentials: 'include',
    });
    // Server bật TTS → 2xx (kể cả khi vài câu lỗi). 503 khi TTS chưa sẵn sàng.
    return res.ok;
  } catch {
    return false;
  }
}

/** Dừng audio server đang phát (nếu có). */
export function stopAudio(): void {
  if (currentAudio) {
    const a = currentAudio;
    currentAudio = null;
    try {
      a.pause();
      a.currentTime = 0;
    } catch {
      /* bỏ qua */
    }
  }
}

/** Cắt văn bản dài thành các đoạn ≤ ~900 ký tự (đủ dài để 1 request, URL vẫn gọn). */
function splitForAudio(text: string, max = 900): string[] {
  const parts = String(text || '')
    .split(/(?<=[.!?…:])\s+|\n+/)
    .map((s) => s.trim())
    .filter(Boolean);
  const out: string[] = [];
  let cur = '';
  for (const p of parts) {
    if ((`${cur} ${p}`).trim().length > max && cur) {
      out.push(cur.trim());
      cur = p;
    } else {
      cur = `${cur} ${p}`.trim();
    }
  }
  if (cur.trim()) out.push(cur.trim());
  return out.length ? out : [String(text || '').trim()].filter(Boolean);
}

/* Nạp trước đoạn kế vào cache trình duyệt để phát liền mạch (không chờ mạng). */
function prefetch(url: string): void {
  try {
    const pre = new Audio();
    pre.preload = 'auto';
    pre.src = url;
  } catch {
    /* bỏ qua */
  }
}

/**
 * Phát audio server cho `text`. TÁI DÙNG một thẻ audio cho mọi đoạn (giảm GC,
 * liền mạch) và PREFETCH đoạn kế. Lỗi → gọi `onError` để nơi gọi fallback.
 */
export function playAudio(text: string, opts: SpeakOptions = {}): void {
  stopAudio();
  const chunks = splitForAudio(text);
  if (chunks.length === 0) {
    opts.onError?.();
    return;
  }

  const audio = new Audio();
  audio.preload = 'auto';
  currentAudio = audio;

  let i = 0;
  let failed = false;

  const fail = (): void => {
    if (failed) return;
    failed = true;
    if (currentAudio === audio) currentAudio = null;
    opts.onError?.();
  };

  const playNext = (): void => {
    // Bị dừng giữa chừng (currentAudio đã đổi) hoặc lỗi → không phát tiếp.
    if (failed || currentAudio !== audio) return;
    if (i >= chunks.length) {
      currentAudio = null;
      opts.onEnd?.();
      return;
    }
    const chunk = chunks[i];
    i += 1;
    if (i < chunks.length) prefetch(ttsUrl(chunks[i]));
    audio.src = ttsUrl(chunk);
    void audio.play().catch(fail);
  };

  audio.onended = playNext;
  audio.onerror = fail;
  playNext();
}

/** Có API Web Speech để fallback không. */
export function hasBrowserVoice(): boolean {
  return typeof window !== 'undefined' && !!window.speechSynthesis;
}
