'use client';

/* Nút "?" trên nav + banner gợi ý ở dưới trang (dùng driver.js).
 * - TourHelpButton: nút ? đặt trong Navbar. Tự ẩn khi trang không có tour
 *   (tránh hướng dẫn thừa cho trang đơn giản như login/legal/404).
 * - TourPrompt: banner "Bạn có muốn xem hướng dẫn?" hiện 1 lần mỗi trang,
 *   lưu lựa chọn vào localStorage để không hiện lại khi đã xong / đã từ chối.
 * - startTourForPath: chạy tour của trang hiện tại, lọc bỏ bước mà selector
 *   không tồn tại (tránh bug kẹt tour khi DOM thiếu / responsive khác nhau).
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { usePathname } from 'next/navigation';
import 'driver.js/dist/driver.css';
import { TOURS, getTourIdForPath } from '@/lib/tours';

const STORE_KEY = 'shieldcall_guide_v1';

interface GuideStore {
  done: string[];
  dismissed: string[];
}

function readStore(): GuideStore {
  if (typeof window === 'undefined') return { done: [], dismissed: [] };
  try {
    const raw = window.localStorage.getItem(STORE_KEY);
    if (!raw) return { done: [], dismissed: [] };
    const parsed = JSON.parse(raw) as Partial<GuideStore>;
    return {
      done: Array.isArray(parsed.done) ? parsed.done : [],
      dismissed: Array.isArray(parsed.dismissed) ? parsed.dismissed : [],
    };
  } catch {
    return { done: [], dismissed: [] };
  }
}

function writeStore(next: GuideStore): void {
  try {
    window.localStorage.setItem(STORE_KEY, JSON.stringify(next));
  } catch {
    /* localStorage đầy / bị chặn: bỏ qua, tour vẫn chạy tay được. */
  }
}

export function isTourDone(id: string): boolean {
  return readStore().done.includes(id);
}

export function isTourDismissed(id: string): boolean {
  return readStore().dismissed.includes(id);
}

export function markTourDone(id: string): void {
  const s = readStore();
  if (!s.done.includes(id)) writeStore({ ...s, done: [...s.done, id] });
}

export function markTourDismissed(id: string): void {
  const s = readStore();
  if (!s.dismissed.includes(id)) writeStore({ ...s, dismissed: [...s.dismissed, id] });
}

/* Singleton driver đang chạy (để hủy khi chuyển trang / chạy tour mới). */
let activeDestroy: (() => void) | null = null;

function destroyActiveTour(): void {
  try {
    activeDestroy?.();
  } catch {
    /* bỏ qua */
  }
  activeDestroy = null;
}

/** Chạy tour của pathname hiện tại. Trả về true nếu tour đã khởi động. */
export async function startTourForPath(pathname: string): Promise<boolean> {
  if (typeof window === 'undefined' || typeof document === 'undefined') return false;
  const tourId = getTourIdForPath(pathname);
  if (!tourId) return false;
  const tour = TOURS[tourId];
  if (!tour || tour.steps.length === 0) return false;

  // Bỏ các bước trỏ tới element không tồn tại (mobile / chưa đăng nhập /
  // kết quả scan chưa có...). Luôn giữ bước không có element (giới thiệu).
  const steps = tour.steps.filter((s) => {
    if (!s.element) return true;
    try {
      return document.querySelector(s.element) !== null;
    } catch {
      return false;
    }
  });
  if (steps.length === 0) return false;

  destroyActiveTour();
  const { driver } = await import('driver.js');
  let lastIndex = -1;
  const driverObj = driver({
    showProgress: true,
    progressText: '{{current}} / {{total}}',
    nextBtnText: 'Tiếp tục',
    prevBtnText: 'Quay lại',
    doneBtnText: 'Đã hiểu',
    closeBtnLabel: 'Đóng hướng dẫn',
    smoothScroll: true,
    allowClose: true,
    overlayColor: '#020617',
    overlayOpacity: 0.68,
    stagePadding: 8,
    stageRadius: 12,
    popoverClass: 'scv-guide-popover',
    overlayClickBehavior: 'close',
    steps: steps.map((s) => ({
      ...(s.element ? { element: s.element } : {}),
      popover: {
        title: s.title,
        description: s.description,
        side: s.side ?? 'bottom',
        align: s.align ?? 'start',
      },
    })),
    onHighlighted: (_el, _step, opts) => {
      const idx = (opts?.state as { activeIndex?: number } | undefined)?.activeIndex;
      if (typeof idx === 'number') lastIndex = idx;
    },
    onDestroyed: () => {
      activeDestroy = null;
      // Chỉ tính là "đã xong" khi người dùng đi tới bước cuối (bấm "Đã hiểu"
      // hoặc Next ở bước cuối). Đóng sớm giữa chừng thì không đánh dấu,
      // banner có thể gợi ý lại vào lần ghé sau (không làm phiền phiên này).
      if (lastIndex >= steps.length - 1) markTourDone(tour.id);
    },
  });
  activeDestroy = () => {
    try {
      if (driverObj.isActive()) driverObj.destroy();
    } catch {
      /* bỏ qua */
    }
  };
  driverObj.drive();
  return true;
}

/* ============ Nút "?" trên nav ============ */

export function TourHelpButton({ className = '' }: { className?: string }) {
  const pathname = usePathname() || '';
  const tourId = getTourIdForPath(pathname);
  const [busy, setBusy] = useState(false);
  const tour = tourId ? TOURS[tourId] : undefined;

  // Không có tour cho trang này -> ẩn hẳn nút (tránh icon thừa).
  if (!tour) return null;

  const onClick = async (): Promise<void> => {
    if (busy) return;
    setBusy(true);
    try {
      await startTourForPath(pathname);
    } finally {
      // Tránh double-click đúp tour; mở khóa sau 600ms.
      window.setTimeout(() => setBusy(false), 600);
    }
  };

  return (
    <button
      type="button"
      onClick={() => void onClick()}
      disabled={busy}
      aria-label={`Hướng dẫn sử dụng: ${tour.label}`}
      title={`Hướng dẫn: ${tour.label}`}
      data-tour="nav-help"
      className={`h-9 w-9 rounded-full inline-flex items-center justify-center text-slate-300 border border-white/10 bg-white/[0.05] hover:text-cyan-300 hover:border-cyan-500/40 hover:bg-cyan-500/10 transition-all outline-none cursor-pointer disabled:opacity-60 ${className}`}
    >
      <i className="bi bi-question-circle text-base leading-none"></i>
    </button>
  );
}

/* ============ Banner gợi ý ở cuối trang ============ */

const SNOOZE_KEY = 'shieldcall_guide_snooze_v1';

function isSnoozed(id: string): boolean {
  if (typeof window === 'undefined') return true;
  try {
    const raw = window.sessionStorage.getItem(SNOOZE_KEY);
    if (!raw) return false;
    return (JSON.parse(raw) as string[]).includes(id);
  } catch {
    return false;
  }
}

function snooze(id: string): void {
  try {
    const raw = window.sessionStorage.getItem(SNOOZE_KEY);
    const list = raw ? (JSON.parse(raw) as string[]) : [];
    if (!list.includes(id)) window.sessionStorage.setItem(SNOOZE_KEY, JSON.stringify([...list, id]));
  } catch {
    /* bỏ qua */
  }
}

export function TourPrompt() {
  const pathname = usePathname() || '';
  const tourId = getTourIdForPath(pathname);
  const tour = tourId ? TOURS[tourId] : undefined;
  const [visible, setVisible] = useState(false);
  const [starting, setStarting] = useState(false);
  const timer = useRef<number | null>(null);

  const hideForSession = useCallback(() => {
    if (timer.current != null) window.clearTimeout(timer.current);
    timer.current = null;
    setVisible(false);
  }, []);

  useEffect(() => {
    hideForSession();
    destroyActiveTour();
    if (!tour || !tourId) return;
    // Đã xong / đã từ chối vĩnh viễn -> không bao giờ hiện lại.
    if (isTourDone(tourId) || isTourDismissed(tourId) || isSnoozed(tourId)) return;
    // Trang người cao tuổi: chờ lâu hơn, chữ đã to sẵn nên không dồn dập.
    const delay = tourId === 'elder' ? 2200 : 1200;
    timer.current = window.setTimeout(() => setVisible(true), delay);
    return () => {
      if (timer.current != null) window.clearTimeout(timer.current);
      timer.current = null;
      destroyActiveTour();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pathname]);

  if (!tour || !tourId || !visible) return null;

  const start = async (): Promise<void> => {
    if (starting) return;
    setStarting(true);
    setVisible(false);
    try {
      const ok = await startTourForPath(pathname);
      if (!ok) snooze(tourId); // Không chạy được (thiếu DOM) -> ẩn trong phiên này.
    } finally {
      window.setTimeout(() => setStarting(false), 600);
    }
  };

  const later = (): void => {
    snooze(tourId); // Chỉ ẩn trong phiên này, lần sau vào lại vẫn gợi ý.
    setVisible(false);
  };

  const never = (): void => {
    markTourDismissed(tourId); // Từ chối vĩnh viễn cho trang này.
    setVisible(false);
  };

  return (
    <div
      role="dialog"
      aria-live="polite"
      aria-label={`Gợi ý hướng dẫn: ${tour.label}`}
      className="scv-guide-banner fixed bottom-24 right-4 sm:right-6 z-[70] w-[calc(100%-2rem)] max-w-sm"
    >
      <div className="flex items-start gap-3 rounded-2xl border border-cyan-500/25 bg-slate-950/95 backdrop-blur-xl px-4 py-3.5 shadow-[0_20px_60px_rgba(0,0,0,0.6)]">
        <div className="w-9 h-9 rounded-xl bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center text-cyan-300 shrink-0">
          <i className="bi bi-question-circle text-lg leading-none"></i>
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-[13px] font-bold text-white leading-snug">
            Lần đầu dùng {tour.label}?
          </p>
          <p className="text-xs text-slate-400 leading-relaxed mt-0.5">{tour.hint}</p>
          <div className="flex items-center gap-2 mt-2.5">
            <button
              type="button"
              onClick={() => void start()}
              disabled={starting}
              className="h-8 px-4 rounded-full bg-cyan-500 text-slate-950 text-xs font-black hover:bg-cyan-400 transition-colors cursor-pointer disabled:opacity-60"
            >
              {starting ? 'Đang mở…' : `Xem hướng dẫn (${tour.steps.length} bước)`}
            </button>
            <button
              type="button"
              onClick={later}
              className="h-8 px-3 rounded-full text-xs font-bold text-slate-300 hover:text-white hover:bg-white/10 transition-colors cursor-pointer"
            >
              Để sau
            </button>
          </div>
        </div>
        <button
          type="button"
          onClick={never}
          aria-label="Không hiện gợi ý này nữa"
          title="Không hiện gợi ý này nữa"
          className="w-7 h-7 rounded-full inline-flex items-center justify-center text-slate-500 hover:text-slate-200 hover:bg-white/10 transition-colors cursor-pointer shrink-0"
        >
          <i className="bi bi-x-lg text-xs leading-none"></i>
        </button>
      </div>
    </div>
  );
}
