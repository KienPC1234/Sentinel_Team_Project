'use client';

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { api } from '../lib/api';

interface UserCardData {
  username: string;
  display_name?: string;
  avatar?: string | null;
  is_staff?: boolean;
  rank?: {
    level?: string;
    name?: string;
  };
  joined?: string;
  posts_count?: number;
  comments_count?: number;
  reaction_score?: number;
  points?: number;
}

const RANK_CONFIG: Record<string, { bg: string; text: string; border: string }> = {
  diamond: { bg: 'bg-cyan-500/15', text: 'text-cyan-400', border: 'border-cyan-500/30' },
  platinum: { bg: 'bg-purple-500/15', text: 'text-purple-400', border: 'border-purple-500/30' },
  gold: { bg: 'bg-amber-500/15', text: 'text-amber-400', border: 'border-amber-500/30' },
  silver: { bg: 'bg-slate-400/15', text: 'text-slate-300', border: 'border-slate-400/30' },
  bronze: { bg: 'bg-orange-500/15', text: 'text-orange-400', border: 'border-orange-500/30' },
};

const cache: Record<string, UserCardData> = {};

export default function UserCardPopup() {
  const [data, setData] = useState<UserCardData | null>(null);
  const [coords, setCoords] = useState<{ top: number; left: number }>({ top: 0, left: 0 });
  const [visible, setVisible] = useState(false);
  const [display, setDisplay] = useState(false);

  const hideTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const fetchTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const popupRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    function clearTimers() {
      if (hideTimerRef.current) {
        clearTimeout(hideTimerRef.current);
        hideTimerRef.current = null;
      }
      if (fetchTimerRef.current) {
        clearTimeout(fetchTimerRef.current);
        fetchTimerRef.current = null;
      }
    }

    function showCard(el: HTMLElement, username: string) {
      if (!username) return;
      if (hideTimerRef.current) {
        clearTimeout(hideTimerRef.current);
        hideTimerRef.current = null;
      }
      if (fetchTimerRef.current) {
        clearTimeout(fetchTimerRef.current);
      }

      fetchTimerRef.current = setTimeout(async () => {
        let cardData = cache[username];
        if (!cardData) {
          try {
            const json = await api.get<UserCardData>(`/user/card/${encodeURIComponent(username)}/`);
            if (json && !('error' in json)) {
              cache[username] = json;
              cardData = json;
            }
          } catch {
            return;
          }
        }

        if (!cardData) return;

        const rect = el.getBoundingClientRect();
        const popW = 280;
        const popH = 220;
        let left = rect.left + rect.width / 2 - popW / 2;
        let top = rect.bottom + 8;

        if (left < 8) left = 8;
        if (left + popW > window.innerWidth - 8) left = window.innerWidth - popW - 8;
        if (top + popH > window.innerHeight) top = rect.top - popH - 8;

        setData(cardData);
        setCoords({ top, left });
        setDisplay(true);
        requestAnimationFrame(() => {
          setVisible(true);
        });
      }, 350);
    }

    function hideCard() {
      if (fetchTimerRef.current) {
        clearTimeout(fetchTimerRef.current);
        fetchTimerRef.current = null;
      }
      hideTimerRef.current = setTimeout(() => {
        setVisible(false);
        setTimeout(() => {
          setDisplay(false);
          setData(null);
        }, 200);
      }, 200);
    }

    function onMouseEnter(e: MouseEvent) {
      const target = e.target;
      if (target instanceof Element) {
        const el = target.closest('[data-usercard]') as HTMLElement | null;
        if (el && el.dataset.usercard) {
          showCard(el, el.dataset.usercard);
        }
      }
    }

    function onMouseLeave(e: MouseEvent) {
      const target = e.target;
      if (target instanceof Element) {
        const el = target.closest('[data-usercard]') as HTMLElement | null;
        if (el) {
          hideCard();
        }
      }
    }

    document.addEventListener('mouseenter', onMouseEnter, true);
    document.addEventListener('mouseleave', onMouseLeave, true);

    return () => {
      clearTimers();
      document.removeEventListener('mouseenter', onMouseEnter, true);
      document.removeEventListener('mouseleave', onMouseLeave, true);
    };
  }, []);

  if (!display || !data) return null;

  const rankLevel = data.rank?.level || 'bronze';
  const rankName = data.rank?.name || 'Bronze';
  const rankTheme = RANK_CONFIG[rankLevel] || RANK_CONFIG.bronze;

  return (
    <div
      ref={popupRef}
      className={`user-card-popup ${visible ? 'visible' : ''}`}
      style={{
        top: coords.top,
        left: coords.left,
      }}
      onMouseEnter={() => {
        if (hideTimerRef.current) {
          clearTimeout(hideTimerRef.current);
          hideTimerRef.current = null;
        }
      }}
      onMouseLeave={() => {
        if (fetchTimerRef.current) {
          clearTimeout(fetchTimerRef.current);
          fetchTimerRef.current = null;
        }
        hideTimerRef.current = setTimeout(() => {
          setVisible(false);
          setTimeout(() => {
            setDisplay(false);
            setData(null);
          }, 200);
        }, 200);
      }}
    >
      <div className="flex items-center gap-3 mb-3">
        <div className="w-14 h-14 rounded-full bg-white/5 border-2 border-white/10 overflow-hidden flex items-center justify-center shrink-0">
          {data.avatar ? (
            <img src={data.avatar} alt="" className="w-full h-full object-cover rounded-full" />
          ) : (
            <span className="text-cyan-400 text-lg font-black">
              {(data.display_name || data.username || '?')[0].toUpperCase()}
            </span>
          )}
        </div>
        <div className="min-w-0">
          <div className="flex items-center gap-1">
            <span className="font-extrabold text-white text-sm truncate max-w-[140px]">
              {data.display_name || data.username}
            </span>
            {data.is_staff && (
              <i className="bi bi-patch-check-fill text-cyan-400 text-sm" />
            )}
          </div>
          <span
            className={`text-[10px] px-1.5 py-0.5 rounded font-black tracking-wider uppercase border inline-block mt-0.5 ${rankTheme.bg} ${rankTheme.text} ${rankTheme.border}`}
          >
            {rankName}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-1 text-[11px] text-white/50 font-medium">
        <div>Tham gia: <span className="text-white/80">{data.joined || '-'}</span></div>
        <div>Bài viết: <span className="text-white/80">{data.posts_count ?? 0}</span></div>
        <div>Bình luận: <span className="text-white/80">{data.comments_count ?? 0}</span></div>
        <div>Reaction: <span className="text-white/80">{data.reaction_score ?? 0}</span></div>
        <div>Điểm: <span className="text-white/80">{data.points ?? 0}</span></div>
      </div>

      <div className="flex gap-2 mt-2.5">
        <Link
          href={`/profile/@${data.username}/`}
          className="flex-1 text-center text-[10px] font-extrabold py-1.5 rounded-lg bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 uppercase tracking-wider hover:bg-cyan-500/25 transition-colors no-underline"
        >
          Xem hồ sơ
        </Link>
        <Link
          href={`/profile/@${data.username}/`}
          className="flex-1 text-center text-[10px] font-extrabold py-1.5 rounded-lg bg-white/5 text-white/60 border border-white/10 uppercase tracking-wider hover:bg-white/10 transition-colors no-underline"
        >
          Nhắn tin
        </Link>
      </div>
    </div>
  );
}

