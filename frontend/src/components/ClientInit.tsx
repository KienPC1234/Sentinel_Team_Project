'use client';

import { useEffect } from 'react';

export function PwaInit() {
  useEffect(() => {
    // Chỉ đăng ký Service Worker trên client, tránh ảnh hưởng SSR
    import('../pwa').then(({ ShieldCallPWA }) => {
      ShieldCallPWA.init();
    }).catch(() => {});
  }, []);
  return null;
}

/** Đổi ngôn ngữ qua Google Translate cookie (y cơ chế bản gốc). */
export function changeLanguage(lang: string): void {
  try {
    if (lang === 'vi') {
      for (const domain of ['', `;domain=${window.location.hostname}`, `;domain=.${window.location.hostname}`]) {
        document.cookie = `googtrans=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/${domain}`;
      }
      window.location.reload();
      return;
    }
    document.cookie = `googtrans=/vi/${lang}; path=/`;
    document.cookie = `googtrans=/vi/${lang}; path=/;domain=.${window.location.hostname}`;
    try {
      localStorage.setItem('preferred_language', lang);
    } catch {
      /* ignore */
    }
    window.location.reload();
  } catch {
    /* ignore */
  }
}
