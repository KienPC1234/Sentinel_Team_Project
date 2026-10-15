'use client';

import { usePathname } from 'next/navigation';
import type { ReactNode } from 'react';
import { Navbar, Footer } from '@/components/Layout';
import ChatWidget from '@/components/ChatWidget';
import UserCardPopup from '@/components/UserCardPopup';

export function LayoutShell({ children }: { children: ReactNode }) {
  const pathname = usePathname() || '';
  const isAssistant = pathname.startsWith('/ai-assistant');

  if (isAssistant) {
    return (
      // 100dvh (fallback h-screen) để không bị thanh địa chỉ của trình duyệt mobile che mất composer.
      <main className="h-screen w-screen overflow-hidden" style={{ height: '100dvh' }}>
        {children}
      </main>
    );
  }

  return (
    <div className="min-h-screen flex flex-col">
      <div className="mesh-bg" />
      <Navbar />
      <main className="flex-1">{children}</main>
      <Footer />
      <ChatWidget />
      <UserCardPopup />
    </div>
  );
}

