'use client';

import { useEffect, useRef } from 'react';
import { useAuth } from '@/components/AuthContext';
import { authApi, setToken } from '@/lib/api';

export default function LogoutPage() {
  const { logout } = useAuth();
  const executedRef = useRef(false);

  useEffect(() => {
    if (executedRef.current) return;
    executedRef.current = true;

    const doLogout = async () => {
      try {
        await logout();
      } catch {
        try {
          await authApi.logout();
        } catch {
          /* ignore */
        }
      } finally {
        setToken(null);
        window.location.href = '/login/?logged_out=1';
      }
    };

    doLogout();
  }, [logout]);

  return (
    <div className="min-h-[60vh] flex items-center justify-center text-white/50 text-sm">
      <div className="flex items-center gap-3">
        <i className="bi bi-arrow-repeat animate-spin text-brand-400 text-lg"></i>
        <span>Đang đăng xuất...</span>
      </div>
    </div>
  );
}
