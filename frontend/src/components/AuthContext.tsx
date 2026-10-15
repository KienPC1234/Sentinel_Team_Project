'use client';
import { createContext, useContext, useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { authApi, setToken } from '../lib/api';
import type { Me } from '../lib/api';

interface AuthCtx {
  user: Me | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const Ctx = createContext<AuthCtx>({ user: null, loading: true, login: async () => {}, logout: async () => {} });

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    /* Luôn hỏi /auth/me/ (kể cả không có token): đăng nhập Google/OAuth dùng
     * session cookie, không có DRF token ban đầu trong localStorage. */
    authApi
      .me()
      .then((d) => {
        if (d.token) {
          setToken(d.token);
        }
        setUser(d.user);
      })
      .catch(() => {
        setToken(null);
        setUser(null);
      })
      .finally(() => setLoading(false));
  }, []);

  const login = async (username: string, password: string) => {
    const data = await authApi.login(username, password);
    const token = data.token || data.key;
    if (!token) throw new Error('Đăng nhập thất bại: không nhận được token');
    setToken(token);
    const meData = await authApi.me();
    setUser(meData.user);
    if (meData.token) {
      setToken(meData.token);
    }
  };

  const logout = async () => {
    try {
      await authApi.logout();
    } catch {
      /* ignore */
    } finally {
      setToken(null);
      setUser(null);
    }
  };

  return <Ctx.Provider value={{ user, loading, login, logout }}>{children}</Ctx.Provider>;
}

export function useAuth(): AuthCtx {
  return useContext(Ctx);
}
