'use client';
import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import Link from 'next/link';
import { useParams, useSearchParams } from 'next/navigation';
import { api, ApiError } from '../../lib/api';

/* Port từ PKV/templates/account/password_reset_from_key.html
 * (+ password_reset_from_key_done.html) sang React/liquid-glass.
 * Gọi API native thay cho form server-rendered của Django Allauth:
 *   POST /auth/password/reset/confirm/  { uid, token, password1, password2 }
 * Token lấy từ:
 *   - query string: ?uid=...&token=...  (luồng native)
 *   - path Allauth: /accounts/password/reset/key/<uidb36>-<key>/  (link email cũ)
 *   - query ?key=<uidb36>-<key>  (tương thích ngược)
 */

interface Creds {
  uid: string;
  token: string;
}

/** Tách "<uidb36>-<key>" của Allauth (base36 không chứa dấu gạch). */
function splitKey(key: string): Creds {
  const dash = key.indexOf('-');
  if (dash > 0) return { uid: key.slice(0, dash), token: key.slice(dash + 1) };
  return { uid: '', token: key };
}

function fromRouteParams(params: unknown): Creds {
  if (!params || typeof params !== 'object') return { uid: '', token: '' };
  const slug = (params as { slug?: unknown }).slug;
  const segs = Array.isArray(slug) ? slug : typeof slug === 'string' ? [slug] : [];
  const last = segs.filter(Boolean).pop() || '';
  return last ? splitKey(last) : { uid: '', token: '' };
}

function parseCreds(sp: { get(name: string): string | null }, params: unknown): Creds {
  const uid = (sp.get('uid') || '').trim();
  const token = (sp.get('token') || '').trim();
  if (uid && token) return { uid, token };

  const key = (sp.get('key') || '').trim();
  if (key) return splitKey(key);

  return fromRouteParams(params);
}

function errMsg(e: unknown, fallback: string): string {
  if (e instanceof ApiError) {
    const d = e.data as { error?: string } | null;
    if (d && typeof d.error === 'string' && d.error) return d.error;
    return e.message || fallback;
  }
  if (e instanceof Error) return e.message || fallback;
  return fallback;
}

export default function PasswordResetConfirm() {
  const sp = useSearchParams();
  const routeParams = useParams();
  const { uid, token } = parseCreds(sp, routeParams);

  const [password1, setPassword1] = useState('');
  const [password2, setPassword2] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [done, setDone] = useState(false);
  const [linkInvalid, setLinkInvalid] = useState(!uid && !token);

  useEffect(() => {
    if (!done) return;
    const t = setTimeout(() => {
      window.location.href = '/login/';
    }, 1800);
    return () => clearTimeout(t);
  }, [done]);

  async function handleSubmit(e: FormEvent): Promise<void> {
    e.preventDefault();
    if (!uid && !token) {
      setLinkInvalid(true);
      return;
    }
    if (!password1 || !password2) {
      setError('Vui lòng nhập đầy đủ mật khẩu mới');
      return;
    }
    if (password1.length < 8) {
      setError('Mật khẩu mới phải có ít nhất 8 ký tự');
      return;
    }
    if (password1 !== password2) {
      setError('Mật khẩu xác nhận không khớp');
      return;
    }
    setLoading(true);
    setError('');
    try {
      await api.post('/auth/password/reset/confirm/', { uid, token, password1, password2 });
      setDone(true);
    } catch (err) {
      if (err instanceof ApiError) {
        const d = err.data as { token_fail?: boolean } | null;
        if (d && d.token_fail) {
          setLinkInvalid(true);
        } else {
          setError(errMsg(err, 'Không thể đặt lại mật khẩu. Liên kết có thể đã hết hạn.'));
        }
      } else {
        setError('Lỗi kết nối. Vui lòng thử lại.');
      }
    } finally {
      setLoading(false);
    }
  }

  const header = (
    <div className="text-center space-y-3">
      <div
        className="inline-flex items-center justify-center w-20 h-20 rounded-[2.5rem] bg-brand-500/10 text-brand-400 border border-brand-500/20 shadow-lg shadow-brand-500/10 mb-2"
      >
        <i className="bi bi-shield-lock-fill text-4xl"></i>
      </div>
      <h1 className="text-3xl font-black text-white tracking-tight leading-none">
        Đặt lại mật khẩu
      </h1>
      <p className="text-white/55 text-sm font-medium tracking-wide">
        Nhập mật khẩu mới để hoàn tất khôi phục tài khoản
      </p>
    </div>
  );

  /* password_reset_from_key_done.html */
  if (done) {
    return (
      <div className="animate-fadein max-w-md mx-auto pt-16 sm:pt-20 pb-20 px-4 space-y-8 text-center">
        <div className="liquid-card p-8 sm:p-10 space-y-6">
          <div className="inline-flex items-center justify-center w-20 h-20 rounded-[2.5rem] bg-safe-500/10 text-safe-400 border border-safe-500/20 shadow-lg shadow-safe-500/10">
            <i className="bi bi-check-circle-fill text-4xl"></i>
          </div>
          <h1 className="text-2xl font-black text-white tracking-tight">Mật khẩu đã được cập nhật</h1>
          <p className="text-white/55 text-sm font-medium leading-relaxed">
            Bạn có thể đăng nhập lại bằng mật khẩu mới.
          </p>
          <Link
            href="/login/"
            className="liquid-btn w-full py-4 bg-brand-500 text-black font-black uppercase tracking-[0.2em] text-sm hover:bg-brand-400 transition-all"
          >
            Đăng nhập ngay
          </Link>
        </div>
      </div>
    );
  }

  /* token_fail branch trong password_reset_from_key.html */
  if (linkInvalid) {
    return (
      <div className="animate-fadein max-w-md mx-auto pt-16 sm:pt-20 pb-20 px-4 space-y-8">
        {header}
        <div className="liquid-card p-8 sm:p-10">
          <div className="space-y-4 text-center">
            <p className="text-danger-400 text-sm font-bold">
              Liên kết đặt lại mật khẩu không hợp lệ hoặc đã hết hạn.
            </p>
            <Link
              href="/accounts/password/reset/"
              className="liquid-btn w-full py-4 bg-brand-500 text-black font-black uppercase tracking-[0.2em] text-sm hover:bg-brand-400 transition-all"
            >
              Gửi lại liên kết mới
            </Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="animate-fadein max-w-md mx-auto pt-16 sm:pt-20 pb-20 px-4 space-y-8">
      {header}

      <div className="liquid-card p-8 sm:p-10">
        <form onSubmit={handleSubmit} className="space-y-6">
          {error && (
            <div className="rounded-2xl border border-danger-500/30 bg-danger-500/10 p-3 text-sm text-danger-300">{error}</div>
          )}

          <div className="space-y-2">
            <label className="text-[11px] font-black text-white/45 uppercase tracking-[0.2em] ml-2">Mật khẩu mới</label>
            <input
              type="password"
              autoComplete="new-password"
              className="liquid-input w-full py-4 px-6 text-sm font-bold"
              placeholder="••••••••"
              value={password1}
              onChange={(e) => setPassword1(e.target.value)}
              required
            />
          </div>

          <div className="space-y-2">
            <label className="text-[11px] font-black text-white/45 uppercase tracking-[0.2em] ml-2">
              Xác nhận mật khẩu mới
            </label>
            <input
              type="password"
              autoComplete="new-password"
              className="liquid-input w-full py-4 px-6 text-sm font-bold"
              placeholder="••••••••"
              value={password2}
              onChange={(e) => setPassword2(e.target.value)}
              required
            />
          </div>

          <button
            type="submit"
            className="liquid-btn w-full py-5 bg-brand-500 text-black font-black uppercase tracking-[0.2em] text-sm hover:bg-brand-400 transition-all shadow-lg shadow-brand-500/20"
            disabled={loading}
          >
            {!loading ? (
              <span>Cập nhật mật khẩu</span>
            ) : (
              <span className="flex items-center justify-center gap-2">
                <span className="spinner w-5 h-5 border-black"></span>
                <span className="text-xs">Đang xử lý...</span>
              </span>
            )}
          </button>
        </form>
      </div>
    </div>
  );
}
