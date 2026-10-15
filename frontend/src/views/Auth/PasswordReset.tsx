'use client';
import { useState } from 'react';
import type { FormEvent } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { api, ApiError } from '../../lib/api';
import { TurnstileWidget, getTsToken, resetTurnstile } from '../../components/ScanWidgets';
import PasswordResetConfirm from './PasswordResetConfirm';

const TURNSTILE_SITEKEY = (process.env.NEXT_PUBLIC_TURNSTILE_SITEKEY as string | undefined) || '';

function errMsg(e: unknown, fallback: string): string {
  if (e instanceof ApiError) {
    const d = e.data as { error?: string } | null;
    if (d && typeof d.error === 'string' && d.error) return d.error;
    return e.message || fallback;
  }
  if (e instanceof Error) return e.message || fallback;
  return fallback;
}

/* Port từ PKV/templates/account/password_reset.html (+ password_reset_done.html)
 * sang React/liquid-glass. Gọi API native thay cho server-rendered form Django Allauth:
 *   POST /auth/password/reset/  { email, cf-turnstile-response }  → luôn trả 200 (không lộ email tồn tại)
 * Trang này cũng là điểm vào của luồng xác nhận: nếu URL có uid/token/key thì render
 * PasswordResetConfirm (xem app/accounts/password/reset/confirm/). */
export default function PasswordReset() {
  const sp = useSearchParams();
  const hasConfirmCreds = Boolean(sp.get('uid') || sp.get('token') || sp.get('key'));
  if (hasConfirmCreds) return <PasswordResetConfirm />;
  return <PasswordResetRequest />;
}

function PasswordResetRequest() {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [sent, setSent] = useState(false);

  async function handleSubmit(e: FormEvent): Promise<void> {
    e.preventDefault();
    if (!email.trim()) {
      setError('Vui lòng nhập địa chỉ email');
      return;
    }
    const tsToken = getTsToken();
    if (TURNSTILE_SITEKEY && !tsToken) {
      setError('Vui lòng hoàn thành xác thực captcha');
      return;
    }
    setLoading(true);
    setError('');
    try {
      await api.post('/auth/password/reset/', {
        email: email.trim(),
        'cf-turnstile-response': tsToken,
      });
      setSent(true);
    } catch (err) {
      setError(errMsg(err, 'Không thể gửi yêu cầu đặt lại mật khẩu.'));
    } finally {
      setLoading(false);
      resetTurnstile();
    }
  }

  /* password_reset_done.html */
  if (sent) {
    return (
      <div className="animate-fadein max-w-md mx-auto pt-16 sm:pt-20 pb-20 px-4 space-y-8 text-center">
        <div className="liquid-card p-8 sm:p-10 space-y-6">
          <div className="inline-flex items-center justify-center w-20 h-20 rounded-[2.5rem] bg-warn-500/10 text-warn-400 border border-warn-500/20 shadow-lg shadow-warn-500/10">
            <i className="bi bi-envelope-check-fill text-4xl"></i>
          </div>
          <h1 className="text-2xl font-black text-white tracking-tight">Kiểm tra email của bạn</h1>
          <p className="text-white/55 text-sm font-medium leading-relaxed">
            Nếu địa chỉ email tồn tại trong hệ thống, chúng tôi đã gửi liên kết đặt lại mật khẩu.
          </p>
          <Link
            href="/login/"
            className="liquid-btn w-full py-4 bg-white/5 border border-white/10 text-white font-black uppercase tracking-[0.2em] text-sm hover:bg-white/10 transition-all"
          >
            Quay lại đăng nhập
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="animate-fadein max-w-md mx-auto pt-16 sm:pt-20 pb-20 px-4 space-y-8">
      <div className="text-center space-y-3">
        <div
          className="inline-flex items-center justify-center w-20 h-20 rounded-[2.5rem] bg-brand-500/10 text-brand-400 border border-brand-500/20 shadow-lg shadow-brand-500/10 mb-2"
        >
          <i className="bi bi-key-fill text-4xl"></i>
        </div>
        <h1 className="text-3xl font-black text-white tracking-tight leading-none">
          Quên mật khẩu
        </h1>
        <p className="text-white/55 text-sm font-medium tracking-wide">
          Nhập email để nhận liên kết đặt lại mật khẩu
        </p>
      </div>

      <div className="liquid-card p-8 sm:p-10">
        <form onSubmit={handleSubmit} className="space-y-6">
          {error && (
            <div className="rounded-2xl border border-danger-500/30 bg-danger-500/10 p-3 text-sm text-danger-300">{error}</div>
          )}

          <div className="space-y-2">
            <label className="text-[11px] font-black text-white/45 uppercase tracking-[0.2em] ml-2">Email</label>
            <input
              type="email"
              className="liquid-input w-full py-4 px-6 text-sm font-bold"
              placeholder="email@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>

          <TurnstileWidget />

          <button
            type="submit"
            className="liquid-btn w-full py-5 bg-brand-500 text-black font-black uppercase tracking-[0.2em] text-sm hover:bg-brand-400 transition-all shadow-lg shadow-brand-500/20"
            disabled={loading}
          >
            {!loading ? (
              <span>Gửi liên kết đặt lại</span>
            ) : (
              <span className="flex items-center justify-center gap-2">
                <span className="spinner w-5 h-5 border-black"></span>
                <span className="text-xs">Đang xử lý...</span>
              </span>
            )}
          </button>
        </form>

        <div className="mt-8 pt-6 border-t border-white/5 text-center">
          <Link
            href="/login/"
            className="text-white/55 hover:text-brand-400 text-[11px] font-black uppercase tracking-widest transition-colors"
          >
            Quay lại đăng nhập
          </Link>
        </div>
      </div>
    </div>
  );
}
