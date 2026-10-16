'use client';
import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import Link from 'next/link';
import { api, ApiError } from '../../lib/api';

/* Port từ PKV/templates/Auth/change_password.html.
 * Bản gốc là form POST Django classic; bản React dùng API đã có:
 * POST /auth/password/change/ {old_password, new_password, token}
 * với OTP lấy qua GET /auth/mfa/setup/email/ (y flow passwordManager trong profile.html). */
export default function ChangePassword() {
  const [oldPassword, setOldPassword] = useState('');
  const [new1, setNew1] = useState('');
  const [new2, setNew2] = useState('');
  const [token, setToken] = useState('');
  const [loading, setLoading] = useState(false);
  const [otpLoading, setOtpLoading] = useState(false);
  const [countdown, setCountdown] = useState(0);
  const [error, setError] = useState('');
  const [done, setDone] = useState('');

  useEffect(() => {
    if (countdown <= 0) return;
    const t = setInterval(() => setCountdown((c) => (c <= 1 ? 0 : c - 1)), 1000);
    return () => clearInterval(t);
  }, [countdown]);

  async function sendOtp(): Promise<void> {
    if (countdown > 0) return;
    setOtpLoading(true);
    setError('');
    try {
      await api.get('/auth/mfa/setup/email/');
      setCountdown(120);
    } catch (e) {
      if (e instanceof ApiError) {
        const d = e.data as { error?: string } | null;
        setError((d && d.error) || 'Không thể gửi mã OTP. Vui lòng thử lại.');
      } else {
        setError('Lỗi kết nối');
      }
    } finally {
      setOtpLoading(false);
    }
  }

  async function submit(e: FormEvent): Promise<void> {
    e.preventDefault();
    if (!oldPassword || !new1 || !new2) {
      setError('Vui lòng điền đầy đủ thông tin');
      return;
    }
    if (new1 !== new2) {
      setError('Mật khẩu xác nhận không khớp');
      return;
    }
    if (new1.length < 8) {
      setError('Mật khẩu mới phải có ít nhất 8 ký tự');
      return;
    }
    if (token.trim().length < 6) {
      setError('Vui lòng nhập mã OTP Email (6 số)');
      return;
    }
    setLoading(true);
    setError('');
    setDone('');
    try {
      const d = await api.post<{ token?: string }>('/auth/password/change/', {
        old_password: oldPassword,
        new_password: new1,
        token: token.trim(),
      });
      /* Backend xoay DRF token khi đổi mật khẩu — lưu token mới kẻo bị văng. */
      if (d.token) setToken(d.token);
      setDone('Đổi mật khẩu thành công!');
      setOldPassword('');
      setNew1('');
      setNew2('');
      setToken('');
    } catch (e) {
      if (e instanceof ApiError) {
        const d = e.data as { error?: string } | null;
        setError((d && d.error) || 'Lỗi khi đổi mật khẩu');
      } else {
        setError('Lỗi hệ thống');
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-md mx-auto px-4 pt-16 sm:pt-20 pb-20">
      <div className="animate-fadein mb-8 text-center">
        <i className="bi bi-shield-lock-fill text-rose-500 text-5xl"></i>
        <h1 className="text-2xl font-extrabold mt-3">
          <span className="glow-text">Đổi mật khẩu</span>
        </h1>
      </div>

      <div className="glass-card animate-fadein p-6 sm:p-8">
        <form onSubmit={submit}>
          <div className="grid gap-5">
            <div>
              <label className="text-xs font-semibold text-white/60 block mb-1.5">
                Mật khẩu hiện tại
              </label>
              <input
                type="password"
                className="glass-input w-full"
                placeholder="Nhập mật khẩu hiện tại"
                required
                value={oldPassword}
                onChange={(e) => setOldPassword(e.target.value)}
              />
            </div>
            <div>
              <label className="text-xs font-semibold text-white/60 block mb-1.5">
                Mật khẩu mới
              </label>
              <input
                type="password"
                className="glass-input w-full"
                placeholder="Nhập mật khẩu mới (8+ ký tự)"
                required
                minLength={8}
                value={new1}
                onChange={(e) => setNew1(e.target.value)}
              />
            </div>
            <div>
              <label className="text-xs font-semibold text-white/60 block mb-1.5">
                Xác nhận mật khẩu mới
              </label>
              <input
                type="password"
                className="glass-input w-full"
                placeholder="Nhập lại mật khẩu mới"
                required
                minLength={8}
                value={new2}
                onChange={(e) => setNew2(e.target.value)}
              />
            </div>
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-xs font-semibold text-white/60 block">
                  Mã OTP Email
                </label>
                <button
                  type="button"
                  onClick={sendOtp}
                  disabled={otpLoading || countdown > 0}
                  className="text-[10px] font-black text-cyan-400 uppercase tracking-widest hover:underline disabled:opacity-50 disabled:no-underline"
                >
                  {otpLoading ? (
                    <span>Đang gửi...</span>
                  ) : countdown > 0 ? (
                    <span>{`Gửi lại sau ${Math.floor(countdown / 60)}:${String(countdown % 60).padStart(2, '0')}`}</span>
                  ) : (
                    <span>Gửi mã OTP</span>
                  )}
                </button>
              </div>
              <input
                type="text"
                className="glass-input w-full text-center text-lg tracking-[0.45em] font-black"
                placeholder="••••••"
                maxLength={6}
                value={token}
                onChange={(e) => setToken(e.target.value)}
              />
            </div>
          </div>

          <div className="mt-6 flex gap-3">
            <Link href="/profile/" className="glass-btn px-6 py-2.5 text-sm font-semibold">
              <i className="bi bi-arrow-left mr-1.5"></i> Quay lại
            </Link>
            <button
              type="submit"
              className="glass-btn flex-1 justify-center px-6 py-2.5 text-sm font-semibold bg-cyan-500/20 border-cyan-500/40 hover:bg-cyan-500/30"
              disabled={loading}
            >
              <i className="bi bi-key-fill mr-1.5"></i> {loading ? 'Đang xử lý...' : 'Đổi mật khẩu'}
            </button>
          </div>
        </form>

        {error && (
          <div className="mt-4 p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs flex items-center gap-2">
            <i className="bi bi-exclamation-triangle-fill text-sm shrink-0"></i>
            <span>{error}</span>
          </div>
        )}
        {done && (
          <div className="mt-4 p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs flex items-center gap-2">
            <i className="bi bi-check-circle-fill text-sm shrink-0"></i>
            <span>{done}</span>
          </div>
        )}
      </div>
    </div>
  );
}
