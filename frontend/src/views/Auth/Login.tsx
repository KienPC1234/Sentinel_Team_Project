'use client';
import { useEffect, useState } from 'react';

import type { FormEvent } from 'react';
import Link from 'next/link';

import { useSearchParams } from 'next/navigation';

import { useAuth } from '../../components/AuthContext';
import { api, setToken, ApiError } from '../../lib/api';




const TURNSTILE_SITEKEY = (process.env.NEXT_PUBLIC_TURNSTILE_SITEKEY as string | undefined) || '';

interface MfaMethods {
  totp?: boolean;
  email?: boolean;
  recovery?: boolean;
}

interface LoginResp {
  token?: string;
  key?: string;
  mfa_required?: boolean;
  methods?: MfaMethods;
  preferred_method?: string | null;
  error?: string;
}

interface MfaVerifyResp {
  token?: string;
  key?: string;
  error?: string;
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

function resetTurnstile(): void {
  const w = window as unknown as { turnstile?: { reset: () => void } };
  try {
    w.turnstile?.reset();
  } catch {
    /* ignore */
  }
}

function readTurnstileToken(): string {
  return document.querySelector<HTMLInputElement>('[name=cf-turnstile-response]')?.value || '';
}

/* Port từ PKV/templates/Auth/login.html — giữ nguyên text + class Tailwind. */
export default function Login() {
  const { user } = useAuth();
  const params = useSearchParams();
  const next = params.get('next') || '';
  const fromRegister = params.get('from') === 'register';
  const oauthError = params.get('error') || '';
  const isLoggedOut = params.get('logged_out') === '1';

  /* Thông báo khi OAuth/allauth chuyển về (ví dụ email đã tồn tại, hủy đăng nhập). */
  const OAUTH_ERRORS: Record<string, string> = {
    social_signup:
      'Email Google này đã gắn với tài khoản khác. Hãy đăng nhập bằng email/mật khẩu rồi liên kết Google trong hồ sơ.',
    cancelled: 'Bạn đã hủy đăng nhập bằng Google. Hãy thử lại khi sẵn sàng.',
    social: 'Đăng nhập Google thất bại. Vui lòng thử lại hoặc dùng email/mật khẩu.',
  };
  const oauthErrorMsg = OAUTH_ERRORS[oauthError] || (oauthError ? 'Đăng nhập mạng xã hội thất bại. Vui lòng thử lại.' : '');

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [welcome, setWelcome] = useState('');

  const [show2fa, setShow2fa] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [mfaToken, setMfaToken] = useState('');
  const [mfaMethods, setMfaMethods] = useState<MfaMethods>({});
  const [mfaMethod, setMfaMethod] = useState('totp');
  const [canUseRecovery, setCanUseRecovery] = useState(false);
  const [useRecovery, setUseRecovery] = useState(false);
  const [mfaError, setMfaError] = useState('');

  /* Toast chào sau khi đăng ký (bản gốc đọc sessionStorage). */
  useEffect(() => {
    if (fromRegister) {
      try {
        const msg =
          sessionStorage.getItem('register_welcome_message') || 'Xin chào! Tài khoản đã tạo thành công.';
        setWelcome(msg);
        sessionStorage.removeItem('register_welcome_message');
      } catch {
        setWelcome('Xin chào! Tài khoản đã tạo thành công.');
      }
    }
  }, [fromRegister]);

  /* Nếu đã đăng nhập thì về dashboard (y hành vi login_view Django). */
  useEffect(() => {
    if (user && !isLoggedOut) {
      const target = next && next.startsWith('/') && !next.startsWith('//') ? next : '/dashboard/';
      window.location.href = target;
    }
  }, [user, next, isLoggedOut]);

  /* Nạp Cloudflare Turnstile (bản gốc dùng {{ TURNSTILE_SITEKEY }}). */
  useEffect(() => {
    if (!TURNSTILE_SITEKEY) return;
    if (document.querySelector('script[data-turnstile]')) return;
    const s = document.createElement('script');
    s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
    s.async = true;
    s.defer = true;
    s.setAttribute('data-turnstile', '1');
    document.body.appendChild(s);
  }, []);

  function gotoNext(): void {
    const target = next && next.startsWith('/') && !next.startsWith('//') ? next : '/dashboard/';
    window.location.href = target;
  }


  async function resendEmail(): Promise<void> {
    try {
      await api.get('/auth/mfa/setup/email/');
    } catch {
      /* ignore — bản gốc cũng bỏ qua lỗi gửi lại */
    }
  }

  async function verifyMfa(methodOverride?: string): Promise<void> {
    const activeMethod = methodOverride || (useRecovery ? 'recovery' : mfaMethod);
    if (activeMethod === 'recovery' && mfaToken.replace(/[^A-Za-z0-9]/g, '').length < 8) return;
    if (activeMethod !== 'recovery' && mfaToken.length < 6) return;
    setLoading(true);
    try {
      const data = await api.post<MfaVerifyResp>('/auth/mfa/verify/', {
        token: mfaToken,
        method: activeMethod,
      });
      const token = data.token || data.key;
      if (!token) throw new Error('Đăng nhập thất bại: không nhận được token');
      setToken(token);
      gotoNext();
    } catch (e) {
      setMfaError(errMsg(e, 'Mã xác nhận không đúng'));
      setLoading(false);
    }
  }

  async function handleLogin(e: FormEvent): Promise<void> {
    e.preventDefault();
    if (!email.trim() || !password.trim()) {
      setError('Vui lòng điền đầy đủ thông tin');
      return;
    }
    const tsToken = readTurnstileToken();
    if (TURNSTILE_SITEKEY && !tsToken) {
      setError('Vui lòng hoàn thành captcha bảo mật');
      return;
    }
    setLoading(true);
    setError('');
    try {
      const data = await api.post<LoginResp>('/auth/login/', {
        email: email.trim(),
        password,
        'cf-turnstile-response': tsToken,
      });
      if (data.mfa_required) {
        const methods = data.methods || {};
        setShow2fa(true);
        setMfaMethods(methods);
        setMfaMethod(data.preferred_method || (methods.totp ? 'totp' : 'email'));
        setCanUseRecovery(!!methods.recovery);
        setUseRecovery(false);
        setMfaToken('');
        setMfaError('');
        if ((data.preferred_method || (methods.totp ? 'totp' : 'email')) === 'email') {
          void resendEmail();
        }
        setLoading(false);
      } else {
        const token = data.token || data.key;
        if (!token) throw new Error('Đăng nhập thất bại: không nhận được token');
        setToken(token);
        gotoNext();
      }
    } catch (err) {
      setError(errMsg(err, 'Email hoặc mật khẩu không đúng'));
      setLoading(false);
    } finally {
      resetTurnstile();
    }
  }

  const googleNext = next ? `&next=${encodeURIComponent(next)}` : '';

  return (
    <div className="relative animate-fadein max-w-xl mx-auto pt-16 sm:pt-20 pb-20 px-4 space-y-8">
      <div className="pointer-events-none absolute -top-6 -left-8 w-40 h-40 rounded-full bg-brand-500/10 blur-3xl"></div>
      <div className="pointer-events-none absolute -bottom-8 -right-6 w-44 h-44 rounded-full bg-brand2-500/10 blur-3xl"></div>

      <div className="text-center space-y-3">
        <div
          className="inline-flex items-center justify-center w-20 h-20 rounded-[2.5rem] bg-brand-500/10 text-brand-400 border border-brand-500/20 shadow-lg shadow-brand-500/10 mb-2"
        >
          <i className="bi bi-shield-lock-fill text-4xl leading-none"></i>
        </div>
        <h1 className="text-3xl font-black text-white tracking-tight leading-none">
          Vào ShieldCall
        </h1>
        <p className="text-white/55 text-sm font-medium tracking-wide">
          Bảo mật thông tin, bảo vệ cộng đồng
        </p>
      </div>

      <div
        className="liquid-card p-8 sm:p-10 border border-brand-400/15 bg-white/[0.03] backdrop-blur-2xl shadow-2xl shadow-brand-500/10"
      >
        {isLoggedOut && !welcome && (
          <div className="mb-6 rounded-2xl border border-safe-500/20 bg-safe-500/5 px-4 py-3 text-[11px] font-bold text-safe-300 flex items-center gap-2">
            <i className="bi bi-check-circle-fill shrink-0"></i>
            <span>Đã đăng xuất thành công khỏi hệ thống.</span>
          </div>
        )}
        {welcome && (
          <div className="mb-6 rounded-2xl border border-safe-500/20 bg-safe-500/5 px-4 py-3 text-[11px] font-bold text-safe-300">
            {welcome}
          </div>
        )}
        {oauthErrorMsg && (
          <div className="mb-6 rounded-2xl border border-warn-500/30 bg-warn-500/10 px-4 py-3 text-[11px] font-bold text-warn-300 flex items-start gap-2">
            <i className="bi bi-exclamation-triangle-fill mt-0.5 shrink-0"></i>
            <span>{oauthErrorMsg}</span>
          </div>
        )}

        <a
          href={`/accounts/google/login/?process=login${googleNext}`}
          className="liquid-btn w-full flex items-center justify-center gap-3 py-4 mb-8 bg-white/5 border-white/10 hover:bg-white/10 text-sm font-bold tracking-wide transition-all group"
        >
          <svg className="w-5 h-5 group-hover:scale-110 transition-transform" viewBox="0 0 48 48">
            <path
              fill="var(--sc-google-red)"
              d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"
            />
            <path
              fill="var(--sc-google-blue)"
              d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"
            />
            <path
              fill="var(--sc-google-yellow)"
              d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"
            />
            <path
              fill="var(--sc-google-green)"
              d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.31-8.16 2.31-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"
            />
          </svg>
          <span className="text-white/90 uppercase text-[11px] font-black tracking-widest">Tiếp tục với Google</span>
        </a>

        <div className="flex items-center gap-4 mb-8">
          <div className="flex-1 h-px bg-white/5"></div>
          <span className="text-[10px] font-black text-white/35 uppercase tracking-[0.2em]">Hoặc email</span>
          <div className="flex-1 h-px bg-white/5"></div>
        </div>

        {!show2fa && (
          <form onSubmit={handleLogin} className="space-y-6">
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

            <div className="space-y-2">
              <div className="flex justify-between items-center ml-2">
                <label className="text-[11px] font-black text-white/45 uppercase tracking-[0.2em]">Mật khẩu</label>
                <a
                  href="/accounts/password/reset/"
                  className="text-[10px] font-black text-brand-400/60 hover:text-brand-400 uppercase tracking-widest transition-colors"
                >
                  Quên mật khẩu?
                </a>
              </div>

              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  className="liquid-input w-full py-4 px-6 pr-14 text-sm font-bold"
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? 'Ẩn mật khẩu' : 'Hiện mật khẩu'}
                  className="absolute right-4 top-1/2 -translate-y-1/2 text-white/35 hover:text-white/70 transition-colors"
                >
                  <i className={`bi ${showPassword ? 'bi-eye-slash' : 'bi-eye'}`}></i>
                </button>
              </div>
            </div>

            <div className="flex justify-center py-2">
              {TURNSTILE_SITEKEY ? (
                <div className="cf-turnstile" data-sitekey={TURNSTILE_SITEKEY}></div>
              ) : (
                <p className="text-[10px] text-warn-300/70 font-bold uppercase tracking-widest">
                  Chưa cấu hình NEXT_PUBLIC_TURNSTILE_SITEKEY
                </p>
              )}
            </div>

            <button
              type="submit"
              className="liquid-btn w-full py-5 bg-brand-500 text-black font-black uppercase tracking-[0.2em] text-sm hover:bg-brand-400 transition-all shadow-lg shadow-brand-500/20"
              disabled={loading}
            >
              {!loading ? (
                <span>ĐĂNG NHẬP</span>
              ) : (
                <span className="flex items-center justify-center gap-2">
                  <span className="spinner w-5 h-5 border-black"></span>
                  <span className="text-xs">XÁC THỰC...</span>
                </span>
              )}
            </button>

            {error && (
              <p className="text-danger-400 text-[11px] font-bold text-center animate-pulse uppercase tracking-wider">
                {error}
              </p>
            )}
          </form>
        )}

        {show2fa && (
          <div className="space-y-8 animate-fadein">
            <div className="space-y-2 text-center">
              <h3 className="text-sm font-black text-white uppercase tracking-widest">Xác thực 2 lớp</h3>
              <p className="text-[10px] text-white/55 font-bold uppercase tracking-widest">
                Nhập mã xác nhận để tiếp tục
              </p>
            </div>

            <div className="space-y-4">
              <div className="space-y-2 text-center">
                {mfaMethod === 'totp' && !useRecovery && (
                  <p className="text-[11px] text-white/60 font-medium">Mở ứng dụng Authenticator của bạn</p>
                )}
                {mfaMethod === 'email' && (
                  <p className="text-[11px] text-white/60 font-medium">
                    Kiểm tra hòm thư <span>{email}</span>
                  </p>
                )}
                {useRecovery && (
                  <p className="text-[11px] text-warn-300/80 font-semibold">Đang dùng recovery code dự phòng</p>
                )}

                <input
                  type="text"
                  value={mfaToken}
                  maxLength={useRecovery ? 9 : 6}
                  autoFocus
                  onChange={(e) => setMfaToken(e.target.value)}
                  onKeyUp={() => {
                    if (
                      (!useRecovery && mfaToken.length === 6) ||
                      (useRecovery && mfaToken.replace(/[^A-Za-z0-9]/g, '').length >= 8)
                    )
                      void verifyMfa();
                  }}
                  className="liquid-input w-full py-5 text-center text-3xl font-black tracking-[0.5em] placeholder:tracking-normal"
                  placeholder={useRecovery ? 'ABCD-EFGH' : '••••••'}
                />
              </div>

              {mfaMethod === 'totp' && canUseRecovery && (
                <div className="text-center">
                  <button
                    type="button"
                    onClick={() => {
                      setUseRecovery(!useRecovery);
                      setMfaToken('');
                      setMfaError('');
                    }}
                    className="text-[10px] font-black uppercase tracking-widest text-brand-400/70 hover:text-brand-300 transition-colors"
                  >
                    {!useRecovery ? 'Không vào được app? Dùng recovery code' : 'Quay lại nhập mã TOTP'}
                  </button>
                </div>
              )}

              {mfaMethod === 'email' && (
                <div className="text-center">
                  <button
                    type="button"
                    onClick={() => void resendEmail()}
                    className="text-[10px] font-black uppercase tracking-widest text-brand-400/70 hover:text-brand-300 transition-colors"
                  >
                    Gửi lại mã OTP email
                  </button>
                </div>
              )}

              <div className="flex flex-col gap-3">
                <button
                  type="button"
                  onClick={() => void verifyMfa()}
                  disabled={loading}
                  className="liquid-btn w-full py-5 bg-brand-500 text-black font-black uppercase tracking-[0.2em] shadow-lg shadow-brand-500/20"
                >
                  {!loading ? <span>XÁC MINH</span> : <span className="spinner w-5 h-5 border-black"></span>}
                </button>

                <button
                  type="button"
                  onClick={() => {
                    setShow2fa(false);
                    setMfaToken('');
                    setError('');
                  }}
                  className="text-[10px] font-black text-white/35 hover:text-white/55 uppercase tracking-widest transition-colors py-2 inline-flex items-center justify-center gap-2"
                >
                  <i className="bi bi-arrow-left text-xs leading-none"></i>
                  Quay lại đăng nhập
                </button>
              </div>
            </div>

            {mfaError && (
              <p className="text-danger-400 text-[11px] font-bold text-center uppercase tracking-wider">{mfaError}</p>
            )}
            {mfaMethods.totp && mfaMethods.email && !useRecovery && (
              <div className="flex justify-center gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setMfaMethod('totp');
                    setMfaToken('');
                  }}
                  className={`px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-widest border ${
                    mfaMethod === 'totp'
                      ? 'bg-brand-500/20 text-brand-300 border-brand-500/30'
                      : 'text-white/55 border-white/10'
                  }`}
                >
                  Authenticator
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setMfaMethod('email');
                    setMfaToken('');
                    void resendEmail();
                  }}
                  className={`px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-widest border ${
                    mfaMethod === 'email'
                      ? 'bg-brand-500/20 text-brand-300 border-brand-500/30'
                      : 'text-white/55 border-white/10'
                  }`}
                >
                  Email
                </button>
              </div>
            )}
          </div>
        )}

        <div className="mt-10 pt-8 border-t border-white/5 text-center">
          <p className="text-white/45 text-[11px] font-black uppercase tracking-widest">
            Chưa có tài khoản?
            <Link
              href="/register/"
              className="text-brand-400 hover:text-brand-300 ml-1 transition-colors underline underline-offset-4 decoration-brand-400/30"
            >
              Đăng ký ngay
            </Link>
          </p>
          <p className="text-[10px] text-white/35 mt-4 uppercase tracking-widest">
            Cần hỗ trợ?{' '}
            <a
              href={`mailto:${process.env.NEXT_PUBLIC_SUPPORT_EMAIL || 'admin@fptoj.com'}`}
              className="text-brand-300 hover:text-brand-200"
            >
              {process.env.NEXT_PUBLIC_SUPPORT_EMAIL || 'admin@fptoj.com'}
            </a>
          </p>
        </div>
      </div>
    </div>
  );
}
