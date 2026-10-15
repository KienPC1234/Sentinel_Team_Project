'use client';
import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useAuth } from '../../components/AuthContext';
import { api, ApiError } from '../../lib/api';



const TURNSTILE_SITEKEY = (process.env.NEXT_PUBLIC_TURNSTILE_SITEKEY as string | undefined) || '';

function errMsg(e: unknown, fallback: string): string {
  if (e instanceof ApiError) {
    const d = e.data as { error?: string } | null;
    if (d && typeof d.error === 'string' && d.error) return d.error;
    const det = (e.data as { details?: unknown } | null)?.details;
    if (det && typeof det === 'object') {
      const first = Object.values(det as Record<string, unknown>)[0];
      if (Array.isArray(first) && typeof first[0] === 'string') return first[0];
    }
    return e.message || fallback;
  }
  if (e instanceof Error) return e.message || fallback;
  return fallback;
}

function passwordScore(value: string): number {
  let score = 0;
  if (value.length >= 8) score++;
  if (value.length >= 12) score++;
  if (/[a-z]/.test(value) && /[A-Z]/.test(value)) score++;
  if (/\d/.test(value)) score++;
  if (/[^A-Za-z0-9]/.test(value)) score++;
  return Math.min(4, score);
}

function strengthOf(password: string): { label: string; bar: string; color: string; hint: string } {
  const score = passwordScore(password);
  if (!password)
    return {
      label: 'Chưa nhập',
      bar: 'w-0',
      color: 'text-white/35',
      hint: 'Dùng ít nhất 8 ký tự gồm chữ hoa, chữ thường, số, ký tự đặc biệt.',
    };
  if (score <= 1)
    return {
      label: 'Yếu',
      bar: 'w-1/4',
      color: 'text-danger-400',
      hint: 'Mật khẩu đang yếu, nên thêm chữ hoa/số/ký tự đặc biệt.',
    };
  if (score === 2)
    return {
      label: 'Trung bình',
      bar: 'w-2/4',
      color: 'text-warn-300',
      hint: 'Có thể dùng, nhưng nên tăng độ phức tạp để an toàn hơn.',
    };
  if (score === 3)
    return {
      label: 'Khá mạnh',
      bar: 'w-3/4',
      color: 'text-brand-300',
      hint: 'Tốt, bạn có thể thêm ký tự đặc biệt để mạnh hơn nữa.',
    };
  return { label: 'Mạnh', bar: 'w-full', color: 'text-safe-300', hint: 'Mật khẩu mạnh, đạt mức khuyến nghị.' };
}

/* Port từ PKV/templates/Auth/register.html — flow 2 bước: gửi OTP rồi xác thực OTP. */
export default function Register() {
  const { user } = useAuth();
  const router = useRouter();

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [password2, setPassword2] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [otpSent, setOtpSent] = useState(false);
  const [otp, setOtp] = useState('');
  const [otpCooldown, setOtpCooldown] = useState(0);

  useEffect(() => {
    if (user) window.location.href = '/dashboard/';
  }, [user]);


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

  useEffect(() => {
    if (otpCooldown <= 0) return;
    const t = setInterval(() => setOtpCooldown((c) => (c <= 1 ? 0 : c - 1)), 1000);
    return () => clearInterval(t);
  }, [otpCooldown]);

  function readTurnstileToken(): string {
    return document.querySelector<HTMLInputElement>('[name=cf-turnstile-response]')?.value || '';
  }

  function resetTurnstile(): void {
    const w = window as unknown as { turnstile?: { reset: () => void } };
    try {
      w.turnstile?.reset();
    } catch {
      /* ignore */
    }
  }

  async function requestOtp(tsToken: string): Promise<boolean> {
    const r = await api.post<{ message?: string }>('/auth/register/request-otp/', {
      full_name: name.trim(),
      email: email.trim(),
      password,
      'cf-turnstile-response': tsToken,
    });
    void r;
    setOtpSent(true);
    setOtp('');
    setOtpCooldown(60);
    return true;
  }

  async function handleSubmit(e: FormEvent): Promise<void> {
    e.preventDefault();
    if (!name.trim() || !email.trim() || !password.trim()) {
      setError('Vui lòng điền đầy đủ thông tin');
      return;
    }
    if (password !== password2) {
      setError('Mật khẩu xác nhận không khớp');
      return;
    }
    if (password.length < 8) {
      setError('Mật khẩu tối thiểu 8 ký tự');
      return;
    }
    if (passwordScore(password) < 2) {
      setError('Mật khẩu còn quá yếu, vui lòng tăng độ mạnh');
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
      if (!otpSent) {
        await requestOtp(tsToken);
      } else {
        if (!/^\d{6}$/.test(otp.trim())) {
          setError('Vui lòng nhập OTP 6 chữ số');
          setLoading(false);
          return;
        }
        const res = await api.post<{ welcome_message?: string }>('/auth/register/', {
          full_name: name.trim(),
          email: email.trim(),
          password,
          otp: otp.trim(),
        });
        try {
          sessionStorage.setItem(
            'register_welcome_message',
            res.welcome_message || 'Xin chào! Đăng ký thành công, hãy đăng nhập để bắt đầu.',
          );
        } catch {
          /* private mode */
        }
        router.push('/login/?from=register');
      }
    } catch (err) {
      setError(errMsg(err, 'Đăng ký thất bại'));
    } finally {
      setLoading(false);
      resetTurnstile();
    }
  }

  async function handleResend(): Promise<void> {
    if (loading || otpCooldown > 0) return;
    const tsToken = readTurnstileToken();
    if (TURNSTILE_SITEKEY && !tsToken) {
      setError('Vui lòng hoàn thành captcha để gửi lại OTP');
      return;
    }
    setLoading(true);
    setError('');
    try {
      await requestOtp(tsToken);
    } catch (err) {
      setError(errMsg(err, 'Không thể gửi lại OTP'));
    } finally {
      setLoading(false);
      resetTurnstile();
    }
  }

  const strength = strengthOf(password);

  return (
    <div className="relative animate-fadein max-w-xl mx-auto pt-16 sm:pt-20 pb-20 px-4 space-y-8">
      <div className="pointer-events-none absolute -top-6 -right-8 w-44 h-44 rounded-full bg-brand-500/10 blur-3xl"></div>
      <div className="pointer-events-none absolute -bottom-8 -left-6 w-40 h-40 rounded-full bg-brand2-500/10 blur-3xl"></div>

      <div className="text-center space-y-3">
        <div
          className="inline-flex items-center justify-center w-20 h-20 rounded-[2.5rem] bg-brand-500/10 text-brand-400 border border-brand-500/20 shadow-lg shadow-brand-500/10 mb-2"
        >
          <i className="bi bi-shield-check text-4xl leading-none"></i>
        </div>
        <h1 className="text-3xl font-black text-white tracking-tight leading-none">
          Gia nhập ShieldCall
        </h1>
        <p className="text-white/55 text-sm font-medium tracking-wide">
          Bảo vệ chính bạn và cộng đồng khỏi lừa đảo
        </p>
      </div>

      <div
        className="liquid-card p-8 sm:p-10 border border-brand-400/15 bg-white/[0.03] backdrop-blur-2xl shadow-2xl shadow-brand-500/10"
      >
        <a
          href="/accounts/google/login/?process=login"
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
          <span className="text-white/90 uppercase text-[11px] font-black tracking-widest">Đăng ký với Google</span>
        </a>

        <div className="flex items-center gap-4 mb-8">
          <div className="flex-1 h-px bg-white/5"></div>
          <span className="text-[10px] font-black text-white/35 uppercase tracking-[0.2em]">Hoặc thủ công</span>
          <div className="flex-1 h-px bg-white/5"></div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-5">
          <div className="space-y-2">
            <label className="text-[11px] font-black text-white/45 uppercase tracking-[0.2em] ml-2">Họ & Tên</label>
            <input
              type="text"
              className="liquid-input w-full py-4 px-6 text-sm font-bold"
              placeholder="VD: Nguyễn Văn A"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </div>

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
            <label className="text-[11px] font-black text-white/45 uppercase tracking-[0.2em] ml-2">Mật khẩu</label>
            <input
              type="password"
              className="liquid-input w-full py-4 px-6 text-sm font-bold"
              placeholder="Tối thiểu 8 ký tự"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
            <div className="space-y-2 px-2 pt-2">
              <div className="h-2 rounded-full bg-white/5 overflow-hidden border border-white/10">
                <div
                  className={`h-full rounded-full bg-gradient-to-r from-danger-500 via-warn-400 to-safe-400 transition-all duration-300 ${strength.bar}`}
                ></div>
              </div>
              <div className="flex items-center justify-between text-[10px] font-black uppercase tracking-widest">
                <span className="text-white/35">Độ mạnh mật khẩu</span>
                <span className={strength.color}>{strength.label}</span>
              </div>
              <p className="text-[10px] text-white/55 font-medium leading-relaxed">{strength.hint}</p>
            </div>
          </div>

          <div className="space-y-2">
            <label className="text-[11px] font-black text-white/45 uppercase tracking-[0.2em] ml-2">Xác nhận mật khẩu</label>
            <input
              type="password"
              className="liquid-input w-full py-4 px-6 text-sm font-bold"
              placeholder="Nhập lại mật khẩu"
              value={password2}
              onChange={(e) => setPassword2(e.target.value)}
              required
            />
          </div>

          {otpSent && (
            <div className="space-y-2">
              <div className="flex items-center justify-between ml-2">
                <label className="text-[11px] font-black text-white/45 uppercase tracking-[0.2em]">Mã OTP Email</label>
                <button
                  type="button"
                  onClick={handleResend}
                  className="text-[10px] font-black uppercase tracking-widest text-brand-300 hover:text-brand-200 disabled:opacity-50"
                  disabled={loading || otpCooldown > 0}
                >
                  {otpCooldown <= 0 ? <span>Gửi lại OTP</span> : <span>{`Gửi lại sau ${otpCooldown}s`}</span>}
                </button>
              </div>
              <input
                type="text"
                maxLength={6}
                className="liquid-input w-full py-4 px-6 text-center text-xl tracking-[0.45em] font-black"
                placeholder="••••••"
                value={otp}
                onChange={(e) => setOtp(e.target.value)}
              />
            </div>
          )}

          <div className="flex justify-center py-2">
            {TURNSTILE_SITEKEY ? (
              <div className="cf-turnstile" data-sitekey={TURNSTILE_SITEKEY}></div>
            ) : (
              <p className="text-[10px] text-warn-300/70 font-bold uppercase tracking-widest">
                Chưa cấu hình VITE_TURNSTILE_SITEKEY
              </p>
            )}
          </div>

          <button
            type="submit"
            className="liquid-btn w-full py-5 bg-brand-500 text-black font-black uppercase tracking-[0.2em] text-sm hover:bg-brand-400 transition-all shadow-lg shadow-brand-500/20"
            disabled={loading}
          >
            {!loading ? (
              <span>{otpSent ? 'XÁC THỰC OTP & TẠO TÀI KHOẢN' : 'GỬI OTP XÁC THỰC'}</span>
            ) : (
              <span className="flex items-center justify-center gap-3">
                <span className="spinner w-5 h-5 border-black"></span>
                <span className="text-xs">ĐANG XỬ LÝ...</span>
              </span>
            )}
          </button>

          {error && (
            <p className="text-danger-400 text-[11px] font-bold text-center animate-pulse uppercase tracking-wider">{error}</p>
          )}
        </form>

        <div className="mt-10 pt-8 border-t border-white/5 text-center">
          <p className="text-white/45 text-[11px] font-black uppercase tracking-widest">
            Đã có tài khoản?
            <Link
              href="/login/"
              className="text-brand-400 hover:text-brand-300 ml-1 transition-colors underline underline-offset-4 decoration-brand-400/30"
            >
              Đăng nhập
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
