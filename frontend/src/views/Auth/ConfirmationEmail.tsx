'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { api } from '../../lib/api';

/* Port 1-1 từ PKV/templates/account/email_confirm.html.
 * GET do proxy.ts phục vụ native; form POST về /accounts/confirm-email/<key>/
 * để Django xác nhận (csrftoken lấy từ cookie do proxy.ts "prime").
 * Lưu ý: luồng xác thực email hiện tắt (ACCOUNT_EMAIL_VERIFICATION='none'). */
export default function ConfirmationEmail() {
  const params = useParams<{ key?: string }>();
  const key = (params?.key || '').toString();

  const [csrf, setCsrf] = useState('');
  const [email, setEmail] = useState('');
  const [username, setUsername] = useState('');

  useEffect(() => {
    const m = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]*)/);
    setCsrf(m ? decodeURIComponent(m[1]) : '');
  }, []);

  useEffect(() => {
    if (!key) return;
    api
      .get<{ user?: { email?: string; username?: string } }>('/auth/me/')
      .then((me) => {
        setEmail(me.user?.email || '');
        setUsername(me.user?.username || '');
      })
      .catch(() => {
        /* chưa đăng nhập — hiển thị câu chung */
      });
  }, [key]);

  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] animate-fadein">
      <div className="liquid-card p-10 max-w-md w-full text-center space-y-8">
        <div className="inline-flex items-center justify-center w-20 h-20 rounded-[2.5rem] bg-brand-500/10 text-brand-400 border border-brand-500/20 shadow-lg shadow-brand-500/10">
          <i className="bi bi-shield-check text-4xl"></i>
        </div>

        <div className="space-y-4">
          <h1 className="text-3xl font-black text-white tracking-tight">Xác nhận Email</h1>

          {key ? (
            <>
              <p className="text-white/55 text-sm font-medium tracking-wide">
                {email || username ? (
                  <>
                    Vui lòng xác nhận rằng{' '}
                    <span className="text-brand-400 font-bold">{email || 'địa chỉ email này'}</span> là địa chỉ email của
                    tài khoản <span className="text-white font-bold">{username || 'của bạn'}</span>.
                  </>
                ) : (
                  <>Vui lòng xác nhận rằng địa chỉ email này thuộc tài khoản của bạn.</>
                )}
              </p>

              <form method="post" action={`/accounts/confirm-email/${encodeURIComponent(key)}/`} className="pt-4">
                <input type="hidden" name="csrfmiddlewaretoken" value={csrf} readOnly />
                <button
                  type="submit"
                  className="liquid-btn w-full py-5 bg-brand-500 text-black font-black uppercase tracking-[0.2em] text-sm hover:bg-brand-400 transition-all shadow-lg shadow-brand-500/20"
                >
                  Xác nhận ngay
                </button>
              </form>
            </>
          ) : (
            <>
              <p className="text-danger-400 text-sm font-medium tracking-wide">
                Liên kết xác nhận này đã hết hạn hoặc không hợp lệ. Vui lòng yêu cầu một mã xác nhận mới.
              </p>
              <Link
                href="/login/"
                className="liquid-btn w-full py-5 bg-white/5 border border-white/10 text-white font-black uppercase tracking-[0.2em] text-sm hover:bg-white/10 transition-all mt-4"
              >
                Quay lại Đăng nhập
              </Link>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
