'use client';
import Link from 'next/link';

/* Port 1-1 từ PKV/templates/account/email_verification_error.html. */
export default function EmailVerificationError() {
  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] animate-fadein">
      <div className="liquid-card p-10 max-w-md w-full text-center space-y-8">
        <div className="inline-flex items-center justify-center w-20 h-20 rounded-[2.5rem] bg-danger-500/10 text-danger-500 border border-danger-500/20 shadow-lg shadow-danger-500/10">
          <i className="bi bi-exclamation-triangle text-4xl"></i>
        </div>

        <div className="space-y-4">
          <h1 className="text-3xl font-black text-white tracking-tight">Lỗi xác thực</h1>
          <p className="text-white/55 text-sm font-medium tracking-wide">
            Đã xảy ra lỗi trong quá trình xác thực email. Có thể liên kết đã hết hạn hoặc đã được sử dụng.
          </p>
        </div>

        <Link
          href="/login/"
          className="liquid-btn w-full py-5 bg-brand-500 text-black font-black uppercase tracking-[0.2em] text-sm hover:bg-brand-400 transition-all shadow-lg shadow-brand-500/20"
        >
          Thử đăng nhập lại
        </Link>
      </div>
    </div>
  );
}
