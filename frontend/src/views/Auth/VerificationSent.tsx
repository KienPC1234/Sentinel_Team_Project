'use client';
import Link from 'next/link';

/* Port 1-1 từ PKV/templates/account/verification_sent.html.
 * (Luồng xác thực email hiện đang tắt: ACCOUNT_EMAIL_VERIFICATION='none'.) */
export default function VerificationSent() {
  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] animate-fadein">
      <div className="liquid-card p-10 max-w-md w-full text-center space-y-8">
        <div className="inline-flex items-center justify-center w-20 h-20 rounded-[2.5rem] bg-warn-500/10 text-warn-500 border border-warn-500/20 shadow-lg shadow-warn-500/10">
          <i className="bi bi-envelope-check text-4xl"></i>
        </div>

        <div className="space-y-4">
          <h1 className="text-3xl font-black text-white tracking-tight">Xác thực tài khoản</h1>
          <p className="text-white/55 text-sm font-medium tracking-wide">
            Chúng tôi đã gửi một email xác nhận đến địa chỉ email của bạn. Vui lòng kiểm tra hộp thư đến (và cả thư rác) để
            hoàn tất quá trình đăng ký.
          </p>
        </div>

        <div className="pt-4 border-t border-white/5 space-y-4">
          <p className="text-[10px] text-white/35 font-bold uppercase tracking-widest">Không nhận được email?</p>
          <Link
            href="/login/"
            className="liquid-btn w-full py-5 bg-white/5 border border-white/10 text-white font-black uppercase tracking-[0.2em] text-sm hover:bg-white/10 transition-all"
          >
            Quay lại Đăng nhập
          </Link>
        </div>
      </div>
    </div>
  );
}
