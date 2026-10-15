'use client';
import './globals.css';
import ErrorPage from '@/views/ErrorPage';

/* Lỗi ở cấp root layout — phải tự render <html>/<body>. */
export default function GlobalError() {
  return (
    <html lang="vi" className="dark">
      <body>
        <ErrorPage code={500} />
      </body>
    </html>
  );
}
