'use client';
import { useEffect } from 'react';
import ErrorPage from '@/views/ErrorPage';

/* Bắt lỗi runtime trong cây route (tương ứng Errors/500.html).
 * Render bên trong layout gốc nên vẫn giữ Navbar/Footer. */
export default function Error({ error }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => {
    console.error('Route error:', error);
  }, [error]);

  return <ErrorPage code={500} />;
}
