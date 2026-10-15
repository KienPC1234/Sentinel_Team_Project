import { redirect } from 'next/navigation';

/* Trang Admin Panel cũ là bản demo tĩnh (số liệu hardcode).
 * Chuyển hướng sang bảng điều khiển thật /admin-cp/. */
export default function RoutePage() {
  redirect('/admin-cp/');
}
