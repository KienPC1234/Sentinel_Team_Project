import { redirect } from 'next/navigation';

/* Alias cũ của Admin Panel — chuyển sang bảng điều khiển thật /admin-cp/. */
export default function RoutePage() {
  redirect('/admin-cp/');
}
