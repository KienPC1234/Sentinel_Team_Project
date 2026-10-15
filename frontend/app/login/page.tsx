import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Auth/Login';

export const metadata = pageMeta({
  title: 'Đăng nhập',
  description: 'Đăng nhập vào ShieldCall VN để quản lý báo cáo, theo dõi lịch sử quét và nhận cảnh báo.',
  path: '/login/',
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
