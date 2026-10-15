import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Home';

export const metadata = pageMeta({
  title: 'Trang chủ',
  description:
    'Kiểm tra số điện thoại, tin nhắn, website, tài khoản ngân hàng và báo cáo lừa đảo trực tuyến bằng AI.',
  path: '/home/',
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
