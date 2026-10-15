import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Home';

export const metadata = pageMeta({
  title: 'ShieldCall VN - Bảo vệ bạn khỏi lừa đảo số',
  description:
    'Kiểm tra số điện thoại, tin nhắn, website, tài khoản ngân hàng và báo cáo lừa đảo trực tuyến bằng AI. Bảo vệ bạn và cộng đồng khỏi lừa đảo số.',
  path: '/',
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
