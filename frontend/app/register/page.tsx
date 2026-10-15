import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Auth/Register';

export const metadata = pageMeta({
  title: 'Đăng ký',
  description: 'Tạo tài khoản ShieldCall VN miễn phí để bảo vệ bản thân và cộng đồng khỏi lừa đảo số.',
  path: '/register/',
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
