import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Helps';

export const metadata = pageMeta({
  title: 'Trung tâm hướng dẫn',
  description: 'Hướng dẫn sử dụng ShieldCall VN, bảo mật tài khoản và an toàn trực tuyến.',
  path: '/helps/',
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
