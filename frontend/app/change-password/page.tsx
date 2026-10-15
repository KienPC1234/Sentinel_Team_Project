import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Auth/ChangePassword';

export const metadata = pageMeta({
  title: 'Đổi mật khẩu',
  description: 'Đổi mật khẩu tài khoản ShieldCall VN.',
  path: '/change-password/',
  noIndex: true,
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
