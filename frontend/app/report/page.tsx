import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Report/Report';

export const metadata = pageMeta({
  title: 'Gửi báo cáo lừa đảo',
  description:
    'Gửi báo cáo hành vi lừa đảo (số điện thoại, website, tài khoản, email, file, audio) để cộng đồng cùng cảnh giác.',
  path: '/report/',
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
