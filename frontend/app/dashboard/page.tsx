import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Dashboard';

export const metadata = pageMeta({
  title: 'Bảng điều khiển',
  description: 'Bảng điều khiển cá nhân: lịch sử quét, báo cáo, API key và cảnh báo.',
  path: '/dashboard/',
  noIndex: true,
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
