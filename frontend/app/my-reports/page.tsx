import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Report/MyReports';

export const metadata = pageMeta({
  title: 'Báo cáo của tôi',
  description: 'Theo dõi trạng thái các báo cáo lừa đảo bạn đã gửi.',
  path: '/my-reports/',
  noIndex: true,
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
