import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Radar/ScamRadar';

export const metadata = pageMeta({
  title: 'Scam Radar - Bản đồ điểm nóng lừa đảo',
  description:
    'Scam Radar theo dõi điểm nóng lừa đảo trực tuyến theo thời gian thực: số điện thoại, website, tài khoản ngân hàng bị báo cáo nhiều nhất.',
  path: '/scam-radar/',
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
