import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Report/ReportList';

export const metadata = pageMeta({
  title: 'Tra cứu danh sách báo cáo lừa đảo',
  description:
    'Cơ sở dữ liệu cảnh báo lừa đảo cộng đồng do ShieldCall VN xác thực. Tìm theo SĐT, link, STK, ví crypto, hash file, Telegram/Zalo.',
  path: '/reports/',
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
