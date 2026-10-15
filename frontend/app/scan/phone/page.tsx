import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Scan/Phone';

export const metadata = pageMeta({
  title: 'Kiểm tra số điện thoại lừa đảo',
  description: 'Tra cứu số điện thoại nghi ngờ lừa đảo: dữ liệu cộng đồng kết hợp phân tích AI.',
  path: '/scan/phone/',
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
