import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Scan/Bank';

export const metadata = pageMeta({
  title: 'Tra cứu tài khoản ngân hàng lừa đảo',
  description: 'Tra cứu số tài khoản, ngân hàng bị báo cáo lừa đảo để tránh chuyển tiền nhầm.',
  path: '/scan/bank/',
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
