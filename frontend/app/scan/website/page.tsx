import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Scan/Website';

export const metadata = pageMeta({
  title: 'Kiểm tra website & link lừa đảo',
  description: 'Kiểm tra website, đường link phishing và tên miền giả mạo ngân hàng, thương hiệu.',
  path: '/scan/website/',
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
