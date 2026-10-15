import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Scan/Email';

export const metadata = pageMeta({
  title: 'Kiểm tra email lừa đảo',
  description: 'Kiểm tra email giả mạo, phishing và nội dung đáng ngờ bằng AI.',
  path: '/scan/email/',
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
