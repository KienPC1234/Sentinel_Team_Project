import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Scan/Lookup';

export const metadata = pageMeta({
  title: 'Tra cứu lịch sử quét',
  description: 'Tìm kiếm và tra cứu lịch sử quét số điện thoại, website, tài khoản, email và tệp tin.',
  path: '/scan/lookup/',
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
