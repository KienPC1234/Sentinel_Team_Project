import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Scan/Lookup';

export const metadata = pageMeta({
  title: 'Tra cứu & quét lừa đảo',
  description:
    'Tra cứu nhanh số điện thoại, website, tài khoản ngân hàng, email, QR, tệp tin và audio nghi ngờ lừa đảo.',
  path: '/scan/',
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
