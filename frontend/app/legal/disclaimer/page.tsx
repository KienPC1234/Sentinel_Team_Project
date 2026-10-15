import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Disclaimer';

export const metadata = pageMeta({
  title: 'Điều khoản & chính sách',
  description: 'Điều khoản sử dụng, quyền riêng tư và chính sách xử lý dữ liệu của ShieldCall VN.',
  path: '/legal/disclaimer/',
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
