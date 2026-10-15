import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Emergency';

export const metadata = pageMeta({
  title: 'Hỗ trợ khẩn cấp',
  description:
    'Hướng dẫn xử lý khẩn cấp khi bạn hoặc người thân đang bị lừa đảo trực tuyến: các bước cần làm ngay và đầu mối hỗ trợ.',
  path: '/emergency/',
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
