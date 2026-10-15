import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Learn/LearnHub';

export const metadata = pageMeta({
  title: 'Cẩm nang kiến thức phòng tránh lừa đảo',
  description:
    'Bài học, tin tức, cảnh báo và kịch bản mô phỏng giúp bạn nhận diện và phòng tránh lừa đảo trực tuyến.',
  path: '/learn/',
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
