import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Learn/LearnHub';

export const metadata = pageMeta({
  title: 'Tin tức & Cảnh báo lừa đảo mới nhất',
  description:
    'Tổng hợp tin tức an toàn số và cảnh báo thủ đoạn lừa đảo trực tuyến mới nhất từ VnExpress, Tín nhiệm mạng (NCSC) và ShieldCall VN.',
  path: '/learn/news/',
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page initialTab="news" />
    </RouteShell>
  );
}
