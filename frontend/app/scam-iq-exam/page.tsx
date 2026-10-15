import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/AI/ScamIQ';

export const metadata = pageMeta({
  title: 'Bài kiểm tra Scam IQ',
  description:
    'Đo lường khả năng nhận diện lừa đảo của bạn qua các tình huống thực tế. Nhận xếp hạng Scam IQ và lời khuyên cải thiện.',
  path: '/scam-iq-exam/',
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
