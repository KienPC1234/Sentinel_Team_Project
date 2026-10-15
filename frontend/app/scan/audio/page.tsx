import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Scan/Audio';

export const metadata = pageMeta({
  title: 'Phân tích audio / cuộc gọi lừa đảo',
  description: 'Phân tích audio, bản ghi cuộc gọi nghi ngờ lừa đảo bằng AI (deepfake, giả danh).',
  path: '/scan/audio/',
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
