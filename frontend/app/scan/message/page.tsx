import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Scan/Message';

export const metadata = pageMeta({
  title: 'Phân tích tin nhắn lừa đảo',
  description: 'Phân tích tin nhắn, văn bản nghi ngờ lừa đảo bằng AI để nhận diện dấu hiệu nguy hiểm.',
  path: '/scan/message/',
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
