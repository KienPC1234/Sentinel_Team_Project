import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Forum/Forum';

export const metadata = pageMeta({
  title: 'Diễn đàn cộng đồng',
  description:
    'Chia sẻ, cảnh báo và thảo luận về các thủ đoạn lừa đảo trực tuyến cùng cộng đồng ShieldCall VN.',
  path: '/forum/',
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
