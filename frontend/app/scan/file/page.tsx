import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Scan/File';

export const metadata = pageMeta({
  title: 'Quét tệp tin / APK độc hại',
  description: 'Quét tệp tin, APK nghi ngờ mã độc trong sandbox cách ly và phân tích hành vi.',
  path: '/scan/file/',
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
