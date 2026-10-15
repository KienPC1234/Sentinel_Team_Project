import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Trust';

export const metadata = pageMeta({
  title: 'Nguồn & độ tin cậy',
  description: 'Nguồn dữ liệu, độ tin cậy & giới hạn công cụ, kênh chính thức Việt Nam, bảo mật dữ liệu và trạng thái lưu trữ S3 của ShieldCall VN.',
  path: '/trust/',
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
