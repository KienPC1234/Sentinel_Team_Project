import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Scan/Qr';

export const metadata = pageMeta({
  title: 'Quét mã QR & ảnh lừa đảo',
  description: 'Quét mã QR và ảnh nghi ngờ lừa đảo: nhận diện QR độc hại và nội dung giả mạo (OCR + AI).',
  path: '/scan/qr/',
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
