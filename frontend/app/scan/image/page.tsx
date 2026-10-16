import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Scan/Image';

export const metadata = pageMeta({
  title: 'Kiểm tra Ảnh / Chứng từ',
  description:
    'Tải ảnh chụp màn hình chuyển khoản, tin nhắn, hoá đơn, giấy tờ nghi giả mạo để đọc nội dung (OCR) và phân tích dấu hiệu lừa đảo.',
  path: '/scan/image/',
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
