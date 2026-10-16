import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Elder/ElderHub';

export const metadata = pageMeta({
  title: 'Trợ giúp người cao tuổi — kiểm tra lừa đảo thật dễ',
  description:
    'Trang dễ dùng cho người cao tuổi: chữ to, nút to, kiểm tra số điện thoại, tin nhắn, đường link, số tài khoản ngân hàng và hỏi trợ lý AI. Không cần đăng nhập.',
  path: '/nguoi-cao-tuoi/',
});

export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
