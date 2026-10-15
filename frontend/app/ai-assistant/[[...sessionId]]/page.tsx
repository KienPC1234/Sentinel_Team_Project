import { pageMeta } from '@/lib/seo';
import Page from '@/views/AI/Assistant';

// Optional catch-all: /ai-assistant/ và /ai-assistant/<sessionId>/ cùng MỘT route.
//
// KHÔNG bọc <RouteShell> (Suspense fallback=null) ở đây: khi tạo phiên mới rồi
// router.push() sang URL có id, RSC của route mới phải tải -> Suspense sẽ hiện
// fallback null và unmount trang, làm mất state + huỷ luồng stream đang chạy.
export const metadata = pageMeta({
  title: 'Trợ lý AI chống lừa đảo',
  description: 'Trợ lý AI tư vấn nhận diện và phòng chống lừa đảo trực tuyến theo từng tình huống.',
  path: '/ai-assistant/',
  noIndex: true,
});

export default function RoutePage() {
  return <Page />;
}
