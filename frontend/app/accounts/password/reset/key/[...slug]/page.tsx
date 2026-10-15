import { RouteShell } from '@/components/RouteShell';
import Page from '@/views/Auth/PasswordResetConfirm';

// Tương thích link email Allauth cũ: /accounts/password/reset/key/<uidb36>-<key>/
// PasswordResetConfirm tự tách uid/token từ segment động (xem fromRouteParams).
export default function RoutePage() {
  return (
    <RouteShell>
      <Page />
    </RouteShell>
  );
}
