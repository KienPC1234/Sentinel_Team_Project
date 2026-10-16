import { RouteShell } from '@/components/RouteShell';
import { RequireStaff } from '@/views/Admin/_shared';
import Page from '@/views/Admin/RagMgmt';

export default function RoutePage() {
  return (
    <RouteShell>
      <RequireStaff>
      <Page />
    </RequireStaff>
    </RouteShell>
  );
}
