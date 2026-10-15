import { RouteShell } from '@/components/RouteShell';
import { ScenarioMgmt } from '@/views/Admin/ScenarioMgmt';

export default function RoutePage() {
  return (
    <RouteShell>
      <ScenarioMgmt />
    </RouteShell>
  );
}
