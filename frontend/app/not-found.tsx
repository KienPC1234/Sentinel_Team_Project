import { RouteShell } from '@/components/RouteShell';
import ErrorPage from '@/views/ErrorPage';

export default function NotFound() {
  return (
    <RouteShell>
      <ErrorPage code={404} />
    </RouteShell>
  );
}
