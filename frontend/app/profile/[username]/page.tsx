import { notFound } from 'next/navigation';
import { RouteShell } from '@/components/RouteShell';
import PublicProfile from '@/views/Auth/PublicProfile';

export default async function RoutePage({
  params,
}: {
  params: Promise<{ username: string }>;
}) {
  const { username } = await params;
  if (!username) {
    notFound();
  }

  const cleanUser = username.startsWith('@') ? username.slice(1) : username;
  if (!cleanUser) {
    notFound();
  }

  return (
    <RouteShell>
      <PublicProfile usernameProp={decodeURIComponent(cleanUser)} />
    </RouteShell>
  );
}

