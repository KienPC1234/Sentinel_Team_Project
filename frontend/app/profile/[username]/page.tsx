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

  const raw = decodeURIComponent(username).trim();
  const cleanUser = raw.startsWith('@') ? raw.slice(1).trim() : raw;
  if (!cleanUser) {
    notFound();
  }

  return (
    <RouteShell>
      <PublicProfile usernameProp={cleanUser} />
    </RouteShell>
  );
}

