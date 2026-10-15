'use client';

import { Suspense } from 'react';
import type { ReactNode } from 'react';

export function RouteShell({ children }: { children: ReactNode }) {
  return <Suspense fallback={null}>{children}</Suspense>;
}
