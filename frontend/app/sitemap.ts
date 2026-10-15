import type { MetadataRoute } from 'next';

import { SITE_URL } from '@/lib/site-config';
const API_TARGET = process.env.API_TARGET || 'http://127.0.0.1:8001';

type Entry = {
  path: string;
  priority: number;
  changeFrequency: MetadataRoute.Sitemap[number]['changeFrequency'];
  lastModified?: Date;
};

const STATIC_ROUTES: Entry[] = [
  { path: '/', priority: 1.0, changeFrequency: 'daily' },
  { path: '/home/', priority: 1.0, changeFrequency: 'daily' },
  { path: '/scan/', priority: 0.95, changeFrequency: 'weekly' },
  { path: '/scan/phone/', priority: 0.95, changeFrequency: 'weekly' },
  { path: '/scan/message/', priority: 0.9, changeFrequency: 'weekly' },
  { path: '/scan/website/', priority: 0.95, changeFrequency: 'weekly' },
  { path: '/scan/bank/', priority: 0.95, changeFrequency: 'weekly' },
  { path: '/scan/email/', priority: 0.9, changeFrequency: 'weekly' },
  { path: '/scan/qr/', priority: 0.85, changeFrequency: 'weekly' },
  { path: '/scan/file/', priority: 0.9, changeFrequency: 'weekly' },
  { path: '/scan/audio/', priority: 0.85, changeFrequency: 'weekly' },
  { path: '/scam-radar/', priority: 0.9, changeFrequency: 'daily' },
  { path: '/scam-radar/list/phones/', priority: 0.85, changeFrequency: 'daily' },
  { path: '/scam-radar/list/accounts/', priority: 0.85, changeFrequency: 'daily' },
  { path: '/scam-radar/list/domains/', priority: 0.85, changeFrequency: 'daily' },
  { path: '/scam-radar/list/emails/', priority: 0.85, changeFrequency: 'daily' },
  { path: '/report/', priority: 0.85, changeFrequency: 'weekly' },
  { path: '/reports/', priority: 0.85, changeFrequency: 'daily' },
  { path: '/learn/', priority: 0.9, changeFrequency: 'daily' },
  { path: '/forum/', priority: 0.8, changeFrequency: 'daily' },
  { path: '/forum/announcements/', priority: 0.75, changeFrequency: 'weekly' },
  { path: '/ai-assistant/', priority: 0.75, changeFrequency: 'weekly' },
  { path: '/scam-iq-exam/', priority: 0.8, changeFrequency: 'weekly' },
  { path: '/emergency/', priority: 0.8, changeFrequency: 'monthly' },
  { path: '/mcp/', priority: 0.7, changeFrequency: 'monthly' },
  { path: '/helps/', priority: 0.75, changeFrequency: 'weekly' },
  { path: '/trust/', priority: 0.6, changeFrequency: 'monthly' },
  { path: '/legal/disclaimer/', priority: 0.4, changeFrequency: 'yearly' },
];

interface SlugItem {
  slug?: string;
  created_at?: string;
  updated_at?: string;
}

interface HelpsResp {
  articles?: Array<{ slug?: string }>;
}

async function fetchJson<T>(endpoint: string): Promise<T | null> {
  try {
    const res = await fetch(`${API_TARGET}${endpoint}`, {
      next: { revalidate: 3600 },
      signal: AbortSignal.timeout(3000),
    });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const now = new Date();
  const dynamicEntries: Entry[] = [];

  const [articles, lessons, helps] = await Promise.all([
    fetchJson<SlugItem[]>('/api/v1/articles/'),
    fetchJson<SlugItem[]>('/api/v1/learn/lessons/'),
    fetchJson<HelpsResp>('/api/v1/helps/'),
  ]);

  if (Array.isArray(articles)) {
    for (const a of articles) {
      if (a?.slug) {
        dynamicEntries.push({
          path: `/learn/${a.slug}/`,
          priority: 0.85,
          changeFrequency: 'weekly',
          lastModified: a.updated_at || a.created_at ? new Date(a.updated_at || a.created_at!) : now,
        });
      }
    }
  }

  if (Array.isArray(lessons)) {
    for (const l of lessons) {
      if (l?.slug) {
        dynamicEntries.push({
          path: `/learn/lesson/${l.slug}/`,
          priority: 0.85,
          changeFrequency: 'weekly',
          lastModified: l.updated_at || l.created_at ? new Date(l.updated_at || l.created_at!) : now,
        });
      }
    }
  }

  if (helps?.articles && Array.isArray(helps.articles)) {
    for (const h of helps.articles) {
      if (h?.slug && h.slug !== 'index') {
        dynamicEntries.push({
          path: `/helps/${h.slug}/`,
          priority: 0.7,
          changeFrequency: 'monthly',
          lastModified: now,
        });
      }
    }
  }

  const allEntries = [...STATIC_ROUTES, ...dynamicEntries];

  return allEntries.map((r) => ({
    url: `${SITE_URL}${r.path}`,
    lastModified: r.lastModified || now,
    changeFrequency: r.changeFrequency,
    priority: r.priority,
  }));
}
