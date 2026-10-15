import type { Metadata } from 'next';
import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Helps';

const DJANGO = process.env.API_TARGET || 'http://127.0.0.1:8001';
import { SITE_URL } from '@/lib/site-config';

interface HelpMeta {
  title?: string;
  slug?: string;
  content?: string;
}

async function getHelp(slug: string): Promise<HelpMeta | null> {
  try {
    const res = await fetch(`${DJANGO}/api/v1/helps/${slug}/`, { next: { revalidate: 3600 } });
    if (!res.ok) return null;
    return (await res.json()) as HelpMeta;
  } catch {
    return null;
  }
}

function strip(markdown?: string, max = 160): string {
  if (!markdown) return '';
  const clean = markdown
    .replace(/#+\s+/g, '')
    .replace(/[*_`~[\]]/g, '')
    .replace(/\(.*?\)/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ slug: string }>;
}): Promise<Metadata> {
  const { slug } = await params;
  const h = await getHelp(slug);
  const cleanTitle = (h?.title || 'Hướng dẫn sử dụng').replace(/^[^\w\s\u00C0-\u1EF9]+/u, '').trim();

  return pageMeta({
    title: `${cleanTitle} - Hướng dẫn ShieldCall VN`,
    description: strip(h?.content) || 'Cẩm nang hướng dẫn sử dụng và bảo mật tài khoản từ ShieldCall VN.',
    path: `/helps/${slug}/`,
    ogImage: '/icon.png',
  });
}

export default async function RoutePage({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  const h = await getHelp(slug);
  const cleanTitle = (h?.title || slug).replace(/^[^\w\s\u00C0-\u1EF9]+/u, '').trim();

  const articleJsonLd = h
    ? {
        '@context': 'https://schema.org',
        '@type': 'TechArticle',
        headline: cleanTitle,
        description: strip(h.content),
        url: `${SITE_URL}/helps/${slug}/`,
        publisher: {
          '@type': 'Organization',
          name: 'ShieldCall VN',
          logo: {
            '@type': 'ImageObject',
            url: `${SITE_URL}/logo.png`,
          },
        },
        inLanguage: 'vi-VN',
      }
    : null;

  const breadcrumbJsonLd = {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: [
      {
        '@type': 'ListItem',
        position: 1,
        name: 'Trang chủ',
        item: `${SITE_URL}/`,
      },
      {
        '@type': 'ListItem',
        position: 2,
        name: 'Trung tâm hướng dẫn',
        item: `${SITE_URL}/helps/`,
      },
      {
        '@type': 'ListItem',
        position: 3,
        name: cleanTitle,
        item: `${SITE_URL}/helps/${slug}/`,
      },
    ],
  };

  return (
    <RouteShell>
      {articleJsonLd && (
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(articleJsonLd) }}
        />
      )}
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(breadcrumbJsonLd) }}
      />
      <Page />
    </RouteShell>
  );
}
