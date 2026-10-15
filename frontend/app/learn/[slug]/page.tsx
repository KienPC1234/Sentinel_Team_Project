import type { Metadata } from 'next';
import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Learn/ArticleDetail';

const DJANGO = process.env.API_TARGET || 'http://127.0.0.1:8001';
import { SITE_URL } from '@/lib/site-config';

interface ArticleMeta {
  id?: number;
  title?: string;
  slug?: string;
  content?: string;
  summary?: string;
  cover_image?: string | null;
  author_name?: string;
  created_at?: string;
  category?: string;
  category_display?: string;
}

async function getArticle(slug: string): Promise<ArticleMeta | null> {
  try {
    const res = await fetch(`${DJANGO}/api/v1/articles/${slug}/`, { next: { revalidate: 300 } });
    if (!res.ok) return null;
    return (await res.json()) as ArticleMeta;
  } catch {
    return null;
  }
}

function strip(html?: string, max = 160): string {
  if (!html) return '';
  const text = html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ slug: string }>;
}): Promise<Metadata> {
  const { slug } = await params;
  const a = await getArticle(slug);
  return pageMeta({
    title: a?.title || 'Bài viết cảnh báo an ninh mạng',
    description:
      a?.summary || strip(a?.content) || 'Tin tức và kiến thức an ninh mạng từ ShieldCall VN.',
    path: `/learn/${slug}/`,
    ogImage: a?.cover_image || '/icon.png',
    type: 'article',
  });
}

export default async function RoutePage({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  const a = await getArticle(slug);

  const articleJsonLd = a
    ? {
        '@context': 'https://schema.org',
        '@type': 'NewsArticle',
        headline: a.title,
        description: a.summary || strip(a.content),
        image: a.cover_image ? [a.cover_image] : [`${SITE_URL}/icon.png`],
        datePublished: a.created_at,
        dateModified: a.created_at,
        author: [
          {
            '@type': 'Person',
            name: a.author_name || 'Ban biên tập ShieldCall VN',
          },
        ],
        publisher: {
          '@type': 'Organization',
          name: 'ShieldCall VN',
          logo: {
            '@type': 'ImageObject',
            url: `${SITE_URL}/logo.png`,
          },
        },
        mainEntityOfPage: {
          '@type': 'WebPage',
          '@id': `${SITE_URL}/learn/${slug}/`,
        },
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
        name: 'Cẩm nang an ninh mạng',
        item: `${SITE_URL}/learn/`,
      },
      {
        '@type': 'ListItem',
        position: 3,
        name: a?.title || slug,
        item: `${SITE_URL}/learn/${slug}/`,
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
