import type { Metadata } from 'next';
import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import { SITE_URL } from '@/lib/site-config';
import Page from '@/views/Forum/ForumDetail';

const DJANGO = process.env.API_TARGET || 'http://127.0.0.1:8001';

interface PostMeta {
  id?: number;
  title?: string;
  content?: string;
  author_username?: string;
  created_at?: string;
  category_display?: string;
}

async function getPost(id: string): Promise<PostMeta | null> {
  try {
    const res = await fetch(`${DJANGO}/api/v1/forum/posts/${id}/`, { next: { revalidate: 60 } });
    if (!res.ok) return null;
    return (await res.json()) as PostMeta;
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
  params: Promise<{ id: string }>;
}): Promise<Metadata> {
  const { id } = await params;
  const p = await getPost(id);

  return pageMeta({
    title: p?.title ? `${p.title} - Diễn đàn ShieldCall VN` : 'Bài viết diễn đàn - ShieldCall VN',
    description: strip(p?.content) || 'Thảo luận, chia sẻ kinh nghiệm cảnh giác lừa đảo trực tuyến trên diễn đàn ShieldCall VN.',
    path: `/forum/${id}/`,
    ogImage: '/icon.png',
  });
}

export default async function RoutePage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const p = await getPost(id);

  const forumJsonLd = p
    ? {
        '@context': 'https://schema.org',
        '@type': 'DiscussionForumPosting',
        headline: p.title,
        text: strip(p.content, 500),
        url: `${SITE_URL}/forum/${id}/`,
        datePublished: p.created_at,
        author: {
          '@type': 'Person',
          name: p.author_username || 'Thành viên',
        },
        publisher: {
          '@type': 'Organization',
          name: 'ShieldCall VN',
          logo: {
            '@type': 'ImageObject',
            url: `${SITE_URL}/logo.png`,
          },
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
        name: 'Diễn đàn',
        item: `${SITE_URL}/forum/`,
      },
      {
        '@type': 'ListItem',
        position: 3,
        name: p?.title || `Thảo luận #${id}`,
        item: `${SITE_URL}/forum/${id}/`,
      },
    ],
  };

  return (
    <RouteShell>
      {forumJsonLd && (
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(forumJsonLd) }}
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
