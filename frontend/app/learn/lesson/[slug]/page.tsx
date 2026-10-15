import type { Metadata } from 'next';
import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import Page from '@/views/Learn/LessonDetail';

const DJANGO = process.env.API_TARGET || 'http://127.0.0.1:8001';
import { SITE_URL } from '@/lib/site-config';

interface LessonMeta {
  id?: number;
  title?: string;
  slug?: string;
  content?: string;
  summary?: string;
  cover_image?: string | null;
  created_at?: string;
  category?: string;
  category_display?: string;
}

async function getLesson(slug: string): Promise<LessonMeta | null> {
  try {
    const res = await fetch(`${DJANGO}/api/v1/learn/lessons/${slug}/`, { next: { revalidate: 300 } });
    if (!res.ok) return null;
    return (await res.json()) as LessonMeta;
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
  const l = await getLesson(slug);
  return pageMeta({
    title: l?.title || 'Bài học kỹ năng số',
    description:
      l?.summary || strip(l?.content) || 'Bài học phòng tránh lừa đảo trực tuyến từ ShieldCall VN.',
    path: `/learn/lesson/${slug}/`,
    ogImage: l?.cover_image || '/icon.png',
    type: 'article',
  });
}

export default async function RoutePage({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  const l = await getLesson(slug);

  const lessonJsonLd = l
    ? {
        '@context': 'https://schema.org',
        '@type': 'LearningResource',
        name: l.title,
        description: l.summary || strip(l.content),
        image: l.cover_image ? [l.cover_image] : [`${SITE_URL}/icon.png`],
        datePublished: l.created_at,
        educationalLevel: 'Beginner to Advanced',
        learningResourceType: 'Lesson',
        inLanguage: 'vi-VN',
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
          '@id': `${SITE_URL}/learn/lesson/${slug}/`,
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
        name: 'Bài học an toàn số',
        item: `${SITE_URL}/learn/`,
      },
      {
        '@type': 'ListItem',
        position: 3,
        name: l?.title || slug,
        item: `${SITE_URL}/learn/lesson/${slug}/`,
      },
    ],
  };

  return (
    <RouteShell>
      {lessonJsonLd && (
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(lessonJsonLd) }}
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
