import type { Metadata } from 'next';

import { SITE_URL } from '@/lib/site-config';

/** Tạo metadata chuẩn cho một route (title/description/canonical/OG/Twitter). */
export function pageMeta({
  title,
  description,
  path = '/',
  ogImage = '/icon.png',
  type = 'website',
  noIndex = false,
}: {
  title: string;
  description?: string;
  path?: string;
  ogImage?: string;
  type?: 'website' | 'article';
  noIndex?: boolean;
}): Metadata {
  return {
    metadataBase: new URL(SITE_URL),
    title,
    ...(description ? { description } : {}),
    alternates: { canonical: path },
    openGraph: {
      title,
      ...(description ? { description } : {}),
      url: path,
      type,
      images: [{ url: ogImage, alt: title }],
    },
    twitter: {
      card: 'summary_large_image',
      title,
      ...(description ? { description } : {}),
      images: [ogImage],
    },
    ...(noIndex ? { robots: { index: false, follow: false } } : {}),
  };
}

export const SITE_URL_PUBLIC = SITE_URL;

/** fetch API công khai phía server (cho generateMetadata/sitemap). Trả null nếu lỗi. */
export async function fetchPublic<T>(path: string): Promise<T | null> {
  const base = process.env.API_TARGET || 'http://127.0.0.1:8001';
  try {
    const res = await fetch(`${base}/api/v1${path}`, { next: { revalidate: 300 } });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

/** Bỏ tag HTML, cắt ngắn cho meta description. */
export function excerpt(html: string | undefined | null, max = 160): string {
  if (!html) return '';
  const text = String(html).replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}
