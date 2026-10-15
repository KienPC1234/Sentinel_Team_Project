import type { MetadataRoute } from 'next';
import { SITE_URL } from '@/lib/site-config';

export default function robots(): MetadataRoute.Robots {
  const disallowList = [
    '/admin-cp/',
    '/admin-panel/',
    '/admin/',
    '/api/',
    '/accounts/',
    '/profile/',
    '/dashboard/',
    '/change-password/',
    '/logout/',
    '/my-reports/',
    '/scan/status/',
  ];

  return {
    rules: [
      {
        userAgent: 'Googlebot',
        allow: [
          '/',
          '/_next/static/',
          '/_next/image',
          '/static/',
          '/media/',
          '/scan/',
          '/learn/',
          '/helps/',
          '/forum/',
          '/scam-radar/',
        ],
        disallow: disallowList,
      },
      {
        userAgent: '*',
        allow: [
          '/',
          '/_next/static/',
          '/_next/image',
          '/static/',
          '/media/',
        ],
        disallow: disallowList,
      },
    ],
    sitemap: `${SITE_URL}/sitemap.xml`,
    host: SITE_URL,
  };
}
