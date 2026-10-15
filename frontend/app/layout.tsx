import type { Metadata, Viewport } from 'next';
import type { ReactNode } from 'react';
import { Inter } from 'next/font/google';
import Script from 'next/script';
import './globals.css';
import './liquid-glass.css';
import { AuthProvider } from '@/components/AuthContext';
import { PwaInit } from '@/components/ClientInit';
import { LayoutShell } from '@/components/LayoutShell';
import { Toaster } from '@/components/ui/sonner';
import { cn } from "@/lib/utils";

const inter = Inter({
  subsets: ['latin', 'vietnamese'],
  display: 'swap',
  variable: '--font-inter',
});

import { SITE_URL, SITE_NAME, REPO_URL, DEFAULT_DESC } from '@/lib/site-config';

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: {
    default: 'ShieldCall VN - Bảo vệ bạn khỏi lừa đảo số',
    template: '%s | ShieldCall VN',
  },
  description: DEFAULT_DESC,
  applicationName: SITE_NAME,
  keywords: [
    'ShieldCall',
    'lừa đảo số',
    'scam',
    'phishing',
    'kiểm tra số điện thoại',
    'kiểm tra website',
    'báo cáo lừa đảo',
    'an ninh mạng',
    'scam radar',
  ],
  authors: [{ name: 'ShieldCall VN', url: SITE_URL }],
  creator: SITE_NAME,
  publisher: SITE_NAME,
  category: 'security',
  alternates: { canonical: '/' },
  manifest: '/site.webmanifest',
  icons: {
    icon: [
      { url: '/favicon.ico' },
      { url: '/favicon-96x96.png', sizes: '96x96', type: 'image/png' },
      { url: '/favicon.svg', type: 'image/svg+xml' },
    ],
    shortcut: '/favicon.ico',
    apple: [{ url: '/apple-touch-icon.png', sizes: '180x180', type: 'image/png' }],
  },
  openGraph: {
    type: 'website',
    locale: 'vi_VN',
    siteName: SITE_NAME,
    url: '/',
    title: 'ShieldCall VN - Bảo vệ bạn khỏi lừa đảo số',
    description: DEFAULT_DESC,
    images: [{ url: '/icon.png', width: 512, height: 512, alt: 'ShieldCall VN' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'ShieldCall VN - Bảo vệ bạn khỏi lừa đảo số',
    description: DEFAULT_DESC,
    images: ['/icon.png'],
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      'max-video-preview': -1,
      'max-image-preview': 'large',
      'max-snippet': -1,
    },
  },
  formatDetection: { telephone: false },
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  themeColor: '#0d0d1f',
  colorScheme: 'dark',
};

const JSON_LD = {
  '@context': 'https://schema.org',
  '@graph': [
    {
      '@type': 'Organization',
      '@id': `${SITE_URL}/#organization`,
      name: SITE_NAME,
      url: SITE_URL,
      logo: `${SITE_URL}/logo.png`,
      description: DEFAULT_DESC,
      sameAs: [REPO_URL].filter(Boolean),
    },
    {
      '@type': 'WebSite',
      '@id': `${SITE_URL}/#website`,
      url: SITE_URL,
      name: SITE_NAME,
      description: DEFAULT_DESC,
      inLanguage: 'vi-VN',
      publisher: { '@id': `${SITE_URL}/#organization` },
      potentialAction: {
        '@type': 'SearchAction',
        target: {
          '@type': 'EntryPoint',
          urlTemplate: `${SITE_URL}/scan/lookup/?q={search_term_string}`,
        },
        'query-input': 'required name=search_term_string',
      },
    },
    {
      '@type': 'SoftwareApplication',
      '@id': `${SITE_URL}/#app`,
      name: 'ShieldCall VN',
      applicationCategory: 'SecurityApplication',
      operatingSystem: 'All',
      url: SITE_URL,
      offers: {
        '@type': 'Offer',
        price: '0',
        priceCurrency: 'VND',
      },
      description: DEFAULT_DESC,
      featureList: [
        'Quét số điện thoại lừa đảo',
        'Phân tích website lừa đảo & URL Phishing',
        'Tra cứu số tài khoản ngân hàng lừa đảo',
        'Kiểm tra mã độc APK và tệp tin sandbox',
        'Phát hiện tin nhắn mạo danh SMS Brandname',
        'Radar cảnh báo lừa đảo thời gian thực',
      ],
    },
  ],
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="vi" className={cn("dark", inter.variable, "font-sans")}>
      <head>
        {/* bootstrap-icons bundle từ npm (import trong globals.css) */}
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(JSON_LD) }}
        />
      </head>
      <body className={`${inter.className} font-sans`}>
        <AuthProvider>
          <PwaInit />
          <LayoutShell>{children}</LayoutShell>
          <Toaster richColors position="bottom-right" />
        </AuthProvider>
        {/* Google Translate (y bản gốc — phục vụ chọn ngôn ngữ footer) */}
        <Script id="google-translate-init" strategy="lazyOnload">
          {`function googleTranslateElementInit(){try{new google.translate.TranslateElement({pageLanguage:'vi',autoDisplay:false},'google_translate_element');}catch(e){}}`}
        </Script>
        <Script
          src="//translate.google.com/translate_a/element.js?cb=googleTranslateElementInit"
          strategy="lazyOnload"
        />
      </body>
    </html>
  );
}
