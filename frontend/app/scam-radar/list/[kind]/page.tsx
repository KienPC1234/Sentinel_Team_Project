import type { Metadata } from 'next';
import { RouteShell } from '@/components/RouteShell';
import { pageMeta } from '@/lib/seo';
import { SITE_URL } from '@/lib/site-config';
import Page from '@/views/Radar/RadarList';

const RADAR_TITLES: Record<string, { title: string; desc: string }> = {
  phones: {
    title: 'Danh sách số điện thoại lừa đảo bị tố cáo',
    desc: 'Cập nhật danh sách số điện thoại lừa đảo, mạo danh công an, ngân hàng được cảnh báo nhiều nhất.',
  },
  accounts: {
    title: 'Danh sách số tài khoản ngân hàng lừa đảo',
    desc: 'Cảnh báo các số tài khoản ngân hàng gian lận, lừa đảo chuyển tiền và đầu tư tài chính.',
  },
  domains: {
    title: 'Danh sách website và liên kết lừa đảo',
    desc: 'Danh sách các tên miền giả mạo, đường link phishing và trang web độc hại bị cộng đồng báo cáo.',
  },
  emails: {
    title: 'Danh sách địa chỉ email lừa đảo',
    desc: 'Danh sách email mạo danh doanh nghiệp, thông báo trúng thưởng và email phishing độc hại.',
  },
};

export async function generateMetadata({
  params,
}: {
  params: Promise<{ kind: string }>;
}): Promise<Metadata> {
  const { kind } = await params;
  const meta = RADAR_TITLES[kind] || {
    title: 'Radar cảnh báo lừa đảo thời gian thực',
    desc: 'Danh sách các đối tượng và phương thức lừa đảo số được phát hiện và cảnh báo theo thời gian thực.',
  };

  return pageMeta({
    title: `${meta.title} - ShieldCall VN`,
    description: meta.desc,
    path: `/scam-radar/list/${kind}/`,
    ogImage: '/icon.png',
  });
}

export default async function RoutePage({
  params,
}: {
  params: Promise<{ kind: string }>;
}) {
  const { kind } = await params;
  const meta = RADAR_TITLES[kind] || {
    title: `Radar lừa đảo ${kind}`,
    desc: 'Danh sách lừa đảo số từ cộng đồng.',
  };

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
        name: 'Scam Radar',
        item: `${SITE_URL}/scam-radar/`,
      },
      {
        '@type': 'ListItem',
        position: 3,
        name: meta.title,
        item: `${SITE_URL}/scam-radar/list/${kind}/`,
      },
    ],
  };

  return (
    <RouteShell>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(breadcrumbJsonLd) }}
      />
      <Page />
    </RouteShell>
  );
}
