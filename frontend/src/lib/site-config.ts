/**
 * Centralized site configuration driven by environment variables.
 * Anti-hardcoding single source of truth.
 */

export const SITE_URL: string = (
  process.env.NEXT_PUBLIC_SITE_URL || 'https://sc.fptoj.com'
).replace(/\/+$/, '');

export const SITE_NAME: string =
  process.env.NEXT_PUBLIC_SITE_NAME || 'ShieldCall VN';

export const REPO_URL: string =
  process.env.NEXT_PUBLIC_REPO_URL || 'https://github.com/KienPC1234/Sentinel_Team_Project';

export const SUPPORT_EMAIL: string =
  process.env.NEXT_PUBLIC_SUPPORT_EMAIL || 'admin@fptoj.com';

export const HOTLINE: string =
  process.env.NEXT_PUBLIC_HOTLINE || '1800-1031';

export const DEFAULT_DESC: string =
  'ShieldCall VN - Hệ thống phòng thủ an ninh mạng và chống lừa đảo số đa lớp. Scan số điện thoại, tin nhắn, website, tài khoản ngân hàng và sandbox mã độc với AI.';

/** Gói gọn cấu hình site cho các component cũ dùng dạng object. */
export const SITE_CONFIG = {
  url: SITE_URL,
  name: SITE_NAME,
  repoUrl: REPO_URL,
  supportEmail: SUPPORT_EMAIL,
  hotline: HOTLINE,
  description: DEFAULT_DESC,
};

