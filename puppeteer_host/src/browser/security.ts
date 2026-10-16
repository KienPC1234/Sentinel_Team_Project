import dns from 'node:dns/promises';
import net from 'node:net';
import randomUseragent from 'random-useragent';
import type { Page } from 'puppeteer';

export function isPrivateIp(ip: string): boolean {
  if (!ip) return false;

  // IPv4 ranges check
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    if (parts[0] === 127) return true; // 127.0.0.0/8 Loopback
    if (parts[0] === 10) return true; // 10.0.0.0/8 Private
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true; // 172.16.0.0/12 Private
    if (parts[0] === 192 && parts[1] === 168) return true; // 192.168.0.0/16 Private
    if (parts[0] === 169 && parts[1] === 254) return true; // 169.254.0.0/16 Link-local / Cloud metadata
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true; // 100.64.0.0/10 Carrier-grade NAT
    if (parts[0] === 0) return true; // 0.0.0.0/8 Broadcast / Current
    return false;
  }

  // IPv6 ranges check
  if (net.isIPv6(ip)) {
    const normalized = ip.toLowerCase();
    if (normalized === '::1' || normalized === '::') return true;
    if (
      normalized.startsWith('fe80:') || // Link-local
      normalized.startsWith('fc') || // Unique local
      normalized.startsWith('fd')
    ) {
      return true;
    }
    return false;
  }

  return false;
}

export async function isSafeExternalUrl(input: string): Promise<boolean> {
  try {
    const parsed = new URL(input);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return false;
    }

    const hostname = parsed.hostname.toLowerCase();
    if (['localhost', '127.0.0.1', '::1', '0.0.0.0', '169.254.169.254'].includes(hostname)) {
      return false;
    }

    // Direct IP check
    if (net.isIP(hostname) && isPrivateIp(hostname)) {
      return false;
    }

    // Resolve DNS hostname to verify against DNS rebinding / private IP targets
    try {
      const addresses = await dns.lookup(hostname, { all: true });
      for (const addr of addresses) {
        if (isPrivateIp(addr.address)) {
          return false;
        }
      }
    } catch {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

export function isHttpUrl(input: string): boolean {
  try {
    const parsed = new URL(input);
    return ['http:', 'https:'].includes(parsed.protocol);
  } catch {
    return false;
  }
}

export function detectCaptcha(content = '', html = ''): boolean {
  const combined = `${content}\n${html}`.toLowerCase();
  const signatures = [
    'captcha',
    'recaptcha',
    'hcaptcha',
    'verify you are human',
    'checking your browser',
    'cloudflare turnstile',
    'cf-turnstile',
    'challenge-running',
  ];
  return signatures.some((sig) => combined.includes(sig));
}

export function getRandomUA(): string {
  try {
    const candidate = randomUseragent.getRandom((ua: { browserName?: string; osName?: string }) => {
      return ua.browserName === 'Chrome' && ua.osName === 'Windows';
    });
    if (candidate && !/Mobile/i.test(candidate)) {
      return candidate;
    }
  } catch {
    // fallback
  }
  return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36';
}

export async function applyHumanizedPageSetup(page: Page, userAgent?: string): Promise<void> {
  const ua = userAgent || getRandomUA();
  await page.setUserAgent(ua);
  await page.setViewport({
    width: 1440,
    height: 900,
    deviceScaleFactor: 1,
    isMobile: false,
    hasTouch: false,
  });

  await page.setExtraHTTPHeaders({
    'accept-language': 'vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7',
    'sec-ch-ua': '"Not A(Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
  });

  // Evasion overrides
  await page.evaluateOnNewDocument(() => {
    Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
    (window as unknown as { chrome?: { runtime: Record<string, unknown> } }).chrome = { runtime: {} };
  });
}

