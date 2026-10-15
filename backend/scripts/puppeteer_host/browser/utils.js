const randomUseragent = require('random-useragent');
const dns = require('dns').promises;
const net = require('net');

/**
 * Checks if an IP is in a private, loopback, or link-local range.
 */
function isPrivateIp(ip) {
  if (!ip) return false;
  
  // IPv4 checks
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    if (parts[0] === 127) return true; // 127.0.0.0/8 Loopback
    if (parts[0] === 10) return true;  // 10.0.0.0/8 Private
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true; // 172.16.0.0/12 Private
    if (parts[0] === 192 && parts[1] === 168) return true; // 192.168.0.0/16 Private
    if (parts[0] === 169 && parts[1] === 254) return true; // 169.254.0.0/16 Link-local / Cloud metadata
    if (parts[0] === 0) return true; // 0.0.0.0/8
    return false;
  }

  // IPv6 checks
  if (net.isIPv6(ip)) {
    const normalized = ip.toLowerCase();
    if (normalized === '::1' || normalized === '::') return true;
    if (normalized.startsWith('fe80:') || normalized.startsWith('fc') || normalized.startsWith('fd')) return true;
    return false;
  }

  return false;
}

/**
 * Validates that input is a valid HTTP/HTTPS URL and prevents SSRF to internal resources.
 */
async function isSafeExternalUrl(input) {
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

    // Resolve DNS hostname to IP
    try {
      const addresses = await dns.lookup(hostname, { all: true });
      for (const addr of addresses) {
        if (isPrivateIp(addr.address)) {
          return false;
        }
      }
    } catch {
      return false; // Cannot resolve hostname
    }

    return true;
  } catch {
    return false;
  }
}

function isHttpUrl(input) {
  try {
    const parsed = new URL(input);
    return ['http:', 'https:'].includes(parsed.protocol);
  } catch {
    return false;
  }
}

function detectCaptcha(content = '', html = '') {
  const blob = `${content}\n${html}`.toLowerCase();
  return [
    'captcha',
    'recaptcha',
    'hcaptcha',
    'verify you are human',
    'checking your browser',
    'cloudflare turnstile'
  ].some(m => blob.includes(m));
}

function getRandomUA() {
  return randomUseragent.getRandom(ua => (
    ua.browserName === 'Chrome'
    && ua.osName === 'Windows'
    && !/Mobile/i.test(ua.toString())
  )) || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36';
}

async function applyHumanizedPageSetup(page, userAgent) {
  const ua = userAgent || getRandomUA();
  await page.setUserAgent(ua);
  await page.setViewport({
    width: 1440,
    height: 900,
    deviceScaleFactor: 1,
    isMobile: false,
    hasTouch: false
  });

  await page.setExtraHTTPHeaders({
    'accept-language': 'vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7',
    'sec-ch-ua': '"Not A(Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
  });

  // Mask automated flags
  await page.evaluateOnNewDocument(() => {
    Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
    window.chrome = { runtime: {} };
  });
}

module.exports = {
  isHttpUrl,
  isSafeExternalUrl,
  detectCaptcha,
  getRandomUA,
  applyHumanizedPageSetup
};