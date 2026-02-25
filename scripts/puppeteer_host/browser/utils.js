const randomUseragent = require('random-useragent');

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
    'checking your browser'
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
  await page.setUserAgent(userAgent || getRandomUA());
  await page.setViewport({
    width: 1366,
    height: 768,
    deviceScaleFactor: 1,
    isMobile: false,
    hasTouch: false
  });
  await page.setExtraHTTPHeaders({
    'accept-language': 'vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7'
  });
}

module.exports = {
  isHttpUrl,
  detectCaptcha,
  getRandomUA,
  applyHumanizedPageSetup
};