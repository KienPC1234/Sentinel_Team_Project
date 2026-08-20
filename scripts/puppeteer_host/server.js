const express = require('express');
const { isHttpUrl, detectCaptcha } = require('./browser/utils');
const { launchBrowser, closeBrowser, getBrowserInfo } = require('./browser/manager');
const controller = require('./browser/controller');

const app = express();
app.use(express.json({ limit: '2mb' }));

const PORT = process.env.PUPPETEER_HOST_PORT || 3010;

function getBaseUrl(req) {
  const host = req.get('x-forwarded-host') || req.get('host') || `127.0.0.1:${PORT}`;
  const protocol = req.get('x-forwarded-proto') || req.protocol || 'http';
  return `${protocol}://${host}`;
}

/* Health */
app.get('/health', async (req, res) => {
  await launchBrowser();
  res.json({ ok: true });
});

/* Render */
app.post('/render', async (req, res) => {
  const { url, timeoutMs } = req.body;

  if (!isHttpUrl(url)) {
    return res.status(400).json({ ok: false });
  }

  try {
    const result = await controller.renderPage(url, timeoutMs);
    res.json({
      ok: true,
      title: result.title,
      captcha_detected: detectCaptcha(result.content, result.html),
      content: result.content.slice(0, 50000)
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

/* Remote control endpoints */

app.post('/open', async (req, res) => {
  const { url } = req.body;
  if (!isHttpUrl(url)) {
    return res.status(400).json({ ok: false, error: 'Invalid url' });
  }

  try {
    const finalUrl = await controller.openPage(url);
    res.json({ ok: true, final_url: finalUrl });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.post('/click', async (req, res) => {
  try {
    await controller.click(req.body.selector);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.post('/type', async (req, res) => {
  try {
    await controller.type(req.body.selector, req.body.text);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.get('/cookies', async (req, res) => {
  try {
    const cookies = await controller.getCookies();
    res.json({ ok: true, cookies });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.post('/session/login', async (req, res) => {
  const { url } = req.body;
  const targetUrl = isHttpUrl(url) ? url : 'about:blank';

  try {
    const currentUrl = await controller.ensureActivePage(targetUrl);
    const browser = await getBrowserInfo();
    res.json({
      ok: true,
      message: 'Remote login session ready. Đăng nhập thủ công trên browser này, cookie/profile sẽ được lưu để tái sử dụng.',
      active_url: currentUrl,
      ws_endpoint: browser.wsEndpoint,
      profile_dir: browser.profileDir,
      cdp_http_hint: `http://127.0.0.1:${browser.remoteDebuggingPort}/json/version`,
      remote_connect_hint: `ws://<server-ip>:${browser.remoteDebuggingPort}/devtools/browser/...`
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

app.get('/session/status', async (req, res) => {
  try {
    const browser = await getBrowserInfo();
    const baseUrl = getBaseUrl(req);

    res.json({
      ok: true,
      active_url: controller.getActivePageUrl(),
      profile_dir: browser.profileDir,
      ws_endpoint: browser.wsEndpoint,
      cdp_http_version_url: `${baseUrl.replace(/:\d+$/, `:${browser.remoteDebuggingPort}`)}/json/version`,
      remote_debug_host: browser.remoteDebuggingHost,
      remote_debug_port: browser.remoteDebuggingPort
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

/* Graceful shutdown for supervisor */
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, closing browser...');
  controller.stopTabAutoCleanup();
  await closeBrowser();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, closing browser...');
  controller.stopTabAutoCleanup();
  await closeBrowser();
  process.exit(0);
});

app.listen(PORT, () => {
  controller.startTabAutoCleanup();
  console.log(`🔥 Modular Puppeteer running on http://127.0.0.1:${PORT}`);
});