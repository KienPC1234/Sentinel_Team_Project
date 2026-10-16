import { Router, type Request, type Response } from 'express';
import { z } from 'zod';
import { config } from '../config';
import { logger } from '../logger';
import { launchBrowser, getBrowserInfo } from '../browser/manager';
import * as controller from '../browser/controller';
import { isSafeExternalUrl, isHttpUrl, detectCaptcha } from '../browser/security';

export const apiRouter = Router();

function getBaseUrl(req: Request): string {
  const host = (req.get('x-forwarded-host') || req.get('host') || `127.0.0.1:${config.PORT}`).trim();
  const protocol = (req.get('x-forwarded-proto') || req.protocol || 'http').trim();
  return `${protocol}://${host}`;
}

/* 1. Healthcheck */
apiRouter.get('/health', async (_req: Request, res: Response): Promise<void> => {
  try {
    await launchBrowser();
    res.json({ ok: true, status: 'healthy', version: '2.0.0-ts' });
  } catch (error) {
    logger.error('Healthcheck', 'Browser healthcheck failed:', error);
    res.status(500).json({ ok: false, error: String((error as Error).message || error) });
  }
});

/* 2. Render Page */
const renderSchema = z.object({
  url: z.string().min(1),
  timeoutMs: z.coerce.number().int().positive().max(120000).optional().default(25000),
});

apiRouter.post('/render', async (req: Request, res: Response): Promise<void> => {
  const parseResult = renderSchema.safeParse(req.body);
  if (!parseResult.success) {
    res.status(400).json({
      ok: false,
      error: 'Invalid request payload',
      details: parseResult.error.flatten().fieldErrors,
    });
    return;
  }

  const { url, timeoutMs } = parseResult.data;

  const isSafe = await isSafeExternalUrl(url);
  if (!isSafe) {
    res.status(400).json({ ok: false, error: 'Invalid or blocked internal URL' });
    return;
  }

  try {
    const result = await controller.renderPage(url, timeoutMs);
    res.json({
      ok: true,
      title: result.title,
      captcha_detected: detectCaptcha(result.content, result.html),
      content: result.content.slice(0, 50000),
    });
  } catch (error) {
    logger.error('Render', `Failed to render url=${url}:`, (error as Error).message);
    res.status(500).json({ ok: false, error: String((error as Error).message || error) });
  }
});

/* 3. Open Page */
const openSchema = z.object({
  url: z.string().min(1),
});

apiRouter.post('/open', async (req: Request, res: Response): Promise<void> => {
  const parseResult = openSchema.safeParse(req.body);
  if (!parseResult.success) {
    res.status(400).json({ ok: false, error: 'Invalid request payload' });
    return;
  }

  const { url } = parseResult.data;
  const isSafe = await isSafeExternalUrl(url);
  if (!isSafe) {
    res.status(400).json({ ok: false, error: 'Invalid or blocked internal URL' });
    return;
  }

  try {
    const finalUrl = await controller.openPage(url);
    res.json({ ok: true, final_url: finalUrl });
  } catch (error) {
    res.status(500).json({ ok: false, error: String(error) });
  }
});

/* 4. Click */
const clickSchema = z.object({
  selector: z.string().min(1),
});

apiRouter.post('/click', async (req: Request, res: Response): Promise<void> => {
  const parseResult = clickSchema.safeParse(req.body);
  if (!parseResult.success) {
    res.status(400).json({ ok: false, error: 'Selector is required' });
    return;
  }

  try {
    await controller.click(parseResult.data.selector);
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: String(error) });
  }
});

/* 5. Type */
const typeSchema = z.object({
  selector: z.string().min(1),
  text: z.string(),
});

apiRouter.post('/type', async (req: Request, res: Response): Promise<void> => {
  const parseResult = typeSchema.safeParse(req.body);
  if (!parseResult.success) {
    res.status(400).json({ ok: false, error: 'Selector and text are required' });
    return;
  }

  try {
    await controller.type(parseResult.data.selector, parseResult.data.text);
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: String(error) });
  }
});

/* 6. Cookies */
apiRouter.get('/cookies', async (_req: Request, res: Response): Promise<void> => {
  try {
    const cookies = await controller.getCookies();
    res.json({ ok: true, cookies });
  } catch (error) {
    res.status(500).json({ ok: false, error: String(error) });
  }
});

/* 7. Session Login */
const sessionLoginSchema = z.object({
  url: z.string().optional(),
});

apiRouter.post('/session/login', async (req: Request, res: Response): Promise<void> => {
  const parseResult = sessionLoginSchema.safeParse(req.body);
  const rawUrl = parseResult.success ? parseResult.data.url : undefined;
  const targetUrl = rawUrl && isHttpUrl(rawUrl) ? rawUrl : 'about:blank';

  try {
    const currentUrl = await controller.ensureActivePage(targetUrl);
    const browser = await getBrowserInfo();
    res.json({
      ok: true,
      message: 'Remote login session ready. Manual actions will persist in the profile.',
      active_url: currentUrl,
      ws_endpoint: browser.wsEndpoint,
      profile_dir: browser.profileDir,
      cdp_http_hint: `http://127.0.0.1:${browser.remoteDebuggingPort}/json/version`,
      remote_connect_hint: `ws://<server-ip>:${browser.remoteDebuggingPort}/devtools/browser/...`,
    });
  } catch (error) {
    res.status(500).json({ ok: false, error: String(error) });
  }
});

/* 8. Session Status */
apiRouter.get('/session/status', async (req: Request, res: Response): Promise<void> => {
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
      remote_debug_port: browser.remoteDebuggingPort,
    });
  } catch (error) {
    res.status(500).json({ ok: false, error: String(error) });
  }
});

