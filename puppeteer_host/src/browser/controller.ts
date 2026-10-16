import type { Page } from 'puppeteer';
import { config } from '../config';
import { logger } from '../logger';
import { launchBrowser, incrementRenderCount } from './manager';
import { getRandomUA, applyHumanizedPageSetup } from './security';

export interface RenderResult {
  title: string;
  content: string;
  html: string;
}

let activePage: Page | null = null;
const sessionUA = getRandomUA();
const pageActivity = new WeakMap<Page, number>();
const activityBoundPages = new WeakSet<Page>();

let tabCleanupTimer: NodeJS.Timeout | null = null;

function touchPage(page?: Page | null): void {
  if (!page || page.isClosed()) return;
  pageActivity.set(page, Date.now());
}

function bindPageActivity(page: Page): void {
  if (activityBoundPages.has(page)) return;
  activityBoundPages.add(page);

  const onActivity = () => touchPage(page);

  page.on('request', onActivity);
  page.on('framenavigated', onActivity);
  page.on('domcontentloaded', onActivity);
  page.on('load', onActivity);
  page.on('close', () => {
    if (activePage === page) {
      activePage = null;
    }
  });

  touchPage(page);
}

export async function cleanupIdleTabs(): Promise<void> {
  try {
    const browser = await launchBrowser();
    const pages = await browser.pages();
    const now = Date.now();

    for (const page of pages) {
      if (page === activePage) continue;
      const lastActive = pageActivity.get(page) || 0;
      if (now - lastActive >= config.PUPPETEER_IDLE_TAB_TIMEOUT_MS) {
        if (!page.isClosed()) {
          logger.debug('TabController', 'Closing idle page tab to free resources.');
          await page.close().catch(() => {});
        }
      }
    }
  } catch (err) {
    logger.debug('TabController', 'Failed during cleanupIdleTabs check:', err);
  }
}

export function startTabAutoCleanup(): void {
  if (tabCleanupTimer) return;
  tabCleanupTimer = setInterval(() => {
    cleanupIdleTabs().catch(() => {});
  }, config.PUPPETEER_TAB_CLEANUP_INTERVAL_MS);

  if (typeof tabCleanupTimer.unref === 'function') {
    tabCleanupTimer.unref();
  }
}

export function stopTabAutoCleanup(): void {
  if (!tabCleanupTimer) return;
  clearInterval(tabCleanupTimer);
  tabCleanupTimer = null;
}

export async function openPage(url: string): Promise<string> {
  startTabAutoCleanup();

  const browser = await launchBrowser();
  if (!activePage || activePage.isClosed()) {
    activePage = await browser.newPage();
    await applyHumanizedPageSetup(activePage, sessionUA);
    bindPageActivity(activePage);
  }

  touchPage(activePage);
  await activePage.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
  touchPage(activePage);

  return activePage.url();
}

export async function ensureActivePage(url = 'about:blank'): Promise<string> {
  startTabAutoCleanup();

  const browser = await launchBrowser();
  if (!activePage || activePage.isClosed()) {
    activePage = await browser.newPage();
    await applyHumanizedPageSetup(activePage, sessionUA);
    bindPageActivity(activePage);
    await activePage.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
  }

  touchPage(activePage);
  return activePage.url();
}

export async function renderPage(url: string, timeout = 25000): Promise<RenderResult> {
  startTabAutoCleanup();

  const browser = await launchBrowser();
  const page = await browser.newPage();

  bindPageActivity(page);

  try {
    await applyHumanizedPageSetup(page, sessionUA);

    // Optimize memory & bandwidth: drop heavy resources
    await page.setRequestInterception(true);
    page.on('request', (req) => {
      const resourceType = req.resourceType();
      if (['media', 'font', 'websocket'].includes(resourceType)) {
        req.abort();
      } else {
        req.continue();
      }
    });

    await page.goto(url, { timeout, waitUntil: 'domcontentloaded' });

    // Allow slight grace period for single-page client side hydration
    await new Promise((resolve) => setTimeout(resolve, 800));

    const title = await page.title();
    const content = await page.evaluate(() => document.body?.innerText || '');
    const html = await page.content();

    await incrementRenderCount();

    return { title, content, html };
  } finally {
    if (!page.isClosed()) {
      await page.close().catch(() => {});
    }
  }
}

export async function click(selector: string): Promise<void> {
  if (!activePage || activePage.isClosed()) throw new Error('No active page open.');
  touchPage(activePage);
  await activePage.click(selector);
  touchPage(activePage);
}

export async function type(selector: string, text: string): Promise<void> {
  if (!activePage || activePage.isClosed()) throw new Error('No active page open.');
  touchPage(activePage);
  await activePage.type(selector, text, { delay: 50 });
  touchPage(activePage);
}

export async function getCookies(): Promise<unknown[]> {
  if (!activePage || activePage.isClosed()) throw new Error('No active page open.');
  touchPage(activePage);
  return await activePage.cookies();
}

export function getActivePageUrl(): string | null {
  if (!activePage || activePage.isClosed()) return null;
  return activePage.url();
}

