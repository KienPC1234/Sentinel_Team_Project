const { launchBrowser } = require('./manager');
const { getRandomUA, applyHumanizedPageSetup } = require('./utils');

let activePage = null;
const sessionUA = getRandomUA();
const pageActivity = new Map();

const IDLE_TAB_TIMEOUT_MS = Number(process.env.PUPPETEER_IDLE_TAB_TIMEOUT_MS || 15 * 60 * 1000);
const TAB_CLEANUP_INTERVAL_MS = Number(process.env.PUPPETEER_TAB_CLEANUP_INTERVAL_MS || 60 * 1000);

let tabCleanupTimer = null;

function touchPage(page) {
  if (!page || page.isClosed()) return;
  pageActivity.set(page, Date.now());
}

function bindPageActivity(page) {
  if (!page || page.__activityBound) return;

  page.__activityBound = true;
  const onActivity = () => touchPage(page);

  page.on('request', onActivity);
  page.on('framenavigated', onActivity);
  page.on('domcontentloaded', onActivity);
  page.on('load', onActivity);
  page.on('close', () => {
    pageActivity.delete(page);
    if (activePage === page) {
      activePage = null;
    }
  });

  touchPage(page);
}

async function cleanupIdleTabs() {
  const now = Date.now();

  for (const [page, lastActiveAt] of pageActivity.entries()) {
    if (page.isClosed()) {
      pageActivity.delete(page);
      continue;
    }

    if (page === activePage) continue;

    const idleMs = now - lastActiveAt;
    if (idleMs >= IDLE_TAB_TIMEOUT_MS) {
      try {
        await page.close();
      } catch {
      } finally {
        pageActivity.delete(page);
      }
    }
  }
}

function startTabAutoCleanup() {
  if (tabCleanupTimer) return;
  tabCleanupTimer = setInterval(() => {
    cleanupIdleTabs().catch(() => {
    });
  }, TAB_CLEANUP_INTERVAL_MS);

  if (typeof tabCleanupTimer.unref === 'function') {
    tabCleanupTimer.unref();
  }
}

function stopTabAutoCleanup() {
  if (!tabCleanupTimer) return;
  clearInterval(tabCleanupTimer);
  tabCleanupTimer = null;
}

async function openPage(url) {
  startTabAutoCleanup();

  const browser = await launchBrowser();
  if (!activePage || activePage.isClosed()) {
    activePage = await browser.newPage();
    await applyHumanizedPageSetup(activePage, sessionUA);
    bindPageActivity(activePage);
  }

  touchPage(activePage);
  await activePage.goto(url, { waitUntil: 'domcontentloaded' });
  touchPage(activePage);

  return activePage.url();
}

async function ensureActivePage(url = 'about:blank') {
  startTabAutoCleanup();

  const browser = await launchBrowser();
  if (!activePage || activePage.isClosed()) {
    activePage = await browser.newPage();
    await applyHumanizedPageSetup(activePage, sessionUA);
    bindPageActivity(activePage);
    await activePage.goto(url, { waitUntil: 'domcontentloaded' });
  }

  touchPage(activePage);
  return activePage.url();
}

async function renderPage(url, timeout = 20000) {
  startTabAutoCleanup();

  const browser = await launchBrowser();
  const page = await browser.newPage();

  bindPageActivity(page);

  try {
    await applyHumanizedPageSetup(page, sessionUA);
    await page.goto(url, { timeout, waitUntil: 'domcontentloaded' });

    const title = await page.title();
    const content = await page.evaluate(() => document.body?.innerText || '');
    const html = await page.content();

    return { title, content, html };
  } finally {
    if (!page.isClosed()) {
      await page.close();
    }
    pageActivity.delete(page);
  }
}

async function closeAllIdleTabsNow() {
  await cleanupIdleTabs();
}

async function click(selector) {
  if (!activePage) throw new Error('No active page');
  touchPage(activePage);
  await activePage.click(selector);
  touchPage(activePage);
}

async function type(selector, text) {
  if (!activePage) throw new Error('No active page');
  touchPage(activePage);
  await activePage.type(selector, text, { delay: 50 });
  touchPage(activePage);
}

async function getCookies() {
  if (!activePage) throw new Error('No active page');
  touchPage(activePage);
  return await activePage.cookies();
}

function getActivePageUrl() {
  if (!activePage || activePage.isClosed()) return null;
  return activePage.url();
}

module.exports = {
  startTabAutoCleanup,
  stopTabAutoCleanup,
  closeAllIdleTabsNow,
  openPage,
  ensureActivePage,
  renderPage,
  click,
  type,
  getCookies,
  getActivePageUrl
};