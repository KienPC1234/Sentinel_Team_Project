import fs from 'node:fs';
import puppeteer from 'puppeteer-extra';
import StealthPlugin from 'puppeteer-extra-plugin-stealth';
import type { Browser } from 'puppeteer';
import { config } from '../config';
import { logger } from '../logger';

puppeteer.use(StealthPlugin());

export interface BrowserInfo {
  wsEndpoint: string;
  profileDir: string;
  remoteDebuggingHost: string;
  remoteDebuggingPort: number;
}

let browserInstance: Browser | null = null;
let launchPromise: Promise<Browser> | null = null;
let renderCount = 0;

export async function launchBrowser(): Promise<Browser> {
  if (browserInstance) {
    if (browserInstance.isConnected()) {
      return browserInstance;
    }
    browserInstance = null;
  }

  if (launchPromise) {
    return launchPromise;
  }

  // Ensure profile directory exists
  if (!fs.existsSync(config.resolvedProfileDir)) {
    fs.mkdirSync(config.resolvedProfileDir, { recursive: true });
  }

  const launchArgs = [
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-dev-shm-usage',
    '--disable-accelerated-2d-canvas',
    '--disable-gpu',
    '--disable-blink-features=AutomationControlled',
    '--no-first-run',
    '--no-zygote',
    '--disable-background-networking',
    '--disable-default-apps',
    '--disable-extensions',
    '--disable-sync',
    '--disable-translate',
    '--hide-scrollbars',
    '--metrics-recording-only',
    '--mute-audio',
    '--safebrowsing-disable-auto-update',
    `--remote-debugging-port=${config.PUPPETEER_DEBUG_PORT}`,
    `--remote-debugging-address=${config.PUPPETEER_DEBUG_HOST}`,
  ];

  logger.info('BrowserManager', 'Launching headless Chromium instance...', {
    executablePath: config.executablePath,
    profileDir: config.resolvedProfileDir,
    debugPort: config.PUPPETEER_DEBUG_PORT,
  });

  launchArgs.push('--ignore-certificate-errors');

  launchPromise = (async () => {
    try {
      const browser = (await puppeteer.launch({
        headless: true,
        userDataDir: config.resolvedProfileDir,
        acceptInsecureCerts: true,
        args: launchArgs,
        defaultViewport: null,
        ...(config.executablePath ? { executablePath: config.executablePath } : {}),
      })) as unknown as Browser;

      browserInstance = browser;
      renderCount = 0;

      browser.on('disconnected', () => {
        logger.warn('BrowserManager', 'Browser instance disconnected.');
        if (browserInstance === browser) {
          browserInstance = null;
        }
      });

      return browser;
    } catch (error) {
      logger.error('BrowserManager', 'Failed to launch Chromium browser:', error);
      browserInstance = null;
      throw error;
    } finally {
      launchPromise = null;
    }
  })();

  return launchPromise;
}

export async function incrementRenderCount(): Promise<void> {
  renderCount += 1;
  if (renderCount >= config.MAX_RENDERS_BEFORE_RECYCLE) {
    logger.info(
      'BrowserManager',
      `Render threshold reached (${renderCount}/${config.MAX_RENDERS_BEFORE_RECYCLE}). Scheduling browser recycle...`
    );
    setTimeout(async () => {
      try {
        if (browserInstance && browserInstance.isConnected()) {
          const pages = await browserInstance.pages();
          if (pages.length <= 1) {
            await closeBrowser();
            logger.info('BrowserManager', 'Browser successfully recycled to release memory.');
          }
        }
      } catch (err) {
        logger.warn('BrowserManager', 'Error during scheduled browser recycle:', err);
      }
    }, 1000);
  }
}

export async function closeBrowser(): Promise<void> {
  if (browserInstance) {
    try {
      if (browserInstance.isConnected()) {
        await browserInstance.close();
      }
    } catch (err) {
      logger.warn('BrowserManager', 'Error closing browser:', err);
    } finally {
      browserInstance = null;
      renderCount = 0;
    }
  }
}

export async function getBrowserInfo(): Promise<BrowserInfo> {
  const browser = await launchBrowser();
  return {
    wsEndpoint: browser.wsEndpoint(),
    profileDir: config.resolvedProfileDir,
    remoteDebuggingHost: config.PUPPETEER_DEBUG_HOST,
    remoteDebuggingPort: config.PUPPETEER_DEBUG_PORT,
  };
}
