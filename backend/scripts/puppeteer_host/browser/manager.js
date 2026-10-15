const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
const path = require('path');

puppeteer.use(StealthPlugin());

let browserInstance = null;
let launchPromise = null;
let renderCount = 0;
const MAX_RENDERS_BEFORE_RECYCLE = 50;

const profileDir = path.resolve(process.env.PUPPETEER_PROFILE_DIR || './puppeteer_profile');
const remoteDebuggingPort = Number(process.env.PUPPETEER_DEBUG_PORT || 9222);
const remoteDebuggingHost = process.env.PUPPETEER_DEBUG_HOST || '0.0.0.0';

async function launchBrowser() {
  if (browserInstance) {
    if (browserInstance.isConnected()) return browserInstance;
    browserInstance = null;
  }

  const fs = require('fs');
  const candidatePaths = [
    process.env.PUPPETEER_EXECUTABLE_PATH,
    '/usr/bin/chromium-browser',
    '/usr/bin/chromium',
    '/snap/bin/chromium',
    '/usr/bin/google-chrome'
  ].filter(p => p && fs.existsSync(p));

  const launchOptions = {
    headless: "new",
    userDataDir: profileDir,
    ignoreHTTPSErrors: true,
    args: [
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
      `--remote-debugging-port=${remoteDebuggingPort}`,
      `--remote-debugging-address=${remoteDebuggingHost}`
    ],
    defaultViewport: null
  };

  if (candidatePaths.length > 0) {
    launchOptions.executablePath = candidatePaths[0];
  }

  launchPromise = puppeteer.launch(launchOptions)
    .then(browser => {
      browserInstance = browser;
      renderCount = 0;
      browserInstance.on('disconnected', () => {
        browserInstance = null;
      });

      return browserInstance;
    })
    .finally(() => {
      launchPromise = null;
    });

  return launchPromise;
}

async function incrementRenderCount() {
  renderCount++;
  if (renderCount >= MAX_RENDERS_BEFORE_RECYCLE) {
    // Recycle browser in background to free Chrome memory
    setTimeout(async () => {
      try {
        if (browserInstance) {
          const pages = await browserInstance.pages();
          if (pages.length <= 1) {
            await closeBrowser();
          }
        }
      } catch {}
    }, 1000);
  }
}

async function closeBrowser() {
  if (browserInstance) {
    try {
      await browserInstance.close();
    } catch {}
    browserInstance = null;
    renderCount = 0;
  }
}

async function getBrowserInfo() {
  const browser = await launchBrowser();
  return {
    wsEndpoint: browser.wsEndpoint(),
    profileDir,
    remoteDebuggingHost,
    remoteDebuggingPort
  };
}

module.exports = {
  launchBrowser,
  closeBrowser,
  getBrowserInfo,
  incrementRenderCount
};