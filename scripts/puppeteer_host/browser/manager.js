const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
const path = require('path');

puppeteer.use(StealthPlugin());

let browserInstance = null;
let launchPromise = null;

const profileDir = path.resolve(process.env.PUPPETEER_PROFILE_DIR || './puppeteer_profile');
const remoteDebuggingPort = Number(process.env.PUPPETEER_DEBUG_PORT || 9222);
const remoteDebuggingHost = process.env.PUPPETEER_DEBUG_HOST || '0.0.0.0';

async function launchBrowser() {
  if (browserInstance) {
    if (browserInstance.isConnected()) return browserInstance;
    browserInstance = null;
  }

  if (launchPromise) return launchPromise;

  launchPromise = puppeteer.launch({
      headless: "new",
      userDataDir: profileDir,
      ignoreHTTPSErrors: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--start-maximized',
        `--remote-debugging-port=${remoteDebuggingPort}`,
        `--remote-debugging-address=${remoteDebuggingHost}`
      ],
      defaultViewport: null
    })
    .then(browser => {
      browserInstance = browser;
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

async function closeBrowser() {
  if (browserInstance) {
    await browserInstance.close();
    browserInstance = null;
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
  getBrowserInfo
};