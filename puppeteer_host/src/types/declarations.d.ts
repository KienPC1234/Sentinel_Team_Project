declare module 'random-useragent' {
  interface UserAgentData {
    folder?: string;
    description?: string;
    userAgent?: string;
    appCodename?: string;
    appName?: string;
    appVersion?: string;
    platform?: string;
    vendor?: string;
    vendorSub?: string;
    browserName?: string;
    browserMajor?: string;
    browserVersion?: string;
    deviceModel?: string;
    deviceType?: string;
    deviceVendor?: string;
    engineName?: string;
    engineVersion?: string;
    osName?: string;
    osVersion?: string;
  }

  export function getRandom(filter?: (ua: UserAgentData) => boolean): string | null;
  export function getAll(filter?: (ua: UserAgentData) => boolean): string[];
}

declare module 'puppeteer-extra-plugin-stealth' {
  import type { PuppeteerExtraPlugin } from 'puppeteer-extra';
  function plugin(): PuppeteerExtraPlugin;
  export = plugin;
}

