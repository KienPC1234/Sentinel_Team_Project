import fs from 'node:fs';
import path from 'node:path';
import { z } from 'zod';

const envSchema = z.object({
  PORT: z.coerce.number().int().positive().default(3010),
  HOST: z.string().default('127.0.0.1'),
  PUPPETEER_EXECUTABLE_PATH: z.string().optional(),
  PUPPETEER_PROFILE_DIR: z.string().default('./puppeteer_profile'),
  PUPPETEER_DEBUG_PORT: z.coerce.number().int().positive().default(9222),
  PUPPETEER_DEBUG_HOST: z.string().default('0.0.0.0'),
  PUPPETEER_IDLE_TAB_TIMEOUT_MS: z.coerce.number().int().positive().default(10 * 60 * 1000),
  PUPPETEER_TAB_CLEANUP_INTERVAL_MS: z.coerce.number().int().positive().default(60 * 1000),
  MAX_RENDERS_BEFORE_RECYCLE: z.coerce.number().int().positive().default(50),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('production'),
});

const parsedEnv = envSchema.parse({
  PORT: process.env.PUPPETEER_HOST_PORT || process.env.PORT,
  HOST: process.env.PUPPETEER_HOST_BIND || process.env.HOST,
  PUPPETEER_EXECUTABLE_PATH: process.env.PUPPETEER_EXECUTABLE_PATH,
  PUPPETEER_PROFILE_DIR: process.env.PUPPETEER_PROFILE_DIR,
  PUPPETEER_DEBUG_PORT: process.env.PUPPETEER_DEBUG_PORT,
  PUPPETEER_DEBUG_HOST: process.env.PUPPETEER_DEBUG_HOST,
  PUPPETEER_IDLE_TAB_TIMEOUT_MS: process.env.PUPPETEER_IDLE_TAB_TIMEOUT_MS,
  PUPPETEER_TAB_CLEANUP_INTERVAL_MS: process.env.PUPPETEER_TAB_CLEANUP_INTERVAL_MS,
  MAX_RENDERS_BEFORE_RECYCLE: process.env.MAX_RENDERS_BEFORE_RECYCLE,
  NODE_ENV: process.env.NODE_ENV,
});

function resolveChromiumPath(preferredPath?: string): string | undefined {
  if (preferredPath && fs.existsSync(preferredPath)) {
    return preferredPath;
  }

  const standardPaths = [
    '/usr/bin/chromium-browser',
    '/usr/bin/chromium',
    '/snap/bin/chromium',
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
  ];

  return standardPaths.find((p) => fs.existsSync(p));
}

export const config = {
  ...parsedEnv,
  executablePath: resolveChromiumPath(parsedEnv.PUPPETEER_EXECUTABLE_PATH),
  resolvedProfileDir: path.resolve(parsedEnv.PUPPETEER_PROFILE_DIR),
};

