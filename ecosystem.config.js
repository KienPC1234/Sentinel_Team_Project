const fs = require('fs');
const path = require('path');

const ROOT_DIR = process.env.ROOT_DIR || __dirname;

// Lightweight zero-dependency .env parser for robust environment configuration
const envConfig = {};
const envPath = path.join(ROOT_DIR, '.env');
if (fs.existsSync(envPath)) {
  try {
    const rawContent = fs.readFileSync(envPath, 'utf8');
    rawContent.split(/\r?\n/).forEach((line) => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#') || !trimmed.includes('=')) return;
      const idx = trimmed.indexOf('=');
      const key = trimmed.substring(0, idx).trim();
      let val = trimmed.substring(idx + 1).trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      envConfig[key] = val;
    });
  } catch (err) {
    // Non-fatal, fall back to process.env or defaults
  }
}

function getEnv(key, defaultVal) {
  return process.env[key] || envConfig[key] || defaultVal;
}

// Configurable runtime paths
const VENV_DIR = getEnv('VIRTUAL_ENV', path.join(ROOT_DIR, '.venv'));
const VENV_BIN = path.join(VENV_DIR, 'bin');
const VENV_PYTHON = getEnv('PYTHON_BIN', path.join(VENV_BIN, 'python'));
const VENV_DAPHNE = getEnv('DAPHNE_BIN', path.join(VENV_BIN, 'daphne'));
const VENV_CELERY = getEnv('CELERY_BIN', path.join(VENV_BIN, 'celery'));
const PUPPETEER_DIR = path.join(ROOT_DIR, 'scripts', 'puppeteer_host');

// Configurable network parameters
const WEB_HOST = getEnv('WEB_HOST', '0.0.0.0');
const WEB_PORT = getEnv('PORT', getEnv('WEB_PORT', '8001'));
const PUPPETEER_PORT = getEnv('PUPPETEER_HOST_PORT', '3010');

// Configurable Celery parameters
const CELERY_CONCURRENCY = getEnv('CELERY_CONCURRENCY', '4');
const CELERY_LOGLEVEL = getEnv('CELERY_LOGLEVEL', 'info');
const CELERY_QUEUES = getEnv('CELERY_QUEUES', 'celery,default');
const CELERY_BEAT_LOGLEVEL = getEnv('CELERY_BEAT_LOGLEVEL', 'info');

// Configurable memory thresholds
const WEB_MAX_MEM = getEnv('PM2_WEB_MAX_MEMORY', '3G');
const CELERY_MAX_MEM = getEnv('PM2_CELERY_MAX_MEMORY', '4G');
const BEAT_MAX_MEM = getEnv('PM2_BEAT_MAX_MEMORY', '1G');
const PUPPETEER_MAX_MEM = getEnv('PM2_PUPPETEER_MAX_MEMORY', '1G');

module.exports = {
  apps: [
    {
      name: 'pkv-web',
      cwd: ROOT_DIR,
      script: VENV_DAPHNE,
      args: `-b ${WEB_HOST} -p ${WEB_PORT} --proxy-headers PKV.asgi:application`,
      interpreter: VENV_PYTHON,
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: WEB_MAX_MEM,
      env: {
        DJANGO_SETTINGS_MODULE: 'PKV.settings',
        PYTHONUNBUFFERED: '1',
        PORT: WEB_PORT,
        WEB_PORT: WEB_PORT,
        WEB_HOST: WEB_HOST,
      },
    },
    {
      name: 'pkv-celery',
      cwd: ROOT_DIR,
      script: VENV_CELERY,
      args: `-A PKV worker --loglevel=${CELERY_LOGLEVEL} --concurrency=${CELERY_CONCURRENCY} --pool=threads -Q ${CELERY_QUEUES}`,
      interpreter: VENV_PYTHON,
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: CELERY_MAX_MEM,
      env: {
        DJANGO_SETTINGS_MODULE: 'PKV.settings',
        PYTHONUNBUFFERED: '1',
      },
    },
    {
      name: 'pkv-celery-beat',
      cwd: ROOT_DIR,
      script: VENV_CELERY,
      args: `-A PKV beat --loglevel=${CELERY_BEAT_LOGLEVEL}`,
      interpreter: VENV_PYTHON,
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: BEAT_MAX_MEM,
      env: {
        DJANGO_SETTINGS_MODULE: 'PKV.settings',
        PYTHONUNBUFFERED: '1',
      },
    },
    {
      name: 'pkv-puppeteer',
      cwd: PUPPETEER_DIR,
      script: 'server.js',
      interpreter: 'node',
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: PUPPETEER_MAX_MEM,
      env: {
        PUPPETEER_HOST_PORT: PUPPETEER_PORT,
        NODE_ENV: getEnv('NODE_ENV', 'production'),
      },
    },
  ],
};
