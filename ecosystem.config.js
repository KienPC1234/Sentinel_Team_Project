const path = require('path');

const ROOT_DIR = __dirname;
const VENV_PYTHON = path.join(ROOT_DIR, '.venv', 'bin', 'python');
const VENV_DAPHNE = path.join(ROOT_DIR, '.venv', 'bin', 'daphne');
const VENV_CELERY = path.join(ROOT_DIR, '.venv', 'bin', 'celery');
const PUPPETEER_DIR = path.join(ROOT_DIR, 'scripts', 'puppeteer_host');

module.exports = {
  apps: [
    {
      name: 'pkv-web',
      cwd: ROOT_DIR,
      script: VENV_DAPHNE,
      args: '-b 0.0.0.0 -p 8001 --proxy-headers PKV.asgi:application',
      interpreter: VENV_PYTHON,
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '3G',
      env: {
        DJANGO_SETTINGS_MODULE: 'PKV.settings',
        PYTHONUNBUFFERED: '1',
      },
    },
    {
      name: 'pkv-celery',
      cwd: ROOT_DIR,
      script: VENV_CELERY,
      args: '-A PKV worker --loglevel=info --concurrency=4 --pool=threads -Q celery,default',
      interpreter: VENV_PYTHON,
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '4G',
      env: {
        DJANGO_SETTINGS_MODULE: 'PKV.settings',
        PYTHONUNBUFFERED: '1',
      },
    },
    {
      name: 'pkv-celery-beat',
      cwd: ROOT_DIR,
      script: VENV_CELERY,
      args: '-A PKV beat --loglevel=info',
      interpreter: VENV_PYTHON,
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '500M',
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
      max_memory_restart: '1G',
      env: {
        PUPPETEER_HOST_PORT: '3010',
        NODE_ENV: 'production',
      },
    },
  ],
};
