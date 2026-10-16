import express from 'express';
import { config } from './config';
import { logger } from './logger';
import { apiRouter } from './routes/api';
import { closeBrowser } from './browser/manager';
import { startTabAutoCleanup, stopTabAutoCleanup } from './browser/controller';

const app = express();

app.use(express.json({ limit: '2mb' }));
app.use(apiRouter);

const server = app.listen(config.PORT, config.HOST, () => {
  startTabAutoCleanup();
  logger.info('Server', `Puppeteer Host service running at http://${config.HOST}:${config.PORT}`);
});

async function handleShutdown(signal: string): Promise<void> {
  logger.info('Server', `${signal} received. Initiating graceful shutdown...`);
  stopTabAutoCleanup();

  server.close(() => {
    logger.info('Server', 'HTTP server closed.');
  });

  try {
    await closeBrowser();
    logger.info('Server', 'Browser instance closed.');
  } catch (err) {
    logger.warn('Server', 'Error while closing browser during shutdown:', err);
  } finally {
    process.exit(0);
  }
}

process.on('SIGTERM', () => {
  void handleShutdown('SIGTERM');
});

process.on('SIGINT', () => {
  void handleShutdown('SIGINT');
});

export default app;

