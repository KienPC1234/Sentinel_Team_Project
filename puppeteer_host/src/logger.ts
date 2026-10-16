type LogLevel = 'info' | 'warn' | 'error' | 'debug';

function formatMessage(level: LogLevel, component: string, message: string, meta?: unknown): string {
  const timestamp = new Date().toISOString();
  const metaStr = meta ? ` | ${JSON.stringify(meta)}` : '';
  return `[${timestamp}] [${level.toUpperCase()}] [${component}] ${message}${metaStr}`;
}

export const logger = {
  info(component: string, message: string, meta?: unknown): void {
    console.log(formatMessage('info', component, message, meta));
  },
  warn(component: string, message: string, meta?: unknown): void {
    console.warn(formatMessage('warn', component, message, meta));
  },
  error(component: string, message: string, meta?: unknown): void {
    console.error(formatMessage('error', component, message, meta));
  },
  debug(component: string, message: string, meta?: unknown): void {
    if (process.env.DEBUG === 'true' || process.env.NODE_ENV !== 'production') {
      console.debug(formatMessage('debug', component, message, meta));
    }
  },
};

