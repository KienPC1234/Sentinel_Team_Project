// Backward compatibility wrapper for PM2 and legacy invocation
try {
  require('./dist/index.js');
} catch (err) {
  if (err && err.code === 'MODULE_NOT_FOUND' && String(err.message || '').includes('./dist/index.js')) {
    console.warn('[puppeteer_host] dist/index.js not found, running tsc build...');
    require('node:child_process').execSync('npm run build', { cwd: __dirname, stdio: 'inherit' });
    require('./dist/index.js');
  } else {
    throw err;
  }
}