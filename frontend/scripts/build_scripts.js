import { execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const frontendDir = path.resolve(__dirname, '..');
const projectDir = path.resolve(frontendDir, '..');

function run() {
  console.log('[build_scripts] Compiling Service Worker (src/sw.ts -> public/sw.js)...');
  execSync('npx tsc -p tsconfig.worker.json', { cwd: frontendDir, stdio: 'inherit' });

  // Clean up any ES module exports so browser executes sw.js as a classic script without syntax errors
  const swSrc = path.join(frontendDir, 'public', 'sw.js');
  if (fs.existsSync(swSrc)) {
    let content = fs.readFileSync(swSrc, 'utf8');
    content = content.replace(/^\s*export\s*\{[^}]*\}\s*;?\s*$/gm, '');
    fs.writeFileSync(swSrc, content.trimEnd() + '\n', 'utf8');
  }

  // Sync to backend để phục vụ từ domain root (Django pwa_assets phục vụ BASE_DIR/sw.js)
  const swDest = path.join(projectDir, 'backend', 'sw.js');
  if (fs.existsSync(swSrc)) {
    fs.copyFileSync(swSrc, swDest);
    console.log(`[build_scripts] Cleaned and synced sw.js -> ${swDest}`);
  }

  console.log('[build_scripts] Build completed successfully.');
}

run();
