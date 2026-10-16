const http = require('node:http');

const HOST = '127.0.0.1';
const PORT = 3010;

function request(method, path, body = null) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const req = http.request(
      {
        hostname: HOST,
        port: PORT,
        path,
        method,
        headers: {
          'Content-Type': 'application/json',
          ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
        },
      },
      (res) => {
        let raw = '';
        res.on('data', (chunk) => (raw += chunk));
        res.on('end', () => {
          let parsed;
          try {
            parsed = JSON.parse(raw);
          } catch {
            parsed = raw;
          }
          resolve({ status: res.statusCode, body: parsed });
        });
      }
    );
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

async function runTests() {
  console.log('====================================================');
  console.log(' PUPPETEER HOST - COMPREHENSIVE DEEP AUDIT & TEST   ');
  console.log('====================================================\n');

  let totalTests = 0;
  let passedTests = 0;

  function assert(name, condition, details = '') {
    totalTests++;
    if (condition) {
      passedTests++;
      console.log(`[PASS] ${name}`);
    } else {
      console.error(`[FAIL] ${name} ${details ? '-> ' + details : ''}`);
    }
  }

  // 1. Healthcheck
  console.log('--- 1. Healthcheck & Service Status ---');
  const health = await request('GET', '/health');
  assert('Healthcheck returns 200', health.status === 200);
  assert('Healthcheck reports healthy status', health.body?.status === 'healthy');
  assert('Healthcheck version is 2.0.0-ts', health.body?.version === '2.0.0-ts');

  // 2. Schema Validation Errors (Zod)
  console.log('\n--- 2. Request Validation (Zod Schemas) ---');
  const emptyRender = await request('POST', '/render', {});
  assert('Empty render payload returns 400', emptyRender.status === 400);
  assert('Zod reports missing url field', emptyRender.body?.details?.url !== undefined);

  const emptyClick = await request('POST', '/click', {});
  assert('Empty click payload returns 400', emptyClick.status === 400);

  const emptyType = await request('POST', '/type', {});
  assert('Empty type payload returns 400', emptyType.status === 400);

  // 3. SSRF Protection
  console.log('\n--- 3. SSRF & Internal IP Blocking ---');
  const ssrf1 = await request('POST', '/render', { url: 'http://127.0.0.1:8001/admin/' });
  assert('Blocks 127.0.0.1 target', ssrf1.status === 400 && ssrf1.body?.error?.includes('blocked'));

  const ssrf2 = await request('POST', '/render', { url: 'http://localhost:3000' });
  assert('Blocks localhost target', ssrf2.status === 400 && ssrf2.body?.error?.includes('blocked'));

  const ssrf3 = await request('POST', '/render', { url: 'http://169.254.169.254/meta-data' });
  assert('Blocks AWS/cloud metadata IP', ssrf3.status === 400 && ssrf3.body?.error?.includes('blocked'));

  const ssrf4 = await request('POST', '/render', { url: 'http://10.0.0.1' });
  assert('Blocks 10.0.0.0/8 private range', ssrf4.status === 400 && ssrf4.body?.error?.includes('blocked'));

  const ssrf5 = await request('POST', '/render', { url: 'http://127.0.0.1.nip.io' });
  assert('Blocks DNS resolving to 127.0.0.1', ssrf5.status === 400 && ssrf5.body?.error?.includes('blocked'));

  // 4. Remote Page Control (/open, /click, /type, /cookies)
  console.log('\n--- 4. Interactive Tab Control ---');
  const openRes = await request('POST', '/open', { url: 'https://example.com' });
  assert('/open returns 200', openRes.status === 200);
  assert('/open returns final_url', typeof openRes.body?.final_url === 'string' && openRes.body.final_url.includes('example.com'));

  const cookiesRes = await request('GET', '/cookies');
  assert('/cookies returns 200 and array', cookiesRes.status === 200 && Array.isArray(cookiesRes.body?.cookies));

  // 5. Session Status & Login Session
  console.log('\n--- 5. Session & Remote CDP Management ---');
  const sessionStatus = await request('GET', '/session/status');
  assert('/session/status returns 200', sessionStatus.status === 200);
  assert('/session/status contains profile_dir', typeof sessionStatus.body?.profile_dir === 'string');
  assert('/session/status contains ws_endpoint', typeof sessionStatus.body?.ws_endpoint === 'string');
  assert('/session/status contains remote_debug_port', typeof sessionStatus.body?.remote_debug_port === 'number');

  const sessionLogin = await request('POST', '/session/login', { url: 'https://example.com' });
  assert('/session/login returns 200', sessionLogin.status === 200);
  assert('/session/login provides cdp_http_hint', typeof sessionLogin.body?.cdp_http_hint === 'string');

  // 6. Real Render & Captcha Detection
  console.log('\n--- 6. Real Page Render & Captcha Evaluation ---');
  const renderStart = Date.now();
  const renderRes = await request('POST', '/render', { url: 'https://example.com', timeoutMs: 15000 });
  const renderDuration = Date.now() - renderStart;

  assert('/render returns 200', renderRes.status === 200);
  assert('/render extracts title', renderRes.body?.title === 'Example Domain');
  assert('/render extracts body text', typeof renderRes.body?.content === 'string' && renderRes.body.content.length > 50);
  assert('/render reports captcha_detected boolean', typeof renderRes.body?.captcha_detected === 'boolean');
  console.log(`     > Render duration: ${renderDuration} ms`);

  // 7. Concurrent Rendering Under Load (Stress Test)
  console.log('\n--- 7. Concurrency Stress Test (4 Parallel Renders) ---');
  const parallelUrls = [
    'https://example.com',
    'https://example.com',
    'https://example.com',
    'https://example.com'
  ];

  const pStart = Date.now();
  const pResults = await Promise.all(
    parallelUrls.map(url => request('POST', '/render', { url, timeoutMs: 20000 }))
  );
  const pDuration = Date.now() - pStart;

  const allParallelOk = pResults.every(r => r.status === 200 && r.body?.title === 'Example Domain');
  assert('4 concurrent renders all succeed', allParallelOk);
  console.log(`     > 4 parallel renders finished in: ${pDuration} ms (Avg: ${Math.round(pDuration / 4)} ms/req)`);

  // 8. Final Report
  console.log('\n====================================================');
  console.log(` TEST SUMMARY: ${passedTests}/${totalTests} Passed (${Math.round((passedTests / totalTests) * 100)}%)`);
  console.log('====================================================');

  if (passedTests !== totalTests) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('Test execution failed:', err);
  process.exit(1);
});

