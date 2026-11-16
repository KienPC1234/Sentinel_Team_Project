#!/usr/bin/env node
/* Kiểm tra hồi quy cho tour hướng dẫn (driver.js) — không cần dependency ngoài.
 * Chạy: `npm run check:tours` (đã gắn vào `lint:all`).
 *
 * Bắt các lỗi sửa code làm mất neo tour:
 *  1. Bước tour dùng selector lạ (không phải `[data-tour="..."]`) -> FAIL.
 *  2. Neo `[data-tour="X"]` trong tours.ts nhưng không còn tồn tại trong file
 *     view đích (bị xoá/đổi tên khi refactor) -> FAIL.
 *  3. Neo mới chưa khai báo file đích trong ANCHOR_FILES bên dưới -> FAIL.
 *  4. Tour id trong getTourIdForPath không có định nghĩa (hoặc ngược lại,
 *     tour chết không route nào tới) -> FAIL.
 *  5. Mỗi tour phải có 2–4 bước (tránh tour thừa/hiển nhiên) -> FAIL.
 *
 * Quy ước: thêm/sửa/xoá `data-tour="..."` trong view thì cập nhật ANCHOR_FILES
 * cho khớp, rồi chạy lại script này trước khi commit.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const FRONTEND = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const TOURS_FILE = path.join(FRONTEND, 'src/lib/tours.ts');

/* Neo -> các file PHẢI chứa đúng `data-tour="neo"` đó. */
const ANCHOR_FILES = {
  'scan-form': [
    'src/views/Scan/Phone.tsx',
    'src/views/Scan/Website.tsx',
    'src/views/Scan/Bank.tsx',
    'src/views/Scan/Message.tsx',
    'src/views/Scan/Email.tsx',
    'src/views/Scan/Qr.tsx', // Qr.tsx phục vụ cả /scan/qr/ và /scan/image/
    'src/views/Scan/File.tsx',
    'src/views/Scan/Audio.tsx',
    'src/views/Scan/Lookup.tsx',
  ],
  'scan-submit': [
    'src/views/Scan/Phone.tsx',
    'src/views/Scan/Website.tsx',
    'src/views/Scan/Bank.tsx',
    'src/views/Scan/Message.tsx',
    'src/views/Scan/Email.tsx',
    'src/views/Scan/Qr.tsx',
    'src/views/Scan/File.tsx',
    'src/views/Scan/Audio.tsx',
    'src/views/Scan/Lookup.tsx',
  ],
  'scan-privacy': ['src/components/ScanWidgets.tsx'],
  'home-scanner': ['src/views/Home.tsx'],
  'home-scam-iq': ['src/views/Home.tsx'],
  'report-form': ['src/views/Report/Report.tsx'],
  'report-desc': ['src/views/Report/Report.tsx'],
  'radar-filters': ['src/views/Radar/ScamRadar.tsx'],
  'radar-cards': ['src/views/Radar/ScamRadar.tsx'],
  'forum-search': ['src/views/Forum/Forum.tsx'],
  'forum-create': ['src/views/Forum/Forum.tsx'],
  'learn-search': ['src/views/Learn/LearnHub.tsx'],
  'emergency-call': ['src/views/Emergency.tsx'],
  'dashboard-stats': ['src/views/Dashboard.tsx'],
  'scam-iq-start': ['src/views/AI/ScamIQ.tsx'],
  'elder-form': ['src/views/Elder/ElderHub.tsx'],
};

const errors = [];
const warnings = [];
const fail = (msg) => errors.push(msg);

function readFile(rel) {
  return fs.readFileSync(path.join(FRONTEND, rel), 'utf8');
}

function main() {
  if (!fs.existsSync(TOURS_FILE)) fail(`Không tìm thấy ${TOURS_FILE}`);
  const src = fs.readFileSync(TOURS_FILE, 'utf8');

  /* --- 4. id định nghĩa vs id route (id lấy từ header entry TOURS,
   * vì entry dùng helper scanTour() truyền id qua đối số, không có field id:) --- */
  const regionStart = src.indexOf('export const TOURS');
  const regionEnd = src.indexOf('/** Map pathname');
  const region = src.slice(regionStart, regionEnd === -1 ? undefined : regionEnd);
  const headers = [...region.matchAll(/^  (?:'([^']+)'|([A-Za-z0-9-]+)):\s*(scanTour\(|\{)/gm)];
  const definedIds = new Set(headers.map((m) => m[1] || m[2]));
  if (definedIds.size === 0) fail('Không parse được tour nào trong TOURS — cấu trúc tours.ts lạ, kiểm tra tay.');
  const routerFn = src.slice(src.indexOf('getTourIdForPath'));
  const routedIds = new Set([...routerFn.matchAll(/return '([^']+)'/g)].map((m) => m[1]));
  for (const id of routedIds) {
    if (!definedIds.has(id)) fail(`Route trỏ tới tour '${id}' nhưng TOURS không định nghĩa tour này.`);
  }
  for (const id of definedIds) {
    if (!routedIds.has(id)) fail(`Tour '${id}' được định nghĩa nhưng không route nào trỏ tới (tour chết).`);
  }

  /* --- 1. mọi element phải là [data-tour="..."] --- */
  const elements = [...src.matchAll(/element:\s*'([^']+)'/g)].map((m) => m[1]);
  if (elements.length === 0) fail('Không tìm thấy bước nào có element — tours.ts có thể đã bị ghi đè sai.');
  for (const el of elements) {
    if (!el.includes('[data-tour="')) {
      fail(`Bước dùng selector '${el}' không phải neo [data-tour="..."] — dễ gãy khi sửa giao diện.`);
    }
  }

  /* --- Neo được tour tham chiếu (chỉ trích từ giá trị element:, bỏ qua comment) --- */
  const usedAnchors = new Set();
  for (const el of elements) {
    for (const m of el.matchAll(/\[data-tour="([^"]+)"\]/g)) usedAnchors.add(m[1]);
  }

  /* --- 3. neo mới phải khai báo file đích --- */
  for (const anchor of usedAnchors) {
    if (!Object.hasOwn(ANCHOR_FILES, anchor)) {
      fail(`Neo '${anchor}' chưa khai báo trong ANCHOR_FILES của scripts/check-tours.mjs.`);
    }
  }

  /* --- 2. neo phải tồn tại trong file đích --- */
  const fileCache = new Map();
  const getFile = (rel) => {
    if (!fileCache.has(rel)) {
      const abs = path.join(FRONTEND, rel);
      fileCache.set(rel, fs.existsSync(abs) ? fs.readFileSync(abs, 'utf8') : null);
    }
    return fileCache.get(rel);
  };
  for (const [anchor, files] of Object.entries(ANCHOR_FILES)) {
    if (!usedAnchors.has(anchor)) {
      warnings.push(`Neo '${anchor}' khai báo trong ANCHOR_FILES nhưng không tour nào dùng (neo mồ côi).`);
      continue;
    }
    const needle = `data-tour="${anchor}"`;
    const missing = files.filter((rel) => {
      const content = getFile(rel);
      if (content === null) {
        fail(`File đích '${rel}' của neo '${anchor}' không tồn tại.`);
        return false;
      }
      return !content.includes(needle);
    });
    if (missing.length > 0) {
      fail(
        `Neo '${needle}' bị MẤT trong: ${missing.join(', ')} — ` +
          `tour trỏ tới phần tử không còn tồn tại, kiểm tra lại refactor gần nhất.`,
      );
    }
  }

  /* --- 5. mỗi tour 2–4 bước (đếm `title:` trong từng entry TOURS) --- */
  if (headers.length !== definedIds.size) {
    fail(`Parse được ${headers.length} entry nhưng ${definedIds.size} id khác nhau — có tour trùng id trong tours.ts.`);
  } else {
    const scanTourBody = src.slice(src.indexOf('function scanTour'), src.indexOf('export const TOURS'));
    const scanTourSteps = (scanTourBody.match(/^\s+title:/gm) || []).length;
    if (scanTourSteps !== 4) fail(`Helper scanTour() đang có ${scanTourSteps} bước, kỳ vọng 4 — sửa lại hoặc cập nhật test.`);
    for (let i = 0; i < headers.length; i++) {
      const id = headers[i][1] || headers[i][2];
      const isHelper = headers[i][3] === 'scanTour(';
      if (isHelper) continue;
      const start = headers[i].index;
      const end = i + 1 < headers.length ? headers[i + 1].index : region.length;
      const block = region.slice(start, end);
      const steps = (block.match(/^\s+title:/gm) || []).length;
      if (steps < 2 || steps > 4) {
        fail(`Tour '${id}' có ${steps} bước (quy định 2–4 bước để tránh hướng dẫn thừa).`);
      }
    }
  }

  /* --- Cảnh báo: neo theo quy ước nhưng không tour nào dùng --- */
  const tourish = /data-tour="((?:scan|home|report|radar|forum|learn|emergency|dashboard|scam|elder)-[^"]*)"/g;
  const walk = (dir) => {
    for (const name of fs.readdirSync(dir, { withFileTypes: true })) {
      if (name.name === 'node_modules' || name.name === '.next') continue;
      const abs = path.join(dir, name.name);
      if (name.isDirectory()) walk(abs);
      else if (/\.(tsx?)$/.test(name.name) && !abs.endsWith('src/lib/tours.ts')) {
        const content = fs.readFileSync(abs, 'utf8');
        for (const m of content.matchAll(tourish)) {
          if (!usedAnchors.has(m[1]) && !Object.hasOwn(ANCHOR_FILES, m[1])) {
            warnings.push(`Neo '${m[1]}' tồn tại trong ${path.relative(FRONTEND, abs)} nhưng không tour nào dùng.`);
          }
        }
      }
    }
  };
  walk(path.join(FRONTEND, 'src'));

  for (const w of new Set(warnings)) console.log(`⚠ ${w}`);
  if (errors.length > 0) {
    console.error(`\n✖ check:tours THẤT BẠI (${errors.length} lỗi):`);
    for (const e of errors) console.error(`  - ${e}`);
    process.exit(1);
  }
  console.log(`✔ check:tours OK: ${definedIds.size} tour, ${usedAnchors.size} neo, ${elements.length} bước có element.`);
}

main();
