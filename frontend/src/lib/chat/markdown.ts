/* ShieldCall markdown utils — port 1-1 từ PKV/static/js/chat/markdown.js sang TS.
 * Giữ nguyên logic sanitize để giao diện + an toàn XSS y bản gốc.
 */
import { marked } from 'marked';

export function escapeHtml(s: unknown): string {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function sanitizeHtml(html: string): string {
  if (!html) return '';
  try {
    const doc = new DOMParser().parseFromString(String(html), 'text/html');
    const BLOCKED = new Set([
      'SCRIPT', 'STYLE', 'IFRAME', 'OBJECT', 'EMBED', 'LINK', 'META',
      'FORM', 'INPUT', 'BUTTON', 'TEXTAREA', 'SELECT', 'OPTION', 'BASE', 'TITLE',
    ]);
    const DANGEROUS_PROTO = /^(javascript|vbscript|data:text\/html|file):/i;
    const walker = doc.createTreeWalker(doc.body, NodeFilter.SHOW_ELEMENT);
    const nodes: Element[] = [];
    while (walker.nextNode()) nodes.push(walker.currentNode as Element);
    for (const el of nodes) {
      if (BLOCKED.has(el.tagName)) {
        el.remove();
        continue;
      }
      for (const attr of Array.from(el.attributes || [])) {
        const name = attr.name.toLowerCase();
        const val = (attr.value || '').trim();
        if (name.startsWith('on')) {
          el.removeAttribute(attr.name);
        } else if (
          (name === 'href' || name === 'src' || name === 'xlink:href') &&
          DANGEROUS_PROTO.test(val)
        ) {
          el.removeAttribute(attr.name);
        } else if (name === 'srcdoc') {
          el.removeAttribute(attr.name);
        }
      }
      const href = el.getAttribute && el.getAttribute('href');
      if (href && DANGEROUS_PROTO.test(href.trim())) el.removeAttribute('href');
    }
    return doc.body.innerHTML;
  } catch {
    return escapeHtml(html);
  }
}

export function escapeRegExp(s: unknown): string {
  return String(s == null ? '' : s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Chỉ cho http(s)/relative/anchor, còn lại -> '#' (chống javascript: URL). */
export function safeUrl(u: unknown): string {
  const s = String(u == null ? '' : u).trim();
  if (!s || s.startsWith('#') || s.startsWith('/')) return s || '#';
  if (/^https?:\/\//i.test(s)) return s;
  return '#';
}

export function renderMd(text: string): string {
  if (!text) return '';
  let cleanText = String(text);
  cleanText = cleanText.replace(/<think>[\s\S]*?<\/think>/gi, '');
  cleanText = cleanText.replace(/<think>[\s\S]*$/gi, '');

  cleanText = cleanText.replace(
    /background\s*:\s*(?:#d4edda|rgb\(212,\s*237,\s*218\))/gi,
    'background:rgba(34,197,94,0.14);color:#dcfce7;border-color:rgba(34,197,94,0.35)',
  );
  cleanText = cleanText.replace(
    /background\s*:\s*(?:#f8d7da|rgb\(248,\s*215,\s*218\))/gi,
    'background:rgba(239,68,68,0.14);color:#fee2e2;border-color:rgba(239,68,68,0.35)',
  );
  cleanText = cleanText.replace(
    /background\s*:\s*(?:#fff3cd|rgb\(255,\s*243,\s*205\))/gi,
    'background:rgba(234,179,8,0.14);color:#fef9c3;border-color:rgba(234,179,8,0.35)',
  );

  cleanText = cleanText.replace(/^[ \t]*[•●◆▪]\s*/gm, '- ');
  cleanText = cleanText.replace(/<\/div>\s*(?:<br\s*\/?>\s*)*<div/gi, '</div>\n\n<div');
  cleanText = cleanText.replace(
    /(<\/div>)\s*([A-Za-z0-9\u00C0-\u024F\u1EA0-\u1EF9#*•\-\+])/gi,
    '$1\n\n$2',
  );

  cleanText = cleanText.replace(
    /<div\s+([^>]*?(?:style=["'][^"']*(?:background|border)[^"']*["']|class=["'][^"']*callout[^"']*["'])[^>]*)>/gi,
    (_match: string, attrStr: string) => {
      let calloutType = 'callout-safe';
      if (/239\s*,\s*68\s*,\s*68|f8d7da|fee2e2|danger|red/i.test(attrStr)) {
        calloutType = 'callout-danger';
      } else if (/234\s*,\s*179\s*,\s*8|fff3cd|fef9c3|warning|amber|yellow/i.test(attrStr)) {
        calloutType = 'callout-warning';
      } else if (/34\s*,\s*197\s*,\s*94|d4edda|dcfce7|safe|green/i.test(attrStr)) {
        calloutType = 'callout-safe';
      }
      let updatedAttr = attrStr;
      if (/class=["']([^"']*)["']/i.test(updatedAttr)) {
        updatedAttr = updatedAttr.replace(/class=["']([^"']*)["']/i, (_m: string, existing: string) => {
          const classes = existing.split(/\s+/).filter(Boolean);
          if (!classes.includes('callout-box')) classes.push('callout-box');
          if (!classes.includes(calloutType)) classes.push(calloutType);
          return `class="${classes.join(' ')}"`;
        });
      } else {
        updatedAttr = `class="callout-box ${calloutType}" ${updatedAttr}`;
      }
      if (/style=["']([^"']*)["']/i.test(updatedAttr)) {
        updatedAttr = updatedAttr.replace(/style=["']([^"']*)["']/i, (_m: string, style: string) => {
          let s = style;
          if (!/margin/i.test(s)) s += ';margin:16px 0;';
          return `style="${s}"`;
        });
      }
      return `<div ${updatedAttr}>`;
    },
  );

  cleanText = cleanText.trim();
  if (!cleanText) return '';
  try {
    const raw = marked.parse(cleanText, { breaks: true, gfm: true }) as string;
    // KHÔNG bao giờ trả HTML chưa sanitize (XSS).
    return sanitizeHtml(raw);
  } catch (e) {
    console.error('Markdown rendering error:', e);
    return escapeHtml(cleanText);
  }
}
