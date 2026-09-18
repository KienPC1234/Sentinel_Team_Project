"""ShieldCall VN — HTML sanitization helpers (XSS defense).

Server-side layer: bleach-based allowlist cleaning for user-generated
rich content (forum posts/comments). Client-side templates must still
escape/sanitize before innerHTML/x-html (see base.html sanitizeHtml).
"""
import logging

import bleach

logger = logging.getLogger(__name__)

ALLOWED_TAGS = [
    'p', 'br', 'b', 'strong', 'i', 'em', 'u', 's', 'strike',
    'a', 'ul', 'ol', 'li', 'blockquote', 'code', 'pre',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'span',
    'table', 'thead', 'tbody', 'tr', 'th', 'td',
    'img',
]
ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title', 'target', 'rel'],
    'img': ['src', 'alt', 'title'],
    'span': ['class'],
    'code': ['class'],
    'pre': ['class'],
    'th': ['colspan', 'rowspan'],
    'td': ['colspan', 'rowspan'],
}
ALLOWED_PROTOCOLS = ['http', 'https', 'mailto']


def clean_html(value: str) -> str:
    """Bleach-clean an HTML fragment with a conservative allowlist."""
    if not value:
        return ''
    try:
        return bleach.clean(
            str(value),
            tags=ALLOWED_TAGS,
            attributes=ALLOWED_ATTRIBUTES,
            protocols=ALLOWED_PROTOCOLS,
            strip=True,
        )
    except Exception as exc:
        logger.warning(f"bleach clean failed: {exc}")
        return bleach.clean(str(value), tags=[], strip=True)


def _sanitize_editorjs_blocks(data: dict) -> dict:
    """Sanitize inline HTML inside Editor.js blocks; neutralize raw blocks."""
    blocks = data.get('blocks')
    if not isinstance(blocks, list):
        return data
    for block in blocks:
        if not isinstance(block, dict):
            continue
        bdata = block.get('data')
        if not isinstance(bdata, dict):
            continue
        btype = block.get('type')
        if btype == 'raw':
            # Never store raw HTML from users — escape it to inert text.
            raw_html = bdata.get('html', '')
            bdata['html'] = bleach.clean(str(raw_html), tags=[], strip=False)
        elif btype == 'link':
            link = str(bdata.get('link', ''))
            if not link.lower().startswith(('http://', 'https://')):
                bdata['link'] = ''
            meta = bdata.get('meta')
            if isinstance(meta, dict):
                for key in ('title', 'description'):
                    if meta.get(key):
                        meta[key] = clean_html(meta[key])
        elif btype == 'image':
            url = str((bdata.get('file') or {}).get('url', '') or bdata.get('url', ''))
            if url and not url.lower().startswith(('http://', 'https://', '/media/', '/static/', 'data:image/')):
                if isinstance(bdata.get('file'), dict):
                    bdata['file']['url'] = ''
                else:
                    bdata['url'] = ''
            if bdata.get('caption'):
                bdata['caption'] = clean_html(bdata['caption'])
        else:
            for key in ('text', 'caption'):
                if bdata.get(key):
                    bdata[key] = clean_html(bdata[key])
            items = bdata.get('items')
            if isinstance(items, list):
                clean_items = []
                for item in items:
                    if isinstance(item, str):
                        clean_items.append(clean_html(item))
                    elif isinstance(item, dict):
                        if item.get('text'):
                            item['text'] = clean_html(item['text'])
                        if item.get('content'):
                            item['content'] = clean_html(item['content'])
                        clean_items.append(item)
                    else:
                        clean_items.append(item)
                bdata['items'] = clean_items
    return data


def sanitize_forum_content(value: str) -> str:
    """Sanitize forum post/comment content (Editor.js JSON or HTML/markdown).

    - Editor.js JSON: sanitize per-block, neutralize `raw` blocks.
    - Plain HTML: bleach allowlist clean (markdown passes through untouched
      since it contains no HTML tags of its own).
    """
    if not value:
        return ''
    text = str(value)
    stripped = text.strip()
    if stripped.startswith('{') or stripped.startswith('['):
        try:
            import json as _json
            parsed = _json.loads(stripped)
            if isinstance(parsed, dict) and isinstance(parsed.get('blocks'), list):
                return _json.dumps(_sanitize_editorjs_blocks(parsed), ensure_ascii=False)
        except Exception:
            pass
    return clean_html(text)


def sanitize_plain_text(value: str, limit: int = 200) -> str:
    """Strip all tags from short user fields (names, titles)."""
    if not value:
        return ''
    return bleach.clean(str(value), tags=[], strip=True).strip()[:limit]
