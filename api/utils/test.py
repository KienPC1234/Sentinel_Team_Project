import re, json

def web_fetch_url(url: str):
    """
    Fetch a web page. Primary: Ollama web_fetch API. Fallback: local requests + BS4.

    Returns a dict with keys: title, content, links.
    """
    import requests as _requests
    from bs4 import BeautifulSoup

    if not url:
        return None

    target_url = url.strip()
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', target_url):
        target_url = f"https://{target_url}"

    # Block requests to Ollama local server (prevent SSRF)
    blocked = ('localhost:11434', '127.0.0.1:11434')
    if any(b in target_url for b in blocked):
        print(f"web_fetch_url blocked internal URL: {target_url}")
        return None
    
    browser_headers = {
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/126.0.0.0 Safari/537.36'
        ),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'vi-VN,vi;q=0.9,en;q=0.8',
    }

    def _decode_response_text(resp):
        text = resp.text or ''
        if any(marker in text for marker in ('Ã', 'Â', 'á»', '�')):
            try:
                enc = resp.apparent_encoding or 'utf-8'
                text = resp.content.decode(enc, errors='replace')
            except Exception:
                pass
        return text

    def _extract_payload(resp, requested_url):
        html = _decode_response_text(resp)
        soup = BeautifulSoup(html, 'html.parser')

        for tag in soup(['script', 'style', 'noscript', 'iframe']):
            tag.decompose()

        title_tag = soup.find('title')
        title = title_tag.get_text(' ', strip=True) if title_tag else ''

        content = soup.get_text(separator='\n', strip=True)
        if len(content) > 12000:
            content = content[:12000]

        links = []
        for a in soup.find_all('a', href=True):
            href = (a.get('href') or '').strip()
            if not href:
                continue
            absolute = _requests.compat.urljoin(resp.url or requested_url, href)
            if absolute not in links:
                links.append(absolute)
            if len(links) >= 30:
                break

        return {
            'title': title,
            'content': content,
            'links': links,
        }

    try:
        resp = _requests.get(target_url, headers=browser_headers, timeout=20, verify=True, allow_redirects=True)
        resp.raise_for_status()
        payload = _extract_payload(resp, target_url)
        if payload.get('content'):
            return payload
    except Exception as e:
        print(f"web_fetch_url local https failed ({target_url}): {e}")

    if target_url.startswith('https://'):
        try:
            http_url = target_url.replace('https://', 'http://', 1)
            resp = _requests.get(http_url, headers=browser_headers, timeout=20, verify=False, allow_redirects=True)
            resp.raise_for_status()
            payload = _extract_payload(resp, http_url)
            if payload.get('content'):
                return payload
        except Exception as e:
            print(f"web_fetch_url local http failed ({target_url}): {e}")

    return None

def lookup_scamadviser(domain: str):
    """
    Fetch the ScamAdviser report for a domain.

    Prioritizes extracting ``ratingScore`` from the SPA bootstrap payload
    embedded in ``<div id="app" data-page="...">``. This is the same source
    used by client-side rendering and is more reliable than placeholder
    progress bars in static HTML. Falls back to textual verdict extraction
    (e.g. ``Very Likely Safe``, ``Caution Recommended``) when needed.

    Args:
        domain: Domain to look up (e.g. 'example.com').  Any leading scheme
                (``http://`` / ``https://``) is stripped automatically.

    Returns:
        Dict with keys ``source``, ``query_url``, ``title``, ``content``, and
        ``links``; or ``None`` on failure.
    """
    clean = re.sub(r'^https?://', '', domain).split('/')[0].strip()
    if not clean:
        return None
    url = f"https://www.scamadviser.com/check-website/{clean}"

    trust_score_from_page = None
    verdict_from_page = None
    page_text = ""

    # 1) Direct HTML fetch to extract data-page JSON + human-readable verdict.
    import html as _html
    import requests
    from bs4 import BeautifulSoup

    response = requests.get(
        url,
        headers={
            'User-Agent': (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) '
                'Gecko/20100101 Firefox/137.0'
            )
        },
        timeout=12,
    )
    if response.ok:
        html_text = response.text or ''
        page_text = BeautifulSoup(html_text, 'html.parser').get_text(' ', strip=True)[:6000]

        # Parse <div id="app" data-page="..."> then read ratingScore.
        app_data_match = re.search(
            r'<div\s+id=["\']app["\']\s+data-page=["\']([^"\']+)["\']',
            html_text,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if app_data_match:
            data_page_escaped = app_data_match.group(1)
            data_page_unescaped = _html.unescape(data_page_escaped)
            try:
                data_page_obj = json.loads(data_page_unescaped)

                score_candidates = [
                    data_page_obj.get('props', {}).get('score', {}).get('ratingScore'),
                    data_page_obj.get('props', {}).get('ratingScore'),
                    data_page_obj.get('ratingScore'),
                ]
                for candidate in score_candidates:
                    if isinstance(candidate, (int, float)):
                        numeric = int(candidate)
                        if 0 <= numeric <= 100:
                            trust_score_from_page = numeric
                            break

                verdict_candidates = [
                    data_page_obj.get('props', {}).get('score', {}).get('ratingText'),
                    data_page_obj.get('props', {}).get('score', {}).get('ratingLabel'),
                    data_page_obj.get('props', {}).get('score', {}).get('conclusion'),
                    data_page_obj.get('props', {}).get('ratingText'),
                    data_page_obj.get('ratingText'),
                ]
                for candidate in verdict_candidates:
                    if isinstance(candidate, str) and candidate.strip():
                        verdict_from_page = candidate.strip()
                        break
            except Exception:
                # Fallback: extract ratingScore directly from the unescaped data blob.
                score_match = re.search(r'"ratingScore"\s*:\s*(\d+)', data_page_unescaped)
                if score_match:
                    trust_score_from_page = int(score_match.group(1))

        # Secondary fallback: score may still appear in the HTML snapshot.
        if trust_score_from_page is None:
            score_match = re.search(r'"ratingScore"\s*:\s*(\d+)', html_text)
            if score_match:
                trust_score_from_page = int(score_match.group(1))

        # Known ScamAdviser-style conclusions to prioritize.
        if not verdict_from_page:
            verdict_patterns = [
                r'Very\s+Likely\s+Safe',
                r'Likely\s+Safe',
                r'Caution\s+Recommended',
                r'Suspicious',
                r'Unsafe',
                r'Scam',
            ]
            for pattern in verdict_patterns:
                match = re.search(pattern, page_text, flags=re.IGNORECASE)
                if match:
                    verdict_from_page = match.group(0)
                    break

    # 2) Keep existing web relay extraction as primary content source.
    result = web_fetch_url(url) or {
        'title': f'ScamAdviser report for {clean}',
        'content': page_text,
        'links': [],
    }

    # 2) If not found from direct page text, attempt extraction from relay content.
    if not verdict_from_page:
        relay_content = result.get('content', '') or ''
        verdict_patterns = [
            r'Very\s+Likely\s+Safe',
            r'Likely\s+Safe',
            r'Caution\s+Recommended',
            r'Suspicious',
            r'Unsafe',
            r'Scam',
        ]
        for pattern in verdict_patterns:
            match = re.search(pattern, relay_content, flags=re.IGNORECASE)
            if match:
                verdict_from_page = match.group(0)
                break

    existing_content = result.get('content', '') or ''
    prefix_lines = []

    if trust_score_from_page is not None:
        prefix_lines.append(f"ScamAdviser Trust Score (ratingScore): {trust_score_from_page}/100")

    if verdict_from_page:
        prefix_lines.append(f"ScamAdviser Verdict: {verdict_from_page}")

    if prefix_lines:
        prefix = '\n'.join(prefix_lines)
        if prefix not in existing_content:
            result['content'] = f"{prefix}\n{existing_content}".strip()

    result['source'] = 'scamadviser'
    result['query_url'] = url
    return result

print(lookup_scamadviser("bunrieucua.com"))