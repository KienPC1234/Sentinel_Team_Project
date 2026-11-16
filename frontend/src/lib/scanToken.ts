/* Lưu scan_token trả về khi tạo scan.
 *
 * Token này cho phép client (kể cả token-only/mobile hoặc cross-origin) poll
 * `/scan/status/<id>/`, mở SSE giải thích và kết nối WS `/ws/scan/<id>/` mà
 * không cần session cookie. Dùng sessionStorage (tab-scoped) để tránh lưu
 * vĩnh viễn quyền xem kết quả quét trong localStorage.
 */

const STORAGE_KEY = 'sc_scan_tokens';

type TokenMap = Record<string, string>;

function readMap(): TokenMap {
  if (typeof window === 'undefined') return {};
  try {
    const raw = window.sessionStorage.getItem(STORAGE_KEY);
    const parsed = raw ? (JSON.parse(raw) as unknown) : null;
    return parsed && typeof parsed === 'object' ? (parsed as TokenMap) : {};
  } catch {
    return {};
  }
}

function writeMap(map: TokenMap): void {
  if (typeof window === 'undefined') return;
  try {
    window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(map));
  } catch {
    /* private mode / storage full */
  }
}

export function saveScanToken(scanId: number | string, token: string): void {
  const id = String(scanId ?? '').trim();
  if (!id || !token) return;
  const map = readMap();
  map[id] = token;
  writeMap(map);
}

export function getScanToken(scanId: number | string | null | undefined): string {
  const id = String(scanId ?? '').trim();
  if (!id) return '';
  return readMap()[id] || '';
}

export function clearScanToken(scanId: number | string): void {
  const id = String(scanId ?? '').trim();
  if (!id) return;
  const map = readMap();
  delete map[id];
  writeMap(map);
}

/** `?scan_token=...` hoặc chuỗi rỗng, dùng cho URL status/WS. */
export function scanTokenQuery(scanId: number | string | null | undefined): string {
  const token = getScanToken(scanId);
  return token ? `?scan_token=${encodeURIComponent(token)}` : '';
}

/** Tự động lưu token nếu response tạo scan có `{scan_id, scan_token}`. */
export function rememberScanTokenFromPayload(payload: unknown): void {
  if (!payload || typeof payload !== 'object') return;
  const data = payload as { scan_id?: unknown; scan_token?: unknown };
  if (typeof data.scan_token !== 'string' || !data.scan_token) return;
  if (typeof data.scan_id === 'number' || typeof data.scan_id === 'string') {
    saveScanToken(data.scan_id, data.scan_token);
  }
}
