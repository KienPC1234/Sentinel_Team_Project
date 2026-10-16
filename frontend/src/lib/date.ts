const MONTHS_SHORT = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

export function parseSafeDate(raw?: string | null): Date | null {
  if (!raw) return null;
  const s = String(raw).trim();
  if (!s) return null;

  // Try direct Date parse
  const direct = new Date(s);
  if (!isNaN(direct.getTime())) {
    return direct;
  }

  // Support DD/MM/YYYY or DD/MM/YYYY HH:mm:ss format
  const dmyMatch = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})(?:\s+(\d{1,2}):(\d{1,2})(?::(\d{1,2}))?)?$/);
  if (dmyMatch) {
    const day = parseInt(dmyMatch[1], 10);
    const month = parseInt(dmyMatch[2], 10) - 1;
    const year = parseInt(dmyMatch[3], 10);
    const hour = dmyMatch[4] ? parseInt(dmyMatch[4], 10) : 0;
    const min = dmyMatch[5] ? parseInt(dmyMatch[5], 10) : 0;
    const sec = dmyMatch[6] ? parseInt(dmyMatch[6], 10) : 0;
    const parsed = new Date(year, month, day, hour, min, sec);
    if (!isNaN(parsed.getTime())) {
      return parsed;
    }
  }

  // Support YYYY-MM-DD or YYYY/MM/DD
  const ymdMatch = s.match(/^(\d{4})[-/](\d{1,2})[-/](\d{1,2})/);
  if (ymdMatch) {
    const year = parseInt(ymdMatch[1], 10);
    const month = parseInt(ymdMatch[2], 10) - 1;
    const day = parseInt(ymdMatch[3], 10);
    const parsed = new Date(year, month, day);
    if (!isNaN(parsed.getTime())) {
      return parsed;
    }
  }

  return null;
}

export function fmtDate(raw?: string | null): string {
  const d = parseSafeDate(raw);
  if (!d) return '';
  const day = String(d.getDate()).padStart(2, '0');
  const month = String(d.getMonth() + 1).padStart(2, '0');
  return `${day}/${month}/${d.getFullYear()}`;
}

export function fmtDateLong(raw?: string | null): string {
  const d = parseSafeDate(raw);
  if (!d) return '';
  const day = String(d.getDate()).padStart(2, '0');
  const month = MONTHS_SHORT[d.getMonth()] || '';
  return `${day} ${month} ${d.getFullYear()}`.trim();
}

export function isoDate(raw?: string | null): string {
  const d = parseSafeDate(raw);
  if (!d) return '';
  const day = String(d.getDate()).padStart(2, '0');
  const month = String(d.getMonth() + 1).padStart(2, '0');
  return `${d.getFullYear()}-${month}-${day}`;
}

