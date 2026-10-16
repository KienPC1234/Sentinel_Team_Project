/* ShieldCall API client — trỏ về Django DRF (/api/v1).
 * Dev: dùng rewrite /api trong next.config.ts. Production: set
 * NEXT_PUBLIC_API_BASE_URL tới domain Django, ví dụ https://<domain>/api/v1
 */

const API_BASE = (process.env.NEXT_PUBLIC_API_BASE_URL as string | undefined) || '/api/v1';
const TOKEN_KEY = 'sc_token';

export function getToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string | null): void {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* private mode */
  }
}

export class ApiError extends Error {
  status: number;
  data: unknown;
  constructor(status: number, message: string, data?: unknown) {
    super(message);
    this.status = status;
    this.data = data;
  }
}

function getCsrf(): string {
  const m = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]*)/);
  return m ? decodeURIComponent(m[1]) : '';
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    ...(init.headers as Record<string, string> | undefined),
  };
  const isForm = init.body instanceof FormData;
  if (!isForm && init.body !== undefined) headers['Content-Type'] = 'application/json';
  const token = getToken();
  if (token) headers['Authorization'] = `Token ${token}`;
  const csrf = getCsrf();
  if (csrf && init.method && init.method !== 'GET') headers['X-CSRFToken'] = csrf;

  const res = await fetch(`${API_BASE}${path}`, { ...init, headers, credentials: 'include' });
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  if (!res.ok) {
    const d = data as { detail?: string; message?: string; error?: string } | null;
    let msg = d?.error || d?.detail || d?.message;
    if (!msg && typeof data === 'object' && data !== null) {
      const firstVal = Object.values(data)[0];
      if (Array.isArray(firstVal) && typeof firstVal[0] === 'string') {
        msg = firstVal[0];
      } else if (typeof firstVal === 'string') {
        msg = firstVal;
      }
    }
    if (!msg) msg = `Request failed (HTTP ${res.status})`;
    throw new ApiError(res.status, msg, data);
  }
  return data as T;
}

export const api = {
  get: <T>(path: string, headers?: Record<string, string>) =>
    request<T>(path, headers ? { method: 'GET', headers } : { method: 'GET' }),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'POST', body: body instanceof FormData ? body : JSON.stringify(body ?? {}) }),
  put: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'PUT', body: body instanceof FormData ? body : JSON.stringify(body ?? {}) }),
  patch: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'PATCH', body: body instanceof FormData ? body : JSON.stringify(body ?? {}) }),
  del: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
  upload: <T>(path: string, form: FormData) => request<T>(path, { method: 'POST', body: form }),
};

/* ---------- Typed endpoints (subset dùng cho các page đã port) ---------- */

export interface Paged<T> {
  results: T[];
  count?: number;
  next?: string | null;
  previous?: string | null;
}

export interface Article {
  id?: number;
  slug: string;
  title: string;
  summary?: string;
  cover_image?: string | null;
  created_at?: string;
  category?: string;
  category_display?: string;
  source_type?: string;
  source_type_display?: string;
  source_url?: string | null;
  author_name?: string;
  reactions_count?: number;
  comments_count?: number;
}

export interface Me {
  id?: number;
  username: string;
  email?: string;
  first_name?: string;
  last_name?: string;
  display_name?: string;
  gender?: string;
  gender_label?: string;
  is_staff?: boolean;
  is_superuser?: boolean;
  avatar?: string | null;
  date_joined?: string;
  about?: string;
  messenger_link?: string;
  rank_info?: { name: string; level: string; icon: string; color?: string } | null;
}

export interface MeStats {
  total_scans?: number;
  total_reports?: number;
  saved_alerts?: number;
}

/** /auth/me/ trả { user, stats } — không phải object phẳng. */
export interface MeResponse {
  user: Me;
  token?: string;
  stats?: MeStats;
}

export const learnApi = {
  articles: (params: Record<string, string | number> = {}) => {
    const q = new URLSearchParams(Object.entries(params).map(([k, v]) => [k, String(v)])).toString();
    return api.get<Paged<Article> | Article[]>(`/articles/${q ? `?${q}` : ''}`);
  },
  lessons: (params: Record<string, string | number> = {}) => {
    const q = new URLSearchParams(Object.entries(params).map(([k, v]) => [k, String(v)])).toString();
    return api.get<Paged<Article> | Article[]>(`/learn/lessons/${q ? `?${q}` : ''}`);
  },
  scenarios: () => api.get<Paged<Article> | Article[]>('/learn/scenarios/'),
  quizzes: () => api.get<Paged<Article> | Article[]>('/learn/quizzes/'),
  checkQuiz: (id: number, selected: string | string[]) =>
    api.post<{ correct: boolean; correct_answer?: string; correct_answers?: string[]; explanation?: string }>(
      `/learn/quizzes/${id}/check/`,
      { selected },
    ),
  lesson: (slug: string) => api.get<Record<string, unknown>>(`/learn/lessons/${slug}/`),
};

export const authApi = {
  me: () => api.get<MeResponse>('/auth/me/'),
  login: (email: string, password: string) =>
    api.post<{ token?: string; key?: string }>('/auth/login/', { email, password }),
  logout: () => api.post('/auth/logout/'),
};

export function asList<T>(paged: Paged<T> | T[]): T[] {
  return Array.isArray(paged) ? paged : paged.results || [];
}

/** Đảm bảo URL relative qua cổng proxy Next.js / tunnel duy nhất. */
export function djangoUrl(path: string): string {
  if (!path) return '/';
  const stripped = path.replace(/^https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?/i, '');
  return stripped.startsWith('/') ? stripped : `/${stripped}`;
}

/** URL file media (cover, avatar...). Luôn trả về relative /media/* để Next rewrite sang backend,
 * tránh rò rỉ localhost:8001/8000 gây net::ERR_CONNECTION_REFUSED trên tunnel từ xa. */
export function mediaUrl(path?: string | null): string {
  if (!path) return '';
  const stripped = path.replace(/^https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?/i, '');
  if (/^https?:\/\//i.test(stripped)) {
    return stripped;
  }
  return stripped.startsWith('/') ? stripped : `/${stripped}`;
}
