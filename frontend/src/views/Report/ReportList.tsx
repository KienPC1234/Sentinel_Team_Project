'use client';
/* Port 1-1 từ PKV/templates/Report/report_list.html (Alpine.js → React).
 * API giữ nguyên: GET /api/v1/scan/lookup/ (danh sách), GET /api/v1/report/<id>/ (chi tiết).
 * Lưu ý: /scan/lookup/ trả kèm description/scammer/custom_fields cho kind='report';
 * các block tương ứng chỉ hiển thị khi có dữ liệu. Vì privacy, lookup không trả
 * username người báo cáo (hiển thị 'Ẩn danh').
 */
import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { api } from '../../lib/api';
import { useAuth } from '../../components/AuthContext';
import { Spinner } from '../../components/ui';
import { fmtDate } from '../../lib/date';

/* CSS gốc nằm trong {% block head_extra %} của template. */
const REPORT_LIST_CSS = `
.report-card { background: var(--glass-bg); backdrop-filter: blur(20px); border: 1px solid var(--glass-border); transition: all 0.3s ease; }
.report-card:hover { border-color: rgba(24, 255, 255, 0.25); transform: translateY(-2px); }
.filter-pill { transition: all 0.2s ease; }
.filter-pill.active { background: rgba(24, 255, 255, 0.15); color: var(--sc-brand); border-color: rgba(24, 255, 255, 0.4); }
`;

interface LookupItem {
  id: number;
  kind: 'scan' | 'report' | string;
  type: string;
  type_display?: string;
  target: string;
  risk_level?: string;
  risk_display?: string;
  risk_score?: number;
  scam_type?: string;
  time_ago?: string;
  created_at?: string;
  url?: string;
  /* Các trường mô tả/hồ sơ kẻ gian có trong payload /scan/lookup/ với kind='report'. */
  description?: string;
  scammer_name?: string;
  scammer_bank_account?: string;
  scammer_bank_name?: string;
  scammer_phone?: string;
  scammer_social?: string;
  custom_fields?: Record<string, unknown>;
}

interface ScammerInfo {
  name?: string;
  phone?: string;
  bank_account?: string;
  bank_name?: string;
  social?: string;
  custom_fields?: Record<string, unknown>;
}

interface EvidenceImage {
  id: number;
  url: string;
}

interface ReportDetail {
  id: number;
  target_type: string;
  target_value: string;
  severity?: string;
  scam_type?: string;
  scam_type_display?: string;
  description?: string;
  scammer_info?: ScammerInfo;
  scammer_social?: string;
  custom_fields?: Record<string, unknown>;
  evidence_images_data?: EvidenceImage[];
  ocr_text?: string;
  ai_analysis?: unknown;
}

interface LookupPayload {
  results?: LookupItem[];
  total?: number;
  page?: number;
  per_page?: number;
  has_next?: boolean;
}

const TYPE_FILTERS: { v: string; l: string; i: string }[] = [
  { v: 'all', l: 'Tất cả', i: '' },
  { v: 'phone', l: 'Số điện thoại', i: 'bi-phone' },
  { v: 'domain', l: 'Website', i: 'bi-globe2' },
  { v: 'account', l: 'STK Ngân hàng', i: 'bi-bank2' },
  { v: 'email', l: 'Email', i: 'bi-envelope' },
  { v: 'message', l: 'Tin nhắn', i: 'bi-chat-left-dots' },
  { v: 'file', l: 'Tệp tin / APK', i: 'bi-file-earmark-binary' },
  { v: 'social', l: 'MXH / Telegram', i: 'bi-telegram' },
  { v: 'crypto', l: 'Ví Crypto', i: 'bi-coin' },
  { v: 'audio', l: 'Cuộc gọi / Audio', i: 'bi-mic' },
  { v: 'qr', l: 'QR Code', i: 'bi-qr-code' },
];

const SCAM_TYPE_OPTIONS: { v: string; l: string }[] = [
  { v: 'police_impersonation', l: 'Giả danh công an' },
  { v: 'bank_impersonation', l: 'Giả mạo ngân hàng' },
  { v: 'gov_impersonation', l: 'Giả mạo cơ quan Thuế / Dịch vụ công / VNeID' },
  { v: 'recruitment_scam', l: 'Lừa tuyển dụng / Việc nhẹ lương cao' },
  { v: 'investment_scam', l: 'Lừa đầu tư tài chính / Sàn ảo' },
  { v: 'delivery_scam', l: 'Giả mạo giao hàng / Bưu cục' },
  { v: 'loan_scam', l: 'Lừa vay tiền / Tín dụng đen' },
  { v: 'otp_steal', l: 'Chiêu trò OTP/2FA' },
  { v: 'phishing', l: 'Phishing link / Trang web giả mạo' },
  { v: 'romance_scam', l: 'Lừa tình cảm / Bẫy lợn béo (Pig Butchering)' },
  { v: 'deepfake', l: 'Deepfake âm thanh / Video AI mạo danh' },
  { v: 'malware_app', l: 'Mã độc / Ứng dụng APK đánh cắp tài khoản' },
  { v: 'crypto_scam', l: 'Lừa đảo Tiền điện tử / Ví Crypto / Airdrop' },
  { v: 'social_engineering', l: 'Lừa đảo hội nhóm Telegram / Zalo / Fanpage' },
  { v: 'prize_scam', l: 'Trúng thưởng / Quà tri ân / Đơn hàng ảo' },
  { v: 'emergency_scam', l: 'Báo nạn cấp cứu / Tống tiền người thân' },
  { v: 'other', l: 'Khác' },
];

const SCAM_TYPE_LABELS: Record<string, string> = Object.fromEntries(SCAM_TYPE_OPTIONS.map((s) => [s.v, s.l]));

const SEVERITY_OPTIONS: { v: string; l: string }[] = [
  { v: 'low', l: 'Thấp' },
  { v: 'medium', l: 'Trung bình' },
  { v: 'high', l: 'Cao' },
  { v: 'critical', l: 'Khẩn cấp' },
];

const TYPE_META: Record<string, { badge: string; label: string }> = {
  phone: { badge: 'bg-brand-500/10 text-brand-400 border-brand-500/20', label: '📞 Số điện thoại' },
  domain: { badge: 'bg-brand-500/10 text-brand-400 border-brand-500/20', label: '🌐 Website' },
  account: { badge: 'bg-warn-500/10 text-warn-400 border-warn-500/20', label: '🏦 Ngân hàng' },
  email: { badge: 'bg-brand2-500/10 text-brand2-400 border-brand2-500/20', label: '📧 Email' },
  file: { badge: 'bg-danger-500/10 text-danger-400 border-danger-500/20', label: '📁 Tệp tin / APK' },
  social: { badge: 'bg-brand2-500/10 text-brand2-400 border-brand2-500/20', label: '🌐 MXH / Telegram' },
  crypto: { badge: 'bg-warn-500/10 text-warn-400 border-warn-500/20', label: '🪙 Ví Crypto' },
  audio: { badge: 'bg-brand-500/10 text-brand-400 border-brand-500/20', label: '🎙️ Audio / Deepfake' },
};

function typeBadge(type: string, typeDisplay?: string): { badge: string; label: string } {
  return TYPE_META[type] || { badge: 'bg-brand2-500/10 text-brand2-400 border-brand2-500/20', label: `💬 ${typeDisplay || type}` };
}

function severityBadge(riskLevel?: string): string {
  const l = (riskLevel || '').toUpperCase();
  if (l === 'RED') return 'bg-danger-500/10 text-danger-400 border-danger-500/20';
  if (l === 'YELLOW') return 'bg-warn-500/10 text-warn-400 border-warn-500/20';
  return 'bg-safe-500/10 text-safe-400 border-safe-500/20';
}

function copyText(text?: string): void {
  if (!text) return;
  try {
    void navigator.clipboard?.writeText(text);
  } catch {
    /* ignore */
  }
}

function scanUrlFor(d: ReportDetail | null): string {
  if (!d) return '/scan/';
  const t = d.target_type || '';
  const v = encodeURIComponent(d.target_value || '');
  if (t === 'phone') return `/scan/phone/?phone=${v}`;
  if (t === 'domain') return `/scan/?url=${v}`;
  if (t === 'account') return `/scan/bank/?account=${v}`;
  if (t === 'email') return `/scan/email/?email=${v}`;
  if (t === 'file') return `/scan/file/?file=${v}`;
  if (t === 'audio') return `/scan/audio/?q=${v}`;
  if (t === 'qr') return `/scan/qr/?q=${v}`;
  return `/scan/lookup/?q=${v}`;
}

export default function ReportList() {
  const { user } = useAuth();
  const [q, setQ] = useState('');
  const [type, setType] = useState('all');
  const [scamType, setScamType] = useState('all');
  const [severity, setSeverity] = useState('all');
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(20);
  const [items, setItems] = useState<LookupItem[]>([]);
  const [total, setTotal] = useState(0);
  const [hasNext, setHasNext] = useState(false);
  const [loading, setLoading] = useState(true);
  const [detail, setDetail] = useState<ReportDetail | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [modalLoading, setModalLoading] = useState(false);
  const [modalError, setModalError] = useState('');
  const [lightbox, setLightbox] = useState<string | null>(null);
  const [serverStats, setServerStats] = useState<Record<string, number> | null>(null);

  useEffect(() => {
    let alive = true;
    api
      .get<Record<string, number>>('/reports/stats/')
      .then((d) => {
        if (alive) setServerStats(d);
      })
      .catch(() => {
        /* fallback sang đếm client-side */
      });
    return () => {
      alive = false;
    };
  }, []);

  const fetchList = (query: string, t: string, scam: string, sev: string, p: number): void => {
    setLoading(true);
    const risk = sev === 'all' ? 'all' : sev === 'critical' || sev === 'high' ? 'high' : sev;
    const params = new URLSearchParams();
    if (query.trim()) params.set('q', query.trim());
    if (t && t !== 'all') params.set('type', t);
    if (risk !== 'all') params.set('risk', risk);
    params.set('page', String(p));
    api
      .get<LookupPayload>(`/scan/lookup/?${params.toString()}`)
      .then((d) => {
        let list = Array.isArray(d.results) ? d.results : [];
        if (scam !== 'all') {
          const label = SCAM_TYPE_LABELS[scam];
          if (label) list = list.filter((it) => it.scam_type === label);
        }
        setItems(list);
        setTotal(typeof d.total === 'number' ? d.total : list.length);
        setPerPage(typeof d.per_page === 'number' ? d.per_page : 20);
        setHasNext(d.has_next === true);
      })
      .catch(() => {
        setItems([]);
        setTotal(0);
        setHasNext(false);
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchList('', 'all', 'all', 'all', 1);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /* Stats bar: ưu tiên số liệu server-side từ /reports/stats/. */
  const stats = useMemo(() => {
    if (serverStats) {
      return {
        total: serverStats.total_approved || 0,
        phone: serverStats.phone_reports || 0,
        domain: serverStats.domain_reports || 0,
        account: serverStats.bank_reports || 0,
        file: serverStats.file_reports || 0,
        social: serverStats.social_reports || 0,
        crypto: serverStats.crypto_reports || 0,
        audio: serverStats.audio_reports || 0,
      };
    }
    const reports = items.filter((i) => i.kind === 'report');
    const c = (t: string): number => reports.filter((r) => r.type === t).length;
    return {
      total: reports.length,
      phone: c('phone'),
      domain: c('domain'),
      account: c('account'),
      file: c('file'),
      social: c('social'),
      crypto: c('crypto'),
      audio: c('audio'),
    };
  }, [items, serverStats]);

  const numPages = perPage > 0 ? Math.max(1, Math.ceil(total / perPage)) : 1;

  const submitSearch = (e: React.FormEvent): void => {
    e.preventDefault();
    setPage(1);
    fetchList(q, type, scamType, severity, 1);
  };

  const pickType = (t: string): void => {
    setType(t);
    setPage(1);
    fetchList(q, t, scamType, severity, 1);
  };

  const pickScamType = (v: string): void => {
    setScamType(v);
    setPage(1);
    fetchList(q, type, v, severity, 1);
  };

  const pickSeverity = (v: string): void => {
    setSeverity(v);
    setPage(1);
    fetchList(q, type, scamType, v, 1);
  };

  const resetFilters = (): void => {
    setQ('');
    setType('all');
    setScamType('all');
    setSeverity('all');
    setPage(1);
    fetchList('', 'all', 'all', 'all', 1);
  };

  const goPage = (p: number): void => {
    setPage(p);
    fetchList(q, type, scamType, severity, p);
  };

  const openDetail = (it: LookupItem): void => {
    if (it.kind === 'scan') {
      window.location.href = it.url || `/scan/status/${it.id}/`;
      return;
    }
    setModalOpen(true);
    setModalLoading(true);
    setModalError('');
    setDetail(null);
    api
      .get<ReportDetail>(`/report/${it.id}/`)
      .then(setDetail)
      .catch((err: unknown) => {
        setDetail(null);
        setModalError(err instanceof Error ? err.message : 'Không tải được chi tiết báo cáo.');
      })
      .finally(() => setModalLoading(false));
  };

  const closeModal = (): void => {
    setModalOpen(false);
    setDetail(null);
    setLightbox(null);
  };

  useEffect(() => {
    if (!modalOpen) return;
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === 'Escape') closeModal();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [modalOpen]);

  return (
    <>
      <style>{REPORT_LIST_CSS}</style>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10 mt-16 space-y-8">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="flex items-center gap-4">
            <div className="w-14 h-14 rounded-2xl bg-danger-500/10 border border-danger-500/20 flex items-center justify-center shadow-lg shadow-danger-500/10 shrink-0">
              <i className="bi bi-shield-shaded text-danger-500 text-2xl"></i>
            </div>
            <div>
              <h1 className="text-2xl sm:text-3xl font-black text-white tracking-tight">Tra cứu danh sách báo cáo</h1>
              <p className="text-[11px] font-bold text-white/55 uppercase tracking-widest mt-1">Cơ sở dữ liệu cảnh báo lừa đảo cộng đồng do ShieldCall VN xác thực</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <Link href="/report/" className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-danger-500 text-black font-black text-xs uppercase tracking-widest hover:bg-danger-400 transition-all shadow-lg shadow-danger-500/20">
              <i className="bi bi-plus-lg"></i> Gửi báo cáo mới
            </Link>
            {user && (
              <Link href="/my-reports/" className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-white/5 border border-white/10 text-white/80 font-bold text-xs hover:bg-white/10 transition-all">
                <i className="bi bi-clock-history"></i> Của tôi
              </Link>
            )}
          </div>
        </div>

        {/* Stats Bar */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="liquid-card p-4 flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-safe-500/10 border border-safe-500/20 flex items-center justify-center text-safe-400 shrink-0">
              <i className="bi bi-check2-all text-xl"></i>
            </div>
            <div>
              <p className="text-xl font-black text-white">{stats.total}</p>
              <p className="text-[10px] font-bold text-white/55 uppercase tracking-widest">Đã xác minh</p>
            </div>
          </div>
          <div className="liquid-card p-4 flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-brand-500/10 border border-brand-500/20 flex items-center justify-center text-brand-400 shrink-0">
              <i className="bi bi-phone text-xl"></i>
            </div>
            <div>
              <p className="text-xl font-black text-brand-400">{stats.phone}</p>
              <p className="text-[10px] font-bold text-white/55 uppercase tracking-widest">Số điện thoại</p>
            </div>
          </div>
          <div className="liquid-card p-4 flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-brand-500/10 border border-brand-500/20 flex items-center justify-center text-brand-400 shrink-0">
              <i className="bi bi-globe2 text-xl"></i>
            </div>
            <div>
              <p className="text-xl font-black text-brand-400">{stats.domain}</p>
              <p className="text-[10px] font-bold text-white/55 uppercase tracking-widest">Website / Phishing</p>
            </div>
          </div>
          <div className="liquid-card p-4 flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-warn-500/10 border border-warn-500/20 flex items-center justify-center text-warn-400 shrink-0">
              <i className="bi bi-bank2 text-xl"></i>
            </div>
            <div>
              <p className="text-xl font-black text-warn-400">{stats.account}</p>
              <p className="text-[10px] font-bold text-white/55 uppercase tracking-widest">Tài khoản ngân hàng</p>
            </div>
          </div>
          <div className="liquid-card p-4 flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-danger-500/10 border border-danger-500/20 flex items-center justify-center text-danger-400 shrink-0">
              <i className="bi bi-file-earmark-binary text-xl"></i>
            </div>
            <div>
              <p className="text-xl font-black text-danger-400">{stats.file}</p>
              <p className="text-[10px] font-bold text-white/55 uppercase tracking-widest">File / APK độc hại</p>
            </div>
          </div>
          <div className="liquid-card p-4 flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-brand2-500/10 border border-brand2-500/20 flex items-center justify-center text-brand2-400 shrink-0">
              <i className="bi bi-telegram text-xl"></i>
            </div>
            <div>
              <p className="text-xl font-black text-brand2-400">{stats.social}</p>
              <p className="text-[10px] font-bold text-white/55 uppercase tracking-widest">MXH / Telegram</p>
            </div>
          </div>
          <div className="liquid-card p-4 flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-warn-500/10 border border-warn-500/20 flex items-center justify-center text-warn-400 shrink-0">
              <i className="bi bi-coin text-xl"></i>
            </div>
            <div>
              <p className="text-xl font-black text-warn-400">{stats.crypto}</p>
              <p className="text-[10px] font-bold text-white/55 uppercase tracking-widest">Ví Crypto</p>
            </div>
          </div>
          <div className="liquid-card p-4 flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-brand-500/10 border border-brand-500/20 flex items-center justify-center text-brand-400 shrink-0">
              <i className="bi bi-mic text-xl"></i>
            </div>
            <div>
              <p className="text-xl font-black text-brand-400">{stats.audio}</p>
              <p className="text-[10px] font-bold text-white/55 uppercase tracking-widest">Audio / Deepfake</p>
            </div>
          </div>
        </div>

        {/* Search & Filter Controls */}
        <div className="liquid-card p-6 space-y-4">
          <form method="GET" action="/reports/" className="space-y-4" onSubmit={submitSearch}>
            {/* Search input */}
            <div className="relative">
              <i className="bi bi-search absolute left-4 top-1/2 -translate-y-1/2 text-white/45 text-lg pointer-events-none z-10"></i>
              <input
                type="text"
                name="q"
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="Nhập SĐT, link, STK, ví crypto, hash file, Telegram/Zalo, tên scammer..."
                className="w-full pl-12 pr-28 py-3.5 bg-black/40 border border-white/10 rounded-xl text-white placeholder-white/30 text-sm focus:outline-none focus:border-brand-400/50 transition-colors font-medium"
              />
              <button type="submit" className="absolute right-2 top-1/2 -translate-y-1/2 px-4 py-2 bg-brand-400 text-black font-black text-xs uppercase tracking-widest rounded-lg hover:bg-brand-300 transition-colors">
                Tìm kiếm
              </button>
            </div>

            {/* Target Type Filter Pills */}
            <div className="flex items-center gap-2 flex-wrap pt-2 border-t border-white/5">
              <span className="text-[10px] font-black uppercase tracking-widest text-white/45 mr-1">Loại mục tiêu:</span>
              {TYPE_FILTERS.map((t) => (
                <button
                  key={t.v}
                  type="button"
                  onClick={() => pickType(t.v)}
                  className={`filter-pill px-3 py-1.5 rounded-lg text-xs font-bold border border-white/10 ${
                    type === t.v ? 'active' : 'text-white/60 hover:text-white bg-white/5'
                  }`}
                >
                  {t.i && <i className={`bi ${t.i} mr-1`}></i>}
                  {t.l}
                </button>
              ))}

              {/* Reset button if filtering */}
              {(q || type !== 'all' || scamType !== 'all' || severity !== 'all') && (
                <button
                  type="button"
                  onClick={resetFilters}
                  className="ml-auto text-xs text-danger-400 hover:text-danger-300 font-bold flex items-center gap-1"
                >
                  <i className="bi bi-x-circle"></i> Đặt lại bộ lọc
                </button>
              )}
            </div>

            {/* Scam type + Severity dropdowns */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
              <label className="flex items-center gap-2 text-xs text-white/60">
                <span className="text-[10px] font-black uppercase tracking-widest text-white/45 whitespace-nowrap">Phương thức:</span>
                <select
                  name="scam_type"
                  value={scamType}
                  onChange={(e) => pickScamType(e.target.value)}
                  className="flex-1 px-3 py-2.5 bg-black/40 border border-white/10 rounded-xl text-white text-xs font-bold focus:outline-none focus:border-brand-400/50"
                >
                  <option value="all">Tất cả thủ đoạn</option>
                  {SCAM_TYPE_OPTIONS.map((s) => (
                    <option key={s.v} value={s.v}>{s.l}</option>
                  ))}
                </select>
              </label>
              <label className="flex items-center gap-2 text-xs text-white/60">
                <span className="text-[10px] font-black uppercase tracking-widest text-white/45 whitespace-nowrap">Mức độ:</span>
                <select
                  name="severity"
                  value={severity}
                  onChange={(e) => pickSeverity(e.target.value)}
                  className="flex-1 px-3 py-2.5 bg-black/40 border border-white/10 rounded-xl text-white text-xs font-bold focus:outline-none focus:border-brand-400/50"
                >
                  <option value="all">Tất cả mức độ</option>
                  {SEVERITY_OPTIONS.map((s) => (
                    <option key={s.v} value={s.v}>{s.l}</option>
                  ))}
                </select>
              </label>
            </div>
          </form>
        </div>

        {/* Reports Grid */}
        <div className="space-y-4">
          {loading ? (
            <Spinner />
          ) : items.length > 0 ? (
            <>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
                {items.map((it) => {
                  const meta = typeBadge(it.type, it.type_display);
                  return (
                    <div
                      key={`${it.kind}-${it.id}`}
                      className="report-card p-6 rounded-2xl flex flex-col justify-between space-y-4 cursor-pointer"
                      onClick={() => openDetail(it)}
                    >
                      {/* Card Header */}
                      <div className="space-y-3">
                        <div className="flex items-center justify-between gap-2">
                          <span className={`text-[9px] font-black uppercase tracking-widest px-2.5 py-1 rounded-lg border ${meta.badge}`}>
                            {meta.label}
                          </span>
                          <span className={`text-[8px] font-bold px-2 py-0.5 rounded border ${severityBadge(it.risk_level)}`}>
                            {it.risk_display}
                          </span>
                        </div>

                        {/* Target Value */}
                        <div className="text-base font-black text-white tracking-tight break-all">{it.target}</div>

                        {/* Scam Category */}
                        {it.scam_type && (
                          <div className="text-xs font-bold text-brand-400/90 flex items-center gap-1.5">
                            <i className="bi bi-exclamation-octagon-fill text-[11px] text-danger-400"></i>
                            <span>{it.scam_type}</span>
                          </div>
                        )}

                        {/* Description excerpt */}
                        <p className="text-xs text-white/60 line-clamp-3 leading-relaxed">{it.description || ''}</p>

                        {/* Scammer details preview */}
                        {(it.scammer_name || it.scammer_bank_account || it.scammer_phone || it.scammer_social) && (
                          <div className="p-2.5 rounded-xl bg-white/5 border border-white/5 space-y-1 text-[11px]">
                            {it.scammer_name && (
                              <div className="text-white/60 truncate"><span className="text-white/45">Họ tên:</span> <strong className="text-white/90">{it.scammer_name}</strong></div>
                            )}
                            {it.scammer_bank_account && (
                              <div className="text-white/60 truncate"><span className="text-white/45">STK nhận:</span> <span className="font-mono text-brand-300">{it.scammer_bank_account}</span> {it.scammer_bank_name && `(${it.scammer_bank_name})`}</div>
                            )}
                            {it.scammer_phone && it.scammer_phone !== it.target && (
                              <div className="text-white/60 truncate"><span className="text-white/45">SĐT đối tượng:</span> <span className="font-mono text-warn-300">{it.scammer_phone}</span></div>
                            )}
                            {it.scammer_social && (
                              <div className="text-white/60 truncate"><span className="text-white/45">MXH:</span> <span className="text-brand2-300">{it.scammer_social}</span></div>
                            )}
                            {it.custom_fields && (
                              <div className="flex flex-wrap gap-1 pt-1">
                                {!!it.custom_fields.loss_amount_vnd && (
                                  <span className="px-2 py-0.5 rounded bg-danger-500/10 border border-danger-500/20 text-danger-300 font-bold">💸 {String(it.custom_fields.loss_amount_vnd)}đ</span>
                                )}
                                {!!it.custom_fields.impersonated_org && (
                                  <span className="px-2 py-0.5 rounded bg-warn-500/10 border border-warn-500/20 text-warn-300 font-bold">🏛️ {String(it.custom_fields.impersonated_org)}</span>
                                )}
                                {!!it.custom_fields.crypto_wallet && (
                                  <span className="px-2 py-0.5 rounded bg-warn-500/10 border border-warn-500/20 text-warn-300 font-mono">🪙 ví crypto</span>
                                )}
                                {!!(it.custom_fields.file_hash || it.custom_fields.sha256) && (
                                  <span className="px-2 py-0.5 rounded bg-danger-500/10 border border-danger-500/20 text-danger-300 font-mono">🦠 mã độc</span>
                                )}
                              </div>
                            )}
                          </div>
                        )}
                      </div>

                      {/* Card Footer */}
                      <div className="pt-3 border-t border-white/5 flex items-center justify-between text-[10px] text-white/45">
                        <span className="flex items-center gap-1">
                          <i className="bi bi-calendar3"></i> {fmtDate(it.created_at) || it.time_ago || ''}
                        </span>
                        <span className="text-brand-400/80 font-bold hover:text-brand-300 flex items-center gap-1">
                          Chi tiết <i className="bi bi-arrow-right"></i>
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Pagination */}
              {numPages > 1 && (
                <div className="flex items-center justify-center gap-2 pt-6">
                  {page > 1 && (
                    <button
                      type="button"
                      onClick={() => goPage(page - 1)}
                      className="px-3.5 py-2 rounded-xl bg-white/5 border border-white/10 text-white text-xs font-bold hover:bg-white/10 transition-colors"
                    >
                      <i className="bi bi-chevron-left"></i> Trước
                    </button>
                  )}

                  <span className="px-4 py-2 text-xs font-bold text-white/60">
                    Trang {page} / {numPages}
                  </span>

                  {hasNext && (
                    <button
                      type="button"
                      onClick={() => goPage(page + 1)}
                      className="px-3.5 py-2 rounded-xl bg-white/5 border border-white/10 text-white text-xs font-bold hover:bg-white/10 transition-colors"
                    >
                      Sau <i className="bi bi-chevron-right"></i>
                    </button>
                  )}
                </div>
              )}
            </>
          ) : (
            /* Empty State */
            <div className="liquid-card p-12 text-center space-y-4">
              <div className="w-16 h-16 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center mx-auto text-white/35 text-3xl">
                <i className="bi bi-shield-check"></i>
              </div>
              <div className="space-y-1">
                <h3 className="text-lg font-black text-white">Không tìm thấy báo cáo nào</h3>
                <p className="text-xs text-white/55 max-w-md mx-auto">
                  {q ? (
                    <>Không có báo cáo nào khớp với từ khóa &quot;<strong>{q}</strong>&quot;. Nếu bạn nghi ngờ đối tượng này, hãy gửi báo cáo để cộng đồng cùng phòng ngừa.</>
                  ) : (
                    'Chưa có báo cáo lừa đảo nào được ghi nhận trong danh mục này.'
                  )}
                </p>
              </div>
              <div className="pt-2">
                <Link href="/report/" className="inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-danger-500 text-black font-black text-xs uppercase tracking-widest hover:bg-danger-400 transition-all shadow-lg shadow-danger-500/20">
                  <i className="bi bi-plus-lg"></i> Gửi báo cáo đối tượng này
                </Link>
              </div>
            </div>
          )}
        </div>

        {/* Report detail modal */}
        {modalOpen && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={closeModal}></div>
            <div className="relative w-full max-w-3xl max-h-[90vh] overflow-y-auto liquid-card rounded-2xl p-6 space-y-5">
              <div className="flex items-start justify-between gap-3">
                <h2 className="text-lg font-black text-white">Chi tiết báo cáo <span>{detail ? '#' + detail.id : ''}</span></h2>
                <button onClick={closeModal} className="px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-white/60 text-xs font-bold hover:bg-white/10">✕ Đóng</button>
              </div>

              {modalLoading && <p className="text-sm text-white/60">Đang tải chi tiết...</p>}
              {modalError && <p className="text-sm text-danger-400">{modalError}</p>}

              {detail && (
                <div className="space-y-5 text-sm">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="px-2.5 py-1 rounded-lg border text-[10px] font-black uppercase tracking-widest bg-brand-500/10 text-brand-300 border-brand-500/20">{detail.target_type}</span>
                    <span className="px-2.5 py-1 rounded-lg border text-[10px] font-bold bg-warn-500/10 text-warn-300 border-warn-500/20">{detail.severity}</span>
                    <span className="px-2.5 py-1 rounded-lg border text-[10px] font-bold bg-white/5 text-white/60 border-white/10">{detail.scam_type_display || detail.scam_type}</span>
                  </div>

                  <div className="p-3 rounded-xl bg-black/40 border border-white/10 flex items-center justify-between gap-2">
                    <span className="font-black text-white break-all">{detail.target_value}</span>
                    <button onClick={() => copyText(detail.target_value)} className="px-2.5 py-1.5 rounded-lg bg-brand-500/10 border border-brand-500/20 text-brand-300 text-xs font-bold shrink-0">⧉ Copy</button>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                    <div className="p-3 rounded-xl bg-white/5 border border-white/10 space-y-1">
                      <p className="text-[10px] font-black uppercase tracking-widest text-white/45">Hồ sơ kẻ gian</p>
                      <p className="text-white/70">Tên: <strong className="text-white">{detail.scammer_info?.name || '—'}</strong></p>
                      <p className="text-white/70">SĐT: <span className="font-mono text-warn-300">{detail.scammer_info?.phone || '—'}</span></p>
                      <p className="text-white/70">STK: <span className="font-mono text-brand-300">{detail.scammer_info?.bank_account || '—'}</span> <span>{detail.scammer_info?.bank_name || ''}</span></p>
                      <p className="text-white/70">MXH: <span className="text-brand2-300">{detail.scammer_info?.social || detail.scammer_social || '—'}</span></p>
                      <p className="text-white/70">Ví Crypto: <span className="font-mono text-warn-300">{String(detail.scammer_info?.custom_fields?.crypto_wallet || detail.custom_fields?.crypto_wallet || '—')}</span></p>
                    </div>
                    <div className="p-3 rounded-xl bg-white/5 border border-white/10 space-y-1">
                      <p className="text-[10px] font-black uppercase tracking-widest text-white/45">Thiệt hại &amp; tuỳ biến</p>
                      {detail.custom_fields && Object.keys(detail.custom_fields).length > 0 ? (
                        <div className="space-y-1">
                          {Object.entries(detail.custom_fields).map(([k, v]) => (
                            <p key={k} className="text-white/70">
                              <span className="text-white/55">{k + ':'}</span>{' '}
                              <strong className="text-white">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</strong>
                            </p>
                          ))}
                        </div>
                      ) : (
                        <p className="text-white/55">Không có thông tin tuỳ biến.</p>
                      )}
                    </div>
                  </div>

                  <p className="text-white/70 text-[13px] leading-relaxed whitespace-pre-line">{detail.description}</p>

                  {!!detail.evidence_images_data && detail.evidence_images_data.length > 0 && (
                    <div>
                      <p className="text-[10px] font-black uppercase tracking-widest text-white/45 mb-2">Ảnh bằng chứng</p>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                        {detail.evidence_images_data.map((img) => (
                          <img
                            key={img.id}
                            src={img.url}
                            onClick={() => setLightbox(img.url)}
                            className="w-full h-24 object-cover rounded-xl border border-white/10 cursor-zoom-in"
                            loading="lazy"
                            alt=""
                          />
                        ))}
                      </div>
                    </div>
                  )}

                  {detail.ocr_text && (
                    <div className="p-3 rounded-xl bg-black/40 border border-white/10">
                      <p className="text-[10px] font-black uppercase tracking-widest text-white/45 mb-1">OCR trích xuất</p>
                      <p className="text-xs text-white/60 whitespace-pre-line">{detail.ocr_text}</p>
                    </div>
                  )}

                  {!!detail.ai_analysis && (
                    <div className="p-3 rounded-xl bg-black/40 border border-white/10">
                      <p className="text-[10px] font-black uppercase tracking-widest text-white/45 mb-1">Kết luận AI</p>
                      <p className="text-xs text-white/60 whitespace-pre-line">
                        {typeof detail.ai_analysis === 'object' ? JSON.stringify(detail.ai_analysis, null, 2) : String(detail.ai_analysis)}
                      </p>
                    </div>
                  )}

                  <div className="flex gap-2 flex-wrap">
                    <Link href={scanUrlFor(detail)} className="px-4 py-2.5 rounded-xl bg-brand-400 text-black font-black text-xs uppercase tracking-widest hover:bg-brand-300">Quét ngay đối tượng này</Link>
                    <button onClick={() => copyText(detail.target_value)} className="px-4 py-2.5 rounded-xl bg-white/5 border border-white/10 text-white/70 font-bold text-xs">Sao chép đối tượng</button>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {lightbox && (
          <div className="fixed inset-0 z-[110] flex items-center justify-center p-6 bg-black/90" onClick={() => setLightbox(null)}>
            <img src={lightbox} className="max-h-[90vh] max-w-full rounded-2xl border border-white/20" onClick={(e) => e.stopPropagation()} alt="" />
          </div>
        )}
      </div>
    </>
  );
}
