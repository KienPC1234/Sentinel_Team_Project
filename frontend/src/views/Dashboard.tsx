'use client';
import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Tooltip,
} from 'chart.js';
import type { ChartData, ChartOptions } from 'chart.js';
import { Bar } from 'react-chartjs-2';
import { api, asList, learnApi, mediaUrl } from '../lib/api';
import type { Article, Paged } from '../lib/api';
import { useAuth } from '../components/AuthContext';
import { Spinner } from '../components/ui';
import { guardrailTone, guardrailLabel } from '../components/ScanWidgets';

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip);

interface ScanRow {
  id: number;
  scan_type?: string;
  raw_input?: string;
  normalized_input?: string;
  risk_level?: string;
  risk_score?: number;
  result_json?: Record<string, unknown>;
  created_at?: string;
}

interface UserReport {
  id: number;
  target_type?: string;
  target_value?: string;
  scam_type_display?: string;
  status?: string;
  created_at?: string;
}

interface UserAlert {
  id: number;
  target_type?: string;
  target_value?: string;
  risk_level?: string;
  created_at?: string;
}

interface ApiKey {
  id: number;
  name: string;
  prefix?: string;
  tier?: string;
  requests_today?: number;
  daily_quota?: number;
  requests_this_month?: number;
  monthly_quota?: number;
  last_used_at?: string | null;
  is_active?: boolean;
}

type Tab = 'overview' | 'history' | 'reports' | 'alerts' | 'api_keys';

function timeAgo(dt?: string | null): string {
  if (!dt) return '';
  const diff = (Date.now() - new Date(dt).getTime()) / 1000;
  if (Number.isNaN(diff)) return '';
  if (diff < 60) return 'Vừa xong';
  if (diff < 3600) return `${Math.floor(diff / 60)} phút trước`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} giờ trước`;
  return `${Math.floor(diff / 86400)} ngày trước`;
}

export default function Dashboard() {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState<Tab>('overview');
  const [scans, setScans] = useState<ScanRow[]>([]);
  const [scanPage, setScanPage] = useState(1);
  const [scanTotal, setScanTotal] = useState(0);
  const [scanTotalPages, setScanTotalPages] = useState(1);
  const [scansLoading, setScansLoading] = useState(false);
  const [scanDangerTotal, setScanDangerTotal] = useState(0);
  const [scanWeekCounts, setScanWeekCounts] = useState<number[]>([]);
  const [reports, setReports] = useState<UserReport[]>([]);
  const [alerts, setAlerts] = useState<UserAlert[]>([]);
  const [articles, setArticles] = useState<Article[]>([]);
  const [loading, setLoading] = useState(true);
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [loadingKeys, setLoadingKeys] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newKeyName, setNewKeyName] = useState('');
  const [submittingKey, setSubmittingKey] = useState(false);
  const [createdRawKey, setCreatedRawKey] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);
  const scansPerPage = 15;

  /* Lịch sử scan phân trang server-side (trước đây cắt cứng 50 bản ghi đầu). */
  const fetchScans = (p: number): void => {
    setScansLoading(true);
    api
      .get<Paged<ScanRow> | ScanRow[] & { stats?: { total?: number; red?: number; last_7_days?: number[] } }>(`/user/scans/?page=${p}&page_size=${scansPerPage}`)
      .then((d) => {
        setScans(asList(d as Paged<ScanRow> | ScanRow[]));
        if (!Array.isArray(d) && typeof (d as Paged<ScanRow>).count === 'number') {
          const c = (d as Paged<ScanRow>).count || 0;
          setScanTotal(c);
          setScanTotalPages(Math.max(1, Math.ceil(c / scansPerPage)));
        } else {
          setScanTotal(Array.isArray(d) ? d.length : 0);
          setScanTotalPages(1);
        }
        const st = (d as { stats?: { total?: number; red?: number; last_7_days?: number[] } }).stats;
        if (st) {
          if (typeof st.red === 'number') setScanDangerTotal(st.red);
          if (Array.isArray(st.last_7_days)) setScanWeekCounts(st.last_7_days);
        }
      })
      .catch(() => setScans([]))
      .finally(() => setScansLoading(false));
  };

  useEffect(() => {
    fetchScans(scanPage);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanPage]);

  useEffect(() => {
    Promise.allSettled([
      api.get<Paged<UserReport> | UserReport[]>('/user/reports/'),
      api.get<Paged<UserAlert> | UserAlert[] | { alerts?: UserAlert[] }>('/user/alerts/'),
      learnApi.articles({ page_size: 3, ordering: '-created_at' }),
    ]).then(([r, a, n]) => {
      if (r.status === 'fulfilled') setReports(asList(r.value as Paged<UserReport> | UserReport[]));
      if (a.status === 'fulfilled') {
        const v = a.value as unknown as { results?: UserAlert[]; alerts?: UserAlert[] };
        setAlerts(Array.isArray(v) ? (v as UserAlert[]) : v.results || v.alerts || []);
      }
      if (n.status === 'fulfilled') setArticles(asList(n.value));
      setLoading(false);
    });
  }, []);

  const loadApiKeys = () => {
    setLoadingKeys(true);
    api
      .get<{ api_keys?: ApiKey[] } | ApiKey[]>('/user/api-keys/')
      .then((d) => setApiKeys(Array.isArray(d) ? d : d.api_keys || []))
      .catch(() => setApiKeys([]))
      .finally(() => setLoadingKeys(false));
  };

  const switchTab = (t: Tab) => {
    setActiveTab(t);
    if (t === 'api_keys' && apiKeys.length === 0) loadApiKeys();
  };

  const submitCreateKey = () => {
    setSubmittingKey(true);
    api
      .post<{ raw_key?: string; key?: string }>('/user/api-keys/', { name: newKeyName.trim() || 'MCP Client' })
      .then((d) => {
        setCreatedRawKey(d.raw_key || d.key || null);
        setShowCreateModal(false);
        loadApiKeys();
      })
      .catch(() => {})
      .finally(() => setSubmittingKey(false));
  };

  const toggleKey = (k: ApiKey) => {
    api.post<{ is_active?: boolean }>(`/user/api-keys/${k.id}/toggle/`).then((d) => {
      setApiKeys(apiKeys.map((x) => (x.id === k.id ? { ...x, is_active: d.is_active ?? !x.is_active } : x)));
    }).catch(() => {});
  };

  const deleteKey = (k: ApiKey) => {
    if (!window.confirm(`Bạn có chắc muốn xóa vĩnh viễn khóa "${k.name}"?`)) return;
    api.del(`/user/api-keys/${k.id}/`).then(loadApiKeys).catch(() => {});
  };

  const regenerateKey = (k: ApiKey) => {
    if (!window.confirm(`Tạo lại mã bí mật cho "${k.name}"? Khóa cũ sẽ bị vô hiệu hóa ngay lập tức!`)) return;
    api.post<{ raw_key?: string; key?: string }>(`/user/api-keys/${k.id}/regenerate/`).then((d) => {
      setCreatedRawKey(d.raw_key || d.key || null);
      loadApiKeys();
    }).catch(() => {});
  };

  /* Tổng quan dùng số liệu server (đúng cả khi nhiều trang lịch sử). */
  const totalScans = scanTotal;
  const dangerScans = scanDangerTotal;
  const totalReports = reports.length;
  const protection = totalScans === 0 ? 100 : Math.max(0, Math.round(100 - (dangerScans / totalScans) * 100));

  const chart = useMemo(() => {
    const days: string[] = [];
    const counts: number[] = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      days.push(`${String(d.getDate()).padStart(2, '0')}/${String(d.getMonth() + 1).padStart(2, '0')}`);
      const idx = 6 - i;
      counts.push(scanWeekCounts[idx] ?? 0);
    }
    return { days, counts };
  }, [scanWeekCounts]);

  const barData: ChartData<'bar'> = useMemo(
    () => ({
      labels: chart.days,
      datasets: [
        {
          label: 'Scans',
          data: chart.counts,
          backgroundColor: 'rgba(0, 255, 255, 0.4)',
          borderColor: 'rgba(0, 255, 255, 0.8)',
          borderWidth: 0,
          borderRadius: 12,
          hoverBackgroundColor: 'rgba(0, 255, 255, 0.6)',
        },
      ],
    }),
    [chart],
  );

  const barOptions: ChartOptions<'bar'> = useMemo(
    () => ({
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: 'rgba(15, 23, 42, 0.9)',
          padding: 12,
          titleFont: { size: 10, weight: 'bold' },
          bodyFont: { size: 12, weight: 'normal' },
          displayColors: false,
          cornerRadius: 12,
        },
      },
      scales: {
        x: {
          ticks: { color: 'rgba(255,255,255,0.2)', font: { size: 10, weight: 'bold' } },
          grid: { display: false },
        },
        y: {
          ticks: { color: 'rgba(255,255,255,0.2)', font: { size: 10, weight: 'bold' }, stepSize: 1 },
          grid: { color: 'rgba(255,255,255,0.03)' },
          beginAtZero: true,
        },
      },
    }),
    [],
  );
  /* scans đã là trang hiện tại từ server — không slice client-side nữa. */
  const paginatedScans = scans;
  const todayTotal = apiKeys.reduce((a, k) => a + (k.requests_today || 0), 0);
  const dailyQuota = apiKeys.reduce((a, k) => a + (k.daily_quota || 0), 0) || 500;
  const monthTotal = apiKeys.reduce((a, k) => a + (k.requests_this_month || 0), 0);
  const monthlyQuota = apiKeys.reduce((a, k) => a + (k.monthly_quota || 0), 0) || 15000;

  const tabs: { v: Tab; l: string }[] = [
    { v: 'overview', l: 'Tổng quan' },
    { v: 'history', l: 'Lịch sử scan' },
    { v: 'reports', l: 'Báo cáo' },
    { v: 'alerts', l: 'Cảnh báo' },
    { v: 'api_keys', l: 'API & MCP' },
  ];

  return (
    <div className="max-w-6xl mx-auto space-y-10 pt-12 sm:pt-16 pb-20 px-4">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
        <div className="space-y-2">
          <h1 className="text-4xl font-black text-white tracking-tight leading-none">Dashboard</h1>
          <p className="text-white/55 text-sm font-medium tracking-wide flex items-center gap-2">
            Xin chào, {user?.username || 'bạn'}!
            <span className="inline-flex items-center px-2 py-0.5 rounded-full bg-brand-500/10 text-brand-400 border border-brand-500/20 text-[10px] font-black uppercase tracking-widest">
              <i className="bi bi-patch-check-fill mr-1"></i> Verified
            </span>
          </p>
        </div>
        <div className="flex gap-3 w-full md:w-auto flex-wrap">
          <Link href="/scan/phone/" className="py-3 px-6 text-xs font-black bg-white/5 text-white/80 border border-white/10 rounded-xl hover:bg-white/10 uppercase tracking-widest"><i className="bi bi-search mr-2"></i> Scan Mới</Link>
          <Link href="/profile/inbox/" className="py-3 px-6 text-xs font-black bg-white/5 text-white/80 border border-white/10 rounded-xl hover:bg-white/10 uppercase tracking-widest"><i className="bi bi-envelope mr-2"></i> Hộp thư</Link>
          <Link href="/profile/tickets/" className="py-3 px-6 text-xs font-black bg-white/5 text-white/80 border border-white/10 rounded-xl hover:bg-white/10 uppercase tracking-widest"><i className="bi bi-bug mr-2"></i> Báo lỗi</Link>
          <Link href="/report/" className="py-3 px-6 text-xs font-black bg-danger-500 text-black hover:bg-danger-400 uppercase tracking-widest rounded-xl"><i className="bi bi-flag-fill mr-2"></i> Báo Cáo</Link>
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { icon: 'bi-cpu', color: 'text-brand-400', bg: 'bg-brand-500/10', l: 'Tổng Scan', v: String(totalScans), vc: 'text-white' },
          { icon: 'bi-shield-exclamation', color: 'text-danger-500', bg: 'bg-danger-500/10', l: 'Rủi Ro', v: String(dangerScans), vc: 'text-danger-500' },
          { icon: 'bi-megaphone', color: 'text-warn-400', bg: 'bg-warn-500/10', l: 'Báo Cáo', v: String(totalReports), vc: 'text-white' },
          { icon: 'bi-shield-check', color: 'text-safe-400', bg: 'bg-safe-500/10', l: 'Protection', v: `${protection}/100`, vc: 'text-safe-400' },
        ].map((s) => (
          <div key={s.l} className="rounded-2xl border border-white/10 bg-white/[0.02] p-6 space-y-4 hover:bg-white/[0.04] transition-all">
            <div className="flex items-center justify-between">
              <div className={`w-10 h-10 rounded-2xl flex items-center justify-center ${s.bg} ${s.color}`}><i className={`bi ${s.icon}`}></i></div>
              <div className="text-[10px] font-black text-white/35 uppercase tracking-widest text-right">{s.l}</div>
            </div>
            <div className={`text-3xl font-black leading-none ${s.vc}`}>{s.v}</div>
          </div>
        ))}
      </div>

      <div className="inline-flex p-1.5 bg-white/[0.03] border border-white/5 rounded-[2rem] shadow-xl flex-wrap">
        {tabs.map((t) => (
          <button key={t.v} onClick={() => switchTab(t.v)}
            className={`px-8 py-2.5 rounded-full text-[10px] font-black uppercase tracking-widest transition-all ${activeTab === t.v ? (t.v === 'api_keys' ? 'bg-brand-400 text-black' : 'bg-white text-black shadow-lg') : 'text-white/55 hover:text-white/60'}`}>
            {t.l.toUpperCase()}
          </button>
        ))}
      </div>

      {loading ? (
        <Spinner />
      ) : (
        <div>
          {activeTab === 'overview' && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-8 space-y-6">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-black text-white uppercase tracking-widest">Hoạt động 7 ngày qua</h3>
                  <i className="bi bi-bar-chart text-brand-400"></i>
                </div>
                <div className="h-64 relative">
                  <Bar data={barData} options={barOptions} />
                </div>
              </div>
              <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-8 space-y-6">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-black text-white uppercase tracking-widest">Cảnh báo gần đây</h3>
                  <i className="bi bi-bell text-danger-500"></i>
                </div>
                <div className="space-y-4">
                  {alerts.slice(0, 5).map((alert) => (
                    <div key={alert.id} className="flex items-center gap-5 p-4 rounded-3xl bg-white/[0.02] border border-white/5">
                      <div className="w-10 h-10 rounded-2xl bg-danger-500/10 text-danger-500 flex items-center justify-center"><i className="bi bi-shield-fill-exclamation"></i></div>
                      <div className="flex-1 min-w-0">
                        <div className="text-[11px] font-black text-white/90 truncate uppercase tracking-wider">{alert.target_type}: {alert.target_value}</div>
                        <div className="text-[9px] font-bold text-white/35 uppercase tracking-widest mt-0.5">{timeAgo(alert.created_at)} trước</div>
                      </div>
                    </div>
                  ))}
                  {alerts.length === 0 && (
                    <div className="text-center py-12 space-y-3 opacity-20">
                      <i className="bi bi-shield-check text-5xl"></i>
                      <p className="text-[10px] font-black uppercase tracking-widest">Bầu trời đang bình yên</p>
                    </div>
                  )}
                </div>
              </div>
              <div className="lg:col-span-2 rounded-2xl border border-white/10 bg-white/[0.02] p-8 space-y-6">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-black text-white uppercase tracking-widest">Tin tức mới nhất về lừa đảo</h3>
                  <Link href="/learn" className="text-[10px] font-black text-brand-400 uppercase tracking-widest hover:underline">Tất cả bài viết</Link>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  {articles.map((a) => (
                    <Link key={a.slug} href={`/learn/${a.slug}/`} className="group relative overflow-hidden rounded-3xl bg-white/[0.02] border border-white/5 hover:bg-white/[0.04] transition-all p-5">
                      <div className="aspect-video rounded-2xl overflow-hidden mb-4 bg-white/5">
                        {a.cover_image ? <img src={mediaUrl(a.cover_image)} className="w-full h-full object-cover transition-transform duration-500 group-hover:scale-110" alt="" /> : <div className="w-full h-full flex items-center justify-center text-white/20 uppercase font-black text-[10px]">No Cover</div>}
                      </div>
                      <h4 className="text-xs font-black text-white group-hover:text-brand-400 transition-colors line-clamp-2">{a.title}</h4>
                    </Link>
                  ))}
                  {articles.length === 0 && <div className="col-span-3 text-center py-12 opacity-20 italic text-xs uppercase tracking-widest">Chưa có bài viết mới...</div>}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'history' && (
            <div className="space-y-4">
              <div className="rounded-2xl border border-white/10 bg-white/[0.02] overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="bg-white/[0.02] border-b border-white/5">
                        <th className="px-8 py-5 text-[10px] font-black text-white/45 uppercase tracking-[0.2em]">Thời Gian</th>
                        <th className="px-8 py-5 text-[10px] font-black text-white/45 uppercase tracking-[0.2em]">Hạng Mục</th>
                        <th className="px-8 py-5 text-[10px] font-black text-white/45 uppercase tracking-[0.2em]">Đối Tượng</th>
                        <th className="px-8 py-5 text-[10px] font-black text-white/45 uppercase tracking-[0.2em] text-center">Kết Quả</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5">
                      {paginatedScans.map((scan) => {
                        const lvl = guardrailTone(scan.result_json);
                        const lbl = guardrailLabel(scan.result_json);
                        return (
                        <tr key={scan.id} className="hover:bg-white/[0.01] transition-colors">
                          <td className="px-8 py-5 text-xs font-bold text-white/55">{scan.created_at ? new Date(scan.created_at).toLocaleDateString('vi-VN') : ''}</td>
                          <td className="px-8 py-5"><span className="px-3 py-1 rounded-full bg-white/5 border border-white/10 text-[9px] font-black text-white/60 uppercase tracking-widest">{scan.scan_type}</span></td>
                          <td className="px-8 py-5"><div className="text-xs font-black text-white/80 tracking-wide uppercase truncate max-w-xs">{scan.raw_input || scan.normalized_input}</div></td>
                          <td className="px-8 py-5 text-center">
                            <span className={`inline-block px-4 py-1.5 rounded-full text-[9px] font-black tracking-widest uppercase border ${lvl === 'RED' ? 'bg-danger-500/20 text-danger-500 border-danger-500/30' : lvl === 'YELLOW' ? 'bg-warn-500/20 text-warn-500 border-warn-500/30' : lvl === 'UNVERIFIED' ? 'bg-slate-500/20 text-slate-300 border-slate-400/30' : 'bg-safe-500/20 text-safe-500 border-safe-500/30'}`}>
                              {lbl}
                            </span>
                          </td>
                        </tr>
                        );
                      })}
                      {scansLoading && scans.length === 0 && <tr><td colSpan={4} className="px-8 py-20 text-center text-white/20 font-black uppercase tracking-widest text-[10px]">Đang tải lịch sử...</td></tr>}
                      {!scansLoading && scans.length === 0 && <tr><td colSpan={4} className="px-8 py-20 text-center text-white/20 font-black uppercase tracking-widest text-[10px]">Lịch sử sạch bóng lừa đảo</td></tr>}
                    </tbody>
                  </table>
                </div>
              </div>
              {scanTotalPages > 1 && (
                <div className="flex items-center justify-between">
                  <div className="text-[10px] font-bold text-white/35 uppercase tracking-widest">Trang {scanPage} / {scanTotalPages} • {scanTotal} kết quả</div>
                  <div className="flex items-center gap-1">
                    <button onClick={() => setScanPage(Math.max(1, scanPage - 1))} disabled={scanPage <= 1} className="w-8 h-8 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center text-white/55 disabled:opacity-20"><i className="bi bi-chevron-left text-xs"></i></button>
                    <button onClick={() => setScanPage(Math.min(scanTotalPages, scanPage + 1))} disabled={scanPage >= scanTotalPages} className="w-8 h-8 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center text-white/55 disabled:opacity-20"><i className="bi bi-chevron-right text-xs"></i></button>
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'reports' && (
            <div className="space-y-4">
              {reports.map((r) => (
                <div key={r.id} className="rounded-2xl border border-white/10 bg-white/[0.02] p-6 flex flex-col sm:flex-row justify-between items-center gap-6">
                  <div className="flex items-center gap-6">
                    <div className="w-14 h-14 rounded-2xl bg-white/5 flex items-center justify-center text-2xl text-white/35"><i className="bi bi-telephone"></i></div>
                    <div>
                      <div className="text-xs font-black text-white uppercase tracking-widest">{r.target_type}: {r.target_value}</div>
                      <div className="text-[10px] font-bold text-white/55 uppercase tracking-widest mt-1">{r.scam_type_display} • {r.created_at ? new Date(r.created_at).toLocaleDateString('vi-VN') : ''}</div>
                    </div>
                  </div>
                  <div className={`px-6 py-2 rounded-full text-[9px] font-black uppercase tracking-[0.2em] border ${r.status === 'approved' ? 'bg-safe-500/10 text-safe-500 border-safe-500/20' : r.status === 'pending' ? 'bg-warn-500/10 text-warn-500 border-warn-500/20' : 'bg-danger-500/10 text-danger-500 border-danger-500/20'}`}>
                    {r.status === 'approved' ? 'XÁC MINH THÀNH CÔNG' : r.status === 'pending' ? 'ĐANG XỬ LÝ' : 'TỪ CHỐI'}
                  </div>
                </div>
              ))}
              {reports.length === 0 && (
                <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-20 text-center opacity-20 space-y-4">
                  <i className="bi bi-megaphone text-6xl"></i>
                  <p className="text-xs font-black uppercase tracking-widest">Bạn chưa gửi báo cáo nào</p>
                </div>
              )}
            </div>
          )}

          {activeTab === 'alerts' && (
            <div className="space-y-4">
              {alerts.map((alert) => (
                <div key={alert.id} className="rounded-2xl border border-white/10 bg-white/[0.02] p-6 flex items-center justify-between">
                  <div className="flex items-center gap-6">
                    <div className="w-12 h-12 rounded-2xl bg-warn-500/20 text-warn-500 flex items-center justify-center text-xl"><i className="bi bi-bell-fill"></i></div>
                    <div>
                      <div className="text-xs font-black text-white uppercase tracking-widest">{alert.target_type}: {alert.target_value}</div>
                      <div className="text-[10px] font-bold text-white/55 uppercase tracking-widest mt-1">Mức Độ: {alert.risk_level} • {alert.created_at ? new Date(alert.created_at).toLocaleDateString('vi-VN') : ''}</div>
                    </div>
                  </div>
                  <i className="bi bi-bookmark-fill text-white/20"></i>
                </div>
              ))}
              {alerts.length === 0 && (
                <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-20 text-center opacity-20 space-y-4">
                  <i className="bi bi-bell-slash text-6xl"></i>
                  <p className="text-xs font-black uppercase tracking-widest">Không có cảnh báo đã lưu</p>
                </div>
              )}
            </div>
          )}

          {activeTab === 'api_keys' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="rounded-2xl border border-brand-500/20 bg-brand-500/[0.03] p-6 space-y-2">
                  <span className="text-[10px] font-black uppercase tracking-widest text-brand-400">Hạn Mức Hôm Nay</span>
                  <div className="text-2xl font-black text-white">{todayTotal} / {dailyQuota} req</div>
                  <div className="w-full bg-white/10 rounded-full h-2 overflow-hidden">
                    <div className="bg-gradient-to-r from-brand-400 to-brand2-500 h-2 rounded-full transition-all duration-500" style={{ width: `${Math.min(100, (todayTotal / Math.max(1, dailyQuota)) * 100)}%` }}></div>
                  </div>
                  <p className="text-[10px] text-white/55">Tự động làm mới vào 00:00 UTC</p>
                </div>
                <div className="rounded-2xl border border-brand2-500/20 bg-brand2-500/[0.03] p-6 space-y-2">
                  <span className="text-[10px] font-black uppercase tracking-widest text-brand2-400">Hạn Mức Tháng Này</span>
                  <div className="text-2xl font-black text-white">{monthTotal} / {monthlyQuota} req</div>
                  <div className="w-full bg-white/10 rounded-full h-2 overflow-hidden">
                    <div className="bg-gradient-to-r from-brand2-400 to-brand2-500 h-2 rounded-full transition-all duration-500" style={{ width: `${Math.min(100, (monthTotal / Math.max(1, monthlyQuota)) * 100)}%` }}></div>
                  </div>
                  <p className="text-[10px] text-white/55">Tổng tích lũy trong tháng</p>
                </div>
                <div className="rounded-2xl border border-safe-500/20 bg-safe-500/[0.03] p-6 space-y-2 flex flex-col justify-between">
                  <span className="text-[10px] font-black uppercase tracking-widest text-safe-400">Tích Hợp Chatbot</span>
                  <p className="text-xs text-white/70">Kết nối Claude Desktop, Cursor, ChatGPT qua MCP Server.</p>
                  <Link href="/mcp/" className="py-2 px-4 text-center text-xs font-black bg-brand-400 text-black hover:bg-brand-300 uppercase tracking-widest rounded-xl"><i className="bi bi-book mr-1"></i> Xem Hướng Dẫn /mcp/</Link>
                </div>
              </div>

              <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-6 space-y-6">
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-white/10 pb-4">
                  <div>
                    <h3 className="text-base font-black text-white uppercase tracking-wider">Danh Sách API Keys Của Bạn</h3>
                    <p className="text-xs text-white/60">Dùng để kết nối với MCP Server hoặc các phần mềm của bên thứ ba.</p>
                  </div>
                  <button onClick={() => setShowCreateModal(true)} className="py-2.5 px-5 text-xs font-black bg-brand-400 text-black hover:bg-brand-300 uppercase tracking-widest rounded-xl flex items-center gap-1.5">
                    <i className="bi bi-plus-circle-fill"></i> Tạo API Key Mới
                  </button>
                </div>
                {loadingKeys ? (
                  <Spinner />
                ) : apiKeys.length === 0 ? (
                  <div className="p-16 text-center space-y-4">
                    <div className="w-16 h-16 rounded-3xl bg-brand-500/10 text-brand-400 flex items-center justify-center mx-auto text-2xl"><i className="bi bi-key-fill"></i></div>
                    <h4 className="text-sm font-bold text-white">Chưa có API Key nào</h4>
                    <p className="text-xs text-white/55 max-w-md mx-auto">Tạo khóa đầu tiên để bắt đầu kết nối ShieldCall VN với Claude Desktop, Cursor hoặc ChatGPT của bạn.</p>
                    <button onClick={() => setShowCreateModal(true)} className="py-2.5 px-6 text-xs font-black bg-brand-400 text-black hover:bg-brand-300 uppercase tracking-widest rounded-xl">Tạo Khóa Ngay</button>
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead className="bg-white/5 text-white/55 uppercase tracking-wider text-[10px]">
                        <tr><th className="p-3">Tên Khóa</th><th className="p-3">Tiền Tố</th><th className="p-3">Hôm Nay</th><th className="p-3">Trạng Thái</th><th className="p-3 text-right">Thao Tác</th></tr>
                      </thead>
                      <tbody className="divide-y divide-white/5">
                        {apiKeys.map((k) => (
                          <tr key={k.id} className="hover:bg-white/[0.02] font-mono">
                            <td className="p-3 font-sans font-bold text-white">{k.name}</td>
                            <td className="p-3 text-brand-300 font-bold">{k.prefix}...</td>
                            <td className="p-3 font-sans text-white/80">{k.requests_today} / {k.daily_quota} req</td>
                            <td className="p-3">
                              <button onClick={() => toggleKey(k)} className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold transition-colors ${k.is_active ? 'bg-safe-500/15 text-safe-400' : 'bg-danger-500/15 text-danger-400'}`}>
                                <span className={`w-1.5 h-1.5 rounded-full ${k.is_active ? 'bg-safe-400' : 'bg-danger-400'}`}></span>
                                <span>{k.is_active ? 'Hoạt động' : 'Tạm dừng'}</span>
                              </button>
                            </td>
                            <td className="p-3 text-right space-x-2 font-sans">
                              <button onClick={() => regenerateKey(k)} title="Tạo lại mã bí mật" className="p-1.5 text-white/60 hover:text-brand-400 transition-colors"><i className="bi bi-arrow-repeat"></i></button>
                              <button onClick={() => deleteKey(k)} title="Xóa vĩnh viễn khóa" className="p-1.5 text-white/60 hover:text-danger-400 transition-colors"><i className="bi bi-trash"></i></button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
          <div className="rounded-2xl border border-brand-500/30 bg-[var(--sc-panel)] max-w-md w-full p-6 space-y-5">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <h3 className="text-base font-black text-white uppercase tracking-wider flex items-center gap-2"><i className="bi bi-key-fill text-brand-400"></i> Tạo API Key Mới</h3>
              <button onClick={() => setShowCreateModal(false)} className="text-white/55 hover:text-white"><i className="bi bi-x-lg"></i></button>
            </div>
            <input type="text" value={newKeyName} onChange={(e) => setNewKeyName(e.target.value)} placeholder="Ví dụ: Claude Desktop Laptop, Cursor AI..."
              className="w-full bg-white/5 border border-white/15 rounded-xl px-3.5 py-2.5 text-xs text-white placeholder-white/20 focus:outline-none focus:border-brand-400" />
            <div className="p-3 bg-brand-500/10 border border-brand-500/20 rounded-xl text-xs text-brand-300">
              <p className="text-white/70">Khóa mới sẽ được cấp <strong>500 requests/ngày</strong> và giới hạn 60 requests/phút hoàn toàn miễn phí.</p>
            </div>
            <div className="flex justify-end gap-3 pt-2">
              <button onClick={() => setShowCreateModal(false)} className="py-2 px-4 text-xs text-white/60 hover:text-white">Hủy bỏ</button>
              <button onClick={submitCreateKey} disabled={submittingKey} className="py-2 px-5 text-xs font-black bg-brand-400 text-black hover:bg-brand-300 uppercase tracking-widest rounded-xl disabled:opacity-50">
                {submittingKey ? 'Đang tạo...' : 'Tạo Khóa'}
              </button>
            </div>
          </div>
        </div>
      )}

      {createdRawKey && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md">
          <div className="rounded-2xl border border-brand-400/50 bg-[var(--sc-panel)] max-w-lg w-full p-6 space-y-5">
            <h3 className="text-base font-black text-white">Khóa API Đã Được Tạo Thành Công!</h3>
            <div className="p-4 rounded-xl bg-danger-500/10 border border-danger-500/30 text-xs text-danger-300">
              Mã khóa đầy đủ này sẽ <strong>chỉ hiển thị duy nhất một lần này</strong>. Hãy lưu ngay lập tức.
            </div>
            <div className="flex items-center gap-2">
              <input type="text" readOnly value={createdRawKey} className="w-full bg-black/80 border border-brand-400/40 rounded-xl px-3.5 py-2.5 text-xs font-mono text-brand-300 focus:outline-none" />
              <button onClick={() => { navigator.clipboard?.writeText(createdRawKey); setCopiedKey(true); setTimeout(() => setCopiedKey(false), 2000); }}
                className="shrink-0 py-2.5 px-4 text-xs font-black bg-brand-400 text-black hover:bg-brand-300 rounded-xl">
                {copiedKey ? 'Đã chép!' : 'Sao chép'}
              </button>
            </div>
            <div className="flex items-center justify-end pt-3 border-t border-white/10">
              <button onClick={() => setCreatedRawKey(null)} className="py-2 px-5 text-xs font-black bg-white/10 text-white hover:bg-white/20 rounded-xl">Đã Lưu & Đóng</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
