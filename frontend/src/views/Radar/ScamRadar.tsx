'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Filler,
  Tooltip,
  Legend,
} from 'chart.js';
import type { ChartData, ChartOptions } from 'chart.js';
import { Line } from 'react-chartjs-2';
import { api } from '../../lib/api';

/* Port từ PKV/templates/ScamRadar/scam_radar.html — tái tạo 1-1 markup/class/
 * text/icon. Alpine.data('scamRadar') (chart Chart.js + polling 5s + filter/
 * timeRange + goToScan) đã chuyển sang React hooks/handler. Giữ nguyên API:
 * GET /trends/radar-stats/?filter=&timeRange=. */

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Filler, Tooltip, Legend);

/* CSS port từ {% block head_extra %} của template gốc. */
const RADAR_CSS = `
@keyframes radar-sweep { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
@keyframes pulse-ring { 0% { transform: scale(0.5); opacity: 0.8; } 100% { transform: scale(1.5); opacity: 0; } }
@keyframes threat-glow { 0%, 100% { box-shadow: 0 0 20px rgba(239,68,68,0.2); } 50% { box-shadow: 0 0 40px rgba(239,68,68,0.4); } }
.radar-sweep { animation: radar-sweep 4s linear infinite; }
.pulse-ring { animation: pulse-ring 2s ease-out infinite; }
.threat-glow { animation: threat-glow 2s ease-in-out infinite; }
.stat-value { transition: all 0.6s cubic-bezier(0.16, 1, 0.3, 1); }
.scan-card { transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1); }
.scan-card:hover { transform: translateY(-4px) scale(1.02); }
.live-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--sc-danger-500); animation: pulse-ring 1.5s ease-out infinite; }
.threat-bar { height: 6px; border-radius: 3px; transition: width 0.8s cubic-bezier(0.16, 1, 0.3, 1); }
`;

interface HotItem {
  target_type: string;
  masked?: string;
  target_value?: string;
  count: number;
  label?: string;
  source?: string;
}

interface RecentReport {
  id: string;
  target_value: string;
  target_type: string;
  target_type_display?: string;
  scam_type_display?: string;
  severity?: string;
  severity_display?: string;
  created_at_display?: string;
  source?: string;
}

interface TrendDataset {
  label: string;
  data: number[];
  borderColor: string;
}

interface RadarStats {
  reports_this_week?: number;
  pct_change?: number;
  new_phones?: number;
  phishing_domains?: number;
  hot_phones?: HotItem[];
  recent_reports?: RecentReport[];
  trend_data?: { labels?: string[]; datasets?: TrendDataset[] };
}

const FILTERS = [
  { v: 'all', l: 'Tất cả', i: 'bi-globe2' },
  { v: 'phone', l: 'SĐT', i: 'bi-telephone' },
  { v: 'bank', l: 'Ngân hàng', i: 'bi-bank' },
  { v: 'phishing', l: 'Phishing', i: 'bi-bug' },
];

const RANGES = [
  { v: '24h', l: '24h' },
  { v: '7d', l: '7 Ngày' },
  { v: '30d', l: '30 Ngày' },
  { v: '1y', l: '1 Năm' },
];

const QUICK_SCANS = [
  { to: '/scan/phone/', icon: 'bi-telephone-fill', text: 'text-safe-400', iconBg: 'bg-safe-500/10 border-safe-500/15', hoverBg: 'group-hover:bg-safe-500/20', hoverText: 'group-hover:text-safe-400', l: 'Điện thoại' },
  { to: '/scan/website/', icon: 'bi-globe', text: 'text-brand-400', iconBg: 'bg-brand-500/10 border-brand-500/15', hoverBg: 'group-hover:bg-brand-500/20', hoverText: 'group-hover:text-brand-400', l: 'Website' },
  { to: '/scan/bank/', icon: 'bi-bank', text: 'text-warn-400', iconBg: 'bg-warn-500/10 border-warn-500/15', hoverBg: 'group-hover:bg-warn-500/20', hoverText: 'group-hover:text-warn-400', l: 'Ngân hàng' },
  { to: '/scan/email/', icon: 'bi-envelope-fill', text: 'text-brand2-400', iconBg: 'bg-brand2-500/10 border-brand2-500/15', hoverBg: 'group-hover:bg-brand2-500/20', hoverText: 'group-hover:text-brand2-400', l: 'Email' },
  { to: '/scan/message/', icon: 'bi-chat-dots-fill', text: 'text-brand2-400', iconBg: 'bg-brand2-500/10 border-brand2-500/15', hoverBg: 'group-hover:bg-brand2-500/20', hoverText: 'group-hover:text-brand2-400', l: 'Tin nhắn' },
];

const DB_LINKS = [
  { to: '/scam-radar/list/phones/', icon: 'bi-telephone-fill', bg: 'bg-safe-500/10', color: 'text-safe-400', hoverText: 'group-hover:text-safe-400', l: 'SĐT lừa đảo' },
  { to: '/scam-radar/list/accounts/', icon: 'bi-bank', bg: 'bg-warn-500/10', color: 'text-warn-400', hoverText: 'group-hover:text-warn-400', l: 'TK ngân hàng' },
  { to: '/scam-radar/list/domains/', icon: 'bi-globe', bg: 'bg-brand2-500/10', color: 'text-brand2-400', hoverText: 'group-hover:text-brand2-400', l: 'Domain phishing' },
  { to: '/scam-radar/list/emails/', icon: 'bi-envelope-fill', bg: 'bg-brand-500/10', color: 'text-brand-400', hoverText: 'group-hover:text-brand-400', l: 'Email lừa đảo' },
];

/* Chuyển màu border của dataset sang nền alpha 0.1 (giống updateChart gốc). */
function datasetBg(color: string): string {
  try {
    if (color.includes('rgb')) {
      return color.replace(')', ', 0.1)').replace('rgb', 'rgba');
    }
    if (color.startsWith('#')) {
      const r = parseInt(color.slice(1, 3), 16);
      const g = parseInt(color.slice(3, 5), 16);
      const b = parseInt(color.slice(5, 7), 16);
      return `rgba(${r}, ${g}, ${b}, 0.1)`;
    }
  } catch {
    /* fall through */
  }
  return 'rgba(255, 255, 255, 0.1)';
}

const chartOptions: ChartOptions<'line'> = {
  responsive: true,
  maintainAspectRatio: false,
  animation: { duration: 1000, easing: 'easeOutQuart' },
  interaction: { mode: 'index', intersect: false },
  plugins: {
    legend: { display: false },
    tooltip: {
      backgroundColor: 'rgba(15, 23, 42, 0.9)',
      titleColor: 'var(--sc-white)',
      bodyColor: 'var(--sc-slate-300)',
      borderColor: 'rgba(255, 255, 255, 0.1)',
      borderWidth: 1,
      padding: 12,
      cornerRadius: 12,
      displayColors: true,
    },
  },
  scales: {
    x: { ticks: { color: 'rgba(255,255,255,0.4)', font: { size: 10 } }, grid: { display: false } },
    y: { ticks: { color: 'rgba(255,255,255,0.4)', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true },
  },
};

const SCAN_TYPE_MAP: Record<string, string> = {
  phone: '/scan/phone/',
  domain: '/scan/website/',
  account: '/scan/bank/',
  email: '/scan/email/',
  message: '/scan/message/',
  qr: '/scan/qr/',
};

export default function ScamRadar() {
  const router = useRouter();
  const [filter, setFilter] = useState('all');
  const [timeRange, setTimeRange] = useState('7d');
  const [stats, setStats] = useState<RadarStats>({ hot_phones: [], recent_reports: [] });

  useEffect(() => {
    let alive = true;
    const fetchStats = () => {
      const params = new URLSearchParams({ filter, timeRange });
      api
        .get<RadarStats>(`/trends/radar-stats/?${params.toString()}`)
        .then((d) => {
          if (alive && d && !(d as { error?: string }).error) {
            setStats(d);
          }
        })
        .catch(() => {});
    };
    fetchStats();
    const t = setInterval(fetchStats, 5000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [filter, timeRange]);

  const pct = Number(stats.pct_change || 0);
  const hot = stats.hot_phones || [];
  const recent = stats.recent_reports || [];

  const trend = stats.trend_data;
  const chartData: ChartData<'line'> = {
    labels: trend?.labels ?? [],
    datasets: (trend?.datasets ?? []).map((ds) => {
      const baseColor = ds.borderColor || 'var(--sc-brand-500)';
      return {
        label: ds.label || 'Reports',
        data: ds.data || [],
        borderColor: baseColor,
        backgroundColor: datasetBg(baseColor),
        borderWidth: 3,
        pointBackgroundColor: 'var(--sc-slate-900)',
        pointBorderColor: baseColor,
        pointBorderWidth: 2,
        pointRadius: 4,
        pointHoverRadius: 6,
        tension: 0.4,
        fill: true,
      };
    }),
  };

  const goToScan = (report: RecentReport) => {
    const parts = (report.id || '').split('-');
    const type = parts[0];
    const id = parts.slice(1).join('-');
    if (type === 'scan' && id) {
      router.push(`/scan/status/${id}/`);
      return;
    }
    router.push(SCAN_TYPE_MAP[report.target_type] || '/scan/lookup/');
  };

  return (
    <>
      <div className="animate-fadein max-w-6xl mx-auto space-y-8 pt-12 sm:pt-16 pb-20 px-4">
        {/* Hero Section with Radar Animation */}
        <div className="relative overflow-hidden rounded-[2rem] bg-gradient-to-br from-danger-950/30 via-black/40 to-brand-950/30 border border-white/5 p-8 md:p-12">
          {/* Radar BG */}
          <div className="absolute top-1/2 right-8 -translate-y-1/2 w-48 h-48 opacity-10 hidden md:block">
            <div className="absolute inset-0 rounded-full border-2 border-danger-500/40"></div>
            <div className="absolute inset-4 rounded-full border border-danger-500/30"></div>
            <div className="absolute inset-8 rounded-full border border-danger-500/20"></div>
            <div className="absolute top-1/2 left-1/2 w-1 h-1/2 origin-bottom -translate-x-1/2 -translate-y-full radar-sweep">
              <div className="w-full h-full bg-gradient-to-t from-danger-500/60 to-transparent rounded-full"></div>
            </div>
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-3 h-3 bg-danger-500 rounded-full pulse-ring"></div>
          </div>

          <div className="relative z-10 max-w-2xl space-y-4">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-2xl bg-danger-500/15 border border-danger-500/20 flex items-center justify-center">
                <i className="bi bi-radar text-2xl text-danger-400"></i>
              </div>
              <div className="flex items-center gap-2">
                <div className="live-dot"></div>
                <span className="text-[9px] font-black text-danger-400 uppercase tracking-[0.3em]">LIVE MONITORING</span>
              </div>
            </div>
            <h1 className="text-3xl md:text-4xl font-black text-white leading-tight">
              Scam Radar <span className="text-danger-400">Việt Nam</span>
            </h1>
            <p className="text-white/55 text-sm leading-relaxed max-w-lg">
              Giám sát &amp; phân tích xu hướng lừa đảo thời gian thực. Dữ liệu từ AI Scan &amp; báo cáo cộng đồng đã xác minh.
            </p>
            <div className="flex flex-wrap gap-3 pt-2">
              <Link href="/scan/lookup/" className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-brand-400 text-black text-xs font-black uppercase tracking-widest hover:bg-white transition-all shadow-lg shadow-brand-400/20">
                <i className="bi bi-search"></i> Tra cứu hệ thống
              </Link>
              <Link href="/report/" className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-white/5 border border-white/10 text-white/60 text-xs font-black uppercase tracking-widest hover:bg-white/10 transition-all">
                <i className="bi bi-flag"></i> Gửi báo cáo
              </Link>
            </div>
          </div>
        </div>

        {/* Quick Scan Cards */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {QUICK_SCANS.map((s) => (
            <Link key={s.to} href={s.to} className="scan-card liquid-card p-5 text-center space-y-3 group">
              <div className={`w-12 h-12 mx-auto rounded-2xl border flex items-center justify-center transition ${s.iconBg} ${s.hoverBg}`}>
                <i className={`bi ${s.icon} text-xl ${s.text}`}></i>
              </div>
              <div className={`text-[10px] font-black text-white/60 uppercase tracking-widest transition ${s.hoverText}`}>{s.l}</div>
            </Link>
          ))}
        </div>

        {/* Filters */}
        <div className="flex flex-col md:flex-row justify-between items-center gap-4">
          <div className="flex flex-wrap gap-1.5 p-1.5 bg-white/[0.03] border border-white/5 rounded-2xl">
            {FILTERS.map((f) => (
              <button
                key={f.v}
                type="button"
                onClick={() => setFilter(f.v)}
                className={`flex items-center gap-1.5 px-4 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all ${filter === f.v ? 'bg-white/10 text-white shadow-sm' : 'text-white/45 hover:text-white/60'}`}
              >
                <i className={`bi ${f.i} text-xs`}></i>
                <span>{f.l}</span>
              </button>
            ))}
          </div>
          <div className="flex gap-1.5 p-1.5 bg-white/[0.03] border border-white/5 rounded-2xl">
            {RANGES.map((t) => (
              <button
                key={t.v}
                type="button"
                onClick={() => setTimeRange(t.v)}
                className={`px-4 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all ${timeRange === t.v ? 'bg-white/10 text-white shadow-sm' : 'text-white/45 hover:text-white/60'}`}
              >
                <span>{t.l}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Stats Grid - bigger, more colorful */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="liquid-card relative overflow-hidden p-6 space-y-3 group hover:border-danger-500/20 transition-all">
            <div className="absolute top-0 right-0 w-20 h-20 bg-danger-500/5 rounded-full -translate-y-1/2 translate-x-1/2"></div>
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-2xl bg-danger-500/10 flex items-center justify-center text-danger-400 group-hover:scale-110 transition-transform">
                <i className="bi bi-shield-exclamation text-lg"></i>
              </div>
              <div className="text-[9px] font-black text-white/35 uppercase tracking-[0.2em]">Trường hợp</div>
            </div>
            <div className="text-4xl font-black text-white stat-value">{stats.reports_this_week || '0'}</div>
            <div className="flex items-center gap-1.5">
              <span className={`text-[9px] font-black px-2 py-0.5 rounded-full ${pct >= 0 ? 'bg-danger-500/10 text-danger-400' : 'bg-safe-500/10 text-safe-400'}`}>
                {(pct >= 0 ? '↑' : '↓') + ' ' + Math.abs(pct) + '%'}
              </span>
              <span className="text-[8px] text-white/15 font-bold">so với kỳ trước</span>
            </div>
          </div>
          <div className="liquid-card relative overflow-hidden p-6 space-y-3 group hover:border-brand-500/20 transition-all">
            <div className="absolute top-0 right-0 w-20 h-20 bg-brand-500/5 rounded-full -translate-y-1/2 translate-x-1/2"></div>
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-2xl bg-brand-500/10 flex items-center justify-center text-brand-400 group-hover:scale-110 transition-transform">
                <i className="bi bi-graph-up-arrow text-lg"></i>
              </div>
              <div className="text-[9px] font-black text-white/35 uppercase tracking-[0.2em]">Tăng trưởng</div>
            </div>
            <div className={`text-4xl font-black stat-value ${pct >= 0 ? 'text-danger-400' : 'text-safe-400'}`}>
              {(pct >= 0 ? '+' : '') + pct + '%'}
            </div>
            <div className="w-full bg-white/5 rounded-full h-1.5 overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-1000 ${pct >= 0 ? 'bg-danger-400' : 'bg-safe-400'}`}
                style={{ width: `${Math.min(100, Math.abs(pct))}%` }}
              ></div>
            </div>
          </div>
          <div className="liquid-card relative overflow-hidden p-6 space-y-3 group hover:border-warn-500/20 transition-all">
            <div className="absolute top-0 right-0 w-20 h-20 bg-warn-500/5 rounded-full -translate-y-1/2 translate-x-1/2"></div>
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-2xl bg-warn-500/10 flex items-center justify-center text-warn-400 group-hover:scale-110 transition-transform">
                <i className="bi bi-telephone-plus text-lg"></i>
              </div>
              <div className="text-[9px] font-black text-white/35 uppercase tracking-[0.2em]">SĐT lừa đảo</div>
            </div>
            <div className="text-4xl font-black text-white stat-value">{stats.new_phones || '0'}</div>
            <Link href="/scam-radar/list/phones/" className="text-[8px] font-black text-warn-400/50 uppercase tracking-widest hover:text-warn-400 transition">
              Xem danh sách →
            </Link>
          </div>
          <div className="liquid-card relative overflow-hidden p-6 space-y-3 group hover:border-brand2-500/20 transition-all">
            <div className="absolute top-0 right-0 w-20 h-20 bg-brand2-500/5 rounded-full -translate-y-1/2 translate-x-1/2"></div>
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-2xl bg-brand2-500/10 flex items-center justify-center text-brand2-400 group-hover:scale-110 transition-transform">
                <i className="bi bi-bug text-lg"></i>
              </div>
              <div className="text-[9px] font-black text-white/35 uppercase tracking-[0.2em]">Phishing/Domain</div>
            </div>
            <div className="text-4xl font-black text-white stat-value">{stats.phishing_domains || '0'}</div>
            <Link href="/scam-radar/list/domains/" className="text-[8px] font-black text-brand2-400/50 uppercase tracking-widest hover:text-brand2-400 transition">
              Xem danh sách →
            </Link>
          </div>
        </div>

        {/* Chart + Hot Numbers Row */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main Chart */}
          <div className="lg:col-span-2 liquid-card p-8 space-y-6">
            <div className="flex justify-between items-center">
              <h3 className="text-xs font-black text-white uppercase tracking-widest flex items-center gap-2">
                <i className="bi bi-graph-up text-brand-400"></i> Xu hướng (AI Scan + Báo cáo)
              </h3>
              <div className="flex items-center gap-4 text-[8px] font-bold text-white/45">
                <span className="flex items-center gap-1"><span className="w-3 h-0.5 rounded bg-brand-400 inline-block"></span> AI Scan</span>
                <span className="flex items-center gap-1"><span className="w-3 h-0.5 rounded bg-warn-400 inline-block"></span> Báo cáo</span>
              </div>
            </div>
            <div className="h-[300px] w-full relative">
              <Line data={chartData} options={chartOptions} />
            </div>
          </div>

          {/* Hot Numbers */}
          <div className="liquid-card p-6 space-y-5">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-black text-white uppercase tracking-widest flex items-center gap-2">
                <i className="bi bi-fire text-danger-500"></i> Điểm nóng
              </h3>
              <div className="flex items-center gap-1">
                <div className="live-dot"></div>
                <span className="text-[8px] font-black text-danger-400/60 uppercase tracking-widest">Live</span>
              </div>
            </div>
            <div className="space-y-3 overflow-y-auto max-h-[310px] pr-1">
              {hot.map((hp, idx) => (
                <div key={`${hp.source}-${hp.target_type}-${idx}`} className="p-3.5 rounded-xl bg-white/[0.02] border border-white/5 flex items-center gap-3 group hover:bg-white/[0.04] hover:border-white/10 transition-all cursor-pointer">
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${hp.source === 'scan_ai' ? 'bg-brand-500/10 text-brand-400' : 'bg-warn-500/10 text-warn-400'}`}>
                    <i className={`bi text-xs ${hp.target_type === 'phone' ? 'bi-telephone-fill' : hp.target_type === 'domain' ? 'bi-globe' : 'bi-bank'}`}></i>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-black text-white/80 truncate group-hover:text-white transition">{hp.masked}</div>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className={`text-[8px] font-bold uppercase tracking-widest ${hp.source === 'scan_ai' ? 'text-brand-400/50' : 'text-warn-400/50'}`}>
                        {hp.source === 'scan_ai' ? 'AI' : 'Report'}
                      </span>
                      <span className="text-[8px] text-white/15">{hp.label}</span>
                    </div>
                  </div>
                  <div className={`px-2.5 py-1 rounded-lg text-[10px] font-black shrink-0 ${hp.count >= 50 ? 'bg-danger-500/20 text-danger-400 threat-glow' : hp.count >= 20 ? 'bg-danger-500/15 text-danger-400' : 'bg-warn-500/10 text-warn-400'}`}>
                    {hp.count}x
                  </div>
                </div>
              ))}
              {hot.length === 0 && (
                <div className="py-10 text-center">
                  <i className="bi bi-shield-check text-3xl text-white/5 block mb-2"></i>
                  <p className="text-[10px] font-black text-white/15 uppercase tracking-widest">Không phát hiện mối đe dọa</p>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Detailed Databases Quick Links */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {DB_LINKS.map((s) => (
            <Link key={s.to} href={s.to} className="scan-card liquid-card p-5 flex items-center gap-4 group">
              <div className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 ${s.bg} ${s.color}`}>
                <i className={`bi ${s.icon}`}></i>
              </div>
              <div>
                <div className={`text-xs font-black text-white/70 transition ${s.hoverText}`}>{s.l}</div>
                <div className="text-[9px] text-white/55 font-bold">Danh sách đầy đủ</div>
              </div>
              <i className={`bi bi-chevron-right text-white/20 ml-auto transition ${s.hoverText}`}></i>
            </Link>
          ))}
        </div>

        {/* Live Threat Feed */}
        <div className="liquid-card overflow-hidden">
          <div className="p-6 border-b border-white/5 flex items-center justify-between">
            <h3 className="text-xs font-black text-white uppercase tracking-widest flex items-center gap-2">
              <i className="bi bi-broadcast text-danger-400"></i> Threat Feed | Trường hợp mới nhất
            </h3>
            <div className="flex items-center gap-1.5">
              <div className="live-dot"></div>
              <span className="text-[8px] font-black text-white/35 uppercase tracking-widest">Cập nhật mỗi 5 giây</span>
            </div>
          </div>
          <div className="divide-y divide-white/[0.03]">
            {recent.map((report) => (
              <div
                key={report.id}
                onClick={() => goToScan(report)}
                className="flex items-center gap-5 px-6 py-4 hover:bg-white/[0.02] transition-all cursor-pointer group"
              >
                {/* Severity indicator */}
                <div className={`w-2 h-10 rounded-full shrink-0 ${report.severity === 'high' || report.severity === 'critical' ? 'bg-danger-500' : report.severity === 'medium' ? 'bg-warn-500' : 'bg-safe-500'}`}></div>
                {/* Source badge */}
                <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${report.source === 'scan_ai' ? 'bg-brand-500/10 text-brand-400' : 'bg-warn-500/10 text-warn-400'}`}>
                  <i className={`bi text-sm ${report.source === 'scan_ai' ? 'bi-cpu' : 'bi-person-check'}`}></i>
                </div>
                {/* Info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-black text-white/80 truncate group-hover:text-white transition">{report.target_value}</span>
                    <span className="text-[8px] font-bold px-2 py-0.5 rounded-full bg-white/5 text-white/45 uppercase tracking-widest shrink-0">{report.target_type_display}</span>
                  </div>
                  <div className="flex items-center gap-3 mt-0.5">
                    <span className="text-[9px] text-white/55">{report.scam_type_display}</span>
                    <span className="text-[9px] text-white/15">•</span>
                    <span className="text-[9px] text-white/35">{report.created_at_display}</span>
                  </div>
                </div>
                {/* Severity badge */}
                <span className={`px-3 py-1 rounded-lg border text-[9px] font-black uppercase tracking-widest shrink-0 ${report.severity === 'high' || report.severity === 'critical' ? 'bg-danger-500/10 text-danger-400 border-danger-500/20' : report.severity === 'medium' ? 'bg-warn-500/10 text-warn-400 border-warn-500/20' : 'bg-safe-500/10 text-safe-400 border-safe-500/20'}`}>
                  {report.severity_display}
                </span>
                <i className="bi bi-chevron-right text-white/20 group-hover:text-white/45 transition shrink-0"></i>
              </div>
            ))}
            {recent.length === 0 && (
              <div>
                <div className="px-6 py-16 text-center">
                  <i className="bi bi-shield-check text-4xl text-white/5 block mb-3"></i>
                  <p className="text-xs font-black text-white/15 uppercase tracking-widest">Chưa có báo cáo nào trong khoảng thời gian này</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      <style>{RADAR_CSS}</style>
    </>
  );
}
