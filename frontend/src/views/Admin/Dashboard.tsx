'use client';
import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
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
import { useAuth } from '../../components/AuthContext';
import { api } from '../../lib/api';
import { showToast } from '../../lib/ui/feedback';
import { useAdminGet } from './_shared';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Filler, Tooltip, Legend);

/* Port từ PKV/templates/Admin/dashboard.html — tái tạo 1-1 markup/class/text/icon.
 * Alpine.js (gửi broadcast + liquidSelect) và script Chart.js/polling/animateNumber
 * đã chuyển sang React hooks. */

interface DashCharts {
  labels?: string[];
  reports?: number[];
  scans?: number[];
}

interface DashStats {
  total_users?: number;
  pending_reports?: number;
  total_scans?: number;
  total_lessons?: number;
  total_posts?: number;
  pending_forum_reports?: number;
  charts?: DashCharts;
}

interface BroadcastResult {
  status?: string;
  message?: string;
  error?: string;
}

const TYPE_OPTIONS = [
  { value: 'info', label: 'Thông tin' },
  { value: 'success', label: 'Thành công' },
  { value: 'warning', label: 'Cảnh báo' },
  { value: 'error', label: 'Khẩn cấp' },
];

const chartOptions: ChartOptions<'line'> = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: { legend: { display: false } },
  scales: {
    y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: 'rgba(255,255,255,0.4)', font: { size: 10, weight: 900 } } },
    x: { grid: { display: false }, ticks: { color: 'rgba(255,255,255,0.4)', font: { size: 10, weight: 900 } } },
  },
};

/* animateNumber bản gốc: nội suy từ giá trị đang hiển thị tới giá trị mới trong 1500ms. */
function useCountUp(target: number | undefined, duration = 1500): number {
  const [value, setValue] = useState(0);
  const fromRef = useRef(0);

  useEffect(() => {
    if (target === undefined) return;
    const start = fromRef.current;
    const startTime = performance.now();
    let raf = 0;
    const step = (t: number) => {
      const progress = Math.min((t - startTime) / duration, 1);
      setValue(Math.floor(progress * (target - start) + start));
      if (progress < 1) raf = requestAnimationFrame(step);
      else fromRef.current = target;
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [target, duration]);

  return value;
}

export default function Dashboard() {
  const { user } = useAuth();
  const { data: s, error, refetch } = useAdminGet<DashStats>('/admin/stats/');

  const refetchRef = useRef(refetch);
  useEffect(() => {
    refetchRef.current = refetch;
  });
  useEffect(() => {
    const id = setInterval(() => refetchRef.current(), 5000); // 5s Polling
    return () => clearInterval(id);
  }, []);

  const users = useCountUp(s?.total_users);
  const reports = useCountUp(s?.pending_reports);
  const scans = useCountUp(s?.total_scans);
  const connected = !error;

  const meta = user as unknown as { is_superuser?: boolean; profile?: { is_super_admin?: boolean } } | null;
  const isSuperAdmin = Boolean(meta?.is_superuser || meta?.profile?.is_super_admin);

  const [title, setTitle] = useState('');
  const [message, setMessage] = useState('');
  const [ntype, setNtype] = useState('info');
  const [url, setUrl] = useState('');
  const [sending, setSending] = useState(false);
  const [sent, setSent] = useState(false);
  const [typeOpen, setTypeOpen] = useState(false);
  const typeRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onDocClick = (e: Event) => {
      if (typeOpen && typeRef.current && !typeRef.current.contains(e.target as Node)) setTypeOpen(false);
    };
    document.addEventListener('click', onDocClick);
    return () => document.removeEventListener('click', onDocClick);
  }, [typeOpen]);

  const typeLabel = TYPE_OPTIONS.find((o) => o.value === ntype)?.label ?? 'Chọn loại';

  const send = async () => {
    if (!title.trim() || !message.trim()) {
      showToast('Tiêu đề và nội dung là bắt buộc', 'warning');
      return;
    }
    setSending(true);
    try {
      const data = await api.post<BroadcastResult>('/admin/notifications/broadcast/', {
        title,
        message,
        notification_type: ntype,
        url,
      });
      showToast(data.message || 'Đã gửi thông báo!', 'success');
      setTitle('');
      setMessage('');
      setUrl('');
      setSent(true);
      setTimeout(() => setSent(false), 3000);
    } catch (e) {
      showToast(e instanceof Error ? e.message : 'Lỗi gửi thông báo', 'error');
    } finally {
      setSending(false);
    }
  };

  const labels = s?.charts?.labels ?? [];
  const reportsChartData: ChartData<'line'> = {
    labels,
    datasets: [
      {
        label: 'Báo cáo',
        data: s?.charts?.reports ?? [],
        borderColor: 'var(--sc-brand-500)',
        backgroundColor: 'var(--sc-brand-500-20)',
        borderWidth: 3,
        fill: true,
        tension: 0.4,
        pointRadius: 4,
        pointBackgroundColor: 'var(--sc-brand-500)',
        pointBorderColor: 'var(--sc-white)',
        pointHoverRadius: 6,
      },
    ],
  };
  const scansChartData: ChartData<'line'> = {
    labels,
    datasets: [
      {
        label: 'Lượt quét',
        data: s?.charts?.scans ?? [],
        borderColor: 'var(--sc-brand-500)',
        backgroundColor: 'var(--sc-brand-500-20)',
        borderWidth: 3,
        fill: true,
        tension: 0.4,
        pointRadius: 4,
        pointBackgroundColor: 'var(--sc-brand-500)',
        pointBorderColor: 'var(--sc-white)',
        pointHoverRadius: 6,
      },
    ],
  };

  return (
    <>
      <div className="container mx-auto px-4 py-8 mt-16 max-w-7xl">
        {/* Header with Pulse Indicator */}
        <div className="flex flex-col md:flex-row justify-between items-center mb-10 gap-6">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-2 w-2 rounded-full bg-brand-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-brand-500"></span>
              </span>
              <span className="text-[10px] uppercase font-black tracking-[0.2em] text-brand-500/60">Hệ Thống Đang Giám Sát Real-time</span>
            </div>
            <h1 className="text-4xl font-black bg-gradient-to-r from-brand-400 via-brand-400 to-brand-400 bg-clip-text text-transparent tracking-tight">
              Dashboard Trung Tâm
            </h1>
          </div>
          <div className="flex items-center gap-4">
            <div className="px-5 py-2.5 rounded-2xl bg-white/5 border border-white/10 backdrop-blur-xl flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-brand-500/20 flex items-center justify-center text-brand-400">
                <i className="bi bi-shield-check"></i>
              </div>
              <div>
                <div className="text-[9px] font-bold text-white/45 uppercase tracking-widest leading-none">Quyền hạn</div>
                <div className="text-xs font-black text-white">{isSuperAdmin ? 'Super Admin' : 'Admin'}</div>
              </div>
            </div>
            <div
              id="connection-status"
              className={
                connected
                  ? 'px-4 py-2 rounded-xl bg-safe-500/10 border border-safe-500/20 text-[10px] font-black text-safe-400 uppercase flex items-center gap-2'
                  : 'px-4 py-2 rounded-xl bg-danger-500/10 border border-danger-500/20 text-[10px] font-black text-danger-400 uppercase flex items-center gap-2'
              }
            >
              <span className={connected ? 'w-1.5 h-1.5 rounded-full bg-safe-500' : 'w-1.5 h-1.5 rounded-full bg-danger-500 animate-pulse'}></span>
              {connected ? 'Đã kết nối' : 'Mất kết nối'}
            </div>
          </div>
        </div>

        {/* Live Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6 mb-12">
          {/* User Stats */}
          <div className="stat-card relative overflow-hidden p-6 rounded-[2rem] bg-slate-900/40 border border-white/5 backdrop-blur-xl group hover:border-brand-500/30 transition-all">
            <div className="absolute -right-4 -bottom-4 opacity-[0.03] group-hover:opacity-[0.07] transition-all group-hover:scale-110">
              <i className="bi bi-people-fill text-9xl"></i>
            </div>
            <div className="flex justify-between items-start mb-6">
              <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-brand-500 to-brand-600 flex items-center justify-center text-white shadow-lg shadow-brand-500/20">
                <i className="bi bi-people text-xl"></i>
              </div>
              <div className="text-right">
                <div className="text-[10px] font-black text-white/45 uppercase tracking-[0.1em]">Người dùng</div>
                <div className="text-4xl font-black text-white tracking-tighter" id="stat-users">{users}</div>
              </div>
            </div>
            <div className="h-1 w-full bg-white/5 rounded-full overflow-hidden">
              <div className="h-full bg-brand-500 animate-pulse-slow" style={{ width: '70%' }}></div>
            </div>
          </div>

          {/* Pending Reports */}
          <div className="stat-card relative overflow-hidden p-6 rounded-[2rem] bg-slate-900/40 border border-white/5 backdrop-blur-xl group hover:border-danger-500/30 transition-all">
            <div className="absolute -right-4 -bottom-4 opacity-[0.03] group-hover:opacity-[0.07] transition-all group-hover:scale-110">
              <i className="bi bi-exclamation-triangle-fill text-9xl"></i>
            </div>
            <div className="flex justify-between items-start mb-6">
              <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-danger-500 to-warn-600 flex items-center justify-center text-white shadow-lg shadow-danger-500/20">
                <i className="bi bi-exclamation-octagon text-xl"></i>
              </div>
              <div className="text-right">
                <div className="text-[10px] font-black text-white/45 uppercase tracking-[0.1em]">Báo cáo mới</div>
                <div className="text-4xl font-black text-white tracking-tighter" id="stat-reports">{reports}</div>
              </div>
            </div>
            <div className="h-1 w-full bg-white/5 rounded-full overflow-hidden">
              <div className="h-full bg-danger-500" style={{ width: '45%' }}></div>
            </div>
          </div>

          {/* Scan Activity */}
          <div className="stat-card relative overflow-hidden p-6 rounded-[2rem] bg-slate-900/40 border border-white/5 backdrop-blur-xl group hover:border-brand-500/30 transition-all">
            <div className="absolute -right-4 -bottom-4 opacity-[0.03] group-hover:opacity-[0.07] transition-all group-hover:scale-110">
              <i className="bi bi-search text-9xl"></i>
            </div>
            <div className="flex justify-between items-start mb-6">
              <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-brand-500 to-brand-500 flex items-center justify-center text-white shadow-lg shadow-brand-500/20">
                <i className="bi bi-lightning-charge text-xl"></i>
              </div>
              <div className="text-right">
                <div className="text-[10px] font-black text-white/45 uppercase tracking-[0.1em]">Lượt Quét AI</div>
                <div className="text-4xl font-black text-white tracking-tighter" id="stat-scans">{scans}</div>
              </div>
            </div>
            <div className="h-1 w-full bg-white/5 rounded-full overflow-hidden">
              <div className="h-full bg-brand-500" style={{ width: '85%' }}></div>
            </div>
          </div>

          {/* Content Stats */}
          <div className="stat-card relative overflow-hidden p-6 rounded-[2rem] bg-slate-900/40 border border-white/5 backdrop-blur-xl group hover:border-brand2-500/30 transition-all">
            <div className="absolute -right-4 -bottom-4 opacity-[0.03] group-hover:opacity-[0.07] transition-all group-hover:scale-110">
              <i className="bi bi-journal-text text-9xl"></i>
            </div>
            <div className="flex justify-between items-start mb-6">
              <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-brand2-500 to-brand-600 flex items-center justify-center text-white shadow-lg shadow-brand2-500/20">
                <i className="bi bi-journal-code text-xl"></i>
              </div>
              <div className="text-right">
                <div className="text-[10px] font-black text-white/45 uppercase tracking-[0.1em]">Nội Dung</div>
                <div className="text-4xl font-black text-white tracking-tighter" id="stat-content">{s?.total_lessons ?? '-'}</div>
              </div>
            </div>
            <div className="h-1 w-full bg-white/5 rounded-full overflow-hidden">
              <div className="h-full bg-brand2-500" style={{ width: '60%' }}></div>
            </div>
          </div>

          {/* Forum Stats */}
          <div className="stat-card relative overflow-hidden p-6 rounded-[2rem] bg-slate-900/40 border border-white/5 backdrop-blur-xl group hover:border-warn-500/30 transition-all">
            <div className="absolute -right-4 -bottom-4 opacity-[0.03] group-hover:opacity-[0.07] transition-all group-hover:scale-110">
              <i className="bi bi-chat-square-dots-fill text-9xl"></i>
            </div>
            <div className="flex justify-between items-start mb-6">
              <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-warn-500 to-warn-600 flex items-center justify-center text-white shadow-lg shadow-warn-500/20">
                <i className="bi bi-chat-dots text-xl"></i>
              </div>
              <div className="text-right">
                <div className="text-[10px] font-black text-white/45 uppercase tracking-[0.1em]">Diễn Đàn</div>
                <div className="text-4xl font-black text-white tracking-tighter">{s?.total_posts ?? '-'}</div>
              </div>
            </div>
            <div className="flex items-center justify-between text-[10px] mb-2">
              <span className="text-white/45 font-bold">Báo cáo chờ duyệt</span>
              <span className="text-warn-400 font-black">{s?.pending_forum_reports ?? '-'}</span>
            </div>
            <div className="h-1 w-full bg-white/5 rounded-full overflow-hidden">
              <div className="h-full bg-warn-500" style={{ width: '50%' }}></div>
            </div>
          </div>
        </div>

        {/* Charts Section */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-12">
          <div className="p-8 rounded-[2.5rem] bg-slate-900/40 border border-white/5 backdrop-blur-2xl">
            <div className="flex items-center justify-between mb-8">
              <div>
                <h3 className="text-xl font-black text-white tracking-tight">Xu hướng báo cáo</h3>
                <p className="text-[10px] font-bold text-white/35 uppercase tracking-widest mt-1">Dữ liệu 7 ngày gần nhất</p>
              </div>
              <div className="w-10 h-10 rounded-xl bg-white/5 flex items-center justify-center text-white/55">
                <i className="bi bi-graph-up"></i>
              </div>
            </div>
            <div className="h-[300px] w-full">
              <Line data={reportsChartData} options={chartOptions} />
            </div>
          </div>

          <div className="p-8 rounded-[2.5rem] bg-slate-900/40 border border-white/5 backdrop-blur-2xl">
            <div className="flex items-center justify-between mb-8">
              <div>
                <h3 className="text-xl font-black text-white tracking-tight">Hoạt động Quét (Scan)</h3>
                <p className="text-[10px] font-bold text-white/35 uppercase tracking-widest mt-1">Lưu lượng truy vấn AI</p>
              </div>
              <div className="w-10 h-10 rounded-xl bg-white/5 flex items-center justify-center text-white/55">
                <i className="bi bi-activity"></i>
              </div>
            </div>
            <div className="h-[300px] w-full">
              <Line data={scansChartData} options={chartOptions} />
            </div>
          </div>
        </div>

        {/* Management Navigation */}
        <h2 className="text-xs font-black text-white/35 uppercase tracking-[0.3em] mb-8 text-center italic">Trung Tâm Điều Hành ShieldCall</h2>

        {/* Broadcast Notification Section */}
        <div className="mb-12 p-1 rounded-[2.5rem] bg-gradient-to-br from-brand-500/20 to-brand2-500/10">
          <div className="bg-slate-950/80 rounded-[2.3rem] p-8 backdrop-blur-3xl">
            <div className="flex items-center gap-4 mb-6">
              <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-brand-500 to-brand2-600 flex items-center justify-center text-white shadow-lg shadow-brand-500/20">
                <i className="bi bi-megaphone-fill text-xl"></i>
              </div>
              <div>
                <h3 className="text-lg font-black text-white tracking-tight">Gửi Thông Báo Toàn Hệ Thống</h3>
                <p className="text-[10px] font-bold text-white/35 uppercase tracking-widest">Broadcast Notification</p>
              </div>
              {sent && (
                <div className="ml-auto px-4 py-2 rounded-xl bg-safe-500/10 border border-safe-500/20 text-safe-400 text-[10px] font-black">
                  <i className="bi bi-check-circle-fill mr-1"></i> Đã gửi!
                </div>
              )}
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <div>
                <label className="text-[10px] font-black text-white/55 uppercase tracking-widest block mb-2">Tiêu đề <span className="text-danger-400">*</span></label>
                <input
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  type="text"
                  placeholder="Tiêu đề thông báo..."
                  className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white text-sm placeholder-white/20 focus:ring-2 focus:ring-brand-500/30 focus:border-brand-500/30 transition-all"
                />
              </div>
              <div className="grid grid-cols-2 gap-3 min-w-0">
                <div className="min-w-0" ref={typeRef}>
                  <label className="text-[10px] font-black text-white/55 uppercase tracking-widest block mb-2">Loại</label>
                  <div className="dropdown-container liquid-custom-select w-full">
                    <div
                      className={`liquid-select-trigger py-3 px-4 text-sm w-full min-w-0${typeOpen ? ' active' : ''}`}
                      onClick={() => setTypeOpen((o) => !o)}
                    >
                      <span className="truncate">{typeLabel}</span>
                      <i className="bi bi-chevron-down liquid-select-arrow"></i>
                    </div>
                    {typeOpen && (
                      <div className="liquid-select-dropdown">
                        {TYPE_OPTIONS.map((option) => (
                          <div
                            key={option.value}
                            className={`liquid-select-option${ntype === option.value ? ' selected' : ''}`}
                            onClick={() => { setNtype(option.value); setTypeOpen(false); }}
                          >
                            <span>{option.label}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
                <div className="min-w-0">
                  <label className="text-[10px] font-black text-white/55 uppercase tracking-widest block mb-2">URL (tùy chọn)</label>
                  <input
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    type="text"
                    placeholder="/learn/..."
                    className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white text-sm placeholder-white/20 focus:ring-2 focus:ring-brand-500/30 transition-all"
                  />
                </div>
              </div>
            </div>
            <div className="mb-4">
              <label className="text-[10px] font-black text-white/55 uppercase tracking-widest block mb-2">Nội dung <span className="text-danger-400">*</span></label>
              <textarea
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                rows={3}
                placeholder="Nội dung thông báo gửi đến tất cả người dùng..."
                className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white text-sm placeholder-white/20 focus:ring-2 focus:ring-brand-500/30 focus:border-brand-500/30 transition-all resize-none"
              ></textarea>
            </div>
            <div className="flex items-center justify-between">
              <p className="text-[10px] text-white/35 font-bold">
                <i className="bi bi-info-circle mr-1"></i> Thông báo sẽ gửi đến tất cả người dùng qua hệ thống (Hỗ trợ soạn markdown)
              </p>
              <button
                onClick={() => void send()}
                disabled={sending || !title.trim() || !message.trim()}
                className="px-8 py-3 rounded-xl bg-gradient-to-r from-brand-500 to-brand-600 text-white font-black text-xs uppercase tracking-widest hover:scale-105 active:scale-95 transition-all shadow-lg shadow-brand-500/20 disabled:opacity-30 disabled:scale-100 flex items-center gap-2"
              >
                {!sending && (
                  <span className="flex items-center gap-2"><i className="bi bi-send-fill"></i> Gửi Thông Báo</span>
                )}
                {sending && (
                  <span className="flex items-center gap-2"><span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></span> Đang gửi...</span>
                )}
              </button>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {/* Reports */}
          <Link href="/admin-cp/reports/" className="mgmt-card group p-1 rounded-[2.5rem] bg-gradient-to-br from-brand-500/20 to-transparent hover:from-brand-500/40 transition-all duration-500">
            <div className="bg-slate-950/80 rounded-[2.3rem] p-8 h-full flex flex-col gap-5 backdrop-blur-3xl">
              <div className="flex items-center gap-5">
                <div className="w-14 h-14 rounded-2xl bg-brand-500/10 flex items-center justify-center text-brand-400 group-hover:scale-110 group-hover:bg-brand-500 group-hover:text-white transition-all shadow-xl shadow-brand-500/0 group-hover:shadow-brand-500/20">
                  <i className="bi bi-file-earmark-text text-2xl"></i>
                </div>
                <div>
                  <h4 className="text-lg font-black text-white group-hover:text-brand-400 transition-colors tracking-tight">Quản Lý Báo Cáo</h4>
                  <div className="text-[10px] font-bold text-brand-500/50 uppercase tracking-widest">Community Verification</div>
                </div>
              </div>
              <p className="text-slate-400 text-sm leading-relaxed">Phê duyệt và xác minh các báo cáo từ cộng đồng. Sử dụng AI để đánh giá mức độ rủi ro tự động.</p>
              <div className="flex justify-end pt-2">
                <div className="w-10 h-10 rounded-full border border-white/5 flex items-center justify-center text-white/35 group-hover:text-brand-400 group-hover:border-brand-500/30 transition-all">
                  <i className="bi bi-arrow-right"></i>
                </div>
              </div>
            </div>
          </Link>

          {/* Learn Content */}
          <Link href="/admin-cp/learn/" className="mgmt-card group p-1 rounded-[2.5rem] bg-gradient-to-br from-brand2-500/20 to-transparent hover:from-brand2-500/40 transition-all duration-500">
            <div className="bg-slate-950/80 rounded-[2.3rem] p-8 h-full flex flex-col gap-5 backdrop-blur-3xl">
              <div className="flex items-center gap-5">
                <div className="w-14 h-14 rounded-2xl bg-brand2-500/10 flex items-center justify-center text-brand2-400 group-hover:scale-110 group-hover:bg-brand2-500 group-hover:text-white transition-all shadow-xl shadow-brand2-500/0 group-hover:shadow-brand2-500/20">
                  <i className="bi bi-mortarboard text-2xl"></i>
                </div>
                <div>
                  <h4 className="text-lg font-black text-white group-hover:text-brand2-400 transition-colors tracking-tight">Nội Dung Đào Tạo</h4>
                  <div className="text-[10px] font-bold text-brand2-500/50 uppercase tracking-widest">Educational CMS</div>
                </div>
              </div>
              <p className="text-slate-400 text-sm leading-relaxed">Tổ chức các bài học về bảo mật. Cập nhật các kịch bản lừa đảo mới nhất cho người dùng.</p>
              <div className="flex justify-end pt-2">
                <div className="w-10 h-10 rounded-full border border-white/5 flex items-center justify-center text-white/35 group-hover:text-brand2-400 group-hover:border-brand2-500/30 transition-all">
                  <i className="bi bi-arrow-right"></i>
                </div>
              </div>
            </div>
          </Link>

          {/* RAG Brain */}
          <Link href="/admin-cp/rag/" className="mgmt-card group p-1 rounded-[2.5rem] bg-gradient-to-br from-brand-500/20 to-transparent hover:from-brand-500/40 transition-all duration-500">
            <div className="bg-slate-950/80 rounded-[2.3rem] p-8 h-full flex flex-col gap-5 backdrop-blur-3xl">
              <div className="flex items-center gap-5">
                <div className="w-14 h-14 rounded-2xl bg-brand-500/10 flex items-center justify-center text-brand-400 group-hover:scale-110 group-hover:bg-brand-500 group-hover:text-black transition-all shadow-xl shadow-brand-500/0 group-hover:shadow-brand-500/20">
                  <i className="bi bi-cpu text-2xl"></i>
                </div>
                <div>
                  <h4 className="text-lg font-black text-white group-hover:text-brand-400 transition-colors tracking-tight">Trí Tuệ RAG</h4>
                  <div className="text-[10px] font-bold text-brand-500/50 uppercase tracking-widest">Vector Knowledge</div>
                </div>
              </div>
              <p className="text-slate-400 text-sm leading-relaxed">Quản lý &quot;não bộ&quot; của AI. Đồng bộ hóa FAISS Vector Database để AI trả lời chính xác và thực tế.</p>
              <div className="flex justify-end pt-2">
                <div className="w-10 h-10 rounded-full border border-white/5 flex items-center justify-center text-white/35 group-hover:text-brand-400 group-hover:border-brand-500/30 transition-all">
                  <i className="bi bi-arrow-right"></i>
                </div>
              </div>
            </div>
          </Link>

          {/* News / Articles */}
          <Link href="/admin-cp/articles/" className="mgmt-card group p-1 rounded-[2.5rem] bg-gradient-to-br from-brand-500/20 to-transparent hover:from-brand-500/40 transition-all duration-500">
            <div className="bg-slate-950/80 rounded-[2.3rem] p-8 h-full flex flex-col gap-5 backdrop-blur-3xl">
              <div className="flex items-center gap-5">
                <div className="w-14 h-14 rounded-2xl bg-brand-500/10 flex items-center justify-center text-brand-400 group-hover:scale-110 group-hover:bg-brand-500 group-hover:text-white transition-all shadow-xl shadow-brand-500/0 group-hover:shadow-brand-500/20">
                  <i className="bi bi-newspaper text-2xl"></i>
                </div>
                <div>
                  <h4 className="text-lg font-black text-white group-hover:text-brand-400 transition-colors tracking-tight">Tin Tức / Cảnh Báo</h4>
                  <div className="text-[10px] font-bold text-brand-500/50 uppercase tracking-widest">Global Newsroom</div>
                </div>
              </div>
              <p className="text-slate-400 text-sm leading-relaxed">Phát hành các bài viết cảnh báo nóng. Cập nhật tin tức an ninh mạng theo thời gian thực.</p>
              <div className="flex justify-end pt-2">
                <div className="w-10 h-10 rounded-full border border-white/5 flex items-center justify-center text-white/35 group-hover:text-brand-400 group-hover:border-brand-500/30 transition-all">
                  <i className="bi bi-arrow-right"></i>
                </div>
              </div>
            </div>
          </Link>

          {/* Scenarios Management */}
          <Link href="/admin-cp/scenarios/" className="mgmt-card group p-1 rounded-[2.5rem] bg-gradient-to-br from-safe-500/20 to-transparent hover:from-safe-500/40 transition-all duration-500">
            <div className="bg-slate-950/80 rounded-[2.3rem] p-8 h-full flex flex-col gap-5 backdrop-blur-3xl">
              <div className="flex items-center gap-5">
                <div className="w-14 h-14 rounded-2xl bg-safe-500/10 flex items-center justify-center text-safe-400 group-hover:scale-110 group-hover:bg-safe-500 group-hover:text-black transition-all shadow-xl shadow-safe-500/0 group-hover:shadow-safe-500/20">
                  <i className="bi bi-controller text-2xl"></i>
                </div>
                <div>
                  <h4 className="text-lg font-black text-white group-hover:text-safe-400 transition-colors tracking-tight">Kịch Bản Tương Tác</h4>
                  <div className="text-[10px] font-bold text-safe-500/50 uppercase tracking-widest">Interactive Training</div>
                </div>
              </div>
              <p className="text-slate-400 text-sm leading-relaxed">Quản lý và thiết kế các tình huống giả định lừa đảo để người dùng luyện tập kỹ năng phòng chống.</p>
              <div className="flex justify-end pt-2">
                <div className="w-10 h-10 rounded-full border border-white/5 flex items-center justify-center text-white/35 group-hover:text-safe-400 group-hover:border-safe-500/30 transition-all">
                  <i className="bi bi-arrow-right"></i>
                </div>
              </div>
            </div>
          </Link>

          {/* Forum Management */}
          <Link href="/admin-cp/forum/" className="mgmt-card group p-1 rounded-[2.5rem] bg-gradient-to-br from-warn-500/20 to-transparent hover:from-warn-500/40 transition-all duration-500">
            <div className="bg-slate-950/80 rounded-[2.3rem] p-8 h-full flex flex-col gap-5 backdrop-blur-3xl">
              <div className="flex items-center gap-5">
                <div className="w-14 h-14 rounded-2xl bg-warn-500/10 flex items-center justify-center text-warn-400 group-hover:scale-110 group-hover:bg-warn-500 group-hover:text-black transition-all shadow-xl shadow-warn-500/0 group-hover:shadow-warn-500/20">
                  <i className="bi bi-chat-square-dots text-2xl"></i>
                </div>
                <div>
                  <h4 className="text-lg font-black text-white group-hover:text-warn-400 transition-colors tracking-tight">Quản Lý Diễn Đàn</h4>
                  <div className="text-[10px] font-bold text-warn-500/50 uppercase tracking-widest">Community Forum</div>
                </div>
              </div>
              <p className="text-slate-400 text-sm leading-relaxed">Kiểm duyệt bài viết, bình luận. Xử lý các báo cáo vi phạm và quản lý dữ liệu diễn đàn cộng đồng.</p>
              <div className="flex justify-end pt-2">
                <div className="w-10 h-10 rounded-full border border-white/5 flex items-center justify-center text-white/35 group-hover:text-warn-400 group-hover:border-warn-500/30 transition-all">
                  <i className="bi bi-arrow-right"></i>
                </div>
              </div>
            </div>
          </Link>

          {/* Ticket Management */}
          <Link href="/admin-cp/tickets/" className="mgmt-card group p-1 rounded-[2.5rem] bg-gradient-to-br from-danger-500/20 to-transparent hover:from-danger-500/40 transition-all duration-500">
            <div className="bg-slate-950/80 rounded-[2.3rem] p-8 h-full flex flex-col gap-5 backdrop-blur-3xl">
              <div className="flex items-center gap-5">
                <div className="w-14 h-14 rounded-2xl bg-danger-500/10 flex items-center justify-center text-danger-400 group-hover:scale-110 group-hover:bg-danger-500 group-hover:text-white transition-all shadow-xl shadow-danger-500/0 group-hover:shadow-danger-500/20">
                  <i className="bi bi-life-preserver text-2xl"></i>
                </div>
                <div>
                  <h4 className="text-lg font-black text-white group-hover:text-danger-400 transition-colors tracking-tight">Quản Lý Ticket</h4>
                  <div className="text-[10px] font-bold text-danger-500/50 uppercase tracking-widest">/profile/tickets/</div>
                </div>
              </div>
              <p className="text-slate-400 text-sm leading-relaxed">Xử lý ticket hỗ trợ từ người dùng, theo dõi trạng thái và phản hồi trực tiếp từ Admin.</p>
              <div className="flex justify-end pt-2">
                <div className="w-10 h-10 rounded-full border border-white/5 flex items-center justify-center text-white/35 group-hover:text-danger-400 group-hover:border-danger-500/30 transition-all">
                  <i className="bi bi-arrow-right"></i>
                </div>
              </div>
            </div>
          </Link>

          {/* Super Admin Controls */}
          {isSuperAdmin && (
            <Link href="/admin-cp/users/" className="mgmt-card group p-1 rounded-[2.5rem] bg-gradient-to-br from-danger-500/20 to-transparent hover:from-danger-500/40 transition-all duration-500">
              <div className="bg-slate-950/80 rounded-[2.3rem] p-8 h-full flex flex-col gap-5 backdrop-blur-3xl">
                <div className="flex items-center gap-5">
                  <div className="w-14 h-14 rounded-2xl bg-danger-500/10 flex items-center justify-center text-danger-400 group-hover:scale-110 group-hover:bg-danger-500 group-hover:text-white transition-all shadow-xl shadow-danger-500/0 group-hover:shadow-danger-500/20">
                    <i className="bi bi-person-badge text-2xl"></i>
                  </div>
                  <div>
                    <h4 className="text-lg font-black text-white group-hover:text-danger-400 transition-colors tracking-tight">Hệ Thống & User</h4>
                    <div className="text-[10px] font-bold text-danger-500/50 uppercase tracking-widest">Super Admin Only</div>
                  </div>
                </div>
                <p className="text-slate-400 text-sm leading-relaxed">Kiểm soát người dùng, phân quyền Admin và tinh chỉnh các cấu hình hệ thống cốt lõi.</p>
                <div className="flex justify-end pt-2">
                  <div className="w-10 h-10 rounded-full border border-white/5 flex items-center justify-center text-white/35 group-hover:text-danger-400 group-hover:border-danger-500/30 transition-all">
                    <i className="bi bi-arrow-right"></i>
                  </div>
                </div>
              </div>
            </Link>
          )}
        </div>
      </div>

      <style>{`
        .animate-pulse-slow { animation: pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .7; } }
        .mgmt-card:hover { transform: translateY(-4px); }
      `}</style>
    </>
  );
}
