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
import { requestAndSubscribePush } from '../../lib/push';
import { useAdminGet, AdminNavbar } from './_shared';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Filler, Tooltip, Legend);

interface DashCharts {
  labels?: string[];
  reports?: number[];
  scans?: number[];
}

interface DashStats {
  total_users?: number;
  pending_reports?: number;
  total_reports?: number;
  total_articles?: number;
  total_scans?: number;
  total_lessons?: number;
  total_posts?: number;
  pending_forum_reports?: number;
  webpush_subscribers?: number;
  webpush_total?: number;
  pending_tickets?: number;
  scans_today?: number;
  reports_week?: number;
  charts?: DashCharts;
}

interface BroadcastResult {
  status?: string;
  message?: string;
  error?: string;
}

const TYPE_OPTIONS = [
  { value: 'info', label: 'Thông tin thường' },
  { value: 'success', label: 'Thành công / An toàn' },
  { value: 'warning', label: 'Cảnh báo lừa đảo' },
  { value: 'error', label: 'Khẩn cấp / Nguy hiểm' },
];

const chartOptions: ChartOptions<'line'> = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: { display: false },
    tooltip: {
      backgroundColor: 'rgba(15, 23, 42, 0.95)',
      titleColor: '#ffffff',
      bodyColor: '#e2e8f0',
      borderColor: 'rgba(255, 255, 255, 0.15)',
      borderWidth: 1,
      padding: 10,
      displayColors: false,
    },
  },
  scales: {
    y: {
      beginAtZero: true,
      min: 0,
      suggestedMax: 5,
      grid: { color: 'rgba(255, 255, 255, 0.08)' },
      ticks: {
        color: 'rgba(255, 255, 255, 0.75)',
        font: { size: 11, weight: 'bold' },
        stepSize: 1,
        precision: 0,
      },
    },
    x: {
      grid: { color: 'rgba(255, 255, 255, 0.04)' },
      ticks: {
        color: 'rgba(255, 255, 255, 0.75)',
        font: { size: 11, weight: 'bold' },
      },
    },
  },
};

function useCountUp(target: number | undefined, duration = 1200): number {
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
    const id = setInterval(() => refetchRef.current(), 30000);
    return () => clearInterval(id);
  }, []);

  const users = useCountUp(s?.total_users);
  const reports = useCountUp(s?.pending_reports);
  const scans = useCountUp(s?.total_scans);
  const webpushSubscribers = useCountUp(s?.webpush_subscribers);
  const connected = !error;

  const meta = user as unknown as { is_superuser?: boolean; profile?: { is_super_admin?: boolean } } | null;
  const isSuperAdmin = Boolean(meta?.is_superuser || meta?.profile?.is_super_admin);

  // Broadcast state
  const [title, setTitle] = useState('');
  const [message, setMessage] = useState('');
  const [ntype, setNtype] = useState('info');
  const [url, setUrl] = useState('');
  const [sendWebpush, setSendWebpush] = useState(true);
  const [sendInapp, setSendInapp] = useState(true);
  const [sending, setSending] = useState(false);
  const [testingPush, setTestingPush] = useState(false);
  const [sent, setSent] = useState(false);

  // Local push status
  const [pushPerm, setPushPerm] = useState<NotificationPermission>(
    typeof window !== 'undefined' && typeof Notification !== 'undefined' ? Notification.permission : 'default'
  );



  const enableLocalPush = async () => {
    const res = await requestAndSubscribePush();
    setPushPerm(res.permission);
    showToast(res.message || 'Hoàn tất cập nhật quyền', res.success ? 'success' : 'warning');
    refetch();
  };

  const testPushOnCurrentDevice = async () => {
    setTestingPush(true);
    try {
      const res = await api.post<{
        status: string;
        message: string;
        webpush_sent?: number;
        subscriptions_count?: number;
      }>('/notifications/test-push/', {
        title: title.trim() || 'Thông báo thử nghiệm ShieldCall VN',
        message: message.trim() || 'Đây là thông báo WebPush kiểm tra kết nối từ Admin Panel.',
        url: url.trim() || '/admin-cp/',
      });
      if (res.status === 'success') {
        showToast(res.message, 'success');
      } else if (res.status === 'warning') {
        showToast(res.message, 'warning');
      } else {
        showToast(res.message || 'Gửi test push thất bại', 'info');
      }
      refetch();
    } catch (e) {
      showToast(e instanceof Error ? e.message : 'Lỗi gửi test push', 'error');
    } finally {
      setTestingPush(false);
    }
  };

  const send = async () => {
    if (!title.trim() || !message.trim()) {
      showToast('Tiêu đề và nội dung thông báo là bắt buộc', 'warning');
      return;
    }
    if (!sendWebpush && !sendInapp) {
      showToast('Phải chọn ít nhất một kênh gửi (WebPush hoặc In-App)', 'warning');
      return;
    }

    setSending(true);
    try {
      const data = await api.post<BroadcastResult>('/admin/notifications/broadcast/', {
        title,
        message,
        notification_type: ntype,
        url,
        send_webpush: sendWebpush,
        send_inapp: sendInapp,
      });
      showToast(data.message || 'Đã gửi thông báo thành công!', 'success');
      setTitle('');
      setMessage('');
      setUrl('');
      setSent(true);
      setTimeout(() => setSent(false), 4000);
      refetch();
    } catch (e) {
      showToast(e instanceof Error ? e.message : 'Lỗi gửi thông báo', 'error');
    } finally {
      setSending(false);
    }
  };

  const labels = s?.charts?.labels && s.charts.labels.length > 0 ? s.charts.labels : [];
  const reportsData = s?.charts?.reports ?? [];
  const scansData = s?.charts?.scans ?? [];

  const reportsChartData: ChartData<'line'> = {
    labels,
    datasets: [
      {
        label: 'Báo cáo',
        data: reportsData,
        borderColor: '#06b6d4',
        backgroundColor: 'rgba(6, 182, 212, 0.2)',
        borderWidth: 3,
        fill: true,
        tension: 0.35,
        pointRadius: 5,
        pointBackgroundColor: '#06b6d4',
        pointBorderColor: '#ffffff',
        pointBorderWidth: 2,
        pointHoverRadius: 8,
      },
    ],
  };
  const scansChartData: ChartData<'line'> = {
    labels,
    datasets: [
      {
        label: 'Lượt quét',
        data: scansData,
        borderColor: '#38bdf8',
        backgroundColor: 'rgba(56, 189, 248, 0.2)',
        borderWidth: 3,
        fill: true,
        tension: 0.35,
        pointRadius: 5,
        pointBackgroundColor: '#38bdf8',
        pointBorderColor: '#ffffff',
        pointBorderWidth: 2,
        pointHoverRadius: 8,
      },
    ],
  };

  return (
    <div className="container mx-auto px-4 py-8 mt-16 max-w-7xl">
      {/* Header with Pulse Indicator */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 gap-4 pb-6 border-b border-white/10">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="flex h-2.5 w-2.5 relative">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-brand-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-brand-500"></span>
            </span>
            <span className="text-[11px] uppercase font-black tracking-[0.2em] text-brand-400">
              Hệ thống Giám sát & Quản trị Trung tâm
            </span>
          </div>
          <h1 className="text-3xl md:text-4xl font-black text-white tracking-tight">
            Dashboard Điều Hành
          </h1>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <div className="px-4 py-2 rounded-xl bg-slate-900/90 border border-white/10 backdrop-blur-xl flex items-center gap-2.5 shadow-md">
            <div className="w-7 h-7 rounded-lg bg-brand-500/20 border border-brand-500/30 flex items-center justify-center text-brand-400 text-sm">
              <i className="bi bi-shield-check"></i>
            </div>
            <div>
              <div className="text-[9px] font-bold text-slate-400 uppercase tracking-widest leading-none">Vai trò</div>
              <div className="text-xs font-black text-white">{isSuperAdmin ? 'Super Admin' : 'Administrator'}</div>
            </div>
          </div>

          <div
            className={`px-3.5 py-2 rounded-xl border text-xs font-black uppercase flex items-center gap-2 shadow-md ${
              connected
                ? 'bg-safe-500/15 border-safe-500/30 text-safe-300'
                : 'bg-danger-500/15 border-danger-500/30 text-danger-300'
            }`}
          >
            <span
              className={`w-2 h-2 rounded-full ${
                connected ? 'bg-safe-400 shadow-[0_0_8px_rgba(34,197,94,0.6)]' : 'bg-danger-400 animate-pulse'
              }`}
            ></span>
            {connected ? 'Trực tuyến' : 'Mất kết nối'}
          </div>

          <button
            onClick={() => refetch()}
            className="px-3.5 py-2 rounded-xl bg-slate-900/80 border border-white/10 text-slate-300 hover:text-white hover:border-white/25 text-xs font-bold transition-all flex items-center gap-1.5 shadow-md"
            title="Làm mới số liệu"
          >
            <i className="bi bi-arrow-clockwise text-sm"></i>
            <span>Làm mới</span>
          </button>
        </div>
      </div>

      {/* Unified Tab Navigation Bar */}
      <AdminNavbar />

      {/* Live Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4 mb-8">
        {/* User Stats */}
        <div className="relative overflow-hidden p-5 rounded-2xl bg-slate-900/90 border border-white/10 backdrop-blur-xl hover:border-brand-500/40 transition-all shadow-lg">
          <div className="flex justify-between items-start mb-3">
            <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-brand-500 to-brand-600 flex items-center justify-center text-white shadow-lg shadow-brand-500/20">
              <i className="bi bi-people-fill text-lg"></i>
            </div>
            <div className="text-right">
              <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Người dùng</div>
              <div className="text-2xl font-black text-white tracking-tight">{users}</div>
            </div>
          </div>
          <div className="text-[11px] text-slate-400 border-t border-white/5 pt-2 flex items-center justify-between">
            <span>Hoạt động hôm nay</span>
            <span className="font-bold text-brand-300">{s?.total_users ? `${s.total_users} active` : '-'}</span>
          </div>
        </div>

        {/* Pending Reports */}
        <div className="relative overflow-hidden p-5 rounded-2xl bg-slate-900/90 border border-white/10 backdrop-blur-xl hover:border-danger-500/40 transition-all shadow-lg">
          <div className="flex justify-between items-start mb-3">
            <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-danger-500 to-rose-600 flex items-center justify-center text-white shadow-lg shadow-danger-500/20">
              <i className="bi bi-exclamation-octagon-fill text-lg"></i>
            </div>
            <div className="text-right">
              <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Báo cáo chờ</div>
              <div className="text-2xl font-black text-danger-400 tracking-tight">{reports}</div>
            </div>
          </div>
          <div className="text-[11px] text-slate-400 border-t border-white/5 pt-2 flex items-center justify-between">
            <span>Tổng cộng</span>
            <span className="font-bold text-white">{s?.total_reports ?? 0}</span>
          </div>
        </div>

        {/* WebPush Subscribers */}
        <div className="relative overflow-hidden p-5 rounded-2xl bg-slate-900/90 border border-white/10 backdrop-blur-xl hover:border-brand-400/40 transition-all shadow-lg">
          <div className="flex justify-between items-start mb-3">
            <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-cyan-500 to-brand-600 flex items-center justify-center text-white shadow-lg shadow-brand-500/20">
              <i className="bi bi-bell-fill text-lg"></i>
            </div>
            <div className="text-right">
              <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">WebPush Active</div>
              <div className="text-2xl font-black text-cyan-300 tracking-tight">{webpushSubscribers}</div>
            </div>
          </div>
          <div className="text-[11px] text-slate-400 border-t border-white/5 pt-2 flex items-center justify-between">
            <span>Tổng thiết bị</span>
            <span className="font-bold text-white">{s?.webpush_total ?? 0}</span>
          </div>
        </div>

        {/* AI Scan Activity */}
        <div className="relative overflow-hidden p-5 rounded-2xl bg-slate-900/90 border border-white/10 backdrop-blur-xl hover:border-brand-500/40 transition-all shadow-lg">
          <div className="flex justify-between items-start mb-3">
            <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-brand-500 to-indigo-600 flex items-center justify-center text-white shadow-lg shadow-brand-500/20">
              <i className="bi bi-lightning-charge-fill text-lg"></i>
            </div>
            <div className="text-right">
              <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Lượt Quét AI</div>
              <div className="text-2xl font-black text-white tracking-tight">{scans}</div>
            </div>
          </div>
          <div className="text-[11px] text-slate-400 border-t border-white/5 pt-2 flex items-center justify-between">
            <span>Quét hôm nay</span>
            <span className="font-bold text-brand-300">{s?.scans_today ?? 0}</span>
          </div>
        </div>

        {/* Content Stats */}
        <div className="relative overflow-hidden p-5 rounded-2xl bg-slate-900/90 border border-white/10 backdrop-blur-xl hover:border-purple-500/40 transition-all shadow-lg">
          <div className="flex justify-between items-start mb-3">
            <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-purple-500 to-indigo-600 flex items-center justify-center text-white shadow-lg shadow-purple-500/20">
              <i className="bi bi-journal-code text-lg"></i>
            </div>
            <div className="text-right">
              <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Bài học & Tin</div>
              <div className="text-2xl font-black text-white tracking-tight">{s?.total_lessons ?? '-'}</div>
            </div>
          </div>
          <div className="text-[11px] text-slate-400 border-t border-white/5 pt-2 flex items-center justify-between">
            <span>Bài viết tin tức</span>
            <span className="font-bold text-purple-300">{s?.total_articles ?? 0}</span>
          </div>
        </div>

        {/* Forum & Tickets Stats */}
        <div className="relative overflow-hidden p-5 rounded-2xl bg-slate-900/90 border border-white/10 backdrop-blur-xl hover:border-amber-500/40 transition-all shadow-lg">
          <div className="flex justify-between items-start mb-3">
            <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-amber-500 to-orange-600 flex items-center justify-center text-white shadow-lg shadow-amber-500/20">
              <i className="bi bi-chat-dots-fill text-lg"></i>
            </div>
            <div className="text-right">
              <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Diễn đàn</div>
              <div className="text-2xl font-black text-white tracking-tight">{s?.total_posts ?? '-'}</div>
            </div>
          </div>
          <div className="text-[11px] text-slate-400 border-t border-white/5 pt-2 flex items-center justify-between">
            <span>Ticket mở</span>
            <span className="font-bold text-amber-400">{s?.pending_tickets ?? 0}</span>
          </div>
        </div>
      </div>

      {/* Broadcast Notification Section (Refactored & High Contrast) */}
      <div className="mb-10 rounded-3xl bg-slate-900/90 border border-white/15 backdrop-blur-2xl p-6 sm:p-8 shadow-2xl relative overflow-hidden">
        {/* Glow backdrop */}
        <div className="absolute top-0 right-0 w-96 h-96 bg-brand-500/5 rounded-full blur-3xl pointer-events-none"></div>

        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6 pb-5 border-b border-white/10">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-brand-500 to-brand-600 flex items-center justify-center text-white shadow-lg shadow-brand-500/25">
              <i className="bi bi-megaphone-fill text-xl"></i>
            </div>
            <div>
              <h2 className="text-xl font-black text-white tracking-tight">Gửi Thông Báo Toàn Hệ Thống</h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Phát thông báo WebPush tới thiết bị trình duyệt và thông báo In-App tới người dùng
              </p>
            </div>
          </div>

          {/* Device status badge & test button */}
          <div className="flex items-center gap-2 flex-wrap">
            {pushPerm !== 'granted' ? (
              <button
                type="button"
                onClick={() => void enableLocalPush()}
                className="px-3.5 py-2 rounded-xl bg-amber-500/20 border border-amber-500/40 text-amber-300 text-xs font-bold hover:bg-amber-500/30 transition-all flex items-center gap-1.5"
                title="Bật WebPush trên trình duyệt này"
              >
                <i className="bi bi-bell"></i> Bật WebPush trên máy này
              </button>
            ) : (
              <span className="px-3 py-1.5 rounded-xl bg-safe-500/15 border border-safe-500/30 text-safe-300 text-xs font-bold flex items-center gap-1.5">
                <i className="bi bi-check-circle-fill"></i> Trình duyệt đã bật Push
              </span>
            )}

            <button
              type="button"
              disabled={testingPush}
              onClick={() => void testPushOnCurrentDevice()}
              className="px-3.5 py-2 rounded-xl bg-white/10 border border-white/15 text-slate-200 hover:text-white hover:bg-white/15 text-xs font-bold transition-all flex items-center gap-1.5 disabled:opacity-50"
              title="Gửi test push đến thiết bị đang mở"
            >
              {testingPush ? (
                <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin"></span>
              ) : (
                <i className="bi bi-send-check"></i>
              )}
              <span>Test Push máy này</span>
            </button>
          </div>
        </div>

        {sent && (
          <div className="mb-6 p-4 rounded-2xl bg-safe-500/15 border border-safe-500/30 text-safe-300 text-sm font-bold flex items-center gap-2">
            <i className="bi bi-check-circle-fill text-lg"></i>
            <span>Đã gửi thông báo thành công! Tác vụ gửi WebPush và In-App đang được xử lý nền.</span>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-12 gap-5 mb-5">
          <div className="md:col-span-6">
            <label className="text-xs font-bold text-slate-300 uppercase tracking-wider block mb-2">
              Tiêu đề thông báo <span className="text-danger-400">*</span>
            </label>
            <input
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              type="text"
              placeholder="VD: Cảnh báo chiêu trò lừa đảo mạo danh ngân hàng mới..."
              className="w-full bg-slate-950/80 border border-white/15 rounded-xl px-4 py-3 text-white text-sm placeholder-slate-500 focus:outline-none focus:border-brand-400 focus:ring-2 focus:ring-brand-500/20 transition-all font-medium"
            />
          </div>

          <div className="md:col-span-3">
            <label className="text-xs font-bold text-slate-300 uppercase tracking-wider block mb-2">
              Loại thông báo
            </label>
            <select
              value={ntype}
              onChange={(e) => setNtype(e.target.value)}
              className="w-full bg-slate-950/80 border border-white/15 rounded-xl px-4 py-3 text-white text-sm focus:outline-none focus:border-brand-400 focus:ring-2 focus:ring-brand-500/20 transition-all cursor-pointer font-medium"
            >
              {TYPE_OPTIONS.map((o) => (
                <option key={o.value} value={o.value} className="bg-slate-900 text-white">
                  {o.label}
                </option>
              ))}
            </select>
          </div>

          <div className="md:col-span-3">
            <label className="text-xs font-bold text-slate-300 uppercase tracking-wider block mb-2">
              URL đích (tùy chọn)
            </label>
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              type="text"
              placeholder="VD: /learn/ hoặc /radar/"
              className="w-full bg-slate-950/80 border border-white/15 rounded-xl px-4 py-3 text-white text-sm placeholder-slate-500 focus:outline-none focus:border-brand-400 focus:ring-2 focus:ring-brand-500/20 transition-all font-medium"
            />
          </div>
        </div>

        <div className="mb-5">
          <label className="text-xs font-bold text-slate-300 uppercase tracking-wider block mb-2">
            Nội dung thông báo <span className="text-danger-400">*</span>
          </label>
          <textarea
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            rows={3}
            placeholder="Nội dung thông báo gửi đến người dùng qua WebPush và chuông thông báo..."
            className="w-full bg-slate-950/80 border border-white/15 rounded-xl px-4 py-3 text-white text-sm placeholder-slate-500 focus:outline-none focus:border-brand-400 focus:ring-2 focus:ring-brand-500/20 transition-all resize-none font-medium leading-relaxed"
          ></textarea>
        </div>

        {/* Options & Action Row */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pt-4 border-t border-white/10">
          <div className="flex items-center gap-6 flex-wrap">
            <label className="flex items-center gap-2 cursor-pointer text-xs font-bold text-slate-300 hover:text-white">
              <input
                type="checkbox"
                checked={sendWebpush}
                onChange={(e) => setSendWebpush(e.target.checked)}
                className="w-4 h-4 rounded text-brand-500 focus:ring-brand-400 bg-slate-900 border-white/20"
              />
              <span className="flex items-center gap-1.5">
                <i className="bi bi-broadcast text-brand-400"></i> Gửi Web Push đến thiết bị trình duyệt ({s?.webpush_subscribers ?? 0} active)
              </span>
            </label>

            <label className="flex items-center gap-2 cursor-pointer text-xs font-bold text-slate-300 hover:text-white">
              <input
                type="checkbox"
                checked={sendInapp}
                onChange={(e) => setSendInapp(e.target.checked)}
                className="w-4 h-4 rounded text-brand-500 focus:ring-brand-400 bg-slate-900 border-white/20"
              />
              <span className="flex items-center gap-1.5">
                <i className="bi bi-bell text-brand-400"></i> Gửi thông báo In-App &amp; WebSocket
              </span>
            </label>
          </div>

          <button
            onClick={() => void send()}
            disabled={sending || !title.trim() || !message.trim()}
            className="w-full sm:w-auto px-8 py-3.5 rounded-xl bg-gradient-to-r from-brand-500 to-brand-600 text-black font-black text-xs uppercase tracking-wider hover:opacity-95 active:scale-95 transition-all shadow-xl shadow-brand-500/25 disabled:opacity-40 disabled:scale-100 flex items-center justify-center gap-2"
          >
            {sending ? (
              <>
                <span className="w-4 h-4 border-2 border-black/30 border-t-black rounded-full animate-spin"></span>
                <span>Đang phát thông báo...</span>
              </>
            ) : (
              <>
                <i className="bi bi-send-fill text-sm"></i>
                <span>Gửi Thông Báo Broadcast</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-12">
        <div className="p-6 sm:p-8 rounded-3xl bg-slate-900/90 border border-white/10 backdrop-blur-xl shadow-xl">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h3 className="text-lg font-black text-white tracking-tight">Xu hướng báo cáo</h3>
              <p className="text-xs text-slate-400 mt-0.5">Số lượng báo cáo lừa đảo nhận được trong 7 ngày gần nhất</p>
            </div>
            <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center text-slate-300">
              <i className="bi bi-graph-up text-lg"></i>
            </div>
          </div>
          <div className="h-[280px] w-full">
            <Line data={reportsChartData} options={chartOptions} />
          </div>
        </div>

        <div className="p-6 sm:p-8 rounded-3xl bg-slate-900/90 border border-white/10 backdrop-blur-xl shadow-xl">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h3 className="text-lg font-black text-white tracking-tight">Hoạt động Quét (Scan)</h3>
              <p className="text-xs text-slate-400 mt-0.5">Lưu lượng phân tích AI qua URL, SMS, Email, QR và Audio</p>
            </div>
            <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center text-slate-300">
              <i className="bi bi-activity text-lg"></i>
            </div>
          </div>
          <div className="h-[280px] w-full">
            <Line data={scansChartData} options={chartOptions} />
          </div>
        </div>
      </div>

      {/* Management Navigation Grid */}
      <div className="mb-6">
        <h2 className="text-xs font-black text-slate-400 uppercase tracking-[0.25em] mb-4">
          Các phân hệ quản trị ShieldCall
        </h2>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5 mb-12">
        {/* Reports */}
        <Link
          href="/admin-cp/reports/"
          className="group p-6 rounded-3xl bg-slate-900/90 border border-white/10 hover:border-brand-500/40 hover:bg-slate-900 transition-all duration-300 shadow-xl flex flex-col justify-between"
        >
          <div>
            <div className="flex items-center gap-4 mb-4">
              <div className="w-12 h-12 rounded-2xl bg-brand-500/15 border border-brand-500/30 flex items-center justify-center text-brand-400 group-hover:bg-brand-500 group-hover:text-black transition-all shadow-lg">
                <i className="bi bi-file-earmark-text text-xl"></i>
              </div>
              <div>
                <h4 className="text-base font-black text-white group-hover:text-brand-300 transition-colors">
                  Quản Lý Báo Cáo
                </h4>
                <div className="text-[10px] font-bold text-brand-400 uppercase tracking-widest">
                  Xác minh &amp; Duyệt báo cáo ({s?.pending_reports ?? 0} chờ duyệt)
                </div>
              </div>
            </div>
            <p className="text-slate-400 text-xs leading-relaxed">
              Phê duyệt và xác minh các báo cáo từ cộng đồng. Sử dụng AI để đánh giá mức độ rủi ro tự động.
            </p>
          </div>
          <div className="flex justify-end pt-4 mt-2 border-t border-white/5">
            <span className="text-xs font-bold text-brand-400 flex items-center gap-1 group-hover:translate-x-1 transition-transform">
              Truy cập <i className="bi bi-arrow-right"></i>
            </span>
          </div>
        </Link>

        {/* Users */}
        <Link
          href="/admin-cp/users/"
          className="group p-6 rounded-3xl bg-slate-900/90 border border-white/10 hover:border-brand-500/40 hover:bg-slate-900 transition-all duration-300 shadow-xl flex flex-col justify-between"
        >
          <div>
            <div className="flex items-center gap-4 mb-4">
              <div className="w-12 h-12 rounded-2xl bg-indigo-500/15 border border-indigo-500/30 flex items-center justify-center text-indigo-400 group-hover:bg-indigo-500 group-hover:text-white transition-all shadow-lg">
                <i className="bi bi-people text-xl"></i>
              </div>
              <div>
                <h4 className="text-base font-black text-white group-hover:text-indigo-300 transition-colors">
                  Người Dùng &amp; Phân Quyền
                </h4>
                <div className="text-[10px] font-bold text-indigo-400 uppercase tracking-widest">
                  Tài khoản, Admin, Khóa TK &amp; Cấm Forum
                </div>
              </div>
            </div>
            <p className="text-slate-400 text-xs leading-relaxed">
              Quản lý danh sách thành viên, cấp quyền quản trị viên, reset điểm uy tín hoặc cấm thành viên vi phạm.
            </p>
          </div>
          <div className="flex justify-end pt-4 mt-2 border-t border-white/5">
            <span className="text-xs font-bold text-indigo-400 flex items-center gap-1 group-hover:translate-x-1 transition-transform">
              Truy cập <i className="bi bi-arrow-right"></i>
            </span>
          </div>
        </Link>

        {/* News / Articles */}
        <Link
          href="/admin-cp/articles/"
          className="group p-6 rounded-3xl bg-slate-900/90 border border-white/10 hover:border-brand-500/40 hover:bg-slate-900 transition-all duration-300 shadow-xl flex flex-col justify-between"
        >
          <div>
            <div className="flex items-center gap-4 mb-4">
              <div className="w-12 h-12 rounded-2xl bg-brand-500/15 border border-brand-500/30 flex items-center justify-center text-brand-400 group-hover:bg-brand-500 group-hover:text-black transition-all shadow-lg">
                <i className="bi bi-newspaper text-xl"></i>
              </div>
              <div>
                <h4 className="text-base font-black text-white group-hover:text-brand-300 transition-colors">
                  Tin Tức &amp; Cảnh Báo
                </h4>
                <div className="text-[10px] font-bold text-brand-400 uppercase tracking-widest">
                  Biên tập, Magic Create AI &amp; Publish
                </div>
              </div>
            </div>
            <p className="text-slate-400 text-xs leading-relaxed">
              Phát hành bài viết cảnh báo nóng về các thủ đoạn lừa đảo mạng, đồng bộ dữ liệu Tín nhiệm mạng.
            </p>
          </div>
          <div className="flex justify-end pt-4 mt-2 border-t border-white/5">
            <span className="text-xs font-bold text-brand-400 flex items-center gap-1 group-hover:translate-x-1 transition-transform">
              Truy cập <i className="bi bi-arrow-right"></i>
            </span>
          </div>
        </Link>

        {/* Learn Content */}
        <Link
          href="/admin-cp/learn/"
          className="group p-6 rounded-3xl bg-slate-900/90 border border-white/10 hover:border-brand-500/40 hover:bg-slate-900 transition-all duration-300 shadow-xl flex flex-col justify-between"
        >
          <div>
            <div className="flex items-center gap-4 mb-4">
              <div className="w-12 h-12 rounded-2xl bg-purple-500/15 border border-purple-500/30 flex items-center justify-center text-purple-400 group-hover:bg-purple-500 group-hover:text-white transition-all shadow-lg">
                <i className="bi bi-mortarboard text-xl"></i>
              </div>
              <div>
                <h4 className="text-base font-black text-white group-hover:text-purple-300 transition-colors">
                  Bài Học &amp; Đào Tạo
                </h4>
                <div className="text-[10px] font-bold text-purple-400 uppercase tracking-widest">
                  Khóa học, Câu hỏi Quiz &amp; Tình huống
                </div>
              </div>
            </div>
            <p className="text-slate-400 text-xs leading-relaxed">
              Tổ chức nội dung đào tạo an toàn thông tin, bài học trắc nghiệm và thông báo bài học mới.
            </p>
          </div>
          <div className="flex justify-end pt-4 mt-2 border-t border-white/5">
            <span className="text-xs font-bold text-purple-400 flex items-center gap-1 group-hover:translate-x-1 transition-transform">
              Truy cập <i className="bi bi-arrow-right"></i>
            </span>
          </div>
        </Link>

        {/* Scenarios Management */}
        <Link
          href="/admin-cp/scenarios/"
          className="group p-6 rounded-3xl bg-slate-900/90 border border-white/10 hover:border-safe-500/40 hover:bg-slate-900 transition-all duration-300 shadow-xl flex flex-col justify-between"
        >
          <div>
            <div className="flex items-center gap-4 mb-4">
              <div className="w-12 h-12 rounded-2xl bg-safe-500/15 border border-safe-500/30 flex items-center justify-center text-safe-400 group-hover:bg-safe-500 group-hover:text-black transition-all shadow-lg">
                <i className="bi bi-diagram-3 text-xl"></i>
              </div>
              <div>
                <h4 className="text-base font-black text-white group-hover:text-safe-300 transition-colors">
                  Kịch Bản Mô Phỏng
                </h4>
                <div className="text-[10px] font-bold text-safe-400 uppercase tracking-widest">
                  Tình huống tương tác thực tế
                </div>
              </div>
            </div>
            <p className="text-slate-400 text-xs leading-relaxed">
              Thiết kế các kịch bản tương tác đa lựa chọn mô phỏng tình huống lừa đảo tài chính và danh tính.
            </p>
          </div>
          <div className="flex justify-end pt-4 mt-2 border-t border-white/5">
            <span className="text-xs font-bold text-safe-400 flex items-center gap-1 group-hover:translate-x-1 transition-transform">
              Truy cập <i className="bi bi-arrow-right"></i>
            </span>
          </div>
        </Link>

        {/* RAG Brain */}
        <Link
          href="/admin-cp/rag/"
          className="group p-6 rounded-3xl bg-slate-900/90 border border-white/10 hover:border-brand-500/40 hover:bg-slate-900 transition-all duration-300 shadow-xl flex flex-col justify-between"
        >
          <div>
            <div className="flex items-center gap-4 mb-4">
              <div className="w-12 h-12 rounded-2xl bg-brand-500/15 border border-brand-500/30 flex items-center justify-center text-brand-400 group-hover:bg-brand-500 group-hover:text-black transition-all shadow-lg">
                <i className="bi bi-cpu text-xl"></i>
              </div>
              <div>
                <h4 className="text-base font-black text-white group-hover:text-brand-300 transition-colors">
                  RAG &amp; Cơ Sở Tri Thức AI
                </h4>
                <div className="text-[10px] font-bold text-brand-400 uppercase tracking-widest">
                  FAISS Vector Database &amp; Đồng bộ
                </div>
              </div>
            </div>
            <p className="text-slate-400 text-xs leading-relaxed">
              Quản lý kho tri thức của AI trợ lý. Kích hoạt quét lại dữ liệu hoặc kiểm tra truy vấn ngữ nghĩa.
            </p>
          </div>
          <div className="flex justify-end pt-4 mt-2 border-t border-white/5">
            <span className="text-xs font-bold text-brand-400 flex items-center gap-1 group-hover:translate-x-1 transition-transform">
              Truy cập <i className="bi bi-arrow-right"></i>
            </span>
          </div>
        </Link>

        {/* Forum Management */}
        <Link
          href="/admin-cp/forum/"
          className="group p-6 rounded-3xl bg-slate-900/90 border border-white/10 hover:border-amber-500/40 hover:bg-slate-900 transition-all duration-300 shadow-xl flex flex-col justify-between"
        >
          <div>
            <div className="flex items-center gap-4 mb-4">
              <div className="w-12 h-12 rounded-2xl bg-amber-500/15 border border-amber-500/30 flex items-center justify-center text-amber-400 group-hover:bg-amber-500 group-hover:text-black transition-all shadow-lg">
                <i className="bi bi-chat-square-dots text-xl"></i>
              </div>
              <div>
                <h4 className="text-base font-black text-white group-hover:text-amber-300 transition-colors">
                  Quản Lý Diễn Đàn
                </h4>
                <div className="text-[10px] font-bold text-amber-400 uppercase tracking-widest">
                  Kiểm duyệt bài viết &amp; Báo cáo vi phạm
                </div>
              </div>
            </div>
            <p className="text-slate-400 text-xs leading-relaxed">
              Theo dõi và kiểm duyệt các bài viết, bình luận, ghim bài hoặc khóa chủ đề vi phạm tiêu chuẩn cộng đồng.
            </p>
          </div>
          <div className="flex justify-end pt-4 mt-2 border-t border-white/5">
            <span className="text-xs font-bold text-amber-400 flex items-center gap-1 group-hover:translate-x-1 transition-transform">
              Truy cập <i className="bi bi-arrow-right"></i>
            </span>
          </div>
        </Link>

        {/* Ticket Management */}
        <Link
          href="/admin-cp/tickets/"
          className="group p-6 rounded-3xl bg-slate-900/90 border border-white/10 hover:border-danger-500/40 hover:bg-slate-900 transition-all duration-300 shadow-xl flex flex-col justify-between"
        >
          <div>
            <div className="flex items-center gap-4 mb-4">
              <div className="w-12 h-12 rounded-2xl bg-rose-500/15 border border-rose-500/30 flex items-center justify-center text-rose-400 group-hover:bg-rose-500 group-hover:text-white transition-all shadow-lg">
                <i className="bi bi-ticket-detailed text-xl"></i>
              </div>
              <div>
                <h4 className="text-base font-black text-white group-hover:text-rose-300 transition-colors">
                  Hỗ Trợ Người Dùng (Tickets)
                </h4>
                <div className="text-[10px] font-bold text-rose-400 uppercase tracking-widest">
                  Yêu cầu hỗ trợ ({s?.pending_tickets ?? 0} đang chờ)
                </div>
              </div>
            </div>
            <p className="text-slate-400 text-xs leading-relaxed">
              Tiếp nhận, phản hồi và đóng các ticket yêu cầu trợ giúp kỹ thuật hoặc khiếu nại tài khoản.
            </p>
          </div>
          <div className="flex justify-end pt-4 mt-2 border-t border-white/5">
            <span className="text-xs font-bold text-rose-400 flex items-center gap-1 group-hover:translate-x-1 transition-transform">
              Truy cập <i className="bi bi-arrow-right"></i>
            </span>
          </div>
        </Link>
      </div>
    </div>
  );
}
