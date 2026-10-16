'use client';
import { useState, useEffect } from 'react';
import { api } from '../../lib/api';
import { AdminShell, useAdminGet } from './_shared';
import { showToast } from '../../lib/ui/feedback';

interface Ticket {
  id: number;
  title?: string;
  description?: string;
  category?: string;
  priority?: string;
  status?: string;
  admin_reply?: string;
  author_name?: string;
  author_username?: string;
  created_at?: string;
  updated_at?: string;
}

const STATUS_CONFIG: Record<string, { label: string; badge: string; icon: string }> = {
  open: {
    label: 'Mở',
    badge: 'bg-sky-500/15 text-sky-400 border-sky-500/30',
    icon: 'bi-record-circle',
  },
  in_progress: {
    label: 'Đang xử lý',
    badge: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    icon: 'bi-hourglass-split',
  },
  resolved: {
    label: 'Đã giải quyết',
    badge: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    icon: 'bi-check-circle',
  },
  closed: {
    label: 'Đã đóng',
    badge: 'bg-slate-700/50 text-slate-300 border-slate-600/50',
    icon: 'bi-slash-circle',
  },
};

const CATEGORY_LABELS: Record<string, string> = {
  bug: 'Lỗi hệ thống',
  feature: 'Đề xuất',
  account: 'Tài khoản',
  other: 'Khác',
};

const PRIORITY_CONFIG: Record<string, { label: string; color: string }> = {
  low: { label: 'Thấp', color: 'text-slate-400' },
  medium: { label: 'Trung bình', color: 'text-amber-400' },
  high: { label: 'Cao', color: 'text-orange-400' },
  critical: { label: 'Nghiêm trọng', color: 'text-rose-400 font-black' },
};

const STATUS_TABS: Array<{ key: string; label: string }> = [
  { key: '', label: 'Tất cả' },
  { key: 'open', label: 'Mở' },
  { key: 'in_progress', label: 'Đang xử lý' },
  { key: 'resolved', label: 'Đã giải quyết' },
  { key: 'closed', label: 'Đã đóng' },
];

function statusMeta(s?: string) {
  if (s && STATUS_CONFIG[s]) return STATUS_CONFIG[s];
  return {
    label: s || 'Chưa rõ',
    badge: 'bg-slate-800 text-slate-300 border-slate-700',
    icon: 'bi-question-circle',
  };
}

function categoryLabel(c?: string): string {
  return (c && CATEGORY_LABELS[c]) || c || 'Khác';
}

function priorityMeta(p?: string) {
  if (p && PRIORITY_CONFIG[p]) return PRIORITY_CONFIG[p];
  return { label: p || 'Thấp', color: 'text-slate-400' };
}

function timeAgo(dt?: string): string {
  if (!dt) return '';
  const diff = (Date.now() - new Date(dt).getTime()) / 1000;
  if (Number.isNaN(diff)) return '';
  if (diff < 60) return 'Vừa xong';
  if (diff < 3600) return `${Math.floor(diff / 60)} phút trước`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} giờ trước`;
  return `${Math.floor(diff / 86400)} ngày trước`;
}

function asList(data: Ticket[] | { results?: Ticket[] } | null): Ticket[] {
  if (!data) return [];
  return Array.isArray(data) ? data : data.results || [];
}

const TICKETS_PAGE_SIZE = 20;

export default function Tickets() {
  const [statusFilter, setStatusFilter] = useState('');
  const [expandedTicket, setExpandedTicket] = useState<number | null>(null);
  const [replyText, setReplyText] = useState('');
  const [replyStatus, setReplyStatus] = useState('');
  const [replyLoading, setReplyLoading] = useState(false);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);

  const listPath = (() => {
    const params = new URLSearchParams({
      page: String(page),
      page_size: String(TICKETS_PAGE_SIZE),
    });
    if (statusFilter) params.set('status', statusFilter);
    return `/admin/tickets/?${params.toString()}`;
  })();

  const { data, loading, refetch } = useAdminGet<Ticket[] | { results?: Ticket[]; count?: number; status_counts?: Record<string, number> }>(listPath);
  const tickets = asList(data);
  const [statusCounts, setStatusCounts] = useState({ open: 0, in_progress: 0, resolved: 0 });

  useEffect(() => {
    if (data && !Array.isArray(data) && typeof data.count === 'number') {
      setTotal(data.count);
      setTotalPages(Math.max(1, Math.ceil(data.count / TICKETS_PAGE_SIZE)));
      const sc = data.status_counts;
      if (sc) {
        setStatusCounts({
          open: sc.open || 0,
          in_progress: sc.in_progress || 0,
          resolved: sc.resolved || 0,
        });
      }
    }
  }, [data]);

  const pickStatus = (s: string): void => {
    setStatusFilter((prev) => (prev === s ? '' : s));
    setPage(1);
  };

  const goPage = (p: number): void => {
    if (p >= 1 && p <= totalPages && p !== page) setPage(p);
  };

  const stats = {
    total,
    open: statusCounts.open,
    in_progress: statusCounts.in_progress,
    resolved: statusCounts.resolved,
  };

  const toggleExpand = (t: Ticket) => {
    if (expandedTicket === t.id) {
      setExpandedTicket(null);
    } else {
      setExpandedTicket(t.id);
      setReplyText(t.admin_reply || '');
      setReplyStatus(t.status || 'open');
    }
  };

  const submitReply = async (ticket: Ticket) => {
    if (!replyText.trim()) {
      showToast('Vui lòng nhập nội dung phản hồi', 'error');
      return;
    }
    setReplyLoading(true);
    try {
      await api.patch('/admin/tickets/', {
        ticket_id: ticket.id,
        admin_reply: replyText.trim(),
        status: replyStatus,
      });
      showToast('Đã cập nhật ticket thành công', 'success');
      setExpandedTicket(null);
      refetch();
    } catch (e) {
      showToast(e instanceof Error ? e.message : 'Lỗi kết nối máy chủ', 'error');
    } finally {
      setReplyLoading(false);
    }
  };

  return (
    <AdminShell
      breadcrumbs={[{ label: 'Hỗ trợ (Tickets)' }]}
      title="Quản lý Tickets hỗ trợ"
      subtitle="Tiếp nhận, xử lý và phản hồi sự cố hoặc yêu cầu hỗ trợ từ người dùng"
      actions={
        <button
          type="button"
          onClick={() => refetch()}
          className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-white/5 border border-white/10 text-white hover:bg-white/10 hover:border-brand-500/30 transition-all text-xs font-bold shadow-sm"
        >
          <i className="bi bi-arrow-clockwise"></i> Làm mới
        </button>
      }
    >
      {/* Thống kê trạng thái nhanh */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <button
          type="button"
          onClick={() => pickStatus('')}
          className={`text-left p-4 rounded-2xl border transition-all ${
            statusFilter === ''
              ? 'bg-slate-800/90 border-brand-500/50 ring-1 ring-brand-500/30 shadow-lg'
              : 'bg-slate-900/60 border-white/10 hover:border-white/20'
          }`}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">Tổng ticket</span>
            <i className="bi bi-inbox text-slate-400 text-lg"></i>
          </div>
          <div className="text-2xl font-black text-white">{stats.total}</div>
        </button>

        <button
          type="button"
          onClick={() => pickStatus('open')}
          className={`text-left p-4 rounded-2xl border transition-all ${
            statusFilter === 'open'
              ? 'bg-slate-800/90 border-sky-500/50 ring-1 ring-sky-500/30 shadow-lg'
              : 'bg-slate-900/60 border-white/10 hover:border-white/20'
          }`}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold text-sky-400 uppercase tracking-wider">Đang mở</span>
            <i className="bi bi-record-circle text-sky-400 text-lg"></i>
          </div>
          <div className="text-2xl font-black text-sky-400">{stats.open}</div>
        </button>

        <button
          type="button"
          onClick={() => pickStatus('in_progress')}
          className={`text-left p-4 rounded-2xl border transition-all ${
            statusFilter === 'in_progress'
              ? 'bg-slate-800/90 border-amber-500/50 ring-1 ring-amber-500/30 shadow-lg'
              : 'bg-slate-900/60 border-white/10 hover:border-white/20'
          }`}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold text-amber-400 uppercase tracking-wider">Đang xử lý</span>
            <i className="bi bi-hourglass-split text-amber-400 text-lg"></i>
          </div>
          <div className="text-2xl font-black text-amber-400">{stats.in_progress}</div>
        </button>

        <button
          type="button"
          onClick={() => pickStatus('resolved')}
          className={`text-left p-4 rounded-2xl border transition-all ${
            statusFilter === 'resolved'
              ? 'bg-slate-800/90 border-emerald-500/50 ring-1 ring-emerald-500/30 shadow-lg'
              : 'bg-slate-900/60 border-white/10 hover:border-white/20'
          }`}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold text-emerald-400 uppercase tracking-wider">Đã giải quyết</span>
            <i className="bi bi-check-circle text-emerald-400 text-lg"></i>
          </div>
          <div className="text-2xl font-black text-emerald-400">{stats.resolved}</div>
        </button>
      </div>

      {/* Bộ lọc trạng thái */}
      <div className="flex items-center gap-2 mb-6 flex-wrap">
        {STATUS_TABS.map((tab) => {
          const active = statusFilter === tab.key;
          return (
            <button
              key={tab.key}
              type="button"
              onClick={() => pickStatus(tab.key)}
              className={`px-4 py-2 rounded-xl text-xs font-bold transition-all border ${
                active
                  ? 'bg-gradient-to-r from-brand-500 to-brand-600 text-black border-transparent shadow-md font-black'
                  : 'bg-slate-900/60 text-slate-300 border-white/10 hover:bg-slate-800 hover:text-white'
              }`}
            >
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Loading */}
      {loading && (
        <div className="text-center py-16 bg-slate-900/40 rounded-2xl border border-white/10">
          <div className="w-8 h-8 border-2 border-brand-500 border-t-transparent rounded-full animate-spin mx-auto mb-3"></div>
          <p className="text-xs text-slate-400 font-semibold">Đang tải danh sách tickets...</p>
        </div>
      )}

      {/* Tickets List */}
      {!loading && (
        <div className="space-y-3">
          {tickets.map((t) => {
            const sm = statusMeta(t.status);
            const pm = priorityMeta(t.priority);
            const isExpanded = expandedTicket === t.id;

            return (
              <div
                key={t.id}
                className="bg-slate-900/70 border border-white/10 rounded-2xl overflow-hidden transition-all hover:border-brand-500/30 shadow-lg"
              >
                <div
                  className="p-5 cursor-pointer select-none"
                  onClick={() => toggleExpand(t)}
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-2 flex-wrap">
                        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-bold border ${sm.badge}`}>
                          <i className={`bi ${sm.icon}`}></i>
                          {sm.label}
                        </span>
                        <span className={`text-[11px] font-semibold ${pm.color}`}>
                          ● Mức độ: {pm.label}
                        </span>
                        <span className="text-[11px] font-semibold text-slate-300 bg-white/5 border border-white/10 px-2.5 py-1 rounded-md">
                          {categoryLabel(t.category)}
                        </span>
                      </div>

                      <h3 className="text-base font-bold text-white mb-2 leading-snug">
                        #{t.id} - {t.title}
                      </h3>

                      <div className="flex items-center gap-3 text-xs text-slate-400">
                        <span className="font-semibold text-slate-300">
                          {t.author_name || 'Người dùng ẩn danh'}
                        </span>
                        {t.author_username && (
                          <span className="text-brand-400">@{t.author_username}</span>
                        )}
                        <span>·</span>
                        <span>{timeAgo(t.created_at)}</span>
                        {t.admin_reply && (
                          <>
                            <span>·</span>
                            <span className="text-emerald-400 font-medium flex items-center gap-1">
                              <i className="bi bi-reply-fill"></i> Đã có phản hồi
                            </span>
                          </>
                        )}
                      </div>
                    </div>

                    <div className="shrink-0 w-8 h-8 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center text-slate-300">
                      <i className={`bi text-xs transition-transform ${isExpanded ? 'bi-chevron-up' : 'bi-chevron-down'}`}></i>
                    </div>
                  </div>
                </div>

                {/* Expanded Detail */}
                {isExpanded && (
                  <div className="px-5 pb-5 pt-3 border-t border-white/10 bg-black/20">
                    <div className="mb-4">
                      <div className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">
                        Nội dung chi tiết từ người dùng
                      </div>
                      <div className="p-4 rounded-xl bg-slate-950/70 border border-white/10 text-sm text-slate-200 leading-relaxed whitespace-pre-wrap font-sans">
                        {t.description || 'Không có mô tả chi tiết.'}
                      </div>
                    </div>

                    {t.admin_reply && (
                      <div className="mb-4">
                        <div className="text-xs font-bold text-emerald-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                          <i className="bi bi-chat-left-text-fill"></i> Phản hồi hiện tại của Admin
                        </div>
                        <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-500/20 text-sm text-emerald-200 leading-relaxed whitespace-pre-wrap font-sans">
                          {t.admin_reply}
                        </div>
                      </div>
                    )}

                    {/* Admin Reply Form */}
                    <div className="space-y-3 pt-2 border-t border-white/10">
                      <label className="text-xs font-bold text-white uppercase tracking-wider block">
                        Viết phản hồi hoặc cập nhật trạng thái
                      </label>
                      <textarea
                        rows={4}
                        value={replyText}
                        onChange={(e) => setReplyText(e.target.value)}
                        placeholder="Nhập nội dung phản hồi gửi tới người dùng..."
                        className="w-full bg-slate-950/80 border border-white/15 rounded-xl px-4 py-3 text-white placeholder-slate-500 text-sm focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500 transition resize-none"
                      ></textarea>

                      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                        <div className="flex items-center gap-3">
                          <label className="text-xs font-bold text-slate-300">Cập nhật trạng thái:</label>
                          <select
                            value={replyStatus}
                            onChange={(e) => setReplyStatus(e.target.value)}
                            className="bg-slate-900 border border-white/20 rounded-xl px-3 py-2 text-white text-xs font-bold focus:outline-none focus:border-brand-500 cursor-pointer"
                          >
                            <option value="open">Mở</option>
                            <option value="in_progress">Đang xử lý</option>
                            <option value="resolved">Đã giải quyết</option>
                            <option value="closed">Đóng</option>
                          </select>
                        </div>

                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => setExpandedTicket(null)}
                            className="px-4 py-2 rounded-xl text-xs font-bold text-slate-300 hover:text-white hover:bg-white/5 transition"
                          >
                            Đóng lại
                          </button>
                          <button
                            type="button"
                            disabled={replyLoading}
                            onClick={() => void submitReply(t)}
                            className="inline-flex items-center gap-2 px-5 py-2 rounded-xl bg-gradient-to-r from-brand-500 to-brand-600 text-black font-black text-xs hover:brightness-110 transition shadow-md disabled:opacity-50"
                          >
                            {replyLoading ? (
                              <>
                                <span className="inline-block w-3.5 h-3.5 border-2 border-black border-t-transparent rounded-full animate-spin"></span>
                                Đang lưu...
                              </>
                            ) : (
                              <>
                                <i className="bi bi-send-fill"></i>
                                Cập nhật phản hồi
                              </>
                            )}
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}

          {tickets.length === 0 && (
            <div className="text-center py-16 bg-slate-900/40 rounded-2xl border border-white/10">
              <i className="bi bi-inbox text-4xl text-slate-600 mb-3 block"></i>
              <p className="text-slate-300 text-sm font-bold mb-1">Không có ticket nào</p>
              <p className="text-slate-500 text-xs">
                {statusFilter ? `Không có ticket nào ở trạng thái này.` : `Hiện chưa có ticket hỗ trợ nào được gửi đến.`}
              </p>
              {statusFilter && (
                <button
                  type="button"
                  onClick={() => pickStatus('')}
                  className="mt-4 px-4 py-2 rounded-xl bg-white/5 border border-white/10 text-brand-400 text-xs font-bold hover:bg-white/10"
                >
                  Xóa bộ lọc
                </button>
              )}
            </div>
          )}

          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-2 pt-4">
              <button
                type="button"
                onClick={() => goPage(page - 1)}
                disabled={page <= 1}
                className="w-9 h-9 rounded-xl bg-slate-900/80 border border-white/10 flex items-center justify-center text-xs text-slate-300 hover:text-white hover:bg-white/10 transition disabled:opacity-30 disabled:cursor-not-allowed"
              >
                <i className="bi bi-chevron-left"></i>
              </button>
              <span className="mx-3 text-xs text-slate-300 font-bold">
                Trang {page} / {totalPages} · {total} tickets
              </span>
              <button
                type="button"
                onClick={() => goPage(page + 1)}
                disabled={page >= totalPages}
                className="w-9 h-9 rounded-xl bg-slate-900/80 border border-white/10 flex items-center justify-center text-xs text-slate-300 hover:text-white hover:bg-white/10 transition disabled:opacity-30 disabled:cursor-not-allowed"
              >
                <i className="bi bi-chevron-right"></i>
              </button>
            </div>
          )}
        </div>
      )}
    </AdminShell>
  );
}
