'use client';
import { useState } from 'react';
import Link from 'next/link';
import { api } from '../../lib/api';
import { useAdminGet } from './_shared';
import { showToast } from '../../lib/ui/feedback';

/* Port 1-1 từ PKV/templates/Admin/admin_tickets.html.
 * API: GET /admin/tickets/?status= (AdminTicketListView) trả list ticket;
 *      PATCH /admin/tickets/ { ticket_id, admin_reply, status } để phản hồi.
 * CSS <style> riêng của template được port nguyên vào <style> bên dưới. */

const TICKET_CSS = `
.ticket-card {
    background: var(--glass-bg);
    backdrop-filter: blur(20px);
    border: 1px solid var(--glass-border);
    border-radius: 1.25rem;
    transition: all 0.3s ease;
}
.ticket-card:hover { border-color: rgba(24,255,255,0.15); }
.status-badge { font-size: 0.6rem; font-weight: 800; padding: 0.15rem 0.5rem; border-radius: 0.3rem; text-transform: uppercase; }
.status-open { background: rgba(59,130,246,0.15); color: var(--sc-brand-400); border: 1px solid rgba(59,130,246,0.3); }
.status-in_progress { background: rgba(251,191,36,0.15); color: var(--sc-warn-400); border: 1px solid rgba(251,191,36,0.3); }
.status-resolved { background: rgba(34,197,94,0.15); color: var(--sc-safe-500); border: 1px solid rgba(34,197,94,0.3); }
.status-closed { background: rgba(148,163,184,0.15); color: var(--sc-slate-400); border: 1px solid rgba(148,163,184,0.3); }
.priority-low { color: var(--sc-slate-400); } .priority-medium { color: var(--sc-warn-400); } .priority-high { color: var(--sc-warn-500); } .priority-critical { color: var(--sc-danger-500); }
`;

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

const STATUS_LABELS: Record<string, string> = {
  open: 'Mở',
  in_progress: 'Đang xử lý',
  resolved: 'Đã giải quyết',
  closed: 'Đã đóng',
};

const CATEGORY_LABELS: Record<string, string> = {
  bug: 'Lỗi hệ thống',
  feature: 'Đề xuất',
  account: 'Tài khoản',
  other: 'Khác',
};

const PRIORITY_LABELS: Record<string, string> = {
  low: 'Thấp',
  medium: 'TB',
  high: 'Cao',
  critical: 'Nghiêm trọng',
};

const STATUS_TABS = ['open', 'in_progress', 'resolved', 'closed'];

function statusLabel(s?: string): string {
  return (s && STATUS_LABELS[s]) || s || '';
}

function categoryLabel(c?: string): string {
  return (c && CATEGORY_LABELS[c]) || c || '';
}

function priorityLabel(p?: string): string {
  return (p && PRIORITY_LABELS[p]) || p || '';
}

function timeAgo(dt?: string): string {
  if (!dt) return '';
  const diff = (Date.now() - new Date(dt).getTime()) / 1000;
  if (Number.isNaN(diff)) return '';
  if (diff < 60) return 'Vừa xong';
  if (diff < 3600) return `${Math.floor(diff / 60)}ph`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}g`;
  return `${Math.floor(diff / 86400)}ng`;
}

function asList(data: Ticket[] | { results?: Ticket[] } | null): Ticket[] {
  if (!data) return [];
  return Array.isArray(data) ? data : data.results || [];
}

export default function Tickets() {
  const [statusFilter, setStatusFilter] = useState('');
  const [expandedTicket, setExpandedTicket] = useState<number | null>(null);
  const [replyText, setReplyText] = useState('');
  const [replyStatus, setReplyStatus] = useState('');
  const [replyLoading, setReplyLoading] = useState(false);

  const { data, loading, refetch } = useAdminGet<Ticket[] | { results?: Ticket[] }>(
    `/admin/tickets/${statusFilter ? `?status=${statusFilter}` : ''}`,
  );
  const tickets = asList(data);

  const stats = {
    total: tickets.length,
    open: tickets.filter((t) => t.status === 'open').length,
    in_progress: tickets.filter((t) => t.status === 'in_progress').length,
    resolved: tickets.filter((t) => t.status === 'resolved').length,
  };

  const toggleExpand = (t: Ticket) => {
    if (expandedTicket === t.id) {
      setExpandedTicket(null);
    } else {
      setExpandedTicket(t.id);
      setReplyText(t.admin_reply || '');
      setReplyStatus(t.status || '');
    }
  };

  const submitReply = async (ticket: Ticket) => {
    setReplyLoading(true);
    try {
      await api.patch('/admin/tickets/', {
        ticket_id: ticket.id,
        admin_reply: replyText,
        status: replyStatus,
      });
      showToast('Đã cập nhật ticket!', 'success');
      setExpandedTicket(null);
      refetch();
    } catch (e) {
      showToast(e instanceof Error ? e.message : 'Lỗi kết nối', 'error');
    } finally {
      setReplyLoading(false);
    }
  };

  const pickStatus = (s: string) => {
    setStatusFilter(statusFilter === s ? '' : s);
  };

  return (
    <div className="max-w-6xl mx-auto px-4 py-8">
      <style>{TICKET_CSS}</style>

      {/* Breadcrumb */}
      <nav className="flex items-center gap-2 text-sm mb-5 text-white/55">
        <Link href="/admin-cp/" className="hover:text-brand-400 transition">
          <i className="bi bi-speedometer2"></i> Admin
        </Link>
        <i className="bi bi-chevron-right text-[10px]"></i>
        <span className="text-white/60">Quản lý Tickets</span>
      </nav>

      {/* Header */}
      <div className="flex items-center gap-4 mb-8">
        <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-danger-500/20 to-warn-500/20 flex items-center justify-center border border-danger-500/20">
          <i className="bi bi-ticket-detailed-fill text-xl text-danger-400"></i>
        </div>
        <div>
          <h1 className="text-2xl font-black text-white">Quản lý Tickets</h1>
          <p className="text-xs text-white/55">Phản hồi báo lỗi và góp ý từ người dùng</p>
        </div>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-4 gap-3 mb-6">
        <div className="ticket-card p-4 text-center">
          <div className="text-2xl font-black text-white">{stats.total}</div>
          <div className="text-[10px] font-bold text-white/45 uppercase">Tổng</div>
        </div>
        <div className="ticket-card p-4 text-center cursor-pointer" onClick={() => pickStatus('open')}>
          <div className="text-2xl font-black text-brand-400">{stats.open}</div>
          <div className="text-[10px] font-bold text-white/45 uppercase">Mở</div>
        </div>
        <div className="ticket-card p-4 text-center cursor-pointer" onClick={() => pickStatus('in_progress')}>
          <div className="text-2xl font-black text-warn-400">{stats.in_progress}</div>
          <div className="text-[10px] font-bold text-white/45 uppercase">Đang xử lý</div>
        </div>
        <div className="ticket-card p-4 text-center cursor-pointer" onClick={() => pickStatus('resolved')}>
          <div className="text-2xl font-black text-safe-400">{stats.resolved}</div>
          <div className="text-[10px] font-bold text-white/45 uppercase">Đã xử lý</div>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="flex items-center gap-2 mb-4 flex-wrap">
        <button
          type="button"
          onClick={() => setStatusFilter('')}
          className={`px-3 py-1.5 rounded-lg text-[10px] font-bold border transition-all ${
            !statusFilter ? 'bg-brand-400/10 text-brand-400 border-brand-500/30' : 'bg-white/5 text-white/55 border-white/10'
          }`}
        >
          Tất cả
        </button>
        {STATUS_TABS.map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => setStatusFilter(s)}
            className={`px-3 py-1.5 rounded-lg text-[10px] font-bold border transition-all ${
              statusFilter === s ? 'bg-brand-400/10 text-brand-400 border-brand-500/30' : 'bg-white/5 text-white/55 border-white/10'
            }`}
          >
            {statusLabel(s)}
          </button>
        ))}
      </div>

      {/* Loading */}
      {loading && (
        <div className="text-center py-12">
          <div className="w-8 h-8 border-2 border-brand-400 border-t-transparent rounded-full animate-spin mx-auto"></div>
        </div>
      )}

      {/* Tickets List */}
      {!loading && (
        <div className="space-y-3">
          {tickets.map((t) => (
            <div key={t.id} className="ticket-card overflow-hidden">
              <div className="p-5 cursor-pointer" onClick={() => toggleExpand(t)}>
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                      <span className={`status-badge status-${t.status || ''}`}>{statusLabel(t.status)}</span>
                      <span className={`text-[10px] font-bold priority-${t.priority || ''}`}>● {priorityLabel(t.priority)}</span>
                      <span className="text-[10px] font-bold text-white/35 bg-white/5 px-2 py-0.5 rounded">{categoryLabel(t.category)}</span>
                    </div>
                    <h4 className="text-sm font-bold text-white mb-1">{t.title}</h4>
                    <div className="flex items-center gap-3 text-[10px] text-white/55">
                      <span>{t.author_name}</span>
                      <span>
                        @<span>{t.author_username}</span>
                      </span>
                      <span>·</span>
                      <span>{timeAgo(t.created_at)}</span>
                    </div>
                  </div>
                  <i className={`bi text-white/35 transition shrink-0 ${expandedTicket === t.id ? 'bi-chevron-up' : 'bi-chevron-down'}`}></i>
                </div>
              </div>

              {/* Expanded Detail */}
              {expandedTicket === t.id && (
                <div className="px-5 pb-5 border-t border-white/5">
                  <div className="mt-4 mb-4 p-4 rounded-xl bg-white/[0.02] text-sm text-white/60 leading-relaxed whitespace-pre-wrap">
                    {t.description}
                  </div>

                  {/* Admin Reply Form */}
                  <div className="space-y-3">
                    <label className="text-xs font-bold text-white/55">Phản hồi Admin</label>
                    <textarea
                      rows={3}
                      value={replyText}
                      onChange={(e) => setReplyText(e.target.value)}
                      placeholder="Viết phản hồi cho người dùng..."
                      className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white text-sm focus:outline-none focus:border-brand-400/30 transition resize-none"
                    ></textarea>

                    <div className="flex items-center justify-between gap-4">
                      <div className="flex items-center gap-2">
                        <label className="text-[10px] font-bold text-white/45">Trạng thái:</label>
                        <select
                          value={replyStatus}
                          onChange={(e) => setReplyStatus(e.target.value)}
                          className="bg-white/5 border border-white/10 rounded-lg px-3 py-1.5 text-white text-xs focus:outline-none focus:border-brand-400/30"
                        >
                          <option value="open">Mở</option>
                          <option value="in_progress">Đang xử lý</option>
                          <option value="resolved">Đã giải quyết</option>
                          <option value="closed">Đóng</option>
                        </select>
                      </div>
                      <button
                        type="button"
                        disabled={replyLoading}
                        onClick={() => void submitReply(t)}
                        className="bg-gradient-to-r from-brand-400 to-brand-600 text-[var(--sc-night-1)] px-5 py-2 rounded-lg font-bold text-xs hover:scale-105 transition-all disabled:opacity-50"
                      >
                        {!replyLoading ? (
                          <span className="flex items-center gap-1.5">
                            <i className="bi bi-send-fill"></i> Gửi phản hồi
                          </span>
                        ) : (
                          <span>Đang gửi...</span>
                        )}
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))}

          {tickets.length === 0 && (
            <div className="text-center py-16 ticket-card">
              <i className="bi bi-inbox text-4xl text-white/20 mb-3 block"></i>
              <p className="text-white/45 text-sm font-bold">Không có ticket nào</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
