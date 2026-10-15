'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { api } from '../../lib/api';
import { Spinner } from '../../components/ui';

interface Ticket {
  id: number;
  title: string;
  description: string;
  category: string;
  priority: string;
  status: string;
  admin_reply?: string | null;
  created_at?: string;
}

function timeAgo(dt?: string): string {
  if (!dt) return '';
  const diff = (Date.now() - new Date(dt).getTime()) / 1000;
  if (diff < 60) return 'Vừa xong';
  if (diff < 3600) return `${Math.floor(diff / 60)} phút trước`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} giờ trước`;
  return `${Math.floor(diff / 86400)} ngày trước`;
}

function statusLabel(s: string): string {
  const m: Record<string, string> = { open: 'Mở', in_progress: 'Đang xử lý', resolved: 'Đã giải quyết', closed: 'Đã đóng' };
  return m[s] || s;
}

function categoryLabel(c: string): string {
  const m: Record<string, string> = { bug: 'Lỗi hệ thống', feature: 'Đề xuất tính năng', account: 'Vấn đề tài khoản', other: 'Khác' };
  return m[c] || c;
}

export default function Tickets() {
  const [tickets, setTickets] = useState<Ticket[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(true);
  const [newTitle, setNewTitle] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newCategory, setNewCategory] = useState('bug');
  const [newPriority, setNewPriority] = useState('medium');
  const [createLoading, setCreateLoading] = useState(false);
  const [msg, setMsg] = useState('');

  const fetchTickets = () => {
    setLoading(true);
    api
      .get<Ticket[] | { results?: Ticket[] }>('/tickets/')
      .then((r) => setTickets(Array.isArray(r) ? r : r.results || []))
      .catch(() => setTickets([]))
      .finally(() => setLoading(false));
  };

  useEffect(fetchTickets, []);

  const submitTicket = () => {
    if (!newTitle.trim() || !newDescription.trim()) {
      setMsg('Vui lòng điền đầy đủ tiêu đề và mô tả');
      return;
    }
    setCreateLoading(true);
    api
      .post('/tickets/', { title: newTitle, description: newDescription, category: newCategory, priority: newPriority })
      .then(() => {
        setMsg('Đã gửi phiếu hỗ trợ! Admin sẽ phản hồi sớm.');
        setNewTitle('');
        setNewDescription('');
        setShowCreate(false);
        fetchTickets();
      })
      .catch(() => setMsg('Gửi phiếu thất bại'))
      .finally(() => setCreateLoading(false));
  };

  return (
    <div className="max-w-4xl mx-auto px-4 py-8">
      <nav className="flex items-center gap-2 text-sm mb-5 text-white/55">
        <Link href="/" className="hover:text-brand-400 transition"><i className="bi bi-house-door"></i> Trang chủ</Link>
        <i className="bi bi-chevron-right text-[10px]"></i>
        <Link href="/profile/" className="hover:text-brand-400 transition">Hồ sơ</Link>
        <i className="bi bi-chevron-right text-[10px]"></i>
        <span className="text-white/60">Báo lỗi & Góp ý</span>
      </nav>

      <div className="flex items-center justify-between mb-8">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-danger-500/20 to-warn-500/20 flex items-center justify-center border border-danger-500/20">
            <i className="bi bi-bug-fill text-xl text-danger-400"></i>
          </div>
          <div>
            <h1 className="text-2xl font-black text-white">Báo lỗi & Góp ý</h1>
            <p className="text-xs text-white/55">Gửi phản hồi để chúng tôi cải thiện</p>
          </div>
        </div>
        <button onClick={() => setShowCreate(!showCreate)} className="bg-gradient-to-r from-brand-400 to-brand-600 text-[var(--sc-night-1)] px-5 py-2.5 rounded-xl font-bold text-sm hover:scale-105 transition-all shadow-lg shadow-brand-500/20 flex items-center gap-2">
          <i className="bi bi-plus-lg"></i> Tạo phiếu mới
        </button>
      </div>

      {msg && <div className="mb-4 p-3 rounded-xl bg-brand-500/10 border border-brand-500/20 text-brand-300 text-xs font-bold">{msg}</div>}

      {showCreate && (
        <div className="rounded-[1.25rem] border border-white/10 bg-white/[0.02] p-6 mb-6">
          <h3 className="text-sm font-bold text-white/70 mb-4 flex items-center gap-2"><i className="bi bi-pencil-square text-brand-400"></i> Tạo phiếu hỗ trợ mới</h3>
          <div className="space-y-4">
            <input type="text" value={newTitle} onChange={(e) => setNewTitle(e.target.value)} placeholder="Tiêu đề vấn đề..."
              className="w-full bg-white/5 border border-white/10 rounded-xl px-5 py-3 text-white font-semibold focus:outline-none focus:border-brand-400/30 transition" />
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs font-bold text-white/55 mb-1 block">Loại</label>
                <select value={newCategory} onChange={(e) => setNewCategory(e.target.value)} className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white text-sm focus:outline-none focus:border-brand-400/30">
                  <option value="bug">Lỗi hệ thống</option>
                  <option value="feature">Đề xuất tính năng</option>
                  <option value="account">Vấn đề tài khoản</option>
                  <option value="other">Khác</option>
                </select>
              </div>
              <div>
                <label className="text-xs font-bold text-white/55 mb-1 block">Mức độ</label>
                <select value={newPriority} onChange={(e) => setNewPriority(e.target.value)} className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-2.5 text-white text-sm focus:outline-none focus:border-brand-400/30">
                  <option value="low">Thấp</option>
                  <option value="medium">Trung bình</option>
                  <option value="high">Cao</option>
                  <option value="critical">Nghiêm trọng</option>
                </select>
              </div>
            </div>
            <textarea value={newDescription} onChange={(e) => setNewDescription(e.target.value)} rows={5} placeholder="Mô tả chi tiết lỗi hoặc góp ý..."
              className="w-full bg-white/5 border border-white/10 rounded-xl px-5 py-3 text-white text-sm focus:outline-none focus:border-brand-400/30 transition resize-none" />
            <div className="flex items-center justify-end gap-3">
              <button onClick={() => setShowCreate(false)} className="text-sm font-bold text-white/45 hover:text-white transition">Hủy</button>
              <button onClick={submitTicket} disabled={createLoading}
                className="bg-gradient-to-r from-brand-400 to-brand-600 text-[var(--sc-night-1)] px-6 py-2.5 rounded-xl font-bold text-sm hover:scale-105 transition-all disabled:opacity-50">
                {createLoading ? 'Đang gửi...' : <span className="flex items-center gap-2"><i className="bi bi-send-fill"></i> Gửi phiếu</span>}
              </button>
            </div>
          </div>
        </div>
      )}

      <h3 className="text-sm font-bold text-white/60 uppercase tracking-wider mb-4">Phiếu hỗ trợ của bạn</h3>

      {loading ? (
        <Spinner />
      ) : (
        <div className="space-y-3">
          {tickets.map((t) => (
            <div key={t.id} className="rounded-[1.25rem] border border-white/10 bg-white/[0.02] p-5 hover:border-brand-400/20 transition-all">
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1.5">
                    <span className={`text-[0.6rem] font-extrabold px-2 py-0.5 rounded border uppercase tracking-wide status-${t.status}`}>{statusLabel(t.status)}</span>
                    <span className="text-[10px] font-bold text-white/35">● {t.priority}</span>
                  </div>
                  <h4 className="text-sm font-bold text-white mb-1">{t.title}</h4>
                  <p className="text-xs text-white/55 line-clamp-2">{t.description}</p>
                  <div className="flex items-center gap-3 mt-2 text-[10px] text-white/55">
                    <span>{categoryLabel(t.category)}</span><span>·</span><span>{timeAgo(t.created_at)}</span>
                  </div>
                </div>
              </div>
              {t.admin_reply && (
                <div className="mt-4 p-3 rounded-xl bg-brand-500/5 border border-brand-500/10">
                  <div className="text-[10px] font-bold text-brand-400 uppercase tracking-wider mb-1"><i className="bi bi-patch-check-fill mr-1"></i> Phản hồi từ admin</div>
                  <p className="text-xs text-white/60 leading-relaxed">{t.admin_reply}</p>
                </div>
              )}
            </div>
          ))}
          {tickets.length === 0 && (
            <div className="text-center py-16 rounded-[1.25rem] border border-white/10 bg-white/[0.02]">
              <i className="bi bi-ticket-detailed text-4xl text-white/20 mb-3 block"></i>
              <p className="text-white/45 text-sm font-bold">Chưa có phiếu hỗ trợ nào</p>
              <p className="text-white/35 text-xs mt-1">Tạo phiếu mới để báo lỗi hoặc góp ý</p>
            </div>
          )}
        </div>
      )}
      <Link href="/forum/" className="inline-flex items-center gap-2 mt-6 text-brand-400 text-xs font-black uppercase tracking-widest hover:text-brand-300">
        <i className="bi bi-arrow-left"></i> Về diễn đàn
      </Link>
    </div>
  );
}
