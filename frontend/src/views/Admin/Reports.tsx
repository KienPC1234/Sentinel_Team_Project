'use client';
import { useMemo, useState } from 'react';
import Link from 'next/link';
import { api, mediaUrl } from '../../lib/api';
import { useAdminGet, AdminNavbar } from './_shared';
import { showToast } from '../../lib/ui/feedback';

/* Port 1-1 từ PKV/templates/Admin/reports.html.
 * API đọc: GET /admin/reports/?status=&type=&severity=&q=&sort= (AdminReportsView).
 * Thao tác duyệt/từ chối: POST /admin/reports/<id>/action/ (AdminReportActionView).
 * AI analyze + ghi chú kiểm duyệt giữ nguyên endpoint Django gốc của template. */

interface Report {
  id: number;
  target_type?: string;
  target_type_display?: string;
  target_value?: string;
  scam_type?: string;
  scam_type_display?: string;
  severity?: string;
  status?: string;
  description?: string;
  reporter_email?: string;
  reporter?: { username?: string } | string;
  moderation_note?: string;
  ocr_text?: string;
  ai_analysis?: Record<string, unknown> | string | null;
  created_at?: string;
  evidence_file?: string | { url?: string } | null;
  evidence_url?: string;
  evidence_images?: Array<string | { url?: string; caption?: string }>;
  scammer_name?: string;
  scammer_phone?: string;
  scammer_bank_name?: string;
  scammer_bank_account?: string;
}

interface SelectOption {
  value: string;
  label: string;
}

/* ---------- helpers ---------- */

function asList(data: Report[] | { results?: Report[] } | null): Report[] {
  if (!data) return [];
  return Array.isArray(data) ? data : data.results || [];
}

function reporterName(r: Report): string {
  if (typeof r.reporter === 'string') return r.reporter;
  if (r.reporter && typeof r.reporter === 'object' && r.reporter.username) return r.reporter.username;
  return r.reporter_email || 'N/A';
}

function initial(name: string): string {
  return name ? name.slice(0, 1).toUpperCase() : '?';
}

function targetIcon(t?: string): string {
  if (t === 'phone') return 'bi-telephone';
  if (t === 'domain') return 'bi-globe';
  if (t === 'account') return 'bi-bank';
  if (t === 'email') return 'bi-envelope';
  return 'bi-chat-dots';
}

function severityClass(s?: string): string {
  if (s === 'low') return 'bg-safe-500/10 text-safe-400 border-safe-500/20';
  if (s === 'medium') return 'bg-warn-500/10 text-warn-400 border-warn-500/20';
  if (s === 'high') return 'bg-danger-500/10 text-danger-400 border-danger-500/20';
  return 'bg-danger-600/20 text-danger-500 border-danger-600/30';
}

function severityColor(s?: string): string {
  if (s === 'medium') return 'var(--sc-warn-500)';
  if (s === 'high') return 'var(--sc-danger-500)';
  if (s === 'critical') return 'var(--sc-danger-600)';
  return 'var(--sc-safe-500)';
}

function splitDate(iso?: string): { date: string; time: string } {
  if (!iso) return { date: '', time: '' };
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return { date: iso, time: '' };
  const pad = (n: number) => String(n).padStart(2, '0');
  return {
    date: `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()}`,
    time: `${pad(d.getHours())}:${pad(d.getMinutes())}`,
  };
}

function mainEvidenceUrl(r: Report): string {
  if (r.evidence_url) return r.evidence_url;
  if (typeof r.evidence_file === 'string') return r.evidence_file;
  if (r.evidence_file && typeof r.evidence_file === 'object' && r.evidence_file.url) return r.evidence_file.url;
  return '';
}

function galleryFor(r: Report): Array<{ url: string; caption: string }> {
  const out: Array<{ url: string; caption: string }> = [];
  const main = mainEvidenceUrl(r);
  if (main) out.push({ url: main, caption: 'Ảnh bằng chứng chính (OCR)' });
  (r.evidence_images || []).forEach((img, i) => {
    if (typeof img === 'string') out.push({ url: img, caption: `Ảnh bổ sung ${i + 1}` });
    else if (img && img.url) out.push({ url: img.url, caption: img.caption || `Ảnh bổ sung ${i + 1}` });
  });
  return out;
}

function aiObject(r: Report): Record<string, unknown> | null {
  const raw = r.ai_analysis;
  if (raw && typeof raw === 'object') return Object.keys(raw).length ? raw : null;
  if (typeof raw === 'string' && raw && raw !== '{}') {
    try {
      const parsed = JSON.parse(raw) as Record<string, unknown>;
      return Object.keys(parsed).length ? parsed : null;
    } catch {
      return null;
    }
  }
  return null;
}

function asStr(v: unknown): string {
  return v === undefined || v === null ? '' : String(v);
}

function asNum(v: unknown): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

async function postDjango(path: string, body: unknown): Promise<Record<string, unknown>> {
  const match = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]*)/);
  const csrf = match ? decodeURIComponent(match[1]) : '';
  const res = await fetch(path, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf },
    body: JSON.stringify(body ?? {}),
  });
  return (await res.json()) as Record<string, unknown>;
}

/* ---------- LiquidSelect (port Alpine liquidSelect — reports.html) ---------- */

const SELECT_CSS = `
.dropdown-container { overflow: visible !important; }
.liquid-custom-select { position: relative; width: 100%; user-select: none; }
.liquid-select-trigger { background: rgba(0,0,0,0.2); backdrop-filter: blur(12px); border: 1px solid rgba(255,255,255,0.1); border-radius: 1.25rem; color: var(--sc-white); display: flex; align-items: center; justify-content: space-between; cursor: pointer; transition: all 0.3s cubic-bezier(0.4,0,0.2,1); }
.liquid-select-trigger:hover { background: rgba(255,255,255,0.1); border-color: rgba(0,229,255,0.3); box-shadow: 0 0 20px rgba(0,229,255,0.1); }
.liquid-select-trigger.active { border-color: var(--accent-cyan); box-shadow: 0 0 25px rgba(24,255,255,0.15); }
.liquid-select-dropdown { position: absolute; top: calc(100% + 8px); left: 0; min-width: 100%; width: max-content; max-width: min(90vw, 560px); background: linear-gradient(145deg, rgba(16, 22, 46, 0.88) 0%, rgba(10, 14, 30, 0.95) 100%) !important; backdrop-filter: blur(36px) saturate(190%) !important; -webkit-backdrop-filter: blur(36px) saturate(190%) !important; border: 1px solid rgba(255,255,255,0.18) !important; border-radius: 1.25rem; box-shadow: 0 25px 70px -10px rgba(0,0,0,0.85), inset 0 1px 0 rgba(255,255,255,0.25) !important; z-index: 999999; overflow: hidden; max-height: min(320px, 60vh); overflow-y: auto; transform-origin: top; }
.liquid-select-dropdown.entered { opacity: 1; transform: translateY(0) scale(1); }
.liquid-select-option { padding: 0.5rem 1rem; color: rgba(255,255,255,0.7); cursor: pointer; transition: all 0.2s ease; display: flex; align-items: center; gap: 0.75rem; font-size: 0.8rem; font-weight: 500; }
.liquid-select-option:hover { background: rgba(24,255,255,0.08); color: var(--accent-cyan); padding-left: 1.25rem; }
.liquid-select-option.selected { background: rgba(24,255,255,0.12); color: var(--accent-cyan); font-weight: 700; }
.liquid-select-arrow { transition: transform 0.4s cubic-bezier(0.175,0.885,0.32,1.275); opacity: 0.4; }
.active .liquid-select-arrow, .rotate-180 { transform: rotate(180deg); color: var(--accent-cyan); opacity: 1; }
`;

function LiquidSelect({
  name,
  value,
  placeholder,
  options,
  className = '',
  onChange,
}: {
  name: string;
  value: string;
  placeholder: string;
  options: SelectOption[];
  className?: string;
  onChange: (value: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const current = options.find((o) => o.value === value);
  return (
    <div className={`dropdown-container liquid-custom-select ${className}`}>
      <input type="hidden" name={name} value={value} readOnly />
      <div
        className={`liquid-select-trigger py-2.5 px-4 text-[11px]${open ? ' active' : ''}`}
        onClick={() => setOpen((o) => !o)}
      >
        <span className="truncate">{current ? current.label : placeholder}</span>
        <i className={`bi bi-chevron-down liquid-select-arrow${open ? ' rotate-180' : ''}`}></i>
      </div>
      {open && (
        <div className="liquid-select-dropdown entered">
          {options.map((option) => (
            <div
              key={option.value || '__empty'}
              className={`liquid-select-option${value === option.value ? ' selected' : ''}`}
              onClick={() => {
                onChange(option.value);
                setOpen(false);
              }}
            >
              <span>{option.label}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ---------- Image viewer (port openImageViewer) ---------- */

function ImageViewer({
  images,
  startIndex,
  onClose,
}: {
  images: Array<{ url: string; caption: string }>;
  startIndex: number;
  onClose: () => void;
}) {
  const [idx, setIdx] = useState(startIndex);
  const img = images[idx];
  if (!img) return null;
  return (
    <div className="fixed inset-0 z-[1000000] bg-black/90 flex items-center justify-center p-4" onClick={onClose}>
      <div className="relative w-full max-w-5xl" onClick={(e) => e.stopPropagation()}>
        <button
          type="button"
          onClick={onClose}
          className="absolute -top-3 -right-3 z-10 w-9 h-9 rounded-full bg-white/10 border border-white/20 text-white/70 hover:text-white flex items-center justify-center"
        >
          <i className="bi bi-x-lg"></i>
        </button>
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src={mediaUrl(img.url)} alt={img.caption} className="w-full max-h-[80vh] object-contain rounded-xl" />
        <div className="absolute bottom-0 inset-x-0 bg-gradient-to-t from-black/90 to-transparent p-6 rounded-b-xl">
          <p className="text-sm font-bold text-white">{img.caption}</p>
          <p className="text-[10px] text-white/55 mt-1">
            {idx + 1} / {images.length}
          </p>
        </div>
        {images.length > 1 && (
          <>
            <button
              type="button"
              onClick={() => setIdx((i) => (i - 1 + images.length) % images.length)}
              className="absolute left-3 top-1/2 -translate-y-1/2 w-10 h-10 rounded-full bg-black/60 text-white flex items-center justify-center hover:bg-black/80 transition-all border border-white/10"
            >
              <i className="bi bi-chevron-left"></i>
            </button>
            <button
              type="button"
              onClick={() => setIdx((i) => (i + 1) % images.length)}
              className="absolute right-3 top-1/2 -translate-y-1/2 w-10 h-10 rounded-full bg-black/60 text-white flex items-center justify-center hover:bg-black/80 transition-all border border-white/10"
            >
              <i className="bi bi-chevron-right"></i>
            </button>
          </>
        )}
      </div>
    </div>
  );
}

/* ---------- Detail modal (port showReportDetails) ---------- */

function ReportDetailModal({
  report,
  onClose,
  onRunAi,
  onOpenImage,
  onAction,
}: {
  report: Report;
  onClose: () => void;
  onRunAi: (report: Report) => Promise<void>;
  onOpenImage: (images: Array<{ url: string; caption: string }>, index: number) => void;
  onAction: (report: Report, action: 'approve' | 'reject') => Promise<void>;
}) {
  const [note, setNote] = useState(report.moderation_note || '');
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const gallery = galleryFor(report);
  const ai = aiObject(report);
  const sevColor = severityColor(report.severity);
  const hasScammer = Boolean(report.scammer_name || report.scammer_phone || report.scammer_bank_account);
  const riskScore = ai ? asNum(ai.risk_score) : 0;
  const scoreColor = riskScore > 75 ? 'var(--sc-danger-500)' : riskScore > 40 ? 'var(--sc-warn-500)' : 'var(--sc-safe-500)';
  const indicators = ai && Array.isArray(ai.indicators) ? (ai.indicators as unknown[]) : [];

  const saveNote = async () => {
    setSaving(true);
    try {
      await postDjango(`/admin-cp/reports/${report.id}/note/`, { note });
      setSaved(true);
      showToast('Đã lưu ghi chú', 'success');
      setTimeout(() => setSaved(false), 2000);
    } catch {
      showToast('Lưu ghi chú thất bại', 'error');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[999999] bg-black/70 backdrop-blur-sm flex items-start justify-center overflow-y-auto p-4 custom-scrollbar">
      <div className="w-full max-w-[900px] rounded-[2rem] border border-white/10 bg-[var(--sc-night-1)] my-8">
        <div className="flex items-start justify-between gap-4 p-6 border-b border-white/5">
          <div className="flex items-center gap-3 text-left">
            <div className="w-11 h-11 rounded-2xl bg-brand-500/10 text-brand-400 flex items-center justify-center border border-brand-500/20">
              <i className="bi bi-file-earmark-text text-lg"></i>
            </div>
            <div>
              <h2 className="text-lg font-black text-white tracking-tight">Báo cáo #{report.id}</h2>
              <p className="text-[9px] font-bold text-white/35 uppercase tracking-widest mt-0.5">
                {report.created_at || ''} • {reporterName(report)}
              </p>
            </div>
          </div>
          <button type="button" onClick={onClose} className="text-white/55 hover:text-white transition-colors">
            <i className="bi bi-x-lg text-lg"></i>
          </button>
        </div>

        <div className="space-y-6 p-8 max-h-[80vh] overflow-y-auto custom-scrollbar">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 p-5 rounded-2xl bg-white/[0.02] border border-white/5">
            <div className="space-y-1">
              <p className="text-[8px] font-black text-white/35 uppercase tracking-[0.2em]">Đối tượng</p>
              <p className="text-sm font-bold text-white">{report.target_type_display || report.target_type || ''}</p>
            </div>
            <div className="space-y-1">
              <p className="text-[8px] font-black text-white/35 uppercase tracking-[0.2em]">Giá trị</p>
              <p className="text-sm font-bold text-brand-400 break-all">{report.target_value}</p>
            </div>
            <div className="space-y-1">
              <p className="text-[8px] font-black text-white/35 uppercase tracking-[0.2em]">Loại lừa đảo</p>
              <p className="text-sm font-bold text-white">{report.scam_type_display || report.scam_type || ''}</p>
            </div>
            <div className="space-y-1">
              <p className="text-[8px] font-black text-white/35 uppercase tracking-[0.2em]">Cấp độ</p>
              <span
                className="inline-block px-2 py-0.5 rounded text-[9px] font-black uppercase tracking-wider border"
                style={{ background: `${sevColor}10`, color: sevColor, borderColor: `${sevColor}30` }}
              >
                {report.severity}
              </span>
            </div>
          </div>

          {hasScammer && (
            <div className="space-y-3">
              <h3 className="text-[10px] font-black text-danger-400 uppercase tracking-[0.2em] ml-1 flex items-center gap-2">
                <i className="bi bi-person-x"></i> Thông tin kẻ lừa đảo
              </h3>
              <div className="p-5 rounded-2xl bg-danger-500/[0.03] border border-danger-500/10 grid grid-cols-2 gap-4">
                {report.scammer_name && (
                  <div>
                    <p className="text-[8px] font-black text-danger-400/40 uppercase">Họ tên</p>
                    <p className="text-sm font-bold text-white">{report.scammer_name}</p>
                  </div>
                )}
                {report.scammer_phone && (
                  <div>
                    <p className="text-[8px] font-black text-danger-400/40 uppercase">SĐT</p>
                    <p className="text-sm font-bold text-white">{report.scammer_phone}</p>
                  </div>
                )}
                {report.scammer_bank_name && (
                  <div>
                    <p className="text-[8px] font-black text-danger-400/40 uppercase">Ngân hàng</p>
                    <p className="text-sm font-bold text-white">{report.scammer_bank_name}</p>
                  </div>
                )}
                {report.scammer_bank_account && (
                  <div>
                    <p className="text-[8px] font-black text-danger-400/40 uppercase">Số TK</p>
                    <p className="text-sm font-bold text-white">{report.scammer_bank_account}</p>
                  </div>
                )}
              </div>
            </div>
          )}

          <div className="space-y-3">
            <h3 className="text-[10px] font-black text-white/55 uppercase tracking-[0.2em] ml-1">Mô tả chi tiết</h3>
            <div className="p-5 rounded-2xl bg-white/[0.02] border border-white/5 text-sm text-white/60 leading-relaxed ai-markdown max-h-[200px] overflow-y-auto custom-scrollbar whitespace-pre-wrap">
              {report.description}
            </div>
          </div>

          {report.ocr_text && (
            <div className="space-y-3">
              <h3 className="text-[10px] font-black text-brand-400 uppercase tracking-[0.2em] ml-1 flex items-center gap-2">
                <i className="bi bi-card-text"></i> Văn bản OCR
              </h3>
              <div className="p-5 rounded-2xl bg-brand-500/[0.03] border border-brand-500/10 text-xs text-white/60 leading-relaxed font-mono whitespace-pre-line max-h-[150px] overflow-y-auto custom-scrollbar">
                {report.ocr_text}
              </div>
            </div>
          )}

          {gallery.length > 0 && (
            <div className="space-y-3">
              <h3 className="text-[10px] font-black text-white/55 uppercase tracking-[0.2em] ml-1 flex items-center gap-2">
                <i className="bi bi-images"></i> Bằng chứng ({gallery.length} ảnh)
              </h3>
              <div className={`grid grid-cols-2 ${gallery.length > 2 ? 'md:grid-cols-3' : ''} gap-3`}>
                {gallery.map((img, i) => (
                  <div
                    key={`${img.url}-${i}`}
                    className="group/img relative rounded-2xl overflow-hidden border border-white/10 cursor-zoom-in hover:border-brand-500/50 transition-all aspect-[4/3] bg-black/40"
                    onClick={() => onOpenImage(gallery, i)}
                  >
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img
                      src={mediaUrl(img.url)}
                      alt={img.caption}
                      className="w-full h-full object-cover transition-transform group-hover/img:scale-105"
                      loading="lazy"
                    />
                    <div className="absolute bottom-0 inset-x-0 bg-gradient-to-t from-black/80 to-transparent p-2">
                      <p className="text-[9px] font-bold text-white/60">{img.caption}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {ai && (
            <div className="space-y-3">
              <h3 className="text-[10px] font-black text-brand2-400 uppercase tracking-[0.2em] ml-1 flex items-center gap-2">
                <i className="bi bi-robot"></i> AI Phân tích
              </h3>
              <div className="p-5 rounded-2xl bg-brand2-500/[0.03] border border-brand2-500/10 space-y-4">
                <div className="flex items-center justify-between border-b border-brand2-500/10 pb-3">
                  <div>
                    <p className="text-[9px] font-black text-brand2-400/40 uppercase tracking-widest">Đánh giá</p>
                    <p className="text-sm font-bold text-white">
                      {ai.is_scam ? '[CẢNH BÁO] CÓ DẤU HIỆU LỪA ĐẢO' : '[AN TOÀN] BÌNH THƯỜNG'}
                    </p>
                  </div>
                  <div className="text-right">
                    <p className="text-[9px] font-black text-brand2-400/40 uppercase tracking-widest">Điểm rủi ro</p>
                    <p className="text-3xl font-black" style={{ color: scoreColor }}>
                      {riskScore}
                      <span className="text-sm text-white/35">/100</span>
                    </p>
                  </div>
                </div>
                <div>
                  <p className="text-[9px] font-black text-brand2-400/40 uppercase tracking-widest mb-1">Phân tích</p>
                  <p className="text-xs text-white/60 leading-relaxed">
                    {asStr(ai.explanation) || asStr(ai.reason) || 'N/A'}
                  </p>
                </div>
                {indicators.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {indicators.map((ind, i) => (
                      <span
                        key={i}
                        className="px-2 py-0.5 rounded-lg bg-brand2-500/10 text-brand2-400 text-[8px] font-bold border border-brand2-500/20"
                      >
                        {asStr(ind)}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          <div className="flex justify-center">
            <button
              type="button"
              onClick={() => void onRunAi(report)}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-brand2-500/10 text-brand2-400 border border-brand2-500/20 text-[10px] font-black uppercase tracking-widest hover:bg-brand2-500/20 transition-all"
            >
              <i className="bi bi-robot"></i> {ai ? 'Phân tích lại AI' : 'Chạy AI Phân tích'}
            </button>
          </div>

          <div className="space-y-3 border-t border-white/5 pt-6">
            <h3 className="text-[10px] font-black text-white/55 uppercase tracking-[0.2em] ml-1 flex items-center gap-2">
              <i className="bi bi-sticky"></i> Ghi chú kiểm duyệt
            </h3>
            <textarea
              rows={3}
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Ghi chú nội bộ cho admin..."
              className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-xs text-white placeholder:text-white/35 focus:outline-none focus:border-brand-500/30 transition-all resize-none"
            ></textarea>
            <div className="flex justify-end">
              <button
                type="button"
                disabled={saving}
                onClick={() => void saveNote()}
                className="px-4 py-2 rounded-xl bg-brand-500/10 text-brand-400 border border-brand-500/20 text-[10px] font-black uppercase tracking-widest hover:bg-brand-500/20 transition-all disabled:opacity-50"
              >
                {saved ? (
                  <>
                    <i className="bi bi-check-lg mr-1"></i>Đã lưu
                  </>
                ) : (
                  <>
                    <i className="bi bi-floppy mr-1"></i>Lưu ghi chú
                  </>
                )}
              </button>
            </div>
          </div>

          {report.status === 'pending' && (
            <div className="flex justify-center gap-4 border-t border-white/5 pt-6">
              <button
                type="button"
                onClick={() => void onAction(report, 'approve')}
                className="inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-safe-500 text-black text-[10px] font-black uppercase tracking-widest hover:bg-safe-400 transition-all shadow-lg shadow-safe-500/20"
              >
                <i className="bi bi-check-lg"></i> Duyệt báo cáo
              </button>
              <button
                type="button"
                onClick={() => void onAction(report, 'reject')}
                className="inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-danger-500/10 text-danger-400 border border-danger-500/20 text-[10px] font-black uppercase tracking-widest hover:bg-danger-500/20 transition-all"
              >
                <i className="bi bi-x-lg"></i> Từ chối
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/* ---------- Main view ---------- */

const STATUS_OPTIONS: SelectOption[] = [
  { value: '', label: '-- Trạng thái --' },
  { value: 'pending', label: 'Chờ duyệt' },
  { value: 'approved', label: 'Đã duyệt' },
  { value: 'rejected', label: 'Từ chối' },
];

const TYPE_OPTIONS: SelectOption[] = [
  { value: '', label: '-- Loại --' },
  { value: 'phone', label: 'SĐT' },
  { value: 'domain', label: 'Website' },
  { value: 'account', label: 'Tài khoản' },
  { value: 'email', label: 'Email' },
  { value: 'message', label: 'Tin nhắn' },
];

const SEVERITY_OPTIONS: SelectOption[] = [
  { value: '', label: '-- Mức độ --' },
  { value: 'low', label: 'Thấp' },
  { value: 'medium', label: 'Trung bình' },
  { value: 'high', label: 'Cao' },
  { value: 'critical', label: 'Nghiêm trọng' },
];

const PAGE_SIZE = 25;

export default function Reports() {
  const [statusFilter, setStatusFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [qInput, setQInput] = useState('');
  const [query, setQuery] = useState('');
  const [sort, setSort] = useState('-created_at');
  const [page, setPage] = useState(1);

  const [detail, setDetail] = useState<Report | null>(null);
  const [viewer, setViewer] = useState<{ images: Array<{ url: string; caption: string }>; index: number } | null>(null);
  const [actingId, setActingId] = useState<number | null>(null);

  const listPath = `/admin/reports/?status=${statusFilter}&type=${typeFilter}&severity=${severityFilter}&q=${encodeURIComponent(query)}&sort=${sort}`;
  const { data, loading, refetch } = useAdminGet<Report[] | { results?: Report[] }>(listPath);
  const { data: allData } = useAdminGet<Report[] | { results?: Report[] }>('/admin/reports/?status=');

  const reports = useMemo(() => {
    let list = asList(data);
    if (statusFilter) list = list.filter((r) => r.status === statusFilter);
    if (typeFilter) list = list.filter((r) => r.target_type === typeFilter);
    if (severityFilter) list = list.filter((r) => r.severity === severityFilter);
    if (query) {
      const q = query.toLowerCase();
      list = list.filter((r) =>
        [r.target_value, r.description, r.scammer_name, r.scammer_phone, r.scammer_bank_account, reporterName(r)]
          .some((v) => (v || '').toLowerCase().includes(q)),
      );
    }
    const copy = [...list];
    const key = sort.replace(/^-/, '');
    copy.sort((a, b) => {
      let av: string | number = '';
      let bv: string | number = '';
      if (key === 'created_at') {
        av = a.created_at || '';
        bv = b.created_at || '';
      } else if (key === 'reporter__username') {
        av = reporterName(a);
        bv = reporterName(b);
      } else if (key === 'severity') {
        const order: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };
        av = order[a.severity || ''] || 0;
        bv = order[b.severity || ''] || 0;
      }
      if (av < bv) return sort.startsWith('-') ? 1 : -1;
      if (av > bv) return sort.startsWith('-') ? -1 : 1;
      return 0;
    });
    return copy;
  }, [data, statusFilter, typeFilter, severityFilter, query, sort]);

  const stats = useMemo(() => {
    const all = asList(allData);
    return {
      total: all.length,
      pending: all.filter((r) => r.status === 'pending').length,
      approved: all.filter((r) => r.status === 'approved').length,
      rejected: all.filter((r) => r.status === 'rejected').length,
      high_severity: all.filter((r) => r.severity === 'high').length,
      has_ai: all.filter((r) => aiObject(r) !== null).length,
    };
  }, [allData]);

  const totalPages = Math.max(1, Math.ceil(reports.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages);
  const pageReports = reports.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);
  const hasFilter = Boolean(statusFilter || typeFilter || severityFilter || query);

  const applyStatus = (s: string) => {
    setStatusFilter(s);
    setTypeFilter('');
    setSeverityFilter('');
    setQInput('');
    setQuery('');
    setSort('-created_at');
    setPage(1);
  };

  const clearFilters = () => {
    setStatusFilter('');
    setTypeFilter('');
    setSeverityFilter('');
    setQInput('');
    setQuery('');
    setPage(1);
  };

  const runAi = async (r: Report) => {
    setActingId(r.id);
    try {
      const res = await postDjango(`/admin-cp/reports/${r.id}/analyze/`, {});
      if (res.status === 'success') {
        showToast('AI Phân tích hoàn tất', 'success');
        refetch();
      } else {
        showToast(asStr(res.message) || 'Lỗi phân tích AI', 'error');
      }
    } catch {
      showToast('Lỗi kết nối', 'error');
    } finally {
      setActingId(null);
    }
  };

  const handleReportAction = async (reportId: number, action: 'approve' | 'reject') => {
    setActingId(reportId);
    try {
      const res = await api.post<{ message?: string; status?: string }>(`/admin/reports/${reportId}/action/`, { action });
      showToast(res.message || `Đã ${action === 'approve' ? 'chấp thuận' : 'từ chối'} báo cáo`, 'success');
      setDetail(null);
      refetch();
    } catch (e) {
      showToast(e instanceof Error ? e.message : 'Thao tác thất bại', 'error');
    } finally {
      setActingId(null);
    }
  };

  const toggleSort = (next: string) => {
    setSort((prev) => (prev === next ? `-${next}` : next));
    setPage(1);
  };

  const sortArrow = (key: string): string => (sort === key ? '↑' : sort === `-${key}` ? '↓' : '');

  return (
    <div className="container mx-auto px-4 py-10 mt-16 max-w-7xl space-y-8">
      <style>{SELECT_CSS}</style>

      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 pb-6 border-b border-white/10">
        <div className="flex items-center gap-4">
          <Link
            href="/admin-cp/"
            className="w-12 h-12 rounded-2xl bg-slate-900 border border-white/10 flex items-center justify-center text-slate-300 hover:text-white hover:border-white/20 transition-all shadow-lg"
          >
            <i className="bi bi-chevron-left text-xl"></i>
          </Link>
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="relative inline-flex rounded-full h-2 w-2 bg-brand-500"></span>
              <span className="text-[10px] uppercase font-black tracking-[0.2em] text-brand-400">Kiểm duyệt cộng đồng</span>
            </div>
            <h1 className="text-3xl font-black text-white tracking-tight">Báo Cáo Lừa Đảo</h1>
            <p className="text-xs text-slate-400 mt-0.5">Xác minh, phân tích AI và phê duyệt báo cáo lừa đảo từ người dùng</p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <Link
            href="/admin-cp/"
            className="px-4 py-2.5 rounded-xl bg-slate-900 border border-white/10 text-xs font-bold text-slate-300 hover:text-white hover:border-white/20 transition-all"
          >
            ← Dashboard
          </Link>
        </div>
      </div>

      {/* Unified Tab Navigation */}
      <AdminNavbar />

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="p-4 rounded-2xl bg-slate-900/90 border border-white/10 text-center space-y-1 shadow-md">
          <div className="w-9 h-9 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center mx-auto text-slate-300">
            <i className="bi bi-file-earmark-text text-sm"></i>
          </div>
          <p className="text-2xl font-black text-white">{stats.total}</p>
          <p className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Tổng báo cáo</p>
        </div>
        <div
          className={`p-4 rounded-2xl bg-slate-900/90 border text-center space-y-1 cursor-pointer transition-all shadow-md ${
            statusFilter === 'pending'
              ? 'border-warn-400 bg-warn-500/10 shadow-warn-500/10'
              : 'border-white/10 hover:border-warn-400/50'
          }`}
          onClick={() => applyStatus('pending')}
        >
          <div className="w-9 h-9 rounded-xl bg-warn-500/15 border border-warn-500/30 flex items-center justify-center mx-auto text-warn-400">
            <i className="bi bi-clock-history text-sm"></i>
          </div>
          <p className="text-2xl font-black text-warn-400">{stats.pending}</p>
          <p className="text-[10px] font-bold text-slate-300 uppercase tracking-wider">Chờ duyệt</p>
        </div>
        <div
          className={`p-4 rounded-2xl bg-slate-900/90 border text-center space-y-1 cursor-pointer transition-all shadow-md ${
            statusFilter === 'approved'
              ? 'border-safe-400 bg-safe-500/10 shadow-safe-500/10'
              : 'border-white/10 hover:border-safe-400/50'
          }`}
          onClick={() => applyStatus('approved')}
        >
          <div className="w-9 h-9 rounded-xl bg-safe-500/15 border border-safe-500/30 flex items-center justify-center mx-auto text-safe-400">
            <i className="bi bi-check-circle-fill text-sm"></i>
          </div>
          <p className="text-2xl font-black text-safe-400">{stats.approved}</p>
          <p className="text-[10px] font-bold text-slate-300 uppercase tracking-wider">Đã duyệt</p>
        </div>
        <div
          className={`p-4 rounded-2xl bg-slate-900/90 border text-center space-y-1 cursor-pointer transition-all shadow-md ${
            statusFilter === 'rejected'
              ? 'border-danger-400 bg-danger-500/10 shadow-danger-500/10'
              : 'border-white/10 hover:border-danger-400/50'
          }`}
          onClick={() => applyStatus('rejected')}
        >
          <div className="w-9 h-9 rounded-xl bg-danger-500/15 border border-danger-500/30 flex items-center justify-center mx-auto text-danger-400">
            <i className="bi bi-x-circle-fill text-sm"></i>
          </div>
          <p className="text-2xl font-black text-danger-400">{stats.rejected}</p>
          <p className="text-[10px] font-bold text-slate-300 uppercase tracking-wider">Từ chối</p>
        </div>
        <div className="p-4 rounded-2xl bg-slate-900/90 border border-white/10 text-center space-y-1 shadow-md">
          <div className="w-9 h-9 rounded-xl bg-rose-500/15 border border-rose-500/30 flex items-center justify-center mx-auto text-rose-400">
            <i className="bi bi-exclamation-triangle-fill text-sm"></i>
          </div>
          <p className="text-2xl font-black text-rose-400">{stats.high_severity}</p>
          <p className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Nghiêm trọng</p>
        </div>
        <div className="p-4 rounded-2xl bg-slate-900/90 border border-white/10 text-center space-y-1 shadow-md">
          <div className="w-9 h-9 rounded-xl bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center mx-auto text-cyan-400">
            <i className="bi bi-robot text-sm"></i>
          </div>
          <p className="text-2xl font-black text-cyan-400">{stats.has_ai}</p>
          <p className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">AI Đã Quét</p>
        </div>
      </div>

      {/* Filter Bar */}
      <form
        method="GET"
        className="liquid-card p-5"
        onSubmit={(e) => {
          e.preventDefault();
          setQuery(qInput.trim());
          setPage(1);
        }}
      >
        <input type="hidden" name="sort" value={sort} readOnly />
        <div className="flex flex-wrap items-center gap-3">
          <LiquidSelect
            name="status"
            value={statusFilter}
            placeholder="-- Trạng thái --"
            options={STATUS_OPTIONS}
            className="min-w-[150px]"
            onChange={(v) => {
              setStatusFilter(v);
              setPage(1);
            }}
          />
          <LiquidSelect
            name="type"
            value={typeFilter}
            placeholder="-- Loại --"
            options={TYPE_OPTIONS}
            className="min-w-[130px]"
            onChange={(v) => {
              setTypeFilter(v);
              setPage(1);
            }}
          />
          <LiquidSelect
            name="severity"
            value={severityFilter}
            placeholder="-- Mức độ --"
            options={SEVERITY_OPTIONS}
            className="min-w-[150px]"
            onChange={(v) => {
              setSeverityFilter(v);
              setPage(1);
            }}
          />

          {/* Search */}
          <div className="relative flex-1 min-w-[200px]">
            <i className="bi bi-search absolute left-3.5 top-1/2 -translate-y-1/2 text-white/45 text-xs pointer-events-none z-10"></i>
            <input
              type="text"
              name="q"
              value={qInput}
              onChange={(e) => setQInput(e.target.value)}
              placeholder="Tìm SĐT, tên, STK, nội dung..."
              className="w-full bg-white/5 border border-white/10 rounded-xl pl-10 pr-4 py-2.5 text-xs font-bold text-white placeholder:text-white/35 focus:outline-none focus:border-brand-500/50 transition-all"
            />
          </div>

          <button
            type="submit"
            className="bg-brand-500 text-black px-5 py-2.5 rounded-xl text-[10px] font-black uppercase tracking-widest hover:bg-brand-400 transition-all"
          >
            Lọc
          </button>
          {hasFilter && (
            <button
              type="button"
              onClick={clearFilters}
              className="text-[9px] font-bold text-white/45 hover:text-white transition-colors"
            >
              <i className="bi bi-x-lg mr-1"></i>Xóa lọc
            </button>
          )}
        </div>
      </form>

      {/* Reports Table */}
      <div className="p-1 rounded-2xl bg-slate-900/40 border border-white/5 backdrop-blur-xl overflow-hidden shadow-2xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-separate border-spacing-0">
            <thead>
              <tr className="bg-white/[0.02]">
                <th className="px-5 py-5 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5 w-8">
                  <span className="text-white/35">#</span>
                </th>
                <th className="px-5 py-5 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">
                  <button
                    type="button"
                    onClick={() => toggleSort('created_at')}
                    className="flex items-center gap-1 hover:text-brand-400 transition-colors"
                  >
                    Thời gian {sortArrow('created_at')}
                  </button>
                </th>
                <th className="px-5 py-5 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">
                  <button
                    type="button"
                    onClick={() => toggleSort('reporter__username')}
                    className="flex items-center gap-1 hover:text-brand-400 transition-colors"
                  >
                    Người báo {sortArrow('reporter__username')}
                  </button>
                </th>
                <th className="px-5 py-5 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Đối tượng</th>
                <th className="px-5 py-5 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">Bằng chứng</th>
                <th className="px-5 py-5 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5">
                  <button
                    type="button"
                    onClick={() => toggleSort('severity')}
                    className="flex items-center gap-1 hover:text-brand-400 transition-colors"
                  >
                    Mức độ {sortArrow('severity')}
                  </button>
                </th>
                <th className="px-5 py-5 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5 text-center">AI</th>
                <th className="px-5 py-5 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5 text-center">Trạng thái</th>
                <th className="px-5 py-5 text-[9px] font-black text-white/55 uppercase tracking-widest border-b border-white/5 text-right">Hành động</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.02]">
              {pageReports.map((r) => {
                const dt = splitDate(r.created_at);
                const name = reporterName(r);
                const imgs = r.evidence_images || [];
                const main = mainEvidenceUrl(r);
                const hasAi = aiObject(r) !== null;
                return (
                  <tr key={r.id} className="group hover:bg-white/[0.03] transition-all duration-300" id={`report-row-${r.id}`}>
                    <td className="px-5 py-5 text-[10px] font-bold text-white/35">{r.id}</td>
                    <td className="px-5 py-5 text-[10px] font-bold text-white/60 whitespace-nowrap">
                      {dt.date}
                      <br />
                      <span className="text-white/55">{dt.time}</span>
                    </td>
                    <td className="px-5 py-5">
                      <div className="flex items-center gap-2.5">
                        <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-brand-500/10 to-brand-500/10 border border-white/10 flex items-center justify-center text-brand-400 font-black text-[10px] shrink-0">
                          {initial(name)}
                        </div>
                        <span className="text-xs font-black text-white tracking-tight truncate max-w-[100px]">{name}</span>
                      </div>
                    </td>
                    <td className="px-5 py-5">
                      <div className="space-y-1">
                        <div className="flex items-center gap-1.5">
                          <span className="px-1.5 py-0.5 rounded bg-white/5 text-white/45 text-[7px] font-black uppercase tracking-wider border border-white/10">
                            <i className={`bi ${targetIcon(r.target_type)}`}></i> {r.target_type}
                          </span>
                          <span className="text-[8px] font-bold text-brand-500/40 uppercase">
                            {r.scam_type_display || r.scam_type}
                          </span>
                        </div>
                        <div className="text-xs font-black text-white/80 tracking-tight truncate max-w-[180px]" title={r.target_value}>
                          {r.target_value}
                        </div>
                      </div>
                    </td>
                    <td className="px-5 py-5">
                      <div className="flex items-center gap-1.5">
                        {main && (
                          <div
                            className="w-10 h-10 rounded-lg overflow-hidden border border-white/10 cursor-zoom-in shrink-0 hover:border-brand-500/50 transition-all"
                            onClick={() => setViewer({ images: galleryFor(r), index: 0 })}
                          >
                            {/* eslint-disable-next-line @next/next/no-img-element */}
                            <img src={mediaUrl(main)} className="w-full h-full object-cover" loading="lazy" alt="evidence" />
                          </div>
                        )}
                        {imgs.slice(0, 2).map((img, i) => {
                          const url = typeof img === 'string' ? img : img.url || '';
                          if (!url) return null;
                          return (
                            <div
                              key={`${url}-${i}`}
                              className="w-10 h-10 rounded-lg overflow-hidden border border-white/10 cursor-zoom-in shrink-0 hover:border-brand-500/50 transition-all"
                              onClick={() => setViewer({ images: galleryFor(r), index: main ? i + 1 : i })}
                            >
                              {/* eslint-disable-next-line @next/next/no-img-element */}
                              <img src={mediaUrl(url)} className="w-full h-full object-cover" loading="lazy" alt="evidence" />
                            </div>
                          );
                        })}
                        {imgs.length > 2 && (
                          <div className="w-10 h-10 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center text-[9px] font-black text-white/55">
                            +{imgs.length - 2}
                          </div>
                        )}
                        {!main && imgs.length === 0 && <span className="text-[9px] text-white/15">-</span>}
                      </div>
                    </td>
                    <td className="px-5 py-5">
                      <span className={`px-2 py-1 rounded-lg text-[8px] font-black uppercase tracking-wider border ${severityClass(r.severity)}`}>
                        {(r.severity || '').toUpperCase()}
                      </span>
                    </td>
                    <td className="px-5 py-5 text-center">
                      {hasAi ? (
                        <div
                          className="w-8 h-8 rounded-lg bg-brand2-500/10 border border-brand2-500/20 flex items-center justify-center mx-auto"
                          title="AI đã phân tích"
                        >
                          <i className="bi bi-robot text-brand2-400 text-xs"></i>
                        </div>
                      ) : (
                        <span className="text-[9px] text-white/15">-</span>
                      )}
                    </td>
                    <td className="px-5 py-5">
                      <div className="flex justify-center">
                        {r.status === 'pending' ? (
                          <span className="px-2.5 py-1 rounded-xl bg-warn-500/10 text-warn-500 text-[8px] font-black uppercase border border-warn-500/20 tracking-wider">
                            Chờ duyệt
                          </span>
                        ) : r.status === 'approved' ? (
                          <span className="px-2.5 py-1 rounded-xl bg-safe-500/10 text-safe-400 text-[8px] font-black uppercase border border-safe-500/20 tracking-wider">
                            Đã duyệt
                          </span>
                        ) : (
                          <span className="px-2.5 py-1 rounded-xl bg-danger-500/10 text-danger-500 text-[8px] font-black uppercase border border-danger-500/20 tracking-wider">
                            Từ chối
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-5 py-5 text-right">
                      <div className="flex justify-end gap-2 opacity-0 group-hover:opacity-100 transition-all duration-300">
                        <button
                          type="button"
                          onClick={() => setDetail(r)}
                          className="w-9 h-9 rounded-xl bg-white/5 text-white/55 flex items-center justify-center hover:bg-brand-500 hover:text-black transition-all border border-white/10 hover:border-brand-500"
                          title="Xem chi tiết"
                        >
                          <i className="bi bi-eye-fill text-sm"></i>
                        </button>
                        <button
                          type="button"
                          disabled={actingId === r.id}
                          onClick={() => void runAi(r)}
                          className="w-9 h-9 rounded-xl bg-white/5 text-white/55 flex items-center justify-center hover:bg-brand2-500 hover:text-white transition-all border border-white/10 hover:border-brand2-500 disabled:opacity-50"
                          title="AI Phân tích"
                        >
                          <i className={`bi ${actingId === r.id ? 'bi-arrow-repeat animate-spin' : 'bi-robot'} text-sm`}></i>
                        </button>
                        {r.status === 'pending' && (
                          <>
                            <button
                              type="button"
                              onClick={() => void handleReportAction(r.id, 'approve')}
                              className="w-9 h-9 rounded-xl bg-white/5 text-white/55 flex items-center justify-center hover:bg-safe-500 hover:text-black transition-all border border-white/10 hover:border-safe-500"
                              title="Duyệt"
                            >
                              <i className="bi bi-check-lg text-sm"></i>
                            </button>
                            <button
                              type="button"
                              onClick={() => void handleReportAction(r.id, 'reject')}
                              className="w-9 h-9 rounded-xl bg-white/5 text-white/55 flex items-center justify-center hover:bg-danger-500 hover:text-white transition-all border border-white/10 hover:border-danger-500"
                              title="Từ chối"
                            >
                              <i className="bi bi-x-lg text-sm"></i>
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
              {!loading && pageReports.length === 0 && (
                <tr>
                  <td colSpan={9} className="px-8 py-32 text-center">
                    <div className="w-20 h-20 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center mx-auto mb-4">
                      <i className="bi bi-inbox text-3xl text-white/20"></i>
                    </div>
                    <div className="text-[10px] font-black text-white/35 uppercase tracking-widest mb-2">Không tìm thấy báo cáo</div>
                    <p className="text-xs text-white/20">Thử thay đổi bộ lọc hoặc từ khóa tìm kiếm.</p>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="mt-4 flex items-center justify-between gap-3 px-2">
          <p className="text-[10px] text-white/45 font-bold uppercase tracking-widest">
            Trang {safePage}/{totalPages} · Tổng {reports.length} báo cáo
          </p>
          <div className="flex items-center gap-2">
            {safePage > 1 && (
              <button
                type="button"
                onClick={() => setPage(safePage - 1)}
                className="px-3 py-2 rounded-xl bg-white/5 border border-white/10 text-white/60 hover:text-brand-400 hover:border-brand-500/30 text-xs font-bold"
              >
                Trước
              </button>
            )}
            {safePage < totalPages && (
              <button
                type="button"
                onClick={() => setPage(safePage + 1)}
                className="px-3 py-2 rounded-xl bg-white/5 border border-white/10 text-white/60 hover:text-brand-400 hover:border-brand-500/30 text-xs font-bold"
              >
                Sau
              </button>
            )}
          </div>
        </div>
      )}

      {detail && (
        <ReportDetailModal
          key={detail.id}
          report={detail}
          onClose={() => setDetail(null)}
          onRunAi={(r) => {
            setDetail(null);
            return runAi(r);
          }}
          onAction={(r, action) => handleReportAction(r.id, action)}
          onOpenImage={(images, index) => setViewer({ images, index })}
        />
      )}

      {viewer && (
        <ImageViewer images={viewer.images} startIndex={viewer.index} onClose={() => setViewer(null)} />
      )}
    </div>
  );
}
