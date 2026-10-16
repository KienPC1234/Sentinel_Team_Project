'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import Swal from 'sweetalert2';
import { api, mediaUrl } from '../../lib/api';
import { escapeHtml } from '../../lib/chat/markdown';
import { Spinner } from '../../components/ui';

/* Port từ PKV/templates/ScamRadar/list.html.
 * Giữ nguyên endpoint hiện có: GET /trends/hot/?type=<phone|account|domain|email>.
 * Modal "Chi tiết báo cáo" dùng endpoint hiện có GET /report/<id>/ (report đã duyệt). */

interface HotRow {
  id?: number;
  target_type: string;
  target_value: string;
  report_count: number;
  scam_type?: string;
  scam_type_display?: string;
  severity?: string;
  source?: string;
  reporter_name?: string;
  scammer_name?: string;
  created_at?: string;
  created_at_display?: string;
}

interface ReportScammerInfo {
  name?: string;
  phone?: string;
  bank_account?: string;
  bank_name?: string;
}

interface ReportDetailData {
  scam_type?: string;
  scam_type_display?: string;
  severity?: string;
  created_at?: string;
  description?: string;
  ai_analysis?: unknown;
  evidence_url?: string;
  scammer_info?: ReportScammerInfo;
}

const KIND_META: Record<string, { title: string; type: string }> = {
  phones: { title: 'Danh sách SĐT lừa đảo', type: 'phone' },
  accounts: { title: 'Danh sách TK ngân hàng lừa đảo', type: 'account' },
  domains: { title: 'Danh sách Website/Link lừa đảo', type: 'domain' },
  emails: { title: 'Danh sách Email lừa đảo', type: 'email' },
};

const SCAM_TYPE_LABELS: Record<string, string> = {
  police_impersonation: 'Giả danh công an',
  bank_impersonation: 'Giả mạo ngân hàng',
  gov_impersonation: 'Giả mạo cơ quan Thuế / Dịch vụ công / VNeID',
  recruitment_scam: 'Lừa tuyển dụng / Việc nhẹ lương cao',
  investment_scam: 'Lừa đầu tư tài chính / Sàn ảo',
  delivery_scam: 'Giả mạo giao hàng / Bưu cục',
  loan_scam: 'Lừa vay tiền / Tín dụng đen',
  otp_steal: 'Chiêu trò OTP/2FA',
  phishing: 'Phishing link / Trang web giả mạo',
  romance_scam: 'Lừa tình cảm / Bẫy lợn béo (Pig Butchering)',
  deepfake: 'Deepfake âm thanh / Video AI mạo danh',
  malware_app: 'Mã độc / Ứng dụng APK đánh cắp tài khoản',
  crypto_scam: 'Lừa đảo Tiền điện tử / Ví Crypto / Airdrop',
  social_engineering: 'Lừa đảo hội nhóm Telegram / Zalo / Fanpage',
  prize_scam: 'Trúng thưởng / Quà tri ân / Đơn hàng ảo',
  emergency_scam: 'Báo nạn cấp cứu / Tống tiền người thân',
  other: 'Khác',
  ai_detected: 'AI phát hiện rủi ro',
};

function scamTypeLabel(row: HotRow): string {
  return row.scam_type_display || SCAM_TYPE_LABELS[row.scam_type || ''] || row.scam_type || '-';
}

/** severity suy ra từ số báo cáo (endpoint hot chỉ trả report_count). */
function rowSeverity(row: HotRow): string {
  if (row.severity) return row.severity;
  if (row.report_count >= 20) return 'high';
  if (row.report_count >= 5) return 'medium';
  return 'low';
}

function SeverityBadge({ severity }: { severity: string }) {
  if (severity === 'high' || severity === 'critical') {
    return (
      <span className="text-danger-400 font-bold">
        <i className="bi bi-shield-x-fill"></i> Cao
      </span>
    );
  }
  if (severity === 'medium') {
    return (
      <span className="text-warn-400 font-bold">
        <i className="bi bi-shield-exclamation"></i> Trung bình
      </span>
    );
  }
  return (
    <span className="text-brand-400 font-bold">
      <i className="bi bi-shield-minus"></i> Thấp
    </span>
  );
}

async function showReportDetail(id: number): Promise<void> {
  void Swal.fire({
    title: 'Đang tải thông tin...',
    html: '<div class="flex flex-col items-center"><div class="animate-spin rounded-full h-8 w-8 border-b-2 border-white mb-2"></div><span class="text-white/60 text-sm">Vui lòng chờ...</span></div>',
    background: 'var(--sc-slate-900)',
    color: 'var(--sc-white)',
    showConfirmButton: false,
    allowOutsideClick: false,
    customClass: {
      popup: 'liquid-card border border-white/10 !bg-[var(--sc-slate-900)] !rounded-2xl',
      title: 'text-xl font-bold text-white',
    },
  });

  try {
    const data = await api.get<ReportDetailData>(`/report/${id}/`);

    let severityBadge = '';
    if (data.severity === 'high' || data.severity === 'critical') {
      severityBadge = '<span class="px-2 py-0.5 rounded bg-danger-500/20 text-danger-400 text-xs border border-danger-500/30">Cao</span>';
    } else if (data.severity === 'medium') {
      severityBadge = '<span class="px-2 py-0.5 rounded bg-warn-500/20 text-warn-400 text-xs border border-warn-500/30">Trung bình</span>';
    } else {
      severityBadge = '<span class="px-2 py-0.5 rounded bg-brand-500/20 text-brand-400 text-xs border border-brand-500/30">Thấp</span>';
    }

    let aiAnalysisBlock = '';
    if (data.ai_analysis) {
      let aiRaw: string;
      if (typeof data.ai_analysis !== 'string') {
        try {
          aiRaw = JSON.stringify(data.ai_analysis, null, 2);
        } catch {
          aiRaw = String(data.ai_analysis);
        }
      } else {
        aiRaw = data.ai_analysis;
      }
      const safeAnalysis = escapeHtml(aiRaw || '').replace(/\n/g, '<br>');
      aiAnalysisBlock = `
        <div class="mt-4 p-3 bg-brand-500/10 border border-brand-500/20 rounded-lg">
            <div class="flex items-center gap-2 mb-2">
                <i class="bi bi-robot text-brand-400"></i>
                <span class="text-xs font-bold text-brand-300 uppercase">Phân tích AI</span>
            </div>
            <div class="text-sm text-brand-100/80 leading-relaxed max-h-32 overflow-y-auto custom-scrollbar">
                ${safeAnalysis}
            </div>
        </div>
      `;
    }

    let evidenceBlock = '';
    const safeEvidenceUrl = data.evidence_url ? mediaUrl(data.evidence_url) : '';
    if (safeEvidenceUrl) {
      evidenceBlock = `
        <div class="mt-4">
            <h4 class="text-xs uppercase text-white/55 font-bold mb-2">Bằng chứng</h4>
            <div class="rounded-lg overflow-hidden border border-white/10 group cursor-pointer" onclick="window.open('${escapeHtml(safeEvidenceUrl)}', '_blank')">
                <img src="${escapeHtml(safeEvidenceUrl)}" class="w-full h-32 object-cover transition-transform group-hover:scale-105" alt="Evidence">
                <div class="bg-black/50 p-1 text-center text-xs text-white/60">Nhấn để xem ảnh gốc</div>
            </div>
        </div>
      `;
    }

    const scammer = data.scammer_info || {};
    const bankInfo = scammer.bank_account ? `${scammer.bank_account} (${scammer.bank_name || 'N/A'})` : 'Không có';
    const scammerPhone = scammer.phone || 'Không có';
    const scammerName = scammer.name || 'Không rõ';

    const htmlContent = `
        <div class="text-left mt-2">
            <div class="flex justify-between items-start mb-4 pb-4 border-b border-white/10">
                <div>
                    <div class="text-xs text-white/60 uppercase mb-1">Loại lừa đảo</div>
                    <div class="font-bold text-white flex items-center gap-2">
                        ${escapeHtml(data.scam_type_display || data.scam_type || 'Khác')}
                        ${severityBadge}
                    </div>
                </div>
                <div class="text-right">
                    <div class="text-xs text-white/60 uppercase mb-1">Ngày báo cáo</div>
                    <div class="text-white font-mono text-sm">${data.created_at ? new Date(data.created_at).toLocaleDateString() : ''}</div>
                </div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div class="space-y-3">
                    <div class="bg-white/5 p-3 rounded-lg border border-white/10">
                        <h4 class="text-xs uppercase text-white/55 font-bold mb-2 border-b border-white/5 pb-1">Thông tin đối tượng</h4>
                        <ul class="space-y-2 text-sm">
                            <li class="flex justify-between">
                                <span class="text-white/60">Tên:</span>
                                <span class="text-white font-medium text-right">${escapeHtml(scammerName)}</span>
                            </li>
                            <li class="flex justify-between">
                                <span class="text-white/60">SĐT:</span>
                                <span class="text-white font-mono text-right">${escapeHtml(scammerPhone)}</span>
                            </li>
                            <li class="flex justify-between">
                                <span class="text-white/60">Ngân hàng:</span>
                                <span class="text-white font-mono text-right truncate ml-2" title="${escapeHtml(bankInfo)}">${escapeHtml(bankInfo)}</span>
                            </li>
                        </ul>
                    </div>
                </div>

                <div class="space-y-3">
                    <div class="bg-white/5 p-3 rounded-lg border border-white/10 h-full">
                        <h4 class="text-xs uppercase text-white/55 font-bold mb-2 border-b border-white/5 pb-1">Mô tả sự việc</h4>
                        <p class="text-sm text-white/80 leading-relaxed max-h-[120px] overflow-y-auto custom-scrollbar">
                            ${escapeHtml(data.description || 'Không có mô tả chi tiết.')}
                        </p>
                    </div>
                </div>
            </div>

            ${aiAnalysisBlock}
            ${evidenceBlock}
        </div>
    `;

    void Swal.fire({
      title: 'Chi Tiết Báo Cáo',
      html: htmlContent,
      width: '600px',
      showConfirmButton: true,
      confirmButtonText: 'Đóng',
      confirmButtonColor: 'var(--sc-brand-500)',
      background: 'var(--sc-slate-800)',
      color: 'var(--sc-white)',
      customClass: {
        popup: 'liquid-card border border-white/10 shadow-2xl !bg-[var(--sc-slate-900)]',
        title: 'text-left text-xl font-bold text-white border-b border-white/10 pb-3',
        htmlContainer: '!mx-1 !text-left',
        confirmButton: 'bg-brand-600 hover:bg-brand-700 text-white font-bold py-2 px-6 rounded-lg shadow-lg shadow-brand-500/30',
      },
    });
  } catch {
    void Swal.fire({
      icon: 'error',
      title: 'Lỗi',
      text: 'Không thể tải thông tin báo cáo.',
      background: 'var(--sc-slate-800)',
      color: 'var(--sc-white)',
      confirmButtonColor: 'var(--sc-danger-500)',
    });
  }
}

export default function RadarList() {
  const { kind } = useParams<{ kind: string }>();
  const meta = KIND_META[kind || ''] || { title: 'Danh sách rủi ro', type: '' };
  const [rows, setRows] = useState<HotRow[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const q = meta.type ? `?type=${encodeURIComponent(meta.type)}` : '';
    api
      .get<{ hot?: HotRow[] }>(`/trends/hot/${q}`)
      .then((d) => {
        const hot = d.hot || [];
        setRows(meta.type ? hot.filter((h) => h.target_type === meta.type) : hot);
      })
      .catch(() => setRows([]))
      .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kind]);

  return (
    <div className="animate-fadein max-w-6xl mx-auto space-y-8 pt-12 sm:pt-16 pb-20 px-4">
      {/* Breadcrumb */}
      <div className="text-white/55 text-sm flex items-center gap-2">
        <Link href="/" className="hover:text-white transition-colors">
          Trang chủ
        </Link>
        <i className="bi bi-chevron-right text-[10px]"></i>
        <Link href="/scam-radar/" className="hover:text-white transition-colors">
          Radar
        </Link>
        <i className="bi bi-chevron-right text-[10px]"></i>
        <span className="text-white">{meta.title}</span>
      </div>

      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-black text-white glow-text">{meta.title}</h1>
        <div className="text-white/60 text-sm">Top 50 tín hiệu rủi ro (Report đã duyệt + AI Scan)</div>
      </div>

      {/* Table */}
      <div className="liquid-card overflow-hidden">
        {loading ? (
          <Spinner />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="text-xs uppercase tracking-wider text-white/55 border-b border-white/5 bg-white/[0.02]">
                  <th className="p-4 font-bold">#</th>
                  <th className="p-4 font-bold">Đối tượng</th>
                  <th className="p-4 font-bold">Loại lừa đảo</th>
                  <th className="p-4 font-bold">Mức độ</th>
                  <th className="p-4 font-bold">Người báo cáo</th>
                  <th className="p-4 font-bold">Thời gian</th>
                  <th className="p-4 font-bold text-center">Chi tiết</th>
                </tr>
              </thead>
              <tbody className="text-sm divide-y divide-white/5">
                {rows.map((r, i) => (
                  <tr key={`${r.target_type}-${r.target_value}-${i}`} className="hover:bg-white/5 transition-colors group">
                    <td className="p-4 text-white/45 font-mono">{i + 1}</td>
                    <td className="p-4">
                      <div className="font-bold text-white font-mono tracking-tight">{r.target_value}</div>
                      {r.scammer_name && <div className="text-xs text-white/55 mt-1 uppercase">{r.scammer_name}</div>}
                    </td>
                    <td className="p-4">
                      <span className="px-2 py-1 rounded-lg bg-white/5 text-xs font-semibold text-white/70 border border-white/10">
                        {scamTypeLabel(r)}
                      </span>
                    </td>
                    <td className="p-4">
                      <SeverityBadge severity={rowSeverity(r)} />
                    </td>
                    <td className="p-4 text-white/60">
                      {r.source === 'scan_ai' ? (
                        <div className="flex items-center gap-2 text-brand-300/70">
                          <i className="bi bi-cpu"></i>
                          AI Scan
                        </div>
                      ) : (
                        <div className="flex items-center gap-2">
                          <i className="bi bi-person-circle"></i>
                          {r.reporter_name || 'Ẩn danh'}
                        </div>
                      )}
                    </td>
                    <td
                      className="p-4 text-white/55 whitespace-nowrap"
                      title={r.created_at || ''}
                    >
                      {r.created_at_display || '—'}
                    </td>
                    <td className="p-4 text-center">
                      {r.source === 'scan_ai' && r.id != null ? (
                        <Link
                          href={`/scan/status/${r.id}/`}
                          className="inline-flex w-8 h-8 rounded-full bg-brand-500/10 hover:bg-brand-500/20 items-center justify-center transition-colors text-brand-300/80 hover:text-brand-200"
                        >
                          <i className="bi bi-box-arrow-up-right"></i>
                        </Link>
                      ) : r.id != null ? (
                        <button
                          onClick={() => void showReportDetail(r.id as number)}
                          className="w-8 h-8 rounded-full bg-white/5 hover:bg-white/10 flex items-center justify-center transition-colors text-white/60 hover:text-white"
                        >
                          <i className="bi bi-eye-fill"></i>
                        </button>
                      ) : (
                        <Link
                          href={`/scan/lookup/?q=${encodeURIComponent(r.target_value)}`}
                          className="inline-flex w-8 h-8 rounded-full bg-brand-500/10 hover:bg-brand-500/20 items-center justify-center transition-colors text-brand-300/80 hover:text-brand-200"
                        >
                          <i className="bi bi-box-arrow-up-right"></i>
                        </Link>
                      )}
                    </td>
                  </tr>
                ))}
                {rows.length === 0 && (
                  <tr>
                    <td colSpan={7} className="p-12 text-center text-white/45">
                      <i className="bi bi-inbox text-4xl mb-3 block opacity-50"></i>
                      Chưa có dữ liệu báo cáo nào
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
