'use client';
/* Port 1-1 từ PKV/templates/Forum/forum_create.html.
 * Chuyển Alpine.data('forumCreate') → React state/hooks/handler. Giữ nguyên
 * tầng API: POST /forum/posts/ (multipart: title, content, category, scan_id,
 * image, cf-turnstile-response), GET /user/scan-picker/.
 */
import { useRef, useState } from 'react';
import type { ChangeEvent } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import Swal from 'sweetalert2';
import { api } from '../../lib/api';
import { showToast } from '../../lib/ui/feedback';
import RichEditor from '../../components/RichEditor';
import { TurnstileWidget, getTsToken, resetTurnstile } from '../../components/ScanWidgets';

const CATS = [
  { val: 'discussion', label: 'Thảo luận', icon: 'bi-chat-dots', color: 'hover:border-brand-500/50' },
  { val: 'warning', label: 'Cảnh báo', icon: 'bi-exclamation-octagon', color: 'hover:border-danger-500/50' },
  { val: 'experience', label: 'Kinh nghiệm', icon: 'bi-gem', color: 'hover:border-brand2-500/50' },
  { val: 'question', label: 'Hỏi đáp', icon: 'bi-patch-question', color: 'hover:border-warn-500/50' },
];

const CREATE_CSS = `
.create-card{background:var(--glass-bg);backdrop-filter:blur(40px);border:1px solid var(--glass-border);border-radius:2.5rem;box-shadow:0 25px 50px -12px rgba(0,0,0,0.5)}
.input-premium{background:var(--glass-bg);border:1px solid var(--glass-border);border-radius:1.25rem;color:var(--text-primary);transition:all 0.3s ease}
.input-premium:focus{background:var(--glass-border);border-color:var(--accent-cyan);box-shadow:0 0 20px rgba(24,255,255,0.1);outline:none}
.spinner-border{display:inline-block;width:2rem;height:2rem;vertical-align:-0.125em;border:0.25em solid currentColor;border-right-color:transparent;border-radius:50%;animation:sb-spin 0.75s linear infinite}
.spinner-border-sm{width:1rem;height:1rem;border-width:0.2em}
@keyframes sb-spin{to{transform:rotate(360deg)}}
`;

interface CreatedPost {
  id: number;
}

interface PickScan {
  id: number;
  scan_type?: string;
  status?: string;
  risk_score?: number;
  risk_level?: string;
  verdict_tone?: string;
  verdict_label?: string;
  preview?: string;
  is_owner?: boolean;
}

function scanTypeLabel(scan: PickScan | null | undefined): string {
  const type = (scan?.scan_type || 'scan').toUpperCase();
  const map: Record<string, string> = {
    PHONE: 'Số điện thoại', MESSAGE: 'Tin nhắn', DOMAIN: 'Domain', ACCOUNT: 'Tài khoản',
    QR: 'QR/Ảnh', EMAIL: 'Email', FILE: 'Tệp', AUDIO: 'Âm thanh',
  };
  return map[type] || type;
}

export default function ForumCreate() {
  const router = useRouter();
  const imageInputRef = useRef<HTMLInputElement>(null);

  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const [category, setCategory] = useState('discussion');
  const [scanId, setScanId] = useState('');
  const [selectedScan, setSelectedScan] = useState<PickScan | null>(null);
  const [imageName, setImageName] = useState('');
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);

  const onImage = (e: ChangeEvent<HTMLInputElement>): void => {
    const f = e.target.files?.[0] || null;
    setImageFile(f);
    setImageName(f ? f.name : '');
  };

  const selectedScanLabel = (): string => {
    if (!selectedScan || !scanId) return '';
    return `#${selectedScan.id} · ${scanTypeLabel(selectedScan)} · ${selectedScan.risk_score || 0}/100`;
  };

  const fetchScanPicker = async (extra: { scanId?: string } = {}): Promise<PickScan[]> => {
    const params = new URLSearchParams();
    params.set('scope', 'mine');
    if (extra.scanId) params.set('scan_id', String(extra.scanId));
    try {
      const payload = await api.get<PickScan[] | { results?: PickScan[] }>(`/user/scan-picker/?${params.toString()}`);
      return Array.isArray(payload) ? payload : (payload.results || []);
    } catch {
      return [];
    }
  };

  const selectScan = (scan: PickScan): void => {
    if (!scan || !scan.id) return;
    setScanId(String(scan.id));
    setSelectedScan(scan);
    showToast(`Đã chọn Scan #${scan.id}`, 'success');
  };

  const clearScanSelection = (): void => {
    setScanId('');
    setSelectedScan(null);
    showToast('Đã xóa scan tham chiếu', 'info');
  };

  const applyManualScanId = async (raw: string): Promise<void> => {
    const digits = String(raw || '').replace(/\D/g, '');
    if (!digits) {
      showToast('Vui lòng nhập Scan ID', 'warning');
      return;
    }
    const rows = await fetchScanPicker({ scanId: digits });
    if (!rows.length) {
      showToast('Scan ID không thuộc bạn hoặc chưa được public refer bởi chủ scan', 'error');
      return;
    }
    selectScan(rows[0]);
  };

  const openScanPicker = async (): Promise<void> => {
    const rows = await fetchScanPicker();
    if (!rows.length) {
      const manual = await Swal.fire({
        title: 'Không có scan phù hợp',
        text: 'Bạn có thể nhập Scan ID thủ công',
        input: 'text',
        inputPlaceholder: 'Nhập Scan ID...',
        showCancelButton: true,
        confirmButtonText: 'Dùng Scan ID',
        cancelButtonText: 'Hủy',
        background: 'var(--sc-night-2)',
        color: 'var(--sc-white)',
        customClass: { popup: 'liquid-card border border-white/10 !rounded-2xl' },
      });
      if (!manual.isConfirmed) return;
      await applyManualScanId(String(manual.value || ''));
      return;
    }

    const result = await Swal.fire({
      title: 'Chọn scan tham chiếu',
      html: `
        <div class="space-y-3 text-left">
          <label for="forum-create-scan-select" class="text-[10px] font-black uppercase tracking-widest text-white/45">Danh sách scan</label>
          <select id="forum-create-scan-select" class="liquid-input w-full py-3 px-4 text-sm font-bold">
            <option value="">-- Chọn 1 scan --</option>
            ${rows.slice(0, 100).map((scan) => {
              const text = `#${scan.id} · ${scanTypeLabel(scan)} · ${(scan.verdict_label || scan.risk_level || 'N/A')}`;
              return `<option value="${scan.id}">${text.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</option>`;
            }).join('')}
          </select>
        </div>
      `,
      showCancelButton: true,
      showDenyButton: true,
      denyButtonText: 'Nhập ID',
      confirmButtonText: 'Gắn scan',
      cancelButtonText: 'Hủy',
      background: 'var(--sc-night-2)',
      color: 'var(--sc-white)',
      customClass: { popup: 'liquid-card border border-white/10 !rounded-2xl' },
      preConfirm: () => {
        const selected = (document.getElementById('forum-create-scan-select') as HTMLSelectElement | null)?.value || '';
        if (!selected) {
          Swal.showValidationMessage('Vui lòng chọn scan');
          return null;
        }
        return selected;
      },
    });

    if (result.isDenied) {
      const manual = await Swal.fire({
        title: 'Nhập Scan ID',
        input: 'text',
        inputPlaceholder: 'VD: 123',
        showCancelButton: true,
        confirmButtonText: 'Dùng ID này',
        cancelButtonText: 'Hủy',
        background: 'var(--sc-night-2)',
        color: 'var(--sc-white)',
        customClass: { popup: 'liquid-card border border-white/10 !rounded-2xl' },
      });
      if (manual.isConfirmed) {
        await applyManualScanId(String(manual.value || ''));
      }
      return;
    }

    if (result.isConfirmed && result.value) {
      const picked = rows.find((item) => String(item.id) === String(result.value));
      selectScan(picked || { id: Number(result.value) });
    }
  };

  const submitPost = async (): Promise<void> => {
    if (!title.trim() || !content.trim()) {
      showToast('Vui lòng điền đầy đủ tiêu đề và nội dung', 'warning');
      return;
    }

    const tsToken = getTsToken();
    const siteKey = (process.env.NEXT_PUBLIC_TURNSTILE_SITEKEY as string | undefined) || '';
    if (siteKey && !tsToken) {
      showToast('Vui lòng hoàn thành xác minh anti-spam', 'warning');
      return;
    }

    setLoading(true);
    const formData = new FormData();
    formData.append('title', title);
    formData.append('content', content);
    formData.append('category', category);
    if (scanId && String(scanId).trim()) formData.append('scan_id', String(scanId).trim());
    if (tsToken) formData.append('cf-turnstile-response', tsToken);
    if (imageFile) formData.append('image', imageFile);

    try {
      const post = await api.upload<CreatedPost>('/forum/posts/', formData);
      showToast('Đăng bài thành công!', 'success');
      window.setTimeout(() => router.push(`/forum/${post.id}/`), 1500);
    } catch (e) {
      showToast(e instanceof Error ? e.message : 'Lỗi khi đăng bài', 'error');
    } finally {
      setLoading(false);
      try { resetTurnstile(); } catch { /* ignore */ }
    }
  };

  return (
    <div className="max-w-4xl mx-auto px-4 py-12">
      <style>{CREATE_CSS}</style>

      {/* Breadcrumb */}
      <div className="mb-10 flex items-center gap-3">
        <Link href="/forum/" className="w-10 h-10 rounded-full bg-white/5 flex items-center justify-center text-white/55 hover:text-white hover:bg-white/10 transition-all border border-white/5">
          <i className="bi bi-arrow-left"></i>
        </Link>
        <h1 className="text-3xl font-black text-white">Chia sẻ <span className="text-brand-400">câu chuyện</span></h1>
      </div>

      <div className="create-card p-8 md:p-12">
        <div className="space-y-8">
          {/* Category Selection */}
          <div className="space-y-3">
            <label className="text-[10px] font-black uppercase tracking-widest text-white/45 ml-1">Chọn danh mục</label>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
              {CATS.map((cat) => (
                <button key={cat.val} onClick={() => setCategory(cat.val)} type="button"
                  className={`flex flex-col items-center gap-2 p-4 rounded-2xl border transition-all ${category === cat.val ? 'bg-white/10 border-white/20 text-white' : `text-white/55 border-white/5 ${cat.color}`}`}>
                  <i className={`bi ${cat.icon} text-xl`}></i>
                  <span className="text-[11px] font-black uppercase">{cat.label}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Title */}
          <div className="space-y-3">
            <label className="text-[10px] font-black uppercase tracking-widest text-white/45 ml-1">Tiêu đề bài viết</label>
            <input type="text" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Nhập tiêu đề ngắn gọn nhưng đủ thông tin..."
              className="input-premium w-full px-6 py-4 text-lg font-bold" />
          </div>

          <div className="space-y-3">
            <label className="text-[10px] font-black uppercase tracking-widest text-white/45 ml-1">Tham chiếu kết quả scan (tuỳ chọn)</label>
            <div className="flex flex-wrap gap-2">
              <button onClick={() => void openScanPicker()} type="button" className="bg-brand-500/15 border border-brand-400/30 text-brand-300 px-4 py-2 rounded-xl text-xs font-black uppercase tracking-widest hover:bg-brand-500/25 transition-all">
                <i className="bi bi-search mr-1"></i> Chọn scan tham chiếu
              </button>
              {scanId && (
                <button onClick={clearScanSelection} type="button" className="bg-white/5 border border-white/10 text-white/60 px-4 py-2 rounded-xl text-xs font-black uppercase tracking-widest hover:bg-white/10 transition-all">
                  <i className="bi bi-x-circle mr-1"></i> Bỏ chọn
                </button>
              )}
            </div>
            {scanId && (
              <div className="inline-flex items-center gap-2 px-3 py-2 rounded-xl border border-brand-400/30 bg-brand-500/10 text-brand-200 text-xs font-bold">
                <i className="bi bi-link-45deg"></i>
                <span>{selectedScanLabel() || `Scan #${scanId}`}</span>
              </div>
            )}
            <p className="text-[10px] text-white/55 font-medium">Hỗ trợ lọc theo loại/risk, tìm kiếm và nhập trực tiếp Scan ID để kiểm tra quyền refer.</p>
          </div>

          {/* Image Upload */}
          <div className="space-y-3">
            <label className="text-[10px] font-black uppercase tracking-widest text-white/45 ml-1">Hình ảnh đính kèm (Tùy chọn)</label>
            <div className="input-premium p-6 border-dashed flex flex-col items-center justify-center cursor-pointer hover:bg-white/[0.05] transition-all" onClick={() => imageInputRef.current?.click()}>
              <i className="bi bi-cloud-arrow-up text-3xl mb-2 text-white/35"></i>
              <span className="text-xs text-white/45 font-bold uppercase tracking-widest">{imageName || 'Nhấn để chọn ảnh minh chứng'}</span>
              <input ref={imageInputRef} type="file" accept="image/*" className="hidden" onChange={onImage} />
            </div>
          </div>

          {/* Content */}
          <div className="input-premium w-full overflow-hidden bg-black/20">
            <RichEditor
              placeholder="Mô tả kỹ chi tiết vụ việc, cách thức lừa đảo..."
              minLines={13}
              onChangeData={setContent}
            />
          </div>
          <p className="text-[10px] text-white/35 font-medium flex items-center gap-1.5"><i className="bi bi-info-circle"></i> CKEditor 5 hỗ trợ soạn thảo trực quan với thanh công cụ tích hợp.</p>

          {/* Antispam & Control */}
          <div className="flex flex-col md:flex-row items-center justify-between gap-8 pt-8 border-t border-white/5">
            <TurnstileWidget />

            <div className="flex items-center gap-4 w-full md:w-auto">
              <Link href="/forum/" className="text-sm font-black text-white/45 hover:text-white transition-colors uppercase tracking-widest">Hủy</Link>
              <button onClick={() => void submitPost()} disabled={loading}
                className="flex-1 md:flex-none bg-gradient-to-r from-brand-400 to-brand-600 text-[var(--sc-night-1)] px-10 py-4 rounded-2xl font-black transition-all hover:scale-105 shadow-xl shadow-brand-400/20">
                {!loading && (
                  <span className="flex items-center gap-2 justify-center">
                    <i className="bi bi-send-fill"></i> ĐĂNG BÀI VIẾT
                  </span>
                )}
                {loading && (
                  <span className="flex items-center justify-center">
                    <span className="spinner-border spinner-border-sm"></span>
                  </span>
                )}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
