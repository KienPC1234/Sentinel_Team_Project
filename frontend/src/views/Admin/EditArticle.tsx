'use client';
import { useState, useEffect, useRef } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { api, mediaUrl } from '../../lib/api';
import { AdminShell } from './_shared';

const CATEGORIES = [
  { value: 'news', label: 'Tin tức' },
  { value: 'guide', label: 'Hướng dẫn' },
  { value: 'alert', label: 'Cảnh báo mới' },
  { value: 'story', label: 'Chuyện cảnh giác' },
  { value: 'inclusive', label: 'An ninh số Bao trùm' },
  { value: 'empathy', label: 'Góc thấu cảm' },
];

export default function EditArticle() {
  const params = useParams();
  const router = useRouter();
  const articleId = params?.id as string | undefined;
  const isEditing = Boolean(articleId);

  const [title, setTitle] = useState('');
  const [category, setCategory] = useState('news');
  const [summary, setSummary] = useState('');
  const [content, setContent] = useState('');
  const [isPublished, setIsPublished] = useState(true);
  const [existingCover, setExistingCover] = useState<string | null>(null);
  const [coverFile, setCoverFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);

  const [sourceType, setSourceType] = useState('internal');
  const [sourceUrl, setSourceUrl] = useState('');

  const fileInputRef = useRef<HTMLInputElement>(null);
  const [loading, setLoading] = useState(false);
  const [fetching, setFetching] = useState(isEditing);
  const [summaryLoading, setSummaryLoading] = useState(false);
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null);

  useEffect(() => {
    if (!articleId) return;
    let alive = true;
    api.get<{
      title: string;
      category: string;
      summary: string;
      content: string;
      is_published: boolean;
      cover_image: string | null;
      source_type?: string;
      source_url?: string;
    }>(`/admin/articles/${articleId}/`)
      .then((d) => {
        if (!alive) return;
        setTitle(d.title || '');
        setCategory(d.category || 'news');
        setSummary(d.summary || '');
        setContent(d.content || '');
        setIsPublished(d.is_published ?? true);
        setSourceType(d.source_type || 'internal');
        setSourceUrl(d.source_url || '');
        if (d.cover_image) setExistingCover(d.cover_image);
      })
      .catch((err: unknown) => {
        const e = err as { message?: string };
        setMsg({ text: e.message || 'Không thể tải bài viết.', ok: false });
      })
      .finally(() => {
        if (alive) setFetching(false);
      });
    return () => {
      alive = false;
    };
  }, [articleId]);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (f) {
      setCoverFile(f);
      setPreviewUrl(URL.createObjectURL(f));
    }
  };

  const genSummary = async () => {
    if (!content.trim()) return;
    setSummaryLoading(true);
    try {
      const d = await api.post<{ summary?: string } | string>('/admin/content/generate-summary/', { content, title });
      setSummary(typeof d === 'string' ? d : d.summary || '');
    } catch {
      setMsg({ text: 'Không thể sinh tóm tắt AI.', ok: false });
    } finally {
      setSummaryLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim() || !content.trim()) {
      setMsg({ text: 'Vui lòng nhập tiêu đề và nội dung bài viết.', ok: false });
      return;
    }

    setLoading(true);
    setMsg(null);

    const formData = new FormData();
    formData.append('title', title);
    formData.append('category', category);
    formData.append('source_type', sourceType);
    if (sourceUrl) {
      formData.append('source_url', sourceUrl);
    }
    formData.append('summary', summary);
    formData.append('content', content);
    formData.append('is_published', isPublished ? 'true' : 'false');
    if (coverFile) {
      formData.append('cover_image', coverFile);
    }

    try {
      if (isEditing) {
        await api.put(`/admin/articles/${articleId}/`, formData);
        setMsg({ text: 'Đã cập nhật bài viết thành công.', ok: true });
      } else {
        await api.post('/admin/articles/', formData);
        setMsg({ text: 'Đã tạo bài viết mới thành công.', ok: true });
        router.push('/admin-cp/articles/');
      }
    } catch (err: unknown) {
      const e = err as { message?: string };
      setMsg({ text: e.message || 'Lưu bài viết thất bại.', ok: false });
    } finally {
      setLoading(false);
    }
  };

  if (fetching) {
    return (
      <AdminShell title="Đang Tải..." subtitle="Vui lòng chờ giây lát">
        <div className="liquid-card p-8 text-center text-white/60 text-sm">
          Đang tải dữ liệu bài viết...
        </div>
      </AdminShell>
    );
  }

  return (
    <AdminShell
      title={isEditing ? 'Chỉnh Sửa Bài Viết' : 'Soạn Bài Viết Mới'}
      subtitle="Biên tập tin tức cảnh báo an ninh mạng và kiến thức bảo mật"
    >
      {msg && (
        <div className={`p-4 rounded-xl mb-6 text-xs font-bold border ${msg.ok ? 'bg-safe-500/10 border-safe-500/20 text-safe-300' : 'bg-danger-500/10 border-danger-500/20 text-danger-300'}`}>
          {msg.text}
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="flex flex-wrap gap-2">
          <Link href="/admin-cp/articles/" className="px-4 py-2 rounded-xl bg-white/5 border border-white/10 text-xs font-bold text-white/70 hover:bg-white/10 transition-all">
            ← Danh sách bài viết
          </Link>
          <Link href="/admin-cp/articles/magic-create/" className="px-4 py-2 rounded-xl bg-brand2-500/15 border border-brand2-500/30 text-xs font-bold text-brand2-200 hover:bg-brand2-500/25 transition-all">
            <i className="bi bi-magic mr-1.5"></i> Tạo bằng AI
          </Link>
        </div>

        <div className="liquid-card p-4 sm:p-6 space-y-5">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="md:col-span-2 space-y-1.5">
              <label className="text-xs font-bold text-white/70">Tiêu đề bài viết</label>
              <input
                type="text"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="VD: Cảnh báo thủ đoạn lừa đảo cuộc gọi Deepfake video..."
                className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-brand-500/40"
                required
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-bold text-white/70">Chuyên mục</label>
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-brand-500/40"
              >
                {CATEGORIES.map((c) => (
                  <option key={c.value} value={c.value} className="bg-slate-900 text-white">
                    {c.label}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label className="text-xs font-bold text-white/70">Nguồn bài viết</label>
              <select
                value={sourceType}
                onChange={(e) => setSourceType(e.target.value)}
                className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-brand-500/40"
              >
                <option value="internal" className="bg-slate-900 text-white">Nội bộ ShieldCall VN</option>
                <option value="tinnhiemmang" className="bg-slate-900 text-white">Tín nhiệm mạng (tinnhiemmang.vn)</option>
                <option value="press" className="bg-slate-900 text-white">Báo chí chính thống</option>
                <option value="community" className="bg-slate-900 text-white">Cộng đồng đóng góp</option>
              </select>
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-bold text-white/70">
                Link nguồn gốc bài viết
                {sourceUrl && (
                  <a
                    href={sourceUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="ml-2 text-brand-400 hover:underline font-normal text-[11px]"
                  >
                    (Mở trang gốc <i className="bi bi-box-arrow-up-right"></i>)
                  </a>
                )}
              </label>
              <input
                type="url"
                value={sourceUrl}
                onChange={(e) => setSourceUrl(e.target.value)}
                placeholder="https://tinnhiemmang.vn/..."
                className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-brand-500/40 font-mono text-xs"
              />
            </div>
          </div>

          {/* Cover image upload */}
          <div className="space-y-2">
            <label className="text-xs font-bold text-white/70">Ảnh bìa bài viết</label>
            <div className="flex flex-col sm:flex-row gap-4 items-start">
              {(previewUrl || existingCover) && (
                <div className="relative w-40 h-24 rounded-xl overflow-hidden border border-white/10 bg-black/40 flex-shrink-0">
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img
                    src={previewUrl || mediaUrl(existingCover)}
                    alt="Cover preview"
                    className="w-full h-full object-cover"
                  />
                </div>
              )}
              <div className="space-y-2">
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileChange}
                  accept="image/*"
                  className="hidden"
                />
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  className="px-4 py-2 rounded-xl bg-white/5 border border-white/10 text-xs font-bold text-white/80 hover:bg-white/10 transition-all inline-flex items-center gap-2"
                >
                  <i className="bi bi-image"></i> {coverFile ? 'Đổi ảnh bìa khác' : 'Chọn ảnh bìa từ máy'}
                </button>
                {coverFile && (
                  <p className="text-[11px] text-brand-300 font-mono">Đã chọn: {coverFile.name}</p>
                )}
                <p className="text-[11px] text-white/35">Hỗ trợ JPG, PNG, WEBP tối đa 5MB</p>
              </div>
            </div>
          </div>

          <div className="space-y-1.5">
            <div className="flex flex-wrap justify-between items-center gap-2">
              <label className="text-xs font-bold text-white/70">Tóm tắt ngắn (Summary)</label>
              <button
                type="button"
                onClick={() => void genSummary()}
                disabled={summaryLoading || !content.trim()}
                className="text-xs text-brand2-300 font-bold hover:underline disabled:opacity-40 inline-flex items-center gap-1"
              >
                <i className="bi bi-stars"></i> {summaryLoading ? 'Đang tóm tắt...' : 'AI Tóm tắt'}
              </button>
            </div>
            <textarea
              value={summary}
              onChange={(e) => setSummary(e.target.value)}
              rows={3}
              placeholder="Tóm tắt nội dung chính để hiển thị ngoài danh sách tin tức..."
              className="w-full bg-black/40 border border-white/10 rounded-xl p-3 text-sm text-white/85 focus:outline-none focus:border-brand-500/40 resize-none"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-bold text-white/70">Nội dung chi tiết (Markdown)</label>
            <textarea
              value={content}
              onChange={(e) => setContent(e.target.value)}
              rows={14}
              placeholder="Soạn thảo nội dung bài viết định dạng Markdown..."
              className="w-full bg-black/40 border border-white/10 rounded-2xl p-4 text-sm text-white/85 font-mono focus:outline-none focus:border-brand-500/40 resize-y"
              required
            />
          </div>

          <div className="flex items-center gap-3 pt-2">
            <input
              type="checkbox"
              id="pub_check"
              checked={isPublished}
              onChange={(e) => setIsPublished(e.target.checked)}
              className="w-4 h-4 rounded border-white/20 bg-black/40 text-brand-500 focus:ring-0"
            />
            <label htmlFor="pub_check" className="text-xs font-bold text-white/80 cursor-pointer">
              Xuất bản bài viết ngay (Hiển thị trên trang chủ và danh mục Tin tức)
            </label>
          </div>
        </div>

        <div className="flex flex-col md:flex-row md:justify-end gap-3 pt-4">
          <Link
            href="/admin-cp/articles/"
            className="px-6 py-3 rounded-xl bg-white/5 border border-white/10 text-xs font-bold text-white/70 hover:bg-white/10 transition-all text-center"
          >
            Hủy
          </Link>
          <button
            type="submit"
            disabled={loading}
            className="px-8 py-3 rounded-xl bg-brand-500 text-black text-xs font-black uppercase tracking-widest hover:bg-brand-400 transition-all shadow-[0_0_24px_rgba(6,182,212,0.3)] disabled:opacity-50"
          >
            {loading ? 'Đang lưu...' : isEditing ? 'Lưu Thay Đổi' : 'Đăng Bài Viết'}
          </button>
        </div>
      </form>
    </AdminShell>
  );
}
