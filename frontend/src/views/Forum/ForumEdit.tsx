'use client';
/* Port 1-1 từ PKV/templates/Forum/forum_edit.html.
 * Chuyển Alpine.data('forumEdit') → React state/hooks/handler. Giữ nguyên tầng
 * API: GET /forum/posts/<id>/ (nạp post_data) + PATCH /forum/posts/<id>/
 * (multipart: title, content, category, image). CKEditor dùng chung RichEditor
 * (thay window.createCKEditor('#forum-editor')).
 */
import { useEffect, useRef, useState } from 'react';
import type { ChangeEvent } from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import { api, mediaUrl } from '../../lib/api';
import { showToast } from '../../lib/ui/feedback';
import RichEditor, { hasEditorContent } from '../../components/RichEditor';

const CATS = [
  { val: 'discussion', label: 'Thảo luận', icon: 'bi-chat-dots' },
  { val: 'warning', label: 'Cảnh báo', icon: 'bi-exclamation-octagon' },
  { val: 'experience', label: 'Kinh nghiệm', icon: 'bi-gem' },
  { val: 'question', label: 'Hỏi đáp', icon: 'bi-patch-question' },
];

/* CSS riêng của trang (port nguyên block head_extra trong template). */
const EDIT_CSS = `
.edit-card{background:var(--glass-bg);backdrop-filter:blur(40px);border:1px solid var(--glass-border);border-radius:1.5rem;box-shadow:0 25px 50px -12px rgba(0,0,0,0.5)}
.input-premium{background:rgba(255,255,255,0.03);border:1px solid var(--glass-border);border-radius:1rem;color:var(--text-primary);transition:all 0.3s ease}
.input-premium:focus{background:rgba(255,255,255,0.06);border-color:var(--accent-cyan);box-shadow:0 0 20px rgba(24,255,255,0.1);outline:none}
.cat-btn{transition:all .25s ease}
.cat-btn.active{transform:scale(1.03)}
.img-preview{max-height:200px;border-radius:1rem;object-fit:cover}
`;

interface EditData {
  id: number;
  title: string;
  content: string;
  category: string;
  image?: string | null;
}

export default function ForumEdit() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const imageInputRef = useRef<HTMLInputElement>(null);

  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const [category, setCategory] = useState('discussion');
  const [currentImage, setCurrentImage] = useState<string | null>(null);
  const [newImageName, setNewImageName] = useState('');
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [ready, setReady] = useState(false);
  const [errors, setErrors] = useState<{ title?: string; content?: string }>({});

  useEffect(() => {
    if (!id) return;
    api
      .get<EditData>(`/forum/posts/${id}/`)
      .then((d) => {
        setTitle(d.title || '');
        setContent(d.content || '');
        setCategory(d.category || 'discussion');
        setCurrentImage(d.image ? mediaUrl(d.image) : null);
      })
      .catch(() => {
        showToast('Không thể tải bài viết. Vui lòng thử lại.', 'error');
      })
      .finally(() => setReady(true));
  }, [id]);

  const handleImageSelect = (e: ChangeEvent<HTMLInputElement>): void => {
    const file = e.target.files?.[0];
    if (!file) return;
    setImageFile(file);
    setNewImageName(file.name);
    const reader = new FileReader();
    reader.onload = (ev) => setPreviewUrl(String(ev.target?.result || ''));
    reader.readAsDataURL(file);
  };

  const submitEdit = (): void => {
    /* Bỏ tag trước khi kiểm tra rỗng — CKEditor trả <p>&nbsp;</p> khi rỗng. */
    const errs: { title?: string; content?: string } = {};
    const cleanTitle = title.trim();
    const cleanContent = hasEditorContent(content) ? content.trim() : '';
    if (!cleanTitle) errs.title = 'Tiêu đề không được để trống';
    else if (cleanTitle.length < 10) errs.title = 'Tiêu đề quá ngắn (tối thiểu 10 ký tự)';
    if (!cleanContent) errs.content = 'Nội dung không được để trống';
    setErrors(errs);
    if (Object.keys(errs).length) {
      showToast('Vui lòng điền đầy đủ thông tin', 'warning');
      return;
    }
    if (!id) return;

    setLoading(true);
    const formData = new FormData();
    formData.append('title', cleanTitle);
    formData.append('content', cleanContent);
    formData.append('category', category);
    if (imageFile) formData.append('image', imageFile);

    api
      .patch(`/forum/posts/${id}/`, formData)
      .then(() => {
        showToast('Cập nhật bài viết thành công!', 'success');
        window.setTimeout(() => router.push(`/forum/${id}/`), 1200);
      })
      .catch((e: unknown) => {
        showToast(e instanceof Error ? e.message : 'Lỗi khi cập nhật bài viết', 'error');
      })
      .finally(() => setLoading(false));
  };

  return (
    <div className="max-w-4xl mx-auto px-4 py-8">
      <style>{EDIT_CSS}</style>

      {/* Breadcrumb */}
      <nav className="flex items-center gap-2 text-sm mb-6 text-white/55">
        <Link href="/forum/" className="hover:text-brand-400 transition"><i className="bi bi-house-door"></i> Diễn đàn</Link>
        <i className="bi bi-chevron-right text-[10px]"></i>
        <Link href={`/forum/${id}/`} className="hover:text-brand-400 transition truncate max-w-[200px]">{title || 'Bài viết'}</Link>
        <i className="bi bi-chevron-right text-[10px]"></i>
        <span className="text-white/60">Chỉnh sửa</span>
      </nav>

      {/* Header */}
      <div className="flex items-center gap-4 mb-8">
        <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-brand-500/20 to-brand-500/20 flex items-center justify-center border border-brand-500/20">
          <i className="bi bi-pencil-square text-xl text-brand-400"></i>
        </div>
        <div>
          <h1 className="text-2xl font-black text-white">Chỉnh sửa bài viết</h1>
          <p className="text-xs text-white/55">Bài viết #<span>{id}</span></p>
        </div>
      </div>

      <div className="edit-card p-6 md:p-10">
        <div className="space-y-6">

          {/* Category Selection */}
          <div>
            <label className="text-xs font-bold uppercase tracking-wider text-white/60 mb-2 block">Danh mục</label>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
              {CATS.map((cat) => (
                <button
                  key={cat.val}
                  onClick={() => setCategory(cat.val)}
                  type="button"
                  className={`flex items-center gap-3 p-3 rounded-xl border transition-all text-left ${
                    category === cat.val
                      ? 'bg-white/10 border-white/30 text-white cat-btn active'
                      : 'text-white/55 border-white/5 hover:border-white/20 cat-btn'
                  }`}
                >
                  <i className={`bi ${cat.icon} text-lg`}></i>
                  <span className="text-xs font-bold uppercase">{cat.label}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Title */}
          <div>
            <label className="text-xs font-bold uppercase tracking-wider text-white/60 mb-2 block">Tiêu đề</label>
            <input
              type="text"
              value={title}
              maxLength={200}
              onChange={(e) => {
                setTitle(e.target.value);
                if (errors.title) setErrors((prev) => ({ ...prev, title: undefined }));
              }}
              placeholder="Nhập tiêu đề bài viết..."
              className={`input-premium w-full px-5 py-3.5 text-base font-semibold ${errors.title ? 'border-danger-500/50' : ''}`}
            />
            {errors.title && <p className="text-danger-400 text-xs mt-1">{errors.title}</p>}
          </div>

          {/* Current Image + Upload */}
          <div>
            <label className="text-xs font-bold uppercase tracking-wider text-white/60 mb-2 block">Ảnh đính kèm</label>
            <div className="space-y-3">
              {previewUrl && (
                <div className="relative inline-block">
                  <img src={previewUrl} className="img-preview border border-brand-400/20" alt="" />
                  <span className="absolute top-2 left-2 bg-brand-500/80 text-[10px] text-black font-bold px-2 py-0.5 rounded-full">Ảnh mới</span>
                </div>
              )}
              {currentImage && !previewUrl && (
                <div className="relative inline-block">
                  <img src={currentImage} className="img-preview border border-white/10" alt="" />
                  <span className="absolute top-2 left-2 bg-black/60 text-[10px] text-white/60 px-2 py-0.5 rounded-full">Ảnh hiện tại</span>
                </div>
              )}
              <div
                className="input-premium p-5 border-dashed flex items-center gap-4 cursor-pointer hover:bg-white/[0.04] transition-all"
                onClick={() => imageInputRef.current?.click()}
              >
                <i className="bi bi-cloud-arrow-up text-2xl text-white/35"></i>
                <div>
                  <p className="text-sm font-semibold text-white/60">{newImageName || 'Nhấn để chọn ảnh mới'}</p>
                  <p className="text-[10px] text-white/55">Bỏ qua nếu muốn giữ ảnh cũ</p>
                </div>
                <input ref={imageInputRef} type="file" accept="image/*" className="hidden" onChange={handleImageSelect} />
              </div>
            </div>
          </div>

          {/* Content */}
          <div>
            <label className="text-xs font-bold uppercase tracking-wider text-white/60 mb-2 block">Nội dung</label>
            <div className={`input-premium w-full overflow-hidden ${errors.content ? 'border-danger-500/50' : ''}`}>
              {ready && (
                <RichEditor
                  initialData={content}
                  placeholder="Chỉnh sửa nội dung bài viết..."
                  minLines={13}
                  onChangeData={(html) => {
                    setContent(html);
                    if (errors.content && hasEditorContent(html)) {
                      setErrors((prev) => ({ ...prev, content: undefined }));
                    }
                  }}
                />
              )}
            </div>
            {errors.content && <p className="text-danger-400 text-xs mt-1">{errors.content}</p>}
            <p className="text-[10px] text-white/35 font-medium flex items-center gap-1 mt-1.5"><i className="bi bi-info-circle"></i> Hỗ trợ định dạng với thanh công cụ CKEditor 5</p>
          </div>

          {/* Actions */}
          <div className="flex items-center justify-between gap-4 pt-6 border-t border-white/5">
            <Link href={`/forum/${id}/`} className="text-sm font-bold text-white/45 hover:text-white transition flex items-center gap-1.5">
              <i className="bi bi-x-lg"></i> Hủy
            </Link>
            <button
              onClick={submitEdit}
              disabled={loading}
              type="button"
              className="bg-gradient-to-r from-brand-400 to-brand-600 text-[var(--sc-night-1)] px-8 py-3 rounded-xl font-bold transition-all hover:scale-105 shadow-lg shadow-brand-400/20 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100"
            >
              {!loading && (
                <span className="flex items-center gap-2">
                  <i className="bi bi-check-lg"></i> Cập nhật bài viết
                </span>
              )}
              {loading && (
                <span className="flex items-center gap-2">
                  <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" /></svg>
                  Đang lưu...
                </span>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
