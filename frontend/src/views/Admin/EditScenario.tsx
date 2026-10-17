'use client';
import { useState, useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { api } from '../../lib/api';
import { AdminShell } from './_shared';

interface Step {
  speaker: 'scammer' | 'victim' | 'narrator';
  text: string;
  note: string;
}

interface ArticleOption {
  id: number;
  title: string;
}

interface LessonOption {
  id: number;
  title: string;
}

export default function EditScenario() {
  const params = useParams();
  const router = useRouter();
  const scenarioId = params?.id as string | undefined;
  const isEditing = Boolean(scenarioId);

  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [articleId, setArticleId] = useState<number | ''>('');
  const [lessonId, setLessonId] = useState<number | ''>('');
  const [steps, setSteps] = useState<Step[]>([
    { speaker: 'narrator', text: 'Nạn nhân nhận được một cuộc gọi bất ngờ...', note: 'Bối cảnh khởi đầu' },
  ]);

  const [articles, setArticles] = useState<ArticleOption[]>([]);
  const [lessons, setLessons] = useState<LessonOption[]>([]);

  const [loading, setLoading] = useState(false);
  const [fetching, setFetching] = useState(isEditing);
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null);

  // Live preview state
  const [showPreview, setShowPreview] = useState(false);
  const [previewStep, setPreviewStep] = useState(0);

  useEffect(() => {
    api.get<ArticleOption[]>('/admin/articles/')
      .then((data) => setArticles(data || []))
      .catch(() => {});
    api.get<LessonOption[]>('/admin/learn/')
      .then((data) => setLessons(data || []))
      .catch(() => {});

    if (!scenarioId) return;
    let alive = true;
    api.get<{
      title: string;
      description: string;
      article_id: number | null;
      lesson_id: number | null;
      steps: Step[];
    }>(`/admin/scenarios/${scenarioId}/`)
      .then((d) => {
        if (!alive) return;
        setTitle(d.title || '');
        setDescription(d.description || '');
        setArticleId(d.article_id ?? '');
        setLessonId(d.lesson_id ?? '');
        if (Array.isArray(d.steps) && d.steps.length > 0) {
          setSteps(d.steps);
        }
      })
      .catch((err: unknown) => {
        const e = err as { message?: string };
        setMsg({ text: e.message || 'Không thể tải kịch bản.', ok: false });
      })
      .finally(() => {
        if (alive) setFetching(false);
      });
    return () => {
      alive = false;
    };
  }, [scenarioId]);

  const addStep = () => {
    setSteps([...steps, { speaker: 'scammer', text: '', note: '' }]);
  };

  const insertStep = (idx: number) => {
    const next = [...steps];
    next.splice(idx + 1, 0, { speaker: 'victim', text: '', note: '' });
    setSteps(next);
  };

  const duplicateStep = (idx: number) => {
    const target = steps[idx];
    if (!target) return;
    const next = [...steps];
    next.splice(idx + 1, 0, { ...target });
    setSteps(next);
  };

  const removeStep = (idx: number) => {
    if (steps.length <= 1) return;
    setSteps(steps.filter((_, i) => i !== idx));
  };

  const moveUp = (idx: number) => {
    if (idx <= 0) return;
    const next = [...steps];
    const temp = next[idx - 1];
    next[idx - 1] = next[idx];
    next[idx] = temp;
    setSteps(next);
  };

  const moveDown = (idx: number) => {
    if (idx >= steps.length - 1) return;
    const next = [...steps];
    const temp = next[idx + 1];
    next[idx + 1] = next[idx];
    next[idx] = temp;
    setSteps(next);
  };

  const updateStep = (idx: number, patch: Partial<Step>) => {
    setSteps(steps.map((s, i) => (i === idx ? { ...s, ...patch } : s)));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim()) {
      setMsg({ text: 'Vui lòng nhập tiêu đề kịch bản.', ok: false });
      return;
    }

    const validSteps = steps.filter((s) => s.text.trim());
    if (validSteps.length === 0) {
      setMsg({ text: 'Kịch bản phải có ít nhất một bước diễn tập hợp lệ.', ok: false });
      return;
    }

    setLoading(true);
    setMsg(null);

    const payload = {
      title,
      description,
      article_id: articleId !== '' ? Number(articleId) : null,
      lesson_id: lessonId !== '' ? Number(lessonId) : null,
      steps: validSteps,
    };

    try {
      if (isEditing) {
        await api.put(`/admin/scenarios/${scenarioId}/`, payload);
        setMsg({ text: 'Đã cập nhật kịch bản thành công.', ok: true });
      } else {
        await api.post('/admin/scenarios/', payload);
        setMsg({ text: 'Đã tạo kịch bản mới thành công.', ok: true });
        router.push('/admin-cp/scenarios/');
      }
    } catch (err: unknown) {
      const e = err as { message?: string };
      setMsg({ text: e.message || 'Lưu kịch bản thất bại.', ok: false });
    } finally {
      setLoading(false);
    }
  };

  if (fetching) {
    return (
      <AdminShell title="Đang Tải..." subtitle="Vui lòng chờ giây lát">
        <div className="liquid-card p-8 text-center text-white/60 text-sm">
          Đang tải dữ liệu kịch bản...
        </div>
      </AdminShell>
    );
  }

  return (
    <AdminShell
      title={isEditing ? 'Chỉnh Sửa Kịch Bản' : 'Soạn Kịch Bản Mới'}
      subtitle="Thiết kế tình huống lừa đảo tương tác từng bước cho Scam IQ và huấn luyện cộng đồng"
    >
      {msg && (
        <div className={`p-4 rounded-xl mb-6 text-xs font-bold border ${msg.ok ? 'bg-safe-500/10 border-safe-500/20 text-safe-300' : 'bg-danger-500/10 border-danger-500/20 text-danger-300'}`}>
          {msg.text}
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <Link href="/admin-cp/scenarios/" className="px-4 py-2 rounded-xl bg-white/5 border border-white/10 text-xs font-bold text-white/70 hover:bg-white/10 transition-all">
            <i className="bi bi-arrow-left mr-1.5"></i> Danh sách kịch bản
          </Link>
          <button
            type="button"
            onClick={() => {
              setShowPreview(!showPreview);
              setPreviewStep(0);
            }}
            className={`px-4 py-2 rounded-xl text-xs font-bold border transition-all flex items-center gap-1.5 ${
              showPreview
                ? 'bg-brand2-500/20 border-brand2-500/40 text-brand2-300'
                : 'bg-white/5 border-white/10 text-white/70 hover:text-white'
            }`}
          >
            <i className={`bi ${showPreview ? 'bi-eye-slash' : 'bi-eye'}`}></i>
            {showPreview ? 'Ẩn xem trước' : 'Xem trước mô phỏng'}
          </button>
        </div>

        {/* Live Simulation Preview Box */}
        {showPreview && (
          <div className="liquid-card p-6 bg-slate-950/80 border border-brand2-500/30 space-y-4">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div>
                <span className="text-[10px] font-black uppercase tracking-widest text-brand2-400">Xem trước trực tiếp</span>
                <h4 className="text-sm font-bold text-white mt-0.5">{title || 'Tiêu đề chưa đặt'}</h4>
              </div>
              <div className="text-xs font-bold text-white/60">
                Bước {previewStep + 1} / {steps.length}
              </div>
            </div>

            <div className="space-y-3 min-h-[160px] max-h-[360px] overflow-y-auto p-2">
              {steps.slice(0, previewStep + 1).map((s, idx) => {
                const isScammer = s.speaker === 'scammer';
                const isVictim = s.speaker === 'victim';
                return (
                  <div key={idx} className={`flex flex-col ${isScammer ? 'items-start' : isVictim ? 'items-end' : 'items-center'}`}>
                    <div
                      className={`flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-bold mb-1 border ${
                        isScammer
                          ? 'text-danger-400 bg-danger-500/10 border-danger-500/20'
                          : isVictim
                          ? 'text-brand-400 bg-brand-500/10 border-brand-500/20'
                          : 'text-brand2-400 bg-brand2-500/10 border-brand2-500/20'
                      }`}
                    >
                      <i className={`bi ${isScammer ? 'bi-exclamation-octagon-fill' : isVictim ? 'bi-person-badge-fill' : 'bi-info-circle-fill'}`}></i>
                      <span>{isScammer ? 'Kẻ lừa đảo' : isVictim ? 'Nạn nhân' : 'Bối cảnh'}</span>
                    </div>
                    <div
                      className={`max-w-[85%] rounded-2xl px-4 py-2.5 text-xs leading-relaxed border ${
                        isScammer
                          ? 'bg-slate-900 border-danger-500/30 text-danger-100 rounded-tl-sm'
                          : isVictim
                          ? 'bg-brand-950/60 border-brand-500/30 text-white rounded-tr-sm'
                          : 'bg-white/5 border-white/10 text-white/80 text-center italic'
                      }`}
                    >
                      {s.text || <span className="opacity-40 italic">Chưa nhập nội dung thoại</span>}
                    </div>
                    {s.note && (
                      <div className="mt-1.5 p-2 rounded-lg bg-warn-500/10 border border-warn-500/20 max-w-[85%] text-[11px] text-warn-200">
                        <span className="font-bold text-warn-400 mr-1">Phân tích:</span>
                        {s.note}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-white/5">
              <button
                type="button"
                disabled={previewStep === 0}
                onClick={() => setPreviewStep((p) => Math.max(0, p - 1))}
                className="px-3 py-1.5 rounded-lg bg-white/10 text-white text-xs font-bold disabled:opacity-30"
              >
                ← Trước
              </button>
              {previewStep < steps.length - 1 ? (
                <button
                  type="button"
                  onClick={() => setPreviewStep((p) => Math.min(steps.length - 1, p + 1))}
                  className="px-3 py-1.5 rounded-lg bg-brand2-500 text-white text-xs font-bold"
                >
                  Sau →
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() => setPreviewStep(0)}
                  className="px-3 py-1.5 rounded-lg bg-white/15 text-white text-xs font-bold"
                >
                  Diễn tập lại
                </button>
              )}
            </div>
          </div>
        )}

        {/* Basic Scenario Info */}
        <div className="liquid-card p-4 sm:p-6 space-y-5">
          <h3 className="text-sm font-black text-white uppercase tracking-wider">Thông Tin Kịch Bản</h3>

          <div className="space-y-1.5">
            <label className="text-xs font-bold text-white/70">Tiêu đề kịch bản</label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="VD: Kịch bản giả danh nhân viên điện lực báo cắt điện..."
              className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-brand-500/40"
              required
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-bold text-white/70">Mô tả bối cảnh tình huống</label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
              placeholder="Mô tả hoàn cảnh nạn nhân gặp phải, kênh tiếp cận của kẻ lừa đảo..."
              className="w-full bg-black/40 border border-white/10 rounded-xl p-3 text-sm text-white/85 focus:outline-none focus:border-brand-500/40 resize-none"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label className="text-xs font-bold text-white/70">Liên kết Bài học (Tùy chọn)</label>
              <select
                value={lessonId}
                onChange={(e) => setLessonId(e.target.value ? Number(e.target.value) : '')}
                className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-brand-500/40"
              >
                <option value="" className="bg-slate-900 text-white">Không gắn bài học</option>
                {lessons.map((l) => (
                  <option key={l.id} value={l.id} className="bg-slate-900 text-white">
                    {l.title}
                  </option>
                ))}
              </select>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-bold text-white/70">Liên kết Tin tức (Tùy chọn)</label>
              <select
                value={articleId}
                onChange={(e) => setArticleId(e.target.value ? Number(e.target.value) : '')}
                className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-brand-500/40"
              >
                <option value="" className="bg-slate-900 text-white">Không gắn tin tức</option>
                {articles.map((a) => (
                  <option key={a.id} value={a.id} className="bg-slate-900 text-white">
                    {a.title}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>

        {/* Steps Editor */}
        <div className="liquid-card p-4 sm:p-6 space-y-5">
          <div className="flex flex-col md:flex-row md:justify-between md:items-center gap-3">
            <div>
              <h3 className="text-sm font-black text-white uppercase tracking-wider">Diễn Biến Từng Bước ({steps.length})</h3>
              <p className="text-xs text-white/55 mt-0.5">Xây dựng chuỗi hội thoại mô phỏng tâm lý kẻ lừa đảo và phản ứng</p>
            </div>
            <button
              type="button"
              onClick={addStep}
              className="px-3.5 py-2 rounded-xl bg-brand-500/15 border border-brand-500/30 text-brand-300 text-xs font-bold hover:bg-brand-500/25 transition-all self-start md:self-auto"
            >
              <i className="bi bi-plus-lg mr-1"></i> Thêm bước ở cuối
            </button>
          </div>

          <div className="space-y-4">
            {steps.map((s, idx) => (
              <div key={idx} className="p-4 rounded-xl bg-white/[0.02] border border-white/10 space-y-3">
                <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs font-black text-brand-400 uppercase">Bước #{idx + 1}</span>
                    <select
                      value={s.speaker}
                      onChange={(e) => updateStep(idx, { speaker: e.target.value as Step['speaker'] })}
                      className="w-full md:w-auto bg-black/50 border border-white/10 rounded-lg px-3 py-1 text-xs text-white focus:outline-none"
                    >
                      <option value="scammer">Kẻ lừa đảo (Scammer)</option>
                      <option value="victim">Nạn nhân (Victim)</option>
                      <option value="narrator">Người dẫn / Bối cảnh (Narrator)</option>
                    </select>
                  </div>

                  <div className="flex items-center gap-1.5 self-end md:self-auto">
                    <button
                      type="button"
                      disabled={idx === 0}
                      onClick={() => moveUp(idx)}
                      title="Di chuyển lên"
                      className="w-7 h-7 rounded-lg bg-white/5 hover:bg-white/15 text-white/70 hover:text-white flex items-center justify-center text-xs disabled:opacity-20 transition-all"
                    >
                      <i className="bi bi-arrow-up"></i>
                    </button>
                    <button
                      type="button"
                      disabled={idx === steps.length - 1}
                      onClick={() => moveDown(idx)}
                      title="Di chuyển xuống"
                      className="w-7 h-7 rounded-lg bg-white/5 hover:bg-white/15 text-white/70 hover:text-white flex items-center justify-center text-xs disabled:opacity-20 transition-all"
                    >
                      <i className="bi bi-arrow-down"></i>
                    </button>
                    <button
                      type="button"
                      onClick={() => insertStep(idx)}
                      title="Chèn bước mới phía dưới"
                      className="w-7 h-7 rounded-lg bg-white/5 hover:bg-white/15 text-white/70 hover:text-white flex items-center justify-center text-xs transition-all"
                    >
                      <i className="bi bi-plus"></i>
                    </button>
                    <button
                      type="button"
                      onClick={() => duplicateStep(idx)}
                      title="Nhân bản bước này"
                      className="w-7 h-7 rounded-lg bg-white/5 hover:bg-white/15 text-white/70 hover:text-white flex items-center justify-center text-xs transition-all"
                    >
                      <i className="bi bi-copy"></i>
                    </button>
                    {steps.length > 1 && (
                      <button
                        type="button"
                        onClick={() => removeStep(idx)}
                        title="Xóa bước này"
                        className="w-7 h-7 rounded-lg bg-danger-500/10 hover:bg-danger-500/20 text-danger-400 flex items-center justify-center text-xs transition-all ml-1"
                      >
                        <i className="bi bi-trash"></i>
                      </button>
                    )}
                  </div>
                </div>

                <textarea
                  value={s.text}
                  onChange={(e) => updateStep(idx, { text: e.target.value })}
                  rows={3}
                  placeholder="Nội dung lời thoại, tin nhắn hoặc hành động của bước này..."
                  className="w-full bg-black/40 border border-white/10 rounded-xl p-3 text-sm text-white focus:outline-none focus:border-brand-500/40 resize-y"
                  required
                />

                <input
                  type="text"
                  value={s.note}
                  onChange={(e) => updateStep(idx, { note: e.target.value })}
                  placeholder="Ghi chú phân tích thủ đoạn / bài học rút ra..."
                  className="w-full bg-black/20 border border-white/5 rounded-lg px-3 py-1.5 text-xs text-white/70 focus:outline-none focus:border-brand-500/30"
                />
              </div>
            ))}
          </div>
        </div>

        <div className="flex flex-col md:flex-row md:justify-end gap-3 pt-4">
          <Link
            href="/admin-cp/scenarios/"
            className="px-6 py-3 rounded-xl bg-white/5 border border-white/10 text-xs font-bold text-white/70 hover:bg-white/10 transition-all text-center"
          >
            Hủy
          </Link>
          <button
            type="submit"
            disabled={loading}
            className="px-8 py-3 rounded-xl bg-brand-500 text-black text-xs font-black uppercase tracking-widest hover:bg-brand-400 transition-all shadow-[0_0_24px_rgba(6,182,212,0.3)] disabled:opacity-50"
          >
            {loading ? 'Đang lưu...' : isEditing ? 'Lưu Thay Đổi' : 'Tạo Kịch Bản'}
          </button>
        </div>
      </form>
    </AdminShell>
  );
}
