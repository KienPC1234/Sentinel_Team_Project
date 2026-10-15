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

  useEffect(() => {
    // Load articles and lessons for dropdown
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

  const removeStep = (idx: number) => {
    setSteps(steps.filter((_, i) => i !== idx));
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

    setLoading(true);
    setMsg(null);

    const payload = {
      title,
      description,
      article_id: articleId !== '' ? Number(articleId) : null,
      lesson_id: lessonId !== '' ? Number(lessonId) : null,
      steps: steps.filter((s) => s.text.trim()),
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
        <div className="flex flex-wrap gap-2">
          <Link href="/admin-cp/scenarios/" className="px-4 py-2 rounded-xl bg-white/5 border border-white/10 text-xs font-bold text-white/70 hover:bg-white/10 transition-all">
            ← Danh sách kịch bản
          </Link>
        </div>

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
                <option value="" className="bg-slate-900 text-white">-- Không gắn bài học --</option>
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
                <option value="" className="bg-slate-900 text-white">-- Không gắn tin tức --</option>
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
              className="px-3.5 py-2 rounded-xl bg-brand-500/15 border border-brand-500/30 text-brand-300 text-xs font-bold hover:bg-brand-500/25 transition-all"
            >
              <i className="bi bi-plus-lg mr-1"></i> Thêm bước
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
                  {steps.length > 1 && (
                    <button
                      type="button"
                      onClick={() => removeStep(idx)}
                      className="text-xs text-danger-400 hover:text-danger-300"
                    >
                      <i className="bi bi-trash mr-1"></i> Xóa bước này
                    </button>
                  )}
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
