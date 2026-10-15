'use client';
import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { api, mediaUrl } from '../../lib/api';
import { showToast, scConfirm } from '../../lib/ui/feedback';
import { LiquidSelect } from '../../components/ui';
import type { SelectOption } from '../../components/ui';
import RichEditor from '../../components/RichEditor';

/* Port 1-1 từ PKV/templates/Admin/edit_lesson.html (Alpine lessonEditor()).
 *
 * API giữ nguyên:
 *   - GET  /admin/learn/<id>/            -> nạp bài học, quiz, kịch bản
 *   - POST /admin/learn/                 -> tạo bài học mới
 *   - PUT  /admin/learn/<id>/            -> cập nhật bài học
 *   - DELETE /admin/learn/<id>/          -> xóa bài học
 *   - POST /admin/content/generate-summary/ -> sinh tóm tắt AI
 *
 * Lưu ý field thiếu từ API (giữ markup + fallback):
 *   - cover_image: AdminLearnDetailView trả + AdminLearnView POST/PUT lưu (FormData).
 *   - slug: AdminLearnView POST/PUT nhận và lưu.
 */

type QuestionType = 'single_choice' | 'multiple_choice' | 'true_false';

interface QuizItem {
  question: string;
  question_type: QuestionType | string;
  options: string[];
  correct_answer: string;
  correct_answers: string[];
  correct_index: number;
  correct_indices: number[];
  explanation: string;
}

interface ScenarioStep {
  speaker: 'scammer' | 'victim' | 'narrator';
  text: string;
  note: string;
}

interface LessonDetail {
  id: number;
  title: string;
  slug: string;
  category: string;
  summary: string;
  content: string;
  is_published: boolean;
  cover_image?: string | null;
  quizzes?: Partial<QuizItem>[];
  scenario?: { id?: number; title: string; description: string; steps: ScenarioStep[] } | null;
}

const CATEGORY_OPTIONS: SelectOption[] = [
  { value: 'guide', label: 'Hướng dẫn' },
  { value: 'alert', label: 'Cảnh báo mới' },
  { value: 'story', label: 'Chuyện cảnh giác' },
  { value: 'news', label: 'Tin tức' },
];

const LESSON_CSS = `
.admin-form-input {
    width: 100%;
    background: rgba(15, 23, 42, 0.4);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 1rem;
    padding: 0.75rem 1rem;
    color: white;
    transition: all 0.3s;
    font-size: 0.875rem;
}
.admin-form-input:focus {
    border-color: var(--sc-brand-500);
    outline: none;
    background: rgba(15, 23, 42, 0.6);
}
.admin-form-input::placeholder { color: rgba(255,255,255,0.25); }
textarea.admin-form-input { resize: vertical; min-height: 80px; }

.quiz-option { display: flex; align-items: center; gap: 0.75rem; }
.quiz-option input[type="radio"] {
    accent-color: var(--sc-safe-500);
    width: 16px; height: 16px;
    cursor: pointer;
    flex-shrink: 0;
}

.step-card {
    background: rgba(255,255,255,0.02);
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 1rem;
    padding: 1rem;
    transition: all 0.2s;
}
.step-card:hover { border-color: rgba(59,130,246,0.3); }

.section-header {
    display: flex; align-items: center; gap: 0.75rem;
    padding-bottom: 1rem; margin-bottom: 1.5rem;
    border-bottom: 1px solid rgba(255,255,255,0.05);
}
.section-icon {
    width: 2.5rem; height: 2.5rem; border-radius: 0.75rem;
    display: flex; align-items: center; justify-content: center;
    font-size: 1rem;
}

.cover-dropzone {
    border: 1px dashed rgba(255,255,255,0.16);
    background: linear-gradient(135deg, rgba(255,255,255,0.03), rgba(255,255,255,0.01));
    border-radius: 1rem;
    padding: 1rem;
    cursor: pointer;
    transition: all 0.25s ease;
}
.cover-dropzone:hover { border-color: rgba(59,130,246,0.45); background: rgba(59,130,246,0.08); }
.cover-preview {
    border-radius: 1rem;
    border: 1px solid rgba(255,255,255,0.12);
    overflow: hidden;
    background: rgba(255,255,255,0.02);
}
.cover-preview img {
    width: 100%;
    height: 220px;
    object-fit: cover;
    display: block;
}

.publish-toggle {
    width: 52px;
    height: 28px;
    border-radius: 9999px;
    background: rgba(255,255,255,0.14);
    border: 1px solid rgba(255,255,255,0.16);
    position: relative;
    transition: all 0.25s ease;
}
.publish-toggle::after {
    content: '';
    width: 22px;
    height: 22px;
    border-radius: 9999px;
    background: var(--sc-white);
    position: absolute;
    left: 2px;
    top: 2px;
    transition: transform 0.25s ease;
}
.publish-toggle.on {
    background: rgba(34,197,94,0.35);
    border-color: rgba(34,197,94,0.45);
}
.publish-toggle.on::after {
    transform: translateX(24px);
}
`;

function normalizeQuiz(q: Partial<QuizItem>): QuizItem {
  const opts = Array.isArray(q.options) && q.options.length === 4 ? [...q.options] : ['', '', '', ''];
  const qType = (q.question_type as string) || 'single_choice';
  if (qType === 'true_false') {
    opts[0] = 'Đúng';
    opts[1] = 'Sai';
    opts[2] = '';
    opts[3] = '';
  }
  const correctAnswer = q.correct_answer || '';
  const correctIdx = opts.indexOf(correctAnswer);
  const rawCorrectAnswers = Array.isArray(q.correct_answers) ? q.correct_answers : correctAnswer ? [correctAnswer] : [];
  const correctIndices = rawCorrectAnswers.map((ans) => opts.indexOf(ans)).filter((idx) => idx >= 0);
  return {
    question: q.question || '',
    question_type: qType,
    options: opts,
    correct_answer: correctAnswer,
    correct_answers: rawCorrectAnswers,
    correct_index: correctIdx >= 0 ? correctIdx : 0,
    correct_indices: correctIndices.length ? correctIndices : [0],
    explanation: q.explanation || '',
  };
}

function emptyQuiz(): QuizItem {
  return {
    question: '',
    question_type: 'single_choice',
    options: ['', '', '', ''],
    correct_answer: '',
    correct_answers: [],
    correct_index: 0,
    correct_indices: [0],
    explanation: '',
  };
}

function applyTypeChange(quiz: QuizItem): QuizItem {
  if (quiz.question_type === 'true_false') {
    const options = ['Đúng', 'Sai', '', ''];
    return { ...quiz, options, correct_index: 0, correct_indices: [0], correct_answer: options[0], correct_answers: [options[0]] };
  }
  if (quiz.question_type === 'multiple_choice') {
    const correct_indices = Array.isArray(quiz.correct_indices) && quiz.correct_indices.length ? quiz.correct_indices : [0];
    const correct_answers = correct_indices.map((i) => quiz.options[i]).filter(Boolean);
    return { ...quiz, correct_indices, correct_answers, correct_answer: correct_answers[0] || '' };
  }
  const correct_index = Number.isInteger(quiz.correct_index) ? quiz.correct_index : 0;
  const correct_answer = quiz.options[correct_index] || quiz.options[0] || '';
  return { ...quiz, correct_index, correct_answer, correct_answers: [correct_answer].filter(Boolean) };
}

function applyToggleMulti(quiz: QuizItem, optionIndex: number): QuizItem {
  let correct_indices = Array.isArray(quiz.correct_indices) ? [...quiz.correct_indices] : [];
  if (correct_indices.includes(optionIndex)) {
    correct_indices = correct_indices.filter((i) => i !== optionIndex);
  } else {
    correct_indices.push(optionIndex);
  }
  if (!correct_indices.length) correct_indices = [0];
  const correct_answers = correct_indices.map((i) => quiz.options[i]).filter(Boolean);
  return { ...quiz, correct_indices, correct_answers, correct_answer: correct_answers[0] || '' };
}

function applySyncAnswer(quiz: QuizItem, optionIndex: number): QuizItem {
  if (quiz.question_type === 'multiple_choice') {
    const correct_answers = quiz.correct_indices.map((i) => quiz.options[i]).filter(Boolean);
    return { ...quiz, correct_answers, correct_answer: correct_answers[0] || '' };
  }
  if (quiz.correct_index === optionIndex) {
    const correct_answer = quiz.options[optionIndex];
    return { ...quiz, correct_answer, correct_answers: [correct_answer].filter(Boolean) };
  }
  return quiz;
}

function normalizeSummaryText(value: unknown): string {
  const text = String(value ?? '').trim();
  if (!text) return '';
  const pick = (obj: unknown): string => {
    if (!obj || typeof obj !== 'object') return '';
    const o = obj as Record<string, unknown>;
    return String(o.summary || o['tóm_tắt'] || o.tom_tat || o.content || o.text || '').trim();
  };
  if ((text.startsWith('{') && text.endsWith('}')) || (text.startsWith('[') && text.endsWith(']'))) {
    try {
      const parsed: unknown = JSON.parse(text);
      const fromParsed = Array.isArray(parsed) ? pick(parsed[0]) : pick(parsed);
      if (fromParsed) return fromParsed;
    } catch {
      /* ignore */
    }
  }
  return text;
}

export default function EditLesson() {
  const params = useParams();
  const router = useRouter();
  const lessonId = params?.id as string | undefined;
  const isEditing = Boolean(lessonId);

  const [title, setTitle] = useState('');
  const [slug, setSlug] = useState('');
  const [category, setCategory] = useState('guide');
  const [summary, setSummary] = useState('');
  const [content, setContent] = useState('');
  const [initialContent, setInitialContent] = useState('');
  const [isPublished, setIsPublished] = useState(true);
  const [existingCover, setExistingCover] = useState('');
  const [coverFile, setCoverFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState('');

  const [quizzes, setQuizzes] = useState<QuizItem[]>([]);
  const [scenarioId, setScenarioId] = useState<number | null>(null);
  const [scenarioTitle, setScenarioTitle] = useState('');
  const [scenarioDesc, setScenarioDesc] = useState('');
  const [steps, setSteps] = useState<ScenarioStep[]>([]);

  const [saving, setSaving] = useState(false);
  const [fetching, setFetching] = useState(isEditing);
  const [summaryLoading, setSummaryLoading] = useState(false);

  useEffect(() => {
    if (!lessonId) return;
    let alive = true;
    api
      .get<LessonDetail>(`/admin/learn/${lessonId}/`)
      .then((d) => {
        if (!alive) return;
        setTitle(d.title || '');
        setSlug(d.slug || '');
        setCategory(d.category || 'guide');
        setSummary(d.summary || '');
        setContent(d.content || '');
        setInitialContent(d.content || '');
        setIsPublished(d.is_published ?? true);
        setExistingCover(d.cover_image || '');
        if (Array.isArray(d.quizzes)) setQuizzes(d.quizzes.map(normalizeQuiz));
        if (d.scenario) {
          setScenarioId(d.scenario.id ?? null);
          setScenarioTitle(d.scenario.title || '');
          setScenarioDesc(d.scenario.description || '');
          setSteps(Array.isArray(d.scenario.steps) ? d.scenario.steps : []);
        }
      })
      .catch((err: unknown) => {
        showToast(err instanceof Error ? err.message : 'Không thể tải dữ liệu bài học.', 'error');
      })
      .finally(() => {
        if (alive) setFetching(false);
      });
    return () => {
      alive = false;
    };
  }, [lessonId]);

  const updateQuiz = (idx: number, updater: (q: QuizItem) => QuizItem) => {
    setQuizzes((prev) => prev.map((q, i) => (i === idx ? updater(q) : q)));
  };

  const addQuiz = () => setQuizzes((prev) => [...prev, emptyQuiz()]);
  const removeQuiz = (idx: number) => setQuizzes((prev) => prev.filter((_, i) => i !== idx));

  const addStep = () => setSteps((prev) => [...prev, { speaker: 'scammer', text: '', note: '' }]);
  const removeStep = (idx: number) => setSteps((prev) => prev.filter((_, i) => i !== idx));
  const updateStep = (idx: number, patch: Partial<ScenarioStep>) =>
    setSteps((prev) => prev.map((s, i) => (i === idx ? { ...s, ...patch } : s)));

  const quizzesForSave = () =>
    quizzes.map((q) => ({
      question: q.question,
      question_type: q.question_type || 'single_choice',
      options: q.options,
      correct_answer:
        q.question_type === 'multiple_choice'
          ? q.correct_indices.map((i) => q.options[i]).filter(Boolean)[0] || ''
          : q.options[q.correct_index] || q.options[0] || '',
      correct_answers:
        q.question_type === 'multiple_choice'
          ? q.correct_indices.map((i) => q.options[i]).filter(Boolean)
          : [(q.options[q.correct_index] || q.options[0] || '')].filter(Boolean),
      explanation: q.explanation,
    }));

  const genSummary = async () => {
    if (!content.trim()) {
      showToast('Cần có nội dung để tạo tóm tắt', 'warning');
      return;
    }
    setSummaryLoading(true);
    try {
      const d = await api.post<{ status?: string; summary?: string; message?: string }>('/admin/content/generate-summary/', {
        title,
        content,
      });
      if (!d.status || d.status === 'success') {
        setSummary(normalizeSummaryText(d.summary));
        showToast('Đã tạo tóm tắt', 'success');
      } else {
        showToast(d.message || 'Không tạo được tóm tắt', 'error');
      }
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Lỗi kết nối khi tạo tóm tắt', 'error');
    } finally {
      setSummaryLoading(false);
    }
  };

  const handleCoverChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0] || null;
    setCoverFile(f);
    setPreviewUrl(f ? URL.createObjectURL(f) : '');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (saving) return;
    if (!title.trim() || !content.trim()) {
      showToast('Vui lòng nhập tiêu đề và nội dung bài học.', 'warning');
      return;
    }

    setSaving(true);
    const form = new FormData();
    form.append('title', title);
    form.append('slug', slug);
    form.append('category', category);
    form.append('summary', summary);
    form.append('content', content);
    form.append('is_published', isPublished ? 'true' : 'false');
    form.append('quizzes', JSON.stringify(quizzes.filter((q) => q.question.trim())));
    form.append(
      'scenario',
      scenarioTitle.trim()
        ? JSON.stringify({
            title: scenarioTitle,
            description: scenarioDesc,
            steps: steps.filter((s) => s.text.trim()),
          })
        : '',
    );
    if (coverFile) form.append('cover_image', coverFile);

    try {
      if (isEditing) {
        await api.put(`/admin/learn/${lessonId}/`, form);
        showToast('Bài học đã được lưu thành công.', 'success');
      } else {
        await api.post('/admin/learn/', form);
        showToast('Bài học đã được lưu thành công.', 'success');
        router.push('/admin-cp/learn/');
      }
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Lưu bài học thất bại.', 'error');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    const ok = await scConfirm('Xóa bài học này?', {
      title: 'Xóa bài học',
      icon: 'warning',
      confirmButtonText: 'Xóa',
      cancelButtonText: 'Hủy',
    });
    if (!ok) return;
    try {
      await api.del(`/admin/learn/${lessonId}/`);
      showToast('Đã xóa bài học.', 'success');
      router.push('/admin-cp/learn/');
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Xóa bài học thất bại.', 'error');
    }
  };

  if (fetching) {
    return (
      <div className="container mx-auto px-4 py-8 mt-16">
        <div className="liquid-card p-8 text-center text-white/60 text-sm">Đang tải dữ liệu bài học...</div>
      </div>
    );
  }

  const previewSrc = previewUrl || mediaUrl(existingCover);
  const pageTitle = isEditing ? 'Chỉnh sửa bài học' : 'Thêm bài học mới';

  return (
    <div className="container mx-auto px-4 py-8 mt-16">
      <style>{LESSON_CSS}</style>

      <div className="flex items-center justify-between mb-10">
        <div className="flex items-center gap-6">
          <Link
            href="/admin-cp/learn/"
            className="w-12 h-12 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center text-white/55 hover:text-brand-400 hover:border-brand-500/30 transition-all"
          >
            <i className="bi bi-chevron-left text-xl"></i>
          </Link>
          <div>
            <h1 className="text-3xl font-black text-white tracking-tight">{pageTitle}</h1>
            <p className="text-[10px] font-bold text-white/35 uppercase tracking-widest mt-1">Bài học · Quiz · Kịch bản</p>
          </div>
        </div>

        <button
          type="submit"
          form="lessonForm"
          disabled={saving}
          className="px-8 py-3.5 rounded-2xl bg-brand-600 text-white font-black uppercase tracking-widest hover:bg-brand-500 transition-all shadow-lg shadow-brand-500/20 flex items-center gap-2"
        >
          <i className="bi bi-save2 text-lg"></i>
          Lưu tất cả
        </button>
      </div>

      <form id="lessonForm" method="post" encType="multipart/form-data" onSubmit={handleSubmit}>
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          {/* Main Column */}
          <div className="lg:col-span-8 space-y-8">
            {/* Lesson Content */}
            <div className="liquid-card p-8 space-y-6 border-white/5 bg-slate-900/40">
              <div className="section-header">
                <div className="section-icon bg-brand-500/10 text-brand-400 border border-brand-500/20">
                  <i className="bi bi-journal-text"></i>
                </div>
                <div>
                  <h2 className="text-sm font-black text-white uppercase tracking-widest">Nội dung bài học</h2>
                  <p className="text-[10px] text-white/45 mt-0.5">Viết nội dung HTML hoặc dùng CKEditor</p>
                </div>
              </div>
              <div className="space-y-4">
                <div className="space-y-2">
                  <label className="block text-[10px] font-black text-white/55 uppercase tracking-widest ml-1">Tiêu đề bài học</label>
                  <input
                    type="text"
                    name="title"
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    placeholder="Nhập tiêu đề bài học..."
                    className="admin-form-input"
                  />
                </div>
                <div className="space-y-2">
                  <label className="block text-[10px] font-black text-white/55 uppercase tracking-widest ml-1">Slug (Đường dẫn)</label>
                  <input
                    type="text"
                    name="slug"
                    value={slug}
                    onChange={(e) => setSlug(e.target.value)}
                    placeholder="duong-dan-bai-hoc (để trống để tự tạo)"
                    className="admin-form-input"
                  />
                </div>
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="block text-[10px] font-black text-white/55 uppercase tracking-widest ml-1">Tóm tắt</label>
                    <button
                      type="button"
                      id="btn-gen-summary-lesson"
                      onClick={() => void genSummary()}
                      disabled={summaryLoading}
                      className="px-3 py-1 rounded-lg bg-brand-500/10 border border-brand-500/20 text-brand-400 text-[10px] font-black uppercase tracking-widest hover:bg-brand-500/20 transition-all"
                    >
                      {summaryLoading ? (
                        <>
                          <i className="bi bi-arrow-repeat animate-spin mr-1"></i> Đang tạo...
                        </>
                      ) : (
                        <>
                          <i className="bi bi-stars mr-1"></i> Gen tóm tắt
                        </>
                      )}
                    </button>
                  </div>
                  <textarea
                    name="summary"
                    value={summary}
                    onChange={(e) => setSummary(e.target.value)}
                    rows={3}
                    placeholder="Tóm tắt ngắn (1-3 câu)..."
                    className="admin-form-input"
                  ></textarea>
                </div>
                <div className="space-y-2">
                  <label className="block text-[10px] font-black text-white/55 uppercase tracking-widest ml-1">Nội dung bài học</label>
                  <div className="rounded-3xl overflow-hidden border border-white/10">
                    <RichEditor initialData={initialContent} onChangeData={setContent} placeholder="Nội dung bài học..." minLines={12} />
                  </div>
                </div>
              </div>
            </div>

            {/* Quiz Section */}
            <div className="liquid-card p-8 space-y-6 border-white/5 bg-slate-900/40">
              <div className="section-header">
                <div className="section-icon bg-brand2-500/10 text-brand2-400 border border-brand2-500/20">
                  <i className="bi bi-list-check"></i>
                </div>
                <div>
                  <h2 className="text-sm font-black text-white uppercase tracking-widest">Quiz kiểm tra</h2>
                  <p className="text-[10px] text-white/45 mt-0.5">Hỗ trợ chọn 1 đáp án, chọn nhiều đáp án và đúng/sai</p>
                </div>
                <button
                  type="button"
                  onClick={addQuiz}
                  className="ml-auto px-4 py-1.5 rounded-lg bg-brand2-500/10 text-brand2-400 text-[10px] font-black uppercase tracking-widest border border-brand2-500/20 hover:bg-brand2-500/20 transition-all"
                >
                  <i className="bi bi-plus-lg mr-1"></i> Thêm quiz
                </button>
              </div>

              <div className="space-y-5">
                {quizzes.map((quiz, qi) => (
                  <div key={qi} className="p-5 rounded-2xl bg-white/[0.02] border border-white/5 space-y-4 transition-all hover:border-brand2-500/15">
                    <div className="flex items-center justify-between">
                      <span className="inline-flex items-center gap-2 px-3 py-1 rounded-lg bg-brand2-500/10 border border-brand2-500/15 text-xs font-black text-brand2-400">
                        <i className="bi bi-patch-question"></i> Quiz #{qi + 1}
                      </span>
                      <button
                        type="button"
                        onClick={() => removeQuiz(qi)}
                        className="px-3 py-1 rounded-lg bg-danger-500/10 text-danger-400 text-[10px] font-bold border border-danger-500/15 hover:bg-danger-500/20 transition-all"
                      >
                        <i className="bi bi-trash3 mr-1"></i> Xóa
                      </button>
                    </div>

                    <div className="space-y-2">
                      <label className="block text-[10px] font-black text-white/55 uppercase tracking-widest ml-1">Câu hỏi</label>
                      <textarea
                        value={quiz.question}
                        onChange={(e) => updateQuiz(qi, (q) => ({ ...q, question: e.target.value }))}
                        className="admin-form-input"
                        rows={2}
                        placeholder="Nhập câu hỏi trắc nghiệm..."
                      ></textarea>
                    </div>

                    <div className="space-y-2">
                      <label className="block text-[10px] font-black text-white/55 uppercase tracking-widest ml-1">Loại câu hỏi</label>
                      <select
                        value={quiz.question_type}
                        onChange={(e) => updateQuiz(qi, (q) => applyTypeChange({ ...q, question_type: e.target.value }))}
                        className="admin-form-input"
                      >
                        <option value="single_choice">Chọn 1 đáp án</option>
                        <option value="multiple_choice">Chọn nhiều đáp án</option>
                        <option value="true_false">Đúng / Sai</option>
                      </select>
                    </div>

                    <div className="space-y-3">
                      <label className="block text-[10px] font-black text-white/55 uppercase tracking-widest ml-1">
                        {quiz.question_type === 'multiple_choice'
                          ? 'Đáp án (checkbox = các đáp án đúng)'
                          : 'Đáp án (radio = đáp án đúng)'}
                      </label>
                      {quiz.options.map((opt, oi) => (
                        <div key={oi} className="quiz-option">
                          {quiz.question_type !== 'multiple_choice' && (
                            <input
                              type="radio"
                              name={`quiz_correct_${qi}`}
                              value={oi}
                              checked={quiz.correct_index === oi}
                              onChange={() =>
                                updateQuiz(qi, (q) => ({ ...q, correct_index: oi, correct_answer: q.options[oi] }))
                              }
                            />
                          )}
                          {quiz.question_type === 'multiple_choice' && (
                            <input
                              type="checkbox"
                              checked={quiz.correct_indices.includes(oi)}
                              onChange={() => updateQuiz(qi, (q) => applyToggleMulti(q, oi))}
                            />
                          )}
                          <input
                            type="text"
                            value={opt}
                            onChange={(e) =>
                              updateQuiz(qi, (q) => {
                                const options = [...q.options];
                                options[oi] = e.target.value;
                                return applySyncAnswer({ ...q, options }, oi);
                              })
                            }
                            className="admin-form-input flex-1"
                            placeholder={`Đáp án ${String.fromCharCode(65 + oi)}`}
                          />
                        </div>
                      ))}
                    </div>

                    <div className="space-y-2">
                      <label className="block text-[10px] font-black text-white/55 uppercase tracking-widest ml-1">Giải thích đáp án</label>
                      <textarea
                        value={quiz.explanation}
                        onChange={(e) => updateQuiz(qi, (q) => ({ ...q, explanation: e.target.value }))}
                        className="admin-form-input"
                        rows={2}
                        placeholder="Giải thích tại sao đáp án đúng..."
                      ></textarea>
                    </div>
                  </div>
                ))}

                {quizzes.length === 0 && (
                  <div className="p-8 rounded-2xl bg-white/[0.02] border border-dashed border-white/10 text-center">
                    <i className="bi bi-patch-question text-3xl text-white/20 mb-2 block"></i>
                    <p className="text-white/35 text-xs font-bold">Chưa có quiz nào</p>
                    <button
                      type="button"
                      onClick={addQuiz}
                      className="mt-3 px-4 py-2 rounded-lg bg-brand2-500/10 text-brand2-400 text-xs font-bold border border-brand2-500/20 hover:bg-brand2-500/20 transition-all"
                    >
                      <i className="bi bi-plus-lg mr-1"></i> Thêm quiz đầu tiên
                    </button>
                  </div>
                )}
              </div>

              {/* Hidden field for quizzes JSON */}
              <input type="hidden" name="quizzes_json" value={JSON.stringify(quizzesForSave())} readOnly />
            </div>

            {/* Scenario Section */}
            <div className="liquid-card p-8 space-y-6 border-white/5 bg-slate-900/40">
              <div className="section-header">
                <div className="section-icon bg-brand-500/10 text-brand-400 border border-brand-500/20">
                  <i className="bi bi-chat-dots"></i>
                </div>
                <div>
                  <h2 className="text-sm font-black text-white uppercase tracking-widest">Kịch bản hội thoại</h2>
                  <p className="text-[10px] text-white/45 mt-0.5">Mô phỏng tình huống lừa đảo</p>
                </div>
              </div>

              {scenarioId != null && <input type="hidden" name="scenario_id" value={scenarioId} readOnly />}

              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <label className="block text-[10px] font-black text-white/55 uppercase tracking-widest ml-1">Tiêu đề kịch bản</label>
                    <input
                      type="text"
                      name="scenario_title"
                      className="admin-form-input"
                      placeholder="VD: Cuộc gọi giả mạo ngân hàng"
                      value={scenarioTitle}
                      onChange={(e) => setScenarioTitle(e.target.value)}
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="block text-[10px] font-black text-white/55 uppercase tracking-widest ml-1">Mô tả ngắn</label>
                    <input
                      type="text"
                      name="scenario_description"
                      className="admin-form-input"
                      placeholder="Mô tả vắn tắt tình huống..."
                      value={scenarioDesc}
                      onChange={(e) => setScenarioDesc(e.target.value)}
                    />
                  </div>
                </div>

                {/* Steps Editor */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="block text-[10px] font-black text-white/55 uppercase tracking-widest ml-1">Các bước hội thoại</label>
                    <button
                      type="button"
                      onClick={addStep}
                      className="px-4 py-1.5 rounded-lg bg-brand-500/10 text-brand-400 text-[10px] font-black uppercase tracking-widest border border-brand-500/20 hover:bg-brand-500/20 transition-all"
                    >
                      <i className="bi bi-plus-lg mr-1"></i> Thêm bước
                    </button>
                  </div>

                  <div className="space-y-3" id="stepsContainer">
                    {steps.map((step, idx) => (
                      <div key={idx} className="step-card">
                        <div className="flex items-start gap-3">
                          <div className="flex flex-col items-center gap-1 pt-1">
                            <span className="text-[9px] font-black text-white/35">{idx + 1}</span>
                            <button
                              type="button"
                              onClick={() => removeStep(idx)}
                              className="w-6 h-6 rounded-md bg-danger-500/10 text-danger-400 flex items-center justify-center hover:bg-danger-500/20 transition-all text-xs"
                            >
                              <i className="bi bi-trash3"></i>
                            </button>
                          </div>
                          <div className="flex-1 space-y-2">
                            <div className="flex gap-2">
                              <select
                                value={step.speaker}
                                onChange={(e) => updateStep(idx, { speaker: e.target.value as ScenarioStep['speaker'] })}
                                className="admin-form-input"
                                style={{ width: '160px', flexShrink: 0 }}
                              >
                                <option value="scammer">🦹 Kẻ lừa đảo</option>
                                <option value="victim">👤 Nạn nhân</option>
                                <option value="narrator">📝 Người kể</option>
                              </select>
                              <input
                                type="text"
                                value={step.text}
                                onChange={(e) => updateStep(idx, { text: e.target.value })}
                                className="admin-form-input flex-1"
                                placeholder="Nội dung lời thoại..."
                              />
                            </div>
                            <input
                              type="text"
                              value={step.note}
                              onChange={(e) => updateStep(idx, { note: e.target.value })}
                              className="admin-form-input text-[11px]"
                              placeholder="Ghi chú phân tích (tùy chọn)..."
                              style={{ background: 'rgba(168,85,247,0.05)', borderColor: 'rgba(168,85,247,0.1)' }}
                            />
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>

                  {steps.length === 0 && (
                    <div className="p-8 rounded-2xl bg-white/[0.02] border border-dashed border-white/10 text-center">
                      <i className="bi bi-chat-square-text text-3xl text-white/20 mb-2 block"></i>
                      <p className="text-white/35 text-xs font-bold">Chưa có bước hội thoại nào</p>
                      <button
                        type="button"
                        onClick={addStep}
                        className="mt-3 px-4 py-2 rounded-lg bg-brand-500/10 text-brand-400 text-xs font-bold border border-brand-500/20 hover:bg-brand-500/20 transition-all"
                      >
                        <i className="bi bi-plus-lg mr-1"></i> Thêm bước đầu tiên
                      </button>
                    </div>
                  )}
                </div>

                {/* Hidden field for steps JSON */}
                <input type="hidden" name="scenario_steps" value={JSON.stringify(steps)} readOnly />
              </div>
            </div>
          </div>

          {/* Sidebar Column */}
          <div className="lg:col-span-4 space-y-8">
            <div className="liquid-card p-6 space-y-6 border-white/5 bg-slate-900/40 sticky top-24">
              <div className="space-y-2">
                <label className="block text-[10px] font-black text-white/55 uppercase tracking-widest ml-1">Danh mục</label>
                <LiquidSelect
                  value={category}
                  options={CATEGORY_OPTIONS}
                  onChange={setCategory}
                  placeholder="Chọn danh mục"
                  triggerClass=""
                />
                <input type="hidden" id="id_category" name="category" value={category} readOnly />
              </div>

              <div className="space-y-2">
                <label className="block text-[10px] font-black text-white/55 uppercase tracking-widest ml-1">Ảnh đại diện (Cover)</label>
                <div className="p-4 rounded-2xl bg-black/40 border border-white/5 space-y-3">
                  <input
                    id="id_cover_image"
                    name="cover_image"
                    type="file"
                    accept="image/*"
                    className="sr-only"
                    onChange={handleCoverChange}
                  />
                  <input type="hidden" id="lesson-cover-existing" value={existingCover} readOnly />
                  <label htmlFor="id_cover_image" className="cover-dropzone block">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-xl bg-brand-500/15 text-brand-400 flex items-center justify-center">
                        <i className="bi bi-image-fill"></i>
                      </div>
                      <div className="min-w-0">
                        <p className="text-xs font-black text-white">Chọn ảnh bìa</p>
                        <p className="text-[11px] text-white/55 truncate" id="lesson-cover-filename">
                          {coverFile
                            ? coverFile.name
                            : existingCover
                              ? 'Ảnh hiện tại đang được dùng'
                              : 'PNG/JPG/WebP · Tối đa 5MB'}
                        </p>
                      </div>
                    </div>
                  </label>
                  <div id="lesson-cover-preview" className={`cover-preview${previewSrc ? '' : ' hidden'}`}>
                    {previewSrc ? (
                      // eslint-disable-next-line @next/next/no-img-element
                      <img id="lesson-cover-preview-img" src={previewSrc} alt={title} />
                    ) : (
                      // eslint-disable-next-line @next/next/no-img-element
                      <img id="lesson-cover-preview-img" src="" alt="Preview" className="hidden" />
                    )}
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-between p-4 rounded-2xl bg-brand-500/5 border border-brand-500/10">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg bg-brand-500/10 text-brand-400 flex items-center justify-center">
                    <i className="bi bi-eye-fill"></i>
                  </div>
                  <span className="text-xs font-black text-white/80 uppercase tracking-wider">Công khai</span>
                </div>
                <label
                  htmlFor="id_is_published"
                  className={`publish-toggle${isPublished ? ' on' : ''}`}
                  onClick={(e) => {
                    e.preventDefault();
                    setIsPublished((v) => !v);
                  }}
                ></label>
                <div className="hidden">
                  <input
                    type="checkbox"
                    id="id_is_published"
                    name="is_published"
                    checked={isPublished}
                    onChange={(e) => setIsPublished(e.target.checked)}
                  />
                </div>
              </div>

              {/* Summary */}
              <div className="p-4 rounded-2xl bg-white/[0.02] border border-white/5 space-y-2">
                <h4 className="text-[10px] font-black text-white/45 uppercase tracking-widest">Tóm tắt</h4>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-white/55">Quiz</span>
                  <span className={`font-bold ${quizzes.length > 0 ? 'text-safe-400' : 'text-warn-500'}`}>
                    {quizzes.length > 0 ? `✓ ${quizzes.length} quiz` : '⚠ Chưa có'}
                  </span>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-white/55">Kịch bản</span>
                  <span className={`font-bold ${steps.length > 0 ? 'text-safe-400' : 'text-warn-500'}`}>
                    {steps.length > 0 ? `✓ ${steps.length} bước` : '⚠ Chưa có'}
                  </span>
                </div>
              </div>

              {isEditing && (
                <button
                  type="button"
                  onClick={() => void handleDelete()}
                  className="w-full py-4 rounded-xl bg-danger-500/10 hover:bg-danger-500 text-danger-500 hover:text-white font-black uppercase tracking-widest transition-all border border-danger-500/20"
                >
                  <i className="bi bi-trash3 me-2 text-lg"></i> Xóa bài học
                </button>
              )}
            </div>
          </div>
        </div>
      </form>
    </div>
  );
}
