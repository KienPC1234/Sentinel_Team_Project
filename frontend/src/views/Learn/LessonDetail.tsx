'use client';
import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { api, ApiError, mediaUrl } from '../../lib/api';
import { MarkdownView } from '../../components/ui';
import { renderMd } from '../../lib/chat/markdown';
import { fmtDate } from '../../lib/date';

/* Port từ PKV/templates/Learning/lesson_detail.html.
 * API đã đấu: GET /learn/lessons/:slug/ (chi tiết + quiz + scenario),
 * POST /learn/lessons/:slug/reaction/ {reaction_type}. */

interface Lesson {
  slug: string;
  title: string;
  content: string;
  category_display?: string;
  cover_image?: string | null;
  created_at?: string;
}

interface ReactionCounts {
  like: number;
  helpful: number;
  insightful: number;
}

interface ReactResp {
  my_reaction?: string | null;
  counts?: ReactionCounts;
  error?: string;
}

interface QuizOption {
  id: string;
  text: string;
}

interface Quiz {
  id: number;
  question: string;
  options: QuizOption[];
  correct_answer?: string;
  correct_answers?: string[];
  explanation?: string;
}

interface ScenarioStep {
  text?: string;
  actor?: string;
  speaker?: string;
  analysis?: string;
  note?: string;
}

interface Scenario {
  title: string;
  description?: string;
}

const CATEGORY_LABEL: Record<string, string> = {
  guide: 'Hướng dẫn an toàn',
  news: 'Tin tức',
  alert: 'Cảnh báo khẩn',
  story: 'Chuyện cảnh giác',
  inclusive: 'An ninh số Bao trùm',
  empathy: 'Góc thấu cảm',
};

export default function LessonDetail() {
  const { slug } = useParams<{ slug: string }>();
  const [my, setMy] = useState<string | null>(null);
  const [counts, setCounts] = useState<ReactionCounts>({ like: 0, helpful: 0, insightful: 0 });
  const [reacting, setReacting] = useState(false);
  const [lesson, setLesson] = useState<Lesson | null>(null);
  const [quizzes, setQuizzes] = useState<Quiz[]>([]);
  const [scenario, setScenario] = useState<Scenario | null>(null);
  const [scenarioSteps, setScenarioSteps] = useState<ScenarioStep[]>([]);
  const [loadError, setLoadError] = useState('');

  useEffect(() => {
    setMy(null);
    setCounts({ like: 0, helpful: 0, insightful: 0 });
  }, [slug]);

  useEffect(() => {
    if (!slug) return;
    let alive = true;
    setLoadError('');
    api
      .get<{
        title: string;
        slug: string;
        summary?: string;
        content?: string;
        category?: string;
        category_display?: string;
        cover_image?: string | null;
        created_at?: string;
        reaction_counts?: ReactionCounts;
        reactions_count?: number;
        my_reaction?: string | null;
        quizzes?: Array<{
          id: number;
          question: string;
          options?: Array<string | { id?: string; text?: string }>;
          correct_answer?: string;
          explanation?: string;
        }>;
        scenario?: { title: string; description?: string; steps?: unknown[] } | null;
      }>(`/learn/lessons/${slug}/`)
      .then((d) => {
        if (!alive) return;
        setLesson({
          slug: d.slug || slug,
          title: d.title || '',
          content: d.content || '',
          category_display: d.category_display || CATEGORY_LABEL[d.category || ''] || d.category,
          cover_image: d.cover_image || null,
          created_at: d.created_at,
        });
        if (d.reaction_counts) {
          setCounts(d.reaction_counts);
        }
        if (d.my_reaction) {
          setMy(d.my_reaction);
        }
        setQuizzes(
          (d.quizzes || []).map((q) => ({
            id: q.id,
            question: q.question,
            options: (q.options || []).map((o) =>
              typeof o === 'string'
                ? { id: o, text: o }
                : { id: String(o.id ?? o.text ?? ''), text: String(o.text ?? o.id ?? '') },
            ),
            correct_answer: q.correct_answer || '',
            explanation: q.explanation,
          })),
        );
        if (d.scenario) {
          setScenario({ title: d.scenario.title, description: d.scenario.description });
          setScenarioSteps((d.scenario.steps || []) as ScenarioStep[]);
        }
      })
      .catch((e: unknown) => {
        if (!alive) return;
        const err = e as { message?: string };
        setLoadError(err.message || 'Không thể tải bài học.');
      });
    return () => {
      alive = false;
    };
  }, [slug]);

  async function react(type: string): Promise<void> {
    if (!slug || reacting) return;
    setReacting(true);
    try {
      const data = await api.post<ReactResp>(`/learn/lessons/${slug}/reaction/`, { reaction_type: type });
      setMy(data.my_reaction || null);
      if (data.counts) setCounts(data.counts);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        window.location.href = `/login/?next=${encodeURIComponent(`/learn/lesson/${slug}/`)}`;
        return;
      }
    } finally {
      setReacting(false);
    }
  }

  if (!slug) return null;

  return (
    <div className="animate-fadein max-w-4xl mx-auto space-y-12 py-12 px-4 sm:px-0">
      {/* Breadcrumbs */}
      <nav className="flex items-center gap-2 text-[10px] font-black uppercase tracking-widest text-white/35">
        <Link href="/" className="hover:text-brand-400 transition-colors">
          Trang chủ
        </Link>
        <i className="bi bi-chevron-right text-[8px]"></i>
        <Link href="/learn/" className="hover:text-brand-400 transition-colors">
          Kiến thức
        </Link>
        <i className="bi bi-chevron-right text-[8px]"></i>
        <span className="text-white/55">{lesson ? lesson.title.substring(0, 30) : slug}</span>
      </nav>

      {/* Lesson Header */}
      {lesson ? (
        <div className="space-y-8 relative">
          <div className="flex items-center gap-4">
            <span className="px-4 py-1.5 rounded-full bg-brand-500/10 text-brand-400 text-[10px] font-black uppercase tracking-[0.2em] border border-brand-500/10">
              {lesson.category_display}
            </span>
            <span className="px-3 py-1 rounded-lg bg-brand-500/20 text-brand-300 text-[8px] font-black uppercase tracking-[0.2em] border border-brand-500/20">
              <i className="bi bi-stars mr-1"></i>Admin Curated + AI Support
            </span>
            <span className="text-[10px] font-bold text-white/45 uppercase tracking-[0.2em] flex items-center gap-2">
              <i className="bi bi-calendar3"></i> {fmtDate(lesson.created_at)}
            </span>
          </div>

          <h1 className="text-4xl sm:text-6xl font-black text-white tracking-tight leading-[1.1] selection:bg-brand-500/30">
            {lesson.title}
          </h1>

          <div className="flex items-center gap-5 py-8 border-y border-white/5 group">
            <div className="relative">
              <div className="absolute inset-0 bg-brand-500 blur-xl opacity-20 group-hover:opacity-40 transition-opacity"></div>
              <div className="relative w-12 h-12 rounded-2xl bg-gradient-to-tr from-slate-900 to-slate-800 border border-white/10 flex items-center justify-center text-brand-400 font-black text-lg shadow-2xl">
                <i className="bi bi-robot"></i>
              </div>
            </div>
            <div>
              <div className="text-xs font-black text-white uppercase tracking-[0.2em]">Biên tập bởi Admin</div>
              <div className="text-[9px] font-bold text-white/35 uppercase tracking-[0.2em] mt-1 flex items-center gap-1.5">
                <i className="bi bi-cpu-fill text-brand-500/50"></i> Nội dung được tổng hợp bởi admin, có sử dụng AI hỗ trợ
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="liquid-card p-6 border border-white/5 text-white/55 text-sm">
          <i className="bi bi-journal-text text-2xl block mb-2 text-white/35"></i>
          {loadError || 'Đang tải nội dung bài học...'}
        </div>
      )}

      {/* Featured Image */}
      {lesson?.cover_image && (
        <div className="relative">
          <div className="absolute inset-0 bg-brand-500/10 blur-3xl opacity-30 rounded-full"></div>
          <div className="relative aspect-[21/9] rounded-[2.5rem] overflow-hidden bg-slate-900 border border-white/10 shadow-[0_20px_50px_rgba(0,0,0,0.5)]">
            <img
              src={mediaUrl(lesson.cover_image)}
              className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-1000"
              alt={lesson.title}
            />
          </div>
        </div>
      )}

      {/* Lesson Content */}
      {lesson && (
        <div
          className="prose prose-invert prose-cyan max-w-none text-white/85 leading-[1.8] font-medium text-base sm:text-lg selection:bg-brand-500/20 px-2"
        >
          <MarkdownView html={renderMd(lesson.content || '')} className="rich-text-content" />
        </div>
      )}

      {/* Reaction */}
      <div className="liquid-card p-6 border border-white/5 space-y-4">
        <div className="text-[10px] font-black text-white/45 uppercase tracking-[0.2em]">Phản ứng bài học</div>
        <div className="flex flex-wrap gap-3">
          {(
            [
              ['like', 'bg-brand-500/20 text-brand-300 border-brand-500/40', 'bg-white/5 text-white/60 border-white/10 hover:border-brand-500/30', 'bi-hand-thumbs-up-fill', 'Thích', counts.like],
              ['helpful', 'bg-safe-500/20 text-safe-300 border-safe-500/40', 'bg-white/5 text-white/60 border-white/10 hover:border-safe-500/30', 'bi-patch-check-fill', 'Hữu ích', counts.helpful],
              ['insightful', 'bg-brand2-500/20 text-brand2-300 border-brand2-500/40', 'bg-white/5 text-white/60 border-white/10 hover:border-brand2-500/30', 'bi-lightbulb-fill', 'Bổ ích', counts.insightful],
            ] as const
          ).map(([t, activeCls, idleCls, icon, label, n]) => (
            <button
              key={t}
              type="button"
              onClick={() => void react(t)}
              disabled={reacting}
              className={`px-4 py-2 rounded-xl border text-xs font-bold transition-all ${my === t ? activeCls : idleCls}`}
            >
              <i className={`bi ${icon} mr-1.5`}></i> {label} <span className="ml-1">{n}</span>
            </button>
          ))}
        </div>
      </div>

      {/* ═══ QUIZZES SECTION ═══ */}
      {quizzes.length > 0 && (
        <div className="space-y-10 pt-16 border-t border-white/5">
          <div className="flex items-center gap-5">
            <div className="relative">
              <div className="absolute inset-0 bg-brand2-500 blur-xl opacity-30"></div>
              <div className="relative w-14 h-14 rounded-2xl bg-brand2-500/10 text-brand2-400 flex items-center justify-center border border-brand2-500/20 shadow-xl group">
                <i className="bi bi-lightning-charge-fill text-2xl group-hover:scale-110 transition-transform"></i>
              </div>
            </div>
            <div>
              <h2 className="text-2xl font-black text-white tracking-tight">Thử thách kiến thức</h2>
              <p className="text-[10px] font-black text-white/45 uppercase tracking-[0.3em] mt-1">
                {quizzes.length} CÂU HỎI DIỄN TẬP
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            {quizzes.map((q, index) => (
              <QuizCard key={q.id} quiz={q} index={index} />
            ))}
          </div>
        </div>
      )}

      {/* ═══ SCENARIO SECTION ═══ */}
      {scenario && <ScenarioPlayer scenario={scenario} steps={scenarioSteps} />}

      {/* Footer */}
      <div className="pt-12 border-t border-white/5 flex flex-col sm:flex-row justify-between items-center gap-8">
        <div className="flex items-center gap-6">
          <span className="text-[10px] font-black text-white/35 uppercase tracking-[0.3em]">CHIA SẺ KIẾN THỨC</span>
          <div className="flex gap-3">
            <button
              type="button"
              onClick={() => {
                const u = typeof window !== 'undefined' ? window.location.href : '';
                window.open(`https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(u)}`, '_blank', 'noopener');
              }}
              aria-label="Chia sẻ Facebook"
              className="w-12 h-12 rounded-2xl bg-white/5 flex items-center justify-center text-white/55 hover:text-white hover:bg-white/10 transition-all border border-white/5 hover:border-brand-500/20 active:scale-90"
            >
              <i className="bi bi-facebook text-lg"></i>
            </button>
            <button
              type="button"
              onClick={() => {
                const u = typeof window !== 'undefined' ? window.location.href : '';
                window.open(`https://twitter.com/intent/tweet?url=${encodeURIComponent(u)}&text=${encodeURIComponent(lesson?.title || '')}`, '_blank', 'noopener');
              }}
              aria-label="Chia sẻ X"
              className="w-12 h-12 rounded-2xl bg-white/5 flex items-center justify-center text-white/55 hover:text-white hover:bg-white/10 transition-all border border-white/5 hover:border-brand-500/20 active:scale-90"
            >
              <i className="bi bi-twitter-x text-lg"></i>
            </button>
            <button
              type="button"
              onClick={() => {
                const u = typeof window !== 'undefined' ? window.location.href : '';
                void navigator.clipboard?.writeText(u);
              }}
              aria-label="Sao chép liên kết"
              className="w-12 h-12 rounded-2xl bg-white/5 flex items-center justify-center text-white/55 hover:text-white hover:bg-white/10 transition-all border border-white/5 hover:border-brand-500/20 active:scale-90"
            >
              <i className="bi bi-link-45deg text-2xl"></i>
            </button>
          </div>
        </div>
        <Link
          href="/learn/"
          className="group flex items-center gap-3 bg-brand-500/10 text-brand-400 border border-brand-500/20 px-8 py-4 rounded-2xl text-[10px] font-black uppercase tracking-[0.2em] hover:bg-brand-500/20 transition-all active:scale-95"
        >
          <i className="bi bi-arrow-left transition-transform group-hover:-translate-x-1"></i> QUAY LẠI CẨM NANG
        </Link>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Quiz card — port Alpine x-data="{selected, submitted, correct}"    */
/* ------------------------------------------------------------------ */

function QuizCard({ quiz, index }: { quiz: Quiz; index: number }) {
  const [selected, setSelected] = useState<string | null>(null);
  const [submitted, setSubmitted] = useState(false);
  const [checking, setChecking] = useState(false);
  const [answer, setAnswer] = useState<{ correct: boolean; correct_answer?: string; correct_answers?: string[]; explanation?: string } | null>(null);
  const correct = answer?.correct ?? false;

  const resetQuiz = () => {
    setSubmitted(false);
    setSelected(null);
    setAnswer(null);
  };

  const optionClass = (oid: string, isCorrect: boolean): string => {
    if (submitted) {
      if (isCorrect) return 'border-safe-500/50 bg-safe-500/15 text-safe-300';
      if (selected === oid) return 'border-danger-500/50 bg-danger-500/15 text-danger-300';
      return 'border-white/5 text-white/35 opacity-40';
    }
    return selected === oid
      ? 'border-brand-400/60 bg-brand-400/10 text-white translate-x-1'
      : 'border-white/5 text-white/70 hover:border-white/20 hover:bg-white/5 hover:text-white';
  };

  return (
    <div
      className="liquid-card group flex flex-col h-full border border-white/5 hover:border-brand2-500/20 transition-all duration-500 shadow-xl"
    >
      <div className="p-6 pb-0 flex items-start gap-4">
        <div className="relative">
          <div className="absolute inset-0 bg-brand2-500 blur-xl opacity-20 group-hover:opacity-40 transition-opacity"></div>
          <div className="relative w-10 h-10 flex-shrink-0 rounded-xl bg-slate-900 border border-brand2-500/30 text-brand2-400 flex items-center justify-center font-black text-sm">
            {index + 1}
          </div>
        </div>
        <h3 className="text-base font-black text-white leading-tight group-hover:text-brand-400 transition-colors pt-1">
          {quiz.question}
        </h3>
      </div>

      <div className="p-6 flex-1 space-y-3">
        {(quiz.options || []).map((opt, optIdx) => {
          const isCorrect = opt.id === (answer?.correct_answer ?? quiz.correct_answer);
          const letter = opt.id && opt.id.length <= 2 ? opt.id : String.fromCharCode(65 + optIdx);
          return (
            <button
              key={opt.id}
              type="button"
              onClick={() => {
                if (!submitted) setSelected(opt.id);
              }}
              disabled={submitted}
              className={`w-full text-left px-5 py-4 rounded-2xl border text-sm font-bold transition-all duration-300 flex items-center justify-between group/opt ${optionClass(opt.id, isCorrect)}`}
            >
              <div className="flex items-center gap-4 min-w-0">
                <span
                  className={`w-7 h-7 shrink-0 rounded-lg bg-white/5 flex items-center justify-center text-xs font-black text-white/55 group-hover/opt:bg-brand-500/20 group-hover/opt:text-brand-400 ${
                    selected === opt.id ? 'bg-brand-500/25 text-brand-300' : ''
                  }`}
                >
                  {letter}
                </span>
                <span className="text-white/90 font-medium break-words leading-relaxed">{opt.text}</span>
              </div>
              <div className="flex items-center shrink-0 ml-3">
                {submitted && isCorrect && <i className="bi bi-check2-circle text-xl text-safe-400"></i>}
                {submitted && selected === opt.id && !isCorrect && <i className="bi bi-x-circle text-xl text-danger-400"></i>}
              </div>
            </button>
          );
        })}
      </div>

      <div className="p-6 pt-0 space-y-4">
        {!submitted ? (
          <button
            type="button"
            onClick={async () => {
              if (selected && !submitted && !checking) {
                setChecking(true);
                try {
                  const res = await api.post<{ correct: boolean; correct_answer?: string; correct_answers?: string[]; explanation?: string }>(
                    `/learn/quizzes/${quiz.id}/check/`,
                    { selected },
                  );
                  setAnswer(res);
                } catch {
                  setAnswer({ correct: false });
                } finally {
                  setSubmitted(true);
                  setChecking(false);
                }
              }
            }}
            disabled={!selected || checking}
            className={`w-full py-4 rounded-2xl text-[11px] font-black uppercase tracking-[0.2em] transition-all shadow-xl flex items-center justify-center gap-2 ${
              !selected || checking
                ? 'bg-white/5 text-white/20 cursor-not-allowed border border-white/5'
                : 'bg-gradient-to-r from-brand-600 to-brand-700 text-white hover:scale-[1.02] active:scale-95 shadow-brand-500/20'
            }`}
          >
            {checking ? (
              <>
                <i className="bi bi-arrow-repeat animate-spin text-sm"></i> Đang đối chiếu...
              </>
            ) : (
              <>
                Kiểm tra đáp án <i className="bi bi-check-circle ml-1"></i>
              </>
            )}
          </button>
        ) : (
          <div className="space-y-3">
            {correct ? (
              <div className="flex items-center gap-3">
                <div className="flex-1 py-3 px-4 rounded-2xl bg-safe-500/10 border border-safe-500/30 text-safe-400 text-xs font-black flex items-center justify-center gap-2">
                  <i className="bi bi-patch-check-fill text-base"></i> Chính xác tuyệt đối!
                </div>
                <button
                  type="button"
                  onClick={resetQuiz}
                  title="Làm lại câu hỏi này"
                  className="px-4 py-3 rounded-2xl bg-white/5 hover:bg-white/15 text-white/70 hover:text-white border border-white/10 text-xs font-bold transition-all flex items-center gap-1.5 active:scale-95"
                >
                  <i className="bi bi-arrow-counterclockwise"></i> Làm lại
                </button>
              </div>
            ) : (
              <div className="space-y-3">
                <div className="p-3.5 rounded-2xl bg-danger-500/10 border border-danger-500/30 text-danger-300 text-xs font-bold flex items-center justify-between">
                  <span className="flex items-center gap-2">
                    <i className="bi bi-exclamation-octagon-fill text-base text-danger-400"></i> Chưa chính xác - Cần xem lại!
                  </span>
                </div>
                <button
                  type="button"
                  onClick={resetQuiz}
                  className="w-full py-3.5 rounded-2xl text-[11px] font-black uppercase tracking-[0.2em] bg-white/10 hover:bg-white/20 text-white border border-white/15 transition-all flex items-center justify-center gap-2 shadow-lg active:scale-98"
                >
                  <i className="bi bi-arrow-counterclockwise text-sm"></i> Thử chọn lại đáp án
                </button>
              </div>
            )}
          </div>
        )}

        {(quiz.explanation || answer?.explanation) && submitted && (
          <div className="p-5 rounded-3xl bg-warn-400/[0.05] border border-warn-400/20">
            <span className="text-[9px] font-black text-warn-400 uppercase tracking-widest flex items-center gap-2 mb-2">
              <i className="bi bi-lightbulb-fill"></i> GIẢI THÍCH CHUYÊN GIA
            </span>
            <p className="text-[13px] text-white/90 font-medium leading-relaxed italic">{quiz.explanation || answer?.explanation}</p>
          </div>
        )}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Scenario player — port Alpine x-data="scenarioPlayer"              */
/* ------------------------------------------------------------------ */

function ScenarioPlayer({ scenario, steps: rawSteps }: { scenario: Scenario; steps: Array<ScenarioStep | string> }) {
  const [open, setOpen] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const chatRef = useRef<HTMLDivElement | null>(null);

  const steps: ScenarioStep[] = rawSteps.map((s) => {
    if (typeof s === 'string') return { text: s, actor: '', analysis: '' };
    return {
      text: s.text || '',
      actor: s.actor || s.speaker || '',
      analysis: s.analysis || s.note || '',
    };
  });
  const maxSteps = steps.length;

  useEffect(() => {
    if (open && chatRef.current) {
      chatRef.current.scrollTo({ top: chatRef.current.scrollHeight, behavior: 'smooth' });
    }
  }, [open, currentStep]);

  const play = () => {
    setOpen(true);
    setCurrentStep(0);
  };
  const next = () => {
    if (currentStep < maxSteps - 1) setCurrentStep((s) => s + 1);
  };
  const prev = () => {
    if (currentStep > 0) setCurrentStep((s) => s - 1);
  };

  const actorAlign = (actor: string): string => {
    if (actor === 'scammer' || actor === 'Kẻ lừa đảo') return 'items-start';
    if (actor === 'victim' || actor === 'Nạn nhân') return 'items-end';
    return 'items-center';
  };
  const actorBadge = (actor: string): string => {
    if (actor === 'scammer' || actor === 'Kẻ lừa đảo') return 'text-danger-400 bg-danger-400/5 border-danger-500/10';
    if (actor === 'victim' || actor === 'Nạn nhân') return 'text-brand-400 bg-brand-400/5 border-brand-500/10';
    return 'text-brand2-400 bg-brand2-400/5 border-brand2-500/10';
  };
  const actorBubble = (actor: string): string => {
    if (actor === 'scammer' || actor === 'Kẻ lừa đảo') return 'bg-[var(--sc-ink-deep)] border-danger-500/20 text-danger-100/90 rounded-tl-lg';
    if (actor === 'victim' || actor === 'Nạn nhân') return 'bg-[var(--sc-slate-900)] border-brand-500/20 text-brand-50/90 rounded-tr-lg';
    return 'bg-white/5 border-white/5 text-white/60 text-center italic py-2 px-8 rounded-full';
  };

  return (
    <div className="space-y-10 pt-16 border-t border-white/5">
      <div className="flex items-center gap-5">
        <div className="relative">
          <div className="absolute inset-0 bg-brand2-500 blur-xl opacity-30"></div>
          <div className="relative w-14 h-14 rounded-2xl bg-brand2-500/10 text-brand2-400 flex items-center justify-center border border-brand2-500/20 shadow-xl group">
            <i className="bi bi-mask text-2xl group-hover:scale-110 transition-transform"></i>
          </div>
        </div>
        <div>
          <h2 className="text-2xl font-black text-white tracking-tight">Mô phỏng tình huống</h2>
          <p className="text-[10px] font-black text-white/45 uppercase tracking-[0.3em] mt-1">{scenario.title}</p>
        </div>
      </div>

      <div className="liquid-card p-0 flex flex-col border border-white/5 overflow-hidden shadow-2xl">
        {/* Start button */}
        {!open && (
          <div className="p-12 text-center space-y-8 bg-gradient-to-br from-brand2-500/5 to-brand-500/5">
            <p className="text-white/60 text-sm font-medium leading-relaxed italic max-w-2xl mx-auto">
              &quot;
              {scenario.description ||
                'Trải nghiệm kịch bản mô phỏng để nhận biết các dấu hiệu lừa đảo trong thực tế.'}
              &quot;
            </p>
            <button
              onClick={play}
              className="relative group overflow-hidden rounded-2xl px-12 py-5 bg-brand2-600 text-white font-black text-xs uppercase tracking-[0.3em] transition-all hover:scale-[1.05] hover:shadow-[0_0_40px_rgba(168,85,247,0.4)]"
            >
              <div className="absolute inset-0 bg-gradient-to-r from-brand2-500 to-brand2-600 opacity-0 group-hover:opacity-100 transition-opacity"></div>
              <span className="relative flex items-center justify-center gap-3">
                <i className="bi bi-play-circle-fill text-xl"></i> BẮT ĐẦU DIỄN TẬP
              </span>
            </button>
          </div>
        )}

        {/* Immersive Chat Player */}
        {open && (
          <div className="flex flex-col h-[600px] bg-[var(--sc-ink-deep)]">
            {/* Player Header */}
            <div className="p-5 bg-white/[0.03] border-b border-white/10 flex items-center justify-between backdrop-blur-3xl sticky top-0 z-20">
              <div className="flex items-center gap-4">
                <div className="w-10 h-10 rounded-2xl bg-brand2-500/10 text-brand2-400 flex items-center justify-center border border-brand2-500/20">
                  <i className="bi bi-shield-shaded"></i>
                </div>
                <div>
                  <h4 className="text-[11px] font-black text-white uppercase tracking-widest">{scenario.title}</h4>
                  <div className="flex items-center gap-1.5 mt-2 h-2 w-44">
                    {steps.map((_, i) => (
                      <button
                        key={i}
                        type="button"
                        onClick={() => setCurrentStep(i)}
                        title={`Chuyển đến bước ${i + 1}`}
                        className={`h-full rounded-full transition-all duration-300 cursor-pointer ${
                          i === currentStep
                            ? 'bg-brand2-400 flex-1 ring-2 ring-brand2-400/40'
                            : i < currentStep
                            ? 'bg-brand2-600/70 w-3 hover:bg-brand2-500'
                            : 'bg-white/10 w-2 hover:bg-white/25'
                        }`}
                      />
                    ))}
                  </div>
                </div>
              </div>
              <button
                onClick={() => setOpen(false)}
                className="w-10 h-10 rounded-2xl hover:bg-white/5 text-white/35 hover:text-white transition-all flex items-center justify-center"
              >
                <i className="bi bi-x-lg"></i>
              </button>
            </div>

            {/* Chat Area */}
            <div
              ref={chatRef}
              className="flex-1 overflow-y-auto p-8 space-y-10 scrollbar-hide bg-[radial-gradient(circle_at_bottom,rgba(168,85,247,0.08),transparent_70%)]"
            >
              {steps.map((s, i) =>
                i <= currentStep ? (
                  <div key={i} className="flex flex-col gap-3">
                    <div className={`flex flex-col ${actorAlign(s.actor || '')}`}>
                      <div
                        className={`flex items-center gap-2 mb-2 px-3 py-1 rounded-full border text-[10px] font-black uppercase tracking-widest ${actorBadge(
                          s.actor || '',
                        )}`}
                      >
                        <span>{s.actor}</span>
                      </div>
                      <div
                        className={`max-w-[80%] rounded-[2rem] px-6 py-4 text-sm font-medium leading-relaxed shadow-2xl border ${actorBubble(
                          s.actor || '',
                        )}`}
                      >
                        <span>{s.text}</span>
                      </div>
                      {s.analysis && (
                        <div className="mt-4 p-5 rounded-3xl bg-warn-400/[0.05] border border-warn-400/20 max-w-[85%] relative overflow-hidden">
                          <p className="text-[10px] font-black text-warn-400 uppercase tracking-[0.2em] mb-1.5 flex items-center gap-2">
                            <i className="bi bi-lightbulb-fill"></i> Phân tích
                          </p>
                          <p className="text-[13px] text-amber-100 font-medium leading-relaxed italic">{s.analysis}</p>
                        </div>
                      )}
                    </div>
                  </div>
                ) : null,
              )}
            </div>

            {/* Footer Controls */}
            <div className="p-6 bg-[var(--sc-ink-deep)] border-t border-white/10 flex items-center justify-between gap-4 relative z-20">
              <button
                type="button"
                onClick={prev}
                disabled={currentStep === 0 || maxSteps === 0}
                title="Bước trước"
                className={`w-14 h-14 rounded-2xl border border-white/5 flex items-center justify-center transition-all bg-white/[0.02] ${
                  currentStep === 0 || maxSteps === 0 ? 'text-white/5 cursor-not-allowed' : 'text-white/70 hover:bg-white/10 hover:text-white'
                }`}
              >
                <i className="bi bi-arrow-left text-xl"></i>
              </button>
              <div className="flex-1 text-center">
                <span className="text-[11px] font-black text-white/50 uppercase tracking-[0.3em]">
                  BƯỚC <span className="text-brand2-400 font-bold">{maxSteps > 0 ? currentStep + 1 : 0}</span> / <span>{maxSteps}</span>
                </span>
              </div>
              {currentStep >= maxSteps - 1 ? (
                <button
                  type="button"
                  onClick={() => setCurrentStep(0)}
                  className="flex-1 sm:flex-none sm:w-64 h-14 rounded-2xl text-[11px] font-black uppercase tracking-[0.2em] transition-all relative overflow-hidden bg-gradient-to-r from-brand2-600 to-brand-600 text-white shadow-2xl hover:scale-[1.02] active:scale-95 flex items-center justify-center gap-2"
                >
                  <i className="bi bi-arrow-counterclockwise text-lg"></i>
                  <span>Diễn tập lại từ đầu</span>
                </button>
              ) : (
                <button
                  type="button"
                  onClick={next}
                  className="flex-1 sm:flex-none sm:w-64 h-14 rounded-2xl text-[11px] font-black uppercase tracking-[0.2em] transition-all relative overflow-hidden bg-brand2-600 hover:bg-brand2-500 text-white shadow-2xl hover:scale-[1.02] active:scale-95 flex items-center justify-center gap-2"
                >
                  <span>Tiếp tục</span>
                  <i className="bi bi-arrow-right-short text-xl"></i>
                </button>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
