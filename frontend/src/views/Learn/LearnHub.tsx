'use client';
import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { learnApi, asList, mediaUrl } from '../../lib/api';
import type { Article } from '../../lib/api';
import { fmtDate, fmtDateLong, isoDate } from '../../lib/date';
import { Spinner } from '../../components/ui';

/* Port từ PKV/templates/LearnHub/learn_hub.html.
 * API đã đấu: GET /articles/, /learn/lessons/, /learn/scenarios/, /learn/quizzes/.
 * Đáp án quiz chấm phía server qua POST /learn/quizzes/<id>/check/ (không lộ đáp án). */

type Tab = 'lessons' | 'news' | 'quiz' | 'scenarios';
type SortBy = 'newest' | 'oldest' | 'alpha';
type FilterCat = 'all' | 'guide' | 'news' | 'alert' | 'story' | 'inclusive' | 'empathy';

interface Lesson {
  slug: string;
  title: string;
  category?: string;
  category_display?: string;
  cover_image?: string | null;
  created_at?: string;
  summary?: string;
  content?: string;
  reactions_count?: number;
  quizzes_count?: number;
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
  lesson?: { slug: string; title: string } | null;
  article?: { slug: string; title: string } | null;
}

interface ScenarioStep {
  text?: string;
  actor?: string;
  speaker?: string;
  analysis?: string;
  note?: string;
}

interface Scenario {
  id: number;
  title: string;
  description?: string;
  created_at?: string;
  steps: Array<ScenarioStep | string>;
}

/* Quiz nay lấy từ API /learn/quizzes/. */

/* Django |striptags + truncatechars */
function stripTags(html: string): string {
  return String(html || '').replace(/<[^>]*>/g, '');
}

function truncatechars(text: string, n: number): string {
  const s = String(text || '');
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}

function matchSearch(title: string, content: string, q: string): boolean {
  if (!q.trim()) return true;
  const needle = q.toLowerCase();
  return (title || '').toLowerCase().includes(needle) || (content || '').toLowerCase().includes(needle);
}

function isTab(v: string): v is Tab {
  return v === 'lessons' || v === 'news' || v === 'quiz' || v === 'scenarios';
}

function isFilterCat(v: string): v is FilterCat {
  return v === 'all' || v === 'guide' || v === 'news' || v === 'alert' || v === 'story' || v === 'inclusive' || v === 'empathy';
}

/* syncTabState() — điều chỉnh bộ lọc khi đổi tab */
function syncCat(_tab: Tab, cat: FilterCat): FilterCat {
  return cat;
}

function sortItems<T>(items: T[], sortBy: SortBy, title: (x: T) => string, date: (x: T) => string | undefined): T[] {
  const list = [...items];
  if (sortBy === 'alpha') list.sort((a, b) => title(a).localeCompare(title(b), 'vi'));
  else if (sortBy === 'oldest') list.sort((a, b) => (date(a) || '').localeCompare(date(b) || ''));
  else list.sort((a, b) => (date(b) || '').localeCompare(date(a) || ''));
  return list;
}

function normalizeStep(s: ScenarioStep | string): ScenarioStep {
  if (typeof s === 'string') return { text: s, actor: '', analysis: '' };
  return {
    text: s.text || '',
    actor: s.actor || s.speaker || '',
    analysis: s.analysis || s.note || '',
  };
}

const PILL_BASE = 'px-4 py-2 rounded-full text-[13px] font-semibold tracking-wide transition-all border';
const PILL_IDLE = 'bg-white/[0.03] text-white/75 border-white/5 hover:text-white hover:border-white/15';

function FilterPill({ active, activeClass, onClick, icon, label }: { active: boolean; activeClass: string; onClick: () => void; icon?: string; label: string }) {
  return (
    <button type="button" onClick={onClick} className={`${PILL_BASE} ${active ? activeClass : PILL_IDLE}`}>
      {icon && <i className={`bi ${icon} mr-1`}></i>} {label}
    </button>
  );
}

function SortItem({ active, onClick, icon, label }: { active: boolean; onClick: () => void; icon: string; label: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`w-full px-4 py-3 text-left text-[13px] font-medium hover:bg-white/5 transition-colors flex items-center gap-3 ${active ? 'text-brand-400' : 'text-white/85'}`}
    >
      <i className={`bi ${icon} text-sm`}></i> {label}
    </button>
  );
}

function LessonCard({ lesson, onOpen }: { lesson: Lesson; onOpen: () => void }) {
  return (
    <div
      className="learn-card liquid-card p-0 group overflow-hidden border border-white/5 hover:border-brand-500/30 transition-all flex flex-col h-full cursor-pointer focus-visible:outline-none"
      data-kind="lesson"
      data-cat={lesson.category}
      data-title={lesson.title}
      data-date={isoDate(lesson.created_at)}
      role="button"
      tabIndex={0}
      onClick={onOpen}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onOpen();
        }
      }}
    >
      <div className="aspect-video bg-white/5 overflow-hidden relative">
        {lesson.cover_image ? (
          <img
            src={mediaUrl(lesson.cover_image)}
            className="w-full h-full object-cover transition-transform duration-500 group-hover:scale-105"
            loading="lazy"
            alt={lesson.title}
          />
        ) : (
          <div className="w-full h-full flex items-center justify-center bg-gradient-to-br from-brand-500/5 to-brand2-500/5">
            <i className="bi bi-shield-check text-5xl text-white/5"></i>
          </div>
        )}
        <div className="absolute top-3 left-3">
          <span className="px-2 py-1 rounded-lg bg-brand-500/20 text-brand-300 text-[10px] font-bold tracking-wide backdrop-blur-sm border border-brand-500/20">
            <i className="bi bi-stars mr-1"></i>AI
          </span>
        </div>
      </div>
      <div className="p-6 space-y-4 flex flex-col flex-1">
        <div className="flex items-center justify-between">
          <span className="px-3 py-1 rounded-full bg-brand-500/10 text-brand-400 text-[11px] font-bold tracking-wide">
            {lesson.category_display || lesson.category}
          </span>
          <span className="text-[12px] font-medium text-white/65" title={fmtDateLong(lesson.created_at)}>
            {fmtDate(lesson.created_at)}
          </span>
        </div>
        <h3 className="text-[17px] font-bold leading-snug text-white line-clamp-2 tracking-tight group-hover:text-brand-400 transition-colors">
          {lesson.title}
        </h3>
        <p className="text-white/75 text-[14px] font-medium leading-relaxed line-clamp-3 min-h-[63px]">
          {lesson.summary || stripTags(lesson.content || '')}
        </p>
        <div className="pt-4 border-t border-white/5 flex items-center justify-between text-[11px] font-bold mt-auto">
          <div className="flex items-center gap-3 text-white/65">
            <span>
              <i className="bi bi-hand-thumbs-up-fill mr-1 text-brand-400/80"></i>
              {lesson.reactions_count || 0}
            </span>
            {(lesson.quizzes_count || 0) > 0 && (
              <span className="text-brand2-400/70">
                <i className="bi bi-patch-question mr-1"></i>
                {lesson.quizzes_count}
              </span>
            )}
          </div>
          <span className="text-[12px] font-semibold text-brand-300 inline-flex items-center gap-1">
            Xem thêm <i className="bi bi-arrow-right"></i>
          </span>
        </div>
      </div>
    </div>
  );
}

function ArticleListItem({ article, onOpen }: { article: Article; onOpen: () => void }) {
  return (
    <div
      className="learn-card liquid-card p-0 group overflow-hidden border border-white/5 hover:border-brand-500/30 transition-all flex items-stretch gap-3 sm:gap-5 cursor-pointer focus-visible:outline-none"
      data-kind="article"
      data-cat={article.category}
      data-title={article.title}
      data-date={isoDate(article.created_at)}
      role="button"
      tabIndex={0}
      onClick={onOpen}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onOpen();
        }
      }}
    >
      <div className="relative shrink-0 w-28 sm:w-48 self-stretch min-h-[92px] sm:min-h-[112px] bg-white/5 overflow-hidden">
        {article.cover_image ? (
          <img
            src={mediaUrl(article.cover_image)}
            className="absolute inset-0 w-full h-full object-cover transition-transform duration-500 group-hover:scale-105"
            loading="lazy"
            alt={article.title}
          />
        ) : (
          <div className="absolute inset-0 flex items-center justify-center bg-gradient-to-br from-warn-500/5 to-danger-500/5">
            <i className="bi bi-newspaper text-3xl text-white/10"></i>
          </div>
        )}
      </div>
      <div className="flex-1 min-w-0 py-4 pr-4 sm:py-5 sm:pr-6 flex flex-col justify-center gap-1.5">
        <div className="flex items-center gap-3 flex-wrap">
          <span className="px-2.5 py-0.5 rounded-full bg-warn-500/10 text-warn-400 text-[10px] font-bold tracking-wide">
            {article.category_display || article.category}
          </span>
          <span className="text-[11px] font-medium text-white/55" title={fmtDateLong(article.created_at)}>
            {fmtDate(article.created_at)}
          </span>
        </div>
        <h3 className="text-[15px] sm:text-[16px] font-bold leading-snug text-white line-clamp-2 tracking-tight group-hover:text-brand-400 transition-colors">
          {article.title}
        </h3>
        <p className="hidden sm:block text-white/70 text-[13px] font-medium leading-relaxed line-clamp-2">
          {stripTags(article.summary || '')}
        </p>
        <div className="flex items-center gap-4 text-[11px] font-bold text-white/60">
          <span>
            <i className="bi bi-hand-thumbs-up-fill mr-1 text-brand-400/80"></i>
            {article.reactions_count || 0}
          </span>
          <span>
            <i className="bi bi-chat-left-text mr-1 text-warn-400/80"></i>
            {article.comments_count || 0}
          </span>
          <span className="ml-auto text-[12px] font-semibold text-brand-300 inline-flex items-center gap-1">
            Xem thêm <i className="bi bi-arrow-right"></i>
          </span>
        </div>
      </div>
    </div>
  );
}

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
      return 'border-white/5 text-white/65 opacity-40';
    }
    return selected === oid
      ? 'border-brand-400/60 bg-brand-400/10 text-white translate-x-1'
      : 'border-white/5 text-white/85 hover:border-white/20 hover:bg-white/5 hover:text-white';
  };

  return (
    <div
      className="liquid-card group flex flex-col h-full border border-white/5 hover:border-brand-500/20 transition-all duration-500 shadow-xl"
    >
      <div className="p-6 pb-0 flex items-start gap-4">
        <div className="relative group-hover:scale-110 transition-transform">
          <div className="absolute inset-0 bg-brand2-500 blur-xl opacity-20 group-hover:opacity-40 transition-opacity"></div>
          <div className="relative w-12 h-12 flex-shrink-0 rounded-[1.25rem] bg-card border border-brand2-500/30 text-brand2-400 flex items-center justify-center font-bold text-lg">
            {index + 1}
          </div>
        </div>
        <div className="flex-1 min-w-0">
          <h3 className="text-lg font-bold text-white leading-tight mb-2 group-hover:text-brand-400 transition-colors">{quiz.question}</h3>
          <div className="flex flex-wrap gap-2">
            {quiz.lesson ? (
              <Link
                href={`/learn/lesson/${quiz.lesson.slug}/`}
                className="flex items-center gap-1.5 px-2 py-1 rounded-lg bg-brand-500/5 border border-brand-500/10 text-[11px] text-brand-400/80 font-bold tracking-wide hover:bg-brand-500/10 hover:text-brand-400 transition-all"
              >
                <i className="bi bi-book"></i> {truncatechars(quiz.lesson.title, 30)}
              </Link>
            ) : quiz.article ? (
              <Link
                href={`/learn/${quiz.article.slug}/`}
                className="flex items-center gap-1.5 px-2 py-1 rounded-lg bg-warn-500/5 border border-warn-500/10 text-[11px] text-warn-400/80 font-bold tracking-wide hover:bg-warn-500/10 hover:text-warn-400 transition-all"
              >
                <i className="bi bi-newspaper"></i> {truncatechars(quiz.article.title, 30)}
              </Link>
            ) : null}
          </div>
        </div>
      </div>

      <div className="p-6 flex-1 space-y-3">
        {quiz.options.map((opt, optIdx) => {
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
              className={`w-full text-left px-5 py-4 rounded-2xl border text-sm font-bold transition-all duration-300 flex items-center justify-between group/opt ${optionClass(
                opt.id,
                isCorrect,
              )}`}
            >
              <div className="flex items-center gap-4 min-w-0">
                <span
                  className={`w-7 h-7 shrink-0 rounded-lg bg-white/5 flex items-center justify-center text-xs font-bold text-white/75 group-hover/opt:bg-brand-500/20 group-hover/opt:text-brand-400 ${
                    selected === opt.id ? 'bg-brand-500/25 text-brand-300' : ''
                  }`}
                >
                  {letter}
                </span>
                <span className="text-white/95 font-medium break-words leading-relaxed">{opt.text}</span>
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
                  const res = await learnApi.checkQuiz(quiz.id, selected);
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
            className={`w-full py-4 rounded-2xl text-[13px] font-bold tracking-wide transition-all shadow-xl flex items-center justify-center gap-2 ${
              !selected || checking
                ? 'bg-white/5 text-white/45 cursor-not-allowed border border-white/5'
                : 'bg-gradient-to-r from-brand-500 to-brand-600 text-white hover:scale-[1.02] active:scale-95 shadow-brand-500/20'
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
                <div className="flex-1 py-3 px-4 rounded-2xl bg-safe-500/10 border border-safe-500/30 text-safe-400 text-xs font-bold flex items-center justify-center gap-2">
                  <i className="bi bi-patch-check-fill text-base"></i> Chính xác tuyệt đối!
                </div>
                <button
                  type="button"
                  onClick={resetQuiz}
                  title="Làm lại câu hỏi này"
                  className="px-4 py-3 rounded-2xl bg-white/5 hover:bg-white/15 text-white/85 hover:text-white border border-white/10 text-xs font-bold transition-all flex items-center gap-1.5 active:scale-95"
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
                  className="w-full py-3.5 rounded-2xl text-[13px] font-bold tracking-wide bg-white/10 hover:bg-white/20 text-white border border-white/15 transition-all flex items-center justify-center gap-2 shadow-lg active:scale-98"
                >
                  <i className="bi bi-arrow-counterclockwise text-sm"></i> Thử chọn lại đáp án
                </button>
              </div>
            )}
          </div>
        )}

        {(quiz.explanation || answer?.explanation) && submitted && (
          <div className="p-5 rounded-3xl bg-white/[0.03] border border-white/10 relative overflow-hidden group/exp">
            <div className="absolute top-0 right-0 w-24 h-24 bg-warn-400/5 blur-3xl rounded-full -mr-10 -mt-10"></div>
            <span className="text-[11px] font-bold text-warn-400 tracking-wide flex items-center gap-2 mb-2">
              <i className="bi bi-lightbulb-fill"></i> Tại sao như vậy?
            </span>
            <p className="text-[14px] text-white/95 font-medium leading-relaxed italic">{quiz.explanation || answer?.explanation}</p>
          </div>
        )}
      </div>
    </div>
  );
}

function ScenarioPlayerCard({ scenario }: { scenario: Scenario; index: number }) {
  const [open, setOpen] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const chatRef = useRef<HTMLDivElement | null>(null);

  const steps = (scenario.steps || []).map(normalizeStep);
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
  const actorIcon = (actor: string): string => {
    if (actor === 'scammer' || actor === 'Kẻ lừa đảo') return 'bi-exclamation-octagon-fill';
    if (actor === 'victim' || actor === 'Nạn nhân') return 'bi-person-badge-fill';
    return 'bi-info-circle-fill';
  };
  const actorBubble = (actor: string): string => {
    if (actor === 'scammer' || actor === 'Kẻ lừa đảo')
      return 'bg-gradient-to-br from-[var(--sc-ink-deep)] to-[var(--sc-ink-deep)] border-danger-500/20 text-danger-100/90 rounded-tl-lg';
    if (actor === 'victim' || actor === 'Nạn nhân')
      return 'bg-gradient-to-br from-[var(--sc-slate-900)] to-[var(--sc-panel)] border-brand-500/20 text-brand-50/90 rounded-tr-lg';
    return 'bg-white/5 border-white/5 text-white/75 text-center italic py-2 px-8 rounded-full';
  };

  return (
    <div
      className="liquid-card p-0 flex flex-col h-full border border-white/5 hover:border-brand2-500/20 transition-all duration-500 overflow-hidden"
    >
      {!open && (
        <div className="relative aspect-[16/6] bg-card overflow-hidden group/head">
          <div className="absolute inset-0 bg-gradient-to-br from-brand2-600/30 via-transparent to-brand-500/20 z-0"></div>
          <div className="absolute inset-0 p-8 flex flex-col justify-center z-10">
            <div className="flex items-center gap-6">
              <div className="relative">
                <div className="absolute inset-0 bg-brand2-500 blur-2xl opacity-40 group-hover/head:opacity-70 transition-opacity"></div>
                <div className="relative w-16 h-16 rounded-[1.5rem] bg-background/80 border border-white/10 flex items-center justify-center text-white shadow-2xl group-hover/head:scale-110 transition-transform duration-500">
                  <i className="bi bi-mask text-3xl text-brand2-400"></i>
                </div>
              </div>
              <div className="flex-1 min-w-0">
                <h3 className="text-2xl font-bold text-white leading-tight mb-2 group-hover/head:text-brand2-400 transition-colors">{scenario.title}</h3>
                <div className="flex items-center gap-4">
                  <span className="flex items-center gap-2 text-[12px] font-bold text-white/65 tracking-wide">
                    <i className="bi bi-layers-half text-brand2-500"></i> <span>{maxSteps}</span> bước mô phỏng
                  </span>
                  <span className="w-1.5 h-1.5 rounded-full bg-white/10"></span>
                  <span className="text-[12px] font-bold text-white/65 tracking-wide">{fmtDateLong(scenario.created_at)}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {!open && (
        <div className="p-8 space-y-6 flex-1 flex flex-col relative z-10 bg-background/40">
          <p className="text-white/75 text-[14px] font-medium leading-relaxed prose-sm italic line-clamp-3">
            &quot;{scenario.description}&quot;
          </p>
          <div className="mt-auto pt-6 flex items-center justify-between">
            <button
              type="button"
              onClick={play}
              className="relative w-full group/btn overflow-hidden rounded-2xl py-4 bg-brand2-500 text-white font-bold text-[13px] tracking-wide transition-all hover:scale-[1.02] hover:shadow-[0_0_30px_rgba(168,85,247,0.3)]"
            >
              <div className="absolute inset-0 bg-gradient-to-r from-brand2-600 to-brand2-600 opacity-0 group-hover/btn:opacity-100 transition-opacity"></div>
              <span className="relative flex items-center justify-center gap-3">
                <i className="bi bi-play-circle-fill text-lg"></i> Bắt đầu trải nghiệm
              </span>
            </button>
          </div>
        </div>
      )}

      {open && (
        <div className="flex flex-col h-[600px] bg-[var(--sc-ink-deep)] relative border-t border-white/5">
          <div className="p-5 bg-white/[0.03] border-b border-white/10 flex items-center justify-between backdrop-blur-3xl sticky top-0 z-20">
            <div className="flex items-center gap-4">
              <div className="w-10 h-10 rounded-2xl bg-brand2-500/10 text-brand2-400 flex items-center justify-center border border-brand2-500/20 shadow-lg shadow-brand2-500/10">
                <i className="bi bi-shield-shaded"></i>
              </div>
              <div>
                <h4 className="text-[13px] font-bold text-white tracking-wide">{scenario.title}</h4>
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
              type="button"
              onClick={() => setOpen(false)}
              className="w-10 h-10 rounded-2xl hover:bg-danger-500/10 text-white/65 hover:text-danger-400 transition-all flex items-center justify-center"
            >
              <i className="bi bi-x-lg text-lg"></i>
            </button>
          </div>

          <div
            ref={chatRef}
            className="flex-1 overflow-y-auto p-8 space-y-10 scrollbar-hide bg-[radial-gradient(circle_at_bottom,rgba(168,85,247,0.08),transparent_70%)]"
          >
            {steps.map((s, i) =>
              i <= currentStep ? (
                <div key={i} className="flex flex-col gap-3">
                  <div className={`flex flex-col ${actorAlign(s.actor || '')}`}>
                    <div
                      className={`flex items-center gap-2 mb-2 px-3 py-1 rounded-full border text-[12px] font-bold tracking-wide ${actorBadge(
                        s.actor || '',
                      )}`}
                    >
                      <i className={`bi ${actorIcon(s.actor || '')}`}></i>
                      <span>{s.actor}</span>
                    </div>

                    <div
                      className={`max-w-[80%] rounded-[2rem] px-6 py-4 text-sm font-medium leading-relaxed shadow-2xl transition-all border relative group/bubble ${actorBubble(
                        s.actor || '',
                      )}`}
                    >
                      <span>{s.text}</span>
                      <div className="absolute inset-0 bg-white/5 opacity-0 group-hover/bubble:opacity-100 transition-opacity rounded-[2rem]"></div>
                    </div>

                    {s.analysis && (
                      <div className="mt-4 p-5 rounded-3xl bg-warn-400/[0.05] border border-warn-400/20 max-w-[85%] relative overflow-hidden group/insight">
                        <div className="absolute top-0 right-0 w-16 h-16 bg-warn-400/5 blur-2xl rounded-full -mr-8 -mt-8"></div>
                        <div className="flex items-start gap-3">
                          <div className="w-8 h-8 rounded-xl bg-warn-400/10 flex items-center justify-center text-warn-500 shrink-0 border border-warn-500/20 shadow-lg shadow-warn-500/10">
                            <i className="bi bi-eyedropper text-sm"></i>
                          </div>
                          <div>
                            <p className="text-[12px] font-bold text-warn-400 tracking-wide mb-1.5">Phân tích kỹ thuật lừa đảo</p>
                            <p className="text-[14px] text-warn-100 font-medium leading-relaxed italic">{s.analysis}</p>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              ) : null,
            )}
          </div>

          <div className="p-6 bg-[var(--sc-ink-deep)] border-t border-white/10 flex items-center justify-between gap-4 relative z-20">
            <button
              type="button"
              onClick={prev}
              disabled={currentStep === 0 || maxSteps === 0}
              title="Bước trước"
              className={`w-14 h-14 rounded-2xl border border-white/5 flex items-center justify-center transition-all bg-white/[0.02] ${
                currentStep === 0 || maxSteps === 0 ? 'text-white/25 cursor-not-allowed' : 'text-white/85 hover:bg-white/10 hover:text-white hover:scale-105'
              }`}
            >
              <i className="bi bi-arrow-left text-xl"></i>
            </button>

            <div className="flex-1 text-center">
              <div className="inline-flex items-center justify-center px-4 py-1.5 rounded-full bg-white/5 border border-white/5">
                <span className="text-[13px] font-bold text-white/70 tracking-wide">
                  <span className="text-brand2-400 font-bold">{maxSteps > 0 ? currentStep + 1 : 0}</span> <span className="mx-1">/</span> <span>{maxSteps}</span> bước
                </span>
              </div>
            </div>

            {currentStep >= maxSteps - 1 ? (
              <button
                type="button"
                onClick={() => setCurrentStep(0)}
                className="flex-1 sm:flex-none sm:w-64 h-14 rounded-2xl text-[13px] font-bold tracking-wide transition-all relative overflow-hidden bg-gradient-to-r from-brand2-600 to-brand-600 text-white shadow-2xl hover:scale-[1.02] active:scale-95 flex items-center justify-center gap-2"
              >
                <i className="bi bi-arrow-counterclockwise text-lg"></i>
                <span>Diễn tập lại từ đầu</span>
              </button>
            ) : (
              <button
                type="button"
                onClick={next}
                className="flex-1 sm:flex-none sm:w-64 h-14 rounded-2xl text-[13px] font-bold tracking-wide transition-all relative overflow-hidden group/next bg-brand2-600 hover:bg-brand2-500 text-white shadow-2xl shadow-brand2-600/30 hover:scale-[1.03] active:scale-95 flex items-center justify-center gap-2"
              >
                <span className="relative z-10 flex items-center justify-center gap-2">
                  Tiếp tục diễn tập <i className="bi bi-arrow-right-short text-xl"></i>
                </span>
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function LearnHub() {
  const router = useRouter();
  const sp = useSearchParams();

  const [activeTab, setActiveTab] = useState<Tab>(() => {
    const t = (sp.get('tab') || 'lessons').toLowerCase();
    return isTab(t) ? t : 'lessons';
  });
  const [filterCat, setFilterCat] = useState<FilterCat>(() => {
    const t = (sp.get('tab') || 'lessons').toLowerCase();
    const tab: Tab = isTab(t) ? t : 'lessons';
    const c = (sp.get('category') || 'all').toLowerCase();
    return syncCat(tab, isFilterCat(c) ? c : 'all');
  });
  const [searchInput, setSearchInput] = useState<string>(() => sp.get('q') || '');
  const [searchQuery, setSearchQuery] = useState<string>(() => sp.get('q') || '');
  const [sortBy, setSortBy] = useState<SortBy>('newest');
  const [sortOpen, setSortOpen] = useState(false);
  const [articles, setArticles] = useState<Article[]>([]);
  const [lessons, setLessons] = useState<Lesson[]>([]);
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [quizzes, setQuizzes] = useState<Quiz[]>([]);
  const [loading, setLoading] = useState(true);

  const sortRef = useRef<HTMLDivElement>(null);

  /* x-model.debounce.300ms */
  useEffect(() => {
    const t = setTimeout(() => setSearchQuery(searchInput), 300);
    return () => clearTimeout(t);
  }, [searchInput]);

  useEffect(() => {
    let alive = true;
    Promise.allSettled([
      learnApi.articles(),
      learnApi.lessons(),
      learnApi.scenarios(),
      learnApi.quizzes(),
    ]).then(([a, l, s, q]) => {
      if (!alive) return;
      if (a.status === 'fulfilled') setArticles(asList(a.value));
      if (l.status === 'fulfilled') setLessons(asList(l.value) as unknown as Lesson[]);
      if (s.status === 'fulfilled')
        setScenarios(
          (asList(s.value) as unknown as Scenario[]).map((sc) => ({ ...sc, steps: sc.steps || [] })),
        );
      if (q.status === 'fulfilled')
        setQuizzes(
          (asList(q.value) as unknown as Array<Record<string, unknown>>).map((x) => ({
            id: Number(x.id),
            question: String(x.question || ''),
            options: ((x.options as Array<string | { id?: string; text?: string }>) || []).map((o) =>
              typeof o === 'string'
                ? { id: o, text: o }
                : { id: String(o.id ?? o.text ?? ''), text: String(o.text ?? o.id ?? '') },
            ),
            correct_answer: String(x.correct_answer || ''),
            explanation: x.explanation ? String(x.explanation) : undefined,
            lesson: (x.lesson as Quiz['lesson']) || null,
            article: (x.article as Quiz['article']) || null,
          })),
        );
      setLoading(false);
    });
    return () => {
      alive = false;
    };
  }, []);

  /* Đổi tab + syncTabState() như Alpine @click + $watch. */
  const switchTab = (t: Tab) => {
    setActiveTab(t);
    setFilterCat((c) => syncCat(t, c));
    if (t === 'news') setSortBy('newest');
  };

  /* @click.outside="sortOpen=false" */
  useEffect(() => {
    if (!sortOpen) return;
    const onDoc = (e: MouseEvent) => {
      if (sortRef.current && !sortRef.current.contains(e.target as Node)) setSortOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [sortOpen]);

  /* matchCatForTab(cat) */
  const matchCatForTab = (cat?: string): boolean => {
    if (filterCat === 'all') return true;
    if (activeTab === 'news' && filterCat === 'news') return cat === 'news' || cat === 'alert';
    return filterCat === cat;
  };

  const visibleLessons = sortItems(
    lessons.filter(
      (l) => matchSearch(l.title, l.summary || stripTags(l.content || ''), searchQuery) && matchCatForTab(l.category),
    ),
    sortBy,
    (l) => l.title,
    (l) => l.created_at,
  );

  const visibleArticles = sortItems(
    articles.filter((a) => matchSearch(a.title, a.summary || '', searchQuery) && matchCatForTab(a.category)),
    sortBy,
    (a) => a.title,
    (a) => a.created_at,
  );

  const visibleQuizzes = quizzes.filter((q) => matchSearch(q.question, q.explanation || '', searchQuery));

  const visibleScenarios = scenarios.filter((s) => matchSearch(s.title, s.description || '', searchQuery));

  /* Tổng số mục khớp của tab đang mở (đã tính cả bộ lọc + từ khoá). */
  const listCount =
    activeTab === 'news'
      ? visibleArticles.length
      : activeTab === 'lessons'
      ? visibleLessons.length
      : activeTab === 'quiz'
      ? visibleQuizzes.length
      : visibleScenarios.length;

  const hasContent = lessons.length > 0 || articles.length > 0;

  /* Số lượng hiển thị ở mỗi tab (cho người dùng biết còn bao nhiêu nội dung). */
  const tabCounts: Record<Tab, number> = {
    lessons: lessons.length,
    news: articles.length,
    quiz: quizzes.length,
    scenarios: scenarios.length,
  };

  /* Nhãn tiếng Việt cho chip "đang lọc" — trước đây in ra mã tiếng Anh. */
  const CAT_LABEL: Record<string, string> = {
    all: 'Tất cả',
    guide: 'Hướng dẫn',
    alert: 'Cảnh báo',
    story: 'Câu chuyện',
    news: 'Tin tức',
  };

  /* Tải thêm: tránh dồn hàng chục thẻ vào một trang dài lê thê. */
  const PAGE_STEP = 12;
  const [shown, setShown] = useState(PAGE_STEP);
  useEffect(() => {
    setShown(PAGE_STEP);
  }, [activeTab, filterCat, searchQuery, sortBy]);

  const shownLessons = visibleLessons.slice(0, shown);
  const shownArticles = visibleArticles.slice(0, shown);
  const shownQuizzes = visibleQuizzes.slice(0, shown);
  const shownScenarios = visibleScenarios.slice(0, shown);
  const remaining = Math.max(0, listCount - shown);

  const clearAll = () => {
    setSearchInput('');
    setSearchQuery('');
    setFilterCat('all');
  };

  const tabs: Array<{ key: Tab; label: string; icon: string }> = [
    { key: 'lessons', label: 'Bài học', icon: 'bi-journal-text' },
    { key: 'news', label: 'Tin tức', icon: 'bi-newspaper' },
    { key: 'quiz', label: 'Quiz', icon: 'bi-patch-question' },
    { key: 'scenarios', label: 'Kịch bản', icon: 'bi-masks' },
  ];

  const searchPlaceholder =
    activeTab === 'quiz'
      ? 'Tìm câu hỏi luyện tập...'
      : activeTab === 'scenarios'
      ? 'Tìm kịch bản diễn tập...'
      : 'Tìm bài học, tin tức, nội dung...';

  /* Thanh tìm kiếm: dùng chung cho cả 4 tab (trước đây chỉ có ở Bài học/Tin tức). */
  const searchBox = (
    <div className="relative max-w-2xl mx-auto group/search">
      <div className="absolute inset-0 bg-brand-500/5 blur-2xl rounded-full opacity-0 group-focus-within/search:opacity-100 transition-opacity duration-500"></div>
      <div className="relative flex items-center bg-card/70 border border-white/10 rounded-2xl backdrop-blur-xl overflow-hidden focus-within:border-brand-500/40 focus-within:shadow-lg focus-within:shadow-brand-500/5 transition-all duration-300">
        <div className="pl-5 pr-3 flex items-center justify-center text-white/65 group-focus-within/search:text-brand-400 transition-colors">
          <i className="bi bi-search text-base"></i>
        </div>
        <input
          type="text"
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          placeholder={searchPlaceholder}
          aria-label="Tìm kiếm nội dung"
          className="flex-1 bg-transparent py-4 pr-4 text-sm font-medium text-white placeholder:text-white/70 focus:outline-none"
        />
        {searchQuery && (
          <button
            type="button"
            onClick={() => {
              setSearchInput('');
              setSearchQuery('');
            }}
            aria-label="Xoá từ khoá tìm kiếm"
            className="mr-3 w-9 h-9 shrink-0 rounded-xl bg-white/5 flex items-center justify-center text-white/65 hover:bg-danger-500/10 hover:text-danger-400 transition-all"
          >
            <i className="bi bi-x-lg text-sm"></i>
          </button>
        )}
        <div className="pr-4 text-[12px] font-semibold text-white/65 whitespace-nowrap">
          <span>{listCount}</span> kết quả
        </div>
      </div>
    </div>
  );

  /* Chip cho biết đang lọc/tìm gì — trước đây in ra mã tiếng Anh ("alert"). */
  const activeChips = (filterCat !== 'all' || searchQuery) && (
    <div className="flex flex-wrap items-center justify-center gap-2">
      <span className="text-[12px] font-medium text-white/65">Đang lọc</span>
      {filterCat !== 'all' && (
        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-white/5 border border-border text-[12px] font-medium text-white/85">
          <span>{CAT_LABEL[filterCat] || filterCat}</span>
          <button
            type="button"
            onClick={() => setFilterCat('all')}
            aria-label="Bỏ lọc theo danh mục"
            className="text-white/65 hover:text-danger-400 transition-colors"
          >
            <i className="bi bi-x"></i>
          </button>
        </span>
      )}
      {searchQuery && (
        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-white/5 border border-border text-[12px] font-medium text-white/85">
          &quot;<span>{searchQuery.substring(0, 20)}</span>&quot;
          <button
            type="button"
            onClick={() => {
              setSearchInput('');
              setSearchQuery('');
            }}
            aria-label="Xoá từ khoá tìm kiếm"
            className="text-white/65 hover:text-danger-400 transition-colors"
          >
            <i className="bi bi-x"></i>
          </button>
        </span>
      )}
      <button
        type="button"
        onClick={clearAll}
        className="text-[12px] font-medium text-danger-400 hover:text-danger-300 transition-colors ml-1"
      >
        Xoá tất cả
      </button>
    </div>
  );

  /* Nút tải thêm + cho biết đang xem bao nhiêu / tổng bao nhiêu. */
  const loadMore = remaining > 0 && (
    <div className="flex flex-col items-center gap-2 pt-8">
      <button
        type="button"
        onClick={() => setShown((s) => s + PAGE_STEP)}
        className="px-6 py-3 rounded-full text-[13px] font-semibold bg-card/70 text-white border border-border hover:border-brand-500/40 hover:text-brand-300 transition-all inline-flex items-center gap-2"
      >
        <i className="bi bi-chevron-down"></i>
        Tải thêm {Math.min(PAGE_STEP, remaining)} nội dung
      </button>
      <span className="text-[12px] text-white/65">
        Đang hiển thị {Math.min(shown, listCount)}/{listCount}
      </span>
    </div>
  );

  return (
    <div className="animate-fadein max-w-6xl mx-auto space-y-10 px-4 pt-16 sm:pt-20 pb-20">
      {/* Page Header */}
      <div className="text-center space-y-4">
        <div
          className="inline-flex items-center justify-center w-20 h-20 rounded-[2.5rem] bg-brand-500/10 text-brand-400 border border-brand-500/20 shadow-lg shadow-brand-500/10 mb-5"
        >
          <i className="bi bi-book-half text-4xl"></i>
        </div>
        <h1 className="text-4xl font-bold text-white tracking-tight leading-none">
          <span className="glow-text">Học cách phòng tránh</span>
        </h1>
        <p className="text-white/75 text-sm font-medium tracking-wide prose-sm">
          Kiến thức là vũ khí tốt nhất để bảo vệ bản thân và gia đình
        </p>
      </div>

      {/* Lối vào dành cho người cao tuổi — đặt ngay TRÊN các tab để dễ thấy nhất */}
      <section
        aria-labelledby="learn-elder"
        className="rounded-2xl border-2 border-safe-500/40 bg-safe-500/10 p-5 sm:p-6"
      >
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
          <div className="flex flex-1 items-start gap-4">
            <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl border border-safe-500/40 bg-safe-500/15 text-safe-300">
              <i className="bi bi-person-hearts text-2xl" aria-hidden="true"></i>
            </div>
            <div className="min-w-0">
              <h2 id="learn-elder" className="text-[18px] font-bold leading-snug text-white">
                Dành cho người cao tuổi
              </h2>
              <p className="mt-1.5 text-[15px] font-medium leading-relaxed text-white/80">
                Trang chữ to, nút to, đọc được thành tiếng: kiểm tra số điện thoại, tin nhắn, đường link, số tài khoản.
                Không cần đăng nhập.
              </p>
            </div>
          </div>
          <Link
            href="/nguoi-cao-tuoi/"
            className="inline-flex min-h-[56px] shrink-0 items-center justify-center gap-2 rounded-xl border border-safe-500/50 bg-safe-500/20 px-6 text-[15px] font-bold text-safe-100 transition-colors hover:bg-safe-500/30"
          >
            <i className="bi bi-box-arrow-up-right" aria-hidden="true"></i> Mở trang chữ to
          </Link>
        </div>
      </section>

      {/* Tab Navigation — cuộn ngang gọn trên màn hình hẹp */}
      <div className="learn-filter-scroll max-w-full pb-1">
        <div
          className="flex justify-start sm:justify-center gap-2 p-1.5 bg-white/5 border border-white/10 rounded-[2rem] w-fit mx-auto backdrop-blur-xl"
        >
          {tabs.map((t) => (
            <button
              key={t.key}
              type="button"
              aria-pressed={activeTab === t.key}
              className={`px-4 sm:px-6 py-2.5 rounded-full text-[13px] font-semibold whitespace-nowrap inline-flex items-center gap-2 transition-all ${
                activeTab === t.key ? 'bg-white/10 text-white shadow-lg' : 'text-white/70 hover:text-white'
              }`}
              onClick={() => switchTab(t.key)}
            >
              <i className={`bi ${t.icon}`}></i>
              <span>{t.label}</span>
              <span
                className={`px-1.5 py-0.5 rounded-full text-[11px] font-bold ${
                  activeTab === t.key ? 'bg-brand-500/20 text-brand-300' : 'bg-white/10 text-white/60'
                }`}
              >
                {tabCounts[t.key]}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* ═══ LESSONS TAB ═══ */}
      {(activeTab === 'lessons' || activeTab === 'news') && (
        <div>
          {/* Search, Filter & Sort Controls */}
          <div className="space-y-5 mb-8 relative" style={{ zIndex: 100, isolation: 'isolate' }}>
            {searchBox}

            <div className="flex flex-col sm:flex-row items-center justify-center gap-3 relative" style={{ zIndex: 50 }}>
              <div className="learn-filter-scroll w-full sm:w-auto pb-1">
                <div className="flex items-center justify-start sm:justify-center gap-2 min-w-max px-1">
                  <FilterPill active={filterCat === 'all'} activeClass="bg-brand-500/20 text-brand-400 border-brand-500/30 shadow-lg shadow-brand-500/10" onClick={() => setFilterCat('all')} label="Tất cả" />
                  {activeTab === 'lessons' && (
                    <FilterPill
                      active={filterCat === 'guide'}
                      activeClass="bg-safe-500/20 text-safe-400 border-safe-500/30 shadow-lg shadow-safe-500/10"
                      onClick={() => setFilterCat('guide')}
                      icon="bi-book"
                      label="Hướng dẫn"
                    />
                  )}
                  {activeTab === 'news' && (
                    <FilterPill
                      active={filterCat === 'news'}
                      activeClass="bg-brand-500/20 text-brand-400 border-brand-500/30 shadow-lg shadow-brand-500/10"
                      onClick={() => setFilterCat('news')}
                      icon="bi-newspaper"
                      label="Tin tức"
                    />
                  )}
                  <FilterPill
                    active={filterCat === 'alert'}
                    activeClass="bg-danger-500/20 text-danger-400 border-danger-500/30 shadow-lg shadow-danger-500/10"
                    onClick={() => setFilterCat('alert')}
                    icon="bi-exclamation-triangle"
                    label="Cảnh báo"
                  />
                  <FilterPill
                    active={filterCat === 'story'}
                    activeClass="bg-brand2-500/20 text-brand2-400 border-brand2-500/30 shadow-lg shadow-brand2-500/10"
                    onClick={() => setFilterCat('story')}
                    icon="bi-chat-heart"
                    label="Câu chuyện"
                  />
                  <FilterPill
                    active={filterCat === 'inclusive'}
                    activeClass="bg-sky-500/20 text-sky-400 border-sky-500/30 shadow-lg shadow-sky-500/10"
                    onClick={() => setFilterCat('inclusive')}
                    icon="bi-people-fill"
                    label="Bao trùm"
                  />
                  <FilterPill
                    active={filterCat === 'empathy'}
                    activeClass="bg-purple-500/20 text-purple-400 border-purple-500/30 shadow-lg shadow-purple-500/10"
                    onClick={() => setFilterCat('empathy')}
                    icon="bi-heart-fill"
                    label="Góc thấu cảm"
                  />
                </div>
              </div>

              <span className="w-px h-6 bg-white/10 hidden sm:block"></span>

              <div className="relative flex items-center gap-2" ref={sortRef}>
                <span className="hidden sm:inline text-[12px] font-medium text-white/65">Sắp xếp</span>
                <button
                  type="button"
                  onClick={() => setSortOpen((v) => !v)}
                  aria-haspopup="listbox"
                  aria-expanded={sortOpen}
                  className="px-3.5 py-2 rounded-xl text-[13px] font-semibold bg-card/70 text-white/85 border border-border hover:text-white hover:border-brand-500/40 transition-all flex items-center gap-2"
                >
                  <i className="bi bi-sort-down text-brand-400"></i>
                  <span>{sortBy === 'newest' ? 'Mới nhất' : sortBy === 'oldest' ? 'Cũ nhất' : 'A → Z'}</span>
                  <i className={`bi bi-chevron-down text-[10px] transition-transform ${sortOpen ? 'rotate-180' : ''}`}></i>
                </button>
                {sortOpen && (
                  <div
                    className="absolute right-0 sm:right-auto sm:left-0 top-full mt-2 w-44 bg-popover border border-white/10 rounded-xl overflow-hidden shadow-2xl shadow-black/40 backdrop-blur-xl"
                    style={{ zIndex: 999 }}
                  >
                    <SortItem
                      active={sortBy === 'newest'}
                      onClick={() => {
                        setSortBy('newest');
                        setSortOpen(false);
                      }}
                      icon="bi-sort-down-alt"
                      label="Mới nhất"
                    />
                    <SortItem
                      active={sortBy === 'oldest'}
                      onClick={() => {
                        setSortBy('oldest');
                        setSortOpen(false);
                      }}
                      icon="bi-sort-up-alt"
                      label="Cũ nhất"
                    />
                    <SortItem
                      active={sortBy === 'alpha'}
                      onClick={() => {
                        setSortBy('alpha');
                        setSortOpen(false);
                      }}
                      icon="bi-sort-alpha-down"
                      label="A → Z"
                    />
                  </div>
                )}
              </div>
            </div>

            {activeChips}
          </div>

          {loading ? (
            <Spinner />
          ) : listCount === 0 ? (
            /* Trạng thái rỗng: hiện cho MỌI trường hợp không có kết quả
               (trước đây chỉ hiện khi có từ khoá tìm kiếm). */
            <div className="liquid-card py-16 text-center space-y-4 bg-white/[0.01] border-dashed">
              <div className="w-16 h-16 mx-auto rounded-2xl bg-white/5 flex items-center justify-center text-white/45">
                <i className="bi bi-search text-3xl"></i>
              </div>
              <p className="text-white/70 text-[15px] font-medium px-6">
                {!hasContent ? (
                  <>Đang soạn thảo nội dung...</>
                ) : searchQuery ? (
                  <>
                    Không tìm thấy kết quả cho &quot;<span className="text-brand-300">{searchQuery}</span>&quot;
                  </>
                ) : (
                  <>Không có nội dung nào khớp với bộ lọc đang chọn</>
                )}
              </p>
              <button
                type="button"
                onClick={clearAll}
                className="text-[13px] font-semibold text-brand-300 hover:text-brand-200"
              >
                Xoá bộ lọc
              </button>
            </div>
          ) : (
            <>
              {activeTab === 'lessons' && (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                  {shownLessons.map((lesson) => (
                    <LessonCard key={lesson.slug} lesson={lesson} onOpen={() => router.push(`/learn/lesson/${lesson.slug}/`)} />
                  ))}
                </div>
              )}

              {activeTab === 'news' && (
                <div className="flex flex-col gap-4">
                  {shownArticles.map((article) => (
                    <ArticleListItem key={article.slug} article={article} onOpen={() => router.push(`/learn/${article.slug}/`)} />
                  ))}
                </div>
              )}
              {loadMore}
            </>
          )}
        </div>
      )}

      {/* ═══ QUIZ TAB ═══ */}
      {activeTab === 'quiz' && (
        <div>
          <div className="space-y-5 mb-8">
            {searchBox}
            {activeChips}
          </div>
          {loading ? (
            <Spinner />
          ) : listCount === 0 ? (
            <div className="liquid-card py-16 text-center space-y-4 bg-white/[0.01] border-dashed">
              <div className="w-16 h-16 mx-auto rounded-2xl bg-white/5 flex items-center justify-center text-white/45">
                <i className="bi bi-patch-question text-3xl"></i>
              </div>
              <p className="text-white/70 text-[15px] font-medium px-6">
                {searchQuery ? (
                  <>
                    Không tìm thấy câu hỏi nào khớp với &quot;<span className="text-brand-300">{searchQuery}</span>&quot;
                  </>
                ) : (
                  <>Đang chuẩn bị bộ câu hỏi</>
                )}
              </p>
              {searchQuery && (
                <button
                  type="button"
                  onClick={clearAll}
                  className="text-[13px] font-semibold text-brand-300 hover:text-brand-200"
                >
                  Xoá bộ lọc
                </button>
              )}
            </div>
          ) : (
            <>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                {shownQuizzes.map((q, i) => (
                  <QuizCard key={q.id} quiz={q} index={i} />
                ))}
              </div>
              {loadMore}
            </>
          )}
        </div>
      )}

      {/* ═══ SCENARIOS TAB ═══ */}
      {activeTab === 'scenarios' && (
        <div>
          <div className="space-y-5 mb-8">
            {searchBox}
            {activeChips}
          </div>
          {loading ? (
            <Spinner />
          ) : listCount === 0 ? (
            <div className="liquid-card py-16 text-center space-y-4 bg-white/[0.01] border-dashed">
              <div className="w-16 h-16 mx-auto rounded-2xl bg-white/5 flex items-center justify-center text-white/45">
                <i className="bi bi-masks text-3xl"></i>
              </div>
              <p className="text-white/70 text-[15px] font-medium px-6">
                {searchQuery ? (
                  <>
                    Không tìm thấy kịch bản nào khớp với &quot;<span className="text-brand-300">{searchQuery}</span>&quot;
                  </>
                ) : (
                  <>Đang cập nhật kịch bản diễn tập</>
                )}
              </p>
              {searchQuery && (
                <button
                  type="button"
                  onClick={clearAll}
                  className="text-[13px] font-semibold text-brand-300 hover:text-brand-200"
                >
                  Xoá bộ lọc
                </button>
              )}
            </div>
          ) : (
            <>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                {shownScenarios.map((sc, i) => (
                  <ScenarioPlayerCard key={sc.id} scenario={sc} index={i} />
                ))}
              </div>
              {loadMore}
            </>
          )}
        </div>
      )}
    </div>
  );
}
