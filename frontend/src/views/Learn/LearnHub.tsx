'use client';
import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { learnApi, asList, mediaUrl } from '../../lib/api';
import type { Article } from '../../lib/api';
import { Spinner } from '../../components/ui';

/* Port từ PKV/templates/LearnHub/learn_hub.html.
 * API đã đấu: GET /articles/, /learn/lessons/, /learn/scenarios/, /learn/quizzes/.
 * Đáp án quiz chấm phía server qua POST /learn/quizzes/<id>/check/ (không lộ đáp án). */

type Tab = 'lessons' | 'news' | 'quiz' | 'scenarios';
type SortBy = 'newest' | 'oldest' | 'alpha';
type FilterCat = 'all' | 'guide' | 'news' | 'alert' | 'story';

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

const MONTHS_SHORT = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

function fmtDate(iso?: string): string {
  if (!iso) return '';
  try {
    const d = new Date(iso);
    return `${String(d.getDate()).padStart(2, '0')}/${String(d.getMonth() + 1).padStart(2, '0')}/${d.getFullYear()}`;
  } catch {
    return '';
  }
}

/* Django date:"d M Y" */
function fmtDateLong(iso?: string): string {
  if (!iso) return '';
  try {
    const d = new Date(iso);
    return `${String(d.getDate()).padStart(2, '0')} ${MONTHS_SHORT[d.getMonth()]} ${d.getFullYear()}`;
  } catch {
    return '';
  }
}

/* Django date:"Y-m-d" */
function isoDate(iso?: string): string {
  if (!iso) return '';
  try {
    const d = new Date(iso);
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  } catch {
    return '';
  }
}

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
  return v === 'all' || v === 'guide' || v === 'news' || v === 'alert' || v === 'story';
}

/* syncTabState() — điều chỉnh bộ lọc khi đổi tab (Alpine $watch + init). */
function syncCat(tab: Tab, cat: FilterCat): FilterCat {
  if (tab === 'news') return cat === 'all' || cat === 'news' || cat === 'alert' || cat === 'story' ? cat : 'news';
  if (tab === 'lessons') return cat === 'all' || cat === 'guide' || cat === 'alert' || cat === 'story' ? cat : 'guide';
  return 'all';
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

const PILL_BASE = 'px-4 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all border';
const PILL_IDLE = 'bg-white/[0.03] text-white/55 border-white/5 hover:text-white/60 hover:border-white/15';

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
      className={`w-full px-4 py-3 text-left text-xs font-bold hover:bg-white/5 transition-colors flex items-center gap-3 ${active ? 'text-brand-400' : 'text-white/60'}`}
    >
      <i className={`bi ${icon} text-sm`}></i> {label}
    </button>
  );
}

function LessonCard({ lesson, onOpen }: { lesson: Lesson; onOpen: () => void }) {
  return (
    <div
      className="learn-card liquid-card p-0 group overflow-hidden border border-white/5 hover:border-brand-500/30 transition-all flex flex-col h-full cursor-pointer"
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
          <span className="px-2 py-1 rounded-lg bg-brand-500/20 text-brand-300 text-[8px] font-black uppercase tracking-widest backdrop-blur-sm border border-brand-500/20">
            <i className="bi bi-stars mr-1"></i>AI
          </span>
        </div>
      </div>
      <div className="p-6 space-y-4 flex flex-col flex-1">
        <div className="flex items-center justify-between">
          <span className="px-3 py-1 rounded-full bg-brand-500/10 text-brand-400 text-[9px] font-black uppercase tracking-widest">
            {lesson.category_display || lesson.category}
          </span>
          <span className="text-[9px] font-bold text-white/35 uppercase tracking-widest">{fmtDate(lesson.created_at)}</span>
        </div>
        <h3 className="text-base font-black text-white line-clamp-2 tracking-tight group-hover:text-brand-400 transition-colors">
          {lesson.title}
        </h3>
        <p className="text-white/55 text-[11px] font-medium leading-relaxed line-clamp-3 min-h-[52px]">
          {lesson.summary || truncatechars(stripTags(lesson.content || ''), 150)}
        </p>
        <div className="pt-4 border-t border-white/5 flex items-center justify-between text-[9px] font-bold mt-auto">
          <div className="flex items-center gap-3 text-white/35">
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
          <span className="text-brand-400 uppercase tracking-widest inline-flex items-center gap-1">
            Xem thêm <i className="bi bi-arrow-right"></i>
          </span>
        </div>
      </div>
    </div>
  );
}

function ArticleCard({ article, onOpen }: { article: Article; onOpen: () => void }) {
  return (
    <div
      className="learn-card liquid-card p-0 group overflow-hidden border border-white/5 hover:border-brand-500/30 transition-all flex flex-col h-full cursor-pointer"
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
      <div className="aspect-video bg-white/5 overflow-hidden">
        {article.cover_image ? (
          <img
            src={mediaUrl(article.cover_image)}
            className="w-full h-full object-cover transition-transform duration-500 group-hover:scale-105"
            loading="lazy"
            alt={article.title}
          />
        ) : (
          <div className="w-full h-full flex items-center justify-center bg-gradient-to-br from-warn-500/5 to-danger-500/5">
            <i className="bi bi-newspaper text-5xl text-white/5"></i>
          </div>
        )}
      </div>
      <div className="p-6 space-y-4 flex flex-col flex-1">
        <div className="flex items-center justify-between">
          <span className="px-3 py-1 rounded-full bg-warn-500/10 text-warn-400 text-[9px] font-black uppercase tracking-widest">
            {article.category_display || article.category}
          </span>
          <span className="text-[9px] font-bold text-white/35 uppercase tracking-widest">{fmtDate(article.created_at)}</span>
        </div>
        <h3 className="text-base font-black text-white line-clamp-2 tracking-tight group-hover:text-brand-400 transition-colors">
          {article.title}
        </h3>
        <p className="text-white/55 text-[11px] font-medium leading-relaxed line-clamp-3 min-h-[52px]">
          {truncatechars(stripTags(article.summary || ''), 150)}
        </p>
        <div className="pt-4 border-t border-white/5 flex items-center justify-between text-[9px] font-bold mt-auto">
          <div className="flex items-center gap-3 text-white/35">
            <span>
              <i className="bi bi-hand-thumbs-up-fill mr-1 text-brand-400/80"></i>
              {article.reactions_count || 0}
            </span>
            <span>
              <i className="bi bi-chat-left-text mr-1 text-warn-400/80"></i>
              {article.comments_count || 0}
            </span>
          </div>
          <span className="text-brand-400 uppercase tracking-widest inline-flex items-center gap-1">
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

  const optionClass = (oid: string, isCorrect: boolean): string => {
    if (submitted) {
      if (isCorrect) return 'border-safe-500/40 bg-safe-500/10 text-safe-400';
      if (selected === oid) return 'border-danger-500/40 bg-danger-500/10 text-danger-400';
      return 'border-white/5 text-white/35 opacity-50';
    }
    return selected === oid
      ? 'border-brand-400/50 bg-brand-400/10 text-white translate-x-1'
      : 'border-white/5 text-white/60 hover:border-white/20 hover:bg-white/5 hover:text-white';
  };

  return (
    <div
      className="liquid-card group flex flex-col h-full border border-white/5 hover:border-brand-500/20 transition-all duration-500"
    >
      <div className="p-6 pb-0 flex items-start gap-4">
        <div className="relative group-hover:scale-110 transition-transform">
          <div className="absolute inset-0 bg-brand2-500 blur-xl opacity-20 group-hover:opacity-40 transition-opacity"></div>
          <div className="relative w-12 h-12 flex-shrink-0 rounded-[1.25rem] bg-slate-900 border border-brand2-500/30 text-brand2-400 flex items-center justify-center font-black text-lg">
            {index + 1}
          </div>
        </div>
        <div className="flex-1 min-w-0">
          <h3 className="text-lg font-black text-white leading-tight mb-2 group-hover:text-brand-400 transition-colors">{quiz.question}</h3>
          <div className="flex flex-wrap gap-2">
            {quiz.lesson ? (
              <Link
                href={`/learn/lesson/${quiz.lesson.slug}/`}
                className="flex items-center gap-1.5 px-2 py-1 rounded-lg bg-brand-500/5 border border-brand-500/10 text-[9px] text-brand-400/80 font-black uppercase tracking-widest hover:bg-brand-500/10 hover:text-brand-400 transition-all"
              >
                <i className="bi bi-book"></i> {truncatechars(quiz.lesson.title, 30)}
              </Link>
            ) : quiz.article ? (
              <Link
                href={`/learn/${quiz.article.slug}/`}
                className="flex items-center gap-1.5 px-2 py-1 rounded-lg bg-warn-500/5 border border-warn-500/10 text-[9px] text-warn-400/80 font-black uppercase tracking-widest hover:bg-warn-500/10 hover:text-warn-400 transition-all"
              >
                <i className="bi bi-newspaper"></i> {truncatechars(quiz.article.title, 30)}
              </Link>
            ) : null}
          </div>
        </div>
      </div>

      <div className="p-6 flex-1 space-y-3">
        {quiz.options.map((opt) => {
          const isCorrect = opt.id === (answer?.correct_answer ?? quiz.correct_answer);
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
              <div className="flex items-center gap-4">
                <span
                  className={`w-6 h-6 rounded-lg bg-white/5 flex items-center justify-center text-[10px] font-black text-white/55 group-hover/opt:bg-brand-500/20 group-hover/opt:text-brand-400 ${
                    selected === opt.id ? 'bg-brand-500/20 text-brand-400' : ''
                  }`}
                >
                  {opt.id}
                </span>
                <span>{opt.text}</span>
              </div>
              <div className="flex items-center">
                {submitted && isCorrect && <i className="bi bi-check2-circle text-xl text-safe-400"></i>}
                {submitted && selected === opt.id && !isCorrect && <i className="bi bi-x-circle text-xl text-danger-400"></i>}
              </div>
            </button>
          );
        })}
      </div>

      <div className="p-6 pt-0 space-y-4">
        <div className="flex items-center justify-between gap-4">
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
            disabled={!selected || submitted}
            className={`flex-1 py-3.5 rounded-2xl text-[11px] font-black uppercase tracking-widest transition-all shadow-xl ${
              !selected || submitted
                ? 'bg-white/5 text-white/20 cursor-not-allowed border border-white/5'
                : 'bg-gradient-to-r from-brand-500 to-brand-600 text-white hover:scale-[1.02] shadow-brand-500/20'
            }`}
          >
            <span className={!submitted ? '' : 'hidden'}>Kiểm tra đáp án</span>
            <span className={submitted && correct ? '' : 'hidden'}>
              <i className="bi bi-hand-thumbs-up-fill mr-2"></i>Chính xác!
            </span>
            <span className={submitted && !correct ? '' : 'hidden'}>
              <i className="bi bi-exclamation-octagon-fill mr-2"></i>Cần xem lại
            </span>
          </button>
        </div>

        {(quiz.explanation || answer?.explanation) && (
          <div
            className={`p-5 rounded-3xl bg-white/[0.03] border border-white/10 relative overflow-hidden group/exp ${submitted ? '' : 'hidden'}`}
          >
            <div className="absolute top-0 right-0 w-24 h-24 bg-warn-400/5 blur-3xl rounded-full -mr-10 -mt-10"></div>
            <span className="text-[9px] font-black text-warn-400 uppercase tracking-[0.2em] flex items-center gap-2 mb-2">
              <i className="bi bi-lightbulb-fill"></i> TẠI SAO NHƯ VẬY?
            </span>
            <p className="text-[12px] text-white/70 font-medium leading-relaxed italic">{quiz.explanation || answer?.explanation}</p>
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
    return 'bg-white/5 border-white/5 text-white/60 text-center italic py-2 px-8 rounded-full';
  };

  return (
    <div
      className="liquid-card p-0 flex flex-col h-full border border-white/5 hover:border-brand2-500/20 transition-all duration-500 overflow-hidden"
    >
      {!open && (
        <div className="relative aspect-[16/6] bg-slate-900 overflow-hidden group/head">
          <div className="absolute inset-0 bg-gradient-to-br from-brand2-600/30 via-transparent to-brand-500/20 z-0"></div>
          <div className="absolute inset-0 p-8 flex flex-col justify-center z-10">
            <div className="flex items-center gap-6">
              <div className="relative">
                <div className="absolute inset-0 bg-brand2-500 blur-2xl opacity-40 group-hover/head:opacity-70 transition-opacity"></div>
                <div className="relative w-16 h-16 rounded-[1.5rem] bg-slate-950/80 border border-white/10 flex items-center justify-center text-white shadow-2xl group-hover/head:scale-110 transition-transform duration-500">
                  <i className="bi bi-mask text-3xl text-brand2-400"></i>
                </div>
              </div>
              <div className="flex-1 min-w-0">
                <h3 className="text-2xl font-black text-white leading-tight mb-2 group-hover/head:text-brand2-400 transition-colors">{scenario.title}</h3>
                <div className="flex items-center gap-4">
                  <span className="flex items-center gap-2 text-[10px] font-black text-white/45 uppercase tracking-[0.2em]">
                    <i className="bi bi-layers-half text-brand2-500"></i> <span>{maxSteps}</span> BƯỚC MÔ PHỎNG
                  </span>
                  <span className="w-1.5 h-1.5 rounded-full bg-white/10"></span>
                  <span className="text-[10px] font-black text-white/45 uppercase tracking-[0.2em]">{fmtDateLong(scenario.created_at)}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {!open && (
        <div className="p-8 space-y-6 flex-1 flex flex-col relative z-10 bg-slate-950/20">
          <p className="text-white/60 text-[13px] font-medium leading-relaxed prose-sm italic line-clamp-3">
            &quot;{scenario.description}&quot;
          </p>
          <div className="mt-auto pt-6 flex items-center justify-between">
            <button
              type="button"
              onClick={play}
              className="relative w-full group/btn overflow-hidden rounded-2xl py-4 bg-brand2-500 text-white font-black text-[11px] uppercase tracking-[0.3em] transition-all hover:scale-[1.02] hover:shadow-[0_0_30px_rgba(168,85,247,0.3)]"
            >
              <div className="absolute inset-0 bg-gradient-to-r from-brand2-600 to-brand2-600 opacity-0 group-hover/btn:opacity-100 transition-opacity"></div>
              <span className="relative flex items-center justify-center gap-3">
                <i className="bi bi-play-circle-fill text-lg"></i> BẮT ĐẦU TRẢI NGHIỆM
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
                <h4 className="text-[11px] font-black text-white uppercase tracking-widest">{scenario.title}</h4>
                <div className="flex items-center gap-2 mt-1.5 h-1.5 w-32">
                  {steps.map((_, i) => (
                    <div
                      key={i}
                      className={`h-full rounded-full transition-all duration-500 ${i <= currentStep ? 'bg-brand2-500 flex-1' : 'bg-white/10 w-1.5'}`}
                    ></div>
                  ))}
                </div>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setOpen(false)}
              className="w-10 h-10 rounded-2xl hover:bg-danger-500/10 text-white/35 hover:text-danger-400 transition-all flex items-center justify-center"
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
                      className={`flex items-center gap-2 mb-2 px-3 py-1 rounded-full border text-[10px] font-black uppercase tracking-widest ${actorBadge(
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
                      <div className="mt-4 p-5 rounded-3xl bg-warn-400/[0.02] border border-warn-400/10 max-w-[75%] relative overflow-hidden group/insight">
                        <div className="absolute top-0 right-0 w-16 h-16 bg-warn-400/5 blur-2xl rounded-full -mr-8 -mt-8"></div>
                        <div className="flex items-start gap-3">
                          <div className="w-8 h-8 rounded-xl bg-warn-400/10 flex items-center justify-center text-warn-500 shrink-0 border border-warn-500/20 shadow-lg shadow-warn-500/10">
                            <i className="bi bi-eyedropper text-sm"></i>
                          </div>
                          <div>
                            <p className="text-[10px] font-black text-warn-500/80 uppercase tracking-[0.2em] mb-1.5">Phân tích kỹ thuật lừa đảo</p>
                            <p className="text-[12px] text-warn-50/40 leading-relaxed italic">{s.analysis}</p>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              ) : null,
            )}
          </div>

          <div className="p-6 bg-[var(--sc-ink-deep)] border-t border-white/10 flex items-center justify-between gap-6 relative z-20">
            <button
              type="button"
              onClick={prev}
              disabled={currentStep === 0}
              className={`w-14 h-14 rounded-2xl border border-white/5 flex items-center justify-center transition-all bg-white/[0.02] ${
                currentStep === 0 ? 'text-white/5 cursor-not-allowed' : 'text-white/60 hover:bg-white/10 hover:text-white hover:scale-105'
              }`}
            >
              <i className="bi bi-arrow-left text-xl"></i>
            </button>

            <div className="flex-1 text-center">
              <div className="inline-flex items-center justify-center px-4 py-1.5 rounded-full bg-white/5 border border-white/5">
                <span className="text-[11px] font-black text-white/35 uppercase tracking-[0.3em]">
                  <span className="text-brand2-400">{currentStep + 1}</span> <span className="mx-1">/</span> <span>{maxSteps}</span> BƯỚC
                </span>
              </div>
            </div>

            <button
              type="button"
              onClick={next}
              disabled={currentStep >= maxSteps - 1}
              className={`flex-1 sm:flex-none sm:w-64 h-14 rounded-2xl text-[11px] font-black uppercase tracking-[0.3em] transition-all relative overflow-hidden group/next ${
                currentStep >= maxSteps - 1
                  ? 'bg-white/5 text-white/20 cursor-not-allowed border border-white/5'
                  : 'bg-brand2-600 text-white shadow-2xl shadow-brand2-600/30 hover:scale-[1.03]'
              }`}
            >
              <span className="relative z-10 flex items-center justify-center gap-3">
                {currentStep < maxSteps - 1 ? (
                  <span className="flex items-center gap-3">
                    Tiếp tục diễn tập <i className="bi bi-arrow-right-short text-xl"></i>
                  </span>
                ) : (
                  <span className="flex items-center gap-3">
                    Hoàn thành mô phỏng <i className="bi bi-check2-all text-xl"></i>
                  </span>
                )}
              </span>
              <div className="absolute inset-0 bg-gradient-to-r from-brand2-500 to-brand-600 opacity-0 group-hover/next:opacity-100 transition-opacity"></div>
            </button>
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

  const visibleCount = activeTab === 'news' ? visibleArticles.length : activeTab === 'lessons' ? visibleLessons.length : 0;
  const hasContent = lessons.length > 0 || articles.length > 0;

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

  return (
    <div className="animate-fadein max-w-6xl mx-auto space-y-10 px-4 pt-16 sm:pt-20 pb-20">
      <style>{`
        .learn-filter-scroll {
            overflow-x: auto;
            overflow-y: hidden;
            scrollbar-width: thin;
            scrollbar-color: rgba(34, 211, 238, 0.35) rgba(255, 255, 255, 0.03);
        }
        .learn-filter-scroll::-webkit-scrollbar {
            height: 8px;
        }
        .learn-filter-scroll::-webkit-scrollbar-track {
            background: rgba(255, 255, 255, 0.03);
            border-radius: 999px;
        }
        .learn-filter-scroll::-webkit-scrollbar-thumb {
            background: linear-gradient(90deg, rgba(34, 211, 238, 0.5), rgba(168, 85, 247, 0.45));
            border-radius: 999px;
            border: 1px solid rgba(255, 255, 255, 0.06);
        }
      `}</style>

      {/* Page Header */}
      <div className="text-center space-y-4">
        <div
          className="inline-flex items-center justify-center w-20 h-20 rounded-[2.5rem] bg-brand-500/10 text-brand-400 border border-brand-500/20 shadow-lg shadow-brand-500/10 mb-5"
        >
          <i className="bi bi-book-half text-4xl"></i>
        </div>
        <h1 className="text-4xl font-black text-white tracking-tight leading-none">
          <span className="glow-text">Học cách phòng tránh</span>
        </h1>
        <p className="text-white/55 text-sm font-medium tracking-wide prose-sm">
          Kiến thức là vũ khí tốt nhất để bảo vệ bản thân và gia đình
        </p>
      </div>

      {/* Tab Navigation */}
      <div
        className="flex justify-center gap-2 p-1.5 bg-white/5 border border-white/10 rounded-[2rem] w-fit mx-auto backdrop-blur-xl"
      >
        {tabs.map((t) => (
          <button
            key={t.key}
            type="button"
            className={`px-6 py-2.5 rounded-full text-[10px] font-black uppercase tracking-widest transition-all ${
              activeTab === t.key ? 'bg-white/10 text-white shadow-lg' : 'text-white/55 hover:text-white/60'
            }`}
            onClick={() => switchTab(t.key)}
          >
            <i className={`bi ${t.icon} mr-2`}></i> {t.label}
          </button>
        ))}
      </div>

      {/* ═══ LESSONS TAB ═══ */}
      {(activeTab === 'lessons' || activeTab === 'news') && (
        <div>
          {/* Search, Filter & Sort Controls */}
          <div className="space-y-5 mb-8 relative" style={{ zIndex: 100, isolation: 'isolate' }}>
            <div className="relative max-w-2xl mx-auto group/search">
              <div className="absolute inset-0 bg-brand-500/5 blur-2xl rounded-full opacity-0 group-focus-within/search:opacity-100 transition-opacity duration-500"></div>
              <div className="relative flex items-center bg-slate-900/60 border border-white/10 rounded-2xl backdrop-blur-xl overflow-hidden focus-within:border-brand-500/40 focus-within:shadow-lg focus-within:shadow-brand-500/5 transition-all duration-300">
                <div className="pl-5 pr-3 flex items-center justify-center text-white/35 group-focus-within/search:text-brand-400 transition-colors">
                  <i className="bi bi-search text-base"></i>
                </div>
                <input
                  type="text"
                  value={searchInput}
                  onChange={(e) => setSearchInput(e.target.value)}
                  placeholder="Tìm bài học, tin tức, nội dung..."
                  className="flex-1 bg-transparent py-4 pr-4 text-sm font-medium text-white placeholder:text-white/55 focus:outline-none"
                />
                {searchQuery && (
                  <button
                    type="button"
                    onClick={() => {
                      setSearchInput('');
                      setSearchQuery('');
                    }}
                    className="mr-3 w-8 h-8 rounded-xl bg-white/5 flex items-center justify-center text-white/45 hover:bg-danger-500/10 hover:text-danger-400 transition-all"
                  >
                    <i className="bi bi-x-lg text-xs"></i>
                  </button>
                )}
                {searchQuery && (
                  <div className="pr-4 text-[10px] font-bold text-white/35 whitespace-nowrap">
                    <span>{visibleCount}</span> kết quả
                  </div>
                )}
              </div>
            </div>

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
                </div>
              </div>

              <span className="w-px h-6 bg-white/10 hidden sm:block"></span>

              <div className="relative" ref={sortRef}>
                <button
                  type="button"
                  onClick={() => setSortOpen((v) => !v)}
                  className="px-4 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest bg-white/[0.03] text-white/55 border border-white/5 hover:text-white/60 hover:border-white/15 transition-all flex items-center gap-2"
                >
                  <i className="bi bi-sort-down"></i>
                  <span>{sortBy === 'newest' ? 'Mới nhất' : sortBy === 'oldest' ? 'Cũ nhất' : 'A → Z'}</span>
                  <i className={`bi bi-chevron-down text-[8px] transition-transform ${sortOpen ? 'rotate-180' : ''}`}></i>
                </button>
                {sortOpen && (
                  <div
                    className="absolute right-0 sm:right-auto sm:left-0 top-full mt-2 w-44 bg-slate-900/95 border border-white/10 rounded-xl overflow-hidden shadow-2xl shadow-black/40 backdrop-blur-xl"
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

            {/* Active filter indicator */}
            {(filterCat !== 'all' || searchQuery) && (
              <div className="flex items-center justify-center gap-2">
                <span className="text-[9px] font-bold text-white/35 uppercase tracking-widest">Đang lọc</span>
                {filterCat !== 'all' && (
                  <span className="inline-flex items-center gap-1 px-2 py-1 rounded-lg bg-white/5 border border-white/10 text-[9px] font-bold text-white/55">
                    <span>{filterCat}</span>
                    <button type="button" onClick={() => setFilterCat('all')} className="text-white/45 hover:text-danger-400 transition-colors">
                      <i className="bi bi-x"></i>
                    </button>
                  </span>
                )}
                {searchQuery && (
                  <span className="inline-flex items-center gap-1 px-2 py-1 rounded-lg bg-white/5 border border-white/10 text-[9px] font-bold text-white/55">
                    &quot;<span>{searchQuery.substring(0, 20)}</span>&quot;
                    <button
                      type="button"
                      onClick={() => {
                        setSearchInput('');
                        setSearchQuery('');
                      }}
                      className="text-white/45 hover:text-danger-400 transition-colors"
                    >
                      <i className="bi bi-x"></i>
                    </button>
                  </span>
                )}
                <button type="button" onClick={clearAll} className="text-[9px] font-bold text-danger-400/50 hover:text-danger-400 transition-colors ml-1">
                  Xóa tất cả
                </button>
              </div>
            )}
          </div>

          {loading ? (
            <Spinner />
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {activeTab === 'lessons' &&
                visibleLessons.map((lesson) => (
                  <LessonCard key={lesson.slug} lesson={lesson} onOpen={() => router.push(`/learn/lesson/${lesson.slug}/`)} />
                ))}

              {activeTab === 'news' &&
                visibleArticles.map((article) => (
                  <ArticleCard key={article.slug} article={article} onOpen={() => router.push(`/learn/${article.slug}/`)} />
                ))}

              {!hasContent && (
                <div className="col-span-3 py-20 text-center text-white/20 uppercase font-black tracking-widest">Đang soạn thảo nội dung...</div>
              )}
            </div>
          )}

          {/* No results message */}
          {!loading && searchQuery && visibleCount === 0 && (
            <div className="py-16 text-center space-y-4">
              <div className="w-16 h-16 mx-auto rounded-2xl bg-white/5 flex items-center justify-center text-white/20">
                <i className="bi bi-search text-3xl"></i>
              </div>
              <p className="text-white/45 text-sm font-bold">
                Không tìm thấy kết quả cho &quot;<span className="text-brand-400">{searchQuery}</span>&quot;
              </p>
              <button type="button" onClick={clearAll} className="text-[10px] font-black text-brand-400 uppercase tracking-widest hover:text-brand-300">
                Xóa bộ lọc
              </button>
            </div>
          )}
        </div>
      )}

      {/* ═══ QUIZ TAB ═══ */}
      {activeTab === 'quiz' && (
        <div>
          {quizzes.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              {quizzes.map((q, i) => (
                <QuizCard key={q.id} quiz={q} index={i} />
              ))}
            </div>
          ) : (
            <div className="liquid-card py-24 text-center space-y-6 bg-white/[0.01] border-dashed">
              <div className="relative w-24 h-24 mx-auto">
                <div className="absolute inset-0 bg-white/5 blur-3xl rounded-full"></div>
                <div className="relative w-full h-full rounded-[2.5rem] bg-slate-900 flex items-center justify-center text-white/20 border border-white/5">
                  <i className="bi bi-patch-question text-5xl"></i>
                </div>
              </div>
              <div className="space-y-2">
                <p className="text-white/55 text-sm font-black uppercase tracking-widest">Đang chuẩn bị bộ câu hỏi</p>
                <p className="text-white/20 text-xs font-bold prose-sm">Hệ thống AI đang tổng hợp các tình huống mới nhất cho bạn.</p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ═══ SCENARIOS TAB ═══ */}
      {activeTab === 'scenarios' && (
        <div>
          {scenarios.length > 0 ? (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              {scenarios.map((sc, i) => (
                <ScenarioPlayerCard key={sc.id} scenario={sc} index={i} />
              ))}
            </div>
          ) : (
            <div className="liquid-card py-24 text-center space-y-6 bg-white/[0.01] border-dashed">
              <div className="relative w-24 h-24 mx-auto">
                <div className="absolute inset-0 bg-white/5 blur-3xl rounded-full"></div>
                <div className="relative w-full h-full rounded-[2.5rem] bg-slate-900 flex items-center justify-center text-white/20 border border-white/5">
                  <i className="bi bi-masks text-5xl"></i>
                </div>
              </div>
              <p className="text-white/55 text-sm font-black uppercase tracking-widest">Đang cập nhật kịch bản diễn tập</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
