'use client';
import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import Swal from 'sweetalert2';
import { api } from '../../lib/api';
import { sanitizeHtml } from '../../lib/chat/markdown';

/* Port 1-1 từ PKV/templates/Admin/magic_create.html — AI tạo bài học.
 * API: POST /admin/learn/ai-generate/ (trả task_id) + WebSocket /ws/task/<id>/
 *      để nhận tiến trình, POST /admin/learn/magic-save/ (lưu bản nháp). */

interface Quiz {
  question: string;
  options: string[];
  correct_answer: string;
  explanation?: string;
}
interface ScenarioStep {
  speaker: string;
  text: string;
  note?: string;
}
interface Scenario {
  title?: string;
  description?: string;
  content_json?: { steps?: ScenarioStep[] };
}
interface Result {
  title?: string;
  summary?: string;
  content?: string;
  category?: string;
  scenario?: Scenario;
}
interface WsData {
  title?: string;
  category?: string;
  summary?: string;
  content?: string;
  content_stream?: string;
  quiz_item?: Quiz;
  quiz_index?: number;
  quizzes?: Quiz[];
  quiz?: Quiz;
  scenario_header?: { title?: string; description?: string };
  scenario_step?: ScenarioStep;
  scenario?: Scenario | null;
}
interface WsMsg {
  type?: string;
  status?: string;
  message?: string;
  step?: number;
  data?: WsData;
}
type Stage = 'input' | 'streaming' | 'done';

const STAGES: Array<{ name: string; icon: string }> = [
  { name: 'Phân tích', icon: 'bi bi-search' },
  { name: 'Nội dung', icon: 'bi bi-journal-text' },
  { name: 'Quiz', icon: 'bi bi-patch-question' },
  { name: 'Kịch bản', icon: 'bi bi-chat-dots' },
  { name: 'Xong', icon: 'bi bi-check-lg' },
];

const MAX_RECONNECTS = 10;

const MAGIC_CSS = `
.mc-textarea {
    width: 100%; background: rgba(15,23,42,0.5); border: 1px solid rgba(255,255,255,0.06);
    border-radius: 1.25rem; padding: 1.25rem 1.5rem; color: white; font-size: 0.875rem;
    line-height: 1.7; transition: all 0.3s ease; resize: vertical; font-family: 'Inter', sans-serif;
}
.mc-textarea:focus { border-color: rgba(139,92,246,0.5); outline: none; background: rgba(15,23,42,0.7); box-shadow: 0 0 0 3px rgba(139,92,246,0.08); }
.mc-textarea::placeholder { color: rgba(255,255,255,0.15); }
.mc-pipeline { display: flex; align-items: center; gap: 0; }
.mc-step-item { display: flex; align-items: center; gap: 0.5rem; position: relative; }
.mc-step-icon {
    width: 36px; height: 36px; border-radius: 12px; display: flex; align-items: center; justify-content: center;
    font-size: 14px; font-weight: 800; transition: all 0.4s ease; position: relative; z-index: 1;
    background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.06); color: rgba(255,255,255,0.2);
}
.mc-step-icon.active {
    background: linear-gradient(135deg, rgba(139,92,246,0.3), rgba(59,130,246,0.3));
    border-color: rgba(139,92,246,0.5); color: var(--sc-brand2-300);
    box-shadow: 0 0 20px rgba(139,92,246,0.15);
    animation: mc-pulse 2s ease-in-out infinite;
}
.mc-step-icon.done {
    background: linear-gradient(135deg, rgba(34,197,94,0.25), rgba(16,185,129,0.2));
    border-color: rgba(34,197,94,0.4); color: var(--sc-safe-300);
}
.mc-step-connector {
    width: 40px; height: 2px; background: rgba(255,255,255,0.05); margin: 0 4px;
    border-radius: 1px; transition: background 0.4s; position: relative; overflow: hidden;
}
.mc-step-connector.done { background: rgba(34,197,94,0.3); }
.mc-step-connector.active::after {
    content: ''; position: absolute; inset: 0; border-radius: 1px;
    background: linear-gradient(90deg, rgba(139,92,246,0.6), rgba(59,130,246,0.6));
    animation: mc-connector-flow 1.5s ease-in-out infinite;
}
@keyframes mc-connector-flow {
    0% { transform: translateX(-100%); } 50% { transform: translateX(0); } 100% { transform: translateX(100%); }
}
@keyframes mc-pulse {
    0%, 100% { box-shadow: 0 0 20px rgba(139,92,246,0.15); }
    50% { box-shadow: 0 0 30px rgba(139,92,246,0.3); }
}
.mc-card {
    background: rgba(255,255,255,0.015); border: 1px solid rgba(255,255,255,0.05);
    border-radius: 1.25rem; overflow: hidden; transition: all 0.4s ease;
}
.mc-card.active { border-color: rgba(139,92,246,0.25); box-shadow: 0 4px 40px rgba(139,92,246,0.06); }
.mc-card.done { border-color: rgba(34,197,94,0.2); }
.mc-card-head {
    display: flex; align-items: center; gap: 0.75rem; padding: 0.875rem 1.25rem;
    background: rgba(255,255,255,0.015); border-bottom: 1px solid rgba(255,255,255,0.04);
}
.mc-card-body { padding: 1.25rem; }
.mc-content { color: rgba(255,255,255,0.7); font-size: 0.8rem; line-height: 1.8; }
.mc-content h1 { color: var(--sc-brand-400); font-size: 1.1rem; font-weight: 800; margin: 1.25rem 0 0.5rem; }
.mc-content h2 { color: var(--sc-brand-400); font-size: 1rem; font-weight: 800; margin: 1rem 0 0.5rem; }
.mc-content h3 { color: rgba(255,255,255,0.85); font-size: 0.9rem; font-weight: 700; margin: 0.75rem 0 0.3rem; }
.mc-content ul, .mc-content ol { padding-left: 1.5rem; }
.mc-content li { margin: 0.3rem 0; }
.mc-content p { margin: 0.5rem 0; }
.mc-content strong { color: white; }
.mc-content blockquote { border-left: 3px solid var(--sc-brand2-500); padding: 0.5rem 1rem; color: rgba(255,255,255,0.5); margin: 0.75rem 0; background: rgba(139,92,246,0.03); border-radius: 0 0.5rem 0.5rem 0; }
.mc-quiz {
    background: rgba(139,92,246,0.03); border: 1px solid rgba(139,92,246,0.08);
    border-radius: 1rem; padding: 1rem; transition: all 0.3s;
}
.mc-quiz:hover { border-color: rgba(139,92,246,0.2); background: rgba(139,92,246,0.05); }
.mc-chat-bubble {
    display: flex; gap: 0.75rem; padding: 0.75rem; border-radius: 1rem; transition: all 0.2s;
}
.mc-chat-bubble:hover { background: rgba(255,255,255,0.02); }
.mc-chat-avatar {
    width: 32px; height: 32px; border-radius: 10px; display: flex; align-items: center; justify-content: center;
    font-size: 15px; flex-shrink: 0;
}
.mc-chat-avatar.scammer { background: linear-gradient(135deg, rgba(239,68,68,0.15), rgba(220,38,38,0.1)); }
.mc-chat-avatar.victim { background: linear-gradient(135deg, rgba(59,130,246,0.15), rgba(37,99,235,0.1)); }
.mc-chat-avatar.narrator { background: linear-gradient(135deg, rgba(168,85,247,0.15), rgba(147,51,234,0.1)); }
.mc-skeleton { background: linear-gradient(90deg, rgba(255,255,255,0.02) 25%, rgba(255,255,255,0.06) 50%, rgba(255,255,255,0.02) 75%);
    background-size: 200% 100%; animation: mc-shimmer 1.5s infinite; border-radius: 0.5rem; }
@keyframes mc-shimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }
.mc-dots { display: inline-flex; gap: 4px; align-items: center; }
.mc-dots span { width: 5px; height: 5px; border-radius: 50%; background: var(--sc-brand2-500); opacity: 0.3; animation: mc-bounce 1.2s infinite; }
.mc-dots span:nth-child(2) { animation-delay: 0.15s; }
.mc-dots span:nth-child(3) { animation-delay: 0.3s; }
@keyframes mc-bounce { 0%,60%,100% { transform: translateY(0); opacity: 0.3; } 30% { transform: translateY(-5px); opacity: 1; } }
.mc-fade { animation: mc-fadeUp 0.5s ease-out both; }
@keyframes mc-fadeUp { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }
.mc-fade-delay-1 { animation-delay: 0.1s; }
.mc-fade-delay-2 { animation-delay: 0.2s; }
.mc-timer { font-variant-numeric: tabular-nums; font-feature-settings: 'tnum'; }
.mc-glow-btn { position: relative; overflow: hidden; }
.mc-glow-btn::before {
    content: ''; position: absolute; inset: -2px; border-radius: inherit;
    background: linear-gradient(135deg, var(--sc-brand2-500), var(--sc-brand-500), var(--sc-brand-500), var(--sc-brand2-500)); background-size: 300% 300%;
    animation: mc-glow-spin 3s linear infinite; z-index: -1; opacity: 0; transition: opacity 0.3s;
}
.mc-glow-btn:hover::before { opacity: 1; }
@keyframes mc-glow-spin { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } }
`;

function Dots() {
  return (
    <span className="mc-dots">
      <span></span>
      <span></span>
      <span></span>
    </span>
  );
}

export default function MagicCreate() {
  const router = useRouter();

  const [stage, setStage] = useState<Stage>('input');
  const [rawText, setRawText] = useState('');
  const [creating, setCreating] = useState(false);
  const [saving, setSaving] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [progressPct, setProgressPct] = useState(0);
  const [statusMsg, setStatusMsg] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [result, setResult] = useState<Result>({});
  const [includeQuiz, setIncludeQuiz] = useState(true);
  const [includeScenario, setIncludeScenario] = useState(true);
  const [quizCount, setQuizCount] = useState(5);
  const [scenarioStepsCount, setScenarioStepsCount] = useState(8);
  const [quizzes, setQuizzes] = useState<Quiz[]>([]);
  const [scenarioSteps, setScenarioSteps] = useState<ScenarioStep[]>([]);
  const [elapsedStr, setElapsedStr] = useState('00:00');

  const wsRef = useRef<WebSocket | null>(null);
  const timerRef = useRef<number | null>(null);
  const pingRef = useRef<number | null>(null);
  const elapsedRef = useRef(0);
  const reconnectRef = useRef(0);
  const creatingRef = useRef(false);
  const stageRef = useRef<Stage>('input');

  useEffect(() => { creatingRef.current = creating; }, [creating]);
  useEffect(() => { stageRef.current = stage; }, [stage]);

  const stopElapsed = () => {
    if (timerRef.current !== null) { window.clearInterval(timerRef.current); timerRef.current = null; }
  };
  const startElapsed = () => {
    elapsedRef.current = 0;
    setElapsedStr('00:00');
    if (timerRef.current !== null) window.clearInterval(timerRef.current);
    timerRef.current = window.setInterval(() => {
      elapsedRef.current += 1;
      const m = String(Math.floor(elapsedRef.current / 60)).padStart(2, '0');
      const s = String(elapsedRef.current % 60).padStart(2, '0');
      setElapsedStr(`${m}:${s}`);
    }, 1000);
  };
  const stopPing = () => {
    if (pingRef.current !== null) { window.clearInterval(pingRef.current); pingRef.current = null; }
  };
  const startPing = () => {
    stopPing();
    pingRef.current = window.setInterval(() => {
      if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ type: 'ping' }));
      }
    }, 25000);
  };

  useEffect(() => () => {
    if (timerRef.current !== null) window.clearInterval(timerRef.current);
    if (pingRef.current !== null) window.clearInterval(pingRef.current);
    wsRef.current?.close();
  }, []);

  function resetResult() {
    setResult({});
    setQuizzes([]);
    setScenarioSteps([]);
    setCurrentStep(0);
    setProgressPct(0);
    setStatusMsg('');
    setErrorMsg('');
    setCreating(false);
    reconnectRef.current = 0;
    stopElapsed();
    stopPing();
    wsRef.current?.close();
    wsRef.current = null;
  }

  function handleWSMessage(msg: WsMsg) {
    if (msg.status === 'processing') {
      if (msg.step) setCurrentStep(msg.step);
      setStatusMsg(msg.message || '');
      if (msg.step) setProgressPct(Math.min((msg.step / 5) * 90 + 5, 95));

      const d = msg.data;
      if (d) {
        setResult((r) => {
          const next: Result = { ...r };
          if (d.title) next.title = d.title;
          if (d.category) next.category = d.category;
          if (d.summary) next.summary = d.summary;
          if (d.content_stream) next.content = d.content_stream;
          if (d.content) next.content = d.content;
          if (d.scenario_header) {
            next.scenario = { title: d.scenario_header.title, description: d.scenario_header.description, content_json: { steps: [] } };
          }
          if (d.scenario) next.scenario = d.scenario;
          return next;
        });

        if (d.quiz_item !== undefined) {
          const item = d.quiz_item;
          const idx = d.quiz_index;
          setQuizzes((prev) => {
            if (idx !== undefined && idx < prev.length) {
              const copy = prev.slice();
              copy[idx] = item;
              return copy;
            }
            return [...prev, item];
          });
        }
        if (d.quizzes) setQuizzes(d.quizzes);

        if (d.scenario_header) setScenarioSteps([]);
        if (d.scenario_step !== undefined) {
          const step = d.scenario_step;
          setScenarioSteps((prev) => [...prev, step]);
          setResult((r) => {
            const steps = [...(r.scenario?.content_json?.steps || []), step];
            const sc: Scenario = r.scenario
              ? { ...r.scenario, content_json: { steps } }
              : { title: '', description: '', content_json: { steps } };
            return { ...r, scenario: sc };
          });
        }
        if (d.scenario) setScenarioSteps(d.scenario.content_json?.steps || []);
      }
    } else if (msg.status === 'done' && msg.data) {
      const d = msg.data;
      setResult({
        title: d.title,
        summary: d.summary,
        content: d.content,
        category: d.category,
        scenario: d.scenario ?? undefined,
      });
      setQuizzes(d.quizzes || (d.quiz ? [d.quiz] : []));
      if (d.scenario) setScenarioSteps(d.scenario.content_json?.steps || []);
      setCurrentStep(5);
      setProgressPct(100);
      setStatusMsg('Hoàn thành!');
      setStage('done');
      setCreating(false);
      stopElapsed();
      stopPing();
      wsRef.current?.close();
    } else if (msg.status === 'error') {
      setErrorMsg(msg.message || '');
      setStatusMsg('');
      setCreating(false);
      stopElapsed();
      stopPing();
      wsRef.current?.close();
    }
  }

  function connectWS(taskId: string) {
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const url = `${proto}://${window.location.host}/ws/task/${taskId}/`;
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      reconnectRef.current = 0;
      startPing();
    };
    ws.onmessage = (e: MessageEvent<string>) => {
      let msg: WsMsg;
      try {
        msg = JSON.parse(e.data) as WsMsg;
      } catch {
        return;
      }
      if (msg.type === 'pong') return;
      handleWSMessage(msg);
    };
    ws.onclose = () => {
      stopPing();
      if (creatingRef.current && stageRef.current === 'streaming' && reconnectRef.current < MAX_RECONNECTS) {
        reconnectRef.current += 1;
        const delay = Math.min(1000 * Math.pow(2, reconnectRef.current - 1), 15000);
        window.setTimeout(() => connectWS(taskId), delay);
      } else if (creatingRef.current) {
        setErrorMsg('Mất kết nối WebSocket. Vui lòng thử lại.');
        setCreating(false);
        stopElapsed();
      }
    };
  }

  async function startCreate() {
    if (!rawText.trim()) return;
    setCreating(true);
    setStage('streaming');
    resetResult();
    setCreating(true);
    startElapsed();
    try {
      const res = await api.post<{ task_id?: string; message?: string }>('/admin/learn/ai-generate/', {
        text: rawText,
        include_quiz: includeQuiz,
        include_scenario: includeScenario,
        quiz_count: quizCount,
        scenario_steps: scenarioStepsCount,
      });
      if (!res.task_id) {
        setErrorMsg(res.message || 'Lỗi server');
        setStage('streaming');
        setCreating(false);
        stopElapsed();
        return;
      }
      connectWS(res.task_id);
    } catch (e) {
      setErrorMsg('Không thể kết nối server: ' + (e instanceof Error ? e.message : String(e)));
      setCreating(false);
      stopElapsed();
    }
  }

  async function saveDraft() {
    setSaving(true);
    try {
      await api.post('/admin/learn/magic-save/', {
        title: result.title,
        summary: result.summary,
        content: result.content,
        category: result.category,
        quizzes,
        scenario: result.scenario,
      });
      await Swal.fire({
        icon: 'success',
        title: 'Đã lưu thành công!',
        html: '<p class="text-white/55 text-sm">Bài học đã được tạo và lưu bản nháp.</p>',
        background: 'var(--sc-night-1)',
        color: 'var(--sc-white)',
        timer: 2000,
        showConfirmButton: false,
        customClass: { popup: 'rounded-[2rem] border border-white/10' },
      });
      router.push('/admin-cp/learn/');
    } catch (e) {
      await Swal.fire({
        icon: 'error',
        title: 'Lỗi lưu',
        text: e instanceof Error ? e.message : 'Không thể lưu',
        background: 'var(--sc-night-1)',
        color: 'var(--sc-white)',
        customClass: { popup: 'rounded-[2rem] border border-white/10' },
      });
    } finally {
      setSaving(false);
    }
  }

  const catClass =
    result.category === 'news' ? 'bg-brand-500/10 text-brand-400 border border-brand-500/10'
    : result.category === 'guide' ? 'bg-safe-500/10 text-safe-400 border border-safe-500/10'
    : result.category === 'alert' ? 'bg-danger-500/10 text-danger-400 border border-danger-500/10'
    : 'bg-brand2-500/10 text-brand2-400 border border-brand2-500/10';
  const catLabel =
    result.category === 'news' ? 'Tin tức'
    : result.category === 'guide' ? 'Hướng dẫn'
    : result.category === 'alert' ? 'Cảnh báo'
    : 'Câu chuyện';

  return (
    <div className="container mx-auto px-4 py-8 mt-16">
      <style>{MAGIC_CSS}</style>

      {/* ═══ Header ═══ */}
      <div className="flex items-center justify-between mb-8">
        <div className="flex items-center gap-4">
          <Link href="/admin-cp/learn/" className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center text-white/55 hover:text-brand2-400 hover:border-brand2-500/30 transition-all">
            <i className="bi bi-chevron-left"></i>
          </Link>
          <div>
            <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-3">
              <span className="w-10 h-10 rounded-xl bg-gradient-to-br from-brand2-600 to-brand-600 flex items-center justify-center text-lg shadow-lg shadow-brand2-500/20"><i className="bi bi-lightning-charge-fill text-white text-base"></i></span>
              Magic Create
            </h1>
            <p className="text-[10px] font-bold text-white/35 uppercase tracking-widest mt-1">AI tạo bài học · quiz/kịch bản tùy chỉnh</p>
          </div>
        </div>
        {/* Timer (visible during streaming) */}
        {stage === 'streaming' && (
          <div className="flex items-center gap-2 px-4 py-2 rounded-xl bg-white/[0.03] border border-white/5">
            <div className="w-2 h-2 rounded-full bg-brand2-500 animate-pulse"></div>
            <span className="text-xs font-bold text-white/55 mc-timer">{elapsedStr}</span>
          </div>
        )}
      </div>

      {/* ═══ INPUT STAGE ═══ */}
      {stage === 'input' && (
        <div className="max-w-3xl mx-auto">
          <div className="liquid-card p-0 border-white/5 bg-slate-900/40 overflow-hidden">
            {/* Top visual */}
            <div className="relative px-8 pt-10 pb-6 text-center overflow-hidden">
              <div className="absolute inset-0 bg-gradient-to-b from-brand2-600/5 to-transparent pointer-events-none"></div>
              <div className="relative">
                <div className="w-20 h-20 rounded-2xl bg-gradient-to-br from-brand2-600/20 to-brand-600/20 border border-brand2-500/15 flex items-center justify-center mx-auto mb-5 shadow-2xl shadow-brand2-500/10">
                  <i className="bi bi-stars text-3xl text-brand2-400"></i>
                </div>
                <h2 className="text-xl font-black text-white mb-2">Biến tin tức thành bài học</h2>
                <p className="text-xs text-white/45 max-w-md mx-auto leading-relaxed">Dán bài báo, tin tức hoặc tài liệu về lừa đảo. AI sẽ tự động phân tích và tạo bài học; bạn có thể bật/tắt quiz và kịch bản bên dưới.</p>
              </div>
            </div>

            {/* Input area */}
            <div className="px-8 pb-8 space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <label className="flex items-center justify-between p-3 rounded-xl bg-white/[0.02] border border-white/5">
                  <div>
                    <p className="text-[11px] font-bold text-white/70 uppercase tracking-wider">Tạo Quiz</p>
                    <p className="text-[10px] text-white/45">Sinh bộ câu hỏi kiểm tra kiến thức</p>
                  </div>
                  <button
                    type="button"
                    onClick={() => setIncludeQuiz((v) => !v)}
                    className={`relative w-11 h-6 rounded-full transition-all ${includeQuiz ? 'bg-brand2-500/70' : 'bg-white/10'}`}
                    aria-pressed={includeQuiz}
                  >
                    <span className={`absolute top-0.5 w-5 h-5 rounded-full bg-white transition-all ${includeQuiz ? 'left-5' : 'left-0.5'}`}></span>
                  </button>
                </label>

                <label className="flex items-center justify-between p-3 rounded-xl bg-white/[0.02] border border-white/5">
                  <div>
                    <p className="text-[11px] font-bold text-white/70 uppercase tracking-wider">Tạo Kịch bản</p>
                    <p className="text-[10px] text-white/45">Sinh hội thoại mô phỏng tình huống</p>
                  </div>
                  <button
                    type="button"
                    onClick={() => setIncludeScenario((v) => !v)}
                    className={`relative w-11 h-6 rounded-full transition-all ${includeScenario ? 'bg-brand-500/70' : 'bg-white/10'}`}
                    aria-pressed={includeScenario}
                  >
                    <span className={`absolute top-0.5 w-5 h-5 rounded-full bg-white transition-all ${includeScenario ? 'left-5' : 'left-0.5'}`}></span>
                  </button>
                </label>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <label className="p-3 rounded-xl bg-white/[0.02] border border-white/5 block">
                  <p className="text-[11px] font-bold text-white/70 uppercase tracking-wider mb-2">Số lượng Quiz</p>
                  <input
                    type="number"
                    min="1"
                    max="20"
                    value={quizCount}
                    onChange={(e) => setQuizCount(Number(e.target.value))}
                    disabled={!includeQuiz}
                    className="w-full bg-black/40 border border-white/10 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-brand2-500/40"
                  />
                </label>
                <label className="p-3 rounded-xl bg-white/[0.02] border border-white/5 block">
                  <p className="text-[11px] font-bold text-white/70 uppercase tracking-wider mb-2">Số bước kịch bản</p>
                  <input
                    type="number"
                    min="4"
                    max="30"
                    value={scenarioStepsCount}
                    onChange={(e) => setScenarioStepsCount(Number(e.target.value))}
                    disabled={!includeScenario}
                    className="w-full bg-black/40 border border-white/10 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-brand-500/40"
                  />
                </label>
              </div>

              <div className="relative">
                <textarea
                  value={rawText}
                  onChange={(e) => setRawText(e.target.value)}
                  className="mc-textarea"
                  rows={10}
                  placeholder={"Dán nội dung tin tức/bài báo về lừa đảo vào đây...\n\nVí dụ: Công an vừa triệt phá đường dây lừa đảo qua mạng với thủ đoạn giả danh nhân viên ngân hàng gọi điện yêu cầu cung cấp OTP..."}
                />
              </div>

              <div className="flex items-center justify-between pt-2">
                <div className="flex items-center gap-3">
                  <span className="text-[10px] text-white/15 font-mono">{rawText.length.toLocaleString()} ký tự</span>
                  {rawText.length > 0 && rawText.length < 100 && (
                    <span className="text-[10px] text-warn-400/60">
                      <i className="bi bi-exclamation-triangle mr-0.5"></i> Nên nhập ít nhất 100 ký tự
                    </span>
                  )}
                </div>
                <button
                  onClick={() => void startCreate()}
                  disabled={!rawText.trim() || rawText.trim().length < 50 || creating}
                  className="mc-glow-btn px-8 py-3 rounded-xl bg-gradient-to-r from-brand2-600 to-brand-600 hover:from-brand2-500 hover:to-brand-500 text-white font-black text-sm uppercase tracking-widest transition-all shadow-lg shadow-brand2-500/20 disabled:opacity-30 disabled:cursor-not-allowed flex items-center gap-2.5"
                >
                  <i className="bi bi-lightning-charge-fill text-base"></i>
                  Magic Create
                </button>
              </div>

              {/* Feature chips */}
              <div className="flex flex-wrap gap-2 pt-2">
                <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/[0.02] border border-white/5 text-[10px] text-white/55">
                  <i className="bi bi-journal-richtext text-brand-500/50"></i> Bài học Markdown
                </span>
                {includeQuiz && (
                  <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/[0.02] border border-white/5 text-[10px] text-white/55">
                    <i className="bi bi-patch-question text-brand2-500/50"></i> <span>{quizCount} câu Quiz</span>
                  </span>
                )}
                {includeScenario && (
                  <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/[0.02] border border-white/5 text-[10px] text-white/55">
                    <i className="bi bi-chat-square-text text-brand-500/50"></i> <span>{'Kịch bản ' + scenarioStepsCount + '+ bước'}</span>
                  </span>
                )}
                <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/[0.02] border border-white/5 text-[10px] text-white/55">
                  <i className="bi bi-bell text-warn-500/50"></i> Push khi xong
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ═══ STREAMING / DONE STAGE ═══ */}
      {(stage === 'streaming' || stage === 'done') && (
        <div>
          {/* Pipeline Stepper */}
          <div className="flex items-center justify-center mb-8">
            <div className="mc-pipeline flex-wrap justify-center gap-y-2">
              {STAGES.map((s, i) => (
                <div key={i} className="flex items-center">
                  <div className="mc-step-item">
                    <div className={`mc-step-icon ${currentStep === i + 1 && stage !== 'done' ? 'active' : ''} ${currentStep > i + 1 || stage === 'done' ? 'done' : ''}`}>
                      {currentStep > i + 1 || stage === 'done' ? (
                        <i className="bi bi-check2 text-sm"></i>
                      ) : currentStep === i + 1 && stage === 'streaming' ? (
                        <Dots />
                      ) : (
                        <i className={`${s.icon} text-xs`}></i>
                      )}
                    </div>
                    <span className={`text-[10px] font-bold uppercase tracking-wider hidden sm:inline ${currentStep >= i + 1 || stage === 'done' ? 'text-white/60' : 'text-white/15'}`}>{s.name}</span>
                  </div>
                  {i < STAGES.length - 1 && (
                    <div className={`mc-step-connector ${currentStep > i + 1 || stage === 'done' ? 'done' : ''} ${currentStep === i + 1 && stage !== 'done' ? 'active' : ''}`}></div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Progress bar */}
          <div className="mb-6">
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-[10px] font-bold text-white/55 uppercase tracking-widest">{statusMsg}</span>
              <span className="text-[10px] font-black text-white/15 mc-timer">{Math.round(progressPct)}%</span>
            </div>
            <div className="w-full bg-white/[0.03] rounded-full h-1 overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-1000 ease-out ${stage === 'done' ? 'bg-gradient-to-r from-safe-500 to-safe-400' : 'bg-gradient-to-r from-brand2-500 via-brand-500 to-brand-400'}`}
                style={{ width: `${progressPct}%` }}
              ></div>
            </div>
          </div>

          {/* Success banner */}
          {stage === 'done' && (
            <div className="mb-6 p-4 rounded-2xl bg-gradient-to-r from-safe-500/5 to-safe-500/5 border border-safe-500/15 flex items-center gap-4">
              <div className="w-12 h-12 rounded-xl bg-safe-500/10 border border-safe-500/20 flex items-center justify-center flex-shrink-0">
                <i className="bi bi-check-circle-fill text-xl text-safe-400"></i>
              </div>
              <div className="flex-1 min-w-0">
                <h3 className="text-sm font-black text-white">Tạo bài học thành công!</h3>
                <p className="text-[11px] text-white/45 mt-0.5">Kiểm tra nội dung bên dưới rồi nhấn <strong className="text-white/60">Lưu bản nháp</strong> để hoàn tất.</p>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                <button
                  onClick={() => void saveDraft()}
                  disabled={saving}
                  className="px-5 py-2.5 rounded-xl bg-safe-600 hover:bg-safe-500 text-white font-black text-xs uppercase tracking-wider transition-all shadow-lg shadow-safe-500/20 flex items-center gap-2 disabled:opacity-50"
                >
                  <i className="bi bi-cloud-arrow-up-fill"></i>
                  <span>{saving ? 'Đang lưu...' : 'Lưu bản nháp'}</span>
                </button>
                <button
                  onClick={() => { setStage('input'); resetResult(); }}
                  className="px-4 py-2.5 rounded-xl bg-white/5 hover:bg-white/10 text-white/55 font-bold text-xs transition-all border border-white/5"
                >
                  <i className="bi bi-arrow-repeat"></i>
                </button>
              </div>
            </div>
          )}

          {/* Error banner */}
          {errorMsg && (
            <div className="mb-6 p-4 rounded-2xl bg-danger-500/5 border border-danger-500/15 flex items-center gap-4">
              <div className="w-10 h-10 rounded-xl bg-danger-500/10 flex items-center justify-center flex-shrink-0">
                <i className="bi bi-exclamation-triangle-fill text-danger-400"></i>
              </div>
              <div className="flex-1">
                <p className="text-xs text-danger-300 font-bold">{errorMsg}</p>
              </div>
              <button onClick={() => { setStage('input'); resetResult(); }} className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-white/55 text-xs font-bold transition-all">Thử lại</button>
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* ─── Main Column ─── */}
            <div className="lg:col-span-8 space-y-6">
              {/* Lesson Content */}
              <div className={`mc-card ${currentStep === 2 && stage !== 'done' ? 'active' : ''} ${currentStep > 2 || stage === 'done' ? 'done' : ''}`}>
                <div className="mc-card-head">
                  <div className="w-7 h-7 rounded-lg bg-brand-500/10 flex items-center justify-center">
                    <i className="bi bi-journal-richtext text-brand-400 text-xs"></i>
                  </div>
                  <span className="text-xs font-black text-white/60 uppercase tracking-widest">Nội dung bài học</span>
                  <div className="ml-auto flex items-center gap-2">
                    {currentStep === 2 && stage !== 'done' && <Dots />}
                    {(currentStep > 2 || stage === 'done') && (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-safe-500/10 text-[9px] font-bold text-safe-400"><i className="bi bi-check2"></i> Xong</span>
                    )}
                  </div>
                </div>
                <div className="mc-card-body">
                  {/* Skeleton */}
                  {!result.title && currentStep <= 2 && stage !== 'done' && (
                    <div className="space-y-3">
                      <div className="mc-skeleton h-6 w-3/4"></div>
                      <div className="mc-skeleton h-3 w-1/4"></div>
                      <div className="mc-skeleton h-3 w-full mt-4"></div>
                      <div className="mc-skeleton h-3 w-5/6"></div>
                      <div className="mc-skeleton h-3 w-4/6"></div>
                      <div className="mc-skeleton h-3 w-full"></div>
                      <div className="mc-skeleton h-3 w-3/4"></div>
                    </div>
                  )}
                  {/* Real content */}
                  {result.title && (
                    <div className="mc-fade">
                      <div className="flex items-start gap-3 mb-4">
                        <div className="flex-1 min-w-0">
                          <h3 className="text-lg font-black text-white leading-tight">{result.title}</h3>
                          {result.summary && (
                            <p className="text-[11px] text-white/45 mt-2 leading-relaxed">{result.summary}</p>
                          )}
                        </div>
                        <span className={`inline-flex px-2.5 py-1 rounded-lg text-[9px] font-black uppercase tracking-wider flex-shrink-0 ${catClass}`}>{catLabel}</span>
                      </div>
                      <div className="mc-content" dangerouslySetInnerHTML={{ __html: sanitizeHtml(result.content || '') }}></div>
                    </div>
                  )}
                </div>
              </div>

              {/* Scenario */}
              <div className={`mc-card ${currentStep === 4 && stage !== 'done' ? 'active' : ''} ${currentStep > 4 || stage === 'done' ? 'done' : ''}`}>
                <div className="mc-card-head">
                  <div className="w-7 h-7 rounded-lg bg-brand-500/10 flex items-center justify-center">
                    <i className="bi bi-chat-square-text text-brand-400 text-xs"></i>
                  </div>
                  <span className="text-xs font-black text-white/60 uppercase tracking-widest">Kịch bản hội thoại</span>
                  <div className="ml-auto flex items-center gap-2">
                    {scenarioSteps.length > 0 && (
                      <span className="text-[9px] text-white/35 font-bold">{scenarioSteps.length} bước</span>
                    )}
                    {currentStep === 4 && stage !== 'done' && <Dots />}
                    {(currentStep > 4 || stage === 'done') && (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-safe-500/10 text-[9px] font-bold text-safe-400"><i className="bi bi-check2"></i> Xong</span>
                    )}
                  </div>
                </div>
                <div className="mc-card-body">
                  {/* Skeleton */}
                  {!result.scenario && currentStep <= 4 && stage !== 'done' && (
                    <div className="space-y-4">
                      {[0, 1, 2].map((i) => (
                        <div key={i} className="flex gap-3">
                          <div className="mc-skeleton w-8 h-8 rounded-lg flex-shrink-0"></div>
                          <div className="flex-1 space-y-2">
                            <div className="mc-skeleton h-2.5 w-20"></div>
                            <div className="mc-skeleton h-3 w-full"></div>
                            <div className="mc-skeleton h-3 w-2/3"></div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                  {/* Real scenario */}
                  {result.scenario && (
                    <div className="mc-fade space-y-1">
                      <div className="mb-4">
                        <h4 className="text-sm font-bold text-white">{result.scenario.title}</h4>
                        <p className="text-[11px] text-white/55 mt-1">{result.scenario.description}</p>
                      </div>
                      {scenarioSteps.map((step, si) => (
                        <div key={si} className="mc-chat-bubble mc-fade" style={{ animationDelay: `${si * 0.05}s` }}>
                          <div className={`mc-chat-avatar ${step.speaker}`}>
                            <i className={step.speaker === 'scammer' ? 'bi bi-person-x-fill text-danger-400' : (step.speaker === 'victim' ? 'bi bi-person-fill text-brand-400' : 'bi bi-book-half text-brand2-400')}></i>
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1">
                              <span className={`text-[9px] font-black uppercase tracking-widest ${step.speaker === 'scammer' ? 'text-danger-400/80' : step.speaker === 'victim' ? 'text-brand-400/80' : 'text-brand2-400/80'}`}>
                                {step.speaker === 'scammer' ? 'Kẻ lừa đảo' : step.speaker === 'victim' ? 'Nạn nhân' : 'Tường thuật'}
                              </span>
                              <span className="text-[8px] text-white/20 font-mono">{'#' + (si + 1)}</span>
                            </div>
                            <p className="text-xs text-white/65 leading-relaxed">{step.text}</p>
                            {step.note && (
                              <p className="text-[10px] text-brand2-400/40 italic mt-1.5 flex items-start gap-1">
                                <i className="bi bi-lightbulb text-brand2-400/30 flex-shrink-0 mt-px"></i>
                                <span>{step.note}</span>
                              </p>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* ─── Sidebar ─── */}
            <div className="lg:col-span-4 space-y-6">
              {/* Quizzes */}
              <div className={`mc-card ${currentStep === 3 && stage !== 'done' ? 'active' : ''} ${currentStep > 3 || stage === 'done' ? 'done' : ''}`}>
                <div className="mc-card-head">
                  <div className="w-7 h-7 rounded-lg bg-brand2-500/10 flex items-center justify-center">
                    <i className="bi bi-patch-question text-brand2-400 text-xs"></i>
                  </div>
                  <span className="text-xs font-black text-white/60 uppercase tracking-widest">Quiz</span>
                  <div className="ml-auto flex items-center gap-2">
                    {quizzes.length > 0 && (
                      <span className="text-[9px] text-white/35 font-bold">{quizzes.length} câu</span>
                    )}
                    {currentStep === 3 && stage !== 'done' && <Dots />}
                    {(currentStep > 3 || stage === 'done') && (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-safe-500/10 text-[9px] font-bold text-safe-400"><i className="bi bi-check2"></i> Xong</span>
                    )}
                  </div>
                </div>
                <div className="mc-card-body space-y-3">
                  {/* Skeleton */}
                  {quizzes.length === 0 && currentStep <= 3 && stage !== 'done' && (
                    <div className="space-y-3">
                      {[0, 1, 2].map((i) => (
                        <div key={i} className="p-3 rounded-lg bg-white/[0.02] space-y-2">
                          <div className="mc-skeleton h-3 w-full"></div>
                          <div className="mc-skeleton h-3 w-4/5"></div>
                          <div className="space-y-1 mt-2">
                            <div className="mc-skeleton h-2.5 w-3/4"></div>
                            <div className="mc-skeleton h-2.5 w-2/3"></div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                  {/* Real quizzes */}
                  {quizzes.map((q, qi) => (
                    <div key={qi} className="mc-quiz mc-fade" style={{ animationDelay: `${qi * 0.08}s` }}>
                      <div className="flex items-start gap-2.5 mb-2.5">
                        <span className="w-6 h-6 rounded-lg bg-gradient-to-br from-brand2-500/20 to-brand-500/20 text-brand2-300 text-[10px] font-black flex items-center justify-center flex-shrink-0">{qi + 1}</span>
                        <p className="text-xs text-white/80 font-bold leading-relaxed">{q.question}</p>
                      </div>
                      <div className="space-y-1 ml-8">
                        {q.options.map((opt, oi) => {
                          const correct = opt === q.correct_answer;
                          return (
                            <div key={oi} className={`text-[10px] px-2.5 py-1.5 rounded-lg flex items-center gap-1.5 transition-all ${correct ? 'bg-safe-500/10 text-safe-400 border border-safe-500/15' : 'bg-white/[0.02] text-white/35 border border-white/[0.03]'}`}>
                              <span className={`w-4 h-4 rounded-md flex items-center justify-center flex-shrink-0 text-[8px] font-black ${correct ? 'bg-safe-500/20 text-safe-300' : 'bg-white/5 text-white/35'}`}>{String.fromCharCode(65 + oi)}</span>
                              <span className="flex-1">{opt}</span>
                              {correct && <i className="bi bi-check-circle-fill text-safe-400 text-[10px]"></i>}
                            </div>
                          );
                        })}
                      </div>
                      {q.explanation && (
                        <div className="mt-2.5 ml-8 p-2 rounded-lg bg-warn-500/[0.03] border border-warn-500/10">
                          <p className="text-[10px] text-warn-300/50 leading-relaxed flex items-start gap-1.5">
                            <i className="bi bi-lightbulb-fill text-warn-400/40 flex-shrink-0 mt-px"></i>
                            <span>{q.explanation}</span>
                          </p>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Summary stats (done) */}
              {stage === 'done' && (
                <div className="mc-card">
                  <div className="mc-card-body">
                    <div className="grid grid-cols-3 gap-3">
                      <div className="text-center p-3 rounded-xl bg-brand-500/5 border border-brand-500/10">
                        <div className="text-lg font-black text-brand-400">1</div>
                        <div className="text-[9px] text-white/35 font-bold uppercase mt-0.5">Bài học</div>
                      </div>
                      <div className="text-center p-3 rounded-xl bg-brand2-500/5 border border-brand2-500/10">
                        <div className="text-lg font-black text-brand2-400">{quizzes.length}</div>
                        <div className="text-[9px] text-white/35 font-bold uppercase mt-0.5">Quiz</div>
                      </div>
                      <div className="text-center p-3 rounded-xl bg-brand-500/5 border border-brand-500/10">
                        <div className="text-lg font-black text-brand-400">{scenarioSteps.length}</div>
                        <div className="text-[9px] text-white/35 font-bold uppercase mt-0.5">Bước</div>
                      </div>
                    </div>
                    <div className="mt-3 text-center text-[10px] text-white/15">
                      <i className="bi bi-clock mr-1"></i> Hoàn thành trong <span className="text-white/45 font-bold">{elapsedStr}</span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
