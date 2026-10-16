'use client';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Link from 'next/link';
import { api } from '../../lib/api';
import { useTaskSocket } from '../../lib/useTaskSocket';
import type { TaskSocketMessage } from '../../lib/useTaskSocket';
import { SITE_URL } from '../../lib/site-config';

/* Port từ PKV/templates/AI/scam_iq_exam.html (Alpine x-data="scamIQExam()").
 * Giữ nguyên endpoint hiện có:
 *   POST /scam-iq/start/            -> { task_id }
 *   GET  /scam-iq/status/<task_id>/ -> { ready, exam_id, questions, total_questions, message, ... }
 *   POST /scam-iq/submit/           -> ExamResult (kèm ai_task_id khi có câu tự luận)
 *   GET  /scam-iq/history/?limit=10 -> { results }
 * Tiến trình khởi tạo (task_id) + AI chấm điểm (ai_task_id) ưu tiên cập nhật qua
 * WebSocket /ws/task/<id>/ như bản gốc; REST polling status vẫn giữ làm fallback.
 */

interface Opt { id: string; text: string }
interface Sim {
  channel?: string;
  from?: string;
  sender_name?: string;
  time?: string;
  subject?: string;
  preview?: string;
  body?: string;
  trap_signals?: string[];
  risk_clues?: string[];
  expected_keywords?: string[];
}
interface Q {
  id: string;
  question: string;
  type: string;
  difficulty?: string;
  difficulty_label?: string;
  category?: string;
  options?: Opt[];
  simulation?: Sim;
  explanation?: string;
  correct_option_ids?: string[];
}
interface Answer { selected_ids: string[]; free_text: string }
interface HistoryRow {
  id: number;
  created_at: string;
  score: number;
  max_score: number;
  correct_count: number;
  level_label?: string;
}
interface Band {
  key: string;
  label: string;
  textColor: string;
  barColor: string;
  ratio: string;
  pct: number;
  status: string;
}
interface LevelBand { code: string; label: string; min: number; max: number; description: string }
interface ReviewQ {
  id: string;
  index: number;
  question: string;
  difficulty?: string;
  difficulty_label?: string;
  type: string;
  category?: string;
  options: Opt[];
  expected: string[];
  selected: string[];
  explanation: string;
  isSim: boolean;
  isMistake: boolean;
  userAnswerText: string;
  aiFeedback: { ai_score?: number; ai_comment?: string } | null;
}
interface ExamResult {
  score: number;
  max_score: number;
  correct_count: number;
  level: { code?: string; label: string; description?: string };
  level_bands?: LevelBand[];
  mistakes?: Array<{ question_id: string; expected: string[]; explanation?: string }>;
  ai_feedback?: Array<{ question_id: string; ai_score?: number; ai_comment?: string }>;
  difficulty_breakdown?: Record<string, { total: number; correct: number }>;
  ai_task_id?: string;
  attempt_id?: number;
}

const SIM_TYPES = ['simulation_sms', 'simulation_email', 'incident_response'];

const SCAM_IQ_CSS = `
.scam-iq-shimmer {
    animation: scam-iq-shimmer 1.8s linear infinite;
    will-change: transform;
}
@keyframes scam-iq-shimmer {
    0% { transform: translateX(-130%); }
    100% { transform: translateX(330%); }
}
.scam-iq-wrap {
    white-space: pre-wrap;
    word-break: normal;
    overflow-wrap: break-word;
}
.custom-scrollbar::-webkit-scrollbar { width: 6px; height: 6px; }
.custom-scrollbar::-webkit-scrollbar-track { background: rgba(255, 255, 255, 0.02); border-radius: 999px; }
.custom-scrollbar::-webkit-scrollbar-thumb { background: rgba(34, 211, 238, 0.25); border-radius: 999px; }
.custom-scrollbar::-webkit-scrollbar-thumb:hover { background: rgba(34, 211, 238, 0.5); }
`;

function cleanQ(q: unknown): string {
  return String(q || '').replace(/^\[[^\]]{1,140}\]\s*/, '').trim();
}

function typeLabel(t: string): string {
  if (t === 'multi_select') return 'Nhiều đáp án';
  if (t === 'true_false') return 'Đúng / Sai';
  if (t === 'simulation_sms') return 'Mô phỏng SMS';
  if (t === 'simulation_email') return 'Mô phỏng Email';
  if (t === 'incident_response') return 'Phản ứng sự cố';
  return 'Một đáp án';
}

function isSimulationType(t: string): boolean {
  return SIM_TYPES.includes(t);
}

/* ------------------------------------------------------------------ */
/* Simulation helpers — port 1-1 từ Alpine scamIQExam().               */
/* ------------------------------------------------------------------ */

function deriveSimulationFromQuestion(question: Q | null): Sim {
  const sim: Sim = { ...(question?.simulation || {}) };
  const qType = String(question?.type || '').toLowerCase();
  const qText = cleanQ(question?.question || '');

  const quotedChunks = Array.from(qText.matchAll(/["“](.{12,}?)["”]/g)).map((m) => String(m[1] || '').trim());
  const smsInline = (qText.match(/SMS\s*:\s*["“]([\s\S]{8,}?)["”]/i) || [])[1] || '';
  const emailInline = (qText.match(/Email\s*:\s*["“]([\s\S]{8,}?)["”]/i) || [])[1] || '';

  if (qType === 'simulation_sms') {
    if (String(smsInline || '').trim()) {
      sim.body = String(smsInline).trim();
      const phoneFromInline = (String(sim.body).match(/(?:\+?84|0)\d[\d\s\-.]{7,14}\d/) || [])[0];
      sim.from = String(phoneFromInline || 'Unknown sender').trim();
      sim.sender_name = 'Tin nhắn mới';
      sim.time = '--:--';
    } else if (!String(sim.body || '').trim()) {
      sim.body = String(quotedChunks[0] || qText).trim();
    }
    if (!String(sim.sender_name || '').trim()) sim.sender_name = 'Tin nhắn mới';
    if (!String(sim.time || '').trim()) sim.time = '--:--';
    if (!String(sim.from || '').trim()) {
      const phone = (String(sim.body || '').match(/(?:\+?84|0)\d[\d\s\-.]{7,14}\d/) || [])[0];
      sim.from = phone || 'Unknown sender';
    }
  }

  if (qType === 'simulation_email') {
    const fromMatch = qText.match(/email\s+từ\s*["“]([^"”]+)["”]/i);
    const subjectMatch = qText.match(/tiêu đề\s*["“]([^"”]+)["”]/i);

    if (String(emailInline || '').trim()) {
      sim.body = String(emailInline).trim();
      sim.from = String(fromMatch?.[1] || '').trim() || 'security-alert@unknown-domain';
      sim.subject = String(subjectMatch?.[1] || '').trim() || 'Security Alert';
      sim.preview = String(sim.body || '').trim().slice(0, 180) || 'Không có preview';
    } else {
      if (!String(sim.from || '').trim()) {
        sim.from = String(fromMatch?.[1] || '').trim() || 'security-alert@unknown-domain';
      }
      if (!String(sim.subject || '').trim()) {
        sim.subject = String(subjectMatch?.[1] || '').trim() || 'Security Alert';
      }
      if (!String(sim.body || '').trim()) {
        sim.body = String(quotedChunks[0] || qText).trim();
      }
      if (!String(sim.preview || '').trim()) {
        sim.preview = String(sim.body || '').trim().slice(0, 180) || 'Không có preview';
      }
    }
  }

  return sim;
}

type SimFieldKey = 'sender_name' | 'time' | 'from' | 'subject' | 'preview' | 'body';

function simField(question: Q | null, key: SimFieldKey, fallback = '-'): string {
  const derived = deriveSimulationFromQuestion(question);
  const value = derived[key];
  const normalized = String(value || '').trim();
  return normalized || fallback;
}

function simBodyText(question: Q | null): string {
  const derived = deriveSimulationFromQuestion(question);
  const body = String(derived.body || '').trim();
  return (
    body ||
    'Nội dung tình huống mô phỏng đang được chuẩn hóa. Hãy tập trung vào quy trình xác minh trước khi thao tác.'
  );
}

export default function ScamIQ() {
  const [stage, setStage] = useState<'idle' | 'loading' | 'ready' | 'result'>('idle');
  const [loading, setLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [questions, setQuestions] = useState<Q[]>([]);
  const [index, setIndex] = useState(0);
  const [answers, setAnswers] = useState<Record<string, Answer>>({});
  const [result, setResult] = useState<ExamResult | null>(null);
  const [history, setHistory] = useState<HistoryRow[]>([]);
  const [progress, setProgress] = useState({ created: 0, total: 30, msg: 'Đang chuẩn bị...', phase: 'Khởi tạo' });
  const [elapsed, setElapsed] = useState(0);
  const [reviewFilter, setReviewFilter] = useState<'all' | 'mistakes' | 'simulations'>('all');
  const [toast, setToast] = useState('');
  const [aiScoring, setAiScoring] = useState(false);
  const [aiMsg, setAiMsg] = useState('');
  const [taskId, setTaskId] = useState<string | null>(null);
  const [aiTaskId, setAiTaskId] = useState<string | null>(null);
  /* exam_id backend cấp khi đề sẵn sàng — phải giữ riêng vì mảng questions
   * không chứa nó. Trước đây submit đọc exam_id từ questions (luôn undefined)
   * nên mọi lượt nộp bài đều 400 "Thiếu exam_id". */
  const [examId, setExamId] = useState<string | null>(null);
  const timer = useRef<number | null>(null);
  const cancelled = useRef(false);
  const toastTimeout = useRef<number | null>(null);
  const taskIdRef = useRef<string | null>(null);
  const taskFinishedRef = useRef(false);
  const aiFinishedRef = useRef(false);
  const aiWsActiveRef = useRef(false);

  const current = questions[index] || null;
  const timerText = `${String(Math.floor(elapsed / 60)).padStart(2, '0')}:${String(elapsed % 60).padStart(2, '0')}`;

  const startTimer = () => {
    setElapsed(0);
    if (timer.current) window.clearInterval(timer.current);
    timer.current = window.setInterval(() => setElapsed((e) => e + 1), 1000);
  };
  const stopTimer = () => {
    if (timer.current) {
      window.clearInterval(timer.current);
      timer.current = null;
    }
  };
  useEffect(() => () => stopTimer(), []);
  useEffect(() => () => {
    cancelled.current = true;
  }, []);

  const showMessage = useCallback((msg: string) => {
    setToast(msg);
    if (toastTimeout.current) window.clearTimeout(toastTimeout.current);
    toastTimeout.current = window.setTimeout(() => setToast(''), 3000);
  }, []);

  const loadHistory = useCallback(async () => {
    try {
      const d = await api.get<{ results?: HistoryRow[] } | HistoryRow[]>('/scam-iq/history/?limit=10');
      setHistory(Array.isArray(d) ? d : d.results || []);
    } catch {
      /* ignore — giữ lịch sử hiện có y bản gốc */
    }
  }, []);
  useEffect(() => {
    void loadHistory();
  }, [loadHistory]);

  const isAnswered = (q: Q): boolean => {
    const a = answers[q.id];
    if (!a) return false;
    return a.selected_ids.length > 0 || !!a.free_text.trim();
  };
  const answeredCount =
    Object.values(answers).filter((a) => a.selected_ids.length > 0 || !!a.free_text.trim()).length;

  const freeTextValue = (qid: string): string => answers[qid]?.free_text || '';
  const selectedCount = (qid: string): number => (answers[qid]?.selected_ids || []).length;
  const isChecked = (oid: string): boolean => (answers[current?.id || '']?.selected_ids || []).includes(oid);

  const jumpTo = (i: number) => {
    if (i >= 0 && i < questions.length) setIndex(i);
  };
  const prevQuestion = () => {
    if (index > 0) setIndex(index - 1);
  };
  const nextQuestion = () => {
    if (index < questions.length - 1) setIndex(index + 1);
  };

  /* ---------------- WebSocket tiến trình (ưu tiên) + polling (fallback) ---------------- */

  const applyExamStatus = (s: Record<string, unknown>): void => {
    if (typeof s.total_questions === 'number') setProgress((p) => ({ ...p, total: s.total_questions as number }));
    if (typeof s.created_questions === 'number') setProgress((p) => ({ ...p, created: s.created_questions as number }));
    const prog = (s.progress ?? s.data ?? {}) as Record<string, unknown>;
    if (typeof prog.phase_label === 'string') setProgress((p) => ({ ...p, phase: prog.phase_label as string }));
    if (typeof s.message === 'string') setProgress((p) => ({ ...p, msg: s.message as string }));
  };

  const finalizeExam = (s: Record<string, unknown>): void => {
    if (taskFinishedRef.current) return;
    taskFinishedRef.current = true;
    const qs = (s.questions as Q[]) || [];
    const eid = typeof s.exam_id === 'string' && s.exam_id ? s.exam_id : null;
    setQuestions(qs);
    setExamId(eid);
    setStage('ready');
    setIndex(0);
    setProgress((p) => ({ ...p, created: qs.length || 30, msg: 'Bộ câu hỏi đã sẵn sàng.', phase: 'Hoàn tất' }));
    setTaskId(null);
    startTimer();
    if (!eid) {
      setError('Đề thi thiếu mã định danh. Vui lòng tạo đề mới.');
      setStage('idle');
    }
  };

  const failExam = (message: string): void => {
    if (taskFinishedRef.current) return;
    taskFinishedRef.current = true;
    setError(message);
    setStage('idle');
    setTaskId(null);
  };

  const fetchExamStatus = async (): Promise<void> => {
    const tid = taskIdRef.current;
    if (taskFinishedRef.current || !tid) return;
    try {
      const s = await api.get<Record<string, unknown>>(`/scam-iq/status/${tid}/`);
      if (taskFinishedRef.current) return;
      applyExamStatus(s);
      if (s.ready) {
        finalizeExam(s);
      } else if (s.status === 'FAILURE') {
        failExam(typeof s.error === 'string' ? s.error : 'Không thể tạo bài kiểm tra lúc này. Vui lòng thử lại sau.');
      }
    } catch {
      /* WS lỗi/không kết nối được -> vòng lặp polling bên dưới vẫn tiếp tục */
    }
  };

  const handleTaskSocketMessage = (msg: TaskSocketMessage): void => {
    if (msg.type && msg.type !== 'task_progress') return;
    const data = (msg.data ?? {}) as Record<string, unknown>;
    if (msg.status === 'done') {
      void fetchExamStatus();
      return;
    }
    if (msg.status === 'failed' || msg.status === 'error') {
      failExam(typeof msg.message === 'string' && msg.message ? msg.message : 'Khởi tạo bài kiểm tra thất bại.');
      return;
    }
    if (typeof data.total_questions === 'number') setProgress((p) => ({ ...p, total: data.total_questions as number }));
    if (typeof data.created_questions === 'number') setProgress((p) => ({ ...p, created: data.created_questions as number }));
    if (typeof data.phase_label === 'string') setProgress((p) => ({ ...p, phase: data.phase_label as string }));
    if (typeof msg.message === 'string' && msg.message) setProgress((p) => ({ ...p, msg: msg.message as string }));
  };

  const applyAiDone = (data: Record<string, unknown>, message?: string): void => {
    if (aiFinishedRef.current) return;
    aiFinishedRef.current = true;
    setResult((prev) =>
      prev
        ? {
            ...prev,
            score: typeof data.score === 'number' ? data.score : prev.score,
            correct_count: typeof data.correct_count === 'number' ? data.correct_count : prev.correct_count,
            ai_feedback: (data.feedback as ExamResult['ai_feedback']) ?? prev.ai_feedback,
            level: (data.level as ExamResult['level']) ?? prev.level,
          }
        : prev,
    );
    setAiMsg(message && message.trim() ? message : 'Hoàn tất chấm điểm AI!');
    setAiScoring(false);
    setAiTaskId(null);
  };

  const applyAiFailed = (message?: string): void => {
    if (aiFinishedRef.current) return;
    aiFinishedRef.current = true;
    setAiMsg(message && message.trim() ? message : 'Lỗi khi chấm điểm AI.');
    setAiScoring(false);
    setAiTaskId(null);
  };

  const handleAiSocketMessage = (msg: TaskSocketMessage): void => {
    if (msg.type && msg.type !== 'task_progress') return;
    const data = (msg.data ?? {}) as Record<string, unknown>;
    if (msg.status === 'processing') {
      if (typeof msg.message === 'string' && msg.message) setAiMsg(msg.message);
    } else if (msg.status === 'done') {
      applyAiDone(data, typeof msg.message === 'string' ? msg.message : undefined);
    } else if (msg.status === 'failed') {
      applyAiFailed(typeof msg.message === 'string' ? msg.message : undefined);
    }
  };

  useTaskSocket(stage === 'loading' ? taskId : null, { onMessage: handleTaskSocketMessage });
  useTaskSocket(stage === 'result' && aiScoring ? aiTaskId : null, {
    onMessage: handleAiSocketMessage,
    onOpen: () => {
      aiWsActiveRef.current = true;
    },
    onUnavailable: () => {
      /* WS không nối được: vòng poll /scam-iq/attempt/ vẫn lấy được điểm AI
       * nên chỉ đánh dấu để vòng lặp không kết luận "treo" sớm. */
      aiWsActiveRef.current = false;
    },
  });

  const startExam = async () => {
    setError('');
    setLoading(true);
    setStage('loading');
    setResult(null);
    setAnswers({});
    setQuestions([]);
    setExamId(null);
    setIndex(0);
    setProgress({ created: 0, total: 30, msg: 'Đang khởi tạo pipeline đề thi...', phase: 'Khởi tạo' });
    stopTimer();
    taskFinishedRef.current = false;
    taskIdRef.current = null;
    try {
      const d = await api.post<{ task_id: string }>('/scam-iq/start/', {});
      taskIdRef.current = d.task_id;
      setTaskId(d.task_id);
      // WS cập nhật tiến trình & có thể gọi status ngay khi done; vòng lặp này là fallback.
      for (let i = 0; i < 80; i++) {
        if (cancelled.current || taskFinishedRef.current) return;
        const s = await api.get<Record<string, unknown>>(`/scam-iq/status/${d.task_id}/`);
        if (taskFinishedRef.current) return;
        applyExamStatus(s);
        if (s.ready) {
          finalizeExam(s);
          return;
        }
        if (s.status === 'FAILURE') {
          throw new Error(typeof s.error === 'string' ? s.error : 'Không thể tạo bài kiểm tra lúc này. Vui lòng thử lại sau.');
        }
        await new Promise((r) => setTimeout(r, 1500));
      }
      throw new Error('Hệ thống đang chuẩn bị đề thi kỹ lưỡng hơn thường lệ. Vui lòng bấm thử lại.');
    } catch (e) {
      taskIdRef.current = null;
      setTaskId(null);
      setError(e instanceof Error ? e.message : 'Khởi tạo bài kiểm tra thất bại.');
      setStage('idle');
    } finally {
      setLoading(false);
    }
  };

  const submitExam = async () => {
    setError('');
    if (!examId) {
      setError('Không tìm thấy mã đề thi. Vui lòng tạo đề mới rồi nộp lại.');
      return;
    }
    setSubmitting(true);
    stopTimer();
    try {
      const payload: Record<string, Answer> = {};
      questions.forEach((q) => {
        if (answers[q.id]) payload[q.id] = answers[q.id];
      });
      const d = await api.post<ExamResult>('/scam-iq/submit/', { exam_id: examId, answers: payload });
      setResult(d);
      setStage('result');
      setReviewFilter('all');
      if (d.ai_task_id && d.attempt_id) {
        aiFinishedRef.current = false;
        aiWsActiveRef.current = false;
        setAiTaskId(d.ai_task_id);
        setAiScoring(true);
        setAiMsg('Đang kết nối AI giám khảo...');
        /* WS là kênh chính; poll GET /scam-iq/attempt/<id>/ làm fallback.
         * Trước đây fallback poll /scam-iq/status/<ai_task_id>/ — endpoint đó
         * chỉ hiểu task tạo đề nên luôn 500, khiến AI chấm xong mà UI treo mãi. */
        for (let i = 0; i < 90; i++) {
          await new Promise((r) => setTimeout(r, 2000));
          if (aiFinishedRef.current) break;
          try {
            const a = await api.get<{
              is_ai_scored?: boolean; score?: number; correct_count?: number;
              level?: ExamResult['level']; ai_feedback?: ExamResult['ai_feedback'];
            }>(`/scam-iq/attempt/${d.attempt_id}/`);
            if (aiFinishedRef.current) break;
            if (a.is_ai_scored) {
              applyAiDone(
                {
                  score: a.score, correct_count: a.correct_count,
                  level: a.level, feedback: a.ai_feedback,
                },
                'Hoàn tất chấm điểm AI!',
              );
              break;
            }
            if (i === 0) setAiMsg('AI giám khảo đang chấm các câu tự luận...');
          } catch {
            /* mất mạng thoáng qua — thử lại ở vòng sau */
          }
        }
        if (!aiFinishedRef.current) {
          /* Hết 3 phút vẫn chưa có điểm AI: giữ điểm chấm tự động, báo rõ. */
          applyAiFailed('AI chấm điểm quá lâu. Điểm hiện tại là kết quả chấm tự động — đáp án tự luận sẽ được cập nhật sau.');
        }
      }
      void loadHistory();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Nộp bài thất bại.');
    } finally {
      setSubmitting(false);
    }
  };

  const resetExam = () => {
    stopTimer();
    taskFinishedRef.current = true;
    aiFinishedRef.current = true;
    aiWsActiveRef.current = false;
    taskIdRef.current = null;
    setTaskId(null);
    setAiTaskId(null);
    setStage('idle');
    setQuestions([]);
    setExamId(null);
    setIndex(0);
    setAnswers({});
    setResult(null);
    setError('');
    setAiMsg('');
    setAiScoring(false);
    setReviewFilter('all');
  };

  const percentile = !result
    ? ''
    : result.score >= 270
      ? 'Top 5% người dùng có năng lực tự vệ số cao nhất'
      : result.score >= 210
        ? 'Top 20% người dùng có kiến thức an ninh mạng tốt'
        : result.score >= 150
          ? 'Top 45% người dùng mức độ cảnh giác trung bình'
          : 'Cần trang bị thêm kiến thức phòng chống lừa đảo trực tuyến';

  const bands: Band[] = useMemo(() => {
    const bd = result?.difficulty_breakdown || {};
    return [
      { key: 'easy', label: 'Căn bản (Easy)', textColor: 'text-safe-400', barColor: 'bg-safe-400' },
      { key: 'medium', label: 'Trung bình (Medium)', textColor: 'text-brand-400', barColor: 'bg-brand-400' },
      { key: 'hard', label: 'Nâng cao (Hard)', textColor: 'text-warn-400', barColor: 'bg-warn-400' },
      { key: 'extreme', label: 'Cực khó (Extreme)', textColor: 'text-brand2-400', barColor: 'bg-brand2-400' },
    ].map((c) => {
      const t = bd[c.key] || { total: 0, correct: 0 };
      const pct = t.total > 0 ? Math.round((t.correct / t.total) * 100) : 0;
      return {
        ...c,
        ratio: `${t.correct}/${t.total}`,
        pct,
        status: pct >= 85 ? 'Thành thạo' : pct >= 60 ? 'Khá vững' : 'Cần luyện thêm',
      };
    });
  }, [result]);

  const review: ReviewQ[] = useMemo(() => {
    if (!result) return [];
    const mMap: Record<string, { expected: string[]; explanation?: string }> = {};
    (result.mistakes || []).forEach((m) => {
      mMap[m.question_id] = m;
    });
    const aiMap: Record<string, { ai_score?: number; ai_comment?: string }> = {};
    (result.ai_feedback || []).forEach((f) => {
      aiMap[f.question_id] = f;
    });
    const list = questions.map((q, idx) => {
      const isSim = isSimulationType(q.type);
      const m = mMap[q.id];
      const a = answers[q.id] || { selected_ids: [], free_text: '' };
      return {
        id: q.id,
        index: idx,
        question: q.question,
        difficulty: q.difficulty,
        difficulty_label: q.difficulty_label,
        type: q.type,
        category: q.category,
        options: q.options || [],
        expected: m ? m.expected : q.correct_option_ids || [],
        selected: a.selected_ids,
        explanation: q.explanation || (m ? m.explanation || '' : ''),
        isSim,
        isMistake: !!m,
        userAnswerText: a.free_text,
        aiFeedback: aiMap[q.id] || null,
      };
    });
    if (reviewFilter === 'mistakes') return list.filter((q) => q.isMistake);
    if (reviewFilter === 'simulations') return list.filter((q) => q.isSim);
    return list;
  }, [result, questions, answers, reviewFilter]);

  const copySummary = () => {
    if (!result) return;
    const score = result.score;
    const maxScore = result.max_score || 300;
    const level = result.level?.label || 'Scam IQ';
    const siteOrigin = typeof window !== 'undefined' ? window.location.origin : SITE_URL;
    const text =
      `[ShieldCall VN] Tôi vừa hoàn tất bài kiểm tra Scam IQ:\n` +
      `• Xếp hạng: ${level}\n` +
      `• Điểm số: ${score}/${maxScore} (${Math.round((score / maxScore) * 100)}%)\n` +
      `• Thời gian hoàn thành: ${timerText}\n` +
      `Kiểm tra chỉ số đề kháng lừa đảo số của bạn tại: ${siteOrigin}/scam-iq-exam/`;
    navigator.clipboard
      ?.writeText(text)
      .then(() => showMessage('Đã sao chép kết quả thi vào bộ nhớ tạm!'))
      .catch(() => {});
  };

  const setSingle = (qid: string, oid: string) =>
    setAnswers((a) => ({ ...a, [qid]: { selected_ids: [oid], free_text: a[qid]?.free_text || '' } }));
  const toggle = (qid: string, oid: string) =>
    setAnswers((a) => {
      const cur = new Set(a[qid]?.selected_ids || []);
      if (cur.has(oid)) cur.delete(oid);
      else cur.add(oid);
      return { ...a, [qid]: { selected_ids: Array.from(cur), free_text: a[qid]?.free_text || '' } };
    });
  const setFree = (qid: string, v: string) =>
    setAnswers((a) => ({ ...a, [qid]: { selected_ids: a[qid]?.selected_ids || [], free_text: v } }));

  const filterActiveCls = (k: 'all' | 'mistakes' | 'simulations'): string =>
    k === 'mistakes' ? 'bg-danger-500 text-white font-black' : k === 'simulations' ? 'bg-brand2-500 text-white font-black' : 'bg-brand-500 text-black font-black';

  return (
    <section className="max-w-7xl mx-auto px-4 pt-16 sm:pt-20 pb-20 space-y-6">
      <style dangerouslySetInnerHTML={{ __html: SCAM_IQ_CSS }} />
      {/* Top Welcome Card */}
      <div className="liquid-card p-6 sm:p-8 border-brand-500/20">
        <p className="text-[10px] font-black text-brand-300 uppercase tracking-[0.28em]">Scam IQ Exam</p>
        <h1 className="text-2xl sm:text-3xl font-black text-white mt-2 leading-tight">
          Bài kiểm tra về những hình thức lừa đảo mới nhất hiện nay
        </h1>
        <p className="text-sm text-white/55 mt-3 max-w-3xl leading-relaxed">
          Bộ đề gồm 30 câu từ dễ đến cực khó, bao gồm mô phỏng tin nhắn SMS mạo danh, email phishing và tình huống
          phản ứng sự cố an ninh khẩn cấp. Mỗi câu tối đa 10 điểm, tổng điểm tối đa 300.
        </p>

        {stage === 'idle' && (
          <div className="mt-6 flex flex-wrap items-center gap-3">
            <button
              onClick={() => void startExam()}
              disabled={loading}
              className="liquid-btn py-3 px-6 bg-brand-500 text-black font-black hover:bg-brand-400 disabled:opacity-50 transition-all"
            >
              <i className="bi bi-lightning-charge-fill mr-2"></i> Khởi tạo câu hỏi
            </button>
            <Link href="/home/" className="liquid-btn py-3 px-6 bg-white/5 text-white font-black hover:bg-white/10 transition-all">
              Về trang chủ
            </Link>
          </div>
        )}

        {/* History Section in Idle */}
        {stage === 'idle' && (
          <div className="mt-6 rounded-2xl border border-white/10 bg-white/[0.02] p-4">
            <div className="flex items-center justify-between gap-2">
              <p className="text-xs font-black text-white/80 uppercase tracking-widest">Lịch sử làm bài gần đây</p>
              <button
                onClick={() => void loadHistory()}
                className="text-[11px] text-brand-300 hover:text-brand-200 font-bold"
              >
                Làm mới
              </button>
            </div>
            {history.length > 0 ? (
              <div className="mt-3 overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-[10px] uppercase tracking-widest text-white/55">
                      <th className="py-2 pr-3">Thời gian</th>
                      <th className="py-2 pr-3">Điểm</th>
                      <th className="py-2 pr-3">Đúng/Sai</th>
                      <th className="py-2 pr-3">Xếp hạng</th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.map((h) => (
                      <tr key={h.id} className="border-t border-white/5">
                        <td className="py-2 pr-3 text-white/70">{formatTime(h.created_at)}</td>
                        <td className="py-2 pr-3 text-brand-300 font-bold">
                          {h.score}/{h.max_score}
                        </td>
                        <td className="py-2 pr-3 text-white/70">{h.correct_count}/30 đúng</td>
                        <td className="py-2 pr-3 text-brand2-300">{h.level_label || '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="text-[12px] text-white/45 mt-3">
                Bạn chưa có lượt làm bài nào. Hoàn thành 1 bài để lịch sử hiển thị tại đây.
              </p>
            )}
          </div>
        )}

        {/* Loading Progress */}
        {stage === 'loading' && (
          <div className="mt-5 rounded-2xl border border-brand-500/20 bg-brand-500/5 p-5 overflow-hidden relative">
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(34,211,238,0.12),transparent_45%)] pointer-events-none"></div>
            <div className="relative z-10 flex items-start gap-4">
              <div className="w-12 h-12 rounded-2xl border border-brand-400/40 bg-brand-500/10 flex items-center justify-center shrink-0">
                <i className="bi bi-arrow-repeat text-brand-300 text-lg animate-spin"></i>
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <p className="text-sm font-bold text-brand-300">AI đang tổng hợp bộ câu hỏi mới...</p>
                  <span className="px-2 py-0.5 rounded-lg text-[10px] font-black bg-white/10 text-white/70">
                    {progress.created}/{progress.total} câu
                  </span>
                  <span className="px-2 py-0.5 rounded-lg text-[10px] font-black bg-brand-500/15 text-brand-200">
                    {progress.phase}
                  </span>
                </div>
                <p className="text-[11px] text-white/60 mt-1">{progress.msg}</p>

                <div className="mt-3 h-2.5 rounded-full bg-white/10 overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-brand-400 via-brand-400 to-brand2-400 transition-all duration-500"
                    style={{ width: `${Math.min(100, Math.round((progress.created / Math.max(progress.total, 1)) * 100))}%` }}
                  ></div>
                </div>
                <div className="mt-3 h-1.5 rounded-full overflow-hidden bg-white/5">
                  <div className="h-full w-1/3 bg-gradient-to-r from-transparent via-brand-300/70 to-transparent scam-iq-shimmer"></div>
                </div>
              </div>
            </div>
          </div>
        )}

        {error && (
          <div className="mt-5 rounded-2xl border border-danger-500/30 bg-danger-500/10 p-4 text-danger-200 text-sm flex items-center justify-between gap-3">
            <span>{error}</span>
            <button
              onClick={() => void startExam()}
              className="px-3 py-1 rounded-lg bg-danger-500/20 text-danger-100 text-xs font-bold hover:bg-danger-500/30"
            >
              Thử lại
            </button>
          </div>
        )}
      </div>

      {/* Active Question Stage */}
      {stage === 'ready' && current && (
        <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,1fr)_280px] gap-6 items-start">
          <div className="liquid-card p-6 sm:p-8 space-y-6">
            {/* Top Status Bar with Timer */}
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/5 pb-4">
              <div className="flex flex-wrap items-center gap-2">
                <span className="px-3 py-1 rounded-lg text-[10px] font-black uppercase tracking-widest bg-white/5 text-white/70">
                  Câu {index + 1} / {questions.length}
                </span>
                <span className="px-3 py-1 rounded-lg text-[10px] font-black uppercase tracking-widest bg-brand-500/10 text-brand-300">
                  {current.difficulty_label || current.difficulty}
                </span>
                <span className="px-3 py-1 rounded-lg text-[10px] font-black uppercase tracking-widest bg-brand2-500/10 text-brand2-300">
                  {typeLabel(current.type)}
                </span>
                {current.category && (
                  <span className="px-2.5 py-1 rounded-lg text-[10px] font-bold bg-white/[0.04] text-white/45">
                    {current.category}
                  </span>
                )}
              </div>
              {/* Running Exam Timer */}
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-xl bg-brand-500/10 border border-brand-500/20 text-brand-300 text-xs font-mono font-bold">
                <i className="bi bi-clock-history text-xs"></i>
                <span>{timerText}</span>
              </div>
            </div>

            {/* Mobile Quick Question Navigation Strip (Only visible < 1024px) */}
            <div className="lg:hidden -mx-2 px-2 pb-1 overflow-x-auto custom-scrollbar">
              <div className="flex gap-1.5 min-w-max">
                {questions.map((q, idx) => (
                  <button
                    key={q.id}
                    onClick={() => jumpTo(idx)}
                    className={`w-8 h-8 rounded-lg text-[10px] font-black border transition-all ${
                      idx === index
                        ? 'bg-brand-400 text-black border-brand-300 scale-105 shadow-sm'
                        : isAnswered(q)
                          ? 'bg-safe-500/20 text-safe-300 border-safe-500/40'
                          : 'bg-white/5 text-white/55 border-white/10'
                    }`}
                  >
                    {idx + 1}
                  </button>
                ))}
              </div>
            </div>

            {/* Question Title */}
            <h2 className="text-xl font-black text-white leading-relaxed scam-iq-wrap">
              {cleanQ(current.question)}
            </h2>

            {/* Simulation Block */}
            {isSimulationType(current.type) ? (
              <div className="space-y-4">
                {/* SMS Simulation Card */}
                {current.type === 'simulation_sms' && (
                  <div className="rounded-3xl border border-white/10 bg-gradient-to-br from-[var(--sc-panel)] to-[var(--sc-panel)] p-4 max-w-2xl shadow-[0_10px_35px_rgba(0,0,0,0.35)]">
                    <div className="flex items-center justify-between text-[11px] text-white/60 mb-3">
                      <span className="inline-flex items-center gap-1.5">
                        <i className="bi bi-phone"></i>
                        <span>{simField(current, 'sender_name', 'Tin nhắn mới')}</span>
                      </span>
                      <span className="text-brand-200/80">{simField(current, 'time', '--:--')}</span>
                    </div>
                    <div className="rounded-2xl bg-white/[0.05] border border-white/10 p-4">
                      <p className="text-[11px] text-brand-300 font-mono tracking-wide">
                        {simField(current, 'from', 'Unknown sender')}
                      </p>
                      <p className="text-sm text-white/90 mt-2 whitespace-pre-line leading-relaxed">{simBodyText(current)}</p>
                      <div className="mt-3 text-[11px] text-white/45 inline-flex items-center gap-1.5">
                        <i className="bi bi-shield-exclamation"></i> Tình huống mô phỏng nhằm mục đích luyện tập an ninh số
                      </div>
                    </div>
                  </div>
                )}

                {/* Email Simulation Card */}
                {current.type === 'simulation_email' && (
                  <div className="rounded-3xl border border-white/10 bg-gradient-to-br from-[var(--sc-panel)] to-[var(--sc-panel)] overflow-hidden shadow-[0_10px_35px_rgba(0,0,0,0.35)]">
                    <div className="px-4 py-3 border-b border-white/10 bg-white/[0.03] flex items-center justify-between">
                      <p className="text-[11px] text-white/70 inline-flex items-center gap-1.5">
                        <i className="bi bi-envelope-paper"></i> Security Inbox
                      </p>
                      <i className="bi bi-envelope-open text-brand-300"></i>
                    </div>
                    <div className="p-4 space-y-2.5">
                      <p className="text-[11px] text-white/60">
                        <span className="text-white/85 font-bold">From:</span>{' '}
                        <span>{simField(current, 'from', 'security-alert@unknown-domain')}</span>
                      </p>
                      <p className="text-[11px] text-white/60">
                        <span className="text-white/85 font-bold">Subject:</span>{' '}
                        <span>{simField(current, 'subject', 'Security Alert')}</span>
                      </p>
                      <p className="text-[11px] text-white/60">
                        <span className="text-white/85 font-bold">Preview:</span>{' '}
                        <span>{simField(current, 'preview', 'Không có preview')}</span>
                      </p>
                      <div className="rounded-2xl bg-white/[0.04] border border-white/10 p-4 mt-2">
                        <p className="text-sm text-white/90 whitespace-pre-line leading-relaxed">{simBodyText(current)}</p>
                        <div className="mt-3 text-[11px] text-white/45 inline-flex items-center gap-1.5">
                          <i className="bi bi-shield-exclamation"></i> Tình huống mô phỏng nhằm mục đích luyện tập an ninh số
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* Incident Response Simulation Card */}
                {current.type === 'incident_response' && (
                  <div className="rounded-3xl border border-warn-500/30 bg-gradient-to-br from-[var(--sc-ink-deep)] to-[var(--sc-panel)] p-5 max-w-2xl shadow-[0_10px_35px_rgba(245,158,11,0.12)] space-y-3">
                    <div className="flex items-center justify-between text-[11px] text-warn-300 border-b border-warn-500/20 pb-2.5">
                      <span className="inline-flex items-center gap-2 font-black uppercase tracking-wider">
                        <i className="bi bi-shield-slash-fill text-warn-400"></i> Báo động Sự cố An toàn Số
                      </span>
                      <span className="px-2.5 py-0.5 rounded-lg bg-warn-500/20 border border-warn-500/30 text-warn-200 text-[10px] font-black uppercase tracking-wider">
                        Khẩn cấp
                      </span>
                    </div>
                    <div className="p-3.5 rounded-2xl bg-black/40 border border-warn-500/20">
                      <p className="text-xs text-warn-100/90 font-medium leading-relaxed">
                        <i className="bi bi-info-circle-fill text-warn-400 mr-1.5"></i> Tình huống phản ứng sự cố khẩn cấp.
                        Trình bày chi tiết: các bước xác thực thông tin, biện pháp cô lập rủi ro, tuyệt đối không chuyển tiền
                        theo lệnh phi chính thống và đầu mối báo cáo an ninh mạng.
                      </p>
                    </div>
                  </div>
                )}

                {/* Free text answer input */}
                <div className="space-y-2">
                  <p className="text-[11px] font-black text-white/60 uppercase tracking-widest">
                    Bạn sẽ phản hồi hoặc hành động như thế nào?
                  </p>
                  <textarea
                    value={freeTextValue(current.id)}
                    onChange={(e) => setFree(current.id, e.target.value)}
                    className="liquid-input w-full min-h-[120px] p-4 text-sm font-medium focus:border-brand-400"
                    placeholder="Viết phản hồi/hành động cụ thể (ví dụ: không bấm link, xác minh hotline chính thức, đổi mật khẩu, báo cáo phishing...)"
                  />
                </div>
              </div>
            ) : (
              /* Multiple Choice Block */
              <div className="space-y-3">
                {current.type === 'multi_select' && (
                  <div className="flex items-center justify-between py-1">
                    <p className="text-[11px] text-brand-300 font-bold uppercase tracking-widest">
                      <i className="bi bi-check2-square mr-1"></i> Có nhiều đáp án đúng
                    </p>
                    <span className="text-[11px] text-white/55">Đã chọn: {selectedCount(current.id)}</span>
                  </div>
                )}
                {(current.options || []).map((opt) => {
                  const checked = isChecked(opt.id);
                  return (
                    <label
                      key={opt.id}
                      className={`w-full flex items-start gap-3 rounded-2xl border p-4 hover:border-brand-400/30 cursor-pointer transition-all ${
                        checked ? 'border-brand-400/50 bg-brand-500/[0.08]' : 'border-white/10 bg-white/[0.02]'
                      }`}
                    >
                      <input
                        type={current.type === 'multi_select' ? 'checkbox' : 'radio'}
                        name={`q-${current.id}`}
                        checked={checked}
                        onChange={() => (current.type === 'multi_select' ? toggle(current.id, opt.id) : setSingle(current.id, opt.id))}
                        className="mt-1 accent-brand-400"
                      />
                      <div className="min-w-0">
                        <p className="text-xs font-black text-brand-300">{opt.id}</p>
                        <p className="text-sm text-white/80 mt-1 leading-relaxed">{opt.text}</p>
                      </div>
                    </label>
                  );
                })}
              </div>
            )}

            {/* Action Buttons Row */}
            <div className="flex flex-wrap items-center justify-between gap-3 pt-4 border-t border-white/5">
              <button
                onClick={prevQuestion}
                disabled={index === 0}
                className="liquid-btn py-2.5 px-5 bg-white/5 text-white font-bold hover:bg-white/10 disabled:opacity-40"
              >
                ← Câu trước
              </button>
              <div className="text-[11px] text-white/55 font-mono">
                Đã trả lời {answeredCount} / {questions.length}
              </div>
              {index < questions.length - 1 ? (
                <button onClick={nextQuestion} className="liquid-btn py-2.5 px-5 bg-brand-500 text-black font-black hover:bg-brand-400">
                  Câu tiếp theo →
                </button>
              ) : (
                <button
                  onClick={() => void submitExam()}
                  disabled={submitting}
                  className="liquid-btn py-2.5 px-6 bg-safe-500 text-black font-black hover:bg-safe-400 disabled:opacity-60 shadow-lg shadow-safe-500/20"
                >
                  <span className={submitting ? 'hidden' : ''}>Nộp bài thi</span>
                  <span className={submitting ? '' : 'hidden'}>Đang chấm điểm...</span>
                </button>
              )}
            </div>
          </div>

          {/* Desktop Sidebar Navigation Grid */}
          <aside className="liquid-card p-4 lg:sticky lg:top-24 space-y-3 border border-brand-500/20 bg-gradient-to-b from-brand-500/[0.06] to-transparent">
            <div className="flex items-center justify-between">
              <p className="text-[10px] font-black uppercase tracking-[0.18em] text-white/45">Điều hướng câu hỏi</p>
              <p className="text-[10px] text-brand-300 font-bold">
                {answeredCount}/{questions.length}
              </p>
            </div>
            <div className="w-full h-1.5 rounded-full bg-white/10 overflow-hidden">
              <div
                className="h-full bg-brand-400 transition-all duration-300"
                style={{ width: `${Math.round((answeredCount / Math.max(questions.length, 1)) * 100)}%` }}
              ></div>
            </div>
            <div className="grid grid-cols-5 gap-2 max-h-[420px] overflow-y-auto pr-1 custom-scrollbar">
              {questions.map((q, idx) => (
                <button
                  key={q.id}
                  onClick={() => jumpTo(idx)}
                  className={`h-10 rounded-xl text-[11px] font-black border transition-all shadow-sm ${
                    idx === index
                      ? 'bg-brand-400 text-black border-brand-300 scale-[1.03] shadow-[0_0_14px_rgba(34,211,238,0.35)]'
                      : isAnswered(q)
                        ? 'bg-safe-500/20 text-safe-200 border-safe-500/40 hover:bg-safe-500/30'
                        : 'bg-white/[0.03] text-white/45 border-white/10 hover:border-brand-500/40 hover:text-white/80'
                  }`}
                >
                  {idx + 1}
                </button>
              ))}
            </div>
            <div className="grid grid-cols-1 gap-1.5 text-[10px] text-white/55 pt-1 border-t border-white/5">
              <p className="flex items-center">
                <span className="inline-block w-2 h-2 rounded-full bg-brand-300 mr-2"></span> Đang làm
              </p>
              <p className="flex items-center">
                <span className="inline-block w-2 h-2 rounded-full bg-safe-400 mr-2"></span> Đã chọn
              </p>
              <p className="flex items-center">
                <span className="inline-block w-2 h-2 rounded-full bg-white/25 mr-2"></span> Chưa chọn
              </p>
            </div>
          </aside>
        </div>
      )}

      {/* Results Stage */}
      {stage === 'result' && result && (
        <div className="liquid-card p-6 sm:p-8 space-y-8">
          {/* Stylized Certificate Banner */}
          <div className="relative overflow-hidden rounded-3xl border border-brand-500/30 bg-gradient-to-br from-brand-950/40 via-[var(--sc-panel)] to-brand2-950/30 p-6 sm:p-8 shadow-[0_20px_50px_rgba(0,0,0,0.5)]">
            <div className="absolute top-0 right-0 w-80 h-80 bg-brand-500/10 rounded-full blur-3xl pointer-events-none"></div>
            <div className="relative z-10 flex flex-col md:flex-row md:items-center md:justify-between gap-6">
              <div className="space-y-2 max-w-xl">
                <div className="flex items-center gap-2">
                  <span className="px-3 py-1 rounded-lg text-[10px] font-black uppercase tracking-widest bg-brand-500/20 border border-brand-400/40 text-brand-300">
                    Bảng điểm &amp; Chứng nhận Scam IQ
                  </span>
                  <span className="text-xs text-white/55">Thời gian: {timerText || '--:--'}</span>
                </div>
                <h3 className="text-3xl sm:text-4xl font-black text-white tracking-tight">{result.level.label}</h3>
                <p className="text-sm text-white/70 leading-relaxed">{result.level.description}</p>
                <p className="text-xs text-brand-300/90 font-medium pt-1">{percentile}</p>
              </div>

              {/* Score Badge Circle */}
              <div className="flex flex-col items-center justify-center p-6 rounded-3xl border border-brand-400/30 bg-white/[0.03] backdrop-blur-md shrink-0 shadow-lg text-center min-w-[210px]">
                <p className="text-[10px] font-black uppercase tracking-[0.2em] text-white/45">Điểm số đạt được</p>
                <div className="text-4xl font-black text-transparent bg-clip-text bg-gradient-to-r from-brand-300 via-brand-200 to-brand2-300 my-1">
                  {result.score}
                  <span className="text-lg text-white/55 font-normal"> / 300</span>
                </div>
                <p className="text-xs font-bold text-white/60">
                  Tỷ lệ: {Math.round((result.score / (result.max_score || 300)) * 100)}%
                </p>
                <p className="text-[11px] text-safe-400 font-bold mt-2">Đúng {result.correct_count}/30 câu</p>
              </div>
            </div>

            {/* Certificate action buttons */}
            <div className="mt-6 pt-5 border-t border-white/10 flex flex-wrap items-center gap-3">
              <button
                onClick={copySummary}
                className="liquid-btn py-2.5 px-5 bg-brand-400 text-black font-black text-xs hover:bg-brand-300 transition-all"
              >
                <i className="bi bi-clipboard-check mr-1.5"></i> Sao chép kết quả
              </button>
              <button
                onClick={resetExam}
                className="liquid-btn py-2.5 px-5 bg-white/10 text-white font-bold text-xs hover:bg-white/15 transition-all"
              >
                <i className="bi bi-arrow-clockwise mr-1.5"></i> Làm bài mới
              </button>
              <Link href="/home/" className="liquid-btn py-2.5 px-5 bg-white/5 text-white/70 font-bold text-xs hover:bg-white/10 transition-all">
                Về trang chủ
              </Link>
            </div>
          </div>

          {/* AI Background Scoring Notification (if simulations present) */}
          {aiScoring && (
            <div className="rounded-2xl border border-brand2-500/30 bg-brand2-500/10 p-5">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-brand2-500/20 flex items-center justify-center shrink-0">
                  <i className="bi bi-robot text-brand2-300 text-lg animate-bounce"></i>
                </div>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-bold text-brand2-200">
                    AI Giám khảo đang chấm điểm các tình huống thực tế...
                  </p>
                  <p className="text-[11px] text-brand2-300/70 mt-1">{aiMsg || 'Đang kết nối AI giám khảo...'}</p>
                  <div className="mt-2 h-1 rounded-full bg-white/10 overflow-hidden">
                    <div className="h-full bg-brand2-400 scam-iq-shimmer w-full"></div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Difficulty Breakdown (4 Cards: Easy, Medium, Hard, Extreme) */}
          <div className="space-y-3">
            <p className="text-[11px] font-black text-brand-300 uppercase tracking-widest">Năng lực theo cấp độ thử thách</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {bands.map((b) => (
                <div key={b.key} className="rounded-2xl border border-white/10 bg-white/[0.02] p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className={`text-xs font-black uppercase tracking-wider ${b.textColor}`}>{b.label}</span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-white/5 text-white/70">{b.ratio}</span>
                  </div>
                  <div className="w-full h-2 rounded-full bg-white/10 overflow-hidden">
                    <div className={`h-full rounded-full transition-all duration-500 ${b.barColor}`} style={{ width: `${b.pct}%` }}></div>
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-white/60">
                    <span>{b.pct}% chính xác</span>
                    <span>{b.status}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Level Scale Table */}
          <div className="space-y-3">
            <p className="text-[11px] font-black text-white/60 uppercase tracking-widest">Thang cấp độ năng lực Scam IQ</p>
            <div className="overflow-x-auto rounded-2xl border border-white/10">
              <table className="w-full text-sm">
                <thead className="bg-white/[0.03]">
                  <tr>
                    <th className="px-4 py-3 text-left text-[11px] font-black text-white/60 uppercase">Mức</th>
                    <th className="px-4 py-3 text-left text-[11px] font-black text-white/60 uppercase">Điểm</th>
                    <th className="px-4 py-3 text-left text-[11px] font-black text-white/60 uppercase">Đánh giá</th>
                  </tr>
                </thead>
                <tbody>
                  {(result.level_bands || []).map((band) => (
                    <tr key={band.code} className={band.code === result.level.code ? 'bg-brand-500/10' : 'border-t border-white/5'}>
                      <td className="px-4 py-3 text-white font-bold">{band.label}</td>
                      <td className="px-4 py-3 text-white/70">
                        {band.min} - {band.max}
                      </td>
                      <td className="px-4 py-3 text-white/70">{band.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Interactive Question Review */}
          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-white/10 pb-3">
              <div>
                <h4 className="text-lg font-black text-white">Xem lại chi tiết câu hỏi</h4>
                <p className="text-xs text-white/60">Phân tích đáp án và giải thích chuyên sâu từ ShieldCall VN</p>
              </div>
              {/* Review Filter Pills */}
              <div className="flex flex-wrap gap-1.5 p-1 rounded-xl bg-white/[0.03] border border-white/10 text-xs">
                {(['all', 'mistakes', 'simulations'] as const).map((k) => (
                  <button
                    key={k}
                    onClick={() => setReviewFilter(k)}
                    className={`px-3 py-1.5 rounded-lg font-bold transition-all ${
                      reviewFilter === k ? filterActiveCls(k) : 'text-white/60 hover:text-white'
                    }`}
                  >
                    {k === 'all'
                      ? 'Tất cả (30)'
                      : k === 'mistakes'
                        ? `Câu sai (${result.mistakes ? result.mistakes.length : 0})`
                        : `Tự luận (${(result.ai_feedback || []).length})`}
                  </button>
                ))}
              </div>
            </div>

            {/* Questions List */}
            <div className="space-y-4">
              {review.map((q) => (
                <div
                  key={q.id}
                  className={`rounded-2xl border p-5 space-y-3 transition-all ${
                    q.isMistake ? 'border-danger-500/25 bg-danger-500/[0.03]' : q.isSim ? 'border-brand2-500/25 bg-brand2-500/[0.03]' : 'border-safe-500/25 bg-safe-500/[0.02]'
                  }`}
                >
                  {/* Question meta & status */}
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="px-2.5 py-0.5 rounded-lg text-[10px] font-black uppercase tracking-wider bg-white/10 text-white/80">
                        Câu {q.index + 1}
                      </span>
                      <span className="px-2.5 py-0.5 rounded-lg text-[10px] font-black uppercase tracking-wider bg-brand-500/10 text-brand-300">
                        {q.difficulty_label || q.difficulty}
                      </span>
                      <span className="px-2.5 py-0.5 rounded-lg text-[10px] font-bold bg-white/5 text-white/60">{q.category}</span>
                    </div>
                    {q.isSim ? (
                      <span className="px-2.5 py-1 rounded-lg text-[10px] font-black bg-brand2-500/20 text-brand2-300">
                        <i className="bi bi-robot mr-1"></i> Tự luận AI chấm
                      </span>
                    ) : q.isMistake ? (
                      <span className="px-2.5 py-1 rounded-lg text-[10px] font-black bg-danger-500/20 text-danger-300">
                        <i className="bi bi-x-circle mr-1"></i> Chưa chính xác (0đ)
                      </span>
                    ) : (
                      <span className="px-2.5 py-1 rounded-lg text-[10px] font-black bg-safe-500/20 text-safe-300">
                        <i className="bi bi-check-circle mr-1"></i> Chính xác (+10đ)
                      </span>
                    )}
                  </div>

                  {/* Question content */}
                  <p className="text-sm font-bold text-white scam-iq-wrap leading-relaxed">{cleanQ(q.question)}</p>

                  {/* Options display for multiple choice */}
                  {!q.isSim && q.options && q.options.length > 0 && (
                    <div className="grid grid-cols-1 gap-2 pt-1">
                      {q.options.map((opt) => (
                        <div
                          key={opt.id}
                          className={`p-3 rounded-xl border text-xs flex items-start gap-2.5 ${
                            q.expected.includes(opt.id)
                              ? 'border-safe-500/40 bg-safe-500/10 text-safe-200 font-medium'
                              : q.selected.includes(opt.id)
                                ? 'border-danger-500/40 bg-danger-500/10 text-danger-200'
                                : 'border-white/5 bg-white/[0.02] text-white/60'
                          }`}
                        >
                          <span className="font-black">{opt.id}.</span>
                          <span className="flex-1">{opt.text}</span>
                          {q.expected.includes(opt.id) && (
                            <span className="text-[10px] font-black uppercase text-safe-400 shrink-0">Đáp án đúng</span>
                          )}
                          {q.selected.includes(opt.id) && !q.expected.includes(opt.id) && (
                            <span className="text-[10px] font-black uppercase text-danger-400 shrink-0">Lựa chọn của bạn</span>
                          )}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Free text display for simulations */}
                  {q.isSim && (
                    <div className="space-y-2 pt-1">
                      <div className="p-3 rounded-xl bg-white/[0.03] border border-white/10 text-xs">
                        <p className="text-white/55 text-[10px] font-black uppercase tracking-wider mb-1">Câu trả lời của bạn:</p>
                        <p className="text-white/90 whitespace-pre-wrap">{q.userAnswerText || '(Chưa nhập)'}</p>
                      </div>
                      {q.aiFeedback && (
                        <div className="p-3.5 rounded-xl bg-brand2-500/10 border border-brand2-500/20 text-xs space-y-1">
                          <div className="flex items-center justify-between text-brand2-300 font-bold">
                            <span>
                              <i className="bi bi-robot mr-1"></i> Đánh giá từ AI:
                            </span>
                            <span>{q.aiFeedback.ai_score}/10 điểm</span>
                          </div>
                          <p className="text-brand2-200">{q.aiFeedback.ai_comment}</p>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Explanation Box */}
                  <div className="p-3 rounded-xl bg-brand-500/5 border border-brand-500/15 text-xs text-brand-200/90 leading-relaxed">
                    <span className="font-black text-brand-300 uppercase text-[10px] mr-1">
                      <i className="bi bi-lightbulb mr-1"></i>Giải thích:
                    </span>
                    <span>{q.explanation}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Floating Copy Toast */}
      {toast && (
        <div className="fixed bottom-6 right-6 z-50 px-4 py-3 rounded-2xl bg-brand-400 text-black font-black text-xs shadow-2xl flex items-center gap-2">
          <i className="bi bi-check-circle-fill"></i>
          <span>{toast}</span>
        </div>
      )}
    </section>
  );
}

function formatTime(iso: string): string {
  try {
    return new Date(iso).toLocaleString('vi-VN');
  } catch {
    return iso || '';
  }
}
