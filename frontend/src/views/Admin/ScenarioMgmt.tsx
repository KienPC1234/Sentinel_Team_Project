'use client';
import { useState, useMemo } from 'react';
import Link from 'next/link';
import { api } from '../../lib/api';
import { AdminShell, useAdminGet } from './_shared';

interface ScenarioItem {
  id: number;
  title: string;
  description: string;
  article_id: number | null;
  article_title: string | null;
  lesson_id: number | null;
  lesson_title: string | null;
  steps_count: number;
  created_at: string;
}

interface StepDetail {
  speaker: 'scammer' | 'victim' | 'narrator';
  text: string;
  note?: string;
}

interface ScenarioFullDetail {
  id: number;
  title: string;
  description: string;
  steps: StepDetail[];
}

export function ScenarioMgmt() {
  const { data, loading, refetch } = useAdminGet<ScenarioItem[]>('/admin/scenarios/');
  const [deletingId, setDeletingId] = useState<number | null>(null);
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null);
  const [search, setSearch] = useState('');
  const [filterType, setFilterType] = useState<'all' | 'lesson' | 'article' | 'standalone'>('all');

  // Preview modal state
  const [previewScenario, setPreviewScenario] = useState<ScenarioFullDetail | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewStep, setPreviewStep] = useState(0);

  const rawList = data || [];

  const metrics = useMemo(() => {
    const total = rawList.length;
    const withLesson = rawList.filter((s) => s.lesson_id).length;
    const withArticle = rawList.filter((s) => s.article_id).length;
    const standalone = rawList.filter((s) => !s.lesson_id && !s.article_id).length;
    const totalSteps = rawList.reduce((acc, s) => acc + (s.steps_count || 0), 0);
    return { total, withLesson, withArticle, standalone, totalSteps };
  }, [rawList]);

  const filteredList = useMemo(() => {
    return rawList.filter((s) => {
      if (filterType === 'lesson' && !s.lesson_id) return false;
      if (filterType === 'article' && !s.article_id) return false;
      if (filterType === 'standalone' && (s.lesson_id || s.article_id)) return false;

      if (!search.trim()) return true;
      const q = search.toLowerCase();
      return (
        (s.title || '').toLowerCase().includes(q) ||
        (s.description || '').toLowerCase().includes(q) ||
        (s.lesson_title || '').toLowerCase().includes(q) ||
        (s.article_title || '').toLowerCase().includes(q)
      );
    });
  }, [rawList, search, filterType]);

  const handleDelete = async (id: number, title: string) => {
    if (!window.confirm(`Bạn có chắc chắn muốn xóa kịch bản "${title}"?`)) return;
    setDeletingId(id);
    setMsg(null);
    try {
      await api.del(`/admin/scenarios/${id}/`);
      setMsg({ text: `Đã xóa kịch bản "${title}"`, ok: true });
      refetch();
    } catch (err: unknown) {
      const e = err as { message?: string };
      setMsg({ text: e.message || 'Xóa kịch bản thất bại', ok: false });
    } finally {
      setDeletingId(null);
    }
  };

  const openPreview = async (id: number) => {
    setPreviewLoading(true);
    setPreviewStep(0);
    try {
      const detail = await api.get<ScenarioFullDetail>(`/admin/scenarios/${id}/`);
      setPreviewScenario(detail);
    } catch (err: unknown) {
      const e = err as { message?: string };
      setMsg({ text: e.message || 'Không thể tải chi tiết kịch bản.', ok: false });
    } finally {
      setPreviewLoading(false);
    }
  };

  const closePreview = () => {
    setPreviewScenario(null);
    setPreviewStep(0);
  };

  return (
    <AdminShell
      title="Kịch Bản Mô Phỏng"
      subtitle="Thiết kế và quản lý các tình huống giả định Scam IQ tương tác cho người dùng"
      actions={
        <Link
          href="/admin-cp/scenarios/add/"
          className="px-4 py-2.5 rounded-xl bg-brand-500 text-black text-xs font-black uppercase tracking-wider hover:bg-brand-400 transition-all shadow-md shadow-brand-500/20 flex items-center gap-1.5"
        >
          <i className="bi bi-plus-lg"></i> Thêm kịch bản mới
        </Link>
      }
    >
      {msg && (
        <div className={`p-4 rounded-xl mb-6 text-xs font-bold border ${msg.ok ? 'bg-safe-500/15 border-safe-500/30 text-safe-300' : 'bg-danger-500/15 border-danger-500/30 text-danger-300'}`}>
          {msg.text}
        </div>
      )}

      {/* Metrics Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div className="p-4 rounded-2xl bg-slate-900/80 border border-white/10 shadow-lg">
          <div className="text-white/40 text-[11px] font-bold uppercase tracking-wider">Tổng kịch bản</div>
          <div className="text-2xl font-black text-white mt-1">{metrics.total}</div>
        </div>
        <div className="p-4 rounded-2xl bg-slate-900/80 border border-white/10 shadow-lg">
          <div className="text-white/40 text-[11px] font-bold uppercase tracking-wider">Gắn bài học</div>
          <div className="text-2xl font-black text-brand-400 mt-1">{metrics.withLesson}</div>
        </div>
        <div className="p-4 rounded-2xl bg-slate-900/80 border border-white/10 shadow-lg">
          <div className="text-white/40 text-[11px] font-bold uppercase tracking-wider">Gắn tin tức</div>
          <div className="text-2xl font-black text-purple-400 mt-1">{metrics.withArticle}</div>
        </div>
        <div className="p-4 rounded-2xl bg-slate-900/80 border border-white/10 shadow-lg">
          <div className="text-white/40 text-[11px] font-bold uppercase tracking-wider">Tổng số bước diễn tập</div>
          <div className="text-2xl font-black text-brand2-400 mt-1">{metrics.totalSteps}</div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 mb-6">
        <div className="flex items-center gap-2 overflow-x-auto pb-1 md:pb-0">
          <button
            type="button"
            onClick={() => setFilterType('all')}
            className={`px-3.5 py-2 rounded-xl text-xs font-bold transition-all border ${
              filterType === 'all'
                ? 'bg-brand-500/20 border-brand-500/40 text-brand-300'
                : 'bg-white/5 border-white/10 text-white/60 hover:text-white hover:bg-white/10'
            }`}
          >
            Tất cả ({metrics.total})
          </button>
          <button
            type="button"
            onClick={() => setFilterType('lesson')}
            className={`px-3.5 py-2 rounded-xl text-xs font-bold transition-all border ${
              filterType === 'lesson'
                ? 'bg-brand-500/20 border-brand-500/40 text-brand-300'
                : 'bg-white/5 border-white/10 text-white/60 hover:text-white hover:bg-white/10'
            }`}
          >
            Gắn bài học ({metrics.withLesson})
          </button>
          <button
            type="button"
            onClick={() => setFilterType('article')}
            className={`px-3.5 py-2 rounded-xl text-xs font-bold transition-all border ${
              filterType === 'article'
                ? 'bg-purple-500/20 border-purple-500/40 text-purple-300'
                : 'bg-white/5 border-white/10 text-white/60 hover:text-white hover:bg-white/10'
            }`}
          >
            Gắn tin tức ({metrics.withArticle})
          </button>
          <button
            type="button"
            onClick={() => setFilterType('standalone')}
            className={`px-3.5 py-2 rounded-xl text-xs font-bold transition-all border ${
              filterType === 'standalone'
                ? 'bg-white/20 border-white/30 text-white'
                : 'bg-white/5 border-white/10 text-white/60 hover:text-white hover:bg-white/10'
            }`}
          >
            Độc lập ({metrics.standalone})
          </button>
        </div>

        <div className="relative w-full md:w-80">
          <i className="bi bi-search absolute left-3.5 top-1/2 -translate-y-1/2 text-white/40 text-xs pointer-events-none"></i>
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Tìm theo tiêu đề, bài học..."
            className="w-full bg-slate-900/90 border border-white/10 rounded-xl pl-9 pr-4 py-2 text-xs text-white placeholder-white/30 focus:outline-none focus:border-brand-500/50"
          />
          {search && (
            <button
              type="button"
              onClick={() => setSearch('')}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-white/40 hover:text-white text-xs"
            >
              <i className="bi bi-x"></i>
            </button>
          )}
        </div>
      </div>

      {/* Main Table */}
      <div className="overflow-x-auto rounded-3xl border border-white/10 bg-slate-900/90 shadow-2xl">
        <table className="w-full text-sm text-left border-separate border-spacing-0 table-fixed">
          <thead className="bg-white/[0.03]">
            <tr>
              <th className="w-[36%] px-6 py-4 text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-white/10">Kịch bản</th>
              <th className="w-[26%] px-6 py-4 text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-white/10">Liên kết</th>
              <th className="w-[12%] px-4 py-4 text-center text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-white/10">Số bước</th>
              <th className="w-[12%] px-4 py-4 text-center text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-white/10">Ngày tạo</th>
              <th className="w-[14%] px-6 py-4 text-right text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-white/10">Thao tác</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {filteredList.map((s) => (
              <tr key={s.id} className="hover:bg-white/[0.04] transition-all">
                <td className="px-6 py-4">
                  <div className="font-bold text-white text-sm tracking-tight break-words">{s.title}</div>
                  <div className="text-xs text-slate-400 line-clamp-2 mt-1">{s.description || 'Không có mô tả'}</div>
                </td>
                <td className="px-6 py-4 text-xs">
                  {s.lesson_title ? (
                    <span className="inline-block max-w-full px-2.5 py-1 rounded-lg bg-brand-500/10 border border-brand-500/20 text-brand-300 font-bold truncate">
                      Bài học: {s.lesson_title}
                    </span>
                  ) : s.article_title ? (
                    <span className="inline-block max-w-full px-2.5 py-1 rounded-lg bg-purple-500/10 border border-purple-500/20 text-purple-300 font-bold truncate">
                      Tin tức: {s.article_title}
                    </span>
                  ) : (
                    <span className="px-2.5 py-1 rounded-lg bg-slate-800 text-slate-400 font-medium">Độc lập</span>
                  )}
                </td>
                <td className="px-4 py-4 text-center whitespace-nowrap">
                  <span className="px-2.5 py-1 rounded-lg bg-slate-800 border border-white/10 text-slate-200 text-xs font-bold">
                    {s.steps_count} bước
                  </span>
                </td>
                <td className="px-4 py-4 text-center text-xs text-slate-400 whitespace-nowrap">{s.created_at}</td>
                <td className="px-6 py-4 text-right whitespace-nowrap">
                  <div className="inline-flex gap-2">
                    <button
                      type="button"
                      onClick={() => void openPreview(s.id)}
                      disabled={previewLoading}
                      title="Diễn tập thử"
                      className="px-2.5 py-1.5 rounded-lg bg-brand2-500/15 border border-brand2-500/30 text-xs font-bold text-brand2-300 hover:bg-brand2-500 hover:text-white transition-all"
                    >
                      <i className="bi bi-play-circle mr-1"></i> Thử
                    </button>
                    <Link
                      href={`/admin-cp/scenarios/${s.id}/edit/`}
                      className="px-2.5 py-1.5 rounded-lg bg-white/10 border border-white/15 text-xs font-bold text-slate-200 hover:bg-brand-500 hover:text-black transition-all"
                    >
                      <i className="bi bi-pencil mr-1"></i> Sửa
                    </Link>
                    <button
                      type="button"
                      disabled={deletingId === s.id}
                      onClick={() => void handleDelete(s.id, s.title)}
                      className="px-2.5 py-1.5 rounded-lg bg-danger-500/15 border border-danger-500/30 text-xs font-bold text-danger-300 hover:bg-danger-500 hover:text-white transition-all disabled:opacity-50"
                    >
                      <i className="bi bi-trash mr-1"></i> Xóa
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {filteredList.length === 0 && (
              <tr>
                <td colSpan={5} className="px-8 py-16 text-center text-slate-400 font-bold text-xs">
                  {loading
                    ? 'Đang tải danh sách kịch bản...'
                    : search
                    ? `Không tìm thấy kịch bản nào khớp với từ khóa "${search}"`
                    : 'Chưa có kịch bản mô phỏng nào được tạo.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Interactive Simulation Modal for Admin Preview */}
      {previewScenario && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
          <div className="relative w-full max-w-2xl bg-slate-900 border border-white/15 rounded-3xl shadow-2xl overflow-hidden flex flex-col max-h-[85vh]">
            <div className="p-5 bg-white/[0.03] border-b border-white/10 flex items-center justify-between">
              <div>
                <span className="text-[10px] font-black uppercase tracking-widest text-brand2-400">Xem trước mô phỏng Scam IQ</span>
                <h3 className="text-base font-bold text-white mt-0.5">{previewScenario.title}</h3>
              </div>
              <button
                type="button"
                onClick={closePreview}
                className="w-8 h-8 rounded-full bg-white/10 hover:bg-white/20 text-white/70 hover:text-white flex items-center justify-center transition-all"
              >
                <i className="bi bi-x-lg text-sm"></i>
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-6 space-y-4">
              {previewScenario.description && (
                <div className="p-3.5 rounded-xl bg-white/[0.03] border border-white/5 text-xs text-white/70 italic">
                  {previewScenario.description}
                </div>
              )}

              {previewScenario.steps.length === 0 ? (
                <div className="text-center py-10 text-white/40 text-xs">Kịch bản này chưa có bước diễn tập nào.</div>
              ) : (
                <div className="space-y-4">
                  {previewScenario.steps.slice(0, previewStep + 1).map((s, idx) => {
                    const isScammer = s.speaker === 'scammer';
                    const isVictim = s.speaker === 'victim';
                    return (
                      <div key={idx} className={`flex flex-col ${isScammer ? 'items-start' : isVictim ? 'items-end' : 'items-center'}`}>
                        <div
                          className={`flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-bold mb-1.5 border ${
                            isScammer
                              ? 'text-danger-400 bg-danger-500/10 border-danger-500/20'
                              : isVictim
                              ? 'text-brand-400 bg-brand-500/10 border-brand-500/20'
                              : 'text-brand2-400 bg-brand2-500/10 border-brand2-500/20'
                          }`}
                        >
                          <i
                            className={`bi ${
                              isScammer ? 'bi-exclamation-octagon-fill' : isVictim ? 'bi-person-badge-fill' : 'bi-info-circle-fill'
                            }`}
                          ></i>
                          <span>{isScammer ? 'Kẻ lừa đảo' : isVictim ? 'Nạn nhân' : 'Bối cảnh'}</span>
                        </div>
                        <div
                          className={`max-w-[85%] rounded-2xl px-4 py-3 text-sm leading-relaxed border ${
                            isScammer
                              ? 'bg-slate-950 border-danger-500/20 text-danger-50 rounded-tl-sm'
                              : isVictim
                              ? 'bg-brand-950/40 border-brand-500/30 text-white rounded-tr-sm'
                              : 'bg-white/5 border-white/10 text-white/80 text-center italic text-xs'
                          }`}
                        >
                          {s.text}
                        </div>
                        {s.note && (
                          <div className="mt-2 p-3 rounded-xl bg-warn-500/10 border border-warn-500/20 max-w-[85%] text-xs text-warn-200">
                            <span className="font-bold text-warn-400 block mb-0.5">Phân tích thủ đoạn:</span>
                            {s.note}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {previewScenario.steps.length > 0 && (
              <div className="p-4 bg-slate-950 border-t border-white/10 flex items-center justify-between gap-3">
                <button
                  type="button"
                  disabled={previewStep === 0}
                  onClick={() => setPreviewStep((p) => Math.max(0, p - 1))}
                  className="px-3 py-2 rounded-xl bg-white/10 text-white text-xs font-bold disabled:opacity-30 transition-all"
                >
                  <i className="bi bi-chevron-left mr-1"></i> Bước trước
                </button>
                <span className="text-xs font-bold text-white/60">
                  Bước {previewStep + 1} / {previewScenario.steps.length}
                </span>
                {previewStep < previewScenario.steps.length - 1 ? (
                  <button
                    type="button"
                    onClick={() => setPreviewStep((p) => Math.min(previewScenario.steps.length - 1, p + 1))}
                    className="px-4 py-2 rounded-xl bg-brand2-500 text-white text-xs font-bold hover:bg-brand2-400 transition-all"
                  >
                    Tiếp tục <i className="bi bi-chevron-right ml-1"></i>
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={() => setPreviewStep(0)}
                    className="px-4 py-2 rounded-xl bg-white/15 text-white text-xs font-bold hover:bg-white/20 transition-all"
                  >
                    Bắt đầu lại
                  </button>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </AdminShell>
  );
}
