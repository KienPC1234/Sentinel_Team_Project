'use client';
import { Fragment, memo, useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';

import type { DragEvent, FormEvent, MouseEventHandler, PointerEvent, ReactNode, TouchEvent } from 'react';

import Link from 'next/link';

import { useParams } from 'next/navigation';
import TextareaAutosize from 'react-textarea-autosize';
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import {
  Accessibility, ALargeSmall, AlertTriangle, ArrowDown, ArrowUp, Bookmark, Check, ChevronDown, Copy, Download, Flag,
  FolderPlus, Globe, HeartHandshake, HeartPulse, Home, ImagePlus, Landmark, Menu,
  MoreHorizontal, Newspaper, PanelLeft, Pencil, Phone, Plus, RefreshCw, Search,
  ShieldCheck, Square, ThumbsDown, ThumbsUp, Trash2, Volume2, X,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

import { cn } from '@/lib/utils';
import { api } from '../../lib/api';

import { escapeHtml, escapeRegExp, renderMd, safeUrl } from '../../lib/chat/markdown';
import { openSseStream } from '../../lib/chat/stream';
import { MarkdownView } from '../../components/ui';
import { ChatGuardrailNote, type GuardrailData } from '../../components/ScanWidgets';
import { useAuth } from '../../components/AuthContext';

import { toast } from 'sonner';
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog';

import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Dialog, DialogContent, DialogTitle,
} from '@/components/ui/dialog';
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select';
import { Separator } from '@/components/ui/separator';
import { Switch } from '@/components/ui/switch';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Textarea } from '@/components/ui/textarea';
import {
  Tooltip, TooltipContent, TooltipProvider, TooltipTrigger,
} from '@/components/ui/tooltip';

/* AI Assistant — bản Next của PKV/templates/AI/assistant.html.
 *
 * Giao diện phong cách ChatGPT, tách khỏi style trang chính:
 * - Component tương tác dùng shadcn/ui (src/components/ui/*).
 * - CSS riêng ở app/styles/assistant.css, scope .gpt, bảng màu --gpt-*.
 * - Không dùng màu brand/brand2 của site → không "ô nhiễm màu".
 */

interface ChatSession { id: string; title?: string; folder?: number | null; }
interface ChatFolder { id: number; name: string; }
interface SrcItem { title?: string; url?: string; text?: string; }
interface MsgMeta { internal_knowledge?: SrcItem[]; web_search?: SrcItem[]; guardrail?: GuardrailData; }
interface ChatMsg { id?: number; role: string; message: string; images?: string[]; metadata?: MsgMeta | null; rating?: number; created_at?: string; }
interface ToolCall { tool: string; args?: Record<string, unknown>; result?: unknown; done: boolean; label: string; }
interface SavedMsg { id: number; message_role: string; message_text: string; session_title?: string; session_id?: string; }
interface SearchSession { id: string; title: string; }
interface SearchMsg { session_id: string; session_title?: string; role: string; message: string; }
interface SearchRes { sessions?: SearchSession[]; messages?: SearchMsg[]; }
interface UiMsg extends ChatMsg {
  thinking?: string;
  showThinking?: boolean;
  tools?: ToolCall[];
  streaming?: boolean;
  annotatedImage?: string;
}
interface PromptItem { prompt: string; title: string; desc: string; icon: LucideIcon; }

type ToolCallPayload = { function?: { name?: string; arguments?: unknown } };
type SideTab = 'chats' | 'saved' | 'settings';
type TextSize = 'normal' | 'large' | 'xlarge';

/* Bề rộng sidebar cho phép kéo (px). */
const NAV_MIN = 208;
const NAV_MAX = 480;
const NAV_DEFAULT = 264;

const TEXT_SIZE_LABEL: Record<TextSize, string> = {
  normal: 'Cỡ chữ thường',
  large: 'Cỡ chữ lớn',
  xlarge: 'Cỡ chữ rất lớn',
};

/* useLayoutEffect ở client (áp dụng cỡ chữ trước khi vẽ -> không nháy), useEffect ở SSR. */
const useIsoLayoutEffect = typeof window !== 'undefined' ? useLayoutEffect : useEffect;

/* Thông báo dùng Sonner (chuẩn shadcn/ui) — thay cho showToast/sweetalert2. */
type NotifyType = 'success' | 'error' | 'warning' | 'info';
function notify(message: string, type: NotifyType = 'info'): void {
  toast[type](message);
}

function formatTime(iso?: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' });
}

/* Bỏ cú pháp Markdown để đọc to / phát âm thanh cho dễ nghe. */
function plainText(md: string): string {
  return String(md || '')
    .replace(/```[\s\S]*?```/g, ' (đoạn mã) ')
    .replace(/`([^`]+)`/g, '$1')
    .replace(/!\[[^\]]*\]\([^)]*\)/g, '')
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/<[^>]+>/g, ' ')
    .replace(/^\s{0,3}#{1,6}\s*/gm, '')
    .replace(/[*_>~]/g, '')
    .replace(/^\s*[-•]\s*/gm, '')
    .replace(/\n{2,}/g, '. ')
    .replace(/\s+/g, ' ')
    .trim();
}

/* Dải phân cách ngày (Hôm nay / Hôm qua / dd/mm/yyyy) giữa các tin nhắn. */
function DateDivider({ iso }: { iso: string }) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  const today = new Date();
  const yesterday = new Date(today);
  yesterday.setDate(today.getDate() - 1);
  const label = d.toDateString() === today.toDateString()
    ? 'Hôm nay'
    : d.toDateString() === yesterday.toDateString()
      ? 'Hôm qua'
      : d.toLocaleDateString('vi-VN', { day: '2-digit', month: '2-digit', year: 'numeric' });
  return (
    <div className="flex items-center gap-3 py-1">
      <span className="h-px flex-1 bg-white/[0.06]" />
      <span className="text-[11px] text-[var(--gpt-faint)]">{label}</span>
      <span className="h-px flex-1 bg-white/[0.06]" />
    </div>
  );
}

const TOOL_META: Record<string, { label: string }> = {
  scan_phone: { label: 'Kiểm tra SĐT đa tầng' },
  scan_url: { label: 'Quét URL & Website' },
  scan_bank_account: { label: 'Tra cứu tài khoản ngân hàng' },
  stealth_browse: { label: 'Trình duyệt Stealth quét mã độc' },
  query_threat_database: { label: 'Tra cứu CSDL cảnh báo lừa đảo' },
  lookup_company: { label: 'Tra cứu pháp lý doanh nghiệp' },
  get_latest_threat_trends: { label: 'Cập nhật xu hướng lừa đảo' },
  web_search: { label: 'Tìm kiếm mạng diện rộng' },
  web_fetch: { label: 'Tải & bóc tách trang web' },
};

const RESULT_LABELS: Record<string, string> = {
  summary: 'Tóm tắt an ninh',
  is_scam: 'Dấu hiệu lừa đảo',
  risk_level: 'Mức độ rủi ro',
  risk_score: 'Điểm rủi ro (0-100)',
  target_phone: 'Số điện thoại',
  account_number: 'Số tài khoản',
  bank_name: 'Ngân hàng',
  matched_bank: 'Thông tin VietQR',
  url: 'Địa chỉ URL',
  domain: 'Tên miền',
  apex_domain: 'Tên miền gốc',
  query: 'Từ khóa tra cứu',
  found: 'Trạng thái tìm thấy',
  internal_database: 'Cơ sở dữ liệu nội bộ',
  sentinel_reports: 'Tố cáo từ cộng đồng',
  fraud_network: 'Mạng lưới liên kết gian lận',
  stealth_browser_inspection: 'Kết quả duyệt Stealth Browser',
  threat_intel: 'Tình báo đe dọa toàn cầu',
  web_intelligence: 'Thông tin tìm kiếm trên Web',
  scamwave_intel: 'Dữ liệu ScamWave',
  scamwave: 'ScamWave',
  scamadviser: 'ScamAdviser',
  trustpilot: 'Trustpilot',
  tranco: 'Xếp hạng Tranco',
  company_info: 'Hồ sơ doanh nghiệp',
  title: 'Tiêu đề',
  content: 'Chi tiết kết quả',
  links: 'Liên kết tham khảo',
  matched_reports_count: 'Số lượng báo cáo khớp',
  reports: 'Danh sách tố cáo',
  blacklist_matches: 'Khớp danh sách đen',
  trends: 'Xu hướng lừa đảo gần đây',
  recent_high_severity_reports: 'Cảnh báo mức độ cao',
  web_results: 'Kết quả tìm kiếm Web',
};

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function argsSummary(args?: Record<string, unknown>): string {
  if (!args) return '';
  const vals = Object.values(args).filter((v) => v !== null && v !== undefined && v !== '');
  return vals.map((v) => String(v)).join(', ');
}

function normalizeSessionId(v: unknown): string | null {
  const s = String(v ?? '').trim().toLowerCase();
  if (!s || ['none', 'null', 'undefined', 'nan', 'false', '0'].includes(s)) return null;
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(s)) return null;
  return s;
}

function highlightText(text: string, q: string): string {
  const safe = escapeHtml(text);
  if (!q) return safe;
  try {
    const re = new RegExp(`(${escapeRegExp(q)})`, 'gi');
    return safe.replace(re, '<mark class="rounded bg-white/20 px-0.5 text-white">$1</mark>');
  } catch {
    return safe;
  }
}

const QUICK_SCAN: PromptItem[] = [
  { prompt: 'Quét số điện thoại 0373821456 xem có phải lừa đảo không', icon: Phone, title: 'Quét SĐT', desc: 'Kiểm tra số điện thoại có bị báo cáo lừa đảo không.' },
  { prompt: 'Kiểm tra website https://shopee-khuyenmai.vn có an toàn không', icon: Globe, title: 'Quét URL', desc: 'Phát hiện website giả mạo, phishing, malware.' },
  { prompt: 'Kiểm tra tài khoản ngân hàng MB 0373821456789 có an toàn không', icon: Landmark, title: 'Quét TK Bank', desc: 'Tra cứu tài khoản ngân hàng trong CSDL lừa đảo.' },
];
const GENERAL_PROMPTS: PromptItem[] = [
  { prompt: 'Tôi vừa nhận cuộc gọi từ số lạ tự xưng là công an yêu cầu chuyển tiền, phải làm sao?', icon: AlertTriangle, title: 'Phân tích cuộc gọi lạ', desc: 'Phân tích tình huống đáng ngờ và hướng dẫn xử lý.' },
  { prompt: 'Hướng dẫn tôi cách bảo vệ tài khoản ngân hàng và mạng xã hội', icon: ShieldCheck, title: 'Hướng dẫn bảo mật', desc: 'Tư vấn bảo mật cá nhân từ chuyên gia AI.' },
  { prompt: 'Các kịch bản lừa đảo phổ biến nhất hiện nay ở Việt Nam là gì?', icon: Newspaper, title: 'Nhận diện lừa đảo', desc: 'Tìm hiểu các chiêu trò lừa đảo mới nhất.' },
  { prompt: 'Tìm kiếm tin tức mới nhất về an ninh mạng tại Việt Nam', icon: Search, title: 'Tin tức bảo mật', desc: 'Tìm kiếm web về các sự kiện an ninh mạng mới.' },
];

/* Prompt riêng cho chế độ SafeTalk (thấu cảm). */
const SAFE_QUICK: PromptItem[] = [
  { prompt: 'Tôi đang bị quấy rối trên mạng, tôi nên làm gì ngay bây giờ?', icon: ShieldCheck, title: 'Thoát quấy rối', desc: 'Các bước bảo vệ bản thân khi bị tấn công mạng.' },
  { prompt: 'Mình cảm thấy rất áp lực và sợ hãi vì những bình luận tiêu cực về mình...', icon: HeartHandshake, title: 'Lắng nghe', desc: 'Chia sẻ cảm xúc và nhận sự khích lệ từ SafeTalk.' },
  { prompt: 'Hãy cho tôi biết các số điện thoại hỗ trợ khẩn cấp tại Việt Nam', icon: Phone, title: 'Hotline khẩn', desc: 'Danh sách 111, Công an và các quỹ cứu trợ.' },
];
const SAFE_GENERAL: PromptItem[] = [
  { prompt: 'Làm thế nào để báo cáo nội dung bắt nạt trên Facebook/TikTok?', icon: Flag, title: 'Báo cáo vi phạm', desc: 'Hướng dẫn report bài viết và tài khoản độc hại.' },
  { prompt: 'Hãy chia sẻ cho tôi các nguyên tắc về an toàn giới và bao trùm số', icon: Accessibility, title: 'Kiến thức bao trùm', desc: 'Hiểu về quyền con người và sự bình đẳng trên mạng.' },
];

/* Nút icon dùng chung: Button (shadcn) + Tooltip (Radix). */
function IconBtn({
  label, onClick, children, active, disabled, className, side = 'top',
}: {
  label: string;
  onClick?: MouseEventHandler<HTMLButtonElement>;
  children: ReactNode;
  active?: boolean;
  disabled?: boolean;
  className?: string;
  side?: 'top' | 'bottom' | 'left' | 'right';
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          type="button"
          variant="ghost"
          size="icon-sm"
          onClick={onClick}
          disabled={disabled}
          aria-label={label}
          className={cn(
            'text-[var(--gpt-muted)] hover:bg-white/10 hover:text-white',
            active && 'text-white',
            className,
          )}
        >
          {children}
        </Button>
      </TooltipTrigger>
      <TooltipContent side={side}>{label}</TooltipContent>
    </Tooltip>
  );
}

/* Markdown + code-box: bọc mỗi <pre> thành khung có header (tên ngôn ngữ + nút copy → tick xanh). */
function RichMarkdown({ html }: { html: string }) {
  const ref = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const root = ref.current;
    if (!root) return;
    const pres = Array.from(root.querySelectorAll('pre'));
    pres.forEach((pre) => {
      const el = pre as HTMLElement;
      if (el.dataset.gptCoded) return;
      el.dataset.gptCoded = '1';
      const code = pre.querySelector('code');
      let lang = 'code';
      if (code) {
        const cls = Array.from(code.classList).find((c) => c.indexOf('language-') === 0);
        if (cls) lang = cls.replace('language-', '');
      }
      const wrap = document.createElement('div');
      wrap.className = 'gpt-code';
      const head = document.createElement('div');
      head.className = 'gpt-code-head';
      const lab = document.createElement('span');
      lab.className = 'gpt-code-lang';
      lab.textContent = lang;
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'gpt-code-copy';
      const COPY_SVG = '<i class="bi bi-clipboard text-xs"></i><span>Sao chép</span>';
      const OK_SVG = '<i class="bi bi-check2 text-xs"></i><span>Đã chép</span>';
      btn.innerHTML = COPY_SVG;
      btn.onclick = () => {
        const txt = code ? code.innerText : pre.innerText;
        const done = () => {
          btn.classList.add('is-copied');
          btn.innerHTML = OK_SVG;
          window.setTimeout(() => { btn.classList.remove('is-copied'); btn.innerHTML = COPY_SVG; }, 1600);
        };
        try {
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(txt).then(done).catch(done);
          } else { done(); }
        } catch { done(); }
      };
      head.appendChild(lab);
      head.appendChild(btn);
      const parent = pre.parentNode;
      if (parent) {
        parent.insertBefore(wrap, pre);
        wrap.appendChild(head);
        wrap.appendChild(pre);
      }
    });
  }, [html]);
  return (
    <div ref={ref}>
      <MarkdownView html={html} className="md" />
    </div>
  );
}

/* Hàng tin nhắn: user = bubble phải, assistant = text thuần full-width.
 * Actions hiện khi hover: sao chép, thích/không thích, tạo lại, lưu. */
const MessageRow = memo(function MessageRow({
  m, index, isLast, canBookmark, canRate, canSpeak, onCopy, onBookmark, onEdit, onRate, onRegenerate,
  onToggleThinking, onPreview, onSpeak,
}: {
  m: UiMsg;
  index: number;
  isLast: boolean;
  canBookmark: boolean;
  canRate: boolean;
  canSpeak: boolean;
  onCopy: (t: string) => void;
  onBookmark: (id: number) => void;
  onEdit: (m: UiMsg) => void;
  onRate: (id: number | undefined, next: number) => void;
  onRegenerate: () => void;
  onToggleThinking: (i: number) => void;
  onPreview: (src: string | null) => void;
  onSpeak: (t: string) => void;
}) {
  const isUser = m.role === 'user';
  const rating = m.rating || 0;
  const reduce = useReducedMotion();
  return (
    <motion.div
      className="group w-full"
      initial={reduce ? false : { opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.18, ease: 'easeOut' }}
    >
      {isUser ? (
        <div className="flex justify-end">
          <div className="max-w-[75%]">
            {m.images && m.images.length > 0 && (
              <div className="mb-2 flex flex-wrap justify-end gap-2">{m.images.map((src, k) => (
                <img key={k} src={src} alt="" onClick={() => onPreview(src)} className="h-28 w-28 cursor-zoom-in rounded-2xl object-cover hover:opacity-90" />
              ))}</div>
            )}
            <div className="gpt-user-bubble break-words rounded-3xl bg-[var(--gpt-bubble)] px-5 py-2.5 text-[15px] leading-relaxed text-[var(--gpt-text)]">
              <UserMessageContent text={m.message} />
            </div>
            <div className="hover-reveal mt-1 flex items-center justify-end gap-0.5 opacity-0 transition-opacity group-hover:opacity-100 focus-within:opacity-100">
              {formatTime(m.created_at) && <span className="px-1 text-[10px] text-[var(--gpt-faint)]">{formatTime(m.created_at)}</span>}
              <IconBtn label="Sao chép" onClick={() => onCopy(m.message)}><Copy className="size-4" /></IconBtn>
              <IconBtn label="Chỉnh sửa" onClick={() => onEdit(m)}><Pencil className="size-4" /></IconBtn>
            </div>
          </div>
        </div>
      ) : (
        <div className="w-full">
          {(m.thinking || m.showThinking) && (
            <button
              type="button"
              onClick={() => onToggleThinking(index)}
              className="mb-2 flex items-center gap-1.5 rounded-lg px-1 py-0.5 text-[13px] text-[var(--gpt-muted)] hover:text-white"
            >
              <ChevronDown size={14} className={cn('transition-transform', m.showThinking === false && '-rotate-90')} />
              {m.streaming && !m.message ? 'Đang suy nghĩ…' : 'Đã suy nghĩ'}
            </button>
          )}
          {m.showThinking !== false && m.thinking && (
            <div className="mb-3 max-h-56 overflow-y-auto border-l-2 border-white/15 pl-4 text-[13px] whitespace-pre-wrap text-[var(--gpt-muted)]">{m.thinking}</div>
          )}
          {(m.tools || []).map((t, k) => <ToolCard key={`${t.tool}-${k}`} t={t} />)}
          <div className="text-[var(--gpt-text)]">
            {m.streaming && !m.message ? (
              <span className="gpt-dots"><span /><span /><span /></span>
            ) : (
              <RichMarkdown html={renderMd(m.message)} />
            )}
            {m.streaming && m.message ? <span className="gpt-dots"><span /><span /><span /></span> : null}
          </div>
          {m.annotatedImage && (
            <div className="mt-3">
              <Button type="button" variant="secondary" size="sm" onClick={() => onPreview(m.annotatedImage || null)}>
                <ImagePlus className="size-4" /> Xem trước OCR
              </Button>
            </div>
          )}
          {m.metadata && ((m.metadata.internal_knowledge || []).length + (m.metadata.web_search || []).length > 0) && (
            <SourcesAccordion meta={m.metadata} />
          )}
          {!m.streaming && m.metadata?.guardrail?.tier && (
            <ChatGuardrailNote guardrail={m.metadata.guardrail} />
          )}
          {!m.streaming && m.message && (
            <div className="hover-reveal mt-1.5 flex items-center gap-0.5 opacity-0 transition-opacity group-hover:opacity-100 focus-within:opacity-100">
              {canSpeak && <IconBtn label="Đọc to tin nhắn" onClick={() => onSpeak(m.message)}><Volume2 className="size-4" /></IconBtn>}
              <IconBtn label="Sao chép" onClick={() => onCopy(m.message)}><Copy className="size-4" /></IconBtn>
              {canRate && (
                <>
                  <IconBtn label="Câu trả lời hay" active={rating === 1} onClick={() => onRate(m.id, rating === 1 ? 0 : 1)}><ThumbsUp className="size-4" /></IconBtn>
                  <IconBtn label="Câu trả lời chưa tốt" active={rating === -1} onClick={() => onRate(m.id, rating === -1 ? 0 : -1)}><ThumbsDown className="size-4" /></IconBtn>
                </>
              )}
              {isLast && <IconBtn label="Tạo lại câu trả lời" onClick={onRegenerate}><RefreshCw className="size-4" /></IconBtn>}
              {canBookmark && m.id && <IconBtn label="Lưu tin nhắn" onClick={() => onBookmark(m.id as number)}><Bookmark className="size-4" /></IconBtn>}
              {formatTime(m.created_at) && <span className="px-1 text-[10px] text-[var(--gpt-faint)]">{formatTime(m.created_at)}</span>}
            </div>
          )}
        </div>
      )}
    </motion.div>
  );
});

export default function Assistant() {
  const { user } = useAuth();
  const params = useParams();
  const reduce = useReducedMotion();

  /* Đổi URL KHÔNG dùng router.push(): push sang URL khác khiến Next tải RSC của
   * route đó rồi remount trang → mất state + huỷ luồng stream đang chạy.
   * History API được Next tích hợp sẵn (đồng bộ usePathname) mà không remount. */
  const setUrl = useCallback((url: string, replace = false) => {
    try {
      if (typeof window === 'undefined' || window.location.pathname === url) return;
      if (replace) window.history.replaceState(null, '', url);
      else window.history.pushState(null, '', url);
    } catch { /* ignore */ }
  }, []);
  const rawParam = (params as Record<string, string | string[] | undefined>).sessionId;
  const routeSession = normalizeSessionId(Array.isArray(rawParam) ? rawParam[0] : rawParam);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [sessions, setSessions] = useState<ChatSession[]>([]);
  const [folders, setFolders] = useState<ChatFolder[]>([]);
  const [messages, setMessages] = useState<UiMsg[]>([]);
  const [title, setTitle] = useState('Cuộc trò chuyện mới');
  const [status, setStatus] = useState('');
  const [input, setInput] = useState('');
  const [streaming, setStreaming] = useState(false);
  const [tab, setTab] = useState<SideTab>('chats');
  const [query, setQuery] = useState('');
  const [searchRes, setSearchRes] = useState<SearchRes | null>(null);
  const [saved, setSaved] = useState<SavedMsg[]>([]);
  const [safeMode, setSafeMode] = useState(false);
  const [brand, setBrand] = useState<'ShieldCall' | 'FairSpace'>('ShieldCall');
  const [previewOcr, setPreviewOcr] = useState(false);
  // Chế độ dễ đọc (người cao tuổi): 3 mức cỡ chữ, tương phản cao + đọc to.
  const [textSize, setTextSize] = useState<TextSize>('normal');
  const elder = textSize !== 'normal';
  // Sidebar desktop: ẩn/hiện + bề rộng kéo được (người dùng tự chỉnh, nhớ lại).
  const [navCollapsed, setNavCollapsed] = useState(false);
  const [navWidth, setNavWidth] = useState(NAV_DEFAULT);
  const [pendingImages, setPendingImages] = useState<string[]>([]);
  const pendingImagesRef = useRef<string[]>([]);
  pendingImagesRef.current = pendingImages;
  const [editId, setEditId] = useState<number | null>(null);
  const [mobileNav, setMobileNav] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [ocrPreview, setOcrPreview] = useState<string | null>(null);
  const [loadingSession, setLoadingSession] = useState(false);
  const [configSaved, setConfigSaved] = useState(false);
  const [cfg, setCfg] = useState({ tone: 'friendly', language_style: 'simple', custom_name: '', custom_instructions: '' });

  /* Hộp thoại xác nhận / nhập liệu bằng shadcn (AlertDialog + Dialog) thay sweetalert2. */
  const [confirmState, setConfirmState] = useState<{ title: string; text: string; confirmText: string; cancelText: string } | null>(null);
  const confirmResolve = useRef<((v: boolean) => void) | null>(null);
  const askConfirm = useCallback((text: string, opts?: { title?: string; confirmButtonText?: string; cancelButtonText?: string }) => (
    new Promise<boolean>((resolve) => {
      confirmResolve.current = resolve;
      setConfirmState({
        title: opts?.title ?? 'Xác nhận',
        text,
        confirmText: opts?.confirmButtonText ?? 'Đồng ý',
        cancelText: opts?.cancelButtonText ?? 'Hủy',
      });
    })
  ), []);
  const settleConfirm = useCallback((v: boolean) => {
    confirmResolve.current?.(v);
    confirmResolve.current = null;
    setConfirmState(null);
  }, []);

  const [promptState, setPromptState] = useState<{ title: string; value: string; placeholder: string } | null>(null);
  const promptResolve = useRef<((v: string | null) => void) | null>(null);
  const askPrompt = useCallback((opts: { title: string; defaultValue?: string; placeholder?: string }) => (
    new Promise<string | null>((resolve) => {
      promptResolve.current = resolve;
      setPromptState({ title: opts.title, value: opts.defaultValue ?? '', placeholder: opts.placeholder ?? '' });
    })
  ), []);
  const settlePrompt = useCallback((v: string | null) => {
    promptResolve.current?.(v);
    promptResolve.current = null;
    setPromptState(null);
  }, []);

  const abortRef = useRef<AbortController | null>(null);
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const composerRef = useRef<HTMLDivElement | null>(null);
  const atBottomRef = useRef(true);
  const [atBottom, setAtBottom] = useState(true);
  const [composerH, setComposerH] = useState(0);
  const inputRef = useRef<HTMLTextAreaElement | null>(null);
  const lastPasteTimeRef = useRef<number>(0);
  const searchRef = useRef<HTMLInputElement | null>(null);
  const seqRef = useRef(0);
  const cfgTimer = useRef<number | null>(null);
  const sessionIdRef = useRef<string | null>(null);
  // Phiên vừa được tạo trong send(): bỏ qua một lần đồng bộ route để không
  // loadDetail() đè lên và huỷ luồng stream đang chạy.
  const suppressLoadRef = useRef<string | null>(null);
  const sendRef = useRef<((preset?: string) => Promise<void>) | null>(null);

  useEffect(() => { sessionIdRef.current = sessionId; }, [sessionId]);

  const scrollBottom = useCallback((force = false) => {
    const el = wrapRef.current;
    if (!el) return;
    if (!force && !atBottomRef.current) return; // không kéo người dùng đang đọc phía trên
    el.scrollTop = el.scrollHeight;
  }, []);

  const onScrollArea = useCallback(() => {
    const el = wrapRef.current;
    if (!el) return;
    const near = el.scrollHeight - el.scrollTop - el.clientHeight < 140;
    atBottomRef.current = near;
    setAtBottom(near);
  }, []);

  const loadSessions = useCallback(async () => {
    try {
      const s = await api.get<ChatSession[] | { results?: ChatSession[] }>('/chat/sessions/');
      setSessions(Array.isArray(s) ? s : s.results || []);
      if (user) {
        try {
          const f = await api.get<ChatFolder[]>('/chat/folders/');
          setFolders(Array.isArray(f) ? f : []);
        } catch { /* guest */ }
      }
    } catch { /* offline */ }
  }, [user]);

  const syncMessageIds = useCallback(async (sid: string) => {
    try {
      const d = await api.get<{ messages?: Array<{ id?: number }> }>(`/chat/sessions/${sid}/`);
      const server = d.messages || [];
      setMessages((prev) => prev.map((m, i) => (m.id == null && server[i]?.id != null ? { ...m, id: server[i].id } : m)));
    } catch { /* ignore */ }
  }, []);

  const resetHome = useCallback(() => {
    seqRef.current++;
    abortRef.current?.abort();
    setSessionId(null);
    setMessages([]);
    setTitle('Cuộc trò chuyện mới');
    setStatus('');
    setEditId(null);
  }, []);

  const loadDetail = useCallback(async (id: string) => {
    const nid = normalizeSessionId(id);
    if (!nid) return;
    // Đang ở đúng phiên này rồi (kể cả vừa tạo xong và đang stream) -> không nạp lại,
    // tránh xoá tin nhắn / huỷ stream.
    if (nid === sessionIdRef.current) return;
    seqRef.current++;
    abortRef.current?.abort();
    setStreaming(false);
    setSessionId(nid);
    setMessages([]);
    setStatus('');
    setEditId(null);
    setLoadingSession(true);
    try {
      const d = await api.get<{ title?: string; messages?: ChatMsg[] }>(`/chat/sessions/${nid}/`);
      setTitle(d.title || 'Cuộc trò chuyện mới');
      setMessages((d.messages || []).map((m) => ({ ...m })));
      setUrl(`/ai-assistant/${nid}/`);
    } catch {
      notify('Không thể mở hội thoại (đã xóa hoặc không có quyền)', 'warning');
      resetHome();
      setUrl('/ai-assistant/', true);
    } finally {
      setLoadingSession(false);
      setTimeout(scrollBottom, 100);
    }
  }, [setUrl, scrollBottom, resetHome]);

  useEffect(() => { void loadSessions(); }, [loadSessions]);

  useEffect(() => { scrollBottom(); }, [messages, scrollBottom]);

  // Đo chiều cao thật của composer để chừa đúng khoảng trống cho vùng tin nhắn (thay pb cứng).
  useEffect(() => {
    const el = composerRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setComposerH(el.offsetHeight));
    ro.observe(el);
    setComposerH(el.offsetHeight);
    return () => ro.disconnect();
  }, []);

  // FairSpace auto SafeTalk.
  useEffect(() => {
    if (typeof window !== 'undefined' && window.location.href.toLowerCase().includes('fairspace')) {
      setBrand('FairSpace');
      setSafeMode(true);
    }
  }, []);

  // Ghi nhớ tuỳ chọn SafeTalk / Preview OCR giữa các lần truy cập.
  useEffect(() => {
    try {
      if (localStorage.getItem('assistant_safe_mode') === '1') setSafeMode(true);
      if (localStorage.getItem('assistant_preview_ocr') === '1') setPreviewOcr(true);
    } catch { /* ignore */ }
  }, []);
  useEffect(() => {
    try { localStorage.setItem('assistant_safe_mode', safeMode ? '1' : '0'); } catch { /* ignore */ }
  }, [safeMode]);
  useEffect(() => {
    try { localStorage.setItem('assistant_preview_ocr', previewOcr ? '1' : '0'); } catch { /* ignore */ }
  }, [previewOcr]);

  // Chế độ dễ đọc: đọc cấu hình đã lưu TRƯỚC khi vẽ (layout effect) để không nháy cỡ chữ.
  const textSizeRef = useRef<TextSize>('normal');
  useIsoLayoutEffect(() => {
    let saved: TextSize = 'normal';
    try {
      const v = localStorage.getItem('assistant_text_size');
      if (v === 'large' || v === 'xlarge' || v === 'normal') saved = v;
      else if (localStorage.getItem('assistant_elder') === '1') saved = 'large';
    } catch { /* ignore */ }
    if (saved !== 'normal') {
      textSizeRef.current = saved;
      setTextSize(saved);
    }
  }, []);

  // Sidebar: đọc cấu hình đã lưu TRƯỚC khi vẽ để không nhảy kích thước.
  const navWidthRef = useRef(NAV_DEFAULT);
  useIsoLayoutEffect(() => {
    try {
      if (localStorage.getItem('assistant_nav_collapsed') === '1') setNavCollapsed(true);
      const w = Number(localStorage.getItem('assistant_nav_width') || '');
      if (Number.isFinite(w) && w >= NAV_MIN && w <= NAV_MAX) {
        navWidthRef.current = w;
        setNavWidth(w);
      }
    } catch { /* ignore */ }
  }, []);
  useEffect(() => {
    try { localStorage.setItem('assistant_nav_collapsed', navCollapsed ? '1' : '0'); } catch { /* ignore */ }
  }, [navCollapsed]);

  /* Kéo vách ngăn để đổi bề rộng sidebar (desktop). */
  const resizeRef = useRef<{ x: number; w: number } | null>(null);
  const onResizeStart = useCallback((e: PointerEvent<HTMLDivElement>) => {
    resizeRef.current = { x: e.clientX, w: navWidthRef.current };
    try { (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId); } catch { /* ignore */ }
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  }, []);
  const onResizeMove = useCallback((e: PointerEvent<HTMLDivElement>) => {
    const r = resizeRef.current;
    if (!r) return;
    const next = Math.min(NAV_MAX, Math.max(NAV_MIN, r.w + (e.clientX - r.x)));
    navWidthRef.current = next;
    setNavWidth(next);
  }, []);
  const onResizeEnd = useCallback(() => {
    if (!resizeRef.current) return;
    resizeRef.current = null;
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
    try { localStorage.setItem('assistant_nav_width', String(navWidthRef.current)); } catch { /* ignore */ }
  }, []);

  // Dừng đọc to khi rời trang.
  useEffect(() => () => {
    try { window.speechSynthesis?.cancel(); } catch { /* ignore */ }
  }, []);

  // Tắt lớp lưới nền toàn site (body::before) khi ở trang assistant cho đỡ rối mắt.
  useEffect(() => {
    document.body.classList.add('assistant-route');
    return () => { document.body.classList.remove('assistant-route'); };
  }, []);

  /* Đọc to 1 tin nhắn (Web Speech API, tiếng Việt). */
  const speak = useCallback((text: string) => {
    if (typeof window === 'undefined' || !('speechSynthesis' in window)) {
      notify('Trình duyệt không hỗ trợ đọc to', 'warning');
      return;
    }
    try {
      const synth = window.speechSynthesis;
      synth.cancel();
      const u = new SpeechSynthesisUtterance(plainText(text).slice(0, 4000));
      u.lang = 'vi-VN';
      u.rate = 0.95;
      synth.speak(u);
    } catch {
      notify('Không đọc được nội dung', 'error');
    }
  }, []);

  /* Đổi cỡ chữ: tính giá trị kế tiếp BÊN NGOÀI updater (updater phải thuần —
   * đặt notify() trong đó sẽ bắn 2 toast mỗi lần bấm). Dùng ref để bấm nhanh
   * liên tiếp vẫn lên đúng từng mức. */
  const cycleTextSize = useCallback(() => {
    const cur = textSizeRef.current;
    const next: TextSize = cur === 'normal' ? 'large' : cur === 'large' ? 'xlarge' : 'normal';
    textSizeRef.current = next;
    setTextSize(next);
    try { localStorage.setItem('assistant_text_size', next); } catch { /* ignore */ }
    notify(TEXT_SIZE_LABEL[next], 'info');
  }, []);

  // Phím tắt: Ctrl/Cmd+K -> tìm kiếm, Esc -> đóng sidebar mobile.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        searchRef.current?.focus();
      } else if (e.key === 'Escape') {
        setMobileNav(false);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  // search debounce
  useEffect(() => {
    if (query.trim().length < 2) { setSearchRes(null); return; }
    const t = window.setTimeout(async () => {
      try {
        setSearchRes(await api.get<SearchRes>(`/chat/search/?q=${encodeURIComponent(query.trim())}`));
      } catch { /* ignore */ }
    }, 400);
    return () => window.clearTimeout(t);
  }, [query]);

  const loadSaved = useCallback(async () => {
    try {
      const s = await api.get<SavedMsg[]>('/chat/saved/');
      setSaved(Array.isArray(s) ? s : []);
    } catch { /* ignore */ }
  }, []);

  const loadConfig = useCallback(async () => {
    try {
      const d = await api.get<Record<string, string>>('/chat/config/');
      setCfg({ tone: d.tone || 'friendly', language_style: d.language_style || 'simple', custom_name: d.custom_name || '', custom_instructions: d.custom_instructions || '' });
    } catch { /* ignore */ }
  }, []);

  useEffect(() => {
    if (tab === 'saved' && user) void loadSaved();
    if (tab === 'settings' && user) void loadConfig();
  }, [tab, user, loadSaved, loadConfig]);

  const saveConfig = (next: typeof cfg) => {
    setCfg(next);
    if (cfgTimer.current) window.clearTimeout(cfgTimer.current);
    cfgTimer.current = window.setTimeout(async () => {
      try {
        await api.put('/chat/config/', { tone: next.tone, language_style: next.language_style, custom_name: next.custom_name, custom_instructions: next.custom_instructions });
        setConfigSaved(true);
        window.setTimeout(() => setConfigSaved(false), 2000);
      } catch { notify('Lỗi khi lưu cài đặt', 'error'); }
    }, 600);
  };

  const newChat = () => {
    resetHome();
    setUrl('/ai-assistant/');
    inputRef.current?.focus();
  };

  /* Đồng bộ theo URL: back/forward hoặc gõ URL trực tiếp. Chỉ reset khi THẬT SỰ
   * rời khỏi một phiên (routeSession từ có -> không), tránh reset nhầm lúc mới tạo phiên. */
  const prevRouteRef = useRef<string | null>(null);
  useEffect(() => {
    const prev = prevRouteRef.current;
    prevRouteRef.current = routeSession;
    if (routeSession) {
      if (routeSession === sessionIdRef.current) { suppressLoadRef.current = null; return; }
      if (routeSession === suppressLoadRef.current) { suppressLoadRef.current = null; return; }
      void loadDetail(routeSession);
    } else if (prev) {
      resetHome();
    }
  }, [routeSession, loadDetail, resetHome]);

  const addFiles = useCallback((files: File[]) => {
    let room = 4 - pendingImagesRef.current.length;
    let warned = false;
    files.forEach((f) => {
      if (!f.type.startsWith('image/')) return;
      if (room <= 0) {
        if (!warned) { notify('Tối đa 4 ảnh mỗi tin nhắn', 'warning'); warned = true; }
        return;
      }
      if (f.size > 5 * 1024 * 1024) {
        notify(`Ảnh ${f.name} quá lớn (tối đa 5MB)`, 'warning');
        return;
      }
      room--;
      const r = new FileReader();
      r.onload = (ev) => {
        const dataUrl = String(ev.target?.result || '');
        if (!dataUrl) return;
        setPendingImages((p) => (p.length >= 4 ? p : [...p, dataUrl]));
      };
      r.readAsDataURL(f);
    });
  }, [notify]);

  const extractImagesFromClipboard = useCallback((e: React.ClipboardEvent | ClipboardEvent): File[] => {
    const data = e.clipboardData;
    if (!data) return [];
    const imageFiles: File[] = [];

    // 1. Check data.items (standard for screenshots copied to clipboard)
    if (data.items && data.items.length > 0) {
      for (let i = 0; i < data.items.length; i++) {
        const item = data.items[i];
        if (item.type.startsWith('image/')) {
          const file = item.getAsFile();
          if (file) {
            const ext = file.type.split('/')[1] || 'png';
            const cleanName = file.name && file.name !== 'image.png'
              ? file.name
              : `screenshot-${Date.now()}.${ext}`;
            const namedFile = new File([file], cleanName, { type: file.type });
            imageFiles.push(namedFile);
          }
        }
      }
    }

    // 2. Check data.files fallback
    if (imageFiles.length === 0 && data.files && data.files.length > 0) {
      for (let i = 0; i < data.files.length; i++) {
        const file = data.files[i];
        if (file.type.startsWith('image/')) {
          imageFiles.push(file);
        }
      }
    }

    return imageFiles;
  }, []);

  const onPaste = useCallback((e: React.ClipboardEvent) => {
    const now = Date.now();
    if (now - lastPasteTimeRef.current < 400) {
      e.preventDefault();
      e.stopPropagation();
      return;
    }
    const images = extractImagesFromClipboard(e);
    if (images.length > 0) {
      e.preventDefault();
      e.stopPropagation();
      lastPasteTimeRef.current = now;
      addFiles(images);
      notify(`Đã dán ${images.length} ảnh từ bộ nhớ tạm`, 'info');
    }
  }, [extractImagesFromClipboard, addFiles, notify]);

  useEffect(() => {
    const handleGlobalPaste = (e: ClipboardEvent) => {
      const target = e.target as HTMLElement | null;
      if (
        !target ||
        target === inputRef.current ||
        composerRef.current?.contains(target) ||
        target.tagName === 'INPUT' ||
        target.tagName === 'TEXTAREA' ||
        target.isContentEditable
      ) {
        return;
      }
      const now = Date.now();
      if (now - lastPasteTimeRef.current < 400) {
        e.preventDefault();
        return;
      }
      const images = extractImagesFromClipboard(e);
      if (images.length > 0) {
        e.preventDefault();
        lastPasteTimeRef.current = now;
        addFiles(images);
        notify(`Đã dán ${images.length} ảnh từ bộ nhớ tạm`, 'info');
        inputRef.current?.focus();
      }
    };
    window.addEventListener('paste', handleGlobalPaste);
    return () => {
      window.removeEventListener('paste', handleGlobalPaste);
    };
  }, [extractImagesFromClipboard, addFiles, notify]);

  const onFiles = (e: FormEvent<HTMLInputElement>) => {
    addFiles(Array.from((e.target as HTMLInputElement).files || []));
    (e.target as HTMLInputElement).value = '';
  };

  const onDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragOver(false);
    addFiles(Array.from(e.dataTransfer?.files || []));
  };

  const stop = () => {
    abortRef.current?.abort();
    setStreaming(false);
    setStatus('');
    notify('Đã dừng phản hồi', 'info');
  };

  const send = async (preset?: string) => {
    const text = (preset ?? input).trim();
    if ((!text && pendingImages.length === 0) || streaming) return;
    let sid = sessionId;
    if (!sid) {
      try {
        const d = await api.post<{ id: string }>('/chat/sessions/', {});
        const nid = normalizeSessionId(d.id);
        if (!nid) throw new Error('invalid');
        sid = nid;
        suppressLoadRef.current = nid;
        setSessionId(nid);
        setUrl(`/ai-assistant/${nid}/`);
        void loadSessions();
      } catch {
        notify('Không thể tạo hội thoại mới', 'error');
        return;
      }
    }
    if (editId) {
      try { await api.del(`/chat/messages/${editId}/delete_after/`); } catch { /* ignore */ }
      setMessages((ms) => ms.filter((m) => (m.id ?? -1) < editId));
      setEditId(null);
    }
    const imgs = [...pendingImages];
    // Người dùng vừa gửi -> luôn kéo xuống cuối, kể cả trước đó đang đọc phía trên.
    atBottomRef.current = true;
    setAtBottom(true);
    setMessages((ms) => [...ms, { role: 'user', message: text, images: imgs }]);
    setInput('');
    setPendingImages([]);
    setStreaming(true);
    setStatus('AI đang xử lý...');
    const seq = ++seqRef.current;
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    const botIdxRef = { i: -1 };
    setMessages((ms) => {
      botIdxRef.i = ms.length;
      return [...ms, { role: 'assistant', message: '', streaming: true, tools: [], thinking: '' }];
    });
    let full = '';
    let thinking = '';
    const patchBot = (fn: (m: UiMsg) => UiMsg) => {
      setMessages((ms) => ms.map((m, i) => (i === botIdxRef.i ? fn(m) : m)));
    };
    try {
      await openSseStream({
        url: '/api/v1/chat/stream/',
        signal: ctrl.signal,
        body: { user_message: text, session_id: sid, images: imgs, preview_ocr: previewOcr, safe_mode: safeMode },
        onEvent: (ev) => {
          switch (ev.type) {
            case 'delta': {
              if (!ev.text) break;
              setStatus('AI đang trả lời...');
              full += ev.text;
              const snapshot = full;
              patchBot((m) => ({
                ...m,
                message: snapshot,
                showThinking: m.thinking ? false : m.showThinking,
                tools: (m.tools || []).map((t) => (t.done ? t : { ...t, done: true })),
              }));
              break;
            }
            case 'thinking': {
              thinking += ev.text;
              const t = thinking;
              patchBot((m) => ({ ...m, thinking: t, showThinking: true }));
              break;
            }
            case 'status': {
              const st = ev.value;
              if (st === 'searching_knowledge') setStatus('AI đang tìm thông tin...');
              else if (st === 'processing_images') setStatus('AI đang xử lý hình ảnh...');
              else if (st === 'thinking') {
                setStatus('AI đang suy nghĩ...');
                patchBot((m) => ({ ...m, showThinking: true }));
              } else if (st === 'answering') setStatus('AI đang trả lời...');
              else if (st.startsWith('executing_tool:')) {
                const tn = st.substring('executing_tool:'.length);
                setStatus(`${(TOOL_META[tn] || { label: tn }).label}...`);
                patchBot((m) => {
                  const tools = [...(m.tools || [])];
                  if (!tools.some((t) => t.tool === tn && !t.done)) {
                    tools.push({ tool: tn, done: false, label: (TOOL_META[tn] || { label: tn }).label });
                  }
                  return { ...m, tools };
                });
              } else setStatus('AI đang xử lý...');
              break;
            }
            case 'metadata':
              patchBot((m) => ({ ...m, metadata: { ...(m.metadata || {}), ...(ev.metadata as MsgMeta) } }));
              break;
            case 'guardrail':
              patchBot((m) => ({ ...m, metadata: { ...(m.metadata || {}), guardrail: ev.guardrail as GuardrailData } }));
              break;
            case 'tool_calls':
              for (const raw of ev.calls as ToolCallPayload[]) {
                const name = raw?.function?.name;
                if (!name) continue;
                const args = raw.function?.arguments as Record<string, unknown> | undefined;
                patchBot((m) => {
                  const tools = [...(m.tools || [])];
                  const idx = tools.findIndex((t) => t.tool === name && !t.done);
                  if (idx >= 0) tools[idx] = { ...tools[idx], args };
                  else tools.push({ tool: name, args, done: false, label: (TOOL_META[name] || { label: name }).label });
                  return { ...m, tools };
                });
              }
              break;
            case 'tool_result': {
              if (!ev.tool) break;
              const tool = ev.tool;
              patchBot((m) => {
                const tools = [...(m.tools || [])];
                for (let k = tools.length - 1; k >= 0; k--) {
                  if (tools[k].tool === tool && !tools[k].done) {
                    tools[k] = { ...tools[k], done: true, result: ev.result, args: tools[k].args || (ev.args as Record<string, unknown> | undefined) };
                    break;
                  }
                }
                return { ...m, tools };
              });
              break;
            }
            case 'image':
              if (ev.annotated_image) patchBot((m) => ({ ...m, annotatedImage: ev.annotated_image }));
              break;
            case 'title':
              if (ev.value && ev.value !== 'Guest Session') setTitle(ev.value);
              break;
            case 'error':
              notify(ev.message, 'error');
              // Không để bong bóng trống: nếu AI chưa trả được gì thì đặt câu nhắc để còn nút "Tạo lại".
              patchBot((m) => (m.message ? m : { ...m, message: 'Xin lỗi, AI đang gặp sự cố. Bạn thử lại giúp mình nhé.' }));
              break;
            case 'done': {
              const nsid = normalizeSessionId(ev.session_id);
              if (nsid) { sid = nsid; setSessionId(nsid); }
              if (ev.title && ev.title !== 'Guest Session') setTitle(ev.title);
              patchBot((m) => ({ ...m, streaming: false }));
              break;
            }
            default:
              break;
          }
          scrollBottom();
        },
      });
    } catch (e) {
      if ((e as Error).name !== 'AbortError') {
        patchBot((m) => ({ ...m, message: full || 'Lỗi kết nối AI, vui lòng thử lại.' }));
        notify('Lỗi kết nối AI', 'error');
      }
    } finally {
      if (seqRef.current === seq) {
        setStreaming(false);
        setStatus('');
        patchBot((m) => ({ ...m, streaming: false }));
        void loadSessions();
        if (sid) void syncMessageIds(sid);
        scrollBottom();
      }
    }
  };
  useEffect(() => { sendRef.current = send; });

  const copyText = useCallback((t: string) => {
    if (!navigator.clipboard || !navigator.clipboard.writeText) { notify('Trình duyệt không hỗ trợ sao chép', 'warning'); return; }
    navigator.clipboard.writeText(t).then(() => notify('Đã sao chép', 'success')).catch(() => notify('Không thể sao chép', 'error'));
  }, []);

  const toggleBookmark = useCallback(async (messageId?: number) => {
    if (!messageId) return;
    try {
      const d = await api.post<{ status?: string }>('/chat/saved/', { message_id: messageId });
      notify(d.status === 'unsaved' ? 'Đã bỏ lưu' : 'Đã lưu tin nhắn', d.status === 'unsaved' ? 'info' : 'success');
      if (tabRef.current === 'saved') void loadSaved();
    } catch { notify('Lỗi khi lưu', 'error'); }
  }, [loadSaved]);

  /* Thích/không thích câu trả lời (lưu server, hiển thị ngay). */
  const rateMessage = useCallback(async (id: number | undefined, next: number) => {
    if (!id) return;
    setMessages((ms) => ms.map((m) => (m.id === id ? { ...m, rating: next } : m)));
    try {
      await api.patch(`/chat/messages/${id}/rating/`, { rating: next });
    } catch { notify('Không lưu được đánh giá', 'error'); }
  }, []);

  const messagesRef = useRef<UiMsg[]>([]);
  useEffect(() => { messagesRef.current = messages; }, [messages]);
  // Ref hoá các state hay đổi để callback giữ nguyên identity -> MessageRow memo
  // không bị re-render hàng loạt khi tab/streaming thay đổi.
  const tabRef = useRef<SideTab>('chats');
  useEffect(() => { tabRef.current = tab; }, [tab]);
  const streamingRef = useRef(false);
  useEffect(() => { streamingRef.current = streaming; }, [streaming]);

  /* Tạo lại câu trả lời cuối: xóa các tin sau tin user cuối rồi gửi lại. */
  const regenerate = useCallback(async () => {
    if (streamingRef.current) return;
    const ms = messagesRef.current;
    for (let i = ms.length - 1; i >= 0; i--) {
      if (ms[i].role === 'user' && (ms[i].message || '').trim()) {
        const text = ms[i].message;
        const uid = ms[i].id;
        if (uid != null) {
          try { await api.del(`/chat/messages/${uid}/delete_after/`); } catch { /* tiếp tục local */ }
        }
        setMessages((prev) => prev.filter((_, xi) => xi < i));
        await sendRef.current?.(text);
        return;
      }
    }
  }, []);

  /* Xuất hội thoại ra file Markdown để lưu trữ / chia sẻ. */
  const exportChat = useCallback(() => {
    const ms = messagesRef.current;
    if (!ms.length) { notify('Chưa có nội dung để xuất', 'info'); return; }
    const lines: string[] = [
      `# ${title}`,
      '',
      `_${brand} · xuất lúc ${new Date().toLocaleString('vi-VN')}_`,
      '',
    ];
    for (const m of ms) {
      lines.push(m.role === 'user' ? '## Bạn' : `## ${brand} AI`, '', m.message || '', '');
    }
    const slug = (title || 'hoi-thoai')
      .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
      .replace(/[^a-zA-Z0-9\s-]/g, '').trim().replace(/\s+/g, '-').slice(0, 60) || 'hoi-thoai';
    const blob = new Blob([lines.join('\n')], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${slug}.md`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    notify('Đã xuất hội thoại (.md)', 'success');
  }, [brand, title]);

  const handleEdit = useCallback((m: UiMsg) => {
    setEditId(m.id ?? null);
    setInput(m.message);
    inputRef.current?.focus();
  }, []);

  const handleToggleThinking = useCallback((i: number) => {
    setMessages((ms) => ms.map((x, xi) => (xi === i ? { ...x, showThinking: x.showThinking === false } : x)));
  }, []);

  const removeSaved = async (id: number) => {
    try {
      await api.del(`/chat/saved/${id}/`);
      setSaved((s) => s.filter((x) => x.id !== id));
      notify('Đã xóa khỏi danh sách lưu', 'info');
    } catch { notify('Không thể xóa', 'error'); }
  };

  const delSession = async (id: string) => {
    const ok = await askConfirm('Hội thoại sẽ bị xóa vĩnh viễn.', { title: 'Xóa hội thoại?', confirmButtonText: 'Xóa' });
    if (!ok) return;
    await api.del(`/chat/sessions/${id}/`);
    if (sessionId === id) { resetHome(); setUrl('/ai-assistant/', true); }
    void loadSessions();
  };

  const renameSession = async (id: string, cur: string) => {
    const v = await askPrompt({ title: 'Đổi tên cuộc trò chuyện', defaultValue: cur });
    if (v && v !== cur) {
      await api.patch(`/chat/sessions/${id}/`, { title: v });
      if (sessionId === id) setTitle(v);
      void loadSessions();
    }
  };

  /* Đổi tên hội thoại đang mở ngay từ header. */
  const renameCurrent = async () => {
    if (!sessionId) return;
    const v = await askPrompt({ title: 'Đổi tên cuộc trò chuyện', defaultValue: title });
    if (v && v !== title) {
      try {
        await api.patch(`/chat/sessions/${sessionId}/`, { title: v });
        setTitle(v);
        void loadSessions();
      } catch { notify('Không đổi được tên', 'error'); }
    }
  };

  const clearAll = async () => {
    const ok = await askConfirm('Hành động này sẽ xóa vĩnh viễn tất cả cuộc trò chuyện của bạn.', { title: 'Xóa toàn bộ lịch sử?', confirmButtonText: 'Xóa tất cả' });
    if (!ok) return;
    try {
      await api.del('/chat/sessions/clear_all/');
      resetHome();
      void loadSessions();
      notify('Đã xóa toàn bộ lịch sử', 'success');
    } catch { notify('Không thể xóa lịch sử', 'error'); }
  };

  const createFolder = async () => {
    const v = await askPrompt({ title: 'Tạo thư mục mới', placeholder: 'Tên thư mục...' });
    if (v) {
      await api.post('/chat/folders/', { name: v });
      void loadSessions();
    }
  };

  const renameFolder = async (id: number, cur: string) => {
    const v = await askPrompt({ title: 'Đổi tên thư mục', defaultValue: cur });
    if (v && v !== cur) {
      await api.patch(`/chat/folders/${id}/`, { name: v });
      void loadSessions();
    }
  };

  const deleteFolder = async (id: number) => {
    const ok = await askConfirm('Các cuộc trò chuyện bên trong sẽ không bị xóa.', { title: 'Xóa thư mục?', confirmButtonText: 'Xóa' });
    if (!ok) return;
    await api.del(`/chat/folders/${id}/`);
    void loadSessions();
  };

  const handleDropToFolder = async (e: DragEvent<HTMLElement>, folderId: number | null) => {
    e.preventDefault();
    const sessId = e.dataTransfer.getData('sessionId');
    setDragOver(false);
    if (!sessId) return;
    try {
      await api.patch(`/chat/sessions/${sessId}/`, { folder_id: folderId ?? '' });
      void loadSessions();
    } catch { notify('Không thể di chuyển hội thoại', 'error'); }
  };

  const toggleSafeMode = () => {
    const next = !safeMode;
    setSafeMode(next);
    if (next) {
      notify('Đã bật chế độ SafeTalk thấu cảm', 'success');
      if (!input.trim() || input.includes('Chào')) {
        setInput(brand === 'FairSpace' ? 'Chào bạn, mình cần một người để chia sẻ...' : 'Chào Shield, mình cần một người để chia sẻ...');
      }
    } else {
      notify('Đã tắt chế độ SafeTalk', 'info');
    }
  };

  const swipeRef = useRef<{ x: number; y: number } | null>(null);

  const onNavTouchStart = useCallback((e: TouchEvent) => {
    const t = e.touches[0];
    swipeRef.current = { x: t.clientX, y: t.clientY };
  }, []);

  /* Vuốt sang trái để đóng sidebar trên điện thoại. */
  const onNavTouchEnd = useCallback((e: TouchEvent) => {
    const s = swipeRef.current;
    swipeRef.current = null;
    if (!s || !mobileNav) return;
    const t = e.changedTouches[0];
    const dx = t.clientX - s.x;
    const dy = t.clientY - s.y;
    if (dx < -60 && Math.abs(dx) > Math.abs(dy) * 1.5) setMobileNav(false);
  }, [mobileNav]);

  const ungrouped = sessions.filter((s) => !s.folder);
  const quickScan = safeMode ? SAFE_QUICK : QUICK_SCAN;
  const generalPrompts = safeMode ? SAFE_GENERAL : GENERAL_PROMPTS;

  return (
    <TooltipProvider delayDuration={250}>
      <div className={cn('gpt -m-0 flex h-screen overflow-hidden', elder && 'gpt-elder', textSize === 'xlarge' && 'gpt-size-xlarge')} style={{ height: '100%' }}>
        <AnimatePresence>
          {mobileNav && (
            <motion.div
              key="nav-overlay"
              className="fixed inset-0 z-20 bg-black/60 md:hidden"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.18, ease: 'easeOut' }}
              onClick={() => setMobileNav(false)}
              aria-hidden="true"
            />
          )}
        </AnimatePresence>

        {/* ── Sidebar ── */}
        <aside
          className={cn(
            'z-40 flex min-h-0 shrink-0 flex-col overflow-hidden bg-[var(--gpt-side)]',
            // Mobile: trượt vào/ra từ cạnh trái. Desktop: hiển thị tĩnh, có thể ẩn.
            'max-md:fixed max-md:inset-y-0 max-md:left-0 max-md:transition-all max-md:duration-200 max-md:ease-out',
            mobileNav ? 'max-md:visible max-md:translate-x-0 max-md:shadow-2xl' : 'max-md:invisible max-md:-translate-x-full',
            navCollapsed ? 'md:hidden' : 'md:flex',
          )}
          style={{ width: `min(${navWidth}px, 85vw)` }}
          onTouchStart={onNavTouchStart}
          onTouchEnd={onNavTouchEnd}
        >
          <div className="flex items-center gap-1 p-3">
            <Button
              type="button"
              variant="ghost"
              onClick={() => { newChat(); setMobileNav(false); }}
              className="flex-1 justify-start gap-2.5 px-2.5 text-sm text-[var(--gpt-text)] hover:bg-[var(--gpt-accent-soft)] hover:text-[var(--gpt-accent)]"
            >
              <Plus className="size-[18px] shrink-0" /> Hội thoại mới
            </Button>
            <IconBtn label="Đóng" onClick={() => setMobileNav(false)} className="shrink-0 md:hidden">
              <X className="size-4" />
            </IconBtn>
          </div>

          <div className="px-3 pb-2">
            <div className="relative">
              <Search className="pointer-events-none absolute top-1/2 left-3 size-3.5 -translate-y-1/2 text-[var(--gpt-faint)]" />
              <Input
                ref={searchRef}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Tìm kiếm đoạn chat"
                title="Ctrl/Cmd+K"
                className="h-9 border-white/10 bg-transparent pl-9 pr-8 text-sm text-[var(--gpt-text)] placeholder:text-[var(--gpt-faint)] focus-visible:border-white/25 focus-visible:ring-0"
              />
              {query && (
                <button
                  type="button"
                  onClick={() => { setQuery(''); setSearchRes(null); }}
                  aria-label="Xóa tìm kiếm"
                  className="absolute top-1/2 right-2 -translate-y-1/2 text-[var(--gpt-faint)] hover:text-white"
                >
                  <X className="size-3.5" />
                </button>
              )}
            </div>
            {searchRes && (
              <div className="mt-2 max-h-60 space-y-1 overflow-y-auto">
                {(searchRes.sessions || []).length > 0 && <div className="px-2 py-1 text-[11px] font-medium text-[var(--gpt-faint)]">Đoạn chat</div>}
                {(searchRes.sessions || []).map((s) => (
                  <button key={s.id} type="button" onClick={() => { void loadDetail(s.id); setQuery(''); setSearchRes(null); setMobileNav(false); }} className="w-full truncate rounded-lg p-2 text-left text-sm text-[var(--gpt-text)] hover:bg-white/[0.06]">{s.title}</button>
                ))}
                {(searchRes.messages || []).length > 0 && <div className="mt-1 px-2 py-1 text-[11px] font-medium text-[var(--gpt-faint)]">Tin nhắn</div>}
                {(searchRes.messages || []).map((m, i) => (
                  <button key={i} type="button" onClick={() => { void loadDetail(m.session_id); setQuery(''); setSearchRes(null); setMobileNav(false); }} className="w-full rounded-lg p-2 text-left hover:bg-white/[0.06]">
                    <div className="mb-0.5 truncate text-[11px] text-[var(--gpt-faint)]">{m.session_title}</div>
                    <div className="line-clamp-2 text-[13px] text-[var(--gpt-text)]" dangerouslySetInnerHTML={{ __html: highlightText(m.message, query) }} />
                  </button>
                ))}
                {(searchRes.sessions || []).length === 0 && (searchRes.messages || []).length === 0 && <div className="py-4 text-center text-xs text-[var(--gpt-faint)]">Không tìm thấy kết quả</div>}
              </div>
            )}
          </div>

          <Tabs value={tab} onValueChange={(v) => setTab(v as SideTab)} className="min-h-0 flex-1 flex-col">
            <TabsList className="mx-3 grid h-8 w-auto grid-cols-3">
              <TabsTrigger value="chats" className="px-1 text-[11px] data-active:text-[var(--gpt-accent)]">Đoạn chat</TabsTrigger>
              <TabsTrigger value="saved" className="px-1 text-[11px] data-active:text-[var(--gpt-accent)]">Đã lưu</TabsTrigger>
              <TabsTrigger value="settings" className="px-1 text-[11px] data-active:text-[var(--gpt-accent)]">Cài đặt</TabsTrigger>
            </TabsList>

            {/* Đoạn chat */}
            <TabsContent value="chats" className="flex min-h-0 flex-1 flex-col">
              <div className="flex items-center justify-between px-4 pt-1 pb-1">
                <h3 className="px-2 text-[13px] font-medium text-[var(--gpt-text)]">Đoạn chat</h3>
                <div className="flex items-center gap-0.5">
                  {user && <IconBtn label="Thư mục mới" onClick={createFolder}><FolderPlus className="size-4" /></IconBtn>}
                  <IconBtn label="Xóa toàn bộ" onClick={clearAll}><Trash2 className="size-4" /></IconBtn>
                </div>
              </div>
              <ScrollArea className="min-h-0 flex-1">
                <div className="px-3 pb-2">
                  {folders.map((f) => (
                    <details key={f.id} className="group/folder mb-1">
                      <summary
                        className="flex cursor-pointer list-none items-center justify-between rounded-lg p-2 text-[var(--gpt-muted)] transition-colors hover:bg-white/[0.06] hover:text-white"
                        onDragOver={(e) => e.preventDefault()}
                        onDrop={(e) => { void handleDropToFolder(e, f.id); }}
                      >
                        <span className="flex min-w-0 flex-1 items-center gap-2 overflow-hidden">
                          <FolderPlus className="size-3.5 shrink-0 text-[var(--gpt-faint)]" />
                          <span className="min-w-0 truncate text-xs font-medium">{f.name}</span>
                        </span>
                        <span className="hover-reveal flex shrink-0 items-center gap-0.5 opacity-0 transition-opacity group-hover/folder:opacity-100">
                          <IconBtn label="Đổi tên thư mục" onClick={(e) => { e.preventDefault(); e.stopPropagation(); void renameFolder(f.id, f.name); }}><Pencil className="size-3.5" /></IconBtn>
                          <IconBtn label="Xóa thư mục" onClick={(e) => { e.preventDefault(); e.stopPropagation(); void deleteFolder(f.id); }}><X className="size-3.5" /></IconBtn>
                        </span>
                      </summary>
                      <div className="mt-1 space-y-0.5 pl-3">
                        {sessions.filter((s) => s.folder === f.id).map((s) => (
                          <SessionRow key={s.id} s={s} active={sessionId === s.id} onOpen={() => loadDetail(s.id)} onRename={() => renameSession(s.id, s.title || '')} onDelete={() => delSession(s.id)} />
                        ))}
                      </div>
                    </details>
                  ))}
                  {ungrouped.length > 0 && (
                    <div
                      className="mt-2 mb-1 px-3 py-2 text-[11px] font-medium text-[var(--gpt-faint)]"
                      onDragOver={(e) => e.preventDefault()}
                      onDrop={(e) => { void handleDropToFolder(e, null); }}
                    >
                      Trò chuyện gần đây
                    </div>
                  )}
                  {ungrouped.map((s) => (
                    <SessionRow key={s.id} s={s} active={sessionId === s.id} onOpen={() => loadDetail(s.id)} onRename={() => renameSession(s.id, s.title || '')} onDelete={() => delSession(s.id)} />
                  ))}
                  {sessions.length === 0 && (
                    <div className="py-10 text-center text-[var(--gpt-faint)]">
                      <p className="text-xs">Chưa có hội thoại nào</p>
                    </div>
                  )}
                </div>
              </ScrollArea>
            </TabsContent>

            {/* Đã lưu */}
            <TabsContent value="saved" className="flex min-h-0 flex-1 flex-col">
              <div className="flex items-center justify-between px-5 py-2">
                <h3 className="text-[13px] font-medium text-[var(--gpt-text)]">Tin nhắn đã lưu</h3>
                <Badge variant="secondary">{saved.length}</Badge>
              </div>
              <ScrollArea className="min-h-0 flex-1">
                <div className="space-y-2 px-3 pb-3">
                  {!user && (
                    <div className="py-8 text-center text-xs text-[var(--gpt-muted)]">
                      Đăng nhập để lưu các tin nhắn quan trọng.
                      <div className="mt-3">
                        <Button asChild size="sm"><Link href="/login/?next=/ai-assistant/">Đăng nhập ngay</Link></Button>
                      </div>
                    </div>
                  )}
                  {user && saved.length === 0 && (
                    <div className="py-10 text-center text-[var(--gpt-faint)]">
                      <Bookmark className="mx-auto mb-2 size-6" />
                      <p className="text-xs">Chưa có tin nhắn nào được lưu</p>
                      <p className="mt-1 text-[11px] text-[var(--gpt-faint)]/70">Nhấn bookmark trên tin nhắn để lưu</p>
                    </div>
                  )}
                  {saved.map((s) => (
                    <div key={s.id} className="group cursor-pointer rounded-xl border border-white/[0.06] bg-white/[0.03] p-3 transition-colors hover:border-white/15" onClick={() => s.session_id && loadDetail(s.session_id)}>
                      <div className="mb-1.5 flex items-center justify-between">
                        <Badge variant="outline" className="text-[10px] text-[var(--gpt-muted)]">{s.message_role === 'user' ? 'Bạn' : 'AI'}</Badge>
                        <button type="button" aria-label="Xóa khỏi danh sách lưu" onClick={(e) => { e.stopPropagation(); void removeSaved(s.id); }} className="hover-reveal text-[var(--gpt-faint)] opacity-0 transition-opacity group-hover:opacity-100 hover:text-white">
                          <X className="size-3.5" />
                        </button>
                      </div>
                      <p className="line-clamp-3 text-[12px] leading-relaxed text-[var(--gpt-text)]/85">{s.message_text}</p>
                      <div className="mt-2 truncate text-[10px] text-[var(--gpt-faint)]">{s.session_title}</div>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </TabsContent>

            {/* Cài đặt */}
            <TabsContent value="settings" className="flex min-h-0 flex-1 flex-col">
              <div className="px-5 py-2"><h3 className="text-[13px] font-medium text-[var(--gpt-text)]">Cá nhân hóa AI</h3></div>
              <ScrollArea className="min-h-0 flex-1">
                <div className="space-y-4 px-4 pb-4">
                  {!user && (
                    <div className="py-6 text-center text-xs text-[var(--gpt-muted)]">
                      Đăng nhập để cá nhân hóa AI theo ý bạn.
                      <div className="mt-3">
                        <Button asChild size="sm"><Link href="/login/?next=/ai-assistant/">Đăng nhập ngay</Link></Button>
                      </div>
                    </div>
                  )}
                  {user && (<>
                  <div className="space-y-2">
                    <Label className="text-[11px] text-[var(--gpt-muted)]">Giọng điệu</Label>
                    <Select value={cfg.tone} onValueChange={(v) => saveConfig({ ...cfg, tone: v })}>
                      <SelectTrigger className="w-full border-white/10 bg-transparent"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="professional">Chuyên nghiệp</SelectItem>
                        <SelectItem value="friendly">Thân thiện</SelectItem>
                        <SelectItem value="casual">Thoải mái</SelectItem>
                        <SelectItem value="formal">Trang trọng</SelectItem>
                        <SelectItem value="humorous">Hài hước</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label className="text-[11px] text-[var(--gpt-muted)]">Phong cách trả lời</Label>
                    <Select value={cfg.language_style} onValueChange={(v) => saveConfig({ ...cfg, language_style: v })}>
                      <SelectTrigger className="w-full border-white/10 bg-transparent"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="simple">Đơn giản, dễ hiểu</SelectItem>
                        <SelectItem value="detailed">Chi tiết, chuyên sâu</SelectItem>
                        <SelectItem value="concise">Ngắn gọn, súc tích</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label className="text-[11px] text-[var(--gpt-muted)]">Tên gọi cho AI</Label>
                    <Input value={cfg.custom_name} onChange={(e) => saveConfig({ ...cfg, custom_name: e.target.value })} placeholder="VD: Shield, Trợ lý..." maxLength={50} className="border-white/10 bg-transparent placeholder:text-[var(--gpt-faint)]" />
                  </div>
                  <div className="space-y-2">
                    <Label className="text-[11px] text-[var(--gpt-muted)]">Hướng dẫn bổ sung</Label>
                    <Textarea value={cfg.custom_instructions} onChange={(e) => saveConfig({ ...cfg, custom_instructions: e.target.value })} placeholder="VD: Luôn giải thích bằng ví dụ thực tế..." rows={3} maxLength={500} className="resize-none border-white/10 bg-transparent text-sm placeholder:text-[var(--gpt-faint)]" />
                    <div className="flex items-center justify-between">
                      <span className={cn('flex items-center gap-1 text-[11px] text-[var(--gpt-muted)] transition-opacity', configSaved ? 'opacity-100' : 'opacity-0')}>
                        <Check className="size-3.5" /> Đã lưu
                      </span>
                      <span className="text-[10px] text-[var(--gpt-faint)]">{cfg.custom_instructions.length}/500</span>
                    </div>
                  </div>
                  </>)}
                </div>
              </ScrollArea>
            </TabsContent>
          </Tabs>

          <Separator className="bg-white/[0.09]" />
          <div className="gpt-side-foot p-3">
            <Link
              href="/"
              className="mb-1 flex items-center gap-2.5 rounded-xl px-2 py-2 text-[13px] text-[var(--gpt-muted)] transition-colors hover:bg-white/[0.06] hover:text-white"
            >
              <Home className="size-4 shrink-0" /> Trang chủ ShieldCall
            </Link>
            <button
              type="button"
              onClick={exportChat}
              disabled={messages.length === 0}
              className="mb-1 flex w-full items-center gap-2.5 rounded-xl px-2 py-2 text-left text-[13px] text-[var(--gpt-muted)] transition-colors hover:bg-white/[0.06] hover:text-white disabled:opacity-40 sm:hidden"
            >
              <Download className="size-4 shrink-0" /> Xuất hội thoại (.md)
            </button>
            <Link
              href={user ? '/profile/' : '/login/?next=/ai-assistant/'}
              className="flex items-center gap-3 rounded-xl p-2 transition-colors hover:bg-white/[0.06]"
            >
              <Avatar className="size-8">
                <AvatarFallback className="bg-white/10 text-xs font-semibold text-[var(--gpt-text)]">
                  {user ? user.username.slice(0, 1).toUpperCase() : '?'}
                </AvatarFallback>
              </Avatar>
              <div className="min-w-0 flex-1">
                <p className="truncate text-[13px] font-medium text-[var(--gpt-text)]">{user ? user.username : 'Đăng nhập'}</p>
                <p className="truncate text-[11px] text-[var(--gpt-faint)]">{user ? 'Người dùng ShieldCall' : 'Lưu lịch sử hội thoại'}</p>
              </div>
            </Link>
          </div>
        </aside>

        {/* Vách ngăn kéo để đổi bề rộng sidebar (chỉ desktop) */}
        {!navCollapsed && (
          <div
            role="separator"
            aria-orientation="vertical"
            aria-label="Kéo để đổi bề rộng thanh bên (nháy đúp để về mặc định)"
            title="Kéo để đổi bề rộng · nháy đúp để về mặc định"
            onPointerDown={onResizeStart}
            onPointerMove={onResizeMove}
            onPointerUp={onResizeEnd}
            onPointerCancel={onResizeEnd}
            onDoubleClick={() => { setNavWidth(NAV_DEFAULT); navWidthRef.current = NAV_DEFAULT; try { localStorage.setItem('assistant_nav_width', String(NAV_DEFAULT)); } catch { /* ignore */ } }}
            className="group/resize relative z-30 hidden w-1 shrink-0 cursor-col-resize md:block"
          >
            <span className="absolute inset-y-0 left-0 w-px bg-white/[0.08] transition-colors group-hover/resize:bg-[var(--gpt-accent-line)]" />
          </div>
        )}

        {/* ── Main ── */}
        <div className="relative flex min-w-0 flex-1 flex-col">
          <header className="z-20 flex h-14 shrink-0 items-center justify-between border-b border-white/[0.08] px-4 md:px-6">
            <div className="flex min-w-0 items-center gap-2">
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon-sm"
                    onClick={() => setNavCollapsed((v) => !v)}
                    aria-label={navCollapsed ? 'Hiện thanh bên' : 'Ẩn thanh bên'}
                    aria-pressed={navCollapsed}
                    className="hidden text-[var(--gpt-muted)] hover:bg-white/10 hover:text-white md:inline-flex"
                  >
                    <PanelLeft className="size-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent side="bottom">{navCollapsed ? 'Hiện thanh bên' : 'Ẩn thanh bên'}</TooltipContent>
              </Tooltip>
              <Button type="button" variant="ghost" size="icon" onClick={() => setMobileNav(!mobileNav)} className="md:hidden" aria-label="Mở danh sách">
                <Menu className="size-5" />
              </Button>
              <div className="min-w-0">
                <div className="group/title flex items-center gap-1">
                  <h1 className="max-w-[46vw] truncate text-sm font-medium text-[var(--gpt-text)] md:max-w-md">{title}</h1>
                  {user && sessionId && (
                    <IconBtn
                      label="Đổi tên hội thoại"
                      onClick={renameCurrent}
                      className="hover-reveal opacity-0 transition-opacity group-hover/title:opacity-100 focus-within:opacity-100"
                    >
                      <Pencil className="size-3.5" />
                    </IconBtn>
                  )}
                </div>
                {(status || safeMode) && (
                  <div className="flex h-4 items-center gap-2">
                    <span aria-live="polite" className="truncate text-[11px] text-[var(--gpt-faint)]">{status}</span>
                    {safeMode && (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Badge variant="secondary" className="h-4 cursor-help border-[var(--gpt-safe-line)] bg-[var(--gpt-safe-soft)] px-1.5 text-[10px] text-[var(--gpt-safe)]">SafeTalk</Badge>
                        </TooltipTrigger>
                        <TooltipContent side="bottom" className="max-w-xs text-xs leading-relaxed">
                          Chế độ thấu cảm: trả lời nhẹ nhàng, ưu tiên an toàn cảm xúc — dành cho người đang bị quấy rối hoặc bắt nạt.
                        </TooltipContent>
                      </Tooltip>
                    )}
                  </div>
                )}
              </div>
            </div>
            <div className="flex items-center gap-1.5">
              <Tooltip>
                <TooltipTrigger asChild>
                  <Badge
                    variant="outline"
                    className={cn(
                      'hidden cursor-help text-[11px] sm:inline-flex',
                      brand === 'FairSpace'
                        ? 'border-[var(--gpt-safe-line)] bg-[var(--gpt-safe-soft)] text-[var(--gpt-safe)]'
                        : 'border-[var(--gpt-accent-line)] text-[var(--gpt-accent)]',
                    )}
                  >
                    {brand === 'FairSpace' ? 'FairSpace' : 'ShieldCall'} · RAG
                  </Badge>
                </TooltipTrigger>
                <TooltipContent side="bottom" className="max-w-xs text-xs leading-relaxed">
                  {brand === 'FairSpace'
                    ? 'Chế độ FairSpace: trợ lý thấu cảm, ưu tiên an toàn cảm xúc. Bật tự động khi truy cập từ tên miền FairSpace.'
                    : 'Trợ lý ShieldCall dùng RAG (kho tri thức + CSDL chống lừa đảo ShieldCall VN) trước khi trả lời.'}
                </TooltipContent>
              </Tooltip>

              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon-sm"
                    onClick={cycleTextSize}
                    aria-label={`Chế độ dễ đọc — ${TEXT_SIZE_LABEL[textSize]}`}
                    aria-pressed={elder}
                    className={cn(
                      'text-[var(--gpt-muted)] hover:bg-white/10 hover:text-white',
                      elder && 'bg-[var(--gpt-accent-soft)] text-[var(--gpt-accent)]',
                    )}
                  >
                    <ALargeSmall className="size-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent side="bottom" className="max-w-xs text-xs leading-relaxed">
                  Chế độ dễ đọc cho người cao tuổi — bấm để đổi cỡ chữ (hiện tại: {TEXT_SIZE_LABEL[textSize]}). Chữ lớn hơn, nút to hơn, tương phản cao, kèm nút đọc to từng tin nhắn.
                </TooltipContent>
              </Tooltip>

              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon-sm"
                    onClick={exportChat}
                    disabled={messages.length === 0}
                    aria-label="Xuất hội thoại"
                    className="hidden text-[var(--gpt-muted)] hover:bg-white/10 hover:text-white sm:inline-flex"
                  >
                    <Download className="size-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent side="bottom">Xuất hội thoại (.md)</TooltipContent>
              </Tooltip>

              <Tooltip>
                <TooltipTrigger asChild>
                  <Button asChild variant="ghost" size="icon-sm" aria-label="Về trang chủ" className="hidden sm:inline-flex">
                    <Link href="/"><Home className="size-4" /></Link>
                  </Button>
                </TooltipTrigger>
                <TooltipContent side="bottom">Về trang chủ ShieldCall</TooltipContent>
              </Tooltip>

              <Avatar className="size-7">
                <AvatarFallback className="border border-[var(--gpt-accent-line)] bg-[var(--gpt-accent-soft)] text-[10px] font-semibold text-[var(--gpt-accent)]">AI</AvatarFallback>
              </Avatar>
            </div>
          </header>

          <div ref={wrapRef} onScroll={onScrollArea} style={{ paddingBottom: (composerH || 192) + 16 }} className="gpt-scroll relative min-h-0 flex-1 overflow-y-auto px-4">
            {loadingSession && (
              <div className="session-loading-overlay">
                <div className="session-loading-card"><span className="session-loading-spinner"></span> Đang đồng bộ...</div>
              </div>
            )}
            <div className="mx-auto max-w-3xl space-y-8 py-8">
              {!sessionId && messages.length === 0 && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ duration: reduce ? 0 : 0.35, ease: 'easeOut' }}
                  className="flex min-h-[60vh] flex-col items-center justify-center space-y-8 text-center"
                >
                  <motion.div
                    initial={{ opacity: 0, y: 12 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: reduce ? 0 : 0.35, ease: 'easeOut' }}
                    className="space-y-3"
                  >
                    <div className="relative mx-auto flex size-14 items-center justify-center">
                      <div className="absolute inset-0 rounded-2xl bg-[var(--gpt-accent)] opacity-25 blur-2xl" aria-hidden="true" />
                      <div className="relative flex size-14 items-center justify-center rounded-2xl border border-[var(--gpt-accent-line)] bg-[var(--gpt-accent-soft)]">
                        <ShieldCheck className="size-7 text-[var(--gpt-accent)]" />
                      </div>
                    </div>
                    <h2 className="text-2xl font-semibold tracking-tight text-[var(--gpt-text)]">
                      {brand === 'FairSpace' ? 'FairSpace Intelligence' : 'ShieldCall Intelligence'}
                    </h2>
                    <p className="mx-auto max-w-lg text-sm leading-relaxed text-[var(--gpt-muted)]">
                      {brand === 'FairSpace'
                        ? 'Trợ lý ảo thấu cảm, bảo vệ bạn khỏi bạo lực mạng và định kiến giới bằng công nghệ AI nhân văn.'
                        : 'Trợ lý ảo dùng RAG và dữ liệu bảo mật ShieldCall VN để bảo vệ bạn trong không gian số.'}
                    </p>
                  </motion.div>
                  <div className="w-full max-w-2xl px-4">
                    <div className="mb-3 text-left text-[11px] font-medium text-[var(--gpt-faint)]">
                      {safeMode ? 'Hỗ trợ thấu cảm & an toàn' : 'Thử ngay các tính năng quét'}
                    </div>
                    <div className="mb-4 grid grid-cols-1 gap-2.5 md:grid-cols-3">
                      {quickScan.map((q, i) => <PromptCard key={q.title} item={q} index={i} onPick={() => send(q.prompt)} />)}
                    </div>
                  </div>
                  <div className="grid w-full max-w-2xl grid-cols-1 gap-2.5 px-4 md:grid-cols-2">
                    {generalPrompts.map((q, i) => <PromptCard key={q.title} item={q} index={quickScan.length + i} onPick={() => send(q.prompt)} />)}
                  </div>
                </motion.div>
              )}
              {messages.map((m, i) => {
                const prev = messages[i - 1];
                const day = m.created_at ? new Date(m.created_at).toDateString() : '';
                const prevDay = prev?.created_at ? new Date(prev.created_at).toDateString() : '';
                return (
                  <Fragment key={i}>
                    {day && day !== prevDay && <DateDivider iso={m.created_at as string} />}
                    <MessageRow
                      m={m}
                      index={i}
                      isLast={i === messages.length - 1}
                      canBookmark={!!user}
                      canRate={!!user}
                      canSpeak={elder}
                      onCopy={copyText}
                      onBookmark={toggleBookmark}
                      onEdit={handleEdit}
                      onRate={rateMessage}
                      onRegenerate={regenerate}
                      onToggleThinking={handleToggleThinking}
                      onPreview={setOcrPreview}
                      onSpeak={speak}
                    />
                  </Fragment>
                );
              })}
            </div>
          </div>

          {/* Nút nhảy xuống cuối khi người dùng đang cuộn lên đọc */}
          <AnimatePresence>
            {!atBottom && (
              <motion.button
                key="jump-bottom"
                type="button"
                onClick={() => scrollBottom(true)}
                aria-label="Xuống tin nhắn mới nhất"
                style={{ bottom: (composerH || 192) + 20 }}
                initial={reduce ? false : { opacity: 0, y: 6, scale: 0.9 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={reduce ? { opacity: 0 } : { opacity: 0, y: 6, scale: 0.9 }}
                transition={{ duration: 0.15, ease: 'easeOut' }}
                className="absolute left-1/2 z-30 -translate-x-1/2 rounded-full border border-white/10 bg-[var(--gpt-side)] p-2 text-[var(--gpt-muted)] shadow-lg hover:text-white"
              >
                <ArrowDown className="size-4" />
              </motion.button>
            )}
          </AnimatePresence>

          {/* ── Composer ── */}
          <div ref={composerRef} className="gpt-composer pointer-events-none absolute right-0 bottom-0 left-0 z-30 p-3 sm:p-5">
            <div className="pointer-events-auto mx-auto max-w-3xl">
              <div
                className={cn(
                  'relative rounded-[26px] border bg-[var(--gpt-bubble)] transition-all duration-150 focus-within:border-[var(--gpt-accent-line)] focus-within:shadow-[0_0_0_3px_var(--gpt-accent-soft)]',
                  dragOver ? 'border-white/35' : 'border-white/10',
                  editId && 'ring-2 ring-warn-500/40',
                )}
                onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                onDragEnter={(e) => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={onDrop}
              >
                <AnimatePresence initial={false}>
                  {pendingImages.length > 0 && (
                    <motion.div
                      key="pending-thumbs"
                      className="flex flex-wrap gap-2 p-3 pb-0"
                      initial={reduce ? false : { opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      transition={{ duration: 0.15, ease: 'easeOut' }}
                    >
                      {pendingImages.map((src, k) => (
                        <motion.div
                          key={k}
                          initial={reduce ? false : { opacity: 0, scale: 0.9 }}
                          animate={{ opacity: 1, scale: 1 }}
                          exit={{ opacity: 0, scale: 0.9 }}
                          transition={{ duration: 0.15, ease: 'easeOut' }}
                          className="group relative size-16 overflow-hidden rounded-xl border border-white/10"
                        >
                          <img src={src} alt="" className="size-full object-cover" />
                          <button type="button" aria-label="Bỏ ảnh" onClick={() => setPendingImages((p) => p.filter((_, x) => x !== k))} className="hover-reveal absolute inset-0 flex items-center justify-center bg-black/50 text-white opacity-0 transition-opacity group-hover:opacity-100">
                            <X className="size-4" />
                          </button>
                        </motion.div>
                      ))}
                    </motion.div>
                  )}
                </AnimatePresence>
                <div className="flex items-end gap-1.5 p-2 pl-4">
                  <TextareaAutosize
                    ref={inputRef}
                    minRows={1}
                    maxRows={8}
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); if (streaming) stop(); else void send(); } }}
                    onPaste={onPaste}
                    placeholder={editId ? 'Đang chỉnh sửa...' : 'Nhập tin nhắn... (hoặc dán ảnh Ctrl+V)'}
                    className="max-h-48 flex-1 resize-none border-0 bg-transparent py-2.5 text-[15px] leading-6 text-[var(--gpt-text)] placeholder:text-[var(--gpt-faint)] focus:outline-none"
                  />
                  <div className="flex items-center gap-0.5 pb-1 pr-1">
                    <IconBtn
                      label="Chế độ thấu cảm (SafeTalk)"
                      active={safeMode}
                      onClick={toggleSafeMode}
                      className={safeMode ? 'text-[var(--gpt-safe)] hover:text-[var(--gpt-safe)] hover:bg-[var(--gpt-safe-soft)]' : undefined}
                    >
                      <HeartPulse className="size-5" />
                    </IconBtn>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <label className="inline-flex size-7 cursor-pointer items-center justify-center rounded-lg text-[var(--gpt-muted)] transition-colors hover:bg-white/10 hover:text-white" aria-label="Đính kèm ảnh">
                          <ImagePlus className="size-5" />
                          <input type="file" multiple accept="image/*" className="hidden" onChange={onFiles} />
                        </label>
                      </TooltipTrigger>
                      <TooltipContent side="top">Đính kèm ảnh (hoặc dán ảnh Ctrl+V)</TooltipContent>
                    </Tooltip>
                    <Button
                      type="button"
                      size="icon"
                      onClick={() => (streaming ? stop() : void send())}
                      disabled={!input.trim() && pendingImages.length === 0 && !streaming}
                      aria-label={streaming ? 'Dừng' : 'Gửi'}
                      className="ml-0.5 size-9 rounded-full bg-[var(--gpt-accent)] text-black shadow-[0_6px_18px_-6px_var(--gpt-accent)] hover:bg-[var(--gpt-accent-2)] disabled:bg-white/10 disabled:text-[var(--gpt-faint)] disabled:shadow-none"
                    >
                      {streaming ? <Square className="size-4" /> : <ArrowUp className="size-4" />}
                    </Button>
                  </div>
                </div>
                <div className="flex items-center gap-4 px-4 pt-0.5 pb-2.5">
                  <span className="flex items-center gap-1.5 text-[11px] text-[var(--gpt-faint)]">
                    <Check className="size-3.5" /> {brand} RAG
                  </span>
                  <label className="flex cursor-pointer items-center gap-2">
                    <Switch checked={previewOcr} onCheckedChange={setPreviewOcr} size="sm" />
                    <span className="text-[11px] text-[var(--gpt-faint)]">Preview Image OCR</span>
                  </label>
                  <span className="ml-auto hidden text-[10px] text-[var(--gpt-faint)] md:inline">Enter để gửi · Shift+Enter xuống dòng</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Dialog xem ảnh / OCR */}
        <Dialog open={!!ocrPreview} onOpenChange={(o) => { if (!o) setOcrPreview(null); }}>
          <DialogContent className="max-w-4xl border border-white/10 bg-[var(--gpt-side)] p-3" showCloseButton>
            <DialogTitle className="sr-only">Xem trước ảnh</DialogTitle>
            {ocrPreview && <img src={ocrPreview} alt="Xem trước OCR" className="max-h-[80vh] w-full rounded-lg object-contain" />}
          </DialogContent>
        </Dialog>

        {/* Xác nhận hành động (thay sweetalert2 scConfirm) */}
        <AlertDialog open={!!confirmState} onOpenChange={(o) => { if (!o) settleConfirm(false); }}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>{confirmState?.title}</AlertDialogTitle>
              <AlertDialogDescription>{confirmState?.text}</AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel onClick={() => settleConfirm(false)}>{confirmState?.cancelText}</AlertDialogCancel>
              <AlertDialogAction onClick={() => settleConfirm(true)}>{confirmState?.confirmText}</AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>

        {/* Nhập liệu: đổi tên hội thoại / thư mục (thay sweetalert2 scPrompt) */}
        <Dialog open={!!promptState} onOpenChange={(o) => { if (!o) settlePrompt(null); }}>
          <DialogContent className="sm:max-w-sm">
            <DialogTitle>{promptState?.title}</DialogTitle>
            <Input
              autoFocus
              value={promptState?.value ?? ''}
              placeholder={promptState?.placeholder}
              maxLength={120}
              onChange={(e) => setPromptState((s) => (s ? { ...s, value: e.target.value } : s))}
              onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); settlePrompt((promptState?.value ?? '').trim() || null); } }}
            />
            <div className="flex justify-end gap-2">
              <Button type="button" variant="ghost" onClick={() => settlePrompt(null)}>Hủy</Button>
              <Button type="button" onClick={() => settlePrompt((promptState?.value ?? '').trim() || null)}>Lưu</Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>
    </TooltipProvider>
  );
}

function PromptCard({ item, index, onPick }: { item: PromptItem; index: number; onPick: () => void }) {
  const Icon = item.icon;
  const reduce = useReducedMotion();
  return (
    <motion.button
      type="button"
      onClick={onPick}
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: reduce ? 0 : 0.3, delay: reduce ? 0 : 0.05 * index, ease: 'easeOut' }}
      className="group rounded-2xl border border-white/10 bg-white/[0.03] p-4 text-left transition-colors hover:border-[var(--gpt-accent-line)] hover:bg-[var(--gpt-accent-soft)]"
    >
      <Icon className="mb-2 size-4 text-[var(--gpt-muted)] transition-colors group-hover:text-[var(--gpt-accent)]" />
      <p className="text-[13px] font-medium text-[var(--gpt-text)]">{item.title}</p>
      <p className="mt-0.5 text-xs leading-relaxed text-[var(--gpt-muted)]">{item.desc}</p>
    </motion.button>
  );
}

function SessionRow({ s, active, onOpen, onRename, onDelete }: { s: ChatSession; active: boolean; onOpen: () => void; onRename: () => void; onDelete: () => void }) {
  return (
    <div
      draggable
      onDragStart={(e) => { e.dataTransfer.setData('sessionId', s.id); e.dataTransfer.effectAllowed = 'move'; }}
      onClick={onOpen}
      className={cn(
        'gpt-session-row group flex cursor-pointer items-center justify-between gap-1 rounded-lg py-1.5 pr-1 pl-2.5 text-sm transition-colors',
        active ? 'bg-[var(--gpt-accent-soft)] text-white shadow-[inset_2px_0_0_var(--gpt-accent)]' : 'text-[var(--gpt-text)] hover:bg-white/[0.06]',
      )}
    >
      <span className="min-w-0 flex-1 truncate">{s.title || 'Cuộc trò chuyện mới'}</span>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            type="button"
            variant="ghost"
            size="icon-xs"
            aria-label="Tùy chọn hội thoại"
            onClick={(e) => e.stopPropagation()}
            className="hover-reveal shrink-0 text-[var(--gpt-muted)] opacity-0 transition-opacity group-hover:opacity-100 data-[state=open]:opacity-100 hover:bg-white/10 hover:text-white"
          >
            <MoreHorizontal className="size-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" onClick={(e) => e.stopPropagation()}>
          <DropdownMenuItem onClick={onRename}><Pencil className="size-4" /> Đổi tên</DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem variant="destructive" onClick={onDelete}><Trash2 className="size-4" /> Xóa</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}

function UserMessageContent({ text }: { text: string }) {
  if (text.includes('[Nội dung từ ảnh]')) {
    let ocrPart = '';
    let displayContent = '';
    const questionMatch = text.match(/\[Câu hỏi\]:\s*([\s\S]*)$/);
    if (questionMatch) {
      const userQuestion = questionMatch[1].trim();
      ocrPart = text.replace(/\[Câu hỏi\]:\s*[\s\S]*$/, '').replace(/^\[Nội dung từ ảnh\]:?\s*/, '').trim();
      displayContent = userQuestion || text.replace(/\[Nội dung từ ảnh\]:?[\s\S]*/g, '').trim() || '[Hình ảnh đính kèm]';
    } else {
      ocrPart = text.replace(/^\[Nội dung từ ảnh\]:?\s*/, '').trim();
      displayContent = text.replace(/\[Nội dung từ ảnh\]:?[\s\S]*/g, '').trim() || '[Hình ảnh đính kèm]';
    }
    return (
      <>
        <details className="mb-3 overflow-hidden rounded-xl border border-white/10 bg-white/5">
          <summary className="flex cursor-pointer items-center gap-2 px-4 py-2 text-[11px] font-medium text-[var(--gpt-muted)] transition-colors hover:bg-white/5">
            <ImagePlus className="size-3.5" /> Xem nội dung trích xuất từ ảnh
          </summary>
          <div className="border-t border-white/5 bg-black/20 px-4 py-3 text-[12px] italic text-[var(--gpt-muted)]" dangerouslySetInnerHTML={{ __html: renderMd(ocrPart) }} />
        </details>
        <MarkdownView html={renderMd(displayContent)} className="md" />
      </>
    );
  }
  return <MarkdownView html={renderMd(text)} className="md" />;
}

function ToolCard({ t }: { t: ToolCall }) {
  const meta = TOOL_META[t.tool] || { label: t.label || t.tool };
  const [open, setOpen] = useState(false);
  useEffect(() => { if (t.done) setOpen(true); }, [t.done]);
  const args = argsSummary(t.args);
  return (
    <div className="my-2 overflow-hidden rounded-xl border border-white/10 bg-white/[0.03]">
      <div
        onClick={() => t.done && setOpen((o) => !o)}
        className={cn('flex items-center gap-2.5 px-3 py-2', t.done && 'cursor-pointer hover:bg-white/[0.04]')}
      >
        <span className={cn('flex size-6 shrink-0 items-center justify-center rounded-lg', t.done ? 'bg-[var(--gpt-accent-soft)] text-[var(--gpt-accent)]' : 'bg-white/5 text-[var(--gpt-muted)]')}>
          {t.done ? <Check className="size-3.5" /> : <RefreshCw className="size-3.5 animate-spin" />}
        </span>
        <span className="min-w-0 flex-1">
          <span className="block truncate text-[12px] font-medium text-[var(--gpt-text)]">{meta.label}</span>
          {args && <span className="block truncate font-mono text-[10px] text-[var(--gpt-faint)]">{args}</span>}
        </span>
        <span className="shrink-0 text-[10px] text-[var(--gpt-faint)]">{t.done ? 'Hoàn tất' : 'Đang chạy'}</span>
        {t.done && <ChevronDown className={cn('size-3.5 shrink-0 text-[var(--gpt-faint)] transition-transform', open && 'rotate-180')} />}
      </div>
      {t.done && open && (
        <div className="border-t border-white/[0.06] px-3 py-2.5">
          <ToolResultView result={t.result} />
        </div>
      )}
    </div>
  );
}

function ToolRow({ label, children, column }: { label: string; children: ReactNode; column?: boolean }) {
  return (
    <div className={cn('gap-2 py-0.5 text-[11px]', column ? 'flex flex-col' : 'flex items-baseline')}>
      <div className="shrink-0 text-[var(--gpt-faint)]">{label}</div>
      <div className="min-w-0 text-[var(--gpt-text)]/90">{children}</div>
    </div>
  );
}

function ToolResultView({ result }: { result: unknown }) {
  if (result == null) {
    return <div className="text-[11px] italic text-[var(--gpt-faint)]">Hoàn tất kiểm tra.</div>;
  }
  let data: unknown = result;
  if (typeof data === 'string') {
    try { data = JSON.parse(data); } catch { /* giữ nguyên string */ }
  }
  if (isRecord(data)) {
    const entries = Object.entries(data);
    if (!entries.length) return <div className="text-[11px] italic text-[var(--gpt-faint)]">Không có dữ liệu</div>;
    return <>{entries.map(([key, val], idx) => <ToolResultEntry key={`${key}-${idx}`} name={key} val={val} />)}</>;
  }
  return <div className="text-[11px] text-[var(--gpt-text)]/90">{String(data)}</div>;
}

function ToolResultEntry({ name, val }: { name: string; val: unknown }) {
  const label = RESULT_LABELS[name] || name;

  if (name === 'is_scam') {
    return (
      <ToolRow label={label}>
        <Badge variant={val ? 'destructive' : 'secondary'}>{val ? 'CẢNH BÁO LỪA ĐẢO' : 'AN TOÀN'}</Badge>
      </ToolRow>
    );
  }

  if (name === 'risk_level') {
    const variant = val === 'RED' ? 'destructive' : (val === 'YELLOW' || val === 'GREEN' || val === 'SAFE') ? 'secondary' : 'outline';
    return <ToolRow label={label}><Badge variant={variant}>{String(val)}</Badge></ToolRow>;
  }

  if (name === 'web_results' && Array.isArray(val)) {
    if (!val.length) return null;
    return (
      <ToolRow label={label} column>
        {val.slice(0, 5).map((r, i) => {
          const rec = isRecord(r) ? r : {};
          const t = String(rec.title ?? rec.url ?? '');
          const u = safeUrl(rec.url);
          const snip = String(rec.content ?? rec.text ?? '');
          return (
            <a key={i} href={u} target="_blank" rel="noopener noreferrer" className="mb-1.5 block rounded-md border border-white/[0.04] bg-white/[0.03] p-1.5 transition-colors hover:bg-white/[0.06]">
              <div className="truncate text-[11px] font-medium text-[var(--gpt-text)]/90">{t}</div>
              {snip && <div className="mt-0.5 line-clamp-2 text-[10px] text-[var(--gpt-muted)]">{snip.substring(0, 150)}</div>}
              <div className="mt-0.5 truncate text-[9px] text-[var(--gpt-faint)]">{u}</div>
            </a>
          );
        })}
      </ToolRow>
    );
  }

  if (name === 'links' && Array.isArray(val) && val.length > 0) {
    return (
      <ToolRow label={label}>
        <span className="block">
          {val.map((u, i) => {
            const raw = String(u);
            return <a key={i} href={safeUrl(raw)} target="_blank" rel="noopener noreferrer" className="block truncate text-[11px] text-[var(--gpt-text)] underline">{raw}</a>;
          })}
        </span>
      </ToolRow>
    );
  }

  if (Array.isArray(val)) {
    if (!val.length) return null;
    return (
      <ToolRow label={`${label} (${val.length})`} column>
        {val.slice(0, 5).map((item, i) => (
          <div key={i} className="border-b border-white/[0.04] py-1 text-[10px] last:border-0">
            {isRecord(item)
              ? Object.entries(item).map(([ik, iv]) => <span key={ik}><strong>{ik}:</strong> {String(iv ?? '')} · </span>)
              : String(item)}
          </div>
        ))}
      </ToolRow>
    );
  }

  if (isRecord(val)) {
    const summary = Object.entries(val)
      .filter(([, v]) => v !== null && v !== '' && (!Array.isArray(v) || v.length > 0))
      .map(([k, v]) => `${RESULT_LABELS[k] || k}: ${String(v).substring(0, 200)}`)
      .join(' · ');
    if (!summary) return null;
    return <ToolRow label={label}>{summary}</ToolRow>;
  }

  const strVal = val == null ? '' : String(val);
  if (!strVal.trim()) return null;
  const displayVal = strVal.length > 400 ? `${strVal.substring(0, 400)}…` : strVal;
  return <ToolRow label={label}>{displayVal}</ToolRow>;
}

function SourcesAccordion({ meta }: { meta: MsgMeta }) {
  const [open, setOpen] = useState(false);
  const items: Array<SrcItem & { type: 'rag' | 'web' }> = [
    ...(meta.internal_knowledge || []).map((r) => ({ ...r, type: 'rag' as const })),
    ...(meta.web_search || []).map((r) => ({ ...r, type: 'web' as const })),
  ];
  if (!items.length) return null;
  return (
    <div className="mt-3 overflow-hidden rounded-xl border border-white/10 bg-white/[0.02]">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-2.5 px-3.5 py-2.5 text-left transition-colors hover:bg-white/[0.05]"
      >
        <Globe className="size-4 shrink-0 text-[var(--gpt-accent)]" />
        <span className="text-[12px] font-medium text-[var(--gpt-text)]">Nguồn tham khảo</span>
        <Badge variant="outline" className="border-[var(--gpt-accent-line)] text-[var(--gpt-accent)]">{items.length}</Badge>
        <ChevronDown className={cn('ml-auto size-4 shrink-0 text-[var(--gpt-faint)] transition-transform', open && 'rotate-180')} />
      </button>
      {open && (
        <div className="space-y-2 border-t border-white/[0.06] px-3.5 pt-3 pb-3">
          {items.map((r, k) => {
            const isRag = r.type === 'rag';
            const url = safeUrl(r.url);
            return (
              <a key={k} href={url} target="_blank" rel="noopener noreferrer" className="group block rounded-lg border border-white/[0.06] bg-white/[0.03] p-2.5 transition-colors hover:border-white/15 hover:bg-white/[0.06]">
                <div className="mb-1 flex items-center gap-2">
                  <Badge variant="outline" className="shrink-0 text-[9px] text-[var(--gpt-muted)]">{isRag ? 'ShieldCall Knowledge' : 'Web Resource'}</Badge>
                  <span className="min-w-0 truncate text-[12px] font-medium text-[var(--gpt-text)]">{r.title || r.url || 'Nguồn thông tin'}</span>
                </div>
                {r.text && <div className="mb-1 line-clamp-2 text-[11px] leading-relaxed text-[var(--gpt-muted)] italic">“{r.text}”</div>}
                <div className="truncate font-mono text-[10px] text-[var(--gpt-faint)]">{url}</div>
              </a>
            );
          })}
        </div>
      )}
    </div>
  );
}
