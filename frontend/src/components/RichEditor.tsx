'use client';

import dynamic from 'next/dynamic';
import type { MutableRefObject } from 'react';

/* RichEditor SSR-safe: CKEditor chỉ tồn tại ở browser nên load dynamic
 * với ssr:false. Các page cứ import RichEditor như bình thường.
 */
interface RichEditorProps {
  initialData?: string;
  placeholder?: string;
  minLines?: number;
  onReady?: (editor: unknown) => void;
  onChangeData?: (html: string) => void;
  editorRef?: MutableRefObject<unknown | null>;
  enableScanReferenceButton?: boolean;
  getCurrentScanId?: () => string | number;
  onScanIdChange?: (id: number | '') => void;
  onScanIdRender?: (editor: unknown, id: number | '') => void;
}

const RichEditorInner = dynamic(() => import('./RichEditorInner'), {
  ssr: false,
  loading: () => <div className="text-white/45 text-xs py-2">Đang tải trình soạn thảo...</div>,
});

export default function RichEditor(props: RichEditorProps) {
  return <RichEditorInner {...props} />;
}

export function getEditorData(editor: unknown): string {
  try {
    return (editor as { getData: () => string }).getData() || '';
  } catch {
    return '';
  }
}

export function setEditorData(editor: unknown, html: string): void {
  try {
    (editor as { setData: (html: string) => void }).setData(html || '');
  } catch {
    /* ignore */
  }
}

/** Bỏ tag/nbsp/entity để kiểm tra "nội dung có thực sự rỗng" hay không.
 * CKEditor luôn trả về markup kể cả khi người dùng chưa gõ gì (ví dụ <p>&nbsp;</p>)
 * nên kiểm tra bằng trim() thường bỏ sót và cho đăng bài rỗng. */
export function stripEditorHtml(html?: string | null): string {
  if (!html) return '';
  return String(html)
    .replace(/<br\s*\/?>/gi, ' ')
    .replace(/<\/(p|div|li|h[1-6]|tr|blockquote|pre)>/gi, ' ')
    .replace(/<[^>]*>/g, '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&quot;/gi, '"')
    .replace(/\s+/g, ' ')
    .trim();
}

export function hasEditorContent(html?: string | null): boolean {
  return stripEditorHtml(html).length > 0;
}
