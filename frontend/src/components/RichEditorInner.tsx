'use client';

import { useMemo, useState } from 'react';
import type { CSSProperties, MutableRefObject } from 'react';
import { CKEditor } from '@ckeditor/ckeditor5-react';
/* Theme của CKEditor phải nạp cùng lúc với component để không bị nháy sáng
 * trước khi CSS dark kịp áp dụng (dropdown/balloon render ở cấp <body> nên
 * theme cũng phải là global). */
import 'ckeditor5/ckeditor5.css';
import '../../app/styles/ckeditor.css';
import { ClassicEditor, buildEditorConfig } from '../lib/editor/ckeditor';
import type { EditorOptions } from '../lib/editor/ckeditor';

/* Rich text editor — CKEditor 5 npm build, config y hệt bản Django
 * (toolbar/plugins/media/upload/mention). Xem src/lib/editor/ckeditor.ts.
 */
interface Props extends EditorOptions {
  initialData?: string;
  placeholder?: string;
  minLines?: number;
  onReady?: (editor: unknown) => void;
  onChangeData?: (html: string) => void;
  editorRef?: MutableRefObject<unknown | null>;
}

export default function RichEditor({
  initialData = '',
  placeholder = 'Nhập nội dung...',
  minLines = 5,
  onReady,
  onChangeData,
  editorRef,
  ...restOptions
}: Props) {
  const [ready, setReady] = useState(false);
  const config = useMemo(
    () => buildEditorConfig({ minLines, ...restOptions }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  );
  /* Chiều cao tối thiểu set bằng CSS variable để không phải inject <style>
   * / set style inline (gây giật layout và rò CSS ra ngoài component). */
  const hostStyle = {
    '--ck-host-min-height': `calc(${Math.max(1, minLines)} * 1.7em + 2rem)`,
  } as CSSProperties;

  return (
    <div className="ck-host" style={hostStyle}>
      <CKEditor
        editor={ClassicEditor}
        config={{ ...config, placeholder, initialData }}
        onReady={(editor: unknown) => {
          if (editorRef) editorRef.current = editor;
          setReady(true);
          onReady?.(editor);
        }}
        onChange={(_event: unknown, editor: unknown) => {
          try {
            onChangeData?.((editor as { getData: () => string }).getData() || '');
          } catch {
            /* ignore */
          }
        }}
      />
      {!ready && (
        <div className="text-white/45 text-xs py-3 text-center">Đang tải trình soạn thảo…</div>
      )}
    </div>
  );
}

