'use client';

import { useMemo, useState } from 'react';
import type { MutableRefObject } from 'react';
import { CKEditor } from '@ckeditor/ckeditor5-react';
import 'ckeditor5/ckeditor5.css';
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
  const minStyle = `calc(${Math.max(1, minLines)} * 1.6em)`;

  return (
    <div className="ck-host">
      <CKEditor
        editor={ClassicEditor}
        config={{ ...config, placeholder, initialData }}
        data={initialData}
        onReady={(editor: unknown) => {
          try {
            const el = (
              editor as { ui?: { view?: { editable?: { element?: HTMLElement } } } }
            ).ui?.view?.editable?.element;
            if (el) el.style.minHeight = minStyle;
          } catch {
            /* ignore */
          }
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
        <div className="text-white/45 text-xs py-2">Đang tải trình soạn thảo...</div>
      )}
      <style>{`.ck-host .ck-editor__editable { min-height: ${minStyle}; }`}</style>
    </div>
  );
}

