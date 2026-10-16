'use client';

/* CKEditor factory — port từ PKV/templates/base.html sang ESM npm package
 * (ckeditor5 + @ckeditor/ckeditor5-react). Giữ nguyên toolbar/plugins/UI;
 * request gắn thêm Authorization Token cho user React.
 */
import {
  ClassicEditor,
  Essentials,
  Paragraph,
  Bold,
  Italic,
  Underline,
  Strikethrough,
  Subscript,
  Superscript,
  Heading,
  Link,
  AutoLink,
  BlockQuote,
  CodeBlock,
  HorizontalLine,
  List,
  TodoList,
  Indent,
  IndentBlock,
  Alignment,
  Table,
  TableToolbar,
  TableCaption,
  Image,
  ImageToolbar,
  ImageCaption,
  ImageStyle,
  ImageTextAlternative,
  ImageUpload,
  ImageInsertViaUrl,
  AutoImage,
  ImageBlock,
  ImageInline,
  ImageUtils,
  ImageEditing,
  MediaEmbed,
  Mention,
  Highlight,
  Style,
  GeneralHtmlSupport,
  ButtonView,
  SpecialCharacters,
  SpecialCharactersEssentials,
} from 'ckeditor5';
import Swal from 'sweetalert2';
import type { Locale } from 'ckeditor5';
import { showToast } from '../ui/feedback';

export interface EditorOptions {
  minLines?: number;
  enableScanReferenceButton?: boolean;
  getCurrentScanId?: () => string | number;
  onScanIdChange?: (id: number | '') => void;
  onScanIdRender?: (editor: unknown, id: number | '') => void;
}

function authHeaders(extra: Record<string, string> = {}): Record<string, string> {
  const h: Record<string, string> = { ...extra };
  try {
    const m = document.cookie.match(/csrftoken=([^;]+)/);
    if (m && !h['X-CSRFToken']) h['X-CSRFToken'] = decodeURIComponent(m[1]);
  } catch {
    /* ignore */
  }
  try {
    const t = localStorage.getItem('sc_token');
    if (t && !h['Authorization']) h['Authorization'] = 'Token ' + t;
  } catch {
    /* ignore */
  }
  return h;
}

class ShieldCallUploadAdapter {
  private loader: { file: Promise<File>; uploadTotal?: number; uploaded?: number };
  private xhr: XMLHttpRequest | null = null;

  constructor(loader: { file: Promise<File> }) {
    this.loader = loader;
  }

  upload(): Promise<{ default: string }> {
    return this.loader.file.then(
      (file) =>
        new Promise<{ default: string }>((resolve, reject) => {
          const data = new FormData();
          data.append('file', file);
          const xhr = new XMLHttpRequest();
          xhr.open('POST', '/api/v1/utils/upload-image/', true);
          const headers = authHeaders();
          if (headers['X-CSRFToken']) xhr.setRequestHeader('X-CSRFToken', headers['X-CSRFToken']);
          if (headers['Authorization']) xhr.setRequestHeader('Authorization', headers['Authorization']);
          xhr.upload.onprogress = (evt) => {
            if (evt.lengthComputable) {
              this.loader.uploadTotal = evt.total;
              this.loader.uploaded = evt.loaded;
            }
          };
          xhr.onload = () => {
            if (xhr.status >= 200 && xhr.status < 300) {
              try {
                const resp = JSON.parse(xhr.responseText) as { file?: { url?: string }; url?: string };
                resolve({ default: resp.file ? resp.file.url || '' : resp.url || '' });
              } catch {
                reject('Upload failed: bad response');
              }
            } else {
              reject('Upload failed: ' + xhr.statusText);
            }
          };
          xhr.onerror = () => reject('Upload failed');
          this.xhr = xhr;
          xhr.send(data);
        }),
    );
  }

  abort(): void {
    this.xhr?.abort();
  }
}

function ShieldCallUploadAdapterPlugin(editor: {
  plugins: { get: (name: string) => { createUploadAdapter: (loader: never) => unknown } };
}): void {
  editor.plugins.get('FileRepository').createUploadAdapter = (loader: never) =>
    new ShieldCallUploadAdapter(
      loader as unknown as { file: Promise<File> },
    ) as unknown;
}

interface MediaItem {
  name?: string;
  path?: string;
  url: string;
  size?: number;
  modified_at?: string;
  absolute_url?: string;
}

async function shieldCallLoadMediaItems(): Promise<MediaItem[]> {
  const resp = await fetch('/api/v1/utils/editor-media/', { headers: authHeaders({}) });
  const data = (await resp.json()) as { success?: number; message?: string; items?: MediaItem[] };
  if (!resp.ok || data.success !== 1) {
    throw new Error(data.message || 'Không thể tải thư viện media');
  }
  return data.items || [];
}

function shieldCallRenderMediaGrid(items: MediaItem[], query = ''): string {
  const q = (query || '').trim().toLowerCase();
  const filtered = q
    ? items.filter((item) => {
        const name = (item.name || '').toLowerCase();
        const path = (item.path || '').toLowerCase();
        return name.includes(q) || path.includes(q);
      })
    : items;
  if (!filtered.length) {
    return '<div class="text-center text-white/40 text-sm py-8">Không tìm thấy ảnh phù hợp.</div>';
  }
  return `<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 max-h-[430px] overflow-auto pr-1">${filtered
    .map((item) => {
      const idx = items.findIndex((src) => src.path === item.path);
      const kb = Math.max(1, Math.round((item.size || 0) / 1024));
      const modified = item.modified_at ? new Date(item.modified_at).toLocaleString('vi-VN') : 'Không rõ';
      const abs = item.absolute_url || new URL(item.url, window.location.origin).href;
      return `
                <div class="rounded-2xl border border-white/10 bg-white/5 p-3 space-y-2" data-index="${idx}">
                    <img src="${item.url}" alt="${item.name || ''}" class="w-full h-36 object-cover rounded-xl border border-white/10 mb-2" loading="lazy" />
                    <div class="text-[11px] text-white/90 truncate" title="${item.name || ''}">${item.name || ''}</div>
                    <div class="text-[10px] text-white/40">${kb} KB • ${modified}</div>
                    <div class="text-[10px] text-brand-300/70 truncate" title="${abs}">${abs}</div>
                    <div class="flex gap-2">
                        <button type="button" class="shieldcall-insert px-2.5 py-1.5 rounded-lg bg-brand-600 hover:bg-brand-500 text-white text-[11px] font-bold" data-index="${idx}">Chèn</button>
                        <button type="button" class="shieldcall-copy px-2.5 py-1.5 rounded-lg bg-white/10 hover:bg-white/20 text-white text-[11px] font-bold" data-index="${idx}">Copy link</button>
                        <a href="${abs}" target="_blank" rel="noopener" class="px-2.5 py-1.5 rounded-lg bg-brand-500/20 hover:bg-brand-500/30 text-brand-200 text-[11px] font-bold">Mở</a>
                        <button type="button" class="shieldcall-delete px-2.5 py-1.5 rounded-lg bg-danger-600/80 hover:bg-danger-500 text-white text-[11px] font-bold" data-index="${idx}">Xóa</button>
                    </div>
                </div>
            `;
    })
    .join('')}</div>`;
}

function shieldCallRenderMediaManagerBody(items: MediaItem[], query = ''): string {
  return `
                <div class="space-y-4 text-left">
                    <div class="flex items-center gap-3">
                        <input id="shieldcall-media-search" type="text" value="${(query || '').replace(/"/g, '&quot;')}"
                               placeholder="Tìm theo tên file..."
                               class="w-full rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-white placeholder:text-white/40 outline-none focus:border-brand-400/40">
                        <span class="text-[11px] text-white/50 whitespace-nowrap">${items.length} tệp</span>
                    </div>
                    ${shieldCallRenderMediaGrid(items, query)}
                </div>
            `;
}

function csrfToken(): string {
  try {
    return (
      (document.querySelector('[name=csrfmiddlewaretoken]') as HTMLInputElement | null)?.value ||
      (document.cookie.match(/csrftoken=([^;]+)/) || ['', ''])[1]
    );
  } catch {
    return '';
  }
}

async function openShieldCallMediaManager(editor: {
  execute: (name: string, arg: unknown) => void;
}): Promise<void> {
  let items: MediaItem[] = [];
  const query = '';
  try {
    items = await shieldCallLoadMediaItems();
  } catch (err) {
    await Swal.fire({
      icon: 'error',
      title: 'Lỗi thư viện media',
      text: (err as Error).message || 'Không thể tải media',
      background: '#0d0d1f',
      color: '#fff',
      customClass: { popup: 'rounded-[2rem] border border-white/10' },
    });
    return;
  }
  await Swal.fire({
    title: 'Media của bạn',
    html: shieldCallRenderMediaManagerBody(items, query),
    width: 920,
    showConfirmButton: false,
    showCloseButton: true,
    background: '#0d0d1f',
    color: '#fff',
    customClass: { popup: 'rounded-[2rem] border border-white/10' },
    didOpen: () => {
      const popup = Swal.getPopup();
      if (!popup) return;
      const searchInput = popup.querySelector<HTMLInputElement>('#shieldcall-media-search');
      if (searchInput) {
        searchInput.focus();
        searchInput.addEventListener('input', (event) => {
          const q = (event.target as HTMLInputElement).value || '';
          Swal.update({ html: shieldCallRenderMediaManagerBody(items, q) });
        });
      }
      popup.addEventListener('click', (event: Event) => {
        const target = event.target as HTMLElement;
        const insertBtn = target.closest('.shieldcall-insert') as HTMLElement | null;
        const copyBtn = target.closest('.shieldcall-copy') as HTMLElement | null;
        const deleteBtn = target.closest('.shieldcall-delete') as HTMLElement | null;
        if (insertBtn) {
          const idx = Number(insertBtn.dataset.index);
          const item = items[idx];
          if (item?.url) {
            const abs = item.absolute_url || new URL(item.url, window.location.origin).href;
            editor.execute('insertImage', { source: abs });
            Swal.close();
          }
          return;
        }
        if (copyBtn) {
          const idx = Number(copyBtn.dataset.index);
          const item = items[idx];
          if (item?.url) {
            const abs = item.absolute_url || new URL(item.url, window.location.origin).href;
            navigator.clipboard
              .writeText(abs)
              .then(() => showToast('Đã copy link ảnh', 'success'))
              .catch(() => showToast('Không thể copy link', 'warning'));
          }
          return;
        }
        if (deleteBtn) {
          const idx = Number(deleteBtn.dataset.index);
          const item = items[idx];
          if (!item) return;
          void (async () => {
            const resp = await fetch('/api/v1/utils/editor-media/', {
              method: 'DELETE',
              headers: authHeaders({ 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken() }),
              body: JSON.stringify({ path: item.path }),
            });
            if (resp.ok) {
              items.splice(idx, 1);
              Swal.update({ html: shieldCallRenderMediaManagerBody(items, query) });
            }
          })();
        }
      });
    },
  });
}

function ShieldCallMediaManagerPlugin(editor: {
  ui?: { componentFactory?: { add: (name: string, fn: (locale: unknown) => unknown) => void } };
}): void {
  if (!editor?.ui?.componentFactory) return;
  editor.ui.componentFactory.add('shieldCallMedia', (locale: unknown) => {
    const button = new ButtonView(locale as Locale);
    button.set({ label: 'Media của tôi', withText: true, tooltip: true });
    button.on('execute', () =>
      openShieldCallMediaManager(
        editor as unknown as { execute: (name: string, arg: unknown) => void },
      ),
    );
    return button;
  });
}

function mentionItemRenderer(item: { id?: string; username?: string; name?: string; avatar?: string }): HTMLElement {
  const mentionId = String(item.id || '').trim();
  const mentionUsername = String((item as { username?: string }).username || mentionId.replace(/^@+/, '')).trim();
  const mentionHandle = mentionUsername ? `@${mentionUsername}` : mentionId;
  const container = document.createElement('div');
  container.style.display = 'flex';
  container.style.alignItems = 'center';
  container.style.gap = '10px';
  container.style.padding = '4px 6px';
  const avatar = document.createElement('div');
  avatar.style.width = '28px';
  avatar.style.height = '28px';
  avatar.style.borderRadius = '8px';
  avatar.style.background = 'rgba(255,255,255,0.06)';
  avatar.style.overflow = 'hidden';
  avatar.style.flexShrink = '0';
  if (item.avatar) {
    const avatarUrl = String(item.avatar);
    const avatarSafe = /^(https?:\/\/|\/media\/|\/static\/|data:image\/)/i.test(avatarUrl) ? avatarUrl : '';
    if (avatarSafe) {
      const avatarImg = document.createElement('img');
      avatarImg.src = avatarSafe;
      avatarImg.style.cssText = 'width:28px;height:28px;object-fit:cover;display:block;';
      avatarImg.loading = 'lazy';
      avatar.appendChild(avatarImg);
    } else {
      avatar.textContent = '@';
    }
  } else {
    const firstChar = (item.name && item.name.length ? item.name[0] : '@').toUpperCase();
    avatar.textContent = firstChar;
  }
  const info = document.createElement('div');
  info.style.display = 'flex';
  info.style.flexDirection = 'column';
  const nameSpan = document.createElement('span');
  nameSpan.style.cssText = 'font-size:12px;font-weight:700;color:var(--sc-white);line-height:1.2;';
  nameSpan.textContent = String(item.name || '');
  const handleSpan = document.createElement('span');
  handleSpan.style.cssText = 'font-size:10px;color:var(--sc-brand-400);font-weight:600;line-height:1.2;';
  handleSpan.textContent = mentionHandle;
  info.appendChild(nameSpan);
  info.appendChild(handleSpan);
  container.appendChild(avatar);
  container.appendChild(info);
  return container;
}

function makeScanReferencePlugin(options: EditorOptions) {
  return class ScanReferencePlugin {
    public static get pluginName(): string {
      return 'ScanReference';
    }

    private editor: {
      ui?: { componentFactory?: { add: (name: string, fn: (locale: unknown) => unknown) => void } };
    };

    constructor(editor: never) {
      this.editor = editor as unknown as {
        ui?: { componentFactory?: { add: (name: string, fn: (locale: unknown) => unknown) => void } };
      };
    }

    public init(): void {
      const editor = this.editor;
      if (!editor?.ui?.componentFactory) return;
      editor.ui.componentFactory.add('scanReference', (locale: unknown) => {
        const button = new ButtonView(locale as Locale);
        button.set({ label: 'Scan ID', withText: true, tooltip: true });
        button.on('execute', () => {
          void (async () => {
            const current =
              typeof options.getCurrentScanId === 'function' ? options.getCurrentScanId() || '' : '';
            const result = await Swal.fire({
              title: 'Gắn Scan ID tham chiếu',
              input: 'number',
              inputValue: current ? Number(current) : '',
              inputPlaceholder: 'Ví dụ: 123',
              showCancelButton: true,
              confirmButtonText: 'Xác nhận',
              cancelButtonText: 'Hủy',
              background: '#161235',
              color: '#fff',
            });
            if (!result.isConfirmed) return;
            const digits = String(result.value || '').replace(/\D/g, '');
            if (!digits) {
              options.onScanIdChange?.('');
              options.onScanIdRender?.(editor, '');
              showToast('Đã xóa Scan ID tham chiếu', 'info');
              return;
            }
            const parsed = parseInt(digits, 10);
            if (!Number.isFinite(parsed) || parsed < 1) {
              showToast('Scan ID không hợp lệ', 'warning');
              return;
            }
            options.onScanIdChange?.(parsed);
            options.onScanIdRender?.(editor, parsed);
            showToast(`Đã gắn Scan ID #${parsed}`, 'success');
          })();
        });
        return button;
      });
    }
  };
}

function mentionFeed(query: string): Promise<{ id: string; text: string; name: string; avatar: string }[]> {
  const q = String(query || '').trim().replace(/^@+/, '');
  if (q.length < 1) return Promise.resolve([]);
  return fetch(`/api/v1/utils/mentions/?query=${encodeURIComponent(q)}`, {
    credentials: 'same-origin',
    headers: authHeaders({ Accept: 'application/json' }),
  })
    .then((response) => {
      if (!response.ok) return [];
      return response.json() as Promise<
        { id: string | number; name?: string; avatar?: string }[]
      >;
    })
    .then((rawItems) => {
      if (!Array.isArray(rawItems)) return [];
      return rawItems
        .filter((item) => item && item.id)
        .map((item) => ({
          id: String(item.id).startsWith('@') ? String(item.id) : `@${item.id}`,
          text: String(item.id).startsWith('@') ? String(item.id) : `@${item.id}`,
          name: String(item.name || item.id || '').trim(),
          avatar: item.avatar || '',
        }));
    })
    .catch(() => []);
}

export function buildEditorConfig(options: EditorOptions = {}): Record<string, unknown> {
  /* Toolbar xếp theo nhóm rõ ràng; '|' là separator. CKEditor tự gộp phần tử
   * dư vào menu overflow khi hẹp nên mobile vẫn dùng được. */
  const toolbarItems: string[] = [
    'undo', 'redo', '|',
    'style', 'heading', '|',
    'bold', 'italic', 'underline', 'strikethrough', '|',
    'blockQuote', 'codeBlock', 'highlight', '|',
    'bulletedList', 'numberedList', 'todoList', 'outdent', 'indent', '|',
    'link', 'insertImage', 'shieldCallMedia', 'mediaEmbed', 'insertTable', '|',
    'horizontalLine', 'alignment',
  ];
  // SpecialCharacters là optional trong bản UMD gốc — npm có sẵn thì dùng.
  if (SpecialCharacters) toolbarItems.push('|', 'specialCharacters');
  if (options.enableScanReferenceButton) toolbarItems.push('|', 'scanReference');

  const config: Record<string, unknown> = {
    licenseKey: 'GPL',
    plugins: [
      Alignment, AutoImage, AutoLink, BlockQuote, Bold,
      CodeBlock, Essentials, GeneralHtmlSupport, Heading,
      Highlight, HorizontalLine, ImageBlock, ImageCaption, ImageEditing,
      ImageInline, ImageInsertViaUrl, ImageStyle, ImageTextAlternative,
      ImageToolbar, ImageUpload, ImageUtils, Indent, IndentBlock, Italic,
      Link, List, MediaEmbed, Mention, Paragraph, Strikethrough,
      Style, Subscript, Superscript, Table, TableCaption, TableToolbar,
      TodoList, Underline, Image,
      ShieldCallUploadAdapterPlugin, ShieldCallMediaManagerPlugin,
      ...(SpecialCharactersEssentials ? [SpecialCharactersEssentials] : []),
      ...(SpecialCharacters ? [SpecialCharacters] : []),
    ].filter(Boolean),
    toolbar: { items: toolbarItems, shouldNotGroupWhenFull: false },
    heading: {
      options: [
        { model: 'paragraph', title: 'Đoạn văn bản', class: 'ck-heading_paragraph' },
        { model: 'heading1', view: 'h1', title: 'Tiêu đề 1', class: 'ck-heading_heading1' },
        { model: 'heading2', view: 'h2', title: 'Tiêu đề 2', class: 'ck-heading_heading2' },
        { model: 'heading3', view: 'h3', title: 'Tiêu đề 3', class: 'ck-heading_heading3' },
        { model: 'heading4', view: 'h4', title: 'Tiêu đề 4', class: 'ck-heading_heading4' },
        { model: 'heading5', view: 'h5', title: 'Tiêu đề 5', class: 'ck-heading_heading5' },
        { model: 'heading6', view: 'h6', title: 'Tiêu đề 6', class: 'ck-heading_heading6' },
      ],
    },
    /* Chỉ cho phép các class/attribute nào thật sự có CSS trong app/styles/ckeditor.css.
     * Trước đây allow /^.*$/ cho phép paste class tuỳ ý làm vỡ layout forum và
     * khiến nội dung soạn thảo lệch với bản hiển thị. */
    htmlSupport: {
      allow: [
        {
          name: /.*/,
          attributes: [
            'id', 'alt', 'title', 'dir', 'target', 'rel', 'colspan', 'rowspan',
            'data-scan-ref', 'data-cke-saved-src',
          ],
          classes: [
            'document-title', 'document-subtitle', 'category', 'info-box',
            'button', 'button--green', 'button--black', 'marker', 'spoiler',
            'mention', 'language-*',
          ],
          styles: ['text-align', 'width', 'height', 'background-color', 'color'],
        },
      ],
      disallow: [{ name: /^(script|style|object|embed|form|input|button)$/ }],
    },
    image: {
      toolbar: ['toggleImageCaption', 'imageTextAlternative', '|', 'imageStyle:inline', 'imageStyle:wrapText', 'imageStyle:breakText'],
    },
    link: {
      addTargetToExternalLinks: true,
      defaultProtocol: 'https://',
      decorators: {
        toggleDownloadable: {
          mode: 'manual',
          label: 'Tải xuống',
          attributes: { download: 'file' },
        },
      },
    },
    mention: {
      feeds: [
        {
          marker: '@',
          feed: mentionFeed,
          minimumCharacters: 1,
          dropdownLimit: 10,
          itemRenderer: mentionItemRenderer,
        },
      ],
    },
    style: {
      definitions: [
        { name: 'Tiêu đề bài viết', element: 'h2', classes: ['document-title'] },
        { name: 'Phụ đề', element: 'h3', classes: ['document-subtitle'] },
        { name: 'Nhãn danh mục', element: 'h3', classes: ['category'] },
        { name: 'Khung thông tin', element: 'p', classes: ['info-box'] },
        { name: 'Nút chính', element: 'a', classes: ['button', 'button--green'] },
        { name: 'Nút phụ', element: 'a', classes: ['button', 'button--black'] },
        { name: 'Đánh dấu', element: 'span', classes: ['marker'] },
        { name: 'Ẩn nội dung (spoiler)', element: 'span', classes: ['spoiler'] },
      ],
    },
    table: { contentToolbar: ['tableColumn', 'tableRow', 'mergeTableCells'] },
  };
  if (options.enableScanReferenceButton) {
    (config.plugins as unknown[]).push(makeScanReferencePlugin(options));
  }
  return config;
}

export { ClassicEditor };
export type { EditorOptions as CKEditorOptions };
