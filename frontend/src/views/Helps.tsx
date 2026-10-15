'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { api } from '../lib/api';
import { renderMd } from '../lib/chat/markdown';
import { MarkdownView, Spinner } from '../components/ui';
import { Button } from '../components/ui/button';
import { Card } from '../components/ui/card';
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
} from '../components/ui/dropdown-menu';

interface HelpItem {
  slug: string;
  title: string;
  icon?: string;
}

const HELP_INDEX: HelpItem[] = [
  { slug: 'index', title: 'Trung Tâm Hỗ Trợ ShieldCall VN', icon: 'bi-grid' },
  { slug: 'huong-dan-nguoi-gia', title: 'Hướng dẫn dành cho Người cao tuổi', icon: 'bi-person-heart' },
  { slug: 'huong-dan-quet-lua-dao', title: 'Hướng dẫn sử dụng các công cụ Quét Lừa Đảo', icon: 'bi-search' },
  { slug: 'cai-dat-ung-dung', title: 'Hướng dẫn Cài đặt Ứng dụng (PWA)', icon: 'bi-phone' },
  { slug: 'huong-dan-bao-cao', title: 'Cách Báo Cáo và Đóng Góp cho Cộng Đồng', icon: 'bi-flag' },
  { slug: 'cong-dong-va-forum', title: 'Cộng đồng và Diễn đàn ShieldCall', icon: 'bi-people' },
  { slug: 'bao-mat-tai-khoan', title: 'Bảo mật Tài khoản và Thông tin Cá nhân', icon: 'bi-shield-check' },
  { slug: 'scam-iq-va-kien-thuc', title: 'ScamIQ và Trung Tâm Kiến Thức', icon: 'bi-mortarboard' },
  { slug: 'mcp-server', title: 'Tích hợp MCP Server & Kết nối Chatbot', icon: 'bi-cpu' },
];

export default function Helps() {
  const { slug } = useParams<{ slug: string }>();
  const active = slug || 'index';
  const [html, setHtml] = useState('');
  const [articleTitle, setArticleTitle] = useState('');
  const [loading, setLoading] = useState(true);
  const [vote, setVote] = useState<'yes' | 'no' | null>(null);

  const item = HELP_INDEX.find((h) => h.slug === active);
  const title = articleTitle || (item ? item.title : 'Trung tâm hỗ trợ');

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setHtml('');
    api
      .get<{ title?: string; html?: string }>(active === 'index' ? '/helps/' : `/helps/${active}/`)
      .then((data) => {
        if (!alive) return;
        setHtml(data.html || renderMd('Chưa có nội dung.'));
        if (data.title) setArticleTitle(data.title);
      })
      .catch(() => {
        if (alive) setHtml(renderMd('Không thể tải bài viết trợ giúp.'));
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [active]);


  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <header className="flex flex-col sm:flex-row justify-between items-start sm:items-center py-6 border-b border-slate-800 mb-8 gap-4">
        <div className="flex items-center gap-4">
          <div className="w-10 h-10 rounded-xl bg-brand-600 flex items-center justify-center shadow-lg">
            <i className="bi bi-shield-check text-xl text-white"></i>
          </div>
          <div>
            <h1 className="text-xl font-bold text-slate-100 leading-tight">ShieldCall Docs</h1>
            <p className="text-xs font-medium text-slate-400">Hệ thống hỗ trợ thông minh</p>
          </div>
        </div>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button
              type="button"
              className="flex items-center gap-2 px-4 py-2 bg-slate-800/80 hover:bg-slate-700/80 border border-white/10 rounded-xl text-sm font-medium text-slate-200 transition-colors cursor-pointer outline-none"
            >
              <i className="bi bi-translate text-brand-400"></i>
              <span>Cơ sở tri thức</span>
              <i className="bi bi-chevron-down text-xs ml-1 opacity-60"></i>
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-52 p-1.5 bg-slate-900/90 backdrop-blur-md border border-white/10 rounded-xl shadow-xl">
            <div className="px-3 py-1.5 text-[10px] font-bold uppercase tracking-wider text-slate-400">
              Chọn ngôn ngữ
            </div>
            <DropdownMenuItem asChild>
              <Link
                href={active === 'index' ? '/helps/' : `/helps/${active}/`}
                className="w-full text-left px-3 py-2 rounded-lg hover:bg-white/10 text-xs font-semibold flex items-center gap-3 transition-colors text-slate-200 cursor-pointer"
              >
                <span className="text-danger-400 font-bold">VN</span> Tiếng Việt
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem
              className="w-full text-left px-3 py-2 rounded-lg hover:bg-white/10 text-xs font-semibold flex items-center gap-3 transition-colors text-slate-200 cursor-pointer"
            >
              <span className="text-brand-400 font-bold">EN</span> English
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
        <aside className="lg:col-span-1">
          <div className="sticky top-6">
            <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-4 px-2">Trung tâm Hỗ trợ</h3>
            <nav className="space-y-1">
              {HELP_INDEX.map((h) => (
                <Link
                  key={h.slug}
                  href={h.slug === 'index' ? '/helps/' : `/helps/${h.slug}/`}
                  className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                    h.slug === active
                      ? 'bg-brand-600/10 text-brand-400 border border-brand-500/20'
                      : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
                  }`}
                >
                  <i className={`bi ${h.icon || (h.slug === 'index' ? 'bi-grid' : 'bi-file-text')} ${h.slug === active ? 'text-brand-400' : ''}`}></i>
                  <span>{h.title}</span>
                </Link>
              ))}
            </nav>

            <div className="mt-8 pt-8 border-t border-slate-800 px-2">
              <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-4">Liên hệ</h3>
              <div className="space-y-3">
                <Link
                  href="/forum/"
                  className="flex items-center gap-3 text-sm text-slate-400 hover:text-brand-400 transition-colors"
                >
                  <i className="bi bi-chat-heart"></i> Cộng đồng VN
                </Link>
              </div>
            </div>
          </div>
        </aside>

        <main className="lg:col-span-3">
          <Card className="bg-slate-900/60 backdrop-blur-md border border-white/10 rounded-2xl p-6 sm:p-10 shadow-xl">
            <header className="mb-10">
              <nav className="flex items-center gap-2 text-xs font-medium text-slate-500 mb-4">
                <Link href="/" className="hover:text-brand-400 transition-colors">
                  ShieldCall
                </Link>
                <i className="bi bi-chevron-right text-[10px]"></i>
                <Link href="/helps/" className="hover:text-brand-400 transition-colors">
                  Knowledge Base
                </Link>
                {active !== 'index' && (
                  <>
                    <i className="bi bi-chevron-right text-[10px]"></i>
                    <span className="text-brand-400">Article</span>
                  </>
                )}
              </nav>

              <h1 className="text-3xl sm:text-4xl font-extrabold text-slate-50 tracking-tight mb-4">{title}</h1>

              <div className="flex flex-wrap items-center gap-4 text-xs font-medium text-slate-500">
                <span className="flex items-center gap-1.5">
                  <i className="bi bi-calendar3"></i> Cập nhật: {new Date().toLocaleDateString('vi-VN')}
                </span>
                <span className="flex items-center gap-1.5">
                  <i className="bi bi-clock"></i> Đọc trong 5 phút
                </span>
              </div>
            </header>

            {loading ? (
              <Spinner />
            ) : html ? (
              <article className="ai-markdown">
                <MarkdownView html={html} />
              </article>
            ) : (
              <div className="ai-markdown text-slate-400 text-sm">
                Không tải được nội dung từ máy chủ.{' '}
                <Link
                  href="/helps/"
                  className="text-brand-400 hover:underline"
                >
                  Về trang hướng dẫn
                </Link>
              </div>
            )}


            <div className="mt-16 pt-8 border-t border-slate-800 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-6">
              <div className="flex flex-col gap-3">
                <span className="text-sm font-semibold text-slate-300">Tài liệu này hữu ích không?</span>
                <div className="flex gap-2">
                  <Button
                    type="button"
                    size="sm"
                    variant={vote === 'yes' ? 'cyber' : 'outline'}
                    onClick={() => setVote('yes')}
                    className="rounded-xl border-white/10"
                  >
                    <i className="bi bi-hand-thumbs-up mr-1.5"></i> Có
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    variant={vote === 'no' ? 'cyber' : 'outline'}
                    onClick={() => setVote('no')}
                    className="rounded-xl border-white/10"
                  >
                    <i className="bi bi-hand-thumbs-down mr-1.5"></i> Không
                  </Button>
                </div>
              </div>

              <Button asChild variant="outline" size="sm" className="rounded-xl border-white/10 hover:border-brand-500/30">
                <Link href="/helps/">
                  <i className="bi bi-arrow-left mr-1.5"></i>
                  Quay lại trang chủ
                </Link>
              </Button>
            </div>
          </Card>
        </main>
      </div>
    </div>
  );
}
