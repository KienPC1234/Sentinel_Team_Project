'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { motion } from 'framer-motion';
import { ScanToolCard, StatCard, Spinner } from '../components/ui';
import type { ToolCardDef } from '../components/ui';
import { Button } from '../components/ui/button';
import { Card } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { api, learnApi, asList, mediaUrl } from '../lib/api';
import type { Article } from '../lib/api';

/* Ô "Phân tích chuyên sâu" trong Scanner card — chuẩn hóa thương hiệu Cyan */
const QUICK_SCAN = [
  { to: '/scan/phone/', icon: 'bi-telephone', label: 'SĐT', hover: 'hover:border-brand-500/40', color: 'group-hover:text-brand-400' },
  { to: '/scan/website/', icon: 'bi-globe2', label: 'URL', hover: 'hover:border-brand-500/40', color: 'group-hover:text-brand-400' },
  { to: '/scan/bank/', icon: 'bi-bank2', label: 'Bank', hover: 'hover:border-brand-500/40', color: 'group-hover:text-brand-400' },
  { to: '/scan/message/', icon: 'bi-chat-left-text', label: 'SMS', hover: 'hover:border-brand-500/40', color: 'group-hover:text-brand-400' },
];

const TOOLS: ToolCardDef[] = [
  { to: '/scan/phone/', icon: 'bi-phone-vibrate', iconBg: 'bg-brand-500/10', iconColor: 'text-brand-400', iconHoverBg: 'group-hover:bg-brand-500/20', hoverBorder: 'hover:border-brand-500/50', title: 'Tra cứu Số điện thoại', desc: 'Xác thực danh tính người gọi, phát hiện các đầu số rác và lừa đảo chuyên nghiệp từ database PKV.', cta: 'KHÁM PHÁ NGAY', bgIcon: 'bi-phone', delay: 100 },
  { to: '/scan/message/', icon: 'bi-chat-square-text', iconBg: 'bg-brand-500/10', iconColor: 'text-brand-400', iconHoverBg: 'group-hover:bg-brand-500/20', hoverBorder: 'hover:border-brand-500/50', title: 'Phân tích Tin nhắn', desc: 'Trí tuệ nhân tạo bóc tách bẫy tâm lý, link phishing và các dấu hiệu gian lận trực tuyến.', cta: 'SỬ DỤNG AI', bgIcon: 'bi-chat-dots', delay: 200 },
  { to: '/scan/website/', icon: 'bi-globe2', iconBg: 'bg-brand-500/10', iconColor: 'text-brand-400', iconHoverBg: 'group-hover:bg-brand-500/20', hoverBorder: 'hover:border-brand-500/50', title: 'Quét Website / Link', desc: 'Kiểm tra độ tin cậy của website trước khi nhập thông tin cá nhân hoặc thanh toán online.', cta: 'TRACKER SCAN', bgIcon: 'bi-globe', delay: 300 },
  { to: '/scan/email/', icon: 'bi-envelope-open', iconBg: 'bg-brand-500/10', iconColor: 'text-brand-400', iconHoverBg: 'group-hover:bg-brand-500/20', hoverBorder: 'hover:border-brand-500/50', title: 'Quét Email', desc: 'Phân tích email header, phát hiện phishing và giả mạo danh tính người gửi bằng AI chuyên sâu.', cta: 'PHÂN TÍCH EMAIL', bgIcon: 'bi-envelope', delay: 100 },
  { to: '/scan/bank/', icon: 'bi-credit-card-2-front', iconBg: 'bg-brand-500/10', iconColor: 'text-brand-400', iconHoverBg: 'group-hover:bg-brand-500/20', hoverBorder: 'hover:border-brand-500/50', title: 'Xác thực Tài khoản', desc: 'Kiểm tra chéo số tài khoản ngân hàng với cơ sở dữ liệu gian lận liên ngành quốc gia.', cta: 'AN TOÀN GIAO DỊCH', bgIcon: 'bi-credit-card', delay: 200 },
  { to: '/scan/qr/', icon: 'bi-qr-code-scan', iconBg: 'bg-brand-500/10', iconColor: 'text-brand-400', iconHoverBg: 'group-hover:bg-brand-500/20', hoverBorder: 'hover:border-brand-500/50', title: 'Quét QR & Hình ảnh', desc: 'Bóc tách dữ liệu từ mã QR, hóa đơn và ảnh chụp màn hình bằng công nghệ Computer Vision.', cta: 'LENS AI SCANNER', bgIcon: 'bi-qr-code', delay: 300 },
  { to: '/scan/file/', icon: 'bi-file-earmark-lock', iconBg: 'bg-brand-500/10', iconColor: 'text-brand-400', iconHoverBg: 'group-hover:bg-brand-500/20', hoverBorder: 'hover:border-brand-500/50', title: 'Quét File & Mã độc', desc: 'Kiểm tra và mổ xẻ tệp tin qua Sentinel Zero-Trust Docker Sandbox (YARA, OLETools, PEFile, ClamAV) phát hiện ransomware, macro và trojan.', cta: 'SANDBOX FILE', bgIcon: 'bi-file-earmark', delay: 100 },
  { to: '/scan/audio/', icon: 'bi-soundwave', iconBg: 'bg-brand-500/10', iconColor: 'text-brand-400', iconHoverBg: 'group-hover:bg-brand-500/20', hoverBorder: 'hover:border-brand-500/50', title: 'Quét Âm Thanh', desc: 'Tải lên hoặc ghi âm trực tiếp: AI nhận diện giọng nói, chuyển thành văn bản và phân tích lừa đảo.', cta: 'VOICE AI SCAN', bgIcon: 'bi-mic', delay: 200 },
  { to: '/forum/', icon: 'bi-people', iconBg: 'bg-white/10', iconColor: 'text-white', iconHoverBg: '', hoverBorder: 'hover:border-white/40', title: 'Cộng đồng ShieldCall', desc: 'Tham gia cùng cộng đồng để cùng nhau xây dựng mạng lưới an toàn và hỗ trợ người bị lừa.', cta: 'THAM GIA NGAY', ctaColor: 'text-white/60', bgIcon: 'bi-people', bgClass: 'bg-white/[0.05]', delay: 300 },
];

function fmtDate(iso?: string): string {
  if (!iso) return '';
  try {
    const d = new Date(iso);
    return `${String(d.getDate()).padStart(2, '0')}/${String(d.getMonth() + 1).padStart(2, '0')}/${d.getFullYear()}`;
  } catch {
    return '';
  }
}

/* Kiểu chung cho card featured/mini (lesson & article). */
interface ContentItem {
  slug: string;
  title: string;
  summary?: string;
  category_display?: string;
  cover_image?: string | null;
  created_at?: string;
}

/* Hàng "Kiến thức mới" lấy từ API /learn/lessons/. */
type LessonItem = ContentItem;

function FeaturedCard({
  item,
  accent,
  label,
  linkPrefix,
  fallbackIcon,
}: {
  item: ContentItem;
  accent: 'cyan' | 'indigo';
  label: string;
  linkPrefix: string;
  fallbackIcon: string;
}) {
  const isCyan = accent === 'cyan';
  const hasCover = Boolean(item.cover_image);

  return (
    <Link
      href={`${linkPrefix}${item.slug}/`}
      className={`group block relative rounded-2xl overflow-hidden border border-white/10 bg-slate-900/80 hover:bg-slate-900/95 transition-all duration-300 ${
        isCyan ? 'hover:border-brand-500/40 hover:shadow-brand-500/10' : 'hover:border-brand-500/40 hover:shadow-brand-500/10'
      } hover:shadow-xl no-underline`}
    >
      {hasCover ? (
        <div className="relative h-44 sm:h-48 overflow-hidden">
          <img
            src={mediaUrl(item.cover_image)}
            alt={item.title}
            className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500"
          />
          <div className="absolute inset-0 bg-gradient-to-t from-slate-950 via-slate-950/60 to-transparent"></div>
          <div className="absolute bottom-0 left-0 right-0 p-5">
            <span
              className={`inline-block px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider mb-2 ${
                isCyan
                  ? 'bg-brand-500/20 text-brand-300 border border-brand-500/30'
                  : 'bg-brand2-500/20 text-brand2-300 border border-brand2-500/30'
              }`}
            >
              {label}
            </span>
            <h3 className="text-base font-bold text-white group-hover:text-brand-300 transition-colors leading-snug line-clamp-2">
              {item.title}
            </h3>
            <p className="text-[11px] text-slate-400 mt-2 flex items-center gap-1.5">
              <i className="bi bi-clock text-[10px]"></i> {fmtDate(item.created_at)}
            </p>
          </div>
        </div>
      ) : (
        <div
          className={`p-5 sm:p-6 relative overflow-hidden bg-gradient-to-br ${
            isCyan
              ? 'from-brand-950/40 via-slate-900 to-slate-950'
              : 'from-brand2-950/40 via-slate-900 to-slate-950'
          }`}
        >
          <div className="flex items-center justify-between mb-3.5">
            <span
              className={`inline-block px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                isCyan
                  ? 'bg-brand-500/15 text-brand-400 border border-brand-500/25'
                  : 'bg-brand2-500/15 text-brand2-400 border border-brand2-500/25'
              }`}
            >
              {label}
            </span>
            <div
              className={`w-9 h-9 rounded-xl flex items-center justify-center ${
                isCyan
                  ? 'bg-brand-500/10 text-brand-400 border border-brand-500/20'
                  : 'bg-brand2-500/10 text-brand2-400 border border-brand2-500/20'
              } text-base`}
            >
              <i className={`bi ${fallbackIcon}`}></i>
            </div>
          </div>
          <h3 className="text-base sm:text-lg font-bold text-white group-hover:text-brand-300 transition-colors leading-snug line-clamp-2 mb-2">
            {item.title}
          </h3>
          {item.summary && (
            <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed mb-4">
              {item.summary}
            </p>
          )}
          <div className="flex items-center justify-between text-[11px] text-slate-400 pt-2 border-t border-white/5">
            <span className="flex items-center gap-1.5">
              <i className="bi bi-calendar3 text-[10px]"></i> {fmtDate(item.created_at)}
            </span>
            <span
              className={`font-semibold flex items-center gap-1 text-[11px] ${
                isCyan ? 'text-brand-400 group-hover:text-brand-300' : 'text-brand-400 group-hover:text-brand-300'
              }`}
            >
              Đọc tiếp <i className="bi bi-arrow-right text-[10px] group-hover:translate-x-0.5 transition-transform"></i>
            </span>
          </div>
        </div>
      )}
    </Link>
  );
}

function MiniRow({
  item,
  linkPrefix,
  fallbackIcon,
  accent = 'cyan',
}: {
  item: ContentItem;
  linkPrefix: string;
  fallbackIcon: string;
  accent?: 'cyan' | 'indigo';
}) {
  const isCyan = accent === 'cyan';
  const hasCover = Boolean(item.cover_image);

  return (
    <Link
      href={`${linkPrefix}${item.slug}/`}
      className={`group flex items-center gap-3.5 p-3 rounded-xl border border-white/8 bg-slate-900/60 hover:bg-slate-900/95 ${
        isCyan ? 'hover:border-brand-500/30' : 'hover:border-brand-500/30'
      } transition-all duration-200 no-underline shadow-sm`}
    >
      <div className="w-12 h-12 rounded-lg overflow-hidden border border-white/10 bg-slate-800/80 flex-shrink-0 flex items-center justify-center">
        {hasCover ? (
          <img
            src={mediaUrl(item.cover_image)}
            alt={item.title}
            className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
          />
        ) : (
          <div
            className={`w-full h-full flex items-center justify-center text-base ${
              isCyan ? 'bg-brand-500/10 text-brand-400' : 'bg-brand-500/10 text-brand-400'
            }`}
          >
            <i className={`bi ${fallbackIcon}`}></i>
          </div>
        )}
      </div>
      <div className="min-w-0 flex-1">
        <h4 className="text-sm font-semibold text-slate-200 group-hover:text-white transition-colors line-clamp-2 leading-snug">
          {item.title}
        </h4>
        <div className="flex items-center gap-2 mt-1 text-[11px] text-slate-400">
          <span className="flex items-center gap-1">
            <i className="bi bi-clock text-[9px]"></i> {fmtDate(item.created_at)}
          </span>
          {item.category_display && (
            <span className="px-1.5 py-0.2 rounded bg-white/5 text-[10px] text-slate-300">
              {item.category_display}
            </span>
          )}
        </div>
      </div>
      <div
        className={`flex-shrink-0 text-slate-600 transition-all ${
          isCyan ? 'group-hover:text-brand-400' : 'group-hover:text-brand-400'
        } group-hover:translate-x-0.5 pr-1`}
      >
        <i className="bi bi-chevron-right text-xs"></i>
      </div>
    </Link>
  );
}

function formatStatNumber(n?: number, fallback = ''): string {
  if (n == null || isNaN(n) || n <= 0) return fallback;
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, '')}M+`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1).replace(/\.0$/, '')}K+`;
  return String(n);
}

export default function Home() {
  const router = useRouter();
  const [q, setQ] = useState('');
  const [articles, setArticles] = useState<Article[]>([]);
  const [lessons, setLessons] = useState<LessonItem[]>([]);
  const [loadingNews, setLoadingNews] = useState(true);
  const [stats, setStats] = useState<{ totalScans: string; threats: string }>({
    totalScans: '1.2M+',
    threats: '45K+',
  });

  useEffect(() => {
    let alive = true;
    Promise.allSettled([
      learnApi.articles({ ordering: '-created_at' }),
      learnApi.lessons({ ordering: '-created_at' }),
      api.get<{ total_scans?: number; scam_detected?: number }>('/stats/public/'),
    ]).then(([a, l, s]) => {
      if (!alive) return;
      if (a.status === 'fulfilled') setArticles(asList(a.value));
      if (l.status === 'fulfilled') setLessons(asList(l.value) as unknown as LessonItem[]);
      if (s.status === 'fulfilled' && s.value) {
        setStats((prev) => ({
          ...prev,
          ...(s.value.total_scans ? { totalScans: formatStatNumber(s.value.total_scans, prev.totalScans) } : {}),
          ...(s.value.scam_detected ? { threats: formatStatNumber(s.value.scam_detected, prev.threats) } : {}),
        }));
      }
      setLoadingNews(false);
    });
    return () => {
      alive = false;
    };
  }, []);

  const submitLookup = (e: React.FormEvent) => {
    e.preventDefault();
    if (!q.trim()) return;
    router.push(`/scan/lookup/?q=${encodeURIComponent(q.trim())}`);
  };

  /* Cả 2 cột lấy đúng 4 mục (1 featured + 3 mini rows) để chiều cao 2 cột cân bằng tuyệt đối */
  const latestLessons = lessons.slice(0, 4);
  const featuredLesson = latestLessons[0];
  const restLessons = latestLessons.slice(1, 4);

  const newsOnly = articles.filter((a) => a.category === 'news');
  const articlesPool = newsOnly.length >= 4 ? newsOnly : articles;
  const latestArticles = articlesPool.slice(0, 4);
  const featuredArticle = latestArticles[0];
  const restArticles = latestArticles.slice(1, 4);

  return (
    <div>
      {/* ============ HERO (port y Home/home.html) ============ */}
      <section className="relative pt-28 md:pt-32 pb-28 md:pb-36 hero-breakout">
        <div className="absolute -top-48 left-[8%] w-[720px] h-[720px] bg-brand-500/10 blur-[170px] rounded-full pointer-events-none"></div>
        <div className="absolute -top-36 right-[8%] w-[620px] h-[620px] bg-blue-600/8 blur-[170px] rounded-full pointer-events-none"></div>
        <div className="absolute -bottom-56 left-1/2 -translate-x-1/2 w-[980px] h-[520px] bg-brand-500/8 blur-[180px] rounded-full pointer-events-none"></div>
        <div className="absolute -bottom-24 left-0 right-0 h-40 bg-gradient-to-b from-transparent via-brand-500/[0.04] to-transparent pointer-events-none"></div>

        <div className="max-w-7xl mx-auto px-5 sm:px-8 lg:px-12 grid grid-cols-1 lg:grid-cols-2 gap-12 lg:gap-16 xl:gap-20 relative z-10">
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, ease: 'easeOut' }}
            className="space-y-8 self-center"
          >
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-brand-500/10 border border-brand-500/20 text-brand-400 text-xs font-black uppercase tracking-widest backdrop-blur-md shadow-[0_0_20px_rgba(34,211,238,0.1)]">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-brand-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-brand-500"></span>
              </span>
              Hệ thống bảo vệ AI
            </div>

            <h1 className="text-5xl md:text-6xl lg:text-7xl font-black text-white leading-[1.12] tracking-tight">
              Tìm đúng rủi ro.<br />
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-brand-300 via-brand-400 to-sky-300 drop-shadow-[0_0_20px_rgba(34,211,238,0.2)]">
                Bảo vệ mọi<br />tài khoản.
              </span>
            </h1>

            <p className="text-base md:text-lg text-white/60 max-w-lg leading-relaxed font-medium">
              Tra cứu và đối chiếu báo cáo lừa đảo từ đa nguồn. Tích hợp AI phân tích hành vi và bằng chứng OSINT theo thời gian thực để bảo vệ bạn 24/7.
            </p>

            <div className="flex flex-wrap gap-4 pt-2">
              <Button
                asChild
                className="h-14 px-8 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold rounded-xl transition-all duration-300 inline-flex items-center gap-3 overflow-hidden shadow-[0_0_30px_rgba(34,211,238,0.26)] hover:shadow-[0_0_42px_rgba(34,211,238,0.4)] hover:-translate-y-0.5"
              >
                <Link href="/scan/">
                  <i className="bi bi-radar text-lg"></i>
                  <span>Kích hoạt Scanner</span>
                </Link>
              </Button>
              <Button
                asChild
                variant="outline"
                className="h-14 px-8 border-white/10 bg-white/5 hover:bg-white/10 hover:border-white/20 text-white rounded-xl font-bold transition-all duration-300 inline-flex items-center gap-2 backdrop-blur-md hover:-translate-y-0.5"
              >
                <Link href="/scam-iq-exam/">
                  <i className="bi bi-patch-question-fill text-brand2-400"></i> BÀI KIỂM TRA SCAM IQ
                </Link>
              </Button>
            </div>

            <div className="flex flex-wrap items-center gap-4 pt-1">
              <span className="text-[11px] text-white/35 font-bold uppercase tracking-wider">Giám sát 24/7</span>
              <span className="w-1 h-1 rounded-full bg-white/30"></span>
              <span className="text-[11px] text-white/35 font-bold uppercase tracking-wider">Phân tích theo ngữ cảnh</span>
              <span className="w-1 h-1 rounded-full bg-white/30"></span>
              <span className="text-[11px] text-white/35 font-bold uppercase tracking-wider">Cảnh báo thời gian thực</span>
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.55, delay: 0.1, ease: 'easeOut' }}
            className="relative w-full max-w-lg mx-auto lg:ml-auto lg:mr-0 lg:pr-1 self-center"
          >
            <div className="relative p-[1px] rounded-3xl bg-gradient-to-b from-brand-500/30 via-brand2-500/10 to-transparent shadow-[0_20px_80px_-20px_rgba(34,211,238,0.15)]">
              <Card className="bg-slate-900/60 backdrop-blur-md border border-white/10 shadow-2xl rounded-3xl p-6 sm:p-8 relative overflow-hidden">
                <div className="absolute -top-24 -right-24 w-48 h-48 bg-brand-500/20 blur-[50px] rounded-full pointer-events-none"></div>
                <div className="relative z-10">
                  <div className="flex items-center justify-between mb-8">
                    <div>
                      <h3 className="text-xl font-black text-white mb-1">Scanner Engine</h3>
                      <p className="text-[11px] text-white/55 uppercase tracking-widest font-bold">ShieldCall VN v2.0</p>
                    </div>
                    <div className="w-10 h-10 rounded-full bg-white/5 border border-white/10 flex items-center justify-center text-brand-400">
                      <i className="bi bi-cpu text-lg"></i>
                    </div>
                  </div>

                  <form onSubmit={submitLookup} className="relative group">
                    <div className="absolute -inset-0.5 bg-gradient-to-r from-brand-500 to-brand2-500 rounded-2xl blur opacity-0 group-focus-within:opacity-30 transition duration-500"></div>
                    <div className="relative flex items-center">
                      <i className="bi bi-search absolute left-5 top-1/2 -translate-y-1/2 text-brand-400 text-lg pointer-events-none z-10"></i>
                      <Input
                        type="text"
                        value={q}
                        onChange={(e) => setQ(e.target.value)}
                        placeholder="Dán SĐT, URL, hoặc STK vào đây..."
                        className="w-full h-16 pl-14 pr-32 rounded-2xl bg-white/5 border border-white/10 text-white text-base placeholder:text-white/45 focus-visible:border-brand-400/50 focus-visible:ring-brand-400/20 transition-all shadow-inner"
                      />
                      <Button
                        type="submit"
                        className="absolute right-2 top-1/2 -translate-y-1/2 h-12 px-6 rounded-xl bg-white text-slate-950 text-sm font-black hover:bg-brand-400 transition-colors flex items-center gap-2 shadow-lg cursor-pointer"
                      >
                        Quét <i className="bi bi-arrow-right"></i>
                      </Button>
                    </div>
                  </form>

                  <div className="mt-8">
                    <p className="text-[11px] text-white/45 font-bold mb-4 uppercase tracking-widest">Phân tích chuyên sâu</p>
                    <div className="grid grid-cols-4 gap-3">
                      {QUICK_SCAN.map((s) => (
                        <Link
                          key={s.to}
                          href={s.to}
                          className={`flex flex-col items-center gap-2 p-3 rounded-2xl bg-white/[0.02] hover:bg-white/[0.08] border border-white/5 ${s.hover} transition-all group`}
                        >
                          <i className={`bi ${s.icon} text-white/60 ${s.color} text-xl transition-colors`}></i>
                          <span className="text-[10px] font-bold text-white/60 group-hover:text-white transition-colors">{s.label}</span>
                        </Link>
                      ))}
                    </div>
                  </div>
                </div>
              </Card>
            </div>
          </motion.div>
        </div>
      </section>

      {/* ============ Impact Stats Row ============ */}
      <motion.section
        initial={{ opacity: 0, y: 15 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, margin: "-40px" }}
        transition={{ duration: 0.4 }}
        className="max-w-6xl mx-auto px-4 mb-24 mt-8 md:mt-10 grid grid-cols-2 md:grid-cols-4 gap-4"
      >
        <StatCard value={stats.totalScans} label="Tổng Lượt Scan" valueClass="text-white" glow />
        <StatCard value={stats.threats} label="Mối Nguy Hiểm" valueClass="text-danger-500" />
        <StatCard value="99.8%" label="Độ Chính Xác" valueClass="text-safe-400" />
        <StatCard value="24/7" label="Thời Gian Thực" valueClass="text-brand-400" />
      </motion.section>

      {/* ============ Latest Knowledge & News ============ */}
      <motion.section
        initial={{ opacity: 0, y: 15 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, margin: "-40px" }}
        transition={{ duration: 0.4 }}
        className="max-w-7xl mx-auto px-4 mb-24 space-y-10"
      >
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-start">
          <div className="space-y-4">
            <div className="flex items-center justify-between pb-1">
              <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2.5">
                <span className="w-1.5 h-5 rounded-full bg-brand-400 inline-block shadow-[0_0_10px_rgba(34,211,238,0.5)]"></span>
                Kiến thức mới
              </h2>
              <Link
                href="/learn/?tab=lessons"
                className="text-brand-400 text-xs font-semibold uppercase tracking-wider hover:text-brand-300 flex items-center gap-1 transition-colors"
              >
                Xem tất cả <i className="bi bi-arrow-right text-[11px]"></i>
              </Link>
            </div>
            {featuredLesson ? (
              <>
                <FeaturedCard
                  item={featuredLesson}
                  accent="cyan"
                  label="Kiến thức nổi bật"
                  linkPrefix="/learn/lesson/"
                  fallbackIcon="bi-journal-bookmark"
                />
                <div className="space-y-2.5">
                  {restLessons.map((lesson) => (
                    <MiniRow
                      key={lesson.slug}
                      item={lesson}
                      linkPrefix="/learn/lesson/"
                      fallbackIcon="bi-journal-richtext"
                      accent="cyan"
                    />
                  ))}
                </div>
              </>
            ) : (
              <div className="rounded-2xl border border-white/10 bg-slate-900/60 p-5 text-slate-400 text-sm">
                Chưa có bài kiến thức nào.
              </div>
            )}
          </div>

          <div className="space-y-4">
            <div className="flex items-center justify-between pb-1">
              <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2.5">
                <span className="w-1.5 h-5 rounded-full bg-brand-400 inline-block shadow-[0_0_10px_rgba(129,140,248,0.5)]"></span>
                Tin tức mới
              </h2>
              <Link
                href="/learn/?tab=news&category=news"
                className="text-brand-400 text-xs font-semibold uppercase tracking-wider hover:text-brand-300 flex items-center gap-1 transition-colors"
              >
                Xem tất cả <i className="bi bi-arrow-right text-[11px]"></i>
              </Link>
            </div>
            {loadingNews ? (
              <div className="py-12 flex justify-center"><Spinner /></div>
            ) : featuredArticle ? (
              <>
                <FeaturedCard
                  item={featuredArticle}
                  accent="indigo"
                  label="Tin nổi bật"
                  linkPrefix="/learn/"
                  fallbackIcon="bi-newspaper"
                />
                <div className="space-y-2.5">
                  {restArticles.map((article) => (
                    <MiniRow
                      key={article.slug}
                      item={article}
                      linkPrefix="/learn/"
                      fallbackIcon="bi-newspaper"
                      accent="indigo"
                    />
                  ))}
                </div>
              </>
            ) : (
              <div className="rounded-2xl border border-white/10 bg-slate-900/60 p-5 text-slate-400 text-sm">
                Chưa có tin tức nào.
              </div>
            )}
          </div>
        </div>
      </motion.section>

      {/* ============ Tools Grid ============ */}
      <motion.section
        initial={{ opacity: 0, y: 15 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, margin: "-40px" }}
        transition={{ duration: 0.4 }}
        className="max-w-7xl mx-auto px-4 mb-24 space-y-12"
      >
        <div className="text-center space-y-4">
          <h2 className="text-4xl font-black text-white tracking-tight">Hệ sinh thái bảo vệ</h2>
          <p className="text-white/55 max-w-xl mx-auto">Bộ công cụ toàn diện giúp bạn an tâm tuyệt đối trên không gian số.</p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
          {TOOLS.map((t) => (
            <ScanToolCard key={t.to + t.title} tool={t} />
          ))}
        </div>
      </motion.section>

      {/* ============ Emergency Banner ============ */}
      <motion.section
        initial={{ opacity: 0, scale: 0.98 }}
        whileInView={{ opacity: 1, scale: 1 }}
        viewport={{ once: true, margin: "-40px" }}
        transition={{ duration: 0.45 }}
        className="max-w-6xl mx-auto px-4 mb-24"
      >
        <Card className="p-8 sm:p-12 text-center bg-gradient-to-br from-rose-950/30 via-slate-900/80 to-slate-950/80 border border-rose-500/25 relative overflow-hidden backdrop-blur-md rounded-3xl shadow-2xl">
          <div className="absolute -top-24 -right-24 w-64 h-64 bg-rose-500/10 blur-[100px] rounded-full pointer-events-none"></div>
          <div className="relative z-10 space-y-6">
            <div className="w-20 h-20 rounded-3xl bg-rose-500/15 border border-rose-500/20 flex items-center justify-center mx-auto mb-4">
              <i className="bi bi-exclamation-octagon text-4xl text-rose-500 animate-pulse"></i>
            </div>
            <h2 className="text-3xl md:text-5xl font-black text-white">Bạn đang bị tấn công lừa đảo?</h2>
            <p className="text-white/60 max-w-xl mx-auto text-base">Đừng hoảng sợ. Hãy thực hiện ngay quy trình khẩn cấp để đóng băng tài khoản và bảo vệ tài sản của bạn.</p>
            <div className="pt-4">
              <Button
                asChild
                className="h-14 px-12 bg-rose-500 text-white font-black hover:bg-rose-600 rounded-xl text-base shadow-2xl shadow-rose-500/30 hover:-translate-y-0.5 transition-all"
              >
                <Link href="/emergency/">
                  HỖ TRỢ KHẨN CẤP NGAY
                </Link>
              </Button>
            </div>
          </div>
        </Card>
      </motion.section>
    </div>
  );
}
