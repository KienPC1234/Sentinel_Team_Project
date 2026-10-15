'use client';
import { useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import Link from 'next/link';
import { Button } from './ui/button';

/* ============ GlassCard — Modern Glass ============ */
export function GlassCard({
  children,
  className = '',
  hover = false,
}: {
  children: ReactNode;
  className?: string;
  hover?: boolean;
}) {
  return (
    <div
      className={`bg-slate-900/60 backdrop-blur-md border border-white/10 rounded-2xl shadow-xl transition-all duration-300 ${
        hover ? 'hover:border-brand-500/30 hover:shadow-brand-500/10 hover:-translate-y-1' : ''
      } ${className}`}
    >
      {children}
    </div>
  );
}

/* ============ RiskBadge — SAFE / WARNING / CRITICAL ============ */
export type RiskLevel = 'SAFE' | 'WARNING' | 'CRITICAL' | string;

export function riskClass(level: RiskLevel): string {
  const l = String(level || '').toUpperCase();
  if (l.includes('SAFE') || l.includes('GREEN') || l === 'LOW') return 'risk-badge-safe';
  if (l.includes('CRITICAL') || l.includes('RED') || l.includes('HIGH') || l.includes('DANGER'))
    return 'risk-badge-critical';
  return 'risk-badge-warning';
}

export function RiskBadge({ level, className = '' }: { level: RiskLevel; className?: string }) {
  return <span className={`risk-badge ${riskClass(level)} ${className}`}>{level}</span>;
}

/* ============ Buttons (shadcn/ui powered) ============ */
export function PrimaryButton({
  children,
  to,
  onClick,
  type,
  className = '',
}: {
  children: ReactNode;
  to?: string;
  onClick?: () => void;
  type?: 'button' | 'submit';
  className?: string;
}) {
  if (to) {
    return (
      <Button asChild variant="cyber" size="xl" className={className}>
        <Link href={to}>{children}</Link>
      </Button>
    );
  }
  return (
    <Button type={type || 'button'} onClick={onClick} variant="cyber" size="xl" className={className}>
      {children}
    </Button>
  );
}

export function GhostButton({
  children,
  to,
  href,
  onClick,
  className = '',
}: {
  children: ReactNode;
  to?: string;
  href?: string;
  onClick?: () => void;
  className?: string;
}) {
  if (to) {
    return (
      <Button asChild variant="outline" size="xl" className={`backdrop-blur-md bg-white/5 border-white/10 hover:bg-white/10 ${className}`}>
        <Link href={to}>{children}</Link>
      </Button>
    );
  }
  if (href) {
    return (
      <Button asChild variant="outline" size="xl" className={`backdrop-blur-md bg-white/5 border-white/10 hover:bg-white/10 ${className}`}>
        <a href={href}>{children}</a>
      </Button>
    );
  }
  return (
    <Button type="button" onClick={onClick} variant="outline" size="xl" className={`backdrop-blur-md bg-white/5 border-white/10 hover:bg-white/10 ${className}`}>
      {children}
    </Button>
  );
}

/* ============ Section heading ============ */
export function SectionHead({
  title,
  subtitle,
  linkText,
  linkTo,
  accent = 'text-brand-400',
}: {
  title: string;
  subtitle?: string;
  linkText?: string;
  linkTo?: string;
  accent?: string;
}) {
  return (
    <div className="text-center space-y-4">
      <h2 className="text-4xl font-black text-white tracking-tight">{title}</h2>
      {subtitle && <p className="text-white/55 max-w-xl mx-auto">{subtitle}</p>}
      {linkText && linkTo && (
        <Link href={linkTo} className={`${accent} text-xs font-black uppercase tracking-widest`}>
          {linkText}
        </Link>
      )}
    </div>
  );
}

/* ============ Scan tool card (ô công cụ trang chủ) ============ */
export interface ToolCardDef {
  to: string;
  icon: string;
  iconBg: string;
  iconColor: string;
  iconHoverBg?: string;
  hoverBorder: string;
  title: string;
  desc: string;
  cta: string;
  ctaColor?: string;
  bgIcon: string;
  /** Extra class cho thẻ (vd. bg-white/[0.05] ở thẻ Cộng đồng). */
  bgClass?: string;
  delay?: number;
}

export function ScanToolCard({ tool }: { tool: ToolCardDef }) {
  return (
    <a
      href={tool.to}
      className={`liquid-card p-10 group ${tool.hoverBorder} transition-all no-underline ${tool.bgClass || ''} overflow-hidden`}
    >
      <div className="absolute top-0 right-0 p-6 opacity-5 group-hover:opacity-10 transition-opacity">
        <i className={`bi ${tool.bgIcon} text-7xl`}></i>
      </div>
      <div
        className={`w-14 h-14 rounded-2xl ${tool.iconBg} flex items-center justify-center ${tool.iconColor} mb-6 group-hover:scale-110 ${tool.iconHoverBg || ''} transition-all duration-500`}
      >
        <i className={`bi ${tool.icon} text-2xl`}></i>
      </div>
      <h3 className="text-xl font-black text-white mb-3">{tool.title}</h3>
      <p className="text-xs text-white/55 leading-relaxed mb-8 flex-1">{tool.desc}</p>
      <div className="flex items-center justify-between mt-auto pt-4 border-t border-white/5">
        <span className={`text-[10px] font-black uppercase tracking-widest ${tool.ctaColor || tool.iconColor}`}>{tool.cta}</span>
        <i className={`bi bi-arrow-right ${tool.ctaColor || tool.iconColor} group-hover:translate-x-2 transition-transform`}></i>
      </div>
    </a>
  );
}

/* ============ Stat card ============ */
export function StatCard({ value, label, valueClass = 'text-white', glow = false }: { value: string; label: string; valueClass?: string; glow?: boolean }) {
  return (
    <div className="bg-slate-900/60 backdrop-blur-md border border-white/10 p-6 sm:p-8 rounded-2xl text-center shadow-xl hover:border-brand-500/30 transition-all">
      <div className={`text-3xl sm:text-4xl font-black ${valueClass} ${glow ? 'glow-text' : ''} mb-1.5`}>{value}</div>
      <div className="text-[10px] sm:text-xs text-white/45 font-black uppercase tracking-[0.2em]">{label}</div>
    </div>
  );
}

/* ============ Spinner / Empty ============ */
export function Spinner({ className = '' }: { className?: string }) {
  return (
    <div className={`flex items-center justify-center p-8 ${className}`}>
      <div className="w-8 h-8 rounded-full border-2 border-brand-500/20 border-t-brand-400 animate-spin"></div>
    </div>
  );
}

export function EmptyState({ icon = 'bi-inbox', text }: { icon?: string; text: string }) {
  return (
    <div className="liquid-card p-5 text-white/35 text-sm text-center">
      <i className={`bi ${icon} text-2xl block mb-2`}></i>
      {text}
    </div>
  );
}

/* ============ Markdown view (render HTML đã sanitize) ============ */
export function MarkdownView({ html, className = '' }: { html: string; className?: string }) {
  return <div className={`ai-markdown ${className}`} dangerouslySetInnerHTML={{ __html: html }} />;
}

/* ============================================================================
 * UI kit dùng chung — port các phần tử lặp lại nhiều lần ở template gốc.
 * (LiquidSelect ≈ Alpine `liquidSelect()`, tab bar, admin page header, pill...)
 * ========================================================================== */

/* ---------- LiquidSelect (dropdown tuỳ biến, port `.liquid-custom-select`) ---------- */
export interface SelectOption {
  value: string;
  label: string;
}

export function LiquidSelect({
  value,
  options,
  onChange,
  placeholder = 'Chọn...',
  className = '',
  triggerClass = 'py-2.5 px-4 text-xs',
}: {
  value: string;
  options: SelectOption[];
  onChange: (value: string) => void;
  placeholder?: string;
  className?: string;
  triggerClass?: string;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open]);

  const current = options.find((o) => o.value === value);

  return (
    <div ref={ref} className={`dropdown-container liquid-custom-select relative ${className}`}>
      <div
        className={`liquid-select-trigger ${triggerClass} ${open ? 'active' : ''}`}
        role="button"
        tabIndex={0}
        onClick={() => setOpen((v) => !v)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            setOpen((v) => !v);
          }
        }}
      >
        <span className="truncate">{current ? current.label : placeholder}</span>
        <i className="bi bi-chevron-down liquid-select-arrow"></i>
      </div>
      {open && (
        <div className="liquid-select-dropdown entering">
          {options.map((o) => (
            <div
              key={o.value}
              className={`liquid-select-option ${value === o.value ? 'selected' : ''}`}
              onClick={() => {
                onChange(o.value);
                setOpen(false);
              }}
            >
              <span>{o.label}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ---------- Tab bar ---------- */
export interface TabDef {
  id: string;
  label: string;
  icon?: string;
}

export function Tabs({
  tabs,
  active,
  onChange,
  className = '',
}: {
  tabs: TabDef[];
  active: string;
  onChange: (id: string) => void;
  className?: string;
}) {
  return (
    <div className={`flex flex-wrap gap-2 ${className}`}>
      {tabs.map((t) => (
        <button
          key={t.id}
          type="button"
          onClick={() => onChange(t.id)}
          className={`px-4 py-2 rounded-xl text-xs font-bold transition-all ${
            active === t.id
              ? 'bg-brand-500/15 text-brand-300 border border-brand-500/30'
              : 'bg-white/5 text-white/60 border border-white/10 hover:text-white'
          }`}
        >
          {t.icon && <i className={`bi ${t.icon} mr-1.5`}></i>}
          {t.label}
        </button>
      ))}
    </div>
  );
}

/* ---------- Admin page header (nút quay lại + icon + tiêu đề) ---------- */
export function AdminPageHeader({
  backTo = '/admin-cp/',
  title,
  subtitle,
  children,
  className = '',
}: {
  backTo?: string;
  title: string;
  subtitle?: string;
  children?: ReactNode;
  className?: string;
}) {
  return (
    <div className={`flex flex-col md:flex-row md:items-center justify-between gap-6 mb-12 ${className}`}>
      <div className="flex items-center gap-6">
        <Link
          href={backTo}
          className="w-14 h-14 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center text-white/55 hover:text-brand-400 hover:border-brand-500/30 transition-all shadow-lg shrink-0"
        >
          <i className="bi bi-chevron-left text-2xl"></i>
        </Link>
        <div>
          <h1 className="text-3xl font-black text-white tracking-tight">{title}</h1>
          {subtitle && (
            <p className="text-[10px] font-bold text-white/35 uppercase tracking-widest mt-1">{subtitle}</p>
          )}
        </div>
      </div>
      {children}
    </div>
  );
}

/* ---------- Filter pill ---------- */
export function Pill({
  children,
  active = false,
  onClick,
  className = '',
}: {
  children: ReactNode;
  active?: boolean;
  onClick?: () => void;
  className?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`px-4 py-2 rounded-xl text-xs font-bold transition-all border ${
        active
          ? 'bg-brand-500 text-black border-brand-400'
          : 'bg-white/5 text-white/60 border-white/10 hover:bg-white/10'
      } ${className}`}
    >
      {children}
    </button>
  );
}

/* ---------- Status / role badges ---------- */
const BADGE_TONES: Record<string, string> = {
  green: 'bg-safe-500/10 text-safe-400 border-safe-500/20',
  cyan: 'bg-brand-500/10 text-brand-300 border-brand-500/20',
  yellow: 'bg-warn-500/10 text-warn-300 border-warn-500/20',
  red: 'bg-danger-500/10 text-danger-300 border-danger-500/20',
  violet: 'bg-brand2-500/10 text-brand2-300 border-brand2-500/20',
  slate: 'bg-white/5 text-white/60 border-white/10',
};

export type BadgeTone = 'green' | 'cyan' | 'yellow' | 'red' | 'violet' | 'slate';

export function Badge({
  children,
  tone = 'slate',
  icon,
  className = '',
}: {
  children: ReactNode;
  tone?: BadgeTone;
  icon?: string;
  className?: string;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border text-[10px] font-black uppercase tracking-wider ${BADGE_TONES[tone]} ${className}`}
    >
      {icon && <i className={`bi ${icon}`}></i>}
      {children}
    </span>
  );
}

/* ---------- Spinner nhỏ inline (port `.spinner`) ---------- */
export function InlineSpinner({ className = '', dark = false }: { className?: string; dark?: boolean }) {
  return (
    <span
      className={`inline-block w-4 h-4 rounded-full border-2 ${
        dark ? 'border-black/20 border-t-black' : 'border-white/20 border-t-brand-400'
      } animate-spin align-[-2px] ${className}`}
    />
  );
}

