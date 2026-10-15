'use client';
/* Trang Nguồn & Độ tin cậy — hiển thị minh bạch:
 * nguồn dữ liệu + độ tin cậy/giới hạn, kênh chính thức VN, báo chí, chính sách riêng tư, trạng thái lưu trữ.
 * API: /trust/sources/, /trust/policy/, /trust/channels/, /trust/privacy/, /trust/storage/.
 */
import { useEffect, useState } from 'react';
import { api } from '../lib/api';

interface SourceItem { key: string; name: string; reliability: string; kind: string; description: string; limits?: string; url?: string | null; }
interface Channel { name: string; phone?: string | null; url?: string | null; description?: string; reliability?: string; }
interface Ref { title: string; url: string; type: string; }
interface Policy { principle?: string; gray_zone?: string; ai_role?: string; disclaimer?: string; }
interface Privacy { enabled?: boolean; summary?: string; protected_fields?: string[]; local_first?: string; retention?: string; }
interface Storage { media_backend?: string; static_backend?: string; media_url?: string; static_url?: string; using_s3?: boolean; bucket?: string; endpoint?: string; public_domain?: string; s3_reachable?: boolean; }

const REL: Record<string, { label: string; cls: string }> = {
  high: { label: 'Tin cậy cao', cls: 'bg-safe-500/10 text-safe-400 border-safe-500/20' },
  medium: { label: 'Tin cậy vừa', cls: 'bg-warn-500/10 text-warn-400 border-warn-500/20' },
  low: { label: 'Tham khảo', cls: 'bg-danger-500/10 text-danger-400 border-danger-500/20' },
};

export default function Trust() {
  const [sources, setSources] = useState<SourceItem[]>([]);
  const [policy, setPolicy] = useState<Policy>({});
  const [channels, setChannels] = useState<Channel[]>([]);
  const [refs, setRefs] = useState<Ref[]>([]);
  const [press, setPress] = useState<Ref[]>([]);
  const [privacy, setPrivacy] = useState<Privacy>({});
  const [storage, setStorage] = useState<Storage>({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([
      api.get<{ policy?: string; gray_zone?: string; sources?: SourceItem[] }>('/trust/sources/'),
      api.get<Policy>('/trust/policy/'),
      api.get<{ channels?: Channel[]; references?: Ref[]; press?: Ref[] }>('/trust/channels/'),
      api.get<Privacy>('/trust/privacy/'),
      api.get<Storage>('/trust/storage/'),
    ]).then(([s, p, c, pv, st]) => {
      if (s.status === 'fulfilled' && s.value) { setPolicy((x) => ({ ...x, principle: s.value.policy, gray_zone: s.value.gray_zone })); setSources(s.value.sources || []); }
      if (p.status === 'fulfilled') setPolicy((x) => ({ ...x, ...p.value }));
      if (c.status === 'fulfilled' && c.value) { setChannels(c.value.channels || []); setRefs(c.value.references || []); setPress(c.value.press || []); }
      if (pv.status === 'fulfilled') setPrivacy(pv.value);
      if (st.status === 'fulfilled') setStorage(st.value);
      setLoading(false);
    });
  }, []);

  return (
    <div className="animate-fadein max-w-6xl mx-auto space-y-10 py-10 px-4">
      <div className="text-center space-y-4">
        <div className="inline-flex items-center justify-center w-20 h-20 rounded-[2.5rem] bg-brand-500/10 text-brand-400 border border-brand-500/20">
          <i className="bi bi-patch-check-fill text-4xl"></i>
        </div>
        <h1 className="text-4xl font-black text-white tracking-tight">Nguồn &amp; <span className="glow-text">Độ tin cậy</span></h1>
        <p className="text-white/60 max-w-2xl mx-auto text-sm leading-relaxed">
          Minh bạch nguồn dữ liệu, độ tin cậy và giới hạn của từng công cụ, cùng cách chúng tôi xử lý &amp; bảo vệ dữ liệu của bạn.
        </p>
      </div>

      {loading && <p className="text-center text-white/45 text-sm">Đang tải…</p>}

      {/* Nguyên tắc */}
      {policy.principle && (
        <section className="liquid-card p-6 sm:p-8 space-y-3">
          <h2 className="text-sm font-black text-white uppercase tracking-wider"><i className="bi bi-signpost-split me-2 text-brand-400"></i>Nguyên tắc tin cậy</h2>
          <p className="text-white/70 text-sm leading-relaxed">{policy.principle}</p>
          {policy.gray_zone && <p className="text-white/60 text-xs leading-relaxed"><b className="text-warn-400">Vùng xám:</b> {policy.gray_zone}</p>}
          {policy.ai_role && <p className="text-white/60 text-xs leading-relaxed"><b className="text-brand-400">Vai trò AI:</b> {policy.ai_role}</p>}
        </section>
      )}

      {/* Danh mục nguồn */}
      <section className="space-y-4">
        <h2 className="text-sm font-black text-white uppercase tracking-wider"><i className="bi bi-diagram-3 me-2 text-brand-400"></i>Nguồn dữ liệu &amp; giới hạn ({sources.length})</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {sources.map((s) => {
            const rel = REL[s.reliability] || REL.medium;
            return (
              <div key={s.key} className="p-4 rounded-2xl bg-white/[0.02] border border-white/[0.06] space-y-2">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[12px] font-black text-white/85">{s.name}</span>
                  <span className={`px-2 py-0.5 rounded-full text-[9px] font-black border ${rel.cls}`}>{rel.label}</span>
                  <span className="text-[9px] uppercase tracking-widest text-white/45">{s.kind}</span>
                </div>
                <p className="text-xs text-white/60 leading-relaxed">{s.description}</p>
                {s.limits && <p className="text-[11px] text-white/35 italic">Giới hạn: {s.limits}</p>}
                {s.url && <a href={s.url} target="_blank" rel="noopener noreferrer" className="text-[10px] font-black text-brand-400 hover:text-brand-300"><i className="bi bi-box-arrow-up-right me-1"></i>Nguồn</a>}
              </div>
            );
          })}
        </div>
      </section>

      {/* Kênh chính thức + báo chí */}
      <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="liquid-card p-6 space-y-4">
          <h2 className="text-sm font-black text-white uppercase tracking-wider"><i className="bi bi-telephone-outbound me-2 text-brand-400"></i>Kênh xác minh chính thức</h2>
          <div className="space-y-2">
            {channels.map((c, i) => (
              <div key={i} className="flex items-center gap-2 flex-wrap text-xs">
                <i className="bi bi-building-check text-brand-400"></i>
                <span className="text-white/75 font-bold">{c.name}</span>
                {c.phone && <a href={`tel:${String(c.phone).replace(/[^0-9+]/g, '')}`} className="text-brand-400 font-black">{c.phone}</a>}
                {c.url && <a href={c.url} target="_blank" rel="noopener noreferrer" className="text-brand-400"><i className="bi bi-box-arrow-up-right"></i></a>}
              </div>
            ))}
          </div>
          {refs.length > 0 && (
            <div className="pt-3 border-t border-white/10">
              <p className="text-[10px] font-black text-white/45 uppercase tracking-widest mb-2">Cổng chính phủ</p>
              <div className="flex flex-wrap gap-2">
                {refs.map((r, i) => <a key={i} href={r.url} target="_blank" rel="noopener noreferrer" className="text-[10px] px-2.5 py-1 rounded-lg bg-white/5 border border-white/10 text-white/60 hover:text-brand-400">{r.title}</a>)}
              </div>
            </div>
          )}
        </div>
        <div className="liquid-card p-6 space-y-4">
          <h2 className="text-sm font-black text-white uppercase tracking-wider"><i className="bi bi-newspaper me-2 text-warn-400"></i>Báo chí chính thống ({press.length})</h2>
          <div className="flex flex-wrap gap-2">
            {press.map((r, i) => <a key={i} href={r.url} target="_blank" rel="noopener noreferrer" className="text-[10px] px-2.5 py-1 rounded-lg bg-warn-500/10 border border-warn-500/20 text-warn-300/80 hover:text-warn-200">{r.title}</a>)}
          </div>
          <p className="text-[11px] text-white/55 leading-relaxed">Nội dung kho tri thức được biên soạn kèm nguồn tham khảo; AI trả lời dựa trên các nguồn này.</p>
        </div>
      </section>

      {/* Bảo mật dữ liệu + Lưu trữ */}
      <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="liquid-card p-6 space-y-3">
          <h2 className="text-sm font-black text-white uppercase tracking-wider"><i className="bi bi-shield-lock me-2 text-safe-400"></i>Bảo mật dữ liệu</h2>
          <p className="text-xs text-white/60 leading-relaxed">{privacy.summary}</p>
          {privacy.protected_fields && (
            <div className="flex flex-wrap gap-2">
              {privacy.protected_fields.map((f) => <span key={f} className="text-[9px] px-2 py-0.5 rounded-full bg-safe-500/10 text-safe-400 border border-safe-500/20 uppercase">{f}</span>)}
            </div>
          )}
          {privacy.local_first && <p className="text-[11px] text-white/55 leading-relaxed">{privacy.local_first}</p>}
          {privacy.retention && <p className="text-[11px] text-white/55 leading-relaxed">{privacy.retention}</p>}
        </div>
        <div className="liquid-card p-6 space-y-3">
          <h2 className="text-sm font-black text-white uppercase tracking-wider"><i className="bi bi-hdd-network me-2 text-brand-400"></i>Lưu trữ (Object Storage)</h2>
          <div className="flex items-center gap-2 text-xs">
            <span className={`px-2 py-0.5 rounded-full text-[10px] font-black border ${storage.using_s3 ? 'bg-safe-500/10 text-safe-400 border-safe-500/20' : 'bg-white/5 text-white/60 border-white/10'}`}>
              {storage.using_s3 ? 'S3-compatible' : 'Lưu cục bộ'}
            </span>
            {storage.using_s3 && storage.s3_reachable && <span className="text-[10px] text-safe-400"><i className="bi bi-check-circle me-1"></i>kết nối OK</span>}
          </div>
          <div className="text-[11px] text-white/60 space-y-1 font-mono">
            {storage.media_backend && <div>media: {storage.media_backend}</div>}
            {storage.static_backend && <div>static: {storage.static_backend}</div>}
            {storage.bucket && <div>bucket: {storage.bucket}</div>}
            {storage.public_domain && <div>domain: {storage.public_domain}</div>}
          </div>
          {policy.disclaimer && <p className="text-[11px] text-white/55 leading-relaxed italic pt-2 border-t border-white/10">{policy.disclaimer}</p>}
        </div>
      </section>
    </div>
  );
}
