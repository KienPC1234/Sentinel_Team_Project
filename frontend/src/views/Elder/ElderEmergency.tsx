'use client';
import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { warmTts } from '../../lib/tts';

interface Hotline {
  name: string;
  phone: string;
  desc: string;
  tag?: string;
}

const EMERGENCY_SERVICES: Hotline[] = [
  {
    name: 'Công an khẩn cấp',
    phone: '113',
    desc: 'Báo công an ngay khi bị dọa dẫm, tống tiền hoặc nghi ngờ lừa đảo lớn',
    tag: 'Khẩn cấp 24/7',
  },
  {
    name: 'Tổng đài Quốc gia 156',
    phone: '156',
    desc: 'Bộ Thông tin & Truyền thông: Tiếp nhận tin nhắn, cuộc gọi lừa đảo, rác',
    tag: 'Miễn phí',
  },
  {
    name: 'Đường dây nóng An ninh mạng (A05)',
    phone: '0692343141',
    desc: 'Cục An ninh mạng và phòng chống tội phạm công nghệ cao (Bộ Công an)',
    tag: 'Chuyên môn',
  },
];

const BANK_HOTLINES: Hotline[] = [
  { name: 'Vietcombank', phone: '1900545413', desc: 'Ngân hàng Ngoại thương Việt Nam' },
  { name: 'Agribank', phone: '1900558818', desc: 'Ngân hàng Nông nghiệp & PTNT' },
  { name: 'BIDV', phone: '19009247', desc: 'Ngân hàng Đầu tư & Phát triển' },
  { name: 'VietinBank', phone: '1900558868', desc: 'Ngân hàng Công thương Việt Nam' },
  { name: 'Techcombank', phone: '1800588822', desc: 'Ngân hàng Kỹ thương (Miễn cước)' },
  { name: 'MBBank', phone: '1900545426', desc: 'Ngân hàng Quân đội' },
  { name: 'VPBank', phone: '1900545415', desc: 'Ngân hàng Việt Nam Thịnh vượng' },
  { name: 'ACB', phone: '1900545486', desc: 'Ngân hàng Á Châu' },
  { name: 'Sacombank', phone: '1800585888', desc: 'Ngân hàng Sài Gòn Thương tín (Miễn cước)' },
  { name: 'TPBank', phone: '1900585885', desc: 'Ngân hàng Tiên Phong' },
];

const SEND_ITEMS = [
  { to: '/scan/image/', icon: 'bi-image-fill', title: 'Gửi ảnh chụp màn hình', hint: 'Ảnh tin nhắn hoặc biên lai chuyển tiền' },
  { to: '/scan/audio/', icon: 'bi-mic-fill', title: 'Gửi ghi âm cuộc gọi', hint: 'Bác ghi âm lại lời kẻ gian rồi gửi lên cho cháu kiểm tra' },
  { to: '/emergency/', icon: 'bi-life-preserver', title: 'Trang cứu viện chuyên sâu', hint: 'Xem cẩm nang xử lý các bước thu hồi tiền' },
];

export default function ElderEmergency({
  canSpeak,
  speak,
}: {
  canSpeak: boolean;
  speak: (text: string) => void;
}) {
  const [installed, setInstalled] = useState(false);
  const [showSteps, setShowSteps] = useState(false);
  const [ios, setIos] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const nav = navigator as Navigator & { standalone?: boolean };
    setInstalled(window.matchMedia('(display-mode: standalone)').matches || nav.standalone === true);
    setIos(/iPhone|iPad|iPod/i.test(navigator.userAgent));
  }, []);

  const install = useCallback(async () => {
    setBusy(true);
    try {
      const ok = await window.ShieldCallPWA?.promptInstall();
      if (!ok) setShowSteps(true);
    } catch {
      setShowSteps(true);
    } finally {
      setBusy(false);
    }
  }, []);

  const steps = ios
    ? [
        'Mở trang này bằng Safari.',
        'Bấm vào nút Chia sẻ (ô vuông có mũi tên chỉ lên).',
        'Kéo xuống tìm dòng "Thêm vào Màn hình chính", rồi bấm "Thêm".',
      ]
    : [
        'Mở trang này bằng Chrome.',
        'Bấm vào nút ba chấm ở góc trên bên phải.',
        'Chọn "Thêm vào Màn hình chính" rồi bấm "Cài đặt".',
      ];

  const speechText =
    'Việc khẩn cấp cần làm ngay: Một, dừng lại không chuyển tiền. Hai, gọi khóa tài khoản ngân hàng ngay. '
    + 'Ba, giữ lại bằng chứng và gọi công an 113 hoặc 156. Bác có thể bấm trực tiếp các nút gọi trên màn hình.';

  /* Build trước audio cho đoạn "3 việc cần làm" ở server. */
  useEffect(() => {
    void warmTts([speechText]);
  }, [speechText]);

  return (
    <div className="space-y-8" role="tabpanel" id="panel-emergency" aria-labelledby="tab-emergency">
      {/* ── 3 Bước khẩn cấp ────────────────────────────────────────── */}
      <section className="elder-urgent space-y-4" aria-labelledby="elder-urgent-heading">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 id="elder-urgent-heading" className="elder-h2 flex items-center gap-3">
            <i className="bi bi-lightning-charge-fill elder-verdict__icon text-danger-300" aria-hidden="true"></i>
            Nếu có người đang đòi bác chuyển tiền ngay
          </h2>
          {canSpeak && (
            <button type="button" className="elder-btn" onClick={() => speak(speechText)}>
              <i className="bi bi-volume-up-fill elder-icon" aria-hidden="true"></i> Đọc to 3 việc cần làm
            </button>
          )}
        </div>

        <p className="elder-lead">
          Bác bình tĩnh làm ngay 3 việc này theo thứ tự, tuyệt đối không làm theo lời người gọi giục:
        </p>

        <ol className="space-y-3">
          <li className="elder-todo">
            <span className="elder-todo__num">1</span>
            <div>
              <strong className="block text-danger-200">Dừng lại ngay lập tức</strong>
              <span>Không chuyển thêm một đồng nào, dù họ dọa bắt giam hay hứa hẹn bất cứ điều gì.</span>
            </div>
          </li>
          <li className="elder-todo">
            <span className="elder-todo__num">2</span>
            <div>
              <strong className="block text-warn-200">Khoá tài khoản hoặc thẻ ngân hàng</strong>
              <span>
                Gọi ngay số hotline in ở mặt sau thẻ ATM của bác, hoặc bấm gọi vào danh sách số ngân hàng bên dưới để
                yêu cầu khóa tài khoản khẩn cấp.
              </span>
            </div>
          </li>
          <li className="elder-todo">
            <span className="elder-todo__num">3</span>
            <div>
              <strong className="block text-safe-200">Giữ nguyên bằng chứng & Báo con cháu</strong>
              <span>
                Giữ nguyên tin nhắn, số điện thoại, ảnh hóa đơn chuyển tiền, không xóa gì cả. Sau đó gọi cho người thân
                hoặc cơ quan công an gần nhất.
              </span>
            </div>
          </li>
        </ol>

        {/* Nút bấm gọi nhanh 1-chạm */}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 pt-2">
          <a
            href="tel:113"
            className="elder-btn elder-btn--danger elder-btn--xl"
            aria-label="Bấm để gọi ngay Công an 113"
          >
            <i className="bi bi-telephone-outbound-fill elder-icon" aria-hidden="true"></i>
            Gọi Công an 113 ngay
          </a>
          <a
            href="tel:156"
            className="elder-btn elder-btn--xl border-brand-400 bg-brand-500/20 text-brand-100"
            aria-label="Bấm để gọi tổng đài 156 báo lừa đảo"
          >
            <i className="bi bi-telephone-fill elder-icon text-brand-300" aria-hidden="true"></i>
            Gọi Tổng đài 156 (báo lừa đảo)
          </a>
        </div>
      </section>

      {/* ── Tổng đài cơ quan chức năng ──────────────────────────────── */}
      <section className="space-y-4" aria-labelledby="elder-hotlines">
        <h2 id="elder-hotlines" className="elder-h2">
          <i className="bi bi-shield-shaded elder-h-icon text-brand-300" aria-hidden="true"></i>
          Đường dây nóng cơ quan nhà nước
        </h2>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          {EMERGENCY_SERVICES.map((h) => (
            <div key={h.phone} className="elder-card flex flex-col justify-between space-y-3">
              <div>
                <div className="flex items-center justify-between gap-2">
                  <span className="font-bold text-foreground">{h.name}</span>
                  {h.tag && (
                    <span className="elder-tag rounded-md bg-brand-500/20 px-2 py-0.5 font-semibold text-brand-200">
                      {h.tag}
                    </span>
                  )}
                </div>
                <p className="elder-note mt-1">{h.desc}</p>
              </div>
              <a
                href={`tel:${h.phone}`}
                className="elder-btn elder-btn--brand w-full"
                aria-label={`Gọi số ${h.phone} - ${h.name}`}
              >
                <i className="bi bi-telephone-fill elder-icon" aria-hidden="true"></i> Bấm gọi {h.phone}
              </a>
            </div>
          ))}
        </div>
      </section>

      {/* ── Danh bạ hotline các ngân hàng phổ biến ─────────────────────── */}
      <section className="space-y-4" aria-labelledby="elder-banks-hotline">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 id="elder-banks-hotline" className="elder-h2">
            <i className="bi bi-credit-card-2-front-fill elder-h-icon text-safe-300" aria-hidden="true"></i>
            Hotline khẩn cấp các ngân hàng (Để khóa tài khoản)
          </h2>
          <p className="elder-note">Bác mở thẻ ở ngân hàng nào thì bấm vào nút của ngân hàng đó để gọi.</p>
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 md:grid-cols-3">
          {BANK_HOTLINES.map((b) => (
            <div key={b.name} className="elder-card flex flex-col justify-between space-y-2">
              <div>
                <span className="elder-h3 block font-bold text-foreground">{b.name}</span>
                <span className="block elder-note">{b.desc}</span>
              </div>
              <a
                href={`tel:${b.phone}`}
                className="elder-btn elder-btn--safe w-full font-bold"
                aria-label={`Gọi ngân hàng ${b.name} số ${b.phone}`}
              >
                <i className="bi bi-telephone-fill elder-icon" aria-hidden="true"></i> Gọi {b.phone}
              </a>
            </div>
          ))}
        </div>
      </section>

      {/* ── Gửi bằng chứng ───────────────────────────────────────────── */}
      <section className="space-y-4" aria-labelledby="elder-send-evidence">
        <h2 id="elder-send-evidence" className="elder-h2">
          <i className="bi bi-paperclip elder-h-icon text-brand-300" aria-hidden="true"></i>
          Gửi ảnh chụp hoặc tệp ghi âm cho cháu kiểm tra
        </h2>
        <div className="flex flex-col gap-3">
          {SEND_ITEMS.map((it) => (
            <Link key={it.to} href={it.to} className="elder-btn elder-btn--choice w-full">
              <i className={`bi ${it.icon} elder-icon text-brand-300`} aria-hidden="true"></i>
              <span className="min-w-0 flex-1 text-left">
                <span className="block font-bold">{it.title}</span>
                <span className="block elder-note">{it.hint}</span>
              </span>
              <i className="bi bi-chevron-right elder-icon" aria-hidden="true"></i>
            </Link>
          ))}
        </div>
      </section>

      {/* ── Cài App PWA ──────────────────────────────────────────────── */}
      <section className="elder-card space-y-4" aria-labelledby="elder-pwa-install">
        <h2 id="elder-pwa-install" className="elder-h2">
          <i className="bi bi-phone-fill elder-h-icon text-brand-300" aria-hidden="true"></i>
          Cài ứng dụng về màn hình chính điện thoại
        </h2>
        <p className="elder-lead">
          Cài vào máy để lần sau bác mở nhanh bằng một nút bấm, khỏi phải gõ tìm trên mạng.
        </p>

        {installed ? (
          <p className="elder-state elder-state--done">
            <i className="bi bi-check-circle-fill" aria-hidden="true"></i>
            Ứng dụng đã có trên màn hình máy bác rồi ạ
          </p>
        ) : (
          <>
            <button
              type="button"
              className="elder-btn elder-btn--xl elder-btn--brand"
              disabled={busy}
              onClick={() => void install()}
            >
              <i className="bi bi-download elder-icon" aria-hidden="true"></i>
              {busy ? 'Đang mở phần cài đặt…' : 'Cài ứng dụng về máy'}
            </button>

            {showSteps && (
              <div className="space-y-3 pt-2">
                <p className="elder-h3">
                  {ios ? 'Trên iPhone bác làm như sau:' : 'Trên điện thoại Android bác làm như sau:'}
                </p>
                <ol className="space-y-2">
                  {steps.map((t, i) => (
                    <li key={i} className="elder-todo">
                      <span className="elder-todo__num">{i + 1}</span>
                      <span>{t}</span>
                    </li>
                  ))}
                </ol>
                <p className="elder-note">Bác không tự làm được thì nhờ con cháu làm giúp một lần là xong ạ.</p>
              </div>
            )}
          </>
        )}
      </section>
    </div>
  );
}

