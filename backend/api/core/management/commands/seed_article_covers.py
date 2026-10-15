"""
Sinh ảnh bìa (cover) thương hiệu cho Article/LearnLesson thiếu cover_image.

- Vẽ PNG 1200x630 theo phong cách ShieldCall (nền navy, dải màu theo danh mục, tiêu đề).
- Lưu qua ImageField → tự động đẩy lên object storage (S3) khi USE_S3_MEDIA=true.
- Idempotent: chỉ tạo cho bản ghi chưa có cover (dùng --force để ghi đè).

Chạy:  python manage.py seed_article_covers
"""
import io
import os
import textwrap

from django.core.files.base import ContentFile
from django.core.management.base import BaseCommand

from api.core.models import Article, LearnLesson

try:
    from PIL import Image, ImageDraw, ImageFont
except Exception:  # pragma: no cover
    Image = None

W, H = 1200, 630
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
FONT_REG = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"

# Màu theo danh mục (khớp bảng màu ngữ nghĩa của frontend)
CAT = {
    "alert": ("#ef4444", "CẢNH BÁO MỚI"),
    "guide": ("#22d3ee", "HƯỚNG DẪN"),
    "news": ("#fbbf24", "TIN TỨC"),
    "story": ("#a78bfa", "CHUYỆN CẢNH GIÁC"),
    "inclusive": ("#22d3ee", "AN NINH SỐ BAO TRÙM"),
    "empathy": ("#a78bfa", "GÓC THẤU CẢM"),
}


def _hex(c):
    c = c.lstrip("#")
    return tuple(int(c[i:i + 2], 16) for i in (0, 2, 4))


def _font(path, size):
    try:
        return ImageFont.truetype(path, size)
    except Exception:
        return ImageFont.load_default()


def _fit(d, text, font, maxw):
    """Cắt bớt chuỗi kèm '…' để vừa bề rộng maxw."""
    text = str(text or "")
    if d.textlength(text, font=font) <= maxw:
        return text
    ell = "…"
    while text and d.textlength(text + ell, font=font) > maxw:
        text = text[:-1]
    return text.rstrip() + ell


def _gradient_bg(img):
    top, bot = _hex("#0d0d1f"), _hex("#161235")
    d = ImageDraw.Draw(img)
    for y in range(H):
        t = y / H
        r = int(top[0] + (bot[0] - top[0]) * t)
        g = int(top[1] + (bot[1] - top[1]) * t)
        b = int(top[2] + (bot[2] - top[2]) * t)
        d.line([(0, y), (W, y)], fill=(r, g, b))
    # lưới mờ
    for x in range(0, W, 80):
        d.line([(x, 0), (x, H)], fill=(255, 255, 255, 5))
    for y in range(0, H, 80):
        d.line([(0, y), (W, y)], fill=(255, 255, 255, 5))


def _shield(d, cx, cy, s, color):
    # khiên đơn giản
    p = [(cx, cy - s), (cx + s * 0.8, cy - s * 0.5), (cx + s * 0.8, cy + s * 0.2),
         (cx, cy + s), (cx - s * 0.8, cy + s * 0.2), (cx - s * 0.8, cy - s * 0.5)]
    d.polygon(p, fill=color)
    d.line([(cx - s * 0.3, cy + s * 0.05), (cx - s * 0.05, cy + s * 0.3), (cx + s * 0.4, cy - s * 0.3)],
           fill=(13, 13, 31), width=max(3, int(s * 0.14)), joint="curve")


class Command(BaseCommand):
    help = "Sinh ảnh bìa thương hiệu cho Article/LearnLesson thiếu cover_image."

    def add_arguments(self, parser):
        parser.add_argument('--force', action='store_true', help="Ghi đè cả bản đã có cover.")

    def _make(self, title, category, subtitle):
        color, label = CAT.get(category, ("#22d3ee", str(category).upper()))
        accent = _hex(color)
        img = Image.new("RGB", (W, H), _hex("#0d0d1f"))
        _gradient_bg(img)
        d = ImageDraw.Draw(img, "RGBA")

        # dải màu trên cùng
        d.rectangle([0, 0, W, 10], fill=accent)
        # khiên
        _shield(d, 110, 150, 54, accent)
        # nhãn danh mục
        f_lbl = _font(FONT_BOLD, 30)
        d.text((190, 128), label, font=f_lbl, fill=accent)
        # tiêu đề (wrap)
        f_title = _font(FONT_BOLD, 58)
        wrapped = textwrap.wrap(title, width=26)[:4]
        y = 260
        for line in wrapped:
            d.text((80, y), line, font=f_title, fill=(255, 255, 255))
            y += 74
        # phụ đề/nguồn (cắt cho vừa lề, tránh tràn)
        f_sub = _font(FONT_REG, 26)
        sub = _fit(d, subtitle or "Kiến thức phòng chống lừa đảo · shieldcall.vn", f_sub, W - 160)
        d.text((80, H - 88), sub, font=f_sub, fill=(148, 163, 184))
        # footer brand
        f_brand = _font(FONT_BOLD, 28)
        d.text((80, H - 48), "ShieldCall VN", font=f_brand, fill=accent)

        buf = io.BytesIO()
        img.save(buf, format="PNG", optimize=True)
        return ContentFile(buf.getvalue())

    def handle(self, *args, **opts):
        if Image is None:
            self.stderr.write(self.style.ERROR("Thiếu Pillow."))
            return
        force = opts['force']
        n = 0
        for model, kind, sub in ((Article, "article", "Kiến thức phòng chống lừa đảo · shieldcall.vn"),
                                 (LearnLesson, "lesson", "Bài học an toàn số · shieldcall.vn")):
            qs = model.objects.filter(is_published=True)
            for obj in qs:
                if obj.cover_image and not force:
                    continue
                content = self._make(obj.title, obj.category, obj.summary or sub)
                name = f"{kind}_{obj.slug or obj.id}.png"
                obj.cover_image.save(name, content, save=True)
                n += 1
                self.stdout.write(f"  ✓ {kind}: {obj.title[:60]}")
        self.stdout.write(self.style.SUCCESS(f"Đã tạo {n} ảnh bìa (đã đẩy lên S3 nếu bật)."))
