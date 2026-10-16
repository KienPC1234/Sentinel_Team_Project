"""
ShieldCall VN — Sinh ảnh bìa (cover) theo thương hiệu cho bài viết / bài học thiếu ảnh.

Tạo ảnh PNG 1200x630: nền gradient theo chủ đề, chip nhãn, tiêu đề (tiếng Việt, DejaVu),
watermark khiên + footer thương hiệu. Dùng cho các mục chưa có ảnh bìa, tránh "thiếu ảnh".
"""

from __future__ import annotations

import io
import os
from typing import Optional, Tuple

from PIL import Image, ImageDraw, ImageFont

# Font hỗ trợ tiếng Việt (DejaVu). Fallback về font mặc định nếu không có.
_FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
_FONT_REG = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"

# Màu gradient theo nhóm chủ đề
_THEME = {
    "alert": ((220, 38, 38), (124, 45, 18)),      # đỏ cảnh báo
    "news": ((6, 182, 212), (37, 99, 235)),        # cyan → xanh
    "guide": ((5, 150, 105), (6, 95, 70)),         # xanh lá
    "story": ((217, 119, 6), (146, 64, 14)),       # cam
    "inclusive": ((139, 92, 246), (76, 29, 149)),  # tím
    "empathy": ((236, 72, 153), (131, 24, 67)),    # hồng
    "default": ((24, 24, 37), (30, 58, 138)),      # navy
}

_LABEL = {
    "alert": "CẢNH BÁO", "news": "TIN TỨC", "guide": "CẨM NANG",
    "story": "CHUYỆN CẢNH GIÁC", "inclusive": "AN NINH SỐ BAO TRÙM",
    "empathy": "GÓC THẤU CẢM", "default": "SHIELDCALL VN",
}

W, H = 1200, 630


def _font(path: str, size: int):
    try:
        return ImageFont.truetype(path, size)
    except Exception:
        return ImageFont.load_default()


def _wrap(draw: ImageDraw.ImageDraw, text: str, font, max_width: int, max_lines: int):
    words = (text or "").split()
    lines, cur = [], ""
    for w in words:
        trial = (cur + " " + w).strip()
        if draw.textlength(trial, font=font) <= max_width or not cur:
            cur = trial
        else:
            lines.append(cur)
            cur = w
            if len(lines) >= max_lines:
                break
    if cur and len(lines) < max_lines:
        lines.append(cur)
    if len(lines) == max_lines and words:
        # cắt bớt nếu còn chữ
        while lines and draw.textlength(lines[-1] + "…", font=font) > max_width:
            lines[-1] = lines[-1][:-1]
        lines[-1] = lines[-1].rstrip() + ("…" if len(" ".join(lines)) < len(text) else "")
    return lines


def generate_cover(title: str, category: str = "default",
                   subtitle: Optional[str] = None) -> bytes:
    """Sinh ảnh bìa PNG (bytes) từ tiêu đề + chủ đề."""
    key = (category or "default").lower()
    c1, c2 = _THEME.get(key, _THEME["default"])
    label = _LABEL.get(key, _LABEL["default"])

    img = Image.new("RGB", (W, H), (10, 12, 20))
    draw = ImageDraw.Draw(img, "RGBA")

    # Gradient chéo
    for y in range(H):
        t = y / (H - 1)
        row = tuple(int(c1[i] + (c2[i] - c1[i]) * t) for i in range(3))
        draw.line([(0, y), (W, y)], fill=row + (255,))

    # Vệt sáng mờ
    for x in range(0, W, 6):
        a = int(18 * (x / W))
        draw.line([(x, 0), (x, H)], fill=(255, 255, 255, a))

    # Watermark khiên (góc phải)
    sx, sy, sw, sh = W - 360, 90, 260, 300
    shield = [(sx + sw / 2, sy), (sx + sw, sy + sh * 0.18),
              (sx + sw, sy + sh * 0.6), (sx + sw / 2, sy + sh), (sx, sy + sh * 0.6),
              (sx, sy + sh * 0.18)]
    draw.polygon(shield, fill=(255, 255, 255, 26), outline=(255, 255, 255, 60))

    fb = _font(_FONT_BOLD, 46)
    f_reg = _font(_FONT_REG, 26)
    f_chip = _font(_FONT_BOLD, 24)
    f_title = _font(_FONT_BOLD, 60)
    f_foot = _font(_FONT_REG, 26)

    # Chip nhãn
    pad_x, pad_y = 22, 12
    tw = draw.textlength(label, font=f_chip)
    chip = [70, 80, 70 + tw + pad_x * 2, 80 + 24 + pad_y * 2]
    draw.rounded_rectangle(chip, radius=10, fill=(0, 0, 0, 90), outline=(255, 255, 255, 90))
    draw.text((70 + pad_x, 80 + pad_y - 2), label, font=f_chip, fill=(255, 255, 255, 235))

    # Tiêu đề
    lines = _wrap(draw, title, f_title, W - 520, 3)
    y = 180
    for ln in lines:
        draw.text((70, y), ln, font=f_title, fill=(255, 255, 255, 255))
        y += 74

    if subtitle:
        sub = _wrap(draw, subtitle, f_reg, W - 520, 2)
        y += 8
        for ln in sub:
            draw.text((70, y), ln, font=f_reg, fill=(255, 255, 255, 200))
            y += 34

    # Footer thương hiệu
    draw.text((70, H - 66), "ShieldCall VN", font=fb, fill=(255, 255, 255, 235))
    draw.text((70 + draw.textlength("ShieldCall VN", font=fb) + 16, H - 60),
              "· Bảo vệ bạn khỏi lừa đảo trực tuyến", font=f_foot, fill=(255, 255, 255, 170))

    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=88, optimize=True)
    return buf.getvalue()
