"""Forum anti-abuse: flood cooldown, spam/slur block, personal-attack strikes.

Triết lý (theo yêu cầu vận hành):
- Từ ngữ gay gắt về KẺ LỪA ĐẢO ("bọn lừa đảo", "cảnh giác", chửi scam) -> ALLOW.
- Công kích CÁ NHÂN thành viên (mày/thằng/con + sỉ nhục, dọa giết) -> xóa + tính strike.
- Spam/slur nặng -> chặn ngay (400), không lưu DB.
- Đủ 3 strike -> ForumBan tạm 7 ngày (persistent, admin thấy được).
- KHÔNG chặn số điện thoại: bài cảnh báo scam chính đáng cần đăng SĐT kẻ lừa.

Trả về của moderate_forum_text: ('allow'|'block'|'attack', lý_do).
"""
import logging
import re
from datetime import timedelta

from django.core.cache import cache
from django.utils import timezone

logger = logging.getLogger(__name__)

POST_COOLDOWN_SECONDS = 120
COMMENT_COOLDOWN_SECONDS = 30
DUP_WINDOW_SECONDS = 600
STRIKE_BAN_THRESHOLD = 3
STRIKE_BAN_DAYS = 7
MAX_URLS = 3

# --- Chặn ngay: đe dọa bạo lực + spam kỹ thuật ---
_BLOCK_PATTERNS = [
    # Đe dọa bạo lực có chủ thể ("tao/mình/t sẽ giết/đánh/chém mày/bạn/nó")
    re.compile(r'(tao|tôi|mình|t)\s+(sẽ\s+)?(giết|đánh\s+chết|chém|đâm|giết\s+chết)\s+(mày|bạn|m|nó|thằng|con)', re.I),
    re.compile(r'(giết|hiếp|đánh\s+chết)\s+(cả\s+nhà|mày|bọn\s+mày)', re.I),
    # Slur phân biệt vùng miền/dân tộc nhắm vào người
    re.compile(r'\b(mọi\s+(rợ|đen)|khmer\s+đỏ|tàu\s+khựa\s+chó)\b', re.I),
]

# --- Xóa + strike: công kích cá nhân (cho phép chửi KẺ LỪA ĐẢO, cấm chửi THÀNH VIÊN) ---
_ATTACK_PATTERNS = [
    re.compile(r'\bmày\b.{0,20}\b(ngu|đần|dốt|chó|lợn|bò|óc\s+(chó|bã\s+đậu|lợn)|não\s+(phẳng|cá\s+vàng)|vô\s+học|mất\s+dạy|thiểu\s+năng)\b', re.I),
    re.compile(r'\b(thằng|con|lão|mụ)\s+(ngu|đần|chó|lợn|khốn|mất\s+dạy|vô\s+học)\b', re.I),
    re.compile(r'\b(óc\s+chó|não\s+phẳng|ngu\s+như\s+(bò|lợn|chó)|đồ\s+(ngu|vô\s+học|mất\s+dạy)|câm\s+(mồm|mõm))\b', re.I),
    re.compile(r'\bmày\s+(thì\s+)?biết\s+(cái\s+)?(gì|đéo|éo)\b', re.I),
    re.compile(r'\b(đm|đcm|dcm|vcl|vcc)\s+(mày|thằng|con)\b', re.I),
]


def forum_ban_active(user) -> tuple:
    """(bị cấm?, mesaage). Kiểm tra ForumBan còn hiệu lực."""
    try:
        from api.core.models import ForumBan
        ban = ForumBan.objects.filter(user=user, is_active=True).order_by('-created_at').first()
        if ban and not ban.is_expired:
            if ban.ban_type == ForumBan.BanType.PERMANENT:
                return True, 'Tài khoản của bạn đã bị cấm khỏi diễn đàn vĩnh viễn.'
            exp = ban.expires_at.strftime('%d/%m/%Y %H:%M') if ban.expires_at else 'không xác định'
            return True, f'Tài khoản tạm bị cấm đăng bài đến {exp}. Lý do: {ban.reason[:200]}'
    except Exception as exc:
        logger.warning('forum_ban check failed: %s', exc)
    return False, ''


def _flood_key(user_id: int, kind: str) -> str:
    return f'forum_flood:{kind}:{user_id}'


def check_flood(user_id: int, kind: str) -> tuple:
    """(được phép?, giây phải chờ). post=120s, comment=30s."""
    cd = POST_COOLDOWN_SECONDS if kind == 'post' else COMMENT_COOLDOWN_SECONDS
    try:
        last = cache.get(_flood_key(user_id, kind))
        if last:
            wait = cd - (timezone.now().timestamp() - float(last))
            if wait > 0:
                return False, int(wait) + 1
    except Exception:
        pass
    return True, 0


def record_flood(user_id: int, kind: str) -> None:
    try:
        cache.set(_flood_key(user_id, kind), timezone.now().timestamp(), timeout=POST_COOLDOWN_SECONDS + 60)
    except Exception:
        pass


def _norm(text: str) -> str:
    return re.sub(r'\s+', ' ', (text or '').lower()).strip()


def moderate_forum_text(text: str) -> tuple:
    """Phân loại nội dung diễn đàn. Không chặn SĐT (bài cảnh báo cần đăng SĐT scam)."""
    t = _norm(text)
    if not t:
        return 'block', 'Nội dung trống.'
    if len(t) > 20000:
        return 'block', 'Nội dung quá dài (tối đa 20000 ký tự).'

    for pat in _BLOCK_PATTERNS:
        if pat.search(t):
            return 'block', 'Nội dung chứa đe dọa bạo lực hoặc ngôn từ cấm, đã bị chặn.'

    urls = re.findall(r'https?://|www\.', t)
    if len(urls) > MAX_URLS:
        return 'block', f'Bài viết chứa quá nhiều liên kết ({len(urls)}>{MAX_URLS}), nghi spam.'
    if re.search(r'(.)\1{9,}', t):
        return 'block', 'Nội dung chứa ký tự lặp nghi spam.'

    for pat in _ATTACK_PATTERNS:
        if pat.search(t):
            return 'attack', 'Bình luận/bài viết chứa công kích cá nhân thành viên, đã bị gỡ. Bạn được phép dùng từ ngữ gay gắt với KẺ LỪA ĐẢO, nhưng không được xúc phạm thành viên khác.'

    return 'allow', ''


# Kích hoạt AI-small review: @nhắc tên, hoặc đại từ ngôi 2 + từ ngữ tiêu cực gần kề.
# (Regex đã bắt obvious-attack; AI xử vùng xám: viết cách điệu, mỉa mai, ngữ cảnh đùa.)
_REVIEW_TRIGGER = re.compile(
    r'@[\w.]{3,40}'
    r'|\b(mày|bạn|cậu)\b.{0,30}\b(ngu|đần|dốt|chó|lợn|bò|óc|não|câm|đéo|éo|khốn|hèn|nhục|vô|mất|thiểu|mõm|mồm)\b',
    re.I,
)

_AI_OVERTURN_CONF = 0.8   # AI gỡ 'attack' của regex khi chắc chắn
_AI_FLAG_CONF = 0.7       # AI gắn 'attack' cho ca regex bỏ sót


def ai_review_attack(text: str):
    """Nhờ AI-small phán lại. Trả dict AI hoặc None (AI chết -> giữ regex). Có cache 10 phút."""
    import hashlib
    try:
        key = 'forum_airev:' + hashlib.sha256(_norm(text).encode()).hexdigest()
        cached = cache.get(key)
        if isinstance(cached, dict) and cached.get('decision') in ('allow', 'attack'):
            return cached
    except Exception:
        key = None
    try:
        from api.utils.ollama_client import moderate_forum_text_ai
        res = moderate_forum_text_ai(text)
    except Exception as exc:
        logger.warning('ai review import/call failed: %s', exc)
        return None
    if res and key:
        try:
            cache.set(key, res, timeout=600)
        except Exception:
            pass
    return res


def decide_forum_text(text: str) -> tuple:
    """Quyết định cuối: regex chặn nhanh + AI-small duyệt vùng xám."""
    decision, reason = moderate_forum_text(text)
    if decision == 'block':
        return decision, reason
    needs_ai = decision == 'attack' or bool(_REVIEW_TRIGGER.search(_norm(text)))
    if not needs_ai:
        return decision, reason
    ai = ai_review_attack(text)
    if not ai:
        return decision, reason  # AI chết -> giữ nguyên regex
    if decision == 'attack' and ai['decision'] == 'allow' and ai['confidence'] >= _AI_OVERTURN_CONF:
        return 'allow', ''
    if decision == 'allow' and ai['decision'] == 'attack' and ai['confidence'] >= _AI_FLAG_CONF:
        return 'attack', ai['reason'] or reason
    if decision == 'attack' and ai['decision'] == 'attack':
        return 'attack', ai['reason'] or reason
    return decision, reason


def _strike_key(user_id: int) -> str:
    return f'forum_strike:{user_id}'


def record_strike(user) -> tuple:
    """Ghi strike công kích cá nhân. Đủ ngưỡng -> ForumBan 7 ngày. Trả về (tổng strike, bị ban?)."""
    try:
        strikes = int(cache.get(_strike_key(user.id), 0)) + 1
        cache.set(_strike_key(user.id), strikes, timeout=30 * 86400)
    except Exception:
        return 1, False
    if strikes >= STRIKE_BAN_THRESHOLD:
        try:
            from api.core.models import ForumBan
            active = ForumBan.objects.filter(user=user, is_active=True).first()
            if active and not active.is_expired:
                return strikes, True
            ForumBan.objects.create(
                user=user, banned_by=None, reason=f'Tự động: {strikes} lần công kích cá nhân thành viên.',
                ban_type=ForumBan.BanType.TEMPORARY,
                expires_at=timezone.now() + timedelta(days=STRIKE_BAN_DAYS),
                is_active=True,
            )
            return strikes, True
        except Exception as exc:
            logger.warning('auto forum ban failed: %s', exc)
    return strikes, False


def is_duplicate_submit(user_id: int, text: str, record: bool = True) -> bool:
    """Chặn copy-paste cùng nội dung trong 10 phút (spam).

    `record=False` để chỉ kiểm tra mà không ghi cache — dùng khi muốn kiểm tra
    trước nhưng chỉ "đánh dấu trùng" sau khi bài viết thực sự được tạo. Nếu
    ghi cache ngay khi request, một bài bị validation lỗi/block vẫn bị khóa
    10 phút với thông báo nhầm "nội dung trùng lặp".
    """
    import hashlib
    try:
        h = hashlib.sha256(_norm(text).encode()).hexdigest()
        key = f'forum_dup:{user_id}:{h}'
        if cache.get(key):
            return True
        if record:
            cache.set(key, 1, timeout=DUP_WINDOW_SECONDS)
    except Exception:
        pass
    return False
