"""ShieldCall VN – Forum Views"""
import re
import hashlib
import logging
import json
import html
from urllib.parse import urlparse
from api.utils.security import verify_turnstile_token
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from django.core.cache import cache
from django.db import IntegrityError, transaction

from django.contrib.auth import authenticate, get_user_model
from django.db.models import Count, Sum, F, Q
from django.utils import timezone
from datetime import datetime, time, timedelta

from django.http import StreamingHttpResponse
from django.utils.html import strip_tags
from rest_framework import status, permissions, generics
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from drf_spectacular.utils import extend_schema

from api.utils.ollama_client import analyze_text_for_scam, generate_response, stream_response

from api.core.models import (
    Domain, BankAccount, Report, ScanEvent, TrendDaily,
    EntityLink, UserAlert, ScamType, RiskLevel, ReportStatus, ForumCategory,
)
from api.core.serializers import (
    RegisterSerializer, LoginSerializer, UserSerializer,
    DomainSerializer, BankAccountSerializer,
    ReportCreateSerializer, ReportListSerializer, ReportModerateSerializer,
    ScanPhoneSerializer, ScanMessageSerializer, ScanDomainSerializer,
    ScanAccountSerializer, ScanImageSerializer, ScanEventListSerializer,
    TrendDailySerializer, TrendHotSerializer, UserAlertSerializer,
)

User = get_user_model()
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# FORUM APIs
# ═══════════════════════════════════════════════════════════════════════════

from api.core.models import ForumPost, ForumComment, ForumLike, ForumCommentLike, ForumPostReaction, ForumPostReport, ForumCommentReport, ForumReactionType, ForumCommentReaction, ForumPostView
from api.core.serializers import (
    ForumPostSerializer, ForumPostListSerializer, ForumCommentSerializer,
    ForumPostReportSerializer, ForumCommentReportSerializer,
)
from django.db.models import Exists, OuterRef, Subquery


# ─── Tối ưu truy vấn cho diễn đàn ────────────────────────────────────────────
# Trước đây mỗi bài viết tốn ~7 query phụ (đếm bài/bình luận của tác giả,
# bình luận cuối, lượt xem duy nhất, 4 trạng thái reaction của người xem) và mỗi
# bình luận lại tốn thêm 4 query — trang danh sách 50 bài là hơn 400 query.
# Các helper dưới gộp hết vào 1 truy vấn chính + 1–2 truy vấn phụ cố định.

def _last_comment_subquery(field):
    return Subquery(
        ForumComment.objects.filter(post=OuterRef('pk'))
        .order_by('-created_at')
        .values(field)[:1]
    )


def forum_post_queryset(request, annotate=True):
    """Queryset bài viết đã tối ưu (dùng cho cả list và detail)."""
    qs = ForumPost.objects.select_related('author', 'author__profile')
    if not annotate:
        return qs
    qs = qs.annotate(
        author_posts_total=Subquery(
            ForumPost.objects.filter(author=OuterRef('author_id'))
            .values('author').annotate(c=Count('id')).values('c')
        ),
        author_comments_total=Subquery(
            ForumComment.objects.filter(author=OuterRef('author_id'))
            .values('author').annotate(c=Count('id')).values('c')
        ),
        unique_views_total=Subquery(
            ForumPostView.objects.filter(post=OuterRef('pk'))
            .values('post').annotate(c=Count('id')).values('c')
        ),
        last_comment_created_at=_last_comment_subquery('created_at'),
        last_comment_id=_last_comment_subquery('id'),
    )
    user = getattr(request, 'user', None)
    if user is not None and user.is_authenticated:
        qs = qs.annotate(
            viewer_has_liked=Exists(ForumLike.objects.filter(post=OuterRef('pk'), user=user)),
            viewer_has_helpful=Exists(ForumPostReaction.objects.filter(
                post=OuterRef('pk'), user=user, reaction_type=ForumReactionType.HELPFUL)),
            viewer_has_shared=Exists(ForumPostReaction.objects.filter(
                post=OuterRef('pk'), user=user, reaction_type=ForumReactionType.SHARE)),
            viewer_has_disliked=Exists(ForumPostReaction.objects.filter(
                post=OuterRef('pk'), user=user, reaction_type=ForumReactionType.DISLIKE)),
        )
    return qs


def build_comment_tree(post, request):
    """Nạp toàn bộ bình luận của 1 bài bằng 1 query và dựng cây + độ sâu.

    Trả về context bổ sung cho serializer: roots / children / depths. Các key
    dict rỗng vẫn được đặt để serializer biết "đã có sẵn" và không query lại.
    """
    rows = list(
        ForumComment.objects
        .filter(post=post)
        .select_related('author', 'author__profile', 'parent')
        .order_by('created_at', 'id')
    )

    # Gom so bai viet cua tung tac gia binh luan: 2 query thay vi N query.
    author_ids = {row.author_id for row in rows if row.author_id}
    if author_ids:
        from django.db.models import Count as _Count
        post_counts = dict(
            ForumPost.objects.filter(author_id__in=author_ids)
            .values('author_id').annotate(c=_Count('id')).values_list('author_id', 'c')
        )
        for row in rows:
            row.author_posts_total = post_counts.get(row.author_id, 0)
    else:
        for row in rows:
            row.author_posts_total = 0

    user = getattr(request, 'user', None)
    authenticated = bool(user is not None and user.is_authenticated)
    if authenticated:
        comment_ids = [row.id for row in rows]
        liked = set(ForumCommentLike.objects.filter(
            comment_id__in=comment_ids, user=user).values_list('comment_id', flat=True)) if comment_ids else set()
        reactions = list(ForumCommentReaction.objects.filter(
            comment_id__in=comment_ids, user=user,
            reaction_type__in=('downvote', 'helpful'),
        ).values_list('comment_id', 'reaction_type')) if comment_ids else []
        disliked = {cid for cid, kind in reactions if kind == 'downvote'}
        helpful = {cid for cid, kind in reactions if kind == 'helpful'}
        for row in rows:
            row.viewer_has_liked = row.id in liked
            row.viewer_has_disliked = row.id in disliked
            row.viewer_has_helpful = row.id in helpful
    else:
        for row in rows:
            row.viewer_has_liked = False
            row.viewer_has_disliked = False
            row.viewer_has_helpful = False

    children = {}
    roots = []
    depths = {}
    for row in rows:
        # Bình luận cha luôn được tạo trước con (không thể trả lời bình luận
        # chưa tồn tại) nên thứ tự created_at đảm bảo cha đã có depth.
        if row.parent_id:
            depths[row.id] = depths.get(row.parent_id, 1) + 1
            children.setdefault(row.parent_id, []).append(row)
        else:
            depths[row.id] = 1
            roots.append(row)

    return {
        'forum_comment_roots_by_post': {post.id: roots},
        'forum_comment_children': children,
        'forum_comment_depths': depths,
    }


def build_last_comment_authors(posts):
    """{post_id: {name, username, avatar}} cho bình luận cuối — 1 query."""
    ids = [post.id for post in posts if getattr(post, 'last_comment_id', None)]
    if not ids:
        return {post.id: None for post in posts}
    last_ids = [post.last_comment_id for post in posts if getattr(post, 'last_comment_id', None)]
    rows = ForumComment.objects.filter(id__in=last_ids).select_related('author', 'author__profile')
    info = {}
    for row in rows:
        profile = row.author.profile
        info[row.post_id] = {
            'name': profile.display_name or row.author.username,
            'username': row.author.username,
            'avatar': profile.avatar.url if profile and profile.avatar else None,
        }
    return {post.id: info.get(getattr(post, 'last_comment_id', None)) for post in posts}


def _safe_get_or_create(model, **kwargs):
    """get_or_create that survives concurrent double-clicks (IntegrityError → fetch existing)."""
    try:
        return model.objects.get_or_create(**kwargs)
    except IntegrityError:
        lookup = {k: v for k, v in kwargs.items() if k != 'defaults'}
        try:
            return model.objects.get(**lookup), False
        except model.DoesNotExist:
            return model.objects.get_or_create(**kwargs)


def _dec_counter(model, obj_id, field):
    """Decrement a counter column, floored at 0 (prevents negative drift)."""
    model.objects.filter(id=obj_id, **{f'{field}__gt': 0}).update(**{field: F(field) - 1})


def _extract_mentioned_usernames(text: str) -> list[str]:
    if not text:
        return []
    matches = re.findall(r'@([A-Za-z0-9_.+-]{3,150})', text)
    seen = set()
    usernames = []
    for username in matches:
        key = username.lower()
        if key in seen:
            continue
        seen.add(key)
        usernames.append(username)
    return usernames[:20]


def _notify_mentions(*, sender, content: str, post: ForumPost, actor_label: str):
    mentioned = _extract_mentioned_usernames(content)
    if not mentioned:
        return

    users = User.objects.filter(username__in=mentioned).only('id', 'username')
    if not users:
        return

    from api.utils.push_service import push_service
    post_url = f'/forum/{post.id}/'
    snippet = _to_plain_notification_text(content, limit=120) or 'Bạn vừa được nhắc tới trong diễn đàn.'

    for user in users:
        if user.id == sender.id:
            continue
        try:
            push_service.send_push(
                user.id,
                f'{actor_label} đã nhắc tới bạn',
                snippet,
                url=post_url,
                notification_type='info'
            )
        except Exception as exc:
            logger.error(f"Mention push notification failed for @{user.username}: {exc}")


def _to_plain_notification_text(raw: str, limit: int = 120) -> str:
    text = str(raw or '')
    text = html.unescape(text)
    text = strip_tags(text)
    text = re.sub(r'\s+', ' ', text).strip()
    if not text:
        return ''
    return text[:limit]


def _broadcast_forum_live(event_name: str, payload: dict):
    try:
        channel_layer = get_channel_layer()
        if not channel_layer:
            return
        async_to_sync(channel_layer.group_send)(
            'forum_live',
            {
                'type': 'forum_live_event',
                'event': event_name,
                'payload': payload or {},
                'timestamp': timezone.now().isoformat(),
            }
        )
    except Exception as exc:
        logger.warning(f"Forum live broadcast failed ({event_name}): {exc}")

class ForumPostListCreateView(APIView):
    """GET /api/forum/posts/ — list, POST — create"""

    def get_permissions(self):
        if self.request.method == 'POST':
            return [IsAuthenticated()]
        return [AllowAny()]

    def _get_client_ip(self, request):
        forwarded = (request.META.get('HTTP_X_FORWARDED_FOR') or '').split(',')[0].strip()
        return forwarded or request.META.get('REMOTE_ADDR')

    @extend_schema(
        operation_id='v1_forum_posts_list',
        summary="Danh sách bài viết diễn đàn cộng đồng",
        responses={200: ForumPostSerializer(many=True)}
    )
    def get(self, request):
        category = (request.query_params.get('category') or '').strip()
        if category:
            valid_categories = {c[0] for c in ForumCategory.choices}
            if category not in valid_categories:
                return Response({'error': 'Danh muc khong hop le.'}, status=400)
            posts = forum_post_queryset(request).order_by('-is_pinned', '-created_at').filter(category=category)
        else:
            posts = forum_post_queryset(request).order_by('-is_pinned', '-created_at')

        query = (request.query_params.get('q') or '').strip()[:100]
        if query:
            from django.db.models import Q
            posts = posts.filter(
                Q(title__icontains=query) | Q(content__icontains=query) | Q(author__username__icontains=query)
            )

        # Mặc định giữ nguyên hành vi cũ (50 bài mới nhất) nhưng cho phép trang
        # hoá / tìm kiếm để không bị cắt cụt khi diễn đàn lớn dần.
        try:
            page = max(1, int(request.query_params.get('page', 1)))
        except (TypeError, ValueError):
            page = 1
        try:
            page_size = int(request.query_params.get('page_size', 50))
        except (TypeError, ValueError):
            page_size = 50
        page_size = max(1, min(page_size, 200))
        offset = (page - 1) * page_size

        total = posts.count()
        items = list(posts[offset:offset + page_size])
        # Bản nhẹ: bỏ field `comments` (danh sách không dùng) + nạp sẵn author
        # của bình luận cuối để không query lặp theo từng bài.
        serializer = ForumPostListSerializer(
            items, many=True,
            context={'request': request, 'forum_last_comment_authors': build_last_comment_authors(items)},
        )
        # Tra envelope {results, count, page, pages} thay vi mang tran: ca 2
        # frontend (Forum + ForumMgmt) deu parse duoc ca 2 dang (Paged | array)
        # nen khong vo tuong thich, ma gio doc duoc tong so bai that.
        pages = max(1, (total + page_size - 1) // page_size)
        response = Response({
            'results': serializer.data,
            'count': total,
            'page': page,
            'pages': pages,
        })
        response['X-Total-Count'] = str(total)
        return response

    def post(self, request):
        # Turnstile Verification
        cf_token = request.data.get('cf-turnstile-response')
        remote_ip = self._get_client_ip(request)
        if not verify_turnstile_token(cf_token, remote_ip=remote_ip):
             return Response({'error': 'Xác minh anti-spam không hợp lệ. Vui lòng thử lại.'}, status=400)

        from api.core.forum_moderation import (
            check_flood, forum_ban_active, is_duplicate_submit,
            decide_forum_text, record_flood, record_strike,
        )
        banned, ban_msg = forum_ban_active(request.user)
        if banned:
            return Response({'error': ban_msg}, status=403)
        ok, wait = check_flood(request.user.id, 'post')
        if not ok:
            return Response({'error': f'Bạn đăng bài quá nhanh. Vui lòng chờ {wait}s.'}, status=429)
        raw_text = f"{request.data.get('title') or ''}\n{request.data.get('content') or ''}"
        # Chi kiem tra trung lap, chi ghi cache sau khi bai thuc su duoc tao --
        # neu khong, mot bai bi loi validation van bi khoa 10 phut.
        if is_duplicate_submit(request.user.id, raw_text, record=False):
            return Response({'error': 'Nội dung trùng lặp vừa đăng, nghi spam.'}, status=400)
        decision, reason = decide_forum_text(raw_text)
        if decision == 'block':
            return Response({'error': reason}, status=400)
        if decision == 'attack':
            strikes, was_banned = record_strike(request.user)
            suffix = ' Tài khoản đã bị cấm đăng 7 ngày.' if was_banned else f' Cảnh cáo {strikes}/3.'
            return Response({'error': reason + suffix}, status=400)

        serializer = ForumPostSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        post = serializer.save(author=request.user)
        record_flood(request.user.id, 'post')
        is_duplicate_submit(request.user.id, raw_text)  # ghi nho sau khi dang thanh cong
        cache.delete('forum_stats_v1')

        try:
            sender_name = getattr(request.user, 'profile', None)
            sender_name = sender_name.display_name if sender_name and sender_name.display_name else request.user.username
            _notify_mentions(sender=request.user, content=post.content, post=post, actor_label=sender_name)
        except Exception as e:
            logger.error(f"Post mention notification failed: {e}")

        serialized_post = ForumPostSerializer(post, context={'request': request}).data
        _broadcast_forum_live('post_created', {
            'post_id': post.id,
            'title': post.title,
            'author': request.user.username,
            'category': post.category,
        })
        return Response(serialized_post, status=201)


class ForumPostDetailView(APIView):
    """GET /api/forum/posts/<id>/ — detail with comments
       PATCH /api/forum/posts/<id>/ — author edits post"""

    def get_permissions(self):
        if self.request.method in ('PATCH', 'DELETE'):
            return [IsAuthenticated()]
        return [AllowAny()]

    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    @extend_schema(
        operation_id='v1_forum_posts_detail',
        summary="Chi tiết bài viết diễn đàn cùng các bình luận"
    )
    def get(self, request, post_id):
        try:
            post = forum_post_queryset(request).get(id=post_id)
        except ForumPost.DoesNotExist:
            return Response({'error': 'Bài viết không tồn tại'}, status=404)

        # Block locked posts for non-staff users
        if post.is_locked and not (request.user.is_authenticated and request.user.is_staff):
            return Response({'error': 'Bài viết này đã bị khóa bởi quản trị viên.'}, status=403)

        # Track unique views
        user = request.user if request.user.is_authenticated else None
        ip_address = self._get_client_ip(request)
        # Refresh nền (WebSocket/bình luận mới) không phải lượt xem thật — client
        # gửi X-Silent-Refresh: 1 để không làm views_count tăng vọt mỗi lần có
        # bình luận mới trong tab đang mở.
        silent_refresh = (request.headers.get('X-Silent-Refresh') or '').strip() == '1'
        if not silent_refresh:
            if user:
                view_exists = ForumPostView.objects.filter(post=post, user=user).exists()
            else:
                # Khach chua co session thi moi IP chi tinh 1 luot (tranh tao
                # session rac cho bot), co session thi tinh theo session.
                session_key = request.session.session_key
                if not session_key:
                    view_exists = ForumPostView.objects.filter(
                        post=post, user__isnull=True, ip_address=ip_address, session_key=''
                    ).exists()
                    session_key = ''
                else:
                    view_exists = ForumPostView.objects.filter(
                        post=post, ip_address=ip_address, session_key=session_key
                    ).exists()

            # Create unique view record if new viewer
            if not view_exists:
                try:
                    ForumPostView.objects.create(
                        post=post,
                        user=user,
                        ip_address=ip_address,
                        session_key=session_key if not user else ''
                    )
                except IntegrityError:
                    pass

            # Always increment total views for legacy compatibility
            ForumPost.objects.filter(id=post_id).update(views_count=F('views_count') + 1)
            post.refresh_from_db()

        serializer_context = {'request': request}
        # Cây bình luận: 1 query thay vì 1 query / bình luận (kể cả phần đi sâu
        # tầng trả lời và 3 query reaction mỗi bình luận).
        serializer_context.update(build_comment_tree(post, request))
        serializer_context['forum_last_comment_authors'] = build_last_comment_authors([post])
        serializer = ForumPostSerializer(post, context=serializer_context)
        return Response(serializer.data)

    def patch(self, request, post_id):
        """Author can edit their own post (title, content, category)."""
        try:
            post = ForumPost.objects.select_related('author').get(id=post_id)
        except ForumPost.DoesNotExist:
            return Response({'error': 'Bài viết không tồn tại'}, status=404)

        if post.author != request.user and not request.user.is_staff:
            return Response({'error': 'Bạn không có quyền chỉnh sửa bài viết này.'}, status=403)

        if post.is_locked and not request.user.is_staff:
            return Response({'error': 'Bài viết đã bị khóa, không thể chỉnh sửa.'}, status=403)

        # Update allowed fields
        title = request.data.get('title')
        content = request.data.get('content')
        category = request.data.get('category')
        lock_state = request.data.get('is_locked', None)
        pin_state = request.data.get('is_pinned', None)

        if title and title.strip():
            post.title = title.strip()
        if content and content.strip():
            post.content = content.strip()
        if category:
            if category not in {c[0] for c in ForumCategory.choices}:
                return Response({'error': 'Danh mục không hợp lệ.'}, status=400)
            post.category = category

        if lock_state is not None and request.user.is_staff:
            post.is_locked = bool(lock_state)

        if pin_state is not None and request.user.is_staff:
            post.is_pinned = bool(pin_state)

        # Handle image update
        if 'image' in request.FILES:
            post.image = request.FILES['image']

        post.save()
        serializer = ForumPostSerializer(post, context={'request': request})
        return Response(serializer.data)

    def delete(self, request, post_id):
        """Author or staff can delete the post."""
        try:
            post = ForumPost.objects.get(id=post_id)
        except ForumPost.DoesNotExist:
            return Response({'error': 'Bài viết không tồn tại'}, status=404)

        if post.author != request.user and not request.user.is_staff:
            return Response({'error': 'Bạn không có quyền xóa bài viết này.'}, status=403)

        post.delete()
        # Báo cho các tab đang mở chủ đề (frontend đã lắng nghe post_deleted).
        _broadcast_forum_live('post_deleted', {'post_id': post_id})
        return Response({'message': 'Đã xóa bài viết thành công.'}, status=200)


class ForumPostCommentView(APIView):
    """POST /api/forum/posts/<id>/comment/"""
    permission_classes = [IsAuthenticated]

    def _get_client_ip(self, request):
        forwarded = (request.META.get('HTTP_X_FORWARDED_FOR') or '').split(',')[0].strip()
        return forwarded or request.META.get('REMOTE_ADDR')

    def post(self, request, post_id):
        try:
            post = ForumPost.objects.get(id=post_id)
            if post.is_locked:
                return Response({'error': 'Bài viết này đã bị khóa, không thể bình luận.'}, status=403)
        except ForumPost.DoesNotExist:
            return Response({'error': 'Bài viết không tồn tại'}, status=404)

        # Turnstile Verification
        cf_token = request.data.get('cf-turnstile-response')
        remote_ip = self._get_client_ip(request)
        if not verify_turnstile_token(cf_token, remote_ip=remote_ip):
             return Response({'error': 'Xác minh anti-spam không hợp lệ. Vui lòng thử lại.'}, status=400)

        from api.core.forum_moderation import (
            check_flood, forum_ban_active, is_duplicate_submit,
            decide_forum_text, record_flood, record_strike,
        )
        banned, ban_msg = forum_ban_active(request.user)
        if banned:
            return Response({'error': ban_msg}, status=403)
        ok, wait = check_flood(request.user.id, 'comment')
        if not ok:
            return Response({'error': f'Bạn bình luận quá nhanh. Vui lòng chờ {wait}s.'}, status=429)
        raw_content = request.data.get('content') or ''
        # record=False: xem giai phap o ForumPostListCreateView.post
        if is_duplicate_submit(request.user.id, raw_content, record=False):
            return Response({'error': 'Nội dung trùng lặp vừa đăng, nghi spam.'}, status=400)
        decision, reason = decide_forum_text(raw_content)
        if decision == 'block':
            return Response({'error': reason}, status=400)
        if decision == 'attack':
            strikes, was_banned = record_strike(request.user)
            suffix = ' Tài khoản đã bị cấm đăng 7 ngày.' if was_banned else f' Cảnh cáo {strikes}/3.'
            return Response({'error': reason + suffix}, status=400)

        serializer = ForumCommentSerializer(data=request.data, context={'request': request, 'post': post})
        serializer.is_valid(raise_exception=True)
        # Tao binh luan + tang dem trong 1 transaction de khong lech comments_count
        # khi 2 request dong thoi (truoc day dem bang update rieng, de drift).
        with transaction.atomic():
            comment = serializer.save(author=request.user, post=post)
            ForumPost.objects.filter(id=post_id).update(comments_count=F('comments_count') + 1)
        record_flood(request.user.id, 'comment')
        is_duplicate_submit(request.user.id, raw_content)
        cache.delete('forum_stats_v1')

        # Push notification: notify parent comment author OR post author
        try:
            from api.utils.push_service import push_service
            sender_name = getattr(request.user, 'profile', None)
            sender_name = sender_name.display_name if sender_name and sender_name.display_name else request.user.username
            post_url = f'/forum/{post.id}/'

            if comment.parent and comment.parent.author != request.user:
                # Reply to a comment → notify parent comment author
                push_service.send_push(
                    comment.parent.author.id,
                    f'{sender_name} đã trả lời bình luận của bạn',
                    _to_plain_notification_text(comment.content, limit=100) or 'Bình luận mới',
                    url=post_url,
                    notification_type='info'
                )
            elif post.author != request.user:
                # Top-level comment → notify post author
                push_service.send_push(
                    post.author.id,
                    f'{sender_name} đã bình luận bài viết của bạn',
                    _to_plain_notification_text(comment.content, limit=100) or 'Bình luận mới',
                    url=post_url,
                    notification_type='info'
                )
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"Comment push notification failed: {e}")

        try:
            sender_name = getattr(request.user, 'profile', None)
            sender_name = sender_name.display_name if sender_name and sender_name.display_name else request.user.username
            _notify_mentions(sender=request.user, content=comment.content, post=post, actor_label=sender_name)
        except Exception as e:
            logger.error(f"Comment mention notification failed: {e}")

        serialized_comment = ForumCommentSerializer(comment, context={'request': request}).data
        _broadcast_forum_live('comment_created', {
            'post_id': post.id,
            'comment_id': comment.id,
            'parent_id': comment.parent_id,
            'author': request.user.username,
        })
        return Response(serialized_comment, status=201)

class ForumCommentLikeView(APIView):
    """POST /api/forum/comments/<id>/like/ — toggle like"""
    permission_classes = [IsAuthenticated]

    def post(self, request, comment_id):
        try:
            comment = ForumComment.objects.get(id=comment_id)
        except ForumComment.DoesNotExist:
            return Response({'error': 'Bình luận không tồn tại'}, status=404)

        like, created = _safe_get_or_create(ForumCommentLike, user=request.user, comment=comment)
        if not created:
            like.delete()
            _dec_counter(ForumComment, comment_id, 'likes_count')
            action = 'unliked'
        else:
            ForumComment.objects.filter(id=comment_id).update(likes_count=F('likes_count') + 1)
            action = 'liked'
        
        comment.refresh_from_db()
        return Response({
            'action': action,
            'likes_count': comment.likes_count,
            'liked': created
        })


class ForumPostLikeView(APIView):
    """POST /api/forum/posts/<id>/like/ — toggle like"""
    permission_classes = [IsAuthenticated]

    def post(self, request, post_id):
        try:
            post = ForumPost.objects.get(id=post_id)
        except ForumPost.DoesNotExist:
            return Response({'error': 'Bài viết không tồn tại'}, status=404)

        like, created = _safe_get_or_create(ForumLike, user=request.user, post=post)
        if not created:
            like.delete()
            _dec_counter(ForumPost, post_id, 'likes_count')
            action = 'unliked'
        else:
            ForumPost.objects.filter(id=post_id).update(likes_count=F('likes_count') + 1)
            action = 'liked'
        
        post.refresh_from_db()
        return Response({
            'action': action,
            'likes_count': post.likes_count,
            'liked': created
        })

class ForumPostReactionView(APIView):
    """POST /api/forum/posts/<id>/reaction/ — reaction_type: helpful, share"""
    permission_classes = [IsAuthenticated]

    def post(self, request, post_id):
        rtype = request.data.get('reaction_type')
        if rtype not in [ForumReactionType.HELPFUL, ForumReactionType.SHARE, ForumReactionType.DISLIKE]:
            return Response({'error': 'Loại tương tác không hợp lệ'}, status=400)

        try:
            post = ForumPost.objects.get(id=post_id)
        except ForumPost.DoesNotExist:
            return Response({'error': 'Bài viết không tồn tại'}, status=404)

        reaction, created = _safe_get_or_create(
            ForumPostReaction,
            user=request.user, post=post, reaction_type=rtype
        )

        # Share la hanh dong "da chia se", khong phai toggle bat/tat nhu like.
        # Truoc day bam copy-link lan 2 (hoac bam nut Facebook/Twitter) lai bi
        # tru shares_count vi endpoint xoa reaction da ton tai.
        if rtype == ForumReactionType.SHARE and not created:
            post.refresh_from_db()
            return Response({
                'action': 'already',
                'helpful_count': post.helpful_count,
                'shares_count': post.shares_count,
                'dislikes_count': post.dislikes_count,
                'reacted': True,
            })

        if not created:
            reaction.delete()
            if rtype == ForumReactionType.HELPFUL:
                _dec_counter(ForumPost, post_id, 'helpful_count')
            elif rtype == ForumReactionType.SHARE:
                _dec_counter(ForumPost, post_id, 'shares_count')
            else:
                _dec_counter(ForumPost, post_id, 'dislikes_count')
            action = 'removed'
        else:
            if rtype == ForumReactionType.HELPFUL:
                ForumPost.objects.filter(id=post_id).update(helpful_count=F('helpful_count') + 1)
            elif rtype == ForumReactionType.SHARE:
                ForumPost.objects.filter(id=post_id).update(shares_count=F('shares_count') + 1)
            else:
                ForumPost.objects.filter(id=post_id).update(dislikes_count=F('dislikes_count') + 1)
            action = 'added'

        post.refresh_from_db()
        return Response({
            'action': action,
            'helpful_count': post.helpful_count,
            'shares_count': post.shares_count,
            'dislikes_count': post.dislikes_count,
            'reacted': created
        })

class ForumPostReportView(APIView):
    """POST /api/forum/posts/<id>/report/"""
    permission_classes = [IsAuthenticated]

    def post(self, request, post_id):
        reason = (request.data.get('reason') or '').strip()
        if not reason:
            return Response({'error': 'Vui lòng cung cấp lý do báo cáo'}, status=400)
        if len(reason) > 1200:
            return Response({'error': 'Lý do báo cáo quá dài.'}, status=400)

        if ForumPostReport.objects.filter(reporter=request.user, post_id=post_id, status='pending').exists():
            return Response({'error': 'Bạn đã báo cáo bài viết này và đang chờ xử lý.'}, status=409)

        rate_key = f"forum_report_post:{request.user.id}"
        hits = int(cache.get(rate_key, 0))
        if hits >= 10:
            return Response({'error': 'Bạn đang gửi báo cáo quá nhanh. Vui lòng thử lại sau.'}, status=429)

        try:
            post = ForumPost.objects.get(id=post_id)
        except ForumPost.DoesNotExist:
            return Response({'error': 'Bài viết không tồn tại'}, status=404)

        # Create report
        report = ForumPostReport.objects.create(
            reporter=request.user,
            post=post,
            reason=reason
        )
        cache.set(rate_key, hits + 1, timeout=600)

        # Increment report count
        ForumPost.objects.filter(id=post_id).update(reports_count=F('reports_count') + 1)

        # Trigger AI analysis task (Import here to avoid circulars)
        try:
            from api.core.tasks import process_forum_report
            process_forum_report.delay(report.id)
        except Exception as e:
            logger.error(f"Failed to trigger AI report task: {e}")

        return Response({'message': 'Báo cáo của bạn đã được gửi. AI đang tiến hành phân tích nội dung. Cảm ơn bạn!'}, status=201)

class ForumCommentReportView(APIView):
    """POST /api/forum/comments/<id>/report/"""
    permission_classes = [IsAuthenticated]

    def post(self, request, comment_id):
        reason = (request.data.get('reason') or '').strip()
        if not reason:
            return Response({'error': 'Vui lòng cung cấp lý do báo cáo'}, status=400)
        if len(reason) > 1200:
            return Response({'error': 'Lý do báo cáo quá dài.'}, status=400)

        if ForumCommentReport.objects.filter(reporter=request.user, comment_id=comment_id, status='pending').exists():
            return Response({'error': 'Bạn đã báo cáo bình luận này và đang chờ xử lý.'}, status=409)

        rate_key = f"forum_report_comment:{request.user.id}"
        hits = int(cache.get(rate_key, 0))
        if hits >= 12:
            return Response({'error': 'Bạn đang gửi báo cáo quá nhanh. Vui lòng thử lại sau.'}, status=429)

        try:
            comment = ForumComment.objects.select_related('post').get(id=comment_id)
        except ForumComment.DoesNotExist:
            return Response({'error': 'Bình luận không tồn tại'}, status=404)

        if comment.post.is_locked:
            return Response({'error': 'Không thể báo cáo bình luận trong bài viết đã bị khóa.'}, status=403)

        # Create report
        report = ForumCommentReport.objects.create(
            reporter=request.user,
            comment=comment,
            reason=reason
        )
        cache.set(rate_key, hits + 1, timeout=600)

        # Trigger AI analysis task
        try:
            from api.core.tasks import process_forum_comment_report
            process_forum_comment_report.delay(report.id)
        except Exception as e:
            logger.error(f"Failed to trigger AI comment report task: {e}")

        return Response({'message': 'Báo cáo bình luận đã được gửi. AI đang phân tích nội dung.'}, status=201)


class ForumCommentReactionView(APIView):
    """POST /api/forum/comments/<id>/reaction/ — upvote, downvote, helpful
    
    Mutual exclusivity rules:
    - Can't upvote AND downvote at the same time
    - Can't have like/helpful AND downvote at the same time
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, comment_id):
        reaction_type = request.data.get('reaction_type')
        valid_types = ['upvote', 'downvote', 'helpful']
        
        if reaction_type not in valid_types:
            return Response({'error': 'Loại tương tác không hợp lệ'}, status=400)

        try:
            comment = ForumComment.objects.get(id=comment_id)
        except ForumComment.DoesNotExist:
            return Response({'error': 'Bình luận không tồn tại'}, status=404)

        user = request.user
        
        # Check if reaction exists
        existing = ForumCommentReaction.objects.filter(
            comment=comment, user=user, reaction_type=reaction_type
        ).first()

        if existing:
            # Remove the reaction (toggle off)
            existing.delete()
            self._update_count(comment, reaction_type, -1)
            if reaction_type == 'upvote':
                ForumCommentLike.objects.filter(comment=comment, user=user).delete()
            action = 'removed'
            reacted = False
        else:
            # Mutual exclusivity: remove conflicting reactions
            if reaction_type == 'downvote':
                # Remove upvote and helpful if exists
                up_deleted = ForumCommentReaction.objects.filter(
                    comment=comment, user=user, reaction_type='upvote'
                ).delete()[0]
                help_deleted = ForumCommentReaction.objects.filter(
                    comment=comment, user=user, reaction_type='helpful'
                ).delete()[0]
                like_deleted = ForumCommentLike.objects.filter(
                    comment=comment, user=user
                ).delete()[0]
                if up_deleted or like_deleted:
                    for _ in range((1 if up_deleted else 0) + (1 if like_deleted else 0)):
                        self._update_count(comment, 'upvote', -1)
                if help_deleted:
                    self._update_count(comment, 'helpful', -1)
                    
            elif reaction_type in ['upvote', 'helpful']:
                # Remove downvote if exists
                down_deleted = ForumCommentReaction.objects.filter(
                    comment=comment, user=user, reaction_type='downvote'
                ).delete()[0]
                if down_deleted:
                    self._update_count(comment, 'downvote', -1)
            
            # Create new reaction
            ForumCommentReaction.objects.create(
                comment=comment, user=user, reaction_type=reaction_type
            )
            self._update_count(comment, reaction_type, 1)
            
            # For upvote, also create a ForumCommentLike for backward compatibility
            if reaction_type == 'upvote':
                ForumCommentLike.objects.get_or_create(comment=comment, user=user)
                
            action = 'added'
            reacted = True

        comment.refresh_from_db()
        
        return Response({
            'action': action,
            'reaction_type': reaction_type,
            'likes_count': comment.likes_count,
            'dislikes_count': comment.dislikes_count,
            'helpful_count': comment.helpful_count,
            'reacted': reacted,
            'user_liked': ForumCommentLike.objects.filter(comment=comment, user=user).exists(),
            'user_disliked': ForumCommentReaction.objects.filter(comment=comment, user=user, reaction_type='downvote').exists(),
            'user_helpful': ForumCommentReaction.objects.filter(comment=comment, user=user, reaction_type='helpful').exists(),
        })

    def _update_count(self, comment, reaction_type, delta):
        field_map = {'upvote': 'likes_count', 'downvote': 'dislikes_count', 'helpful': 'helpful_count'}
        field = field_map.get(reaction_type)
        if not field:
            return
        if delta < 0:
            _dec_counter(ForumComment, comment.id, field)
        else:
            ForumComment.objects.filter(id=comment.id).update(**{field: F(field) + delta})


class ForumPostReactionMutualView(APIView):
    """POST /api/forum/posts/<id>/reaction/mutual/ — with mutual exclusivity
    
    Ensures like/helpful can't coexist with dislike
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, post_id):
        rtype = request.data.get('reaction_type')
        if rtype not in [ForumReactionType.HELPFUL, ForumReactionType.SHARE, ForumReactionType.DISLIKE]:
            return Response({'error': 'Loại tương tác không hợp lệ'}, status=400)

        try:
            post = ForumPost.objects.get(id=post_id)
        except ForumPost.DoesNotExist:
            return Response({'error': 'Bài viết không tồn tại'}, status=404)

        user = request.user
        
        # Check existing reaction of same type
        existing = ForumPostReaction.objects.filter(
            user=user, post=post, reaction_type=rtype
        ).first()

        if existing:
            # Toggle off
            existing.delete()
            if rtype == ForumReactionType.HELPFUL:
                _dec_counter(ForumPost, post_id, 'helpful_count')
            elif rtype == ForumReactionType.SHARE:
                _dec_counter(ForumPost, post_id, 'shares_count')
            else:
                _dec_counter(ForumPost, post_id, 'dislikes_count')
            action = 'removed'
            reacted = False
        else:
            # Mutual exclusivity
            if rtype == ForumReactionType.DISLIKE:
                # Remove like and helpful
                like_deleted = ForumLike.objects.filter(post=post, user=user).delete()[0]
                if like_deleted:
                    _dec_counter(ForumPost, post_id, 'likes_count')

                helpful_deleted = ForumPostReaction.objects.filter(
                    post=post, user=user, reaction_type=ForumReactionType.HELPFUL
                ).delete()[0]
                if helpful_deleted:
                    _dec_counter(ForumPost, post_id, 'helpful_count')
                    
            elif rtype in [ForumReactionType.HELPFUL]:
                # Remove dislike
                dislike_deleted = ForumPostReaction.objects.filter(
                    post=post, user=user, reaction_type=ForumReactionType.DISLIKE
                ).delete()[0]
                if dislike_deleted:
                    _dec_counter(ForumPost, post_id, 'dislikes_count')
            
            # Create reaction
            ForumPostReaction.objects.create(user=user, post=post, reaction_type=rtype)
            if rtype == ForumReactionType.HELPFUL:
                ForumPost.objects.filter(id=post_id).update(helpful_count=F('helpful_count') + 1)
            elif rtype == ForumReactionType.SHARE:
                ForumPost.objects.filter(id=post_id).update(shares_count=F('shares_count') + 1)
            else:
                ForumPost.objects.filter(id=post_id).update(dislikes_count=F('dislikes_count') + 1)
            action = 'added'
            reacted = True

        post.refresh_from_db()
        return Response({
            'action': action,
            'helpful_count': post.helpful_count,
            'shares_count': post.shares_count,
            'dislikes_count': post.dislikes_count,
            'likes_count': post.likes_count,
            'reacted': reacted,
            'user_liked': ForumLike.objects.filter(post=post, user=user).exists(),
            'user_helpful': ForumPostReaction.objects.filter(post=post, user=user, reaction_type=ForumReactionType.HELPFUL).exists(),
            'user_disliked': ForumPostReaction.objects.filter(post=post, user=user, reaction_type=ForumReactionType.DISLIKE).exists(),
        })


class ForumPostLikeMutualView(APIView):
    """POST /api/forum/posts/<id>/like/mutual/ — with mutual exclusivity"""
    permission_classes = [IsAuthenticated]

    def post(self, request, post_id):
        try:
            post = ForumPost.objects.get(id=post_id)
        except ForumPost.DoesNotExist:
            return Response({'error': 'Bài viết không tồn tại'}, status=404)

        user = request.user
        like, created = _safe_get_or_create(ForumLike, user=user, post=post)

        if not created:
            # Toggle off
            like.delete()
            _dec_counter(ForumPost, post_id, 'likes_count')
            action = 'unliked'
            liked = False
        else:
            ForumPost.objects.filter(id=post_id).update(likes_count=F('likes_count') + 1)
            # Remove dislike if exists (mutual exclusivity)
            dislike_deleted = ForumPostReaction.objects.filter(
                post=post, user=user, reaction_type=ForumReactionType.DISLIKE
            ).delete()[0]
            if dislike_deleted:
                _dec_counter(ForumPost, post_id, 'dislikes_count')
            action = 'liked'
            liked = True
        
        post.refresh_from_db()
        return Response({
            'action': action,
            'likes_count': post.likes_count,
            'dislikes_count': post.dislikes_count,
            'liked': liked,
            'user_disliked': ForumPostReaction.objects.filter(post=post, user=user, reaction_type=ForumReactionType.DISLIKE).exists(),
        })


class ForumStatsView(APIView):
    """GET /api/v1/forum/stats/ — thống kê diễn đàn (public).

    Dùng cho sidebar/thống kê trang Forum + Admin forum (thay vì suy ra cục bộ).
    """
    permission_classes = [AllowAny]

    def get(self, request):
        from django.contrib.auth import get_user_model
        from api.core.models import ForumBan, ForumPostReport, ForumCommentReport

        cached = cache.get('forum_stats_v1')
        if cached is not None:
            return Response(cached)

        now = timezone.now()
        tz = timezone.get_current_timezone()
        today = now.astimezone(tz).date()
        today_start = timezone.make_aware(datetime.combine(today, time.min), tz)
        today_end = timezone.make_aware(datetime.combine(today, time.max), tz)
        category_stats = list(
            ForumPost.objects.values('category').annotate(count=Count('id')).order_by('-count')
        )
        # Dem distinct bang SQL thay vi nap toan bo author_id ve Python.
        post_authors = set(ForumPost.objects.values_list('author_id', flat=True).distinct().iterator())
        comment_authors = set(ForumComment.objects.values_list('author_id', flat=True).distinct().iterator())
        post_authors.discard(None)
        comment_authors.discard(None)
        total_members = len(post_authors | comment_authors)
        try:
            pending_reports = (
                ForumPostReport.objects.filter(status=ForumPostReport.ReportStatus.PENDING).count()
                + ForumCommentReport.objects.filter(status=ForumCommentReport.ReportStatus.PENDING).count()
            )
        except Exception:
            pending_reports = 0
        try:
            total_bans = ForumBan.objects.filter(is_active=True).count()
        except Exception:
            total_bans = 0

        payload = {
            'total_posts': ForumPost.objects.count(),
            'total_comments': ForumComment.objects.count(),
            'total_members': total_members,
            'total_bans': total_bans,
            'pending_reports': pending_reports,
            'posts_today': ForumPost.objects.filter(created_at__range=(today_start, today_end)).count(),
            'category_stats': category_stats,
        }
        cache.set('forum_stats_v1', payload, timeout=60)
        return Response(payload)
