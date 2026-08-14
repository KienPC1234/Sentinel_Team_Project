"""ShieldCall VN – Community Views (Announcements, DMs, Tickets, User Card)"""
import logging
from django.contrib.auth import get_user_model
from django.db.models import Q, F, Count
from django.utils import timezone

from rest_framework import status
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from api.core.models import (
    Announcement, AnnouncementReaction, DirectMessage, SupportTicket,
    ForumPost, ForumComment, UserProfile,
)

User = get_user_model()
logger = logging.getLogger(__name__)


# ═══ Announcements ═══════════════════════════════════════════════════════════

class AnnouncementListCreateView(APIView):
    """GET — list, POST — admin creates announcement."""

    def get_permissions(self):
        if self.request.method == 'POST':
            return [IsAdminUser()]
        return [AllowAny()]

    def get(self, request):
        page = int(request.query_params.get('page', 1))
        per_page = 10
        qs = Announcement.objects.select_related('author', 'author__profile').order_by('-is_pinned', '-created_at')
        total = qs.count()
        items = qs[(page - 1) * per_page:page * per_page]

        data = []
        for a in items:
            profile = getattr(a.author, 'profile', None)
            user_reactions = {}
            if request.user.is_authenticated:
                user_reactions = {
                    r.reaction_type: True
                    for r in AnnouncementReaction.objects.filter(announcement=a, user=request.user)
                }
            likes = AnnouncementReaction.objects.filter(announcement=a, reaction_type='like').count()
            data.append({
                'id': a.id,
                'title': a.title,
                'content': a.content,
                'is_pinned': a.is_pinned,
                'likes_count': likes,
                'views_count': a.views_count,
                'author_name': profile.display_name or a.author.username if profile else a.author.username,
                'author_username': a.author.username,
                'author_avatar': profile.avatar.url if profile and profile.avatar else None,
                'author_is_staff': a.author.is_staff,
                'user_liked': user_reactions.get('like', False),
                'created_at': a.created_at.isoformat(),
            })
        return Response({'results': data, 'count': total, 'page': page, 'pages': (total + per_page - 1) // per_page})

    def post(self, request):
        title = request.data.get('title', '').strip()
        content = request.data.get('content', '').strip()
        is_pinned = request.data.get('is_pinned', False)
        if not title or not content:
            return Response({'error': 'Tiêu đề và nội dung là bắt buộc.'}, status=400)
        a = Announcement.objects.create(author=request.user, title=title, content=content, is_pinned=bool(is_pinned))
        return Response({'id': a.id, 'message': 'Đã tạo thông báo.'}, status=201)


class AnnouncementReactionView(APIView):
    """POST — toggle reaction on an announcement."""
    permission_classes = [IsAuthenticated]

    def post(self, request, announcement_id):
        rtype = request.data.get('reaction_type', 'like')
        if rtype not in ('like', 'dislike', 'helpful'):
            return Response({'error': 'Invalid reaction'}, status=400)
        try:
            ann = Announcement.objects.get(id=announcement_id)
        except Announcement.DoesNotExist:
            return Response({'error': 'Không tìm thấy'}, status=404)

        obj, created = AnnouncementReaction.objects.get_or_create(
            user=request.user, announcement=ann, reaction_type=rtype
        )
        if not created:
            obj.delete()
            if rtype == 'like':
                Announcement.objects.filter(id=announcement_id).update(likes_count=F('likes_count') - 1)
            return Response({'action': 'removed', 'likes_count': AnnouncementReaction.objects.filter(announcement=ann, reaction_type='like').count()})
        else:
            if rtype == 'like':
                Announcement.objects.filter(id=announcement_id).update(likes_count=F('likes_count') + 1)
            return Response({'action': 'added', 'likes_count': AnnouncementReaction.objects.filter(announcement=ann, reaction_type='like').count()})


# ═══ Direct Messages ═════════════════════════════════════════════════════════

class DirectMessageInboxView(APIView):
    """GET — user's conversations. POST — send message."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        # Get unique conversation partners
        sent = DirectMessage.objects.filter(sender=user).values_list('receiver_id', flat=True).distinct()
        received = DirectMessage.objects.filter(receiver=user).values_list('sender_id', flat=True).distinct()
        partner_ids = set(list(sent) + list(received))

        conversations = []
        for pid in partner_ids:
            partner = User.objects.select_related('profile').filter(id=pid).first()
            if not partner:
                continue
            last_msg = DirectMessage.objects.filter(
                Q(sender=user, receiver_id=pid) | Q(sender_id=pid, receiver=user)
            ).order_by('-created_at').first()
            unread = DirectMessage.objects.filter(sender_id=pid, receiver=user, is_read=False).count()
            profile = getattr(partner, 'profile', None)
            conversations.append({
                'partner_id': pid,
                'partner_name': profile.display_name or partner.username if profile else partner.username,
                'partner_username': partner.username,
                'partner_avatar': profile.avatar.url if profile and profile.avatar else None,
                'last_message': last_msg.content[:100] if last_msg else '',
                'last_at': last_msg.created_at.isoformat() if last_msg else '',
                'unread': unread,
            })
        conversations.sort(key=lambda c: c['last_at'], reverse=True)
        return Response(conversations)

    def post(self, request):
        receiver_username = request.data.get('receiver')
        content = request.data.get('content', '').strip()
        if not receiver_username or not content:
            return Response({'error': 'Thiếu người nhận hoặc nội dung.'}, status=400)
        try:
            receiver = User.objects.get(username=receiver_username)
        except User.DoesNotExist:
            return Response({'error': 'Người dùng không tồn tại.'}, status=404)
        if receiver == request.user:
            return Response({'error': 'Không thể gửi tin nhắn cho chính mình.'}, status=400)

        msg = DirectMessage.objects.create(sender=request.user, receiver=receiver, content=content)

        # Push notification
        try:
            from api.utils.push_service import push_service
            sender_name = request.user.profile.display_name or request.user.username
            push_service.send_push(
                receiver.id,
                f'Tin nhắn mới từ {sender_name}',
                content[:100],
                url=f'/profile/@{request.user.username}/',
                notification_type='info'
            )
        except Exception as e:
            logger.error(f"DM push failed: {e}")

        return Response({'id': msg.id, 'message': 'Đã gửi tin nhắn.'}, status=201)


class DirectMessageThreadView(APIView):
    """GET — messages with a specific user."""
    permission_classes = [IsAuthenticated]

    def get(self, request, username):
        try:
            partner = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({'error': 'Người dùng không tồn tại.'}, status=404)

        msgs = DirectMessage.objects.filter(
            Q(sender=request.user, receiver=partner) | Q(sender=partner, receiver=request.user)
        ).order_by('created_at')

        # Mark received messages as read
        DirectMessage.objects.filter(sender=partner, receiver=request.user, is_read=False).update(is_read=True)

        data = []
        for m in msgs:
            data.append({
                'id': m.id,
                'sender': m.sender.username,
                'content': m.content,
                'is_read': m.is_read,
                'created_at': m.created_at.isoformat(),
                'is_mine': m.sender == request.user,
            })
        return Response(data)


# ═══ Support Tickets ═════════════════════════════════════════════════════════

class TicketListCreateView(APIView):
    """GET — user's tickets. POST — create ticket."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        tickets = SupportTicket.objects.filter(author=request.user).order_by('-created_at')
        data = [{
            'id': t.id,
            'title': t.title,
            'description': t.description[:200],
            'category': t.category,
            'priority': t.priority,
            'status': t.status,
            'admin_reply': t.admin_reply,
            'created_at': t.created_at.isoformat(),
            'updated_at': t.updated_at.isoformat(),
        } for t in tickets]
        return Response(data)

    def post(self, request):
        title = request.data.get('title', '').strip()
        description = request.data.get('description', '').strip()
        category = request.data.get('category', 'bug')
        priority = request.data.get('priority', 'medium')
        if not title or not description:
            return Response({'error': 'Tiêu đề và mô tả là bắt buộc.'}, status=400)
        t = SupportTicket.objects.create(
            author=request.user, title=title, description=description,
            category=category, priority=priority,
        )
        return Response({'id': t.id, 'message': 'Đã tạo phiếu hỗ trợ.'}, status=201)


class AdminTicketListView(APIView):
    """GET — all tickets. PATCH — respond to ticket."""
    permission_classes = [IsAdminUser]

    def get(self, request):
        status_filter = request.query_params.get('status', '')
        qs = SupportTicket.objects.select_related('author', 'author__profile').order_by('-created_at')
        if status_filter:
            qs = qs.filter(status=status_filter)

        data = []
        for t in qs[:100]:
            profile = getattr(t.author, 'profile', None)
            data.append({
                'id': t.id,
                'title': t.title,
                'description': t.description,
                'category': t.category,
                'priority': t.priority,
                'status': t.status,
                'admin_reply': t.admin_reply,
                'author_name': profile.display_name or t.author.username if profile else t.author.username,
                'author_username': t.author.username,
                'created_at': t.created_at.isoformat(),
                'updated_at': t.updated_at.isoformat(),
            })
        return Response(data)

    def patch(self, request):
        ticket_id = request.data.get('ticket_id')
        try:
            ticket = SupportTicket.objects.get(id=ticket_id)
        except SupportTicket.DoesNotExist:
            return Response({'error': 'Ticket not found'}, status=404)

        admin_reply = request.data.get('admin_reply', '').strip()
        new_status = request.data.get('status', '')

        if admin_reply:
            ticket.admin_reply = admin_reply
            ticket.replied_by = request.user
        if new_status in dict(SupportTicket.TicketStatus.choices):
            ticket.status = new_status
            if new_status == 'resolved':
                ticket.resolved_at = timezone.now()
        ticket.save()

        # Push notification to ticket author
        try:
            from api.utils.push_service import push_service
            push_service.send_push(
                ticket.author.id,
                'Phản hồi từ admin',
                f'Ticket "{ticket.title}" đã được cập nhật.',
                url='/profile/',
                notification_type='info'
            )
        except Exception as e:
            logger.error(f"Ticket push failed: {e}")

        return Response({'message': 'Đã cập nhật ticket.', 'status': ticket.status})


# ═══ User Card (Hover Popup) ════════════════════════════════════════════════

class UserCardView(APIView):
    """GET /api/v1/user/card/<username>/ — Mini user profile card for hover."""
    permission_classes = [AllowAny]

    def get(self, request, username):
        try:
            user = User.objects.select_related('profile').get(username=username)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=404)

        profile = getattr(user, 'profile', None)
        posts_count = ForumPost.objects.filter(author=user).count()
        comments_count = ForumComment.objects.filter(author=user).count()

        # Reaction score (sum of likes received on posts + comments)
        from django.db.models import Sum
        post_likes = ForumPost.objects.filter(author=user).aggregate(s=Sum('likes_count'))['s'] or 0
        comment_likes = ForumComment.objects.filter(author=user).aggregate(s=Sum('likes_count'))['s'] or 0
        reaction_score = post_likes + comment_likes

        return Response({
            'username': user.username,
            'display_name': profile.display_name or user.username if profile else user.username,
            'avatar': profile.avatar.url if profile and profile.avatar else None,
            'is_staff': user.is_staff,
            'rank': profile.rank_info if profile else None,
            'joined': user.date_joined.strftime('%b %d, %Y'),
            'last_seen': user.last_login.isoformat() if user.last_login else None,
            'posts_count': posts_count,
            'comments_count': comments_count,
            'reaction_score': reaction_score,
            'points': profile.rank_points if profile else 0,
        })
