import re
from bs4 import BeautifulSoup
from django.db.models import Count
from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from api.utils.security import verify_turnstile_token

from api.core.models import (
    LearnLesson,
    Article,
    LessonReaction,
    ArticleReaction,
    LearnReactionType,
    ArticleComment,
    ArticleCommentReaction,
    ArticleCommentReactionType,
)


def _clean_comment(text: str, max_len: int = 1500) -> str:
    raw = str(text or '')
    soup = BeautifulSoup(raw, 'html.parser')

    for node in soup.find_all(['script', 'style', 'iframe', 'object', 'embed', 'form', 'input', 'button', 'textarea']):
        node.decompose()

    allowed_tags = {
        'p', 'br', 'strong', 'b', 'em', 'i', 'u', 's', 'blockquote',
        'ul', 'ol', 'li', 'a', 'code', 'pre', 'span'
    }
    allowed_attrs = {
        'a': {'href', 'target', 'rel', 'class', 'data-usercard'},
        'span': {'class', 'data-mention'},
    }

    for tag in soup.find_all(True):
        if tag.name not in allowed_tags:
            tag.unwrap()
            continue

        keep_attrs = allowed_attrs.get(tag.name, set())
        for attr in list(tag.attrs):
            if attr not in keep_attrs:
                del tag.attrs[attr]

        if tag.name == 'a':
            href = (tag.get('href') or '').strip()
            if href and not (href.startswith('http://') or href.startswith('https://') or href.startswith('/') or href.startswith('#')):
                del tag.attrs['href']
            tag['rel'] = 'noopener noreferrer nofollow'

    plain_text = re.sub(r'\s+', ' ', soup.get_text(' ', strip=True)).strip()
    if len(plain_text) > max_len:
        return ''
    return str(soup).strip()


def _serialize_article_comment(comment, request=None):
    profile = getattr(comment.author, 'profile', None)
    reactions = list(getattr(comment, '_prefetched_objects_cache', {}).get('reactions', []) or comment.reactions.all())
    upvotes_count = sum(1 for reaction in reactions if reaction.reaction_type == ArticleCommentReactionType.UPVOTE)
    downvotes_count = sum(1 for reaction in reactions if reaction.reaction_type == ArticleCommentReactionType.DOWNVOTE)
    my_vote = None
    if request and request.user.is_authenticated:
        for reaction in reactions:
            if reaction.user_id == request.user.id:
                my_vote = reaction.reaction_type
                break
    return {
        'id': comment.id,
        'parent_id': comment.parent_id,
        'author_username': comment.author.username,
        'author_name': profile.display_name if profile and profile.display_name else comment.author.username,
        'author_avatar': profile.avatar.url if profile and profile.avatar else None,
        'content': comment.content,
        'created_at': comment.created_at.isoformat(),
        'upvotes_count': upvotes_count,
        'downvotes_count': downvotes_count,
        'my_vote': my_vote,
        'replies': [],
    }


class LessonReactionView(APIView):
    def get_permissions(self):
        if self.request.method == 'GET':
            return [AllowAny()]
        return [IsAuthenticated()]

    def get(self, request, slug):
        lesson = get_object_or_404(LearnLesson, slug=slug, is_published=True)
        counts = {
            k: LessonReaction.objects.filter(lesson=lesson, reaction_type=k).count()
            for k in LearnReactionType.values
        }
        my_reaction = None
        if request.user.is_authenticated:
            my_reaction = LessonReaction.objects.filter(
                lesson=lesson, user=request.user
            ).values_list('reaction_type', flat=True).first()
        return Response({'counts': counts, 'my_reaction': my_reaction, 'total': sum(counts.values())})

    def post(self, request, slug):
        reaction_type = request.data.get('reaction_type', LearnReactionType.LIKE)
        if reaction_type not in LearnReactionType.values:
            return Response({'error': 'Invalid reaction type'}, status=400)

        lesson = get_object_or_404(LearnLesson, slug=slug, is_published=True)
        obj, created = LessonReaction.objects.get_or_create(user=request.user, lesson=lesson)
        action = 'added'
        if not created and obj.reaction_type == reaction_type:
            obj.delete()
            action = 'removed'
        else:
            obj.reaction_type = reaction_type
            obj.save(update_fields=['reaction_type'])
            action = 'updated' if not created else 'added'

        counts = {
            k: LessonReaction.objects.filter(lesson=lesson, reaction_type=k).count()
            for k in LearnReactionType.values
        }
        my_reaction = LessonReaction.objects.filter(lesson=lesson, user=request.user).values_list('reaction_type', flat=True).first()
        return Response({'action': action, 'counts': counts, 'my_reaction': my_reaction, 'total': sum(counts.values())})


class ArticleReactionView(APIView):
    def get_permissions(self):
        if self.request.method == 'GET':
            return [AllowAny()]
        return [IsAuthenticated()]

    def get(self, request, slug):
        article = get_object_or_404(Article, slug=slug, is_published=True)
        counts = {
            k: ArticleReaction.objects.filter(article=article, reaction_type=k).count()
            for k in LearnReactionType.values
        }
        my_reaction = None
        if request.user.is_authenticated:
            my_reaction = ArticleReaction.objects.filter(
                article=article, user=request.user
            ).values_list('reaction_type', flat=True).first()
        return Response({'counts': counts, 'my_reaction': my_reaction, 'total': sum(counts.values())})

    def post(self, request, slug):
        reaction_type = request.data.get('reaction_type', LearnReactionType.LIKE)
        if reaction_type not in LearnReactionType.values:
            return Response({'error': 'Invalid reaction type'}, status=400)

        article = get_object_or_404(Article, slug=slug, is_published=True)
        obj, created = ArticleReaction.objects.get_or_create(user=request.user, article=article)
        action = 'added'
        if not created and obj.reaction_type == reaction_type:
            obj.delete()
            action = 'removed'
        else:
            obj.reaction_type = reaction_type
            obj.save(update_fields=['reaction_type'])
            action = 'updated' if not created else 'added'

        counts = {
            k: ArticleReaction.objects.filter(article=article, reaction_type=k).count()
            for k in LearnReactionType.values
        }
        my_reaction = ArticleReaction.objects.filter(article=article, user=request.user).values_list('reaction_type', flat=True).first()
        return Response({'action': action, 'counts': counts, 'my_reaction': my_reaction, 'total': sum(counts.values())})


class ArticleCommentListCreateView(APIView):
    def get_permissions(self):
        if self.request.method == 'POST':
            return [IsAuthenticated()]
        return [AllowAny()]

    def get(self, request, slug):
        article = get_object_or_404(Article, slug=slug, is_published=True)
        comments = (
            ArticleComment.objects
            .filter(article=article, is_hidden=False)
            .select_related('author', 'author__profile')
            .prefetch_related('reactions')
            .order_by('created_at')
        )
        data = []
        indexed = {}
        for comment in comments:
            serialized = _serialize_article_comment(comment, request=request)
            indexed[comment.id] = serialized
            if comment.parent_id and comment.parent_id in indexed:
                indexed[comment.parent_id]['replies'].append(serialized)
            else:
                data.append(serialized)
        return Response({'results': data, 'count': comments.count()})

    def post(self, request, slug):
        article = get_object_or_404(Article, slug=slug, is_published=True)

        cf_token = request.data.get('cf-turnstile-response')
        forwarded = (request.META.get('HTTP_X_FORWARDED_FOR') or '').split(',')[0].strip()
        remote_ip = forwarded or request.META.get('REMOTE_ADDR')
        if not verify_turnstile_token(cf_token, remote_ip=remote_ip):
            return Response({'error': 'Xác thực bảo mật thất bại. Vui lòng thử lại.'}, status=400)

        content = _clean_comment(request.data.get('content'))
        if not content:
            return Response({'error': 'Nội dung bình luận trống hoặc vượt quá 1500 ký tự.'}, status=400)

        parent_id = request.data.get('parent_id')
        parent = None
        if parent_id not in (None, '', 0, '0'):
            try:
                parent = ArticleComment.objects.get(
                    id=int(parent_id),
                    article=article,
                    is_hidden=False,
                )
            except (ValueError, ArticleComment.DoesNotExist):
                return Response({'error': 'Bình luận cha không hợp lệ.'}, status=400)

        comment = ArticleComment.objects.create(article=article, author=request.user, parent=parent, content=content)
        payload = _serialize_article_comment(comment, request=request)
        return Response(payload, status=201)


class ArticleCommentReactionView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, slug, comment_id):
        reaction_type = request.data.get('reaction_type')
        if reaction_type not in [ArticleCommentReactionType.UPVOTE, ArticleCommentReactionType.DOWNVOTE]:
            return Response({'error': 'Loại tương tác không hợp lệ.'}, status=400)

        article = get_object_or_404(Article, slug=slug, is_published=True)
        comment = get_object_or_404(ArticleComment, id=comment_id, article=article, is_hidden=False)

        existing = ArticleCommentReaction.objects.filter(comment=comment, user=request.user).first()
        action = 'added'

        if existing and existing.reaction_type == reaction_type:
            existing.delete()
            action = 'removed'
        else:
            if existing:
                existing.reaction_type = reaction_type
                existing.save(update_fields=['reaction_type'])
                action = 'updated'
            else:
                ArticleCommentReaction.objects.create(
                    comment=comment,
                    user=request.user,
                    reaction_type=reaction_type,
                )
                action = 'added'

        upvotes_count = ArticleCommentReaction.objects.filter(comment=comment, reaction_type=ArticleCommentReactionType.UPVOTE).count()
        downvotes_count = ArticleCommentReaction.objects.filter(comment=comment, reaction_type=ArticleCommentReactionType.DOWNVOTE).count()
        my_vote = ArticleCommentReaction.objects.filter(comment=comment, user=request.user).values_list('reaction_type', flat=True).first()

        return Response({
            'status': 'ok',
            'action': action,
            'comment_id': comment.id,
            'upvotes_count': upvotes_count,
            'downvotes_count': downvotes_count,
            'my_vote': my_vote,
        })


class LearnLessonListView(APIView):
    """GET /api/v1/learn/lessons/ — danh sách bài học đã xuất bản (LearnHub tab Bài học)."""
    permission_classes = [AllowAny]

    def get(self, request):
        from api.core.models import LearnQuiz, LearnScenario

        category = request.query_params.get('category')
        qs = LearnLesson.objects.filter(is_published=True)
        if category and category != 'all':
            qs = qs.filter(category=category)

        qs = qs.annotate(
            quizzes_total=Count('quizzes', distinct=True),
            scenarios_total=Count('scenarios', distinct=True),
            reactions_total=Count('reactions', distinct=True),
        )
        data = []
        for l in qs.order_by('-created_at')[:100]:
            data.append({
                'id': l.id,
                'title': l.title,
                'slug': l.slug,
                'category': l.category,
                'category_display': l.get_category_display(),
                'summary': l.summary,
                'cover_image': l.cover_image.url if l.cover_image else None,
                'created_at': l.created_at.isoformat(),
                'quizzes_count': getattr(l, 'quizzes_total', 0) or 0,
                'scenarios_count': getattr(l, 'scenarios_total', 0) or 0,
                'reactions_count': getattr(l, 'reactions_total', 0) or 0,
            })
        return Response(data)


class LearnScenarioListView(APIView):
    """GET /api/v1/learn/scenarios/ — danh sách kịch bản mô phỏng (LearnHub tab Tình huống)."""
    permission_classes = [AllowAny]

    def get(self, request):
        from api.core.models import LearnScenario

        qs = LearnScenario.objects.select_related('lesson', 'article').order_by('-created_at')
        data = []
        for sc in qs[:100]:
            content = sc.content or {}
            steps = content.get('steps') if isinstance(content, dict) else (content if isinstance(content, list) else [])
            data.append({
                'id': sc.id,
                'title': sc.title,
                'description': sc.description,
                'lesson_id': sc.lesson_id,
                'lesson_title': sc.lesson.title if sc.lesson else None,
                'lesson_slug': sc.lesson.slug if sc.lesson else None,
                'article_id': sc.article_id,
                'article_title': sc.article.title if sc.article else None,
                'steps': steps or [],
                'steps_count': len(steps or []),
                'created_at': sc.created_at.isoformat() if sc.created_at else '',
            })
        return Response(data)


class LearnQuizListView(APIView):
    """GET /api/v1/learn/quizzes/ — danh sách quiz công khai (LearnHub tab Quiz)."""
    permission_classes = [AllowAny]

    def get(self, request):
        from api.core.models import LearnQuiz

        qs = LearnQuiz.objects.select_related('lesson', 'article').order_by('-id')
        data = []
        for q in qs[:100]:
            data.append({
                'id': q.id,
                'question': q.question,
                'question_type': q.question_type,
                'options': q.options if isinstance(q.options, list) else [],
                'lesson': {'slug': q.lesson.slug, 'title': q.lesson.title} if q.lesson_id else None,
                'article': {'slug': q.article.slug, 'title': q.article.title} if q.article_id else None,
            })
        return Response(data)


class LearnQuizCheckView(APIView):
    """POST /api/v1/learn/quizzes/<int:quiz_id>/check/ — chấm đáp án quiz phía server."""
    permission_classes = [AllowAny]

    def post(self, request, quiz_id):
        from api.core.models import LearnQuiz

        try:
            q = LearnQuiz.objects.get(id=quiz_id)
        except LearnQuiz.DoesNotExist:
            return Response({'error': 'Câu hỏi không tồn tại.'}, status=404)

        selected = request.data.get('selected')
        correct_list = q.correct_answers if isinstance(q.correct_answers, list) and q.correct_answers else (
            [q.correct_answer] if q.correct_answer else []
        )
        corr = [str(c).strip() for c in correct_list]

        if isinstance(selected, list):
            sel = [str(s).strip() for s in selected if str(s).strip()]
            is_correct = bool(sel) and sorted(sel) == sorted(corr)
        else:
            s = str(selected or '').strip()
            is_correct = bool(s) and s in corr

        return Response({
            'correct': bool(is_correct),
            'correct_answer': q.correct_answer,
            'correct_answers': q.correct_answers if isinstance(q.correct_answers, list) else [],
            'explanation': q.explanation,
        })


class LearnLessonDetailView(APIView):
    """GET /api/v1/learn/lessons/<slug>/ — chi tiết bài học + quiz + scenario."""
    permission_classes = [AllowAny]

    def get(self, request, slug):
        from api.core.models import LearnLesson, LearnQuiz, LearnReactionType, LearnScenario, LessonReaction

        try:
            lesson = LearnLesson.objects.get(slug=slug, is_published=True)
        except LearnLesson.DoesNotExist:
            return Response({'error': 'Bài học không tồn tại.'}, status=404)

        counts = {
            k: LessonReaction.objects.filter(lesson=lesson, reaction_type=k).count()
            for k in LearnReactionType.values
        }
        reactions_count = sum(counts.values())

        my_reaction = None
        if request.user.is_authenticated:
            my_reaction = LessonReaction.objects.filter(
                lesson=lesson, user=request.user
            ).values_list('reaction_type', flat=True).first()

        quizzes = []
        for q in LearnQuiz.objects.filter(lesson=lesson):
            quizzes.append({
                'id': q.id,
                'question': q.question,
                'question_type': q.question_type,
                'options': q.options or [],
            })

        scenario = None
        sc = LearnScenario.objects.filter(lesson=lesson).order_by('-created_at').first()
        if sc:
            content = sc.content or {}
            steps = content.get('steps') if isinstance(content, dict) else (content if isinstance(content, list) else [])
            scenario = {
                'id': sc.id,
                'title': sc.title,
                'description': sc.description,
                'steps': steps or [],
            }

        return Response({
            'id': lesson.id,
            'title': lesson.title,
            'slug': lesson.slug,
            'summary': lesson.summary,
            'content': lesson.content,
            'category': lesson.category,
            'category_display': lesson.get_category_display(),
            'cover_image': lesson.cover_image.url if lesson.cover_image else None,
            'is_published': lesson.is_published,
            'created_at': lesson.created_at.isoformat() if lesson.created_at else '',
            'reaction_counts': counts,
            'reactions_count': reactions_count,
            'my_reaction': my_reaction,
            'quizzes': quizzes,
            'scenario': scenario,
        })

