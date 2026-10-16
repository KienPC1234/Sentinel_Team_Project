from django.db.models import Count, Q
from django.shortcuts import get_object_or_404
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from ..models import Article, ArticleCategory, ArticleComment, ArticleReaction, LearnReactionType


class ArticleListView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        operation_id='v1_articles_list',
        summary="Danh sách bài viết tin tức và cảnh báo an toàn"
    )
    def get(self, request):
        category = request.query_params.get('category')
        source_type = request.query_params.get('source_type')
        search_q = (request.query_params.get('q') or request.query_params.get('search') or '').strip()
        raw_limit = request.query_params.get('limit')
        limit = min(int(raw_limit), 500) if raw_limit and raw_limit.isdigit() else 200

        articles = (
            Article.objects
            .filter(is_published=True)
            .select_related('author')
            .annotate(
                reactions_total=Count('reactions', distinct=True),
                comments_total=Count('comments', filter=Q(comments__is_hidden=False), distinct=True),
            )
            .order_by('-created_at')
        )

        if category and category != 'all':
            articles = articles.filter(category=category)
        if source_type:
            articles = articles.filter(source_type=source_type)
        if search_q:
            articles = articles.filter(
                Q(title__icontains=search_q) |
                Q(summary__icontains=search_q) |
                Q(content__icontains=search_q)
            )

        data = [{
            'id': a.id,
            'title': a.title,
            'slug': a.slug,
            'category': a.category,
            'category_display': a.get_category_display(),
            'source_type': getattr(a, 'source_type', 'internal'),
            'source_type_display': a.get_source_type_display() if hasattr(a, 'get_source_type_display') else 'ShieldCall VN',
            'source_url': getattr(a, 'source_url', None),
            'cover_image': a.cover_image.url if a.cover_image else None,
            'author_name': a.author.username if a.author else ('Tín nhiệm mạng (NCSC)' if a.source_type == 'tinnhiemmang' else 'ShieldCall Admin'),
            'created_at': a.created_at.isoformat(),
            'summary': a.summary or a.content[:200],
            'reactions_count': getattr(a, 'reactions_total', 0) or 0,
            'comments_count': getattr(a, 'comments_total', 0) or 0,
        } for a in articles[:limit]]
        return Response(data)


class ArticleDetailView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        operation_id='v1_articles_detail',
        summary="Chi tiết bài viết theo slug"
    )
    def get(self, request, slug):
        article = get_object_or_404(Article, slug=slug, is_published=True)

        counts = {
            k: ArticleReaction.objects.filter(article=article, reaction_type=k).count()
            for k in LearnReactionType.values
        }
        reactions_count = sum(counts.values())

        my_reaction = None
        if request.user.is_authenticated:
            my_reaction = ArticleReaction.objects.filter(
                article=article, user=request.user
            ).values_list('reaction_type', flat=True).first()

        comments_count = ArticleComment.objects.filter(article=article, is_hidden=False).count()

        related_qs = (
            Article.objects
            .filter(is_published=True, category=article.category)
            .exclude(id=article.id)
            .order_by('-created_at')[:3]
        )
        related_articles = [{
            'id': r.id,
            'title': r.title,
            'slug': r.slug,
            'category': r.category,
            'category_display': r.get_category_display(),
            'cover_image': r.cover_image.url if r.cover_image else None,
            'created_at': r.created_at.isoformat(),
            'summary': r.summary or r.content[:150],
        } for r in related_qs]

        return Response({
            'id': article.id,
            'title': article.title,
            'slug': article.slug,
            'summary': article.summary,
            'content': article.content,
            'category': article.category,
            'category_display': article.get_category_display(),
            'source_type': getattr(article, 'source_type', 'internal'),
            'source_type_display': article.get_source_type_display() if hasattr(article, 'get_source_type_display') else 'ShieldCall VN',
            'source_url': getattr(article, 'source_url', None),
            'cover_image': article.cover_image.url if article.cover_image else None,
            'author_name': article.author.username if article.author else ('Tín nhiệm mạng (NCSC)' if article.source_type == 'tinnhiemmang' else 'ShieldCall Admin'),
            'created_at': article.created_at.isoformat(),
            'reaction_counts': counts,
            'reactions_count': reactions_count,
            'my_reaction': my_reaction,
            'comments_count': comments_count,
            'related_articles': related_articles,
        })
