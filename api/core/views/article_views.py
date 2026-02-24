from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from ..models import Article, ArticleCategory
from rest_framework.permissions import AllowAny

class ArticleListView(APIView):
    permission_classes = [AllowAny]
    def get(self, request):
        category = request.query_params.get('category')
        articles = Article.objects.filter(is_published=True)
        if category:
            articles = articles.filter(category=category)
        
        data = [{
            'id': a.id,
            'title': a.title,
            'slug': a.slug,
            'category': a.category,
            'category_display': a.get_category_display(),
            'cover_image': a.cover_image.url if a.cover_image else None,
            'author_name': a.author.username if a.author else 'Admin',
            'created_at': a.created_at.isoformat(),
            'summary': a.content[:200]
        } for a in articles[:20]]
        return Response(data)

class ArticleDetailView(APIView):
    permission_classes = [AllowAny]
    def get(self, request, slug):
        article = get_object_or_404(Article, slug=slug, is_published=True)
        return Response({
            'id': article.id,
            'title': article.title,
            'content': article.content,
            'category': article.category,
            'category_display': article.get_category_display(),
            'cover_image': article.cover_image.url if article.cover_image else None,
            'author_name': article.author.username if article.author else 'Admin',
            'created_at': article.created_at.isoformat(),
        })
