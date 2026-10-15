import os
import markdown
from django.shortcuts import render
from django.http import Http404, HttpResponse
from django.conf import settings
from django.utils.safestring import mark_safe




from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework import status


class HelpsDetailAPIView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, slug='index'):
        helps_dir = os.path.join(settings.BASE_DIR, 'helps')
        articles = []
        try:
            import re
            for filename in sorted(os.listdir(helps_dir)):
                if filename.endswith('.md'):
                    f_slug = filename[:-3]
                    f_path = os.path.join(helps_dir, filename)
                    with open(f_path, 'r', encoding='utf-8') as f:
                        first_line = f.readline()
                        f_title = "Hướng dẫn"
                        h1_match = re.search(r'#\s+(.+)', first_line)
                        if h1_match:
                            f_title = h1_match.group(1).strip()
                        elif not first_line.startswith('#'):
                            content_peek = f.read(200)
                            h1_match = re.search(r'#\s+(.+)', content_peek)
                            if h1_match:
                                f_title = h1_match.group(1).strip()
                        articles.append({
                            'slug': f_slug,
                            'title': f_title,
                            'active': f_slug == slug
                        })
        except Exception:
            pass

        file_path = os.path.join(helps_dir, f"{slug}.md")
        if not os.path.abspath(file_path).startswith(os.path.abspath(helps_dir)):
            return Response({'error': 'Invalid path'}, status=status.HTTP_400_BAD_REQUEST)

        if not os.path.exists(file_path):
            if slug != 'index':
                file_path = os.path.join(helps_dir, "index.md")
                if not os.path.exists(file_path):
                    return Response({'error': 'Article not found'}, status=status.HTTP_404_NOT_FOUND)
                slug = 'index'
            else:
                return Response({'error': 'Article not found'}, status=status.HTTP_404_NOT_FOUND)

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                html_content = markdown.markdown(
                    content,
                    extensions=['extra', 'codehilite', 'toc', 'admonition', 'nl2br']
                )
                title = "Trung tâm hỗ trợ"
                import re
                h1_match = re.search(r'#\s+(.+)', content)
                if h1_match:
                    title = h1_match.group(1).strip()

                return Response({
                    'title': title,
                    'slug': slug,
                    'content': content,
                    'html': html_content,
                    'articles': articles
                })
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

