import os
import requests
from bs4 import BeautifulSoup
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from django.contrib.auth import get_user_model

User = get_user_model()

class EditorImageUploadView(APIView):
    """POST /api/v1/utils/upload-image/ — Editor.js image upload"""
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        file_obj = request.FILES.get('image') or request.FILES.get('file')
        if not file_obj:
            return Response({"success": 0, "message": "No file uploaded"}, status=400)

        # Save to media/editor_images/
        path = default_storage.save(
            os.path.join('editor_images', file_obj.name),
            ContentFile(file_obj.read())
        )
        url = os.path.join(settings.MEDIA_URL, path)

        return Response({
            "success": 1,
            "file": {
                "url": url
            }
        })

class EditorFetchUrlView(APIView):
    """GET /api/v1/utils/fetch-url/?url=... — Get metadata for Editor.js Link tool"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        url = request.query_params.get('url')
        if not url:
            return Response({"success": 0}, status=400)

        try:
            resp = requests.get(url, timeout=5, headers={'User-Agent': 'ShieldCall-Bot/1.0'})
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, 'html.parser')

            title = soup.find('meta', property='og:title') or soup.find('title')
            title = title.get('content') if title and title.name == 'meta' else (title.string if title else url)

            description = soup.find('meta', property='og:description') or soup.find('meta', attrs={'name': 'description'})
            description = description.get('content') if description else ""

            image = soup.find('meta', property='og:image')
            image_url = image.get('content') if image else ""

            return Response({
                "success": 1,
                "meta": {
                    "title": title,
                    "description": description,
                    "image": {
                        "url": image_url
                    }
                }
            })
        except Exception:
            return Response({
                "success": 1,
                "meta": {
                    "title": url,
                    "description": "",
                    "image": { "url": "" }
                }
            })

class MentionUserListView(APIView):
    """GET /api/v1/utils/mentions/?query=@... — Search users for mentions"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        query = request.query_params.get('query', '').replace('@', '')
        if len(query) < 1:
            return Response([])

        users = User.objects.filter(
            username__icontains=query
        ).select_related('profile')[:10]

        results = []
        for user in users:
            # Safer avatar handling
            try:
                avatar = user.profile.avatar.url if user.profile.avatar else ""
            except:
                avatar = ""
                
            results.append({
                'id': f'@{user.username}',
                'userId': user.id,
                'name': user.profile.display_name or user.username,
                'avatar': avatar
            })

        return Response(results)
