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


def _public_media_url(path: str) -> str:
    normalized = str(path or '').replace('\\', '/').lstrip('/')
    return f"{settings.MEDIA_URL.rstrip('/')}/{normalized}"

class EditorImageUploadView(APIView):
    """POST /api/v1/utils/upload-image/ — Editor.js image upload"""
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        file_obj = request.FILES.get('image') or request.FILES.get('file') or request.FILES.get('upload')
        if not file_obj:
            return Response({"success": 0, "message": "No file uploaded"}, status=400)

        # Save to media/editor_images/u_<user_id>/
        path = default_storage.save(
            os.path.join('editor_images', f'u_{request.user.id}', file_obj.name),
            ContentFile(file_obj.read())
        )
        url = _public_media_url(path)
        absolute_url = request.build_absolute_uri(url)

        # Response compatible with both Editor.js and CKEditor 5
        return Response({
            "success": 1,
            "url": absolute_url,
            "path": path,
            "file": {
                "url": absolute_url
            }
        })


class EditorMediaLibraryView(APIView):
    """GET/DELETE /api/v1/utils/editor-media/ — list or delete user's uploaded CKEditor images."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        base_prefix = os.path.join('editor_images', f'u_{request.user.id}')
        if not default_storage.exists(base_prefix):
            return Response({"success": 1, "items": []})

        try:
            _, files = default_storage.listdir(base_prefix)
        except Exception:
            return Response({"success": 1, "items": []})

        items = []
        for name in files:
            lowered = (name or '').lower()
            if not lowered.endswith(('.jpg', '.jpeg', '.png', '.webp', '.gif', '.bmp', '.svg')):
                continue
            rel_path = os.path.join(base_prefix, name)
            try:
                modified = default_storage.get_modified_time(rel_path)
                modified_iso = modified.isoformat() if modified else None
            except Exception:
                modified_iso = None
            try:
                size = default_storage.size(rel_path)
            except Exception:
                size = 0

            public_url = _public_media_url(rel_path)
            items.append({
                "name": name,
                "path": rel_path,
                "url": public_url,
                "absolute_url": request.build_absolute_uri(public_url),
                "size": size,
                "modified_at": modified_iso,
            })

        items.sort(key=lambda x: x.get('modified_at') or '', reverse=True)
        return Response({"success": 1, "items": items})

    def delete(self, request):
        target_path = request.data.get('path', '') if isinstance(request.data, dict) else ''
        user_prefix = os.path.join('editor_images', f'u_{request.user.id}')
        normalized_target = os.path.normpath(target_path).replace('\\', '/')
        normalized_prefix = os.path.normpath(user_prefix).replace('\\', '/')

        if not normalized_target or not (
            normalized_target == normalized_prefix or normalized_target.startswith(normalized_prefix + '/')
        ):
            return Response({"success": 0, "message": "Invalid path"}, status=400)

        if not default_storage.exists(normalized_target):
            return Response({"success": 0, "message": "File not found"}, status=404)

        default_storage.delete(normalized_target)
        return Response({"success": 1})

    def post(self, request):
        """Allow POST as fallback for clients that don't send JSON body with DELETE."""
        return self.delete(request)

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
                'username': user.username,
                'userId': user.id,
                'name': user.profile.display_name or user.username,
                'avatar': avatar
            })

        return Response(results)
