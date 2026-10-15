import os
import urllib.request
import django
from django.core.files.base import ContentFile

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'PKV.settings')
django.setup()

from api.core.models import Article, LearnLesson

IMAGE_MAP = {
    'otp_card': 'https://images.unsplash.com/photo-1563013544-824ae1b704d3?w=1200&auto=format&fit=crop&q=80',
    'pos_shopping': 'https://images.unsplash.com/photo-1556740758-90de374c12ad?w=1200&auto=format&fit=crop&q=80',
    'cyber_shield': 'https://images.unsplash.com/photo-1563986768609-322da13575f3?w=1200&auto=format&fit=crop&q=80',
    'matrix_code': 'https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?w=1200&auto=format&fit=crop&q=80',
    'crypto_chart': 'https://images.unsplash.com/photo-1516245834210-c4c142787335?w=1200&auto=format&fit=crop&q=80',
    'biometric_ai': 'https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?w=1200&auto=format&fit=crop&q=80',
    'network_globe': 'https://images.unsplash.com/photo-1451187580459-43490279c0fa?w=1200&auto=format&fit=crop&q=80',
    'datacenter': 'https://images.unsplash.com/photo-1544197150-b99a580bb7a8?w=1200&auto=format&fit=crop&q=80',
    'soc_dashboard': 'https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=1200&auto=format&fit=crop&q=80',
    'mobile_lock': 'https://images.unsplash.com/photo-1512941937669-90a1b58e7e9c?w=1200&auto=format&fit=crop&q=80',
    'stock_chart': 'https://images.unsplash.com/photo-1579226905180-636b76d96082?w=1200&auto=format&fit=crop&q=80',
    'hotline_team': 'https://images.unsplash.com/photo-1519389950473-47ba0277781c?w=1200&auto=format&fit=crop&q=80',
    'digital_forensics': 'https://images.unsplash.com/photo-1510511459019-5dda7724fd87?w=1200&auto=format&fit=crop&q=80',
}

_download_cache = {}

def get_image_bytes(key: str) -> bytes:
    if key in _download_cache:
        return _download_cache[key]
    url = IMAGE_MAP[key]
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = resp.read()
        _download_cache[key] = data
        return data

# 1. Clean up duplicate dummy lessons that mirrored the 4 articles
deleted_count, _ = LearnLesson.objects.filter(id__in=[28, 29, 30, 31]).delete()
print(f"Deleted {deleted_count} duplicate dummy lessons (IDs 28..31)")

# 2. Update Article cover images
article_key_map = {
    28: 'otp_card',
    27: 'pos_shopping',
    26: 'stock_chart',
    25: 'hotline_team',
    24: 'biometric_ai',
    23: 'mobile_lock',
    22: 'matrix_code',
    21: 'digital_forensics',
    10: 'cyber_shield',
    9: 'mobile_lock',
    8: 'biometric_ai',
    7: 'crypto_chart',
    6: 'biometric_ai',
    5: 'cyber_shield',
    4: 'mobile_lock',
    3: 'datacenter',
    2: 'digital_forensics',
    1: 'network_globe',
}

for art in Article.objects.all():
    key = article_key_map.get(art.id, 'cyber_shield')
    try:
        data = get_image_bytes(key)
        filename = f"article_{art.slug or art.id}.jpg"
        art.cover_image.save(filename, ContentFile(data), save=True)
        print(f"Article {art.id} ({art.title[:35]}...): Updated cover with {key}")
    except Exception as e:
        print(f"Article {art.id} update error: {e}")

# 3. Update LearnLesson cover images
lesson_key_map = {
    5: 'biometric_ai',
    6: 'mobile_lock',
    7: 'soc_dashboard',
    8: 'stock_chart',
    9: 'pos_shopping',
    10: 'datacenter',
    24: 'digital_forensics',
    25: 'matrix_code',
    26: 'otp_card',
    27: 'biometric_ai',
}

for les in LearnLesson.objects.all():
    key = lesson_key_map.get(les.id, 'cyber_shield')
    try:
        data = get_image_bytes(key)
        filename = f"lesson_{les.slug or les.id}.jpg"
        les.cover_image.save(filename, ContentFile(data), save=True)
        print(f"Lesson {les.id} ({les.title[:35]}...): Updated cover with {key}")
    except Exception as e:
        print(f"Lesson {les.id} update error: {e}")

print("Successfully replaced all cover images with clean photographic assets!")

