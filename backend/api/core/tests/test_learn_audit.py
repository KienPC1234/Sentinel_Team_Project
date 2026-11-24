"""Tests cho audit Learn: lesson nhap khong lo, list annotate, article comment."""
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from django.test import TestCase

from api.core.models import LearnLesson

User = get_user_model()


def _rows(resp):
    data = resp.data
    return data.get('results', []) if isinstance(data, dict) else data


class LearnLessonVisibilityTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        LearnLesson.objects.create(
            title='Bai nhap', slug='bai-nhap-test', content='nhap',
            is_published=False,
        )
        LearnLesson.objects.create(
            title='Bai public', slug='bai-public-test', content='ok',
            is_published=True,
        )

    def test_draft_lesson_not_readable(self):
        resp = self.client.get('/api/v1/learn/lessons/bai-nhap-test/')
        self.assertEqual(resp.status_code, 404)

    def test_published_lesson_readable(self):
        resp = self.client.get('/api/v1/learn/lessons/bai-public-test/')
        self.assertEqual(resp.status_code, 200)

    def test_lesson_list_counts(self):
        resp = self.client.get('/api/v1/learn/lessons/')
        self.assertEqual(resp.status_code, 200)
        row = next(r for r in _rows(resp) if r['slug'] == 'bai-public-test')
        self.assertIn('quizzes_count', row)
        self.assertIn('scenarios_count', row)


class ArticleCommentTurnstileTest(TestCase):
    def test_comment_requires_turnstile(self):
        from api.core.models import Article
        art = Article.objects.create(
            title='Tin test', slug='tin-test-audit', content='x', is_published=True)
        user = User.objects.create_user(username='learn_commenter', password='x')
        client = APIClient()
        client.force_authenticate(user=user)
        resp = client.post(
            f'/api/v1/learn/articles/{art.slug}/comments/',
            {'content': 'Binh luan test'}, format='json')
        # Khong co token -> 400 (frontend phai gui token tu widget)
        self.assertEqual(resp.status_code, 400)


class ArticleListOrderingTest(TestCase):
    def test_articles_sorted_newest_first_by_published_date_then_created_at(self):
        from datetime import date, timedelta
        from django.utils import timezone
        from api.core.models import Article

        older_crawl_newer_pub = Article.objects.create(
            title='Bai xuat ban moi hon',
            slug='bai-pub-moi-hon',
            content='a',
            category='news',
            source_type='tinnhiemmang',
            published_date=date(2025, 1, 15),
            is_published=True,
        )
        newer_crawl_older_pub = Article.objects.create(
            title='Bai xuat ban cu hon nhung crawl sau',
            slug='bai-pub-cu-hon',
            content='b',
            category='news',
            source_type='tinnhiemmang',
            published_date=date(2024, 11, 15),
            is_published=True,
        )
        internal_recent = Article.objects.create(
            title='Bai noi bo khong co published_date',
            slug='bai-noi-bo-moi',
            content='c',
            category='guide',
            source_type='internal',
            published_date=None,
            is_published=True,
        )
        # Gia lap bai cu duoc crawl sau -> created_at moi hon bai 2025-01-15
        now = timezone.now()
        Article.objects.filter(id=older_crawl_newer_pub.id).update(created_at=now - timedelta(days=20))
        Article.objects.filter(id=newer_crawl_older_pub.id).update(created_at=now - timedelta(days=5))
        Article.objects.filter(id=internal_recent.id).update(created_at=now)

        client = APIClient()
        resp = client.get('/api/v1/articles/')
        self.assertEqual(resp.status_code, 200)
        slugs = [item['slug'] for item in _rows(resp)]
        self.assertEqual(slugs, ['bai-noi-bo-moi', 'bai-pub-moi-hon', 'bai-pub-cu-hon'])

        resp_oldest = client.get('/api/v1/articles/?sort=oldest')
        self.assertEqual(resp_oldest.status_code, 200)
        self.assertEqual(
            [item['slug'] for item in _rows(resp_oldest)],
            ['bai-pub-cu-hon', 'bai-pub-moi-hon', 'bai-noi-bo-moi'],
        )
