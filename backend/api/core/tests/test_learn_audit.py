"""Tests cho audit Learn: lesson nhap khong lo, list annotate, article comment."""
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from django.test import TestCase

from api.core.models import LearnLesson

User = get_user_model()


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
        row = next(r for r in resp.data if r['slug'] == 'bai-public-test')
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
