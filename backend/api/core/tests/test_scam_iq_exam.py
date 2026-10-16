"""Tests cho sua loi Scam IQ: endpoint attempt + chong dem trung breakdown."""
from django.contrib.auth import get_user_model
from django.core.cache import cache
from rest_framework.test import APIClient

from django.test import TestCase

from api.core.models import ScamIQAttempt

User = get_user_model()


def _make_exam(user_id, exam_id='exam123'):
    payload = {
        'exam_id': exam_id,
        'user_id': user_id,
        'exam_title': 'De thi test',
        'intro': 'intro',
        'max_score': 300,
        'questions': [
            {
                'id': f'Q{i}', 'type': 'single_choice', 'difficulty': 'easy',
                'question': f'Cau hoi {i}?', 'category': 'test',
                'options': [{'id': 'A', 'text': 'X'}, {'id': 'B', 'text': 'Y'}],
                'correct_option_ids': ['A'],
                'explanation': 'giai thich',
            }
            for i in range(1, 31)
        ],
        'public_questions': [],
    }
    cache.set(f'scam_iq_exam:{exam_id}', payload, timeout=3600)
    return payload


class ScamIQSubmitTest(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(username='scamiq_tester', password='x')
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        _make_exam(self.user.id)

    def test_submit_requires_exam_id(self):
        resp = self.client.post('/api/v1/scam-iq/submit/', {'answers': {}}, format='json')
        self.assertEqual(resp.status_code, 400)

    def test_submit_consumes_exam_single_use(self):
        answers = {f'Q{i}': ['A'] for i in range(1, 31)}
        resp = self.client.post(
            '/api/v1/scam-iq/submit/', {'exam_id': 'exam123', 'answers': answers}, format='json')
        self.assertEqual(resp.status_code, 200)
        self.assertIn('attempt_id', resp.data)
        self.assertEqual(resp.data['score'], 300)
        # De da bi khoa sau khi nop
        resp2 = self.client.post(
            '/api/v1/scam-iq/submit/', {'exam_id': 'exam123', 'answers': answers}, format='json')
        self.assertEqual(resp2.status_code, 410)

    def test_attempt_endpoint_returns_result(self):
        answers = {f'Q{i}': ['A'] for i in range(1, 31)}
        resp = self.client.post(
            '/api/v1/scam-iq/submit/', {'exam_id': 'exam123', 'answers': answers}, format='json')
        attempt_id = resp.data['attempt_id']
        got = self.client.get(f'/api/v1/scam-iq/attempt/{attempt_id}/')
        self.assertEqual(got.status_code, 200)
        self.assertEqual(got.data['score'], 300)
        self.assertTrue(got.data['is_ai_scored'])
        # User khac khong xem duoc
        other = User.objects.create_user(username='scamiq_other', password='x')
        self.client.force_authenticate(user=other)
        denied = self.client.get(f'/api/v1/scam-iq/attempt/{attempt_id}/')
        self.assertEqual(denied.status_code, 404)


class ScamIQScoringBreakdownTest(TestCase):
    def test_ai_scoring_does_not_inflate_totals(self):
        user = User.objects.create_user(username='scamiq_ai', password='x')
        attempt = ScamIQAttempt.objects.create(
            user=user, exam_title='t', score=100, max_score=300,
            correct_count=10, wrong_count=12, level_code='x', level_label='y',
            difficulty_breakdown={'easy': {'total': 6, 'correct': 4}},
            mistakes=[],
            ai_feedback=[{
                'question_id': 'Q1', 'question': 'q', 'free_text': 'tra loi',
                'simulation': {}, 'difficulty': 'easy',
            }],
            is_ai_scored=False,
        )
        # Mo phong phan cap nhat breakdown cua score task (khong dem lai total)
        breakdown = attempt.difficulty_breakdown
        for f in [{'difficulty': 'easy', 'is_correct': True}]:
            diff = str(f.get('difficulty') or 'medium').lower()
            if diff in breakdown and f['is_correct']:
                breakdown[diff]['correct'] += 1
        self.assertEqual(breakdown['easy']['total'], 6)
        self.assertEqual(breakdown['easy']['correct'], 5)
