"""Backend tests cho cac cai tien forum (list nhe, validate, duplicate, cay comment)."""
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase

from api.core.forum_moderation import is_duplicate_submit
from api.core.models import ForumComment, ForumPost
from api.core.serializers import ForumPostListSerializer, ForumPostSerializer

User = get_user_model()


class ForumListSerializerTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='forum_tester', password='x')
        self.post = ForumPost.objects.create(
            author=self.user, title='Tieu de bai viet day du',
            content='<p>Noi dung day du cho bai viet</p>', category='discussion',
        )
        ForumComment.objects.create(
            author=self.user, post=self.post, content='<p>Binh luan 1</p>')

    def test_list_serializer_excludes_comments(self):
        self.assertNotIn('comments', ForumPostListSerializer.Meta.fields)
        self.assertIn('comments', ForumPostSerializer.Meta.fields)

    def test_title_validation(self):
        s = ForumPostSerializer()
        with self.assertRaises(Exception):
            s.validate_title('ngan')
        self.assertEqual(s.validate_title('  Tieu de hop le day du  '), 'Tieu de hop le day du')

    def test_content_validation_rejects_empty_markup(self):
        s = ForumPostSerializer()
        with self.assertRaises(Exception):
            s.validate_content('<p>&nbsp;</p>')
        self.assertTrue(s.validate_content('<p>Noi dung that su</p>'))

    def test_comment_tree_structure(self):
        from api.core.views.forum_views import build_comment_tree

        c1 = ForumComment.objects.create(
            author=self.user, post=self.post, content='<p>reply goc</p>')
        c2 = ForumComment.objects.create(
            author=self.user, post=self.post, content='<p>tra loi</p>', parent=c1)

        class FakeReq:
            user = self.user

        ctx = build_comment_tree(self.post, FakeReq())
        roots = ctx['forum_comment_roots_by_post'][self.post.id]
        # post da co 1 binh luan o setUp + c1 la goc -> 2 root
        self.assertEqual(len(roots), 2)
        self.assertEqual(ctx['forum_comment_depths'][c2.id], 2)
        self.assertEqual(len(ctx['forum_comment_children'][c1.id]), 1)

    def test_duplicate_check_does_not_poison_cache(self):
        cache.clear()
        text = 'Noi dung kiem tra trung lap duy nhat 12345'
        # Chi kiem tra -> khong ghi cache
        self.assertFalse(is_duplicate_submit(999999, text, record=False))
        self.assertFalse(is_duplicate_submit(999999, text, record=False))
        # Ghi cache -> lan sau bao trung
        self.assertFalse(is_duplicate_submit(999999, text, record=True))
        self.assertTrue(is_duplicate_submit(999999, text, record=False))
