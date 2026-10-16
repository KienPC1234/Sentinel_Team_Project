"""
Unit & Integration tests for Tín nhiệm mạng feed aggregator in ShieldCall VN.
"""

from unittest.mock import MagicMock, patch
from django.test import TestCase
from rest_framework.test import APIClient

from api.core.models import Article, ArticleCategory, ArticleSourceType
from api.maintenance.tinnhiemmang_feed import sync_tinnhiemmang_articles
from api.utils.tinnhiemmang import (
    NEWS_FEED_CONFIGS,
    TinnhiemArticle,
    parse_news_detail,
    parse_news_listing,
)
from api.utils.vn_sources import (
    VN_OFFICIAL_CHANNELS,
    VN_REFERENCE_SOURCES,
    VN_TINNHIEMMANG_FEEDS,
    VN_TRUSTED_DOMAINS,
    vn_tinnhiemmang_sources,
)


class TinnhiemMangSourcesTests(TestCase):
    def test_official_channels_includes_tinnhiemmang(self):
        tnm = [c for c in VN_OFFICIAL_CHANNELS if "tinnhiemmang.vn" in (c.get("url") or "")]
        self.assertGreaterEqual(len(tnm), 1)
        self.assertEqual(tnm[0]["reliability"], "official")
        self.assertIn("NCSC", tnm[0]["name"])

    def test_trusted_domains_includes_tinnhiemmang(self):
        self.assertIn("tinnhiemmang.vn", VN_TRUSTED_DOMAINS)

    def test_reference_sources_has_tinnhiemmang_type(self):
        sources = vn_tinnhiemmang_sources()
        self.assertGreaterEqual(len(sources), 2)
        urls = [s["url"] for s in sources]
        self.assertIn("https://tinnhiemmang.vn/canh-bao-lua-dao", urls)
        self.assertIn("https://tinnhiemmang.vn/noi-bat", urls)
        for s in sources:
            self.assertEqual(s["type"], "tinnhiemmang")

    def test_feed_configs_validity(self):
        self.assertIn("canh_bao_lua_dao", VN_TINNHIEMMANG_FEEDS)
        self.assertIn("noi_bat", VN_TINNHIEMMANG_FEEDS)
        self.assertEqual(VN_TINNHIEMMANG_FEEDS["canh_bao_lua_dao"]["default_category"], "alert")
        self.assertEqual(VN_TINNHIEMMANG_FEEDS["noi_bat"]["default_category"], "news")


class TinnhiemMangParserTests(TestCase):
    def test_parse_news_listing_extracts_cards(self):
        sample_html = """
        <div class="col-md-9">
            <div class="post-vertical mb-2">
                <a href="/canh-bao-chieu-tro-lua-dao-qua-mang-xa-hoi">
                    <img src="/storage/photos/shares/thumb.jpg" />
                    <h2>Cảnh báo chiêu trò lừa đảo qua mạng xã hội</h2>
                </a>
                <p class="desc">Thủ đoạn giả mạo người thân chuyển khoản khẩn cấp.</p>
            </div>
            <div class="post-vertical mb-2">
                <a href="/website-tin-nhiem">Bỏ qua liên kết danh bạ</a>
            </div>
        </div>
        """
        items = parse_news_listing(sample_html, feed_key="canh_bao_lua_dao", base_url="https://tinnhiemmang.vn")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["title"], "Cảnh báo chiêu trò lừa đảo qua mạng xã hội")
        self.assertEqual(items[0]["url"], "https://tinnhiemmang.vn/canh-bao-chieu-tro-lua-dao-qua-mang-xa-hoi")
        self.assertEqual(items[0]["slug"], "canh-bao-chieu-tro-lua-dao-qua-mang-xa-hoi")
        self.assertIn("thumb.jpg", items[0]["cover_image"])

    def test_parse_news_detail_extracts_article(self):
        sample_html = """
        <div class="col-md-9">
            <h1 class="sf-bold mb-2">CẢNH BÁO LỪA ĐẢO MẠO DANH VNEID</h1>
            <div class="date-create mb-3">15/10/2026</div>
            <p>Thời gian gần đây xuất hiện thủ đoạn gọi điện dụ cài file APK giả mạo.</p>
            <p>Người dân tuyệt đối không nhấn vào liên kết lạ hoặc cấp quyền trợ năng.</p>
        </div>
        """
        art = parse_news_detail(
            sample_html,
            article_url="https://tinnhiemmang.vn/canh-bao-lua-dao-mao-danh-vneid",
            feed_key="canh_bao_lua_dao",
        )
        self.assertIsNotNone(art)
        self.assertEqual(art.title, "CẢNH BÁO LỪA ĐẢO MẠO DANH VNEID")
        self.assertEqual(art.published_date, "2026-10-15")
        self.assertEqual(art.category, "alert")
        self.assertEqual(art.source_type, "tinnhiemmang")
        self.assertIn("thủ đoạn gọi điện", art.content)


class TinnhiemMangIngestionTests(TestCase):
    @patch("api.maintenance.tinnhiemmang_feed.TinnhiemClient")
    def test_sync_creates_and_deduplicates_articles(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        mock_client.get_news_listing.side_effect = lambda feed_key, use_cache=False: [
            {
                "title": f"Bài viết thử nghiệm {feed_key}",
                "url": f"https://tinnhiemmang.vn/bai-viet-thu-nghiem-{feed_key}",
                "slug": f"bai-viet-thu-nghiem-{feed_key}",
                "cover_image": None,
                "summary": "Tóm tắt kiểm thử.",
                "feed_key": feed_key,
                "category": "alert" if feed_key == "canh_bao_lua_dao" else "news",
            }
        ]

        mock_client.get_news_detail.side_effect = lambda url, feed_key, fallback_meta=None, use_cache=False: TinnhiemArticle(
            title=fallback_meta["title"],
            url=url,
            slug=fallback_meta["slug"],
            feed_key=feed_key,
            category=fallback_meta["category"],
            summary=fallback_meta["summary"],
            content="Nội dung bài viết thử nghiệm đầy đủ từ NCSC.",
            cover_image_url=None,
            published_date="2026-10-15",
            source_type="tinnhiemmang",
        )

        # Lần 1: Tạo mới 2 bài viết (1 alert, 1 news)
        stats1 = sync_tinnhiemmang_articles(feed_keys=["canh_bao_lua_dao", "noi_bat"], download_images=False)
        self.assertEqual(stats1["created"], 2)
        self.assertEqual(stats1["skipped"], 0)

        alert_art = Article.objects.get(slug="bai-viet-thu-nghiem-canh_bao_lua_dao")
        self.assertEqual(alert_art.category, ArticleCategory.ALERT)
        self.assertEqual(alert_art.source_type, ArticleSourceType.TINNHIEMMANG)
        self.assertEqual(alert_art.source_url, "https://tinnhiemmang.vn/bai-viet-thu-nghiem-canh_bao_lua_dao")

        news_art = Article.objects.get(slug="bai-viet-thu-nghiem-noi_bat")
        self.assertEqual(news_art.category, ArticleCategory.NEWS)
        self.assertEqual(news_art.source_type, ArticleSourceType.TINNHIEMMANG)

        # Lần 2: Chạy lại không có force_update -> Bỏ qua cả 2 bài vì đã có
        stats2 = sync_tinnhiemmang_articles(feed_keys=["canh_bao_lua_dao", "noi_bat"], download_images=False)
        self.assertEqual(stats2["created"], 0)
        self.assertEqual(stats2["skipped"], 2)

    def test_article_list_api_filter_source_type(self):
        # Tạo bài viết nội bộ và bài viết tinnhiemmang
        Article.objects.create(
            title="Bài viết nội bộ ShieldCall",
            slug="bai-viet-noi-bo",
            content="Nội dung nội bộ",
            category=ArticleCategory.GUIDE,
            source_type=ArticleSourceType.INTERNAL,
            is_published=True,
        )
        Article.objects.create(
            title="Cảnh báo Tín nhiệm mạng",
            slug="canh-bao-tinnhiemmang",
            content="Nội dung cảnh báo",
            category=ArticleCategory.ALERT,
            source_type=ArticleSourceType.TINNHIEMMANG,
            source_url="https://tinnhiemmang.vn/test-alert",
            is_published=True,
        )

        client = APIClient()
        resp = client.get("/api/v1/articles/?source_type=tinnhiemmang")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(all(item["source_type"] == "tinnhiemmang" for item in data))
        self.assertTrue(any(item["slug"] == "canh-bao-tinnhiemmang" for item in data))
        self.assertFalse(any(item["slug"] == "bai-viet-noi-bo" for item in data))

