"""Kiểm thử thư viện tinnhiemmang.vn (phân tích HTML, tra cứu, dataset cục bộ).

Toàn bộ fixture là HTML tối giản mô phỏng đúng cấu trúc thật của tinnhiemmang.vn,
nên test chạy offline và không phụ thuộc mạng.
"""
import tempfile
from pathlib import Path

from django.test import SimpleTestCase

from api.utils import tinnhiemmang as th

TRUSTED_ITEM = """
<ul>
  <li class="item1">
    <div class="row">
      <div class="col-md-8 col-lg-5 obj">
        <div class="icon"><img src="/x.png" alt="logo"></div>
        <div class="meta">
          <a href="https://tinnhiemmang.vn/danh-ba-tin-nhiem/capdobocongangovvn-1790044914" class="sf-semibold webkit-box-1">
            <span>capdo.bocongan.gov.vn </span>
            <svg width="24" height="24"><path d="M0 0"/></svg>
          </a>
          <div class="date font12">Tín nhiệm mạng: 22/09/2026</div>
          <div class="code hidden-xl-up">
            <a href="https://tinnhiemmang.vn/danh-ba-tin-nhiem/cuc-an-ninh-mang-1790044914"><label>Sở hữu bởi: &nbsp; </label> Cục An ninh mạng</a>
          </div>
        </div>
      </div>
      <div class="hidden-lg-down col-lg-4 org sf-medium">
        <img src="/y.png" alt="logo">
        <a href="https://tinnhiemmang.vn/danh-ba-tin-nhiem/cuc-an-ninh-mang-1790044914">Cục An ninh mạng</a>
      </div>
      <div class="col-md-4 col-lg-3 medal">
        <div class="medal_basic1 sf-semibold"> <svg><path d="M1 1"/></svg> Chứng nhận cơ bản </div>
      </div>
    </div>
  </li>
</ul>
"""

SCAM_ITEM = """
<ul>
  <li class="item1">
    <div class="row">
      <div class="col-md-8 col-lg-6 obj">
        <div class="icon3"><img src="/icon_web2.png"></div>
        <div class="meta">
          <div class="sf-semibold"><span class="webkit-box-2"> tiktokshopseller-vn.com </span></div>
          <div class="date font12">Đã phát hiện ngày 18/02/2025</div>
          <div class="code hidden-xl-up">
            <a href="https://tinnhiemmang.vn/danh-ba-tin-nhiem/tiktok-shop-1738566597"><label>Mạo danh tổ chức: </label> TikTok shop</a>
          </div>
        </div>
      </div>
      <div class="hidden-lg-down col-lg-3 org sf-medium">
        <img src="/z.png"><a href="https://tinnhiemmang.vn/danh-ba-tin-nhiem/tiktok-shop-1738566597">TikTok shop</a>
      </div>
      <div class="col-md-4 col-lg-3 status sf-semibold">
        <div class="handling"><svg><g><path d="M9 9"/></g></svg> Đang xử lý </div>
      </div>
    </div>
  </li>
</ul>
"""

ORG_ITEM = """
<ul>
  <li class="item2">
    <div class="row">
      <div class="col-12 obj mb-2">
        <div class="icon"><img src="/logo.png" alt="logo"></div>
        <div class="meta">
          <a href="https://tinnhiemmang.vn/danh-ba-tin-nhiem/vien-kiem-sat-nhan-dan-tinh-nghe-an-1774342584" class="sf-semibold ">
            <span > Viện kiểm sát nhân dân tỉnh Nghệ An </span>
            <svg><path d="M0 0"/></svg>
          </a>
          <div class="date font12">Tín nhiệm mạng: 25/03/2026</div>
        </div>
      </div>
    </div>
  </li>
</ul>
"""

NO_RESULT = "<p>Website bạn tìm kiếm chưa được đăng ký xác nhận Tin nhiệm mạng theo tiêu chí của chúng tôi.</p>"

PAGINATION = '<a class="page-link" href="https://tinnhiemmang.vn/website-tin-nhiem?page=610">610</a>' \
             '<a class="page-link" href="https://tinnhiemmang.vn/website-tin-nhiem?page=2">2</a>'

DETAIL = """
<html><head><title>Thông tin tín nhiệm website: capdo.bocongan.gov.vn</title></head><body>
<div class="box"><div class="text"> Cập nhật ngày 22/09/2026 </div></div>
<div id="trust-page"><div class="col-md-7">
  <ul class="org-info">
    <li><div class="label"> Tổ chức sở hữu </div>
        <div class="info webkit-box-1"><a href="/danh-ba-tin-nhiem/cuc-an-ninh-mang-1"> Cục An ninh mạng </a></div></li>
    <li><div class="label"> Số điện thoại </div><div class="info webkit-box-1"> 84593505999 </div></li>
    <li><div class="label"> Địa chỉ </div><div class="info"> Lô E2 Cầu Giấy, Hà Nội </div></li>
    <li><div class="label"> Ngày duyệt </div><div class="info webkit-box-1"> 22/09/2026 </div></li>
  </ul>
</div>
<div class="col-md-5"><div id="box-medal">
  <div class="obj"><span>capdo.bocongan.gov.vn</span></div>
  <div class="expire_date webkit-box-1 mt-2 mb-2"> Chứng nhận đến ngày: 31/12/2029 </div>
  <img class="mt-2 medal" src="/medal.png" alt="medal">
</div></div></div>
<div class="under"><div class="col-md-8">
  <h2 class="title sf-medium">Các tiêu chí đạt được</h2>
  <ul class="list">
    <li><div class="meta"><h3 class="sf-semibold">Bảo đảm an toàn thông tin theo cấp độ </h3><p>Tuân thủ quy định pháp luật.</p></div></li>
    <li><div class="meta"><h3 class="sf-semibold">Không thuộc danh sách đen</h3><p>Tên miền không thuộc danh sách khuyến cáo.</p></div></li>
  </ul>
</div></div>
</body></html>
"""


class ParsingTests(SimpleTestCase):
    def test_parse_trusted_web_item(self):
        recs = th.parse_listing(TRUSTED_ITEM, "web")
        self.assertEqual(len(recs), 1)
        r = recs[0]
        self.assertEqual(r.kind, "trusted")
        self.assertEqual(r.domain, "capdo.bocongan.gov.vn")
        self.assertEqual(r.ref_id, "1790044914")
        self.assertEqual(r.trusted_since, "2026-09-22")
        self.assertEqual(r.date, "2026-09-22")
        self.assertEqual(r.owner, "Cục An ninh mạng")
        self.assertEqual(r.badge, "Chứng nhận cơ bản")
        self.assertTrue(r.url.startswith("https://tinnhiemmang.vn/danh-ba-tin-nhiem/"))

    def test_parse_scam_item(self):
        r = th.parse_listing(SCAM_ITEM, "fake")[0]
        self.assertEqual(r.kind, "scam")
        self.assertEqual(r.domain, "tiktokshopseller-vn.com")
        self.assertEqual(r.detected_on, "2025-02-18")
        self.assertEqual(r.impersonated, "TikTok shop")
        self.assertEqual(r.owner, "TikTok shop")
        self.assertEqual(r.badge, "Đang xử lý")

    def test_parse_org_item2(self):
        r = th.parse_listing(ORG_ITEM, "org")[0]
        self.assertEqual(r.name, "Viện kiểm sát nhân dân tỉnh Nghệ An")
        self.assertEqual(r.ref_id, "1774342584")
        self.assertIsNone(r.domain)  # tổ chức không phải domain
        self.assertEqual(r.trusted_since, "2026-03-25")

    def test_no_result_fragment_returns_empty(self):
        self.assertEqual(th.parse_listing(NO_RESULT, "web"), [])

    def test_pagination_max_page(self):
        self.assertEqual(th.max_page(PAGINATION, "website-tin-nhiem"), 610)
        self.assertEqual(th.listing_total_pages(PAGINATION, "web"), 610)

    def test_dedup_same_slug(self):
        self.assertEqual(len(th.parse_listing(TRUSTED_ITEM + TRUSTED_ITEM, "web")), 1)


class HelperTests(SimpleTestCase):
    def test_normalize_domain(self):
        self.assertEqual(th.normalize_domain("https://WWW.Vietcombank.com.vn:443/a?b=1"),
                         "vietcombank.com.vn")
        self.assertEqual(th.normalize_domain("  Example.COM. "), "example.com")

    def test_looks_like_domain(self):
        self.assertTrue(th.looks_like_domain("abc.vn"))
        self.assertTrue(th.looks_like_domain("a.b.example.gov.vn"))
        self.assertFalse(th.looks_like_domain("Cục An ninh mạng"))
        self.assertFalse(th.looks_like_domain("IOC Lạc Dương"))

    def test_parse_vn_date(self):
        self.assertEqual(th.parse_vn_date("Tín nhiệm mạng: 22/09/2026"), "2026-09-22")
        self.assertEqual(th.parse_vn_date("Đã phát hiện ngày 1/2/2025"), "2025-02-01")
        self.assertIsNone(th.parse_vn_date("không có ngày"))


class DetailParsingTests(SimpleTestCase):
    def test_parse_detail(self):
        d = th.parse_detail(DETAIL)
        self.assertEqual(d["domain"], "capdo.bocongan.gov.vn")
        self.assertEqual(d["owner"], "Cục An ninh mạng")
        self.assertEqual(d["phone"], "84593505999")
        self.assertEqual(d["address"], "Lô E2 Cầu Giấy, Hà Nội")
        self.assertEqual(d["approved"], "2026-09-22")
        self.assertEqual(d["updated"], "2026-09-22")
        self.assertEqual(d["cert_expire"], "2029-12-31")
        self.assertTrue(d["medal_image"].endswith("/medal.png"))
        self.assertEqual(len(d["criteria"]), 2)
        self.assertEqual(d["criteria"][0]["title"], "Bảo đảm an toàn thông tin theo cấp độ")

    def test_parse_detail_empty(self):
        d = th.parse_detail("<html><body>không có gì</body></html>")
        self.assertEqual(d["fields"], {})
        self.assertEqual(d["criteria"], [])


class DatasetTests(SimpleTestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        th._INDEX_CACHE.clear()

    def test_append_and_load_roundtrip(self):
        rec = th.parse_listing(TRUSTED_ITEM, "web")[0]
        self.assertEqual(th.append_records("web", [rec], base_dir=self.dir), 1)
        rows = th.load_records("web", base_dir=self.dir)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["domain"], "capdo.bocongan.gov.vn")
        self.assertEqual(th.available_datasets(self.dir), {"web": 1})

    def test_local_lookup(self):
        trusted = th.parse_listing(TRUSTED_ITEM, "web")[0]
        scam = th.parse_listing(SCAM_ITEM, "fake")[0]
        th.append_records("web", [trusted], base_dir=self.dir)
        th.append_records("fake", [scam], base_dir=self.dir)
        th._INDEX_CACHE.clear()
        self.assertEqual(th.lookup_local_domain("capdo.bocongan.gov.vn", self.dir)["status"], "trusted")
        self.assertEqual(th.lookup_local_domain("tiktokshopseller-vn.com", self.dir)["status"], "scam")
        self.assertEqual(th.lookup_local_domain("khong-ton-tai.vn", self.dir)["status"], "unknown")

    def test_load_missing_returns_empty_and_skips_bad_lines(self):
        self.assertEqual(th.load_records("org", base_dir=self.dir), [])
        path = th.dataset_path("org", self.dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{"slug": "a-1"}\n\n{ hỏng json\n', encoding="utf-8")
        rows = th.load_records("org", base_dir=self.dir)
        self.assertEqual(len(rows), 1)


class NewsParsingTests(SimpleTestCase):
    """Parser tin tức tinnhiemmang.vn: đủ bài, sạch tiền tố site, content HTML không dính chữ."""

    LISTING = """
    <div class="post-vertical mb-2">
      <a href="/bai-viet-vertical"><img data-src="/storage/a.png"></a>
      <a href="/bai-viet-vertical" class="sf-semibold">Tiêu đề bài viết dạng dọc đủ dài</a>
      <p class="webkit-box-2">Tín nhiệm mạng | Mô tả bài viết dạng dọc.</p>
    </div>
    <div class="post-horizontal">
      <a href="https://tinnhiemmang.vn/bai-viet-horizontal"><img src="https://tinnhiemmang.vn/storage/b.png"></a>
      <h3>Tiêu đề bài viết dạng ngang đủ dài</h3>
      <p>Tín nhiệm mạng | Mô tả bài viết dạng ngang.</p>
    </div>
    <div class="item"><a href="/gioi-thieu">Giới thiệu</a></div>
    """

    DETAIL = """
    <html><head><title>Tín nhiệm mạng | bỏ qua</title></head><body>
      <div class="col-md-9">
        <h1>Tiêu đề bài viết kiểm thử</h1>
        <div class="date-create">15/01/2025</div>
        <img src="/storage/cover.jpg">
        <p>Microsoft tiết lộ rằng họ&nbsp;<a href="https://example.com/x">đang sử dụng hành động</a> pháp lý.</p>
        <h3>Tiêu đề phụ</h3>
        <p>Hãy chia sẻ câu chuyện của bạn với chúng tôi để lan tỏa.</p>
        <ul><li>Ý một</li><li>Ý <strong>hai</strong></li></ul>
      </div>
    </body></html>
    """

    def test_listing_detects_both_card_types_and_strips_prefix(self):
        items = th.parse_news_listing(self.LISTING, "noi_bat")
        urls = {i["url"] for i in items}
        self.assertIn("https://tinnhiemmang.vn/bai-viet-vertical", urls)
        self.assertIn("https://tinnhiemmang.vn/bai-viet-horizontal", urls)
        self.assertNotIn("https://tinnhiemmang.vn/gioi-thieu", urls)
        for it in items:
            self.assertFalse(it["summary"].lower().startswith("tín nhiệm mạng"))

    def test_detail_builds_clean_html(self):
        art = "https://tinnhiemmang.vn/bai-viet-kiem-thu"
        d = th.parse_news_detail(self.DETAIL, art, "noi_bat",
                                 fallback_meta={"title": "Tín nhiệm mạng | Tiêu đề dự phòng",
                                                "summary": "Tín nhiệm mạng | tóm tắt dự phòng",
                                                "category": "news"})
        self.assertEqual(d.title, "Tiêu đề bài viết kiểm thử")
        self.assertFalse(d.summary.lower().startswith("tín nhiệm mạng"))
        self.assertEqual(d.published_date, "2025-01-15")
        self.assertTrue(d.content.startswith("<p>"))
        self.assertIn("<h3>Tiêu đề phụ</h3>", d.content)
        self.assertIn("<ul><li>Ý một</li><li>Ý <strong>hai</strong></li></ul>", d.content)
        self.assertIn('<a href="https://example.com/x"', d.content)
        self.assertNotIn("\xa0", d.content)
        self.assertNotIn("họđang", d.content)  # không dính chữ
        self.assertNotIn("Hãy chia sẻ câu chuyện", d.content)  # đã lọc rác

    def test_detail_keeps_inline_image_absolute(self):
        html = ('<div class="col-md-9"><h1>Tiêu đề có ảnh</h1>'
                '<p>Trước <img data-src="/storage/x.png"> sau</p></div>')
        d = th.parse_news_detail(html, "https://tinnhiemmang.vn/bai-viet-anh", "noi_bat")
        self.assertIn('<img src="https://tinnhiemmang.vn/storage/x.png"', d.content)
        self.assertIn("Trước", d.content)  # không dính chữ quanh ảnh


class VnexpressParsingTests(SimpleTestCase):
    """Parser VnExpress: đủ bài, ngày tháng, content HTML giữ ảnh/figure."""

    LISTING = """
    <div class="list-news">
      <article class="item-news item-news-common">
        <div class="thumb-art"><a href="/bai-vne-1-5130813.html"><img data-src="https://i1.vnecdn.net/a.jpg"></a></div>
        <h2 class="title-news"><a href="/bai-vne-1-5130813.html">Tiêu đề bài VnExpress đủ dài để nhận</a></h2>
        <p class="description"><a href="/bai-vne-1-5130813.html">Mô tả ngắn của bài viết.</a></p>
      </article>
      <article class="item-news">
        <h3 class="title-news"><a href="https://vnexpress.net/bai-vne-2-5129668.html#box_comment_vne">Bài thứ hai đủ dài tiêu đề</a></h3>
        <p class="description">Mô tả hai.</p>
      </article>
    </div>
    """

    DETAIL = """
    <html><body>
      <h1 class="title-detail">Bảy người Việt 'rửa tiền' hàng nghìn tỷ đồng</h1>
      <p class="description">Phú Thọ Nhóm tội phạm lừa đảo qua mạng.</p>
      <span class="date">Thứ bảy, 10/10/2026, 21:10 (GMT+7)</span>
      <article class="fck_detail">
        <p class="Normal">Công an tỉnh Phú Thọ hôm nay cho biết.</p>
        <figure class="tplCaption">
          <picture><source data-srcset="https://i1.vnecdn.net/b.jpg"><img data-src="https://i1.vnecdn.net/b.jpg"></picture>
          <figcaption>Công an lấy lời khai. Ảnh: Công an cung cấp</figcaption>
        </figure>
        <p class="Normal">Kết quả điều tra <strong>ban đầu</strong> xác định.</p>
      </article>
    </body></html>
    """

    def test_listing(self):
        items = th.parse_vnexpress_listing(self.LISTING, "lua_dao_qua_mang")
        urls = [i["url"] for i in items]
        self.assertIn("https://vnexpress.net/bai-vne-1-5130813.html", urls)
        # fragment #box_comment_vne phải bị cắt
        self.assertIn("https://vnexpress.net/bai-vne-2-5129668.html", urls)
        self.assertEqual(items[0]["category"], "alert")
        self.assertTrue(items[0]["cover_image"].startswith("https://i1.vnecdn.net/"))
        self.assertTrue(items[0]["summary"].startswith("Mô tả"))

    def test_detail(self):
        d = th.parse_vnexpress_detail(
            self.DETAIL, "https://vnexpress.net/bai-vne-1-5130813.html", "lua_dao_qua_mang")
        self.assertEqual(d.source_type, "press")
        self.assertEqual(d.published_date, "2026-10-10")
        self.assertIn("<p>Công an tỉnh Phú Thọ", d.content)
        self.assertIn('<img src="https://i1.vnecdn.net/b.jpg"', d.content)
        self.assertIn("<figcaption>Công an lấy lời khai", d.content)
        self.assertIn("<strong>ban đầu</strong>", d.content)
        self.assertNotIn("Phú ThọNhóm", d.content)


class EvidenceTests(SimpleTestCase):
    """Bằng chứng từ danh bạ Tín nhiệm mạng được đưa vào evidence[]."""

    def test_scam_domain_evidence(self):
        from api.utils import trust_guard as tg
        ev = tg.build_evidence({"tinnhiem": {"status": "scam", "record": {
            "domain": "x.vn", "impersonated": "Vietcombank",
            "url": "https://tinnhiemmang.vn/danh-ba-tin-nhiem/x"}}})
        hit = [e for e in ev if e["source"] == "tinnhiemmang"]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["supports"], "malicious")
        self.assertIn("Vietcombank", hit[0]["detail"])

    def test_trusted_domain_evidence(self):
        from api.utils import trust_guard as tg
        ev = tg.build_evidence({"tinnhiem": {"status": "trusted", "record": {
            "owner": "Cục An ninh mạng", "badge": "Chứng nhận cơ bản"}}})
        hit = [e for e in ev if e["source"] == "tinnhiemmang"]
        self.assertEqual(hit[0]["supports"], "benign")
        self.assertIn("Cục An ninh mạng", hit[0]["detail"])


class RobotsTests(SimpleTestCase):
    ROBOTS = "User-agent: *\nDisallow: /admin/\nDisallow: /login/\nDisallow: /*?page=\n"

    def test_wildcard_query_is_disallowed(self):
        rules = th.parse_robots(self.ROBOTS)
        self.assertFalse(rules.allows("/website-tin-nhiem?page=2"))
        self.assertFalse(rules.allows("/website-lua-dao?page=6281"))
        self.assertTrue(rules.allows("/website-tin-nhiem"))
        self.assertTrue(rules.allows("/filterObj?type=web&name_obj=bocongan"))
        self.assertFalse(rules.allows("/admin/dashboard"))

    def test_client_blocks_before_network(self):
        client = th.TinnhiemClient(respect_robots=True)
        client._robots_rules = th.parse_robots(self.ROBOTS)
        self.assertFalse(client.robots_allows("https://tinnhiemmang.vn/x?page=2"))
        self.assertTrue(client.robots_allows("https://tinnhiemmang.vn/x"))
        with self.assertRaises(th.RobotsDisallowed):
            client.get_html("website-tin-nhiem", {"page": 2})

    def test_respect_robots_off_allows(self):
        client = th.TinnhiemClient(respect_robots=False)
        self.assertTrue(client.robots_allows("https://tinnhiemmang.vn/x?page=2"))

    def test_empty_robots_allows_all(self):
        rules = th.parse_robots("")
        self.assertTrue(rules.allows("/anything"))


class IntegrationTests(SimpleTestCase):
    """Tích hợp dataset cục bộ với vn_sources & threat feed."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self._orig_dir = th.DATA_DIR
        th.DATA_DIR = self.dir
        th._INDEX_CACHE.clear()

        def _restore():
            th.DATA_DIR = self._orig_dir
            th._INDEX_CACHE.clear()
            self._tmp.cleanup()

        self.addCleanup(_restore)

        self.trusted = th.parse_listing(TRUSTED_ITEM, "web")[0]
        self.scam = th.parse_listing(SCAM_ITEM, "fake")[0]
        th.append_records("web", [self.trusted], base_dir=self.dir)
        th.append_records("fake", [self.scam], base_dir=self.dir)
        th._INDEX_CACHE.clear()

    def test_vn_sources_trusted_and_scam_domains(self):
        from api.utils import vn_sources
        trusted = vn_sources.tinnhiem_trusted_domains()
        self.assertEqual(trusted.get("capdo.bocongan.gov.vn"), "Cục An ninh mạng")
        scam = vn_sources.tinnhiem_scam_domains()
        self.assertEqual(scam.get("tiktokshopseller-vn.com"), "TikTok shop")

    def test_tinnhiem_lookup_domain_local(self):
        from api.utils import vn_sources
        res = vn_sources.tinnhiem_lookup_domain("capdo.bocongan.gov.vn")
        self.assertEqual(res["status"], "trusted")
        self.assertIsNone(vn_sources.tinnhiem_lookup_domain("khong-co.vn")["record"])

    def test_threat_feed_yields_scam_domain(self):
        from api.maintenance.threat_feeds import fetch_tinnhiem_fake_feed, _guess_tinnhiem_scam_type
        from api.core.models import ScamType
        items = list(fetch_tinnhiem_fake_feed())
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["domain"], "tiktokshopseller-vn.com")
        self.assertIn("tinnhiemmang", items[0]["tags"])
        self.assertIn("TikTok shop", items[0]["tags"])
        # Ảnh xạ loại lừa đảo theo tổ chức bị mạo danh
        self.assertEqual(_guess_tinnhiem_scam_type("TikTok shop"), ScamType.OTHER)
        self.assertEqual(_guess_tinnhiem_scam_type("Vietcombank"), ScamType.BANK_IMPERSONATION)
        self.assertEqual(_guess_tinnhiem_scam_type("Cục Cảnh sát"), ScamType.POLICE_IMPERSONATION)
        self.assertEqual(_guess_tinnhiem_scam_type("Tổng cục Thuế"), ScamType.GOV_IMPERSONATION)
        self.assertEqual(_guess_tinnhiem_scam_type(), ScamType.PHISHING)

