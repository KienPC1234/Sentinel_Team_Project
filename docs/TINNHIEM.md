# Danh bạ Tín nhiệm mạng (`tinnhiemmang.vn`) — thư viện & crawler

> Cập nhật: **2026-10-15**. Nguồn: <https://tinnhiemmang.vn> (hệ thống "Tín nhiệm mạng"
> do Cục An ninh mạng / NCSC–VNCERT vận hành).

Tài liệu này mô tả thư viện `api/utils/tinnhiemmang.py` và CLI
`scripts/crawl_tinnhiemmang.py`, cách nối vào hệ thống (trusted domains, threat feed)
cùng **giới hạn pháp lý/crawl** cần tuân thủ.

---

## 1. Vì sao dùng nguồn này

| Nguồn | Nội dung | Dùng cho |
|---|---|---|
| `website-tin-nhiem` | Website đã được chứng nhận tín nhiệm | Đối chiếu tên miền **tin cậy** (chống giả mạo ngân hàng/gov) |
| `to-chuc-tin-nhiem` | Tổ chức được chứng nhận | Xác minh pháp nhân/đơn vị |
| `he-thong-tin-nhiem` / `ung-dung-tin-nhiem` / `thiet-bi-tin-nhiem` | Hệ thống / ứng dụng / thiết bị | Ngữ cảnh |
| `website-lua-dao` | **Danh sách website lừa đảo** + tổ chức bị mạo danh | Threat intel (đen) |

Đây là nguồn **chính thống**, có thẩm quyền hơn danh sách tự biên soạn — phù hợp
điểm cải tiến #2 (dữ liệu nguồn Việt Nam) và #3 (độ tin cậy nguồn).

---

## 2. Cách lấy dữ liệu (đã kiểm chứng)

Trang danh bạ **render phía máy chủ**:

* Danh sách: `GET /<đường-dẫn>?page=N` (mỗi trang ~10 mục; có phân trang).
* Tra cứu: `GET /filterObj?type=<mã>&name_obj=<từ-khoá>` → trả về **đoạn HTML**
  `<ul><li class="item1">…</li></ul>` (không phải JSON). Không có kết quả → `<p>…`.
* Chi tiết: `/danh-ba-tin-nhiem/<slug>-<id>` chứa khối `ul.org-info`
  (tổ chức sở hữu, SĐT, địa chỉ, email, ngày duyệt), `.expire_date` (hạn chứng
  nhận) và `ul.list` (các tiêu chí đạt được).

Mã danh mục (`type`):

| Khoá | `type` | Đường dẫn | Loại |
|---|---|---|---|
| `web` | `web` | `website-tin-nhiem` | trusted |
| `org` | `org` | `to-chuc-tin-nhiem` | trusted |
| `sys` | `sys` | `he-thong-tin-nhiem` | trusted |
| `app` | `app` | `ung-dung-tin-nhiem` | trusted |
| `iot` | `iot` | `thiet-bi-tin-nhiem` | trusted |
| `fake` | `fake` | `website-lua-dao` | scam |

> **Lưu ý về trang chi tiết của mục lừa đảo:** link trong danh sách lừa đảo trỏ tới
> **trang tổ chức bị mạo danh** (bản thân tên miền lừa đảo không có trang riêng).
> Vì vậy crawler mặc định **không** lấy chi tiết cho mục `fake` (dùng `--detail-scam`
> nếu vẫn muốn).
>
> **Khoá duy nhất:** với mục `fake`, `slug`/`url` là của *tổ chức bị mạo danh* (dùng
> chung cho nhiều tên miền) → phải khử trùng/đánh chỉ mục theo **`domain`**, không
> theo `slug`. Crawler đã làm đúng (`domain or slug`); `domain_index(..., by="domain")`
> cũng vậy. Nếu tự viết script, nhớ điều này kẻo mất dữ liệu.

---

## 3. robots.txt — quyết định của dự án

`robots.txt` của tinnhiemmang.vn hiện có:

```
User-agent: *
Disallow: /admin/
Disallow: /login/
Disallow: /*?page=
```

`/*?page=` chặn đúng cơ chế phân trang của danh bạ → nếu tôn trọng robots thì **không
thể lấy danh bạ** (chỉ được trang 1 mỗi danh mục và endpoint `/filterObj`).

**Quyết định triển khai (theo yêu cầu chủ dự án): mặc định BỎ QUA `robots.txt`** để lấy
đủ dữ liệu. Vẫn có đường bật lại:

* Thư viện: `TinnhiemClient(respect_robots=True)` → URL vi phạm sẽ ném `RobotsDisallowed`
  *trước khi* gọi mạng (kiểm bằng `client.robots_allows(url)`).
* CLI: cờ `--respect-robots`. Lệnh sync: `--respect-robots` (hoặc
  `TINNHIEM_SYNC_RESPECT_ROBOTS=1`).
* Vẫn giữ **delay + retry + User-Agent rõ ràng** để không gây tải nặng cho site.

> Ghi chú liêm chính: đây là lựa chọn có ý thức, đánh đổi việc tuân thủ `robots.txt` để
> có dữ liệu phòng chống lừa đảo. Khi dùng chính thức/nội bộ hoá, nên gửi đề nghị chia sẻ
> dữ liệu tới NCSC/VNCERT. Không dùng để tấn công/khai thác; chỉ thu thập danh bạ công khai.

---

## 4. Thư viện `api/utils/tinnhiemmang.py`

Không phụ thuộc Django (dễ test/tái sử dụng ở script & cron).

### 4.1 Tra cứu nhanh

```python
from api.utils import tinnhiemmang as th

client = th.TinnhiemClient(delay=1.0, cache_dir="/tmp/th-cache")  # tôn trọng robots

# Tra 1 tên miền (dùng /filterObj — được phép)
client.lookup_domain("capdo.bocongan.gov.vn")   # {"status": "trusted", ...}
client.lookup_domain("tiktokshopseller-vn.com") # {"status": "scam", ...}

# Tìm theo từ khoá trong từng danh mục
client.search("web", "bocongan")     # List[TinnhiemRecord]
client.search("fake", "viettel")

# Chi tiết một mục
client.detail("capdobocongangovvn-1790044914")
```

### 4.2 Duyệt danh bạ

```python
for rec in client.iter_listing("web", pages=1):   # pages=1 → chỉ trang đầu (robots OK)
    print(rec.domain, rec.owner, rec.badge)
```

### 4.3 Bản ghi & phân tích HTML

* `TinnhiemRecord` — `category, kind, name, url, slug, ref_id, domain,
  trusted_since, detected_on, owner, impersonated, badge, date`.
* `parse_listing(html, category)`, `parse_detail(html)` — hàm thuần, dễ test.
* `listing_total_pages(html, category)`, `max_page(html, path)`.

### 4.4 Dataset cục bộ (tra cứu offline)

```python
th.append_records("web", records)          # ghi JSONL
th.load_records("web")                     # đọc lại
th.lookup_local_domain("capdo.bocongan.gov.vn")   # không gọi mạng
th.available_datasets()                    # {category: số dòng}
```

Dữ liệu nằm ở `backend/api/core/data/tinnhiemmang/<category>.jsonl`.

### 4.5 Chỉ mục SQLite — tra cứu nhanh

Mỗi danh mục có thêm chỉ mục dẫn xuất `<category>.sqlite` (tự dựng/tự làm mới theo
mtime+size của JSONL; có debounce khi file đang được ghi). Nhờ vậy tra cứu không phải
quét/parse cả file:

```python
th.lookup_local_domain("capdo.bocongan.gov.vn")   # ~0.1 ms (thay vì quét toàn bộ)
th.search_local("viettel", limit=10)              # tìm theo domain/tên/chủ sở/mạo danh
th.reindex("all")                                 # dựng lại chỉ mục
th.index_status()                                 # số bản ghi, lúc dựng, có "stale" không
th.iter_keys("fake")                              # nạp nhanh tập khoá để --resume
```

Kết nối SQLite được **dùng lại theo luồng** (thread-local) nên mỗi tra cứu chỉ ~0.08 ms.
JSONL vẫn là **nguồn chân lý**; file `.sqlite` chỉ là chỉ mục (có thể xoá để dựng lại).

---

## 5. CLI `scripts/crawl_tinnhiemmang.py`

```bash
cd backend

# Trang 1 của mỗi danh mục (được phép) → seed dataset
../.venv/bin/python scripts/crawl_tinnhiemmang.py --category all --pages 1

# Một danh mục, kèm chi tiết (chỉ áp dụng cho mục trusted)
../.venv/bin/python scripts/crawl_tinnhiemmang.py --category web --pages 1 --detail --resume

# Xem hiện có gì
../.venv/bin/python scripts/crawl_tinnhiemmang.py --status

# LẤY TOÀN BỘ (mặc định bỏ qua robots.txt; ghi tăng dần, tiếp tục nếu đã có)
../.venv/bin/python scripts/crawl_tinnhiemmang.py --category fake --all --resume \
    --workers 8 --delay 0.3
```

Tuỳ chọn chính: `--category {web,org,sys,app,iot,fake,all}`, `--pages/--all`,
`--start-page`, `--delay`, `--timeout`, **`--workers`**, `--cache-dir`, `--out`,
`--detail`, `--detail-scam`, `--limit`, `--resume`, `--ignore-robots`, `--status`, `--json`.

* Ghi nối vào JSONL **ngay sau mỗi trang** (an toàn khi chạy hàng nghìn trang).
* `--workers N`: mỗi luồng một `TinnhiemClient` riêng (thread-local), gom theo lô; site
  khá chậm nên 6–10 luồng là hợp lý (mặc định 8).
* Mặc định **bỏ qua robots.txt**; nếu bật `--respect-robots` thì gặp `robots.txt` chặn
  sẽ dừng và báo rõ (trường `robots_blocked` trong thống kê).

### 5.1 Lấy toàn bộ qua PM2 (khuyến nghị cho job dài)

`scripts/crawl_all_tinnhiem.sh` chạy lần lượt các danh mục (ưu tiên `fake` → `web` → …):

```bash
pm2 start backend/scripts/crawl_all_tinnhiem.sh \
    --name pkv-crawl-tinnhiem --no-autorestart --interpreter bash
pm2 logs pkv-crawl-tinnhiem          # theo dõi tiến độ + ETA
# Tinh chỉnh: TINNHIEM_WORKERS=6 TINNHIEM_DELAY=0.5
# Dừng / chạy lại: pm2 stop pkv-crawl-tinnhiem  (dữ liệu đã ghi vẫn giữ; --resume tiếp tục)
```

> Chạy nền bằng `nohup ... &` **không** bền trong môi trường này — dùng PM2.


---

## 6. Đồng bộ hằng tuần bằng Celery

Cơ chế chính thức để "mỗi tuần sync 1 lần, chỉ thêm cái mới".

### 6.1 Lệnh quản trị

```bash
cd backend
../.venv/bin/python manage.py sync_tinnhiem_directory                 # all, chỉ thêm mới, có ingest
../.venv/bin/python manage.py sync_tinnhiem_directory --category fake --workers 10
../.venv/bin/python manage.py sync_tinnhiem_directory --stop-after-known 20   # sync nhanh phần đầu
../.venv/bin/python manage.py sync_tinnhiem_directory --respect-robots         # tôn trọng robots.txt
../.venv/bin/python manage.py sync_tinnhiem_directory --no-ingest              # chỉ crawler, không ghi Domain
```

Lệnh: chạy crawler `--all --resume` (bỏ qua mục đã có) → `reindex` chỉ mục → (mặc định)
nạp danh sách lừa đảo vào model `Domain` qua feed `tinnhiem_fake`.

### 6.2 Celery task + beat (tự động hằng tuần)

* Task: `api.maintenance.tasks.sync_tinnhiem_directory`
* Beat: `sync-tinnhiem-directory-weekly` — `schedule = 7 ngày`, `kwargs = {category: all,
  stop_after_known: 0, ingest: True, respect_robots: False}`

```bash
# Chạy thủ công qua Celery
../.venv/bin/python manage.py shell -c \
  "from api.maintenance.tasks import sync_tinnhiem_directory as t; print(t.delay(category='fake').id)"
```

Biến môi trường (`.env`): `TINNHIEM_SYNC_WORKERS=8`, `TINNHIEM_SYNC_DELAY=0.3`,
`TINNHIEM_SYNC_RESPECT_ROBOTS=0` (mặc định bỏ qua robots — đặt `1` nếu muốn tôn trọng).

> Job **backfill ban đầu** (lấy toàn bộ) có thể chạy một lần qua PM2 như mục 5.1;
> các lần **hằng tuần** để Celery beat lo.

---

## 7. Tận dụng trong Scan & Chatbot

| Điểm nối | Trạng thái |
|---|---|
| `scan_views._get_trusted_domains()` | ✅ Gộp tên miền tín nhiệm tinnhiem vào danh sách tin cậy (chống giả mạo) |
| `scan_views` quét tên miền | ✅ Tra trực tiếp danh bạ (`tinnhiem_lookup_domain`): lừa đảo → điểm ≥ 90; tin nhiệm → giảm điểm + ghi chú. Trả thêm khối `result['tinnhiem']` |
| Threat feed `tinnhiem_fake` → `Domain` | ✅ Nạp danh sách lừa đảo; scan đọc bảng `Domain` (có cache) |
| Chatbot `scan_url` (`_assistant_scan_url`) | ✅ Trả khối `tinnhiem` (mạo danh/chứng nhận); lừa đảo → `is_scam`, risk ≥ 90 |
| Chatbot `query_threat_database` | ✅ Trả `tinnhiem_match` (trạng thái, chủ sở hữu, tổ chức bị mạo danh, mức chứng nhận) |
| `trust_guard.build_evidence` | ✅ Sinh `evidence[]` nguồn `tinnhiemmang` (CRITICAL nếu lừa đảo / benign nếu tín nhiệm), kèm link nguồn |
| Khớp **subdomain** | ✅ Tra theo suffix (`mail.shopee.vn` → `shopee.vn`), mỗi bậc 1 indexed lookup |
| Prompt AI (`ai_agent.SYSTEM_PROMPT`) | ✅ Quy tắc ưu tiên nguồn chính thống "Tín nhiệm mạng" khi kết luận |
| Threat feed `tinnhiem_fake` → `Domain` | ✅ Đã nạp **21.289** tên miền lừa đảo vào bảng `Domain` |

Tra cứu dùng chỉ mục SQLite nên không làm chậm luồng quét/chat.

---

## 8. Nối vào hệ thống ShieldCall

| Điểm nối | Mô tả |
|---|---|
| `api.utils.vn_sources.tinnhiem_trusted_domains()` | `{domain: đơn vị}` từ dataset `web` |
| `api.utils.vn_sources.tinnhiem_scam_domains()` | `{domain: tổ chức bị mạo danh}` từ dataset `fake` |
| `api.utils.vn_sources.tinnhiem_lookup_domain(domain, allow_network=False)` | Tra cứu cục bộ; `allow_network=True` mới gọi mạng |
| `api.core.views.scan_views._get_trusted_domains()` | Đã gộp tên miền tín nhiệm thu thập được vào danh sách tin cậy |
| `api.maintenance.threat_feeds` | Feed `tinnhiem_fake` đọc dataset `fake.jsonl` → ghi vào model `Domain` |
| `api.utils.trust_guard.SOURCE_CATALOG["tinnhiemmang"]` | Mô tả nguồn + giới hạn (hiển thị ở `/api/v1/trust/sources/`) |
| `VN_TINNHIEM_SOURCES` trong `vn_sources` | 4 URL danh bạ để trích dẫn |

### Đồng bộ danh sách lừa đảo vào `Domain`

```bash
cd backend
../.venv/bin/python manage.py sync_threat_intel --sources=tinnhiem_fake --limit=0
# hoặc qua Celery task sync_threat_intelligence(sources=["tinnhiem_fake"])
```

Feed gắn `source=tinnhiemmang.vn`, `threat=reported_scam_website`,
`tags=…impersonates:<tổ chức>`, và suy đoán `scam_type` theo tổ chức bị mạo danh
(ngân hàng, công an, thuế/dịch vụ công, giao hàng…).

### Tin tức / cảnh báo (Article) — parser & sửa lỗi định dạng

Nguồn tin:
* **Tín nhiệm mạng (NCSC)**: `noi-bat` (Tin tức) + `canh-bao-lua-dao` (Cảnh báo) — `source_type='tinnhiemmang'`.
* **VnExpress**: tag "Lừa đảo qua mạng" <https://vnexpress.net/tag/lua-dao-qua-mang-27298> — `source_type='press'`.
  Tự **phân trang** (`-p2`, `-p3`…): tag hiện có 4 trang ≈ **80 bài**; nội dung lấy đầy đủ
  đoạn văn + ảnh (đã đối chiếu: nguồn p=10/figure=1 → parse p=10/figure=1). Cover tải bằng
  **UA trình duyệt** vì CDN `vnecdn.net` chặn UA bot (403).

Parser `parse_news_listing`/`parse_news_detail` (tinnhiemmang) và
`parse_vnexpress_listing`/`parse_vnexpress_detail` (VnExpress) đã được sửa:

* Lấy **đủ bài** — thêm `.post-horizontal` (trước chỉ `.post-vertical` → sót ~2/3 số bài).
* **Sạch tiền tố site** `"Tín nhiệm mạng | …"` trong tiêu đề/mô tả.
* **Không dính chữ** (`họđang`, `Phú ThọNhóm`) — dùng `get_text(strip=False)`, chuẩn hoá `\xa0`
  và chèn khoảng trắng ở ranh giới tag inline.
* **Giữ ảnh/định dạng**: `<img>` (kể cả lazy `data-src`, `<picture><source>`),
  `<figure>`+`<figcaption>`, `<blockquote>`, `<strong>/<em>`, link; nội dung là **HTML**
  (`<p>/<h2>/<h3>/<ul>/<table>`) để render đúng qua MarkdownView.

```bash
cd backend
# Tín nhiệm mạng — ghi đè lại TOÀN BỘ bài hiện có (KHÔNG tạo bài mới)
../.venv/bin/python manage.py sync_tinnhiemmang --refresh-existing
../.venv/bin/python manage.py sync_tinnhiemmang --update-only --force --limit 20

# VnExpress — thu thập/ghi đè (tự duyệt hết các trang tag)
../.venv/bin/python manage.py sync_vnexpress --limit 100
../.venv/bin/python manage.py sync_vnexpress --max-pages 4 --limit 100
../.venv/bin/python manage.py sync_vnexpress --refresh-existing
```

Celery beat: `sync-vnexpress-news-12h` (12 giờ/lần) → task
`api.maintenance.tasks.sync_vnexpress_news`.

---

## 9. Kiểm thử

```bash
cd backend
PYTHONPATH=/tmp/opencode ../.venv/bin/python manage.py test api.core.tests.test_tinnhiemmang \
  --settings=settings_verify --noinput
# 21 test: phân tích listing/detail, robots (kể cả wildcard /*?page=), dataset, tích hợp feed
```

Test dùng HTML fixture nhỏ mô phỏng đúng cấu trúc thật → **chạy offline**, không gọi mạng.

---

## 10. Giới hạn & liêm chính (đọc trước khi trích dẫn)

* **Vắng mặt ≠ an toàn.** Chỉ thực thể đã đăng ký/chứng nhận hoặc đã bị ghi nhận mới
  có trong danh bạ. Mọi kết luận dựa trên nguồn này phải kèm câu miễn trừ chuẩn.
* **Dữ liệu cập nhật theo đợt** — kết quả crawl có thể cũ; luôn ghi `url` nguồn và
  đối chiếu trang gốc khi công bố.
* **Trang chi tiết mục lừa đảo** trỏ tới tổ chức bị mạo danh (không phải site lừa đảo).
* **Chỉ lấy đúng phạm vi robots.txt cho phép** (trang 1 + `filterObj`); phân trang diện
  rộng cần xin phép. Bản seed trong repo = trang 1 mỗi danh mục; muốn lấy hết thì chạy
  `--all --ignore-robots` (chính là lựa chọn *có chủ đích* khi đã xác nhận được phép).
* Quy mô **đã thu thập** (2026-10-15, bỏ qua robots): website tin cậy **5.874**,
  tổ chức **7.075**, ứng dụng **68**, hệ thống **5**, thiết bị **0** (trang rỗng),
  **website lừa đảo 21.310**. Tổng ~34.300 bản ghi. Tải song song 10 luồng mất ~5 phút
  cho `fake`; dữ liệu ghi tăng dần nên dừng/chạy lại không mất.
* `thiet-bi-tin-nhiem` hiện không trả về mục nào (trang rỗng/dựng bằng JS) → `iot=0`.

---

## 11. Tham chiếu

* Trang chủ: <https://tinnhiemmang.vn>
* Website tín nhiệm: <https://tinnhiemmang.vn/website-tin-nhiem>
* Website lừa đảo: <https://tinnhiemmang.vn/website-lua-dao>
* `robots.txt`: <https://tinnhiemmang.vn/robots.txt>
