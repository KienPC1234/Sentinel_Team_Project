# Ảnh minh hoạ kho tri thức

Đặt ảnh tại đây, đặt tên theo **slug của bài viết** (xem `seed_vn_knowledge.py`), ví dụ:
- `gia-danh-cong-an-vien-kiem-sat-co-quan-chuc-nang-de-lua-dao.jpg`
- `canh-bao-sms-brandname-gia-link-la-phishing.png`

Định dạng hỗ trợ: jpg/jpeg/png/webp.
Chạy lại `python manage.py seed_vn_knowledge` để gán ảnh làm `cover_image`
(tự động lưu lên object storage/S3 khi `USE_S3_MEDIA=true`).
