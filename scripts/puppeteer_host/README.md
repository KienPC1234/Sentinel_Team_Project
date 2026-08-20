# BypassBot (Remote Puppeteer Session + Persistent Login)

API server điều khiển Puppeteer từ xa, có lưu profile trình duyệt để bạn đăng nhập trước rồi tái sử dụng cho automation.

## 1) Chạy dự án

```bash
npm install
npm start
```

Mặc định server chạy tại `http://127.0.0.1:3010`.

## 2) Biến môi trường

- `PUPPETEER_HOST_PORT` (default: `3010`): cổng API Express.
- `PUPPETEER_PROFILE_DIR` (default: `./puppeteer_profile`): thư mục lưu profile/cookies.
- `PUPPETEER_DEBUG_PORT` (default: `9222`): cổng Chrome DevTools Protocol (CDP).
- `PUPPETEER_DEBUG_HOST` (default: `0.0.0.0`): host cho CDP remote.
- `PUPPETEER_IDLE_TAB_TIMEOUT_MS` (default: `900000`): tab không hoạt động quá thời gian này sẽ tự đóng.
- `PUPPETEER_TAB_CLEANUP_INTERVAL_MS` (default: `60000`): chu kỳ quét tab idle.

## 3) Luồng đăng nhập trước (remote từ xa)

### Bước A - Tạo phiên login

```http
POST /session/login
Content-Type: application/json

{
  "url": "https://example.com"
}
```

Response trả về:
- `ws_endpoint`: endpoint WebSocket để remote Puppeteer.
- `profile_dir`: thư mục profile đang dùng.
- `active_url`: tab hiện tại để bạn đăng nhập thủ công.

### Bước B - Lấy trạng thái phiên

```http
GET /session/status
```

Response có:
- `active_url`
- `ws_endpoint`
- `remote_debug_host`
- `remote_debug_port`

## 4) Endpoint chính

- `GET /health`
- `POST /render` body: `{ "url": "https://...", "timeoutMs": 20000 }`
- `POST /open` body: `{ "url": "https://..." }`
- `POST /click` body: `{ "selector": "..." }`
- `POST /type` body: `{ "selector": "...", "text": "..." }`
- `GET /cookies`

## 5) Kết nối Puppeteer từ máy khác

```js
const puppeteer = require('puppeteer-core');

(async () => {
  const browser = await puppeteer.connect({
    browserWSEndpoint: 'ws://<server-ip>:9222/devtools/browser/<id>'
  });

  const pages = await browser.pages();
  const page = pages[0] || await browser.newPage();
  await page.bringToFront();
})();
```

> Bạn lấy `<id>` từ `ws_endpoint` trả về bởi `/session/status` hoặc `/session/login`.

## 6) “Nhìn như người thật” (đã bật)

Hiện tại code đã cấu hình:
- `puppeteer-extra-plugin-stealth`
- User-Agent ổn định theo phiên (Windows + Chrome, không đổi lung tung mỗi tab)
- `accept-language` giống trình duyệt thật (`vi-VN,vi,...`)
- Viewport desktop chuẩn (`1366x768`)
- Lưu profile lâu dài (`userDataDir`) để giữ đăng nhập/cookie

## 7) Kiểm tra đồng thời (đã verify)

Đã test thực tế: trong lúc `/render` đang chạy (URL delay), vẫn gọi được:
- `GET /session/status`
- `POST /open`

=> User vẫn có thể vào/điều khiển browser khi hệ thống đang xử lý `/render`.

## 8) Cơ chế tự đóng tab

- Tab tạo từ `/render` sẽ tự đóng ngay sau khi lấy xong dữ liệu (kể cả có lỗi giữa chừng).
- Các tab không hoạt động quá lâu sẽ bị tự đóng theo `PUPPETEER_IDLE_TAB_TIMEOUT_MS`.
- Tab phiên chính (`active tab` cho remote login) được giữ lại, không bị auto-close bởi cơ chế idle.

## 9) Khuyến nghị bảo mật

Nếu mở remote qua mạng ngoài, nên thêm lớp bảo vệ:
- API key / JWT cho endpoint `/open`, `/click`, `/type`, `/session/*`
- Firewall chỉ cho phép IP tin cậy
- Reverse proxy HTTPS (Nginx/Caddy/Cloudflare Tunnel)
