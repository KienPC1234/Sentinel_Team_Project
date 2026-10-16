# Puppeteer Host (TypeScript Edition)

Dịch vụ Headless Browser hiện đại hóa bằng TypeScript cho dự án Sentinel Team Project, hỗ trợ scan website, trích xuất DOM, phát hiện Captcha và phòng vệ SSRF đa lớp.

## 1. Cấu trúc thư mục

```text
puppeteer_host/
├── package.json
├── tsconfig.json
├── server.js               # Entrypoint bọc tương thích ngược
├── src/
│   ├── index.ts            # Khởi tạo Express, HTTP server, graceful shutdown
│   ├── config.ts           # Schema validation môi trường bằng Zod
│   ├── logger.ts           # Structured logging có timestamp ISO
│   ├── browser/
│   │   ├── manager.ts      # Quản lý vòng đời Chromium, stealth plugin, tái chế bộ nhớ
│   │   ├── controller.ts   # Điều phối tab, chặn tài nguyên nặng, humanized setup
│   │   └── security.ts     # Phòng vệ SSRF (IPv4/IPv6 private ranges, DNS resolution check)
│   ├── routes/
│   │   └── api.ts          # Định tuyến REST API với Zod request validation
│   └── types/
│       └── declarations.d.ts
└── dist/                   # File JavaScript sau khi compile (tsc)
```

## 2. Khởi chạy và Build

```bash
cd puppeteer_host

# Cài đặt thư viện
npm install

# Kiểm tra kiểu dữ liệu
npm run typecheck

# Build mã nguồn TypeScript
npm run build

# Chạy bản production
npm start

# Chạy chế độ development (hot reload với tsx)
npm run dev
```

## 3. Biến môi trường

| Biến | Mặc định | Mô tả |
| :--- | :--- | :--- |
| `PUPPETEER_HOST_PORT` | `3010` | Cổng HTTP lắng nghe |
| `PUPPETEER_HOST_BIND` | `127.0.0.1` | Địa chỉ IP bind socket |
| `PUPPETEER_PROFILE_DIR` | `./puppeteer_profile` | Thư mục lưu cache và cookie phiên làm việc |
| `PUPPETEER_DEBUG_PORT` | `9222` | Cổng Chrome DevTools Protocol (CDP) |
| `PUPPETEER_DEBUG_HOST` | `0.0.0.0` | Địa chỉ bind cho CDP remote debugging |
| `MAX_RENDERS_BEFORE_RECYCLE` | `50` | Số lượng render tối đa trước khi tự động tái chế process để chống rò rỉ RAM |
| `PUPPETEER_IDLE_TAB_TIMEOUT_MS` | `600000` | Thời gian tab nhàn rỗi (ms) trước khi tự động đóng |
| `PUPPETEER_TAB_CLEANUP_INTERVAL_MS` | `60000` | Chu kỳ quét dọn tab nhàn rỗi (ms) |

## 4. API Endpoints

### `GET /health`
Kiểm tra trạng thái sẵn sàng của trình duyệt và phiên bản dịch vụ.
```json
{
  "ok": true,
  "status": "healthy",
  "version": "2.0.0-ts"
}
```

### `POST /render`
Render URL và trích xuất nội dung văn bản text và mã HTML, phát hiện Captcha:
```json
// Request Body
{
  "url": "https://example.com",
  "timeoutMs": 20000
}

// Response
{
  "ok": true,
  "title": "Example Domain",
  "captcha_detected": false,
  "content": "Nội dung văn bản..."
}
```

### `POST /open`
Mở URL trên tab điều khiển chính và trả về URL đích sau khi redirect.

### `POST /click`
Mô phỏng click vào selector DOM được chỉ định.

### `POST /type`
Mô phỏng gõ phím với độ trễ tự nhiên vào trường input.

### `GET /cookies`
Lấy toàn bộ cookies của tab điều khiển hiện tại.

### `POST /session/login`
Chuẩn bị phiên tương tác thủ công trên browser để vượt qua các bước xác thực phức tạp.

### `GET /session/status`
Xem trạng thái URL tab hiện tại và thông tin cổng remote debug CDP.

## 5. Đặc tính kỹ thuật mới

* **TypeScript Strict Mode**: 100% type-safe, loại bỏ lỗi runtime tiềm ẩn.
* **Zod Request Validation**: Xác thực schema nghiêm ngặt cho toàn bộ endpoint đầu vào.
* **SSRF Shield Đa lớp**: Ngăn chặn truy cập tới dải mạng riêng tư IPv4, IPv6, loopback, carrier-grade NAT, và metadata cloud 169.254.169.254 kết hợp phân giải DNS thời gian thực.
* **Tối ưu hóa Băng thông**: Tự động chặn các tài nguyên không cần thiết (media, font, websocket) trong quá trình render nhằm tiết kiệm RAM và CPU.
* **Auto Memory Recycling**: Tự động giải phóng Chromium sau mỗi chu kỳ render mà không làm gián đoạn các kết nối khác.
