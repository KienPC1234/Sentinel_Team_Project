# Tích hợp MCP Server & Kết nối Chatbot

Model Context Protocol (MCP) là giao thức mở cho phép mọi mô hình ngôn ngữ lớn (LLM) và chatbot thương mại như Claude Desktop, Cursor, Windsurf, Claude Code, Cline, ChatGPT kết nối trực tiếp vào cơ sở dữ liệu và các công cụ phòng chống lừa đảo của ShieldCall VN.

---

## 1. Danh sách Công cụ Hỗ trợ (MCP Tools)

| Tên Công Cụ | Tham Số Đầu Vào | Mục Đích Sử Dụng |
| :--- | :--- | :--- |
| **`check_phone`** | `phone_number: str` | Quét số điện thoại nghi vấn, kiểm tra blacklist, nhà mạng, dấu hiệu sim rác hoặc VoIP. |
| **`check_bank_account`** | `bank_name: str`, `account_number: str` | Tra cứu tài khoản ngân hàng trong danh sách đen lừa đảo cộng đồng (tự động chuẩn hóa tên ngân hàng). |
| **`check_url_or_domain`** | `url: str` | Phân tích tên miền giả mạo (lookalike domain), chứng chỉ SSL, DNS, trang web phishing. |
| **`analyze_message`** | `message_content: str` | Đánh giá kịch bản tin nhắn mạo danh công an, ngân hàng, lừa nạp tiền OTP. |
| **`check_email_sender`** | `sender_email: str`, `email_content: str`, `email_subject: str` | Kiểm tra SPF, DKIM, DMARC tên miền gửi thư và phát hiện nội dung email lừa đảo. |
| **`get_supported_banks`** | *(Không tham số)* | Lấy danh mục ngân hàng chuẩn Việt Nam kèm mã BIN để thẩm định tài khoản thụ hưởng. |
| **`scan_full_incident`** | `message_content: str`, `phone_number: str`, `bank_name: str`, `account_number: str`, `url: str`, `sender_email: str` | Giám định tổng thể đa thực thể vụ việc nghi vấn lừa đảo trong một lần gọi duy nhất. |
| **`lookup_scam_db`** | `query: str`, `entity_type: str` | Tra cứu thực thể bất kỳ trong kho dữ liệu cộng đồng ShieldCall VN. |
| **`get_scam_radar_trends`** | *(Không tham số)* | Lấy số liệu radar và danh sách các thủ đoạn lừa đảo phổ biến nhất hiện nay. |
| **`report_scam`** | `target_type`, `target_value`, `scam_type`, `description` | Gửi báo cáo đối tượng lừa đảo mới lên ban quản trị. |

---

## 2. Quản lý API Key & Hạn Mức Sử Dụng

Để kết nối với MCP Server, bạn cần có API Key:
1. Đăng nhập tài khoản ShieldCall VN và truy cập mục **Bảng điều khiển (Dashboard) > Tab API & MCP**.
2. Nhấn nút **Tạo API Key Mới**, đặt tên định danh (ví dụ: `Claude Desktop`).
3. Sao chép và lưu trữ mã bí mật `sc_live_...` ngay lập tức (mã chỉ hiển thị một lần duy nhất).

| Gói Dịch Vụ | Giới Hạn Tốc Độ (RPM) | Hạn Mức Ngày (Daily Quota) | Hạn Mức Tháng |
| :--- | :--- | :--- | :--- |
| **Cơ bản (Free)** | 60 requests/phút | 500 requests/ngày | 15.000 requests/tháng |
| **Lập trình viên (Developer)** | 120 requests/phút | 2.000 requests/ngày | 50.000 requests/tháng |
| **Unlimited (Admin/Internal)** | 1.000 requests/phút | Không giới hạn | Không giới hạn |

---

## 3. Hướng Dẫn Cấu Hình Nhanh Cho Claude Desktop

Mở file cấu hình MCP của Claude Desktop:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

Thêm cấu hình sau:

```json
{
  "mcpServers": {
    "shieldcall": {
      "command": "python",
      "args": ["/đường_dẫn_tới/Sentinel_Team_Project/scripts/shieldcall_mcp.py"],
      "env": {
        "SHIELDCALL_API_KEY": "sc_live_your_api_key_here",
        "SHIELDCALL_API_URL": "http://127.0.0.1:8001/api/v1"
      }
    }
  }
}
```

Khởi động lại Claude Desktop. Khi mở hội thoại, công cụ ShieldCall VN sẽ sẵn sàng hoạt động.

---

## 4. Mẫu System Prompt Khởi Đầu (Ready to Copy)

Dán mẫu prompt sau vào System Instructions hoặc Claude Projects để chatbot chủ động tự gọi công cụ tra cứu ngầm:

```text
Bạn là ShieldCall Sentry - Trợ lý Giám sát An toàn Số và Phòng chống Lừa đảo hàng đầu Việt Nam.
NGUYÊN TẮC HOẠT ĐỘNG:
1. Khi vụ việc liên quan nhiều thực thể (vừa có SĐT, link và STK), bạn PHẢI tự động gọi ngay công cụ scan_full_incident để giám định tổng thể.
2. Khi có từng thực thể riêng lẻ, tự động gọi công cụ ShieldCall MCP tương ứng (check_phone, check_bank_account, check_url_or_domain, analyze_message, check_email_sender, get_supported_banks) để thẩm định trước khi đưa ra nhận định.
3. Thang điểm rủi ro:
   - 0-19: An toàn (SAFE)
   - 20-49: Thận trọng (LOW)
   - 50-79: Cảnh báo rủi ro cao (MEDIUM)
   - 80-100: Nguy hiểm, lừa đảo chắc chắn (CRITICAL)
4. Luôn đưa ra lời khuyên hành động dứt khoát: TUYỆT ĐỐI KHÔNG chuyển tiền, KHÔNG tải file APK lạ, KHÔNG nhập OTP vào bất kỳ website nào.
```

---

Để xem hướng dẫn chi tiết cho **Cursor, Windsurf, Claude Code, Cline và ChatGPT Actions**, vui lòng truy cập trang chuyên biệt: **[/mcp/](/mcp/)**.

