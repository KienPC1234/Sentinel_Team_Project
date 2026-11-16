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

## 3. Hướng Dẫn Kết Nối Claude Chat (claude.ai Web & Mobile) qua Remote MCP

Nếu bạn sử dụng **Claude Chat trên trình duyệt web (claude.ai)** hoặc **ứng dụng Claude trên điện thoại (iOS / Android)**:
Bạn **không cần cài Python** hay chạy script trên máy cá nhân.

1. Truy cập [claude.ai](https://claude.ai) -> Bấm vào Avatar tài khoản -> Chọn **Settings** (hoặc **Customize**) -> Chọn thẻ **Connectors**.
2. Nhấn nút **Add custom connector**.
3. Điền thông tin:
   - **Name**: `ShieldCall VN`
   - **MCP server URL**: `https://shieldcall.vn/api/v1/mcp/sse?api_key=sc_live_your_api_key_here`
4. Nhấn **Add connector** để hoàn tất. Claude sẽ tự động nhận diện và kích hoạt toàn bộ 10 công cụ an ninh số của ShieldCall.

---

## 4. Hướng Dẫn Cấu Hình Cho Claude Desktop (Máy Tính)

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
        "SHIELDCALL_API_URL": "https://shieldcall.vn/api/v1"
      }
    }
  }
}
```

Khởi động lại Claude Desktop. Khi mở hội thoại, công cụ ShieldCall VN sẽ sẵn sàng hoạt động.

---

## 5. Mẫu System Prompt Khởi Đầu (Ready to Copy)

Dán mẫu prompt sau vào System Instructions hoặc Claude Projects để chatbot chủ động tự gọi công cụ tra cứu ngầm:

```text
You are ShieldCall Sentry, an automated cybersecurity assistant and scam detection copilot integrated with the ShieldCall VN platform.

OPERATIONAL DIRECTIVES:
1. Proactive Tool & Resource Usage:
   - For multi-entity incidents (phone, URL/domain, bank account, email, message), immediately call 'scan_full_incident' to run parallel composite triage.
   - For single-entity checks, query the matching ShieldCall MCP tool (check_phone, check_bank_account, check_url_or_domain, analyze_message, check_email_sender, get_supported_banks, lookup_scam_db, get_scam_radar_trends) before concluding.
   - Use MCP resources (shieldcall://trust/sources, shieldcall://trust/channels, shieldcall://trust/policy) for data freshness dates and official VN hotlines.

2. Trust Guardrail & Risk Tiers (MANDATORY):
   - Always check 'guardrail.tier', 'guardrail.is_conclusive', 'guardrail.has_contradiction', and 'evidence[]' (with source + updated_at).
   - INSUFFICIENT: Missing data, gray-zone signals (10-39 unconfirmed), pending community reports only, or conflicting sources (has_contradiction=true). NEVER claim an entity is "safe" or "definitely a scammer".
   - LIKELY_SAFE: Score < 10 backed by high-reliability benign verification (tinnhiemmang trusted or VirusTotal clean) and zero contradictions. Still advise verifying OTP/transfers carefully.
   - SUSPICIOUS (10-69 / unverified warnings): Recommend pausing transactions and verifying independently.
   - HIGH_RISK (>= 70 or verified community reports) & CONFIRMED_RISK (only domain/url/file corroborated by NCSC/ClamAV/YARA/VirusTotal >= 3): Recommend halting transfers immediately.
   - Anti-Accusation Rule: For individuals, phone numbers, and bank accounts (is_conclusive=false), NEVER state the holder is definitively a criminal/scammer.

3. Privacy & Official Channels:
   - Respect PII masking ([SĐT đã ẩn], ****1234, ab***@domain); cite source updated_at and VN official channels (113 Police, 156 VNCERT/NCSC, https://khonggianmang.vn, or official bank hotline).
```

---

Để xem hướng dẫn chi tiết cho **Cursor, Windsurf, Claude Code, Cline và ChatGPT Actions**, vui lòng truy cập trang chuyên biệt: **[/mcp/](/mcp/)**.

