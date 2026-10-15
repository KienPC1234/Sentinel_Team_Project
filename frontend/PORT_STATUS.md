# Trạng thái port HTML → Next.js (ShieldCall VN)

Đối chiếu `PKV/templates/*.html` với `frontend/app` + `frontend/src/views`.
Cập nhật: đã hoàn tất port 1-1 nhóm Admin + các trang còn lệch, error pages, socialaccount/verification native.

## 1. Port native (user-facing page)

| Template gốc | Route Next | View |
|---|---|---|
| Home/home.html | `/`, `/home/` | `views/Home.tsx` |
| Dashboard/dashboard.html | `/dashboard/` | `views/Dashboard.tsx` |
| Emergency/emergency.html | `/emergency/` | `views/Emergency.tsx` |
| Legal/disclaimer.html | `/legal/disclaimer/` | `views/Disclaimer.tsx` |
| Helps/helps.html | `/helps/`, `/helps/[slug]/` | `views/Helps.tsx` |
| MCP/mcp_guide.html | `/mcp/` | `views/McpGuide.tsx` |
| Scan/scan_*.html (10) | `/scan/*` | `views/Scan/*.tsx` |
| Report/report.html | `/report/` | `views/Report/Report.tsx` |
| Report/report_list.html | `/reports/`, `/report/lookup/` | `views/Report/ReportList.tsx` |
| Report/my_reports.html | `/my-reports/` | `views/Report/MyReports.tsx` |
| ScamRadar/scam_radar.html | `/scam-radar/` | `views/Radar/ScamRadar.tsx` |
| ScamRadar/list.html | `/scam-radar/list/[kind]/` | `views/Radar/RadarList.tsx` |
| LearnHub/learn_hub.html | `/learn/` | `views/Learn/LearnHub.tsx` |
| Learning/article_detail.html | `/learn/[slug]/` | `views/Learn/ArticleDetail.tsx` |
| Learning/lesson_detail.html | `/learn/lesson/[slug]/` | `views/Learn/LessonDetail.tsx` |
| AI/scam_iq_exam.html | `/scam-iq-exam/` | `views/AI/ScamIQ.tsx` |
| AI/assistant.html | `/ai-assistant/` | `views/AI/Assistant.tsx` |
| Auth/login.html | `/login/` | `views/Auth/Login.tsx` |
| Auth/register.html | `/register/` | `views/Auth/Register.tsx` |
| Auth/profile.html | `/profile/` | `views/Auth/Profile.tsx` |
| Auth/public_profile.html | `/profile/[...slug]/` | `views/Auth/PublicProfile.tsx` |
| Auth/inbox.html | `/profile/inbox/` | `views/Auth/Inbox.tsx` |
| Auth/change_password.html | `/change-password/` | `views/Auth/ChangePassword.tsx` |
| Forum/forum.html | `/forum/` | `views/Forum/Forum.tsx` |
| Forum/forum_detail.html | `/forum/[id]/` | `views/Forum/ForumDetail.tsx` |
| Forum/forum_create.html | `/forum/create/` | `views/Forum/ForumCreate.tsx` |
| Forum/forum_edit.html | `/forum/[id]/edit/` | `views/Forum/ForumEdit.tsx` |
| Forum/announcements.html | `/forum/announcements/` | `views/Forum/Announcements.tsx` |
| Forum/tickets.html | `/profile/tickets/` | `views/Forum/Tickets.tsx` |
| Admin/* (15 templates) | `/admin-cp/*`, `/admin-panel/` | `views/Admin/*.tsx` |
| account/password_reset.html | `/accounts/password/reset/` | `views/Auth/PasswordReset.tsx` |
| account/password_reset_from_key.html | `/accounts/password/reset/confirm/`, `.../key/[...slug]/` | `views/Auth/PasswordResetConfirm.tsx` |
| socialaccount/login.html, signup.html | `/accounts/<provider>/login/` | Direct Django OAuth redirect (xem §4) |
| account/verification_sent.html | `/accounts/confirm-email/` | `views/Auth/VerificationSent.tsx` (xem §4) |
| account/email_confirm.html | `/accounts/confirm-email/<key>/` | `views/Auth/ConfirmationEmail.tsx` (xem §4) |
| account/email_verification_error.html | `/email-confirm/error/` | `views/Auth/EmailVerificationError.tsx` (xem §4) |

## 2. Partial / layout / CSS

| Template / asset | Đích |
|---|---|
| base.html | `app/layout.tsx` + `components/Layout.tsx` |
| Scan/_osint_section.html, Scan/_scan_guide.html | `components/ScanWidgets.tsx` |
| ai_chat/chat_widget_inline.html | `components/ChatWidget.tsx` |
| PKV/static/css/liquid-glass.css | `app/liquid-glass.css` (import sau `globals.css` → toàn bộ class gốc render đúng) |
| feedback (base.html showToast/scConfirm...) | `lib/ui/feedback.ts` |

## 3. Error pages

| Template | Đích |
|---|---|
| Errors/400,403,404,500,502,503,504.html | `views/ErrorPage.tsx` (cấu hình theo mã) |
| Errors/404.html | `app/not-found.tsx` |
| Errors/500.html | `app/error.tsx`, `app/global-error.tsx` |

## 4. Allauth/Socialaccount — Luồng trực tiếp

- `/accounts/google/login/?process=login` được cấu hình với `SOCIALACCOUNT_LOGIN_ON_GET = True` trong Django backend.
- Khi người dùng bấm nút Google Sign-In, backend phản hồi HTTP 302 chuyển hướng trực tiếp sang Google OAuth consent screen, loại bỏ hoàn toàn trang xác nhận trung gian.
- Callback `/accounts/google/login/callback/` xử lý hoàn tất đăng nhập và redirect về `/profile/` hoặc param `next`.
- Đã bật `SOCIALACCOUNT_EMAIL_AUTHENTICATION` và `SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT` để tự động liên kết tài khoản Google khớp email đã đăng ký.

## 5. Ngoài phạm vi frontend (backend)

| Template | Lý do |
|---|---|
| Email/*.html, account/email/*.html | Email do backend (Celery) gửi, không phải trang frontend. |
| account/password_reset_done.html, password_reset_from_key_done.html | Đã thể hiện inline trong flow native. |

## Kết luận

- **Route coverage: 100%** — mọi URL trang trong `PKV/urls.py` có route Next tương ứng.
- **Fidelity: 17 trang từng lệch đã port lại 1-1** (Admin 9 + Report/ReportList/ForumDetail/ForumCreate/LessonDetail/ScamIQ/RadarList/McpGuide).
- **Error pages + socialaccount + verification:** đã port native (xem §3, §4).

## 6. Bổ sung backend API + UI kit (đợt mới)

### UI component dùng chung (`src/components/ui.tsx`)
- `LiquidSelect` — dropdown tuỳ biến (port Alpine `liquidSelect()`, dùng ở 6 template).
- `Tabs` / `TabDef` — thanh tab.
- `AdminPageHeader` — header admin (nút quay lại + icon + tiêu đề).
- `Pill` — nút lọc.
- `Badge` + `BadgeTone` — nhãn trạng thái/vai trò.
- `InlineSpinner` — spinner nhỏ.
- (đã có từ trước: `GlassCard`, `RiskBadge`, `PrimaryButton`, `GhostButton`, `SectionHead`, `StatCard`, `Spinner`, `EmptyState`, `MarkdownView`).
- Helper feedback: `showToast` / `scAlert` / `scConfirm` / `scPrompt` ở `lib/ui/feedback.ts`.

### Backend API mới (`api/core/`)
| Endpoint | Phục vụ |
|---|---|
| `GET /admin/stats/` (mở rộng) | thêm `total_lessons`, `total_articles`, `total_article_comments`, `active_today`, `total_posts`, `total_comments`, `pending_forum_reports`, `forum{}`, `charts{labels,scans,reports}` |
| `GET /admin/forum/reports/` | tab Báo cáo bài viết |
| `POST /admin/forum/reports/<id>/action/` | duyệt/từ chối/phân tích (heuristic) |
| `GET /admin/forum/comment-reports/` | tab Báo cáo bình luận |
| `POST /admin/forum/comment-reports/<id>/action/` | xử lý báo cáo bình luận |
| `GET /admin/forum/bans/` | tab Cấm |
| `POST /admin/forum/ban/` | cấm / gỡ cấm |
| `POST /admin/forum/moderator/` | bổ nhiệm / thu hồi kiểm duyệt viên |
| `GET /learn/lessons/<slug>/` | chi tiết bài học + quiz + scenario cho LessonDetail |
| `PATCH /forum/posts/<id>/` (mở rộng) | hỗ trợ `is_pinned` cho staff |
| `GET /trends/hot/` (mở rộng) | thêm `id`, `scam_type_display`, `severity`, `source`, `reporter_name`, `created_at` cho RadarList |
| `GET /reports/stats/` | stats bar công khai trang `/reports/` |
| `GET /scan/lookup/` (mở rộng) | thêm `severity`, `scam_type_display`, `reporter_name`, `description`, `scammer_*`, `custom_fields`, `evidence_url` cho card + modal ReportList |

Đã wire frontend: `LessonDetail.tsx` (tải quiz/scenario thật), `Admin/ForumMgmt.tsx` (reports/comment-reports/bans + cấm/gỡ cấm/duyệt), `Admin/Dashboard.tsx` + `Admin/Panel.tsx` (stats mới), `Radar/RadarList.tsx` (cột người báo cáo/thời gian/mức độ/modal).

## 7. Realtime (WebSocket) / SEO / Assets / deps

### WebSocket
| Kênh | Nơi dùng | Trạng thái |
|---|---|---|
| `/ws/scan/<id>/` | Scan (Phone/Message/Website/Bank/Email/Qr/File/Audio/Status) qua `ScanWidgets.useScanTracker` | ✅ |
| `/ws/forum/` | `Forum.tsx`, `ForumDetail.tsx` | ✅ |
| `/ws/task/<id>/` | `Admin/MagicCreate.tsx`, `Admin/MagicArticle.tsx`, `AI/ScamIQ.tsx` | ✅ (ScamIQ bổ sung) |
| `/ws/notifications/` | `components/NotificationBell.tsx` (chuông navbar) | ✅ (bổ sung) |
| `/ws/rag/` | `Admin/RagMgmt.tsx` | ✅ (bổ sung) |
| SSE `/api/v1/chat/stream/` | `views/AI/Assistant.tsx`, `components/ChatWidget.tsx` (qua `lib/chat/stream.ts`) | ✅ |

`wsBase()` trong `ScanWidgets.tsx` dựng URL WS qua host hiện tại (proxy `/ws/*` → Django trong `next.config.ts`).

### SEO
- `app/layout.tsx`: `metadataBase`, title template, description, keywords, canonical, OpenGraph, Twitter card, icons, manifest, robots, JSON-LD (Organization + WebSite + SearchAction), `viewport` themeColor.
- `app/robots.ts` (chặn `/admin-cp/`, `/api/`, `/accounts/`, `/dashboard/`…), `app/sitemap.ts` (22 URL công khai).
- `src/lib/seo.ts`: `pageMeta()` + `fetchPublic()`/`excerpt()`.
- Metadata tĩnh cho các route chính; `generateMetadata()` động (fetch nội dung thật) cho `/learn/[slug]/` và `/learn/lesson/[slug]/`.

### Assets
- `frontend/public/`: favicon.ico, favicon-96x96.png, favicon.svg, apple-touch-icon.png, icon.png (OG 512), web-app-manifest-192/512.png, `site.webmanifest` + `manifest.json` (đường dẫn gốc `/`), `logo.png`, `sw.js`, `pwa.js`.
- Bỏ rewrite `/manifest.json` + `/site.webmanifest` để Next tự phục vụ.

### Phụ thuộc (deps thay CDN)
- Font: **`next/font/google` (Inter)** self-host — đã bỏ `<link>` Google Fonts CDN.
- AOS: npm `aos` (+ `aos/dist/aos.css`). bootstrap-icons: npm. sweetalert2, chart.js + react-chartjs-2, ckeditor5 + @ckeditor/ckeditor5-react, marked: npm.
- Còn lại là dịch vụ bắt buộc bên thứ ba (không thay được): Cloudflare Turnstile (anti-spam), Google Translate (widget đa ngôn ngữ).

### Chat (AI Assistant + ChatWidget)
- `views/AI/Assistant.tsx` (~1166 dòng) và `components/ChatWidget.tsx` (~364 dòng) đã rà parity với `PKV/static/js/chat/assistant/*.js` + `widget.js`: kéo-thả ảnh, preview OCR + modal phóng to, drag session vào folder + tạo/đổi tên/xóa folder, Swal (`showToast`/`scConfirm`/`scPrompt`), tool card + render kết quả, thinking collapse, accordion nguồn tham khảo, bookmark/sửa/xóa tin nhắn, safe-mode/FairSpace, search highlight, đóng widget khi click ngoài.
- CSS `.msg-*`, `.tool-card*`, `.search-sources-accordion`, `.safetalk-*`, `body.safe-mode`… (trước đây thiếu) đã port vào `app/globals.css`.
- `lib/useTaskSocket.ts` — hook WebSocket `/ws/task/<id>/` dùng chung (ScamIQ; sẵn sàng cho MagicCreate/MagicArticle).

## 8. Audit Auth (login/register/MFA/profile)

Đã đối chiếu frontend ↔ backend và bản HTML gốc; phát hiện + sửa:

1. **`/auth/me/` trả `{user, stats}`** nhưng `authApi.me()` khai báo `Me` phẳng → `AuthContext.user` bị sai (navbar/profile đọc `user.username` = undefined).
   - Sửa: thêm `MeResponse { user, stats }`; `authApi.me()` trả `MeResponse`; `AuthContext` dùng `.user`; `ConfirmationEmail` đọc `me.user`.
2. **`MeView` thiếu `POST/PUT`** (chỉ có GET/PATCH) → upload avatar ở `Profile` (`api.upload` = POST) bị **405**.
   - Sửa: thêm `post`/`put` alias gọi `patch`. Đã test: POST/PUT `/auth/me/` → 200.

Đã xác nhận khớp (không mismatch):
- Login (`email/password/cf-turnstile-response`), MFA `{token, method}` (totp/email/recovery), session `mfa_user_id` đi qua BFF (cookie được forward).
- Register (request-otp + otp), email-change `{password,new_email}` → `{new_email,otp}`, delete-account `{password, confirmation_text}`.
- MFA status/setup-totp/setup-email/deactivate/recovery `{password,token,method}`.
- Password reset native (`/auth/password/reset/`, `/confirm/`).
- Login/Register template parity: Google OAuth, Turnstile, strength meter, 2 lớp, quên mật khẩu — đủ như bản gốc.
- `PublicProfile` `{user, stats}` khớp.

Lưu ý: Turnstile secret là key Cloudflare thật nên login cần token trình duyệt (đúng như bản gốc); không test được bằng curl thuần.


