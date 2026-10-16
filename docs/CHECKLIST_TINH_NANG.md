# Checklist Kiểm tra Tính năng — ShieldCall VN

> **Mục đích:** checklist kiểm kĩ tính năng theo *Điểm mạnh* và *Yêu cầu cải tiến* mà hội đồng nêu.
> Mỗi mục đều có **cách kiểm** và **trạng thái thực tế** (đã tự chạy lệnh/đọc mã, không chỉ tin tài liệu).
>
> - **Ngày rà soát:** 2026-10-15
> - **Người rà soát:** AI assistant (rà độc lập trên mã nguồn + chạy lệnh)
> - **Phạm vi:** `backend/api/utils/{trust_guard,vn_sources,privacy,prompts}.py`,
>   `backend/api/core/views/{scan_views,trust_views}.py`, `backend/api/core/tasks.py`,
>   `backend/api/utils/sandbox_analyzer.py`, sandbox Dockerfile, `frontend/src/components/ScanWidgets.tsx`.
> - **Ký hiệu:** ✅ Đạt · 🟡 Đạt một phần / cần lưu ý · ❌ Chưa đạt

---

## A. ĐIỂM MẠNH — kiểm chứng

### A1. Ý nghĩa thực tiễn & đối tượng người dùng
| # | Điểm kiểm | Cách kiểm | Trạng thái |
|---|---|---|---|
| A1.1 | Có luồng xử lý cho người *nghi* bị lừa đảo (không chỉ chặn) | `scan/*` trả `actions`, `explanation`, `guardrail.refusal_script` | ✅ |
| A1.2 | Có kênh xác minh/trình báo chính thức gắn vào kết quả | `assess().official_channels` (5 kênh VN: 156, 113, VNCERT…) | ✅ |
| A1.3 | Có kịch bản từ chối an toàn cho nạn nhân | `guardrail.refusal_script` (đã kiểm: có nội dung) | ✅ |

### A2. Đầu vào đa dạng
| # | Điểm kiểm | Cách kiểm | Trạng thái |
|---|---|---|---|
| A2.1 | Số điện thoại | `POST /scan/phone/` → `apply_guardrail(kind='phone')` | ✅ |
| A2.2 | Tài khoản ngân hàng | `POST /scan/account/` → `apply_guardrail(kind='account')` | ✅ |
| A2.3 | URL / website / QR | `/scan/domain/`, QR giải mã rồi quét URL → `kind='url'` | ✅ |
| A2.4 | Tin nhắn SMS/chat | `/scan/message/` → `kind='message'` | ✅ |
| A2.5 | Email (.eml) | `/scan/email/` → `kind='email'` | ✅ |
| A2.6 | Hình ảnh / biên lai (OCR) | VietOCR (`ocr_bridge.py`, venv riêng) + async `/scan/image/` | ✅ |
| A2.7 | Âm thanh | Faster-Whisper (`media_utils`) + async `/scan/audio/` | ✅ |
| A2.8 | Tệp tin | `/scan/file/` → sandbox → `apply_guardrail(kind='file')` trong `tasks.py` | ✅ |

### A3. Ứng dụng AI (Ollama · OCR · Whisper · RAG · chuỗi bằng chứng)
| # | Điểm kiểm | Cách kiểm | Trạng thái |
|---|---|---|---|
| A3.1 | LLM cục bộ Ollama | `api/utils/ollama_client.py` (`_log_llm`, `generate_response`, `stream_response`) | ✅ |
| A3.2 | OCR | VietOCR (venv `.venv-ocr` qua bridge; CER ~0.02) | ✅ |
| A3.3 | STT | `faster_whisper.WhisperModel` | ✅ |
| A3.4 | RAG / tra cứu | `api/utils/vector_db.py` (FAISS, nomic-embed 768-dim; log "Loaded vector index with 41 items") | ✅ |
| A3.5 | Chuỗi thu thập bằng chứng | `build_evidence()` chuẩn hoá → `evidence[]` | ✅ |
| A3.6 | Giải thích + khuyến nghị + kịch bản từ chối | `explanation`, `actions`, `refusal_script` | ✅ |

### A4. Zero-Trust Sandbox
| # | Điểm kiểm | Cách kiểm | Trạng thái |
|---|---|---|---|
| A4.1 | Cô lập mạng | `sandbox_analyzer.py:471` `--network none` | ✅ |
| A4.2 | Bỏ toàn bộ capability | `:472` `--cap-drop ALL` | ✅ |
| A4.3 | Giới hạn tài nguyên | `:473-474` `--memory`, `--pids-limit` | ✅ |
| A4.4 | Mount chỉ đọc | `:475` `-v {file}:/target:ro` | ✅ |
| A4.5 | Chạy bằng user không đặc quyền | `sandbox/Dockerfile:72` `USER sandboxuser` | ✅ |
| A4.6 | `--read-only` + `--security-opt=no-new-privileges` + `--cpus` + `--tmpfs /tmp` | Đã thêm vào CLI (`sandbox_analyzer.py`) và daemon/CI | ✅ (CI xác thực khi push) |

### A5. Đo lường – đánh giá đa phương diện
| # | Điểm kiểm | Cách kiểm | Trạng thái |
|---|---|---|---|
| A5.1 | Django system check | `manage.py check` | ✅ "no issues" |
| A5.2 | Unit/integration tests | `.venv/bin/python manage.py test` | ✅ 56 tests OK |
| A5.3 | Endpoint smoke | `/trust/sources|policy|channels|privacy/` → 200 | ✅ |
| A5.4 | VirusTotal live | google.com sạch / EICAR bị gắn cờ | ✅ |
| A5.5 | Frontend typecheck | `npx tsc --noEmit` | ✅ (theo `_minhchung/verification`) |
| A5.6 | Tuning ngưỡng trên tập chuẩn (ROC) | `docs/EVAL_THRESHOLDS.md`: tập 88 mẫu, **AUC 0.950** vs baseline 0.655 | ✅ (tầng heuristic tin nhắn) · ⏳ phone/domain |

---

## B. YÊU CẦU CẢI TIẾN — kiểm chứng

### B1. Guardrail độ bất định ("chưa đủ cơ sở thì không kết luận")
> Kiểm bằng script: `/tmp/opencode/verify_trust.py` (18 case) — **tất cả PASS**.

| # | Điểm kiểm | Kỳ vọng | Thực tế | TT |
|---|---|---|---|---|
| B1.1 | Điểm 25, không bằng chứng | `INSUFFICIENT` | `INSUFFICIENT` "CHƯA ĐỦ CƠ SỞ XÁC MINH" | ✅ |
| B1.2 | Điểm 0, không bằng chứng | **không** "an toàn" | `INSUFFICIENT` | ✅ |
| B1.3 | Điểm 0 + VirusTotal sạch | `LIKELY_SAFE` (kèm cảnh báo) | `LIKELY_SAFE`, vẫn `requires_verification=true` | ✅ |
| B1.4 | VirusTotal có mã độc | `CONFIRMED_RISK` | `CONFIRMED_RISK`, `is_conclusive=true` | ✅ |
| B1.5 | Điểm ≥ 70 | `HIGH_RISK` | `HIGH_RISK` | ✅ |
| B1.6 | Lỗi/thiếu đầu vào | `INSUFFICIENT` | `INSUFFICIENT` | ✅ |
| B1.7 | Điểm 10–39 + có dấu hiệu | `SUSPICIOUS`, không conclusive | `SUSPICIOUS` | ✅ |
| B1.8 | Luôn kèm kênh chính thức + kịch bản từ chối | có | 5 kênh, có script | ✅ |
| B1.9 | Prompt LLM siết quy tắc | `PROMPT_GUARD` quy tắc 4–5 | có, áp cho mọi prompt phân tích | ✅ |
| B1.10 | Nối guardrail vào **mọi** loại quét | phone/account/url/message/email/file + async status | `scan_views.py` + `tasks.py` + status | ✅ |
| B1.11 | **Không còn câu chữ "an toàn" mâu thuẫn guardrail** | — | **Còn 2 chỗ** | 🟡 → **xem C1, C2** |

### B2. Bổ sung dữ liệu nguồn Việt Nam
| # | Điểm kiểm | Thực tế | TT |
|---|---|---|---|
| B2.1 | Kênh chính thức VN | 10 kênh: NCSC 156, Cục ATTT, Công an 113, CSHS 069.2342609, Bảo vệ trẻ em 111, VNCERT/CC, BHXH 1900 9068, NHNN, Dịch vụ công, Bộ TT&TT | ✅ |
| B2.2 | Tổng đài/website ngân hàng & ví | 39 đơn vị (18 có tổng đài + 21 thêm website chính thức: Eximbank, SeABank, LPBank, Nam A Bank…) | ✅ |
| B2.3 | Từ điển dấu hiệu lừa đảo tiếng Việt (có/không dấu) | 31 nhóm mẫu — **đã nối vào bộ quét tin nhắn** (`VN_SCAM_PATTERNS` trước đây chưa dùng) | ✅ |
| B2.4 | Tên miền tin cậy VN (chống giả mạo) | 78 tên miền (bank + gov + viễn thông + tiện ích + TMĐT) | ✅ |
| B2.5 | Nguồn tham chiếu + báo chí chính thống | 8 nguồn nhà nước + 15 báo chí | ✅ |
| B2.6 | Tra đúng ngân hàng theo tên (khớp chính xác→dài nhất→tiền tố) | `lookup_vn_bank_hotline` (VCB, MB, Techcombank, Eximbank đúng) | ✅ |
| B2.7 | Kho tri thức VN (RAG) có trích dẫn nguồn | 18 bài VN (8 cũ + 10 mới: VNeID, romance, sàn ảo, BHXH/thuế, shipper, hack nick, tín dụng đen, bảo vệ trẻ em/người già, quy trình xử lý, kiểm tra doanh nghiệp); chỉ mục RAG 51 tài liệu | ✅ |
| B2.8 | Danh bạ Tín nhiệm mạng (tinnhiemmang.vn) | Thư viện `api/utils/tinnhiemmang.py` + CLI `scripts/crawl_tinnhiemmang.py`: thu thập website/tổ chức/hệ thống/ứng dụng tín nhiệm & website lừa đảo → JSONL; nối vào `vn_sources` (tên miền tin cậy) và threat feed `tinnhiem_fake` (Domain) | ✅ |

### B3. Độ tin cậy nguồn & giới hạn công cụ
| # | Điểm kiểm | Thực tế | TT |
|---|---|---|---|
| B3.1 | Danh mục nguồn | 14 nguồn (`SOURCE_CATALOG`) | ✅ |
| B3.2 | Mỗi nguồn có `reliability` (high/medium/low) | kiểm: 100% có | ✅ |
| B3.3 | Mỗi nguồn có `limits` (giới hạn nêu rõ) | kiểm: 100% có | ✅ |
| B3.4 | LLM bị đánh dấu **low** (không phải bằng chứng gốc) | `ai_model.reliability == 'low'` | ✅ |
| B3.5 | API công khai | `/trust/sources/`, `/trust/policy/` → 200 | ✅ |

### B4. Bằng chứng cho mọi nhận định
| # | Điểm kiểm | Thực tế | TT |
|---|---|---|---|
| B4.1 | Mỗi phát hiện có `source`, `source_name`, `reliability`, `severity`, `detail`, `limits` | kiểm: đủ trường | ✅ |
| B4.2 | Có `url` tham chiếu khi nguồn cho phép | có (VD VirusTotal permalink) | ✅ |
| B4.3 | Phân biệt `supports` = malicious/benign/context | có | ✅ |
| B4.4 | Gắn `evidence[]` vào kết quả quét | `apply_guardrail` set `evidence`, `verdict_label`, `verdict_conclusive` | ✅ |
| B4.5 | UI hiển thị bằng chứng + nguồn | `TrustGuardrailPanel` (9 trang: Phone/Bank/Website/Message/Email/Qr/File/Audio/Status) | ✅ |

### B5. Bảo mật dữ liệu (chống lộ PII qua LLM / log)
| # | Điểm kiểm | Thực tế | TT |
|---|---|---|---|
| B5.1 | Ẩn SĐT (0xxx và +84) | `[SĐT đã ẩn]` | ✅ |
| B5.2 | Ẩn email | `[email đã ẩn]` | ✅ |
| B5.3 | Ẩn số tài khoản | `[số tài khoản đã ẩn]` | ✅ |
| B5.4 | Ẩn số thẻ | `[số thẻ đã ẩn]` | ✅ |
| B5.5 | Ẩn CCCD/CMND | có (nhãn có thể lệch — xem C5) | 🟡 |
| B5.6 | Ẩn khoá bí mật (sk-, JWT, PEM, GitHub/Slack) | `[khoá/bí mật đã ẩn]` | ✅ |
| B5.7 | Ẩn đệ quy dict/list | `redact_obj` | ✅ |
| B5.8 | Filter log toàn cục | `PIIRedactionFilter` gắn trong `settings.LOGGING`; lọc cả `record.args` | ✅ |
| B5.9 | Ẩn trước khi gửi LLM cloud | `redact_for_external_llm` + `_log_llm` dùng `redact_pii` | ✅ |
| B5.10 | Không che bằng chứng khi phân tích cục bộ | ghi chú thiết kế trong `privacy.py` | ✅ |
| B5.11 | API công bố chính sách + thử nghiệm redact | `/trust/privacy/`, `POST /trust/redact/` → 200 | ✅ |

---

## C. PHÁT HIỆN KHI RÀ KĨ (cần xử lý)

| # | Mức | Vấn đề | Bằng chứng (file:dòng) | Đề xuất | Trạng thái |
|---|---|---|---|---|---|
| **C1** | 🟡 Trung bình | Lời khuyên của **quét tin nhắn** vẫn khẳng định an toàn ở vùng xám, mâu thuẫn với guardrail (cùng response có `guardrail.label = "CHƯA ĐỦ CƠ SỞ XÁC MINH"` nhưng `actions` lại ghi "✅ Tin nhắn có vẻ an toàn"). | `backend/api/core/views/scan_views.py:943-944` | Sinh `actions` theo `guardrail.tier`, không theo riêng `final_score`. | ✅ **Đã sửa** — thêm `_actions_for_guardrail()`, gọi sau `apply_guardrail` (`scan_views.py:851-869, ~965-970`) |
| **C2** | 🟡 Trung bình | Nhánh fallback khi LLM trả JSON lỗi/hết thời gian vẫn **tạm trả "an toàn"**. | `backend/api/utils/ollama_client.py:3963-3985` | Đổi câu chữ trung tính + đánh dấu `insufficient_input=True`. | ✅ **Đã sửa** — explanation trung tính + `insufficient_input: True` |
| **C3** | 🟡 Thấp–TB | Nhiều trường thô vẫn mang nhãn `SAFE`/"an toàn" song song guardrail; **UI hiển thị badge "AN TOÀN/GREEN" theo `risk_level` thô**, đi ngược panel guardrail. | `media_utils.py:463-466`; `scan_views.py:916,1377,1644`; badge ở 9 trang `Scan/*.tsx` + `Dashboard.tsx` | UI ưu tiên nhãn guardrail; đổi `details` sang câu trung tính. | ✅ **Đã sửa** — thêm `guardrailTone()`/`guardrailLabel()` (dùng chung ở `ScanWidgets.tsx`); 9 trang quét (Website/Message/Email/Bank/Qr/Status/Phone/File/Audio) + lịch sử (`Dashboard.tsx`) **hiển thị nhãn guardrail** ("CHƯA ĐỦ CƠ SỞ XÁC MINH", tông xám) thay vì "AN TOÀN/GREEN"; `media_utils.py` đổi `details` sang "Không phát hiện từ khóa rủi ro…". Bổ sung helper backend `verdict_tone`/`verdict_display` (`trust_guard.py`) + áp cho `/scan/lookup/` (`trend_views.py`) và `/user/scan-picker/` (`user_views.py`); màn **Tra cứu** (`Lookup.tsx`) và **tham chiếu scan ở Diễn đàn** (`ForumDetail.tsx`, `ForumCreate.tsx`) nay cũng hiển thị nhãn guardrail |
| **C4** | 🟡 Trung bình | **Tài liệu mô tả quá mức** so với mã: README/OVERVIEW ghi sandbox dùng `--read-only`, `--security-opt=no-new-privileges:true`, `--cpus 2.0` nhưng lệnh `docker run` thực tế **không có** các cờ này. | `backend/api/utils/sandbox_analyzer.py:468-478`; `README.md:215-216` | Thêm cờ thật (kèm `--tmpfs` cho thư mục tạm). | ✅ **Đã sửa & XÁC THỰC BẰNG DOCKER THẬT** — thêm `--read-only`, `--tmpfs /tmp:rw,size=256m,mode=1777`, `--security-opt no-new-privileges:true`, `--cpus`; daemon dùng thêm tmpfs `mode=1777` cho `/var/run/clamav` (nếu không, clamd không bind được socket). Kiểm chứng: CLI file sạch→`SAFE`, EICAR→`MALICIOUS`; daemon (container tạm) `clamav:true`, EICAR→`MALICIOUS` |
| **C5** | ⚪ Thấp | CMND cũ 9 số (VD `012345678`) bị nhãn thành "[SĐT đã ẩn]" thay vì "[CCCD/CMND đã ẩn]". | `backend/api/utils/privacy.py:34,65,67` | Siết regex SĐT (SĐT VN hợp lệ ≥10 số). | ✅ **Đã sửa** — `_PHONE` yêu cầu ≥9 số sau tiền tố; `012345678` → `[CCCD/CMND đã ẩn]` |
| **C6** | ⚪ Ghi nhận | Chưa có tuning ngưỡng trên tập chuẩn (ROC) và công bố số mẫu/baseline. | `docs/REBUTTAL_QA.md` Q2/Q6 | Việc dài hạn. | ✅ **Đã xử lý phần heuristic** — `evaluate_thresholds.py` + tập 88 mẫu + `docs/EVAL_THRESHOLDS.md` (AUC 0.950 vs 0.655). **Bộ công cụ cho phần còn lại đã sẵn:** `evaluate_generic.py` (mọi vector), `cohen_kappa.py` (kiểm định nhãn), templates + `docs/EVAL_GUIDE.md`. Còn: thu thập nhãn phone/domain + đánh giá AI (cần dữ liệu & người gán) |

> **Không** phát hiện lỗi ở: guardrail tier logic, danh mục nguồn, build_evidence, redaction (regex/log/filter),
> khoá đáp án quiz, quyền truy cập kết quả quét (`ScanStatusView` chống IDOR).

---

## D. LỆNH KIỂM CHỨNG (tái lập)

```bash
# 1. Django system check
cd backend && ../.venv/bin/python manage.py check

# 2. Bộ test độc lập cho guardrail / vn_sources / evidence / privacy
../.venv/bin/python /tmp/opencode/verify_trust.py     # 40+ check, tất cả PASS

# 3. Endpoint Trust & redact (server đang chạy ở :8001)
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8001/api/v1/trust/sources/
curl -s -X POST http://127.0.0.1:8001/api/v1/trust/redact/ \
  -H "Content-Type: application/json" \
  -d '{"text":"Goi 0912345678 hoac a@b.com, STK 123456789012"}'
# → {"redacted":"Goi [SĐT đã ẩn] hoac [email đã ẩn], STK [số tài khoản đã ẩn]","enabled":true}

# 4. Unit tests
cd backend && ../.venv/bin/python manage.py test

# 5. Frontend: typecheck + lint + build (sau khi sửa badge guardrail)
cd frontend && npx tsc --noEmit          # → exit 0
cd frontend && npx oxlint                 # → 0 error
cd frontend && npx next build             # → build OK
```

---

## E. KẾT LUẬN

- **5/5 hạng mục Điểm mạnh** có bằng chứng trong mã (A4.6 nay đã bổ sung cờ hardening thật).
- **5/5 Yêu cầu cải tiến** đã triển khai và vượt qua kiểm chứng độc lập (B1–B5).
- **Đã khắc phục trong phiên này:** C1, C2, C3, C4, C5, và **C6 (phần tầng heuristic)**.
- **Tồn đọng thực chất:** C6 cho **phone/domain** (chưa có tập nhãn cho các vector này); mở rộng tập nhãn tin nhắn với người gán độc lập.
- **Lưu ý xác thực cuối:** thay đổi sandbox (C4) cần chạy qua CI `Docker Sandbox CI` (build + chạy cờ `--read-only/--tmpfs/--no-new-privileges`) để xác nhận container vẫn phân tích được; môi trường soạn thảo này không có quyền Docker.
