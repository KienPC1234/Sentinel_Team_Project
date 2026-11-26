# BÁO CÁO CẢI TIẾN VÒNG CHUNG KẾT - SHIELDCALL VN

> **Trạng thái:** hồ sơ nộp · **Cập nhật:** 2026-11-25 · **Đối tượng:** hội đồng giám khảo

- **Đề thi**: Đề cải tiến: Phiên bản 1 (Nộp / cập nhật bài - Chặng 1)
- **Hệ thống**: ShieldCall VN (Nền tảng phòng chống lừa đảo đa kênh tại Việt Nam)
- **Liên kết mã nguồn**: `https://github.com/KienPC1234/Sentinel_Team_Project`
- **Liên kết sản phẩm chạy thử**: `https://sc.fptoj.com`

---

## Tóm tắt cải tiến theo 3 yêu cầu của Hội đồng

Thay vì ép mọi kết quả về hai cực "An toàn" hoặc "Lừa đảo", phiên bản Chung kết nâng cấp cơ chế ra quyết định theo nguyên tắc **chỉ kết luận dứt khoát khi có bằng chứng đa nguồn nhất quán**, tách bạch dữ liệu bên thứ ba với ngày đối soát danh mục nội bộ, và bảo vệ dữ liệu nhạy cảm ngay từ bước tiếp nhận:

| Yêu cầu | Vấn đề trước đây | Giải pháp đã hoàn thiện | Minh chứng đo được |
|---|---|---|---|
| **1. Kiểm soát kết luận ảnh hưởng người dùng** | Khi thiếu dữ liệu, nguồn mâu thuẫn hoặc tin nhắn đời thường trùng từ khóa nhạy cảm, hệ thống dễ gắn nhầm mức cảnh báo hoặc lưu nhãn `SAFE`. | Tách tầng trung gian **`INSUFFICIENT`** ("Chưa đủ cơ sở xác minh"); khóa trần không bao giờ khẳng định cá nhân/STK/SĐT chắc chắn lừa đảo; kết hợp **tiền lọc Regex + AI LLM đối chứng** (`safe_context_discounted`) và fallback tự động sang `SMALL_MODEL` (`gemma4:31b-cloud`). | **20/20** ca guardrail đạt chuẩn (`100%` từ chối ca thiếu/mâu thuẫn); **18/18** ca kiểm thử đối kháng (gồm **12 ca LLM thực** và **6 ca mô phỏng** lỗi/bypass); **0/40** báo nhầm trên tin nhắn đời thường. |
| **2. Truy xuất nguồn & đánh giá tình huống VN** | Chưa rõ nguồn, độ tin cậy, giới hạn và tách bạch ngày dữ liệu ngoài với ngày rà soát nội bộ; thiếu minh chứng ánh xạ nhận định - nguồn. | Công khai **17 nguồn** trong `SOURCE_CATALOG` (Tín nhiệm mạng `04/11/2026`, ScamWave 4.071 mục `2026-11-16`, RAG 299 mục, 39 ngân hàng/ví, 15 báo chí VN), phân tách `updated_at`, `catalog_verified_at` và `freshness_scope`; gắn sẵn vào từng phần tử `evidence[]`. | Đánh giá **offline** (`ai_result=None`) trên bộ 80 tin nhắn kịch bản VN nội bộ đạt **Precision 100.00%, Recall 95.00%, F1 97.44%, FPR 0.00%**; bộ holdout nội bộ 40 mẫu đạt **F1 94.74%, FP=0**; AUC 88 mẫu đạt **0.959**. |
| **3. Bảo vệ PII & quyền kiểm soát dữ liệu** | Rủi ro lộ SĐT/email ở nhánh retry LLM hoặc exception traceback; mô tả tắt che PII chưa nêu rõ khả năng gửi ra AI ngoài; thiếu minh chứng xóa trước - sau. | Nút gạt `ScanPrivacyToggle` (mặc định BẬT `mask_pii=True`) trên cả 8 luồng quét, cảnh báo rõ khi chuyển nguyên văn dữ liệu có thể gửi tới AI bên ngoài; giữ nguyên che PII khi retry; `PIIRedactionFilter` che cả message lẫn exception traceback; API xuất JSON và xóa chọn lọc theo nhóm. | **0** SĐT/email/STK/CCCD/secret thô trên **2.266 dòng** `llm_access.log`; mô phỏng `logger.exception` che toàn bộ PII; demo API xóa chuyển các mảng từ `1` phần tử về rỗng `[]`; IDOR trả `403/401`; **55/55** test `test_trust_privacy` và **313/313** test mặc định PASSED. |

---

## Phần 1. Kiểm soát kết luận có thể ảnh hưởng người dùng

### 1.1. Cơ chế phân tầng 5 mức trong `trust_guard.py`

Hàm `assess(result, kind)` bổ sung tầng trung gian để phản ánh đúng độ chắc chắn của bằng chứng, tuyệt đối không khẳng định cá nhân hay chủ tài khoản là tội phạm:

| Tầng (`guardrail.tier`) | Nhãn hiển thị cho người dân | Kết luận dứt khoát (`is_conclusive`) | Khi nào kích hoạt & ràng buộc bảo vệ |
|---|---|---|---|
| `INSUFFICIENT` | `CHƯA ĐỦ CƠ SỞ XÁC MINH` | `false` | Đầu vào rỗng/lỗi; điểm thấp nhưng không có nguồn sạch uy tín; **nguồn mâu thuẫn** (Tín nhiệm mạng báo `trusted` nhưng bộ quét ngoài cảnh báo, hoặc VirusTotal `0/N` sạch nhưng heuristic cảnh báo ở mức `< 70`); tài khoản ngân hàng mới có báo cáo **chờ kiểm duyệt** (khóa trần `<= 35`). |
| `LIKELY_SAFE` | `CÓ KHẢ NĂNG AN TOÀN (không bảo đảm 100%)` | `false` | Chỉ cấp khi điểm `< 10`, không mâu thuẫn và có nguồn sạch độ tin cậy cao (`tinnhiemmang` trusted hoặc VirusTotal 0 engine gắn cờ). Luôn nhắc cảnh giác chuyển tiền và OTP. |
| `SUSPICIOUS` | `ĐÁNG NGỜ: Cần thận trọng` | `false` | Điểm trung bình (`40..69` hoặc `10..39` kèm dấu hiệu bất thường), chưa có xác thực độc lập. |
| `HIGH_RISK` | `NGUY CƠ CAO` | `false` với STK/SĐT; `true` với tin/URL/tệp | Dấu hiệu mạnh (`>= 70`) hoặc STK/SĐT đã có báo cáo kiểm duyệt. **Riêng số tài khoản và SĐT bị khóa trần tối đa ở mức này**, bắt buộc giữ `is_conclusive = false` và yêu cầu xác minh qua kênh chính thức. |
| `CONFIRMED_RISK` | `CẢNH BÁO RỦI RO CAO (Có nguồn đối chiếu)` | `true` (chỉ URL/domain/tệp) | Chỉ kích hoạt khi có nguồn độc lập xác thực: danh sách lừa đảo NCSC/VNCERT (`tinnhiemmang`), chữ ký cục bộ (`clamav`/`yara`/`sandbox`), hoặc `>= 3` engine VirusTotal `malicious`, và không mâu thuẫn với Tín nhiệm mạng. |

### 1.2. Xử lý tài khoản ngân hàng, số điện thoại và nhánh fallback (`scan_views.py`, `tasks.py`)

1. **Tách riêng báo cáo chờ duyệt trên tài khoản ngân hàng (`ScanAccountView`)**: Đếm độc lập `approved_account_reports` và `pending_account_reports`; báo cáo chưa duyệt bị giới hạn tối đa `35/100` (`min(35, pending * 15)`) và giữ nguyên ở tầng `INSUFFICIENT` kèm ghi chú `"chờ kiểm duyệt (chưa xác thực)"`.
2. **Loại bỏ ngôn ngữ quy kết cá nhân**: Đổi nhãn đỏ SĐT thành `"NGUY CƠ CAO (CẦN XÁC MINH ĐỘC LẬP)"`; quy tắc `PROMPT_GUARD` cấm AI khẳng định cá nhân hoặc chủ tài khoản là tội phạm, luôn kèm hướng dẫn gọi tổng đài ngân hàng hoặc cơ quan Công an.
3. **Chặn lưu nhầm `SAFE` khi fallback**: Khi OCR rỗng, âm thanh không nhận dạng được hoặc AI gián đoạn, `tasks.py` và `media_utils.py` đều gắn `insufficient_input = True` và lưu mức kỹ thuật `RiskLevel.YELLOW` thay vì `SAFE`, bảo đảm giao diện luôn hiển thị `"CHƯA ĐỦ CƠ SỞ XÁC MINH"`.

### 1.3. Cơ chế kết hợp 2 tầng: Tiền lọc Regex + AI LLM đối chứng & chống Jailbreak

Nếu chỉ dùng bộ luật từ khóa (Regex), hệ thống sẽ **báo nhầm** tin nhắn đời thường (nhắc nghề nghiệp công an, người nhà cấp cứu, chuyển tiền ăn trưa, xem phim hình sự) và **bỏ sót** các chiêu lừa mới không có từ khóa. Hệ thống xử lý bằng kiến trúc 2 tầng phối hợp (`scam_rules.py` + `ollama_client.py` + `trust_guard.py`):

| Tình huống tin nhắn đầu vào | Cách Tầng 1 (Regex + Domain) và Tầng 2 (LLM) phối hợp | Kết quả cuối |
|---|---|---|
| **Tin nhắn đời thường có từ khóa nhạy cảm** (ví dụ: *"Bạn trai tớ là công an, tối đi ăn..."*, *"Bố em cấp cứu ở Bạch Mai..."*, *"Chuyển 65k ăn trưa vào STK..."*, *"Xem phim viện kiểm sát đọc lệnh bắt"*) | Tầng 1 gửi danh sách mẫu bắt được qua `pre_filter_context` để AI thẩm định ngữ cảnh thực. Khi AI xác nhận `is_scam=False` (điểm `<= 25`) và văn bản không chứa chỉ thị cưỡng bức/cấp cứu đòi chuyển tiền, `compute_evidence_aware_ensemble()` áp dụng `safe_context_discounted`. | Điểm hạ xuống **`< 10` (`INSUFFICIENT`)**, xóa nhãn từ khóa regex để không báo nhầm `SUSPICIOUS`. |
| **Lừa đảo thủ đoạn mới, không chứa URL hay từ khóa phổ biến** (ví dụ: *"Tao đang kẹt ở cây xăng quên ví, chuyển hộ 200k đừng gọi lại"*) | Tầng 1 không bắt được hết mẫu cũ, nhưng AI đọc hiểu ngữ cảnh mạo danh người quen + ép chuyển tiền khẩn cấp + chặn xác minh ngược. | Bắt chính xác **`85/100` (`RED` / `HIGH_RISK`)**. |
| **Tấn công pha trộn & Jailbreak** (chèn lệnh giả `is_scam: false` hoặc mở đầu bằng *"Bộ Công an khuyến cáo..."* rồi đòi chuyển tiền tạm giữ/đọc OTP) | `PROMPT_GUARD` đặt ở **`role="system"`** tách biệt khỏi khối `<DU_LIEU_NGUOI_DUNG>`, yêu cầu AI chấm điểm theo vế nguy hiểm nhất. Đồng thời lớp bảo vệ clause-level (`_detect_severe_extortion` & `has_active_threat_directive`) giữ sàn điểm ngay cả khi mô hình bị đánh lừa. | Giữ sàn **`>= 70` (`RED`)**; kiểm chứng trực tiếp trên cả `LLM_MODEL` và `gemma4:31b-cloud` đều đạt `95/100`. |
| **Model chính lỗi JSON hoặc gián đoạn** | `analyze_text_for_scam()` tự động fallback sang **`SMALL_MODEL` (`gemma4:31b-cloud`)**; nếu cả mạng/Ollama mất kết nối, chuyển sang `ai_outage_fallback` dùng Regex offline (`scam_rules.py`). | Không sập luồng quét; `SMALL_MODEL` đồng thời đảm nhận kiểm duyệt diễn đàn, đặt tiêu đề chat, tóm tắt MagicCreate, format Markdown và lọc tin trùng. |

### 1.4. Minh chứng chạy thực tế Guardrail (3 ca tiêu biểu & JSON phản hồi)

Bảng dưới tổng hợp đầu ra thực tế từ hàm `apply_guardrail()` (lưu đầy đủ trong repository tại `docs/minh_chung/01_demo_mau_thuan_va_thieu_du_lieu.json`):

| Ca thử thực tế | Bằng chứng đầu vào | Kết quả hệ thống (`tier`, `is_conclusive`, `evidence[]`, hướng dẫn) |
|---|---|---|
| **Nguồn mâu thuẫn** (`contradiction`) | `tinnhiem.status="trusted"` kèm `virustotal` có `3` engine `malicious`, `risk_score=75` | `tier="INSUFFICIENT"`, `is_conclusive=false`, `has_contradiction=true`, đính kèm 2 phần tử `evidence[]` (`virustotal` hỗ trợ `malicious`, `tinnhiemmang` hỗ trợ `benign`) + khuyến nghị không kết luận vội. |
| **Thiếu dữ liệu** (`insufficient_empty`) | `risk_score=0`, `insufficient_input=true` (ảnh mờ / OCR rỗng / đầu vào thiếu) | `tier="INSUFFICIENT"`, `is_conclusive=false`, `requires_verification=true`, kèm `refusal_script` và danh bạ kênh chính thức (`113`, `156`, `tinnhiemmang.vn`). |
| **STK có báo cáo đã duyệt** (`account_capped`) | `kind="account"`, `reports_count=3`, `bank_name="Techcombank"`, `risk_score=75` | `tier="HIGH_RISK"`, nhưng **khóa cứng `is_conclusive=false`**, cảnh báo không quy kết cá nhân, đính kèm tổng đài Techcombank `1800 588822` và `113`/`156`. |

Trích đoạn JSON phản hồi thực tế từ `apply_guardrail()` cho ca mâu thuẫn và ca khóa trần STK:

```json
{
  "contradiction": {
    "risk_score": 75,
    "tier": "INSUFFICIENT",
    "label": "CHƯA ĐỦ CƠ SỞ XÁC MINH",
    "is_conclusive": false,
    "has_contradiction": true,
    "evidence": [
      {
        "source": "virustotal",
        "supports": "malicious",
        "updated_at": "2026-11-24",
        "limits": "Phụ thuộc dữ liệu cộng đồng; tệp/URL mới có thể chưa có báo cáo; bản miễn phí giới hạn số lượt/phút."
      },
      {
        "source": "tinnhiemmang",
        "supports": "benign",
        "updated_at": "04/11/2026",
        "limits": "Chỉ gồm thực thể đã đăng ký/chứng nhận hoặc đã bị ghi nhận - KHÔNG có nghĩa mọi tên miền vắng mặt đều an toàn."
      }
    ],
    "cautions_head": ["Tín hiệu cảnh báo (virustotal) mâu thuẫn với tín hiệu sạch/tin cậy (tinnhiemmang)."]
  },
  "account_capped": {
    "risk_score": 75,
    "tier": "HIGH_RISK",
    "label": "NGUY CƠ CAO",
    "is_conclusive": false,
    "has_contradiction": false,
    "cautions_head": ["Hệ thống không khẳng định một cá nhân hay chủ tài khoản/số điện thoại chắc chắn lừa đảo; chỉ cảnh báo dấu hiệu rủi ro để bạn đối chiếu qua ngân hàng hoặc cơ quan chức năng."]
  }
}
```

---

## Phần 2. Truy xuất nguồn và đánh giá trên tình huống Việt Nam

### 2.1. Bảng 17 nguồn dữ liệu, phạm vi nhận định, giới hạn và phân tách ngày cập nhật

Để tránh nhầm lẫn giữa **thời điểm dữ liệu bên thứ ba được cập nhật** và **ngày nhóm rà soát danh mục/bộ luật** (`SOURCE_VERIFIED_DATE = 2026-11-24`), hàm `source_catalog()` trong `backend/api/utils/trust_guard.py` công khai thêm hai trường `catalog_verified_at` và `freshness_scope`:

- `dataset_snapshot`: dữ liệu snapshot bên ngoài có mốc cập nhật riêng (`tinnhiemmang`: `04/11/2026`; `scamwave`: `2026-11-16`).
- `realtime_query`: truy vấn API/OSINT trực tiếp tại thời điểm người dùng quét (`virustotal`, `network_analysis`, `tranco`, `web_search`), mốc `2026-11-24` là ngày kiểm tra tích hợp gần nhất.
- `catalog_verified`: danh mục kênh chính thức, engine cục bộ hoặc bộ luật nội bộ (`vn_official`, `heuristic`, `rag`, `clamav`, `yara`, `sandbox`, `pefile`, `oletools`, `phone_numbering`, `community`, `ai_model`), mốc `2026-11-24` là ngày rà soát phiên bản hiện hành.

| Mã nguồn (`key`) | Tên nguồn | Độ tin cậy | Phạm vi áp dụng & nhận định tương ứng | Giới hạn đã công bố | Ngày dữ liệu / Đối soát |
|---|---|---|---|---|---|
| `tinnhiemmang` | Tín nhiệm mạng (NCSC/VNCERT) | Cao | Đối chiếu `5.873` mục tín nhiệm và `21.293` tên miền lừa đảo -> `CONFIRMED_RISK` / `LIKELY_SAFE`. | Chỉ gồm thực thể đã ghi nhận; vắng mặt chưa chắc an toàn. | Dữ liệu `04/11/2026` (đối soát `24/11/2026`) |
| `scamwave` | ScamWave (cảnh báo cộng đồng) | Vừa | Đối chiếu `4.071` thực thể (`Scam`, `Doubtful`, `Ponzi`, `Closed`, `Illegal`). | Phần lớn thiếu hồ sơ bằng chứng; chỉ tham khảo và đối chiếu chéo. | Dữ liệu `2026-11-16` (đối soát `24/11/2026`) |
| `vn_official` | Kênh chính thức VN (Bộ CA, NHNN, 39 NH/ví) | Cao | Danh bạ xác minh thủ công (`khonggianmang.vn`, 113, 156, 18 tổng đài & 21 website NH/ví). | Kênh tự kiểm chứng của người dùng, không trả API tự động. | Rà soát `24/11/2026` |
| `virustotal` | VirusTotal (70+ engine AV) | Cao | `>= 3` engine `malicious` -> `CONFIRMED_RISK`; `1-2` engine -> `HIGH_RISK`; `0` engine -> sạch. | Phụ thuộc cộng đồng; URL/tệp mới có thể chưa có mẫu. | Truy vấn live (kiểm tra `24/11/2026`) |
| `network_analysis` | Phân tích kết nối/SSL | Vừa | Kiểm tra chứng chỉ SSL, chuyển hướng URL, tuổi tên miền. | Phụ thuộc phản hồi trang đích; trang chặn bot thiếu dữ liệu. | Truy vấn live (kiểm tra `24/11/2026`) |
| `tranco` | Tranco (thứ hạng phổ biến) | Vừa | Xếp hạng độ phổ biến tên miền toàn cầu làm ngữ cảnh phụ. | Độ phổ biến cao không đồng nghĩa hoàn toàn an toàn. | Truy vấn live (kiểm tra `24/11/2026`) |
| `web_search` | Tìm kiếm/OSINT web | Vừa | Đối chiếu doanh nghiệp (`TraTenCongTy`) và tin công khai khi người dùng đồng ý. | Nguồn mở đa dạng độ tin cậy; phải kiểm chứng từ nguồn gốc. | Truy vấn live (kiểm tra `24/11/2026`) |
| `clamav` | ClamAV (mã độc cục bộ) | Cao | Quét chữ ký mã độc cục bộ cho tệp/APK tải lên. | Chỉ nhận diện chữ ký đã biết; dễ bỏ sót zero-day. | Đối soát `24/11/2026` |
| `yara` | YARA (luật phát hiện) | Cao | Khớp luật cấu trúc và chuỗi hành vi đáng ngờ trong tệp. | Phụ thuộc bộ luật biên soạn; chưa bao phủ hết biến thể mới. | Đối soát `24/11/2026` |
| `sandbox` | Zero-Trust Sandbox (cô lập mạng) | Cao | Phân tích tĩnh/hành vi tệp trong container tắt hoàn toàn kết nối mạng. | Mẫu kích hoạt trễ hoặc cần mạng khó bộc lộ hết hành vi. | Đối soát `24/11/2026` |
| `pefile` | PEFile (giải phẫu PE) | Vừa | Trích xuất import, section, packing của tệp Windows PE. | Chỉ áp dụng tệp PE; dấu hiệu kỹ thuật không tự kết luận độc hại. | Đối soát `24/11/2026` |
| `oletools` | OLEtools (macro Office) | Vừa | Kiểm tra macro VBA trong tài liệu Office. | Macro nghiệp vụ hợp lệ vẫn có thể kích hoạt cảnh báo. | Đối soát `24/11/2026` |
| `phone_numbering` | Kho số viễn thông VN | Vừa | Kiểm tra đầu số +84/di động/cố định/VoIP theo `libphonenumber` và Bộ KH&CN. | Chỉ kiểm tra định dạng; không xác thực chủ thuê bao/Caller ID. | Đối soát `24/11/2026` |
| `heuristic` | Heuristic VN (`scam_rules`) | Vừa | Tiền lọc cụm từ lừa đảo tiếng Việt, chuẩn hóa chữ chèn dấu (`C.ô.n.g a.n`). | Có thể báo nhầm nếu đứng một mình; cần LLM đối chứng ngữ cảnh. | Đối soát `24/11/2026` |
| `rag` | Kho tri thức ShieldCall (FAISS RAG) | Vừa | Truy xuất **299 mục** kịch bản/hướng dẫn xử lý tình huống VN cho AI. | Dữ liệu tĩnh theo phiên bản chỉ mục; cần đối chiếu thêm kênh chính thức. | Chỉ mục `24/11/2026` |
| `community` | Báo cáo cộng đồng | Vừa | Phản ánh người dùng đóng góp (tách riêng `approved` và `pending`). | Chưa xác minh pháp lý; không dùng kết luận danh tính cá nhân. | Theo CSDL (đối soát `24/11/2026`) |
| `ai_model` | Mô hình ngôn ngữ (LLM) | Thấp | Đối chứng ngữ nghĩa, phát hiện thủ đoạn mới và giải thích tiếng Việt dễ hiểu. | Có thể sai lệch (hallucination); chỉ là lớp diễn giải, không thay thế bằng chứng gốc. | Cấu hình `24/11/2026` |

#### Ví dụ ánh xạ trực tiếp từ nhận định cảnh báo tới nguồn, ngày cập nhật và giới hạn

Khi quét một tên miền bị VirusTotal gắn cờ nhưng chưa đồng nhất với Tín nhiệm mạng (`apply_guardrail`), hệ thống trả từng mục trong `evidence[]`:
- **Nhận định 1**: `"3 engine gắn cờ ĐỘC HẠI, 1 engine NGHI NGỜ trên 70 engine."` -> ánh xạ `source: "virustotal"`, `reliability: "high"`, `updated_at: "2026-11-24"`, `limits: "Phụ thuộc dữ liệu cộng đồng..."`.
- **Nhận định 2**: `"Website đã được chứng nhận TÍN NHIỆM - Ngân hàng A"` -> ánh xạ `source: "tinnhiemmang"`, `reliability: "high"`, `updated_at: "04/11/2026"`, `limits: "Chỉ gồm thực thể đã đăng ký/chứng nhận..."`.
- **Tổng hợp kết luận**: Vì hai nguồn độ tin cậy cao cho hướng ngược nhau (`malicious` vs `benign`), bộ lọc bật `has_contradiction = true` và hạ mức kết luận xuống `INSUFFICIENT`.

### 2.2. Nguồn gốc tập dữ liệu & kết quả đánh giá trên tình huống Việt Nam

#### A. Nguồn gốc và giới hạn phương pháp của tập thử nghiệm

1. **Cách xây dựng tập dữ liệu**: Bộ `independent_test_set_vn.jsonl` (80 tin nhắn: 40 lừa đảo, 40 hợp lệ dễ nhầm), `holdout_test_set_b.jsonl` (40 mẫu: 20 lừa đảo, 20 hợp lệ) và `vn_final_suite.jsonl` (20 kịch bản guardrail) là **bộ tình huống chuẩn hóa nội bộ do nhóm phát triển tự biên soạn và gán nhãn thủ công** (`label = 0/1`) mô phỏng các kịch bản phổ biến tại Việt Nam (giả danh Công an/Viện kiểm sát, VNeID APK, OTP, hóa đơn EVN, biến động số dư, tin chuyển tiền ăn trưa, shipper), nhằm tránh dùng dữ liệu nhạy cảm của người dùng thật. Nhóm cũng đã tinh chỉnh một số mẫu lỗi điển hình phát hiện qua các vòng thử trước (`legit_22`, chữ chèn dấu `C.ô.n.g a.n`), nên kết quả là **kiểm thử nội bộ tái lập được**, chưa có bên thứ ba độc lập thẩm định.
2. **Phạm vi phép đo `evaluate_vn_final.py` (Offline, không LLM)**: Script `evaluate_vn_final.py` chạy `scam_rules.heuristic_score` + `compute_evidence_aware_ensemble` với **`ai_result = None`** ở ngưỡng `threshold = 40`. Vì vậy các chỉ số trong Bảng dưới đây đo năng lực của **tầng tiền lọc Heuristic + Guardrail khi tắt AI**, **không** đại diện trực tiếp cho độ chính xác end-to-end khi bật LLM. Năng lực khi có LLM thực được kiểm chứng riêng qua 12 ca thực trong `adversarial_stress_test.py` và các vòng chạy full pipeline trước đó (`BENCHMARK_MESSAGES_HOLDOUT_B.md`).

#### B. Kết quả đo offline trên 80 tin nhắn kịch bản VN (`vn_final_eval_results.json`, `threshold = 40`, `ai_result = None`)

| Chỉ số | Giá trị đo (chế độ offline không LLM) | Phân tích chi tiết |
|---|---|---|
| Tổng số ca | **80** (40 lừa đảo / 40 hợp lệ dễ nhầm) | Bao gồm giả danh công an, VNeID APK, OTP, việc nhẹ lương cao, hoàn thuế, EVN, deepfake và tin nhắn hợp lệ dễ nhầm (OTP ngân hàng, biến động số dư, khuyến cáo Công an, EVNNPC, shipper, chuyển tiền ăn trưa, phỏng vấn). |
| TP / FN & Độ chính xác | **38 / 2** (Precision **100.00%**, Recall **95.00%**, F1 **97.44%**) | Bộ tiền lọc khử trùng lặp từ khóa và chuẩn hóa chữ chèn dấu đạt Recall 95.00% ngay cả khi tắt AI. Trên tập holdout nội bộ 40 mẫu cũng đạt Precision **100.00%**, Recall **90.00%**, F1 **94.74%**, FP=0; AUC 88 mẫu đạt **0.959**. |
| TN / FP & Tỷ lệ báo nhầm | **40 / 0** (**FPR = 0.00%**) | Cả tin nhắn chuyển tiền ăn trưa (`legit_22`), OTP thật, khuyến cáo Bộ Công an/CATP HN, hóa đơn điện nước và shipper đều không vượt ngưỡng cảnh báo. |
| 2 ca bỏ sót khi tắt LLM (FN) | `scam_33`, `scam_37` | Tin nhắn ngữ nghĩa mềm giống giao tiếp đời thường (mượn 200k quên ví, quét QR đặt phòng) được giữ dưới ngưỡng khi tắt LLM để không báo nhầm tin nhắn thật. |

#### C. Tập kiểm thử Guardrail & Tình huống hỗn hợp Chung kết (`vn_final_suite.jsonl` - 20 ca)

| Nhóm tình huống | Số ca | Đạt | Kết quả |
|---|---|---|---|
| `verified_scam` (Tín nhiệm mạng scam, VT `>= 3` engine) | 2 | **2/2** | Trả `CONFIRMED_RISK`, `is_conclusive = true`, đủ nguồn và `updated_at`. |
| `heuristic_scam` (tin nhắn giả công an, APK VNeID) | 2 | **2/2** | Trả `HIGH_RISK` kèm hướng dẫn hành động an toàn. |
| `account_high_risk` / `phone_high_risk` | 2 | **2/2** | Trả `HIGH_RISK` nhưng khóa `is_conclusive = false`, từ chối quy kết cá nhân. |
| `insufficient_missing` (rỗng, ảnh mờ, SĐT sạch, STK chờ duyệt, domain mới) | 5 | **5/5** | `100%` trả `INSUFFICIENT` (`insufficient_refusal_rate = 1.0`). |
| `contradiction` (VT sạch vs heuristic, TN trusted vs VT, VT sạch vs PE packing) | 4 | **4/4** | `100%` bật `has_contradiction = true` và hạ về `INSUFFICIENT` (`contradiction_refusal_rate = 1.0`). |
| `legit_vn` & `legit_vn_fp_prone` (trusted bank, VT sạch, PSA công an, OTP thật, EVN) | 5 | **5/5** | Nguồn xác thực sạch trả `LIKELY_SAFE`; PSA/OTP/EVN có điểm `<= 5` và trả `INSUFFICIENT`, 0 báo nhầm. |
| **Tổng cộng** | **20** | **20/20** | **Đạt 100% (0 ca thất bại)**. |

---

## Phần 3. Bảo vệ dữ liệu nhạy cảm và truy vết xử lý

### 3.1. Sơ đồ luồng dữ liệu: Xử lý cục bộ và Dịch vụ bên ngoài

```mermaid
flowchart LR
    U["Người dùng (Web / API)"] -->|"Dữ liệu quét: Tin nhắn, SĐT, STK, Ảnh, File, Audio"| API["Django Backend (Xử lý cục bộ)"]

    subgraph LOCAL ["Vùng xử lý cục bộ trên máy chủ ShieldCall"]
        direction TB
        API -->|"Mask số hiển thị + Hash SHA-256 STK"| DB[("MariaDB / SQLite (ScanEvent, BankAccount)")]
        API -->|"Lọc PIIRedactionFilter trước khi ghi (cả exception)"| LOG["System Logs (SĐT/CCCD/Email/STK/Secret đã che)"]
        API -->|"Văn bản / Heuristic"| RULES["scam_rules + trust_guard + FAISS RAG (299 mục)"]
        API -->|"Ảnh / Audio / File"| ISOLATED["OCR / Whisper / ClamAV / YARA / Zero-Trust Sandbox (tắt mạng)"]
    end

    API -->|"Kiểm tra mask_pii & consent_external_llm"| GATE{"Cần dịch vụ ngoài?"}

    subgraph EXT ["Dịch vụ bên ngoài (Chỉ gọi khi bật / có consent)"]
        direction TB
        GATE -->|"Mặc định (mask_pii=True): redact_for_external_llm() + PROMPT_GUARD system"| CLOUD_LLM["External Cloud LLM (LLM_MODEL / SMALL_MODEL fallback)"]
        GATE -->|"Hash, URL & tên miền công khai (upload_if_unknown=False cho file)"| VT["VirusTotal / WHOIS / RDAP / Tranco / ScamWave"]
    end

    RULES --> GUARD["trust_guard.assess() + evidence[]"]
    ISOLATED --> GUARD
    CLOUD_LLM --> GUARD
    VT --> GUARD
    GUARD -->|"Kết quả có nguồn + ngày cập nhật + nút Xóa dữ liệu"| U
```

### 3.2. Minh chứng che PII trong log (thực tế & mô phỏng exception) và nút gạt giao diện

1. **Che thông tin trong log (`PIIRedactionFilter`)**:
   - Đã vá bổ sung trong `PIIRedactionFilter.filter()` (`backend/api/utils/privacy.py`) để định dạng và che `record.exc_text` / `stack_info` ngay khi phát sinh `logger.exception(...)`, bảo đảm SĐT, STK, CCCD, email, secret trong message **lẫn trong exception traceback** đều bị thay bằng nhãn che (`[SĐT đã ẩn]`, `[số tài khoản đã ẩn]`, `[CCCD/CMND đã ẩn]`, `[email đã ẩn]`, `[khoá/bí mật đã ẩn]`).
   - Rà soát toàn bộ **2.266 dòng** hiện tại trong `backend/llm_access.log`: ghi nhận **0 SĐT thô, 0 email thô, 0 STK có tiền tố, 0 CCCD 12 số và 0 API secret thô**.
   - Kết quả chạy mô phỏng thực tế qua `PIIRedactionFilter` với dữ liệu nhạy cảm và một `RuntimeError`:

```text
INFO Quet SMS: Chuyen 5tr vao STK [số tài khoản đã ẩn], goi [SĐT đã ẩn], CCCD [CCCD/CMND đã ẩn], email [email đã ẩn], token [khoá/bí mật đã ẩn]
ERROR Loi worker khi xu ly CCCD [CCCD/CMND đã ẩn]
Traceback (most recent call last):
  File "<string>", line 28, in <module>
RuntimeError: Timeout ket noi khi gui SĐT [SĐT đã ẩn] va STK [số tài khoản đã ẩn]
```

2. **Nút gạt quyền riêng tư từng lượt quét (`ScanPrivacyToggle` trong `ScanWidgets.tsx`)**:
   - Mặc định BẬT `mask_pii=True` trên cả 8 màn hình quét (`Phone`, `Bank`, `Message`, `Website`, `Email`, `Qr`, `Audio`, `File`), giữ nguyên `allow_pii=False` qua mọi nhánh repair/rerun/fallback sang `SMALL_MODEL`.
   - Giao diện khi người dùng tắt nút gạt (chế độ nguyên văn) cảnh báo rõ: *"Chế độ nguyên văn: lưu lịch sử gốc và **dữ liệu có thể được gửi tới dịch vụ AI bên ngoài** để phân tích đầy đủ theo lựa chọn của bạn; nhật ký hệ thống vẫn luôn tự động che thông tin cá nhân."*
   - `BankAccount` chỉ lưu `account_number_hash` (SHA-256) và 4 số cuối; kiểm tra tệp VirusTotal đặt `upload_if_unknown=False` (chỉ tra mã băm).

### 3.3. Chức năng quản lý, xuất, xóa dữ liệu cá nhân và bản ghi demo trước - sau

| Chức năng | API Endpoint | Phân quyền & An toàn | Vị trí giao diện |
|---|---|---|---|
| Xóa từng lượt quét | `DELETE /api/v1/user/scans/<scan_id>/` | Kiểm tra sở hữu (`user_id` hoặc `active_scan_ids` phiên ẩn danh); trả 403/401 nếu truy cập chéo. | Bảng Lịch sử quét (`/dashboard`) |
| Bật/tắt chia sẻ công khai | `PATCH /api/v1/user/scans/<scan_id>/` | Chỉ chủ sở hữu được bật/tắt `is_public_referable`. | Cột Thao tác (`/dashboard`) |
| Xóa toàn bộ lịch sử quét | `DELETE /api/v1/user/scans/` | Xóa mọi `ScanEvent` của tài khoản và dọn `active_scan_ids`. | Nút xóa toàn bộ (`/dashboard`) |
| Xuất dữ liệu cá nhân (JSON) | `GET /api/v1/user/privacy/export-data/` | Xuất bản sao JSON gồm lịch sử quét, phiên chat AI và cảnh báo. | Nút `"Xuất JSON"` (`/profile`) |
| Xóa dữ liệu chọn lọc theo nhóm | `POST /api/v1/user/privacy/delete-data/` | Chọn `scopes`: `["scans", "chat_sessions", "alerts"]` hoặc `["all"]` trong transaction atomic. | Thẻ quản lý dữ liệu (`/profile`) |
| Xóa toàn bộ chat AI | `DELETE /api/v1/chat/sessions/clear-all/` | Xóa toàn bộ `ChatSession` của người dùng hiện tại. | `/ai-assistant` |
| Xóa tài khoản | `POST /api/v1/auth/account/delete/` | Xóa tài khoản và dữ liệu liên quan sau khi xác nhận mật khẩu. | `/profile` |

Bản ghi thực thi kiểm chứng API xuất và xóa dữ liệu trước - sau trên tài khoản thử nghiệm (`APIClient`, lưu tại `docs/minh_chung/06_demo_xoa_du_lieu_truoc_sau.txt`; lưu ý `GET /export-data/` trả về các mảng JSON `scans[]`, `chat_sessions[]`, `alerts[]`):

```text
1) Trước khi xóa (GET /api/v1/user/privacy/export-data/):
   Số phần tử trong các mảng JSON xuất ra: len(scans)=1, len(chat_sessions)=1, len(alerts)=1
2) Gửi yêu cầu xóa theo nhóm (POST /api/v1/user/privacy/delete-data/, scopes=["scans","chat_sessions","alerts"]):
   HTTP 200 {"deleted": {"scans": 1, "chat_sessions": 1, "alerts": 1}, "scopes": ["alerts", "chat_sessions", "scans"], "message": "Đã xóa dữ liệu đã chọn khỏi tài khoản."}
3) Truy vấn lại sau khi xóa (GET /api/v1/user/privacy/export-data/):
   {"scans": [], "chat_sessions": [], "alerts": []} (tổng = 0)
```

---

## Phần 4. Tổng hợp kiểm chứng kỹ thuật sau chỉnh sửa cuối

| Hạng mục kiểm tra | Lệnh thực thi | Kết quả đo được sau bản cập nhật cuối (`25/11/2026`) |
|---|---|---|
| Kiểm thử toàn bộ Backend | `DJANGO_SETTINGS_MODULE=PKV.settings_ci ../.venv/bin/python manage.py test --noinput` | `System check`: 0 issues; **313/313 test mặc định PASSED** (tổng **319 tests**, `OK`, `skipped=6` test AI Red-Team tách riêng qua `RUN_LIVE_AI_TESTS=1`, `152.834s`); gồm **55/55** test `test_trust_privacy` (kể cả test che PII trong exception traceback) và **21/21** test `test_mcp_and_api_keys`. |
| Đánh giá offline VN, Guardrail & Đối kháng | `../.venv/bin/python scripts/eval/evaluate_vn_final.py` & `adversarial_stress_test.py` | 80 tin nhắn kịch bản VN (offline `ai_result=None`): **Precision 100.00%, Recall 95.00%, F1 97.44%, FPR 0.00%**; 20 ca Guardrail: **20/20 PASSED**; **18/18 ca kiểm thử đối kháng đạt yêu cầu** (gồm **12 ca LLM thực** và **6 ca mô phỏng** lỗi mạng/503 hoặc bypass); kiểm tra `SMALL_MODEL` `gemma4:31b-cloud`: 3/3 ca jailbreak đạt `score=95`, ca tán gẫu công an `score=10`; AUC 88 mẫu nội bộ đạt **0.959**. |
| TypeScript, Oxlint & Tour Frontend | `cd frontend && npx tsc --noEmit && npx oxlint && npm run check:tours` | `tsc`: **0 errors**; `oxlint`: **0 errors** (143 warnings trên 204 tệp); `check:tours`: **19 tour, 16 neo, 18 bước có element**. |
| Build Production Frontend | `cd frontend && npm run build` | Hoàn tất build **78 route** (62 static pages cùng các dynamic route) Next.js 16.4.5 và đồng bộ `sw.js`. |
