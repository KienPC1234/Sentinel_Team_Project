# Hướng dẫn hoàn tất các phần đánh giá còn lại (dễ hiểu, cho người mới)

> Mục tiêu: bạn **không cần biết ML**. Chỉ cần làm theo các bước dưới đây.
> Tất cả công cụ đã được dựng sẵn trong `backend/scripts/eval/`.

---

## 0. Ba việc còn lại là gì?

1. **Tập nhãn cho phone/domain** → để chạy ROC (giống cái đã làm cho tin nhắn).
2. **Người gán nhãn độc lập** → kiểm định chất lượng nhãn (tránh tự lừa mình).
3. **Đánh giá tầng AI** → AI có "bịa" (hallucination) không?

Tin nhắn (message) đã xong: `docs/EVAL_THRESHOLDS.md`.

---

## 1. Ba nguyên tắc phải nhớ (quan trọng nhất)

- **Nhãn phải do NGƯỜI quyết định.** `label = 1` nghĩa là lừa đảo/độc hại, `label = 0` là hợp lệ.
  **Không** lấy điểm do máy chấm làm nhãn (như vậy là tự khen mình → vô nghĩa).
- **Không dán dữ liệu cá nhân thật** (số ĐT/STK/CCCD của người thật). Dùng dữ liệu công khai
  đã ẩn danh, hoặc che bớt chữ số.
- **Cần khoảng 100–300 mẫu mỗi vector** để số liệu có ý nghĩa. Ít quá thì chỉ gọi là "thử nghiệm".

---

## 2. Việc 1 — Thu thập & gán nhãn phone/domain

### 2.1 Domain / URL (có script TỰ ĐỘNG — không cần gán tay)
- Lấy mẫu **độc hại (label 1)** từ danh sách công khai miễn phí:
  - PhishTank, OpenPhish, URLhaus, APWG eCrime Exchange.
- Lấy mẫu **hợp lệ (label 0)** từ: top website (Tranco top-1M) + website cơ quan/bank chính thức.
- **Cách nhanh nhất:** chạy script thu thập tự động (đã dựng sẵn):
  ```bash
  .venv/bin/python backend/scripts/eval/collect_domain_dataset.py \
      --pos 100 --neg 100 --out backend/scripts/eval/domain_labels.jsonl
  ```
  (Tải OpenPhish + Tranco; ghi rõ nguồn + ngày trong mỗi dòng.)
- Hoặc điền tay theo mẫu: `backend/scripts/eval/templates/domain_labels.template.csv`.

### 2.2 Phone
- **Không có dataset công khai "số lừa đảo"**. Cách làm thực tế:
  - **Positives (1):** số đã bị cộng đồng trình báo (kho báo cáo ShieldCall / tổng hợp báo chí),
    nên **che bớt chữ số** khi lưu.
  - **Negatives (0):** tổng đài công ty/bank chính thức, số người quen **tình nguyện** (đã xin phép).
- Điền theo mẫu: `backend/scripts/eval/templates/phone_labels.template.csv`.

> Mẹo: mỗi dòng ghi thêm `source` và `notes` để sau này giải trình nguồn dữ liệu.

---

## 3. Việc 2 — Kiểm định nhãn (2 người gán độc lập)

1. Chọn ngẫu nhiên **10–20%** mẫu. Cho **2 người gán mà KHÔNG nhìn bài của nhau**.
2. Ghi vào file `labels_agreement.csv` (mẫu: `templates/labels_agreement.template.csv`):
   ```csv
   id,label_a,label_b
   1,1,1
   2,0,1
   ```
3. Chạy:
   ```bash
   .venv/bin/python backend/scripts/eval/cohen_kappa.py --csv backend/scripts/eval/labels_agreement.csv
   ```
4. Đọc kết quả: **kappa ≥ 0.61** là dùng được. Nếu thấp hơn → họp lại, viết "codebook"
   (định nghĩa rõ khi nào label=1) rồi gán lại.

---

## 4. Việc 3 — Chạy đánh giá ROC

- **Message** (đã có): 
  ```bash
  .venv/bin/python backend/scripts/eval/evaluate_thresholds.py
  ```
- **Bất kỳ vector** (phone/domain/AI) khi đã có tập nhãn:
  ```bash
  # Domain — pipeline đầy đủ (engine thật, CÓ mạng):
  #   b1) chấm điểm từng URL (chậm ~30-60s/URL do SSL/WHOIS/VT; có resume nếu chạy lại):
  .venv/bin/python backend/scripts/eval/score_domain_dataset.py \
      --in backend/scripts/eval/domain_labels.jsonl \
      --out backend/scripts/eval/domain_labels_scored.jsonl --per-class 100 --sleep 0.2
  #   b2) đánh giá ROC trên điểm đã chấm:
  .venv/bin/python backend/scripts/eval/evaluate_generic.py \
      --dataset backend/scripts/eval/domain_labels_scored.jsonl --scorer field --text-field url

  # Domain (offline, chỉ lớp lookalike — không cần mạng, nhanh):
  .venv/bin/python backend/scripts/eval/evaluate_generic.py \
      --dataset backend/scripts/eval/domain_labels.jsonl --scorer domain_lookalike --text-field url

  # Phone/AI: tự tính điểm cho từng mẫu, lưu vào cột "score", rồi:
  .venv/bin/python backend/scripts/eval/evaluate_generic.py \
      --dataset backend/scripts/eval/phone_labels.jsonl --scorer field --score-field score
  ```

**Cách tạo cột `score` cho phone/domain** (khi bạn đã có danh sách): viết 1 script nhỏ gọi hàm
chấm điểm của hệ thống cho từng mẫu và lưu lại. Ví dụ khung:
```python
# backend/scripts/eval/score_phone_dataset.py  (tự viết)
import json, os, django, sys
sys.path.insert(0, "backend"); os.environ.setdefault("DJANGO_SETTINGS_MODULE", "PKV.settings"); django.setup()
from api.core.views.scan_views import _phone_risk_score
rows = [json.loads(l) for l in open("backend/scripts/eval/phone_labels.jsonl", encoding="utf-8") if l.strip()]
out = []
for r in rows:
    res = _phone_risk_score(r["phone"])
    out.append({**r, "score": res.get("risk_score", 0)})
open("backend/scripts/eval/phone_labels_scored.jsonl", "w", encoding="utf-8").write(
    "\n".join(json.dumps(x, ensure_ascii=False) for x in out))
```

> Đã có sẵn bản demo để bạn xem công cụ chạy:
> ```bash
> .venv/bin/python backend/scripts/eval/evaluate_generic.py \
>   --dataset backend/scripts/eval/domain_labels.demo.jsonl --scorer domain_lookalike --text-field url
> ```
> Kết quả demo: AUC 0.80 nhưng **recall chỉ 0.60** — vì lớp lookalike **bỏ sót** dạng
> `bidv.com.vn.evil.xyz` và `vietcombank.vn`. Đây là lý do cần thêm tầng network (SSL/VT) —
> và cũng là ví dụ cho thấy vì sao phải đánh giá từng tầng.

---

## 5. Việc 4 — Đánh giá tầng AI (faithfulness / hallucination)

Câu hỏi cần trả lời: *"Các nhận định của AI có được bằng chứng RAG hỗ trợ không?"*

1. Viết **30–50 câu hỏi thật** kèm bằng chứng truy xuất — mẫu: `templates/ai_faithfulness.template.jsonl`.
2. Cho AI trả lời (qua trang AI Assistant hoặc API `/chat/stream/`).
3. Tách câu trả lời thành các **claim** (nhận định có thể kiểm chứng) và đánh dấu
   `supported: true/false` — do **người chấm**, hoặc dùng LLM làm giám khảo rồi **kiểm tra tay một phần**.
4. Công thức:
   - `Faithfulness = (# claim supported) / (# claim)`
   - `Hallucination rate = 1 - Faithfulness`
5. Ghi vào báo cáo `docs/EVAL_AI_FAITHFULNESS.md`, nêu rõ số mẫu + ngày + người chấm.

> Cảnh báo: dùng AI chấm AI dễ thiên vị. Tối thiểu 20% mẫu phải được người kiểm lại.

---

## 6. Phân công & thời lượng gợi ý (đội 3–4 người)

| Việc | Ai | Thời lượng |
|---|---|---|
| Thu thập + gán nhãn domain | 2 người | ~1–2 ngày |
| Thu thập + gán nhãn phone | 1 người | ~1 ngày |
| Kiểm định (gán độc lập + kappa) | 1 người | ~0.5 ngày |
| Chạy script + viết báo cáo | 1 người | ~0.5 ngày |
| Đánh giá AI faithfulness | 1–2 người | ~2 ngày |

---

## 7. Checklist nhanh (copy ra dùng)

- [ ] Viết **codebook**: định nghĩa rõ khi nào label = 1 vs 0
- [ ] Có **≥100 mẫu** cho mỗi vector (domain, phone)
- [ ] **2 người gán độc lập ≥10%** mẫu + **kappa ≥ 0.61**
- [ ] Chạy `evaluate_thresholds.py` / `evaluate_generic.py`, lưu báo cáo `.md`
- [ ] Báo cáo ghi rõ: **số mẫu, nguồn dữ liệu, ngày, hạn chế**
- [ ] Không tự bịa số; không lấy điểm máy làm nhãn

---

## 8. Cảnh báo liêm chính (rất quan trọng khi trình hội đồng)

- Trình bày **trung thực**: đây là tập nhỏ nội bộ, không phải benchmark công khai.
- Nói rõ **nguồn** (PhishTank/OpenPhish/báo cáo cộng đồng) và **ngày** thu thập.
- Nếu chưa đủ dữ liệu → nói "chưa đủ cơ sở để công bố", **đừng** đưa số đẹp mà không có bằng chứng.
