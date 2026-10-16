#!/usr/bin/env bash
# Thu thập TOÀN BỘ danh bạ tinnhiemmang.vn (ghi tăng dần + resume), chạy dưới PM2.
#
#   pm2 start backend/scripts/crawl_all_tinnhiem.sh --name pkv-crawl-tinnhiem \
#       --no-autorestart --interpreter bash
#   pm2 logs pkv-crawl-tinnhiem
#
# LƯU Ý: robots.txt của tinnhiemmang.vn chặn `/*?page=` — chỉ chạy khi có phép.
# Có thể dừng/chạy lại bất cứ lúc nào; `--resume` sẽ bỏ qua slug đã có.
set -u
cd "$(dirname "$0")/.." || exit 1
PY="../.venv/bin/python"
CACHE="${TINNHIEM_CACHE:-/tmp/opencode/th-cache}"
WORKERS="${TINNHIEM_WORKERS:-8}"
DELAY="${TINNHIEM_DELAY:-0.3}"
# 0 = quét toàn bộ (lần đầu). >0 = sync tăng dần: dừng sau N trang liên tiếp không có mục mới.
STOP_KNOWN="${TINNHIEM_STOP_AFTER_KNOWN:-0}"

# Thứ tự ưu tiên: lừa đảo (giá trị cao nhất) → website → tổ chức → app → sys → iot
for cat in fake web org app sys iot; do
  echo "########## $cat $(date +%F_%T) ##########"
  "$PY" scripts/crawl_tinnhiemmang.py --category "$cat" --all --resume \
    --workers "$WORKERS" --delay "$DELAY" \
    --stop-after-known "$STOP_KNOWN" --cache-dir "$CACHE" --json
  echo "########## done $cat $(date +%F_%T) ##########"
done
echo "########## ALL DONE $(date +%F_%T) ##########"
