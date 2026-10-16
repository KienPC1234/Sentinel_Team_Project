#!/usr/bin/env bash
# Chạy một lần: dùng LLM nhỏ (SMALL_MODEL) định dạng lại nội dung tin tức thành Markdown.
#   pm2 start backend/scripts/format_news_llm.sh --name pkv-news-llm --no-autorestart --interpreter bash
#   pm2 logs pkv-news-llm
set -u
cd "$(dirname "$0")/.." || exit 1
export DJANGO_SETTINGS_MODULE=PKV.settings
export PYTHONUNBUFFERED=1
exec ../.venv/bin/python manage.py format_news --llm
