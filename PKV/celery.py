import os
from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "PKV_TEAM.settings")

app = Celery("PKV_TEAM")

app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
