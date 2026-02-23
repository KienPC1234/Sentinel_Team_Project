from django.urls import re_path
from api.core import consumers

websocket_urlpatterns = [
    re_path(r'ws/scan/(?P<scan_id>\d+)/$', consumers.ScanProgressConsumer.as_asgi()),
    re_path(r'ws/task/(?P<task_id>[\w-]+)/$', consumers.TaskProgressConsumer.as_asgi()),
    re_path(r'ws/rag/$', consumers.RagStatusConsumer.as_asgi()),
    re_path(r'ws/notifications/$', consumers.NotificationConsumer.as_asgi()),
]
