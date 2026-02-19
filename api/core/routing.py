from django.urls import re_path
from api.core import consumers

websocket_urlpatterns = [
    re_path(r'ws/scan/(?P<scan_id>\d+)/$', consumers.ScanProgressConsumer.as_asgi()),
]
