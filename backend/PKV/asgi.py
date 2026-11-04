"""
ASGI config for PKV project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/asgi/
"""

import os
from django.core.asgi import get_asgi_application
from django.conf import settings
from django.contrib.staticfiles.handlers import ASGIStaticFilesHandler
from channels.routing import ProtocolTypeRouter, URLRouter

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'PKV.settings')

django_asgi_app = get_asgi_application()

from api.core.channels_middleware import TokenAuthMiddlewareStack  # noqa: E402
from api.core.routing import websocket_urlpatterns  # noqa: E402

application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": TokenAuthMiddlewareStack(
        URLRouter(
            websocket_urlpatterns
        )
    ),
})

application = ASGIStaticFilesHandler(application)

try:
    from api.utils.vector_db import preload_vector_db_async
    preload_vector_db_async()
except Exception:
    pass

