"""
Channels Token Authentication Middleware for ShieldCall VN.
Enables WebSocket connections to authenticate via DRF Token in query params (?token=...)
or Authorization header, falling back to Django session cookies.
"""
from urllib.parse import parse_qs
from channels.db import database_sync_to_async
from channels.auth import AuthMiddlewareStack
from django.contrib.auth.models import AnonymousUser


@database_sync_to_async
def get_user_from_token(token_key):
    if not token_key or not isinstance(token_key, str):
        return AnonymousUser()
    try:
        from rest_framework.authtoken.models import Token
        token = Token.objects.select_related('user').get(key=token_key.strip())
        if token.user.is_active:
            return token.user
        return AnonymousUser()
    except Exception:
        return AnonymousUser()


class TokenAuthMiddleware:
    """
    Middleware that inspects scope for DRF Token in:
    1. Query parameters (?token=...)
    2. 'Authorization: Token ...' header in handshake headers
    If a valid token is found, populates scope['user'] with the corresponding User.
    """
    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "websocket":
            user = scope.get("user")
            if not user or not getattr(user, "is_authenticated", False):
                token_key = None
                # 1. Check query string (?token=...)
                query_string = scope.get("query_string", b"").decode("utf-8")
                if query_string:
                    params = parse_qs(query_string)
                    tokens = params.get("token")
                    if tokens and tokens[0]:
                        token_key = tokens[0]

                # 2. Check authorization header if not in query params
                if not token_key:
                    headers = dict(scope.get("headers", []))
                    auth_header = headers.get(b"authorization", b"").decode("latin-1")
                    if auth_header.startswith("Token "):
                        token_key = auth_header[6:].strip()
                    elif auth_header.startswith("Bearer "):
                        token_key = auth_header[7:].strip()

                if token_key:
                    scope["user"] = await get_user_from_token(token_key)

        return await self.inner(scope, receive, send)


def TokenAuthMiddlewareStack(inner):
    """Combines Channels AuthMiddlewareStack (sessions) with TokenAuthMiddleware (DRF tokens)."""
    return TokenAuthMiddleware(AuthMiddlewareStack(inner))
