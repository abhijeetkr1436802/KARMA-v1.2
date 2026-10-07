"""Management authentication and bounded HTTP request handling."""
import asyncio
import hashlib
import hmac
import ipaddress
import os
import secrets
import time
from collections import OrderedDict, deque
from urllib.parse import urlsplit
from starlette.responses import JSONResponse, RedirectResponse
from backend import config

COOKIE_NAME = "karma_session"
SESSION_SECONDS = 8 * 60 * 60


def load_admin_token():
    token = config.ADMIN_TOKEN
    if config.PRODUCTION and (len(token) < 32 or not config.COOKIE_SECURE):
        raise RuntimeError("Production requires KARMA_ADMIN_TOKEN (32+ characters) and secure cookies")
    if not token:
        config.DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = config.ADMIN_TOKEN_FILE
        try:
            with open(path, "x", encoding="utf-8", opener=lambda p, f: os.open(p, f, 0o600)) as file:
                file.write(secrets.token_urlsafe(32))
        except FileExistsError:
            pass
        token = path.read_text(encoding="utf-8").strip()
    if len(token) < 32:
        raise RuntimeError("Admin token must contain at least 32 characters")
    return token


def session_value(token):
    expires = str(int(time.time()) + SESSION_SECONDS)
    signature = hmac.new(token.encode(), expires.encode(), hashlib.sha256).hexdigest()
    return expires + "." + signature


def authenticated(headers, token):
    auth = headers.get("authorization", "")
    if auth.startswith("Bearer ") and secrets.compare_digest(auth[7:], token):
        return True
    from http.cookies import SimpleCookie
    cookie = SimpleCookie()
    try:
        cookie.load(headers.get("cookie", ""))
        value = cookie[COOKIE_NAME].value
        expires, signature = value.split(".", 1)
        expected = hmac.new(token.encode(), expires.encode(), hashlib.sha256).hexdigest()
        return 0 < int(expires) - time.time() <= SESSION_SECONDS and hmac.compare_digest(signature, expected)
    except (KeyError, ValueError, TypeError):
        return False


def same_origin(headers, scheme):
    origin = headers.get("origin")
    if not origin:
        return True  # Non-browser clients still require a bearer token or CSRF header.
    try:
        parsed = urlsplit(origin)
        return parsed.scheme == scheme and parsed.netloc == headers.get("host", "")
    except ValueError:
        return False


class RequestGuard:
    """Limit actual streamed bytes, requests, hosts and cross-origin mutations."""
    def __init__(self, app, management=True):
        self.app = app
        self.management = management
        self.windows = OrderedDict()

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        from starlette.datastructures import Headers
        headers = Headers(scope=scope)
        websocket = scope["type"] == "websocket"
        async def reject(status, detail):
            if websocket:
                await send({"type": "websocket.close", "code": 1008})
            else:
                await JSONResponse({"detail": detail}, status_code=status)(scope, receive, send)
        path = scope["path"]
        if self.management:
            if not config.PRODUCTION:
                try:
                    local = ipaddress.ip_address((scope.get("client") or ("", 0))[0]).is_loopback
                except ValueError:
                    local = False
                if not local:
                    return await reject(403, "Remote management requires production HTTPS configuration")
            host = headers.get("host", "").lower()
            try:
                hostname = urlsplit("//" + host).hostname
            except ValueError:
                return await reject(400, "Invalid host")
            allowed = {h.strip().strip("[]").lower() for h in config.ALLOWED_HOSTS}
            if hostname not in allowed:
                return await reject(400, "Unrecognized host")
            scheme = "https" if scope["scheme"] in ("https", "wss") else "http"
            if not same_origin(headers, scheme):
                return await reject(403, "Cross-origin access denied")
            if config.PRODUCTION and scheme != "https":
                return await reject(400, "HTTPS is required")
            public = path in {"/login", "/healthz"}
            if not public and not authenticated(headers, scope["app"].state.admin_token):
                if not websocket and path == "/":
                    return await RedirectResponse("/login", status_code=303)(scope, receive, send)
                return await reject(401, "Authentication required")
            if not public and not websocket and scope["method"] not in {"GET", "HEAD", "OPTIONS"}:
                if not headers.get("authorization", "").startswith("Bearer ") and headers.get("x-karma-request") != "1":
                    return await reject(403, "Missing CSRF request header")
        client = (scope.get("client") or ("unknown", 0))[0]
        key = (client, "login" if path == "/login" and scope.get("method") == "POST" else "request")
        now = time.monotonic()
        window = self.windows.setdefault(key, deque())
        self.windows.move_to_end(key)
        while window and window[0] < now - 60:
            window.popleft()
        limit = 10 if key[1] == "login" else 600
        if len(window) >= limit:
            return await reject(429, "Rate limit exceeded; retry later")
        window.append(now)
        while len(self.windows) > 4096:
            self.windows.popitem(last=False)
        if websocket:
            return await self.app(scope, receive, send)
        # Buffer only up to the enforced cap, including chunked bodies.
        chunks = []
        size = 0
        while True:
            try:
                message = await asyncio.wait_for(receive(), timeout=10)
            except asyncio.TimeoutError:
                return await reject(408, "Request body timeout")
            if message["type"] == "http.disconnect":
                return
            size += len(message.get("body", b""))
            if size > config.MAX_BODY_BYTES:
                return await reject(413, "Request body exceeds 2 MiB")
            chunks.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        delivered = False
        async def body_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()
        async def secure_send(message):
            if message["type"] == "http.response.start":
                message.setdefault("headers", []).extend([
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"cache-control", b"no-store"),
                    (b"content-security-policy", b"frame-ancestors 'none'; object-src 'none'; base-uri 'self'"),
                ])
            await send(message)
        await self.app(scope, body_receive, secure_send)
