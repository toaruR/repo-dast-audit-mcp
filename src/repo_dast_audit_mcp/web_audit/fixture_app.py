"""Synthetic paired fixture. Never used as evidence about an unrelated project."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
import html
import json
import os
import secrets

PATCHED = os.environ.get("LAB_PATCHED") == "1"
NONCE = os.environ.get("LAB_NONCE", "fixture")
SESSIONS = {}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def send(self, status, value, cookie=None):
        body = json.dumps(value).encode() if isinstance(value, dict) else value.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json" if isinstance(value, dict) else "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", "lab_session=" + cookie + "; HttpOnly; SameSite=Strict; Path=/")
        if cookie:
            self.send_header("Location", "/orders")
        self.end_headers()
        self.wfile.write(body)

    def actor(self):
        cookie = self.headers.get("Cookie", "")
        return SESSIONS.get(cookie.split("lab_session=")[-1].split(";")[0], "anonymous")

    def do_GET(self):
        url = urlsplit(self.path)
        if url.path == "/login":
            self.send(200, '<form method="post" action="/login"><input id="username" name="username"><input id="password" name="password" type="password"><button id="login" type="submit">Login</button></form>')
        elif url.path == "/identity":
            self.send(200, {"user": self.actor()})
        elif url.path == "/orders":
            self.send(200, '<a id="order" href="/api/orders/2">Order B</a><form action="/search"><input id="search" name="q"><button id="search_submit">Search</button></form>')
        elif url.path.startswith("/api/orders/"):
            resource = url.path.rsplit("/", 1)[-1]
            if resource not in ("1", "2"):
                self.send(404, {"error": "missing"})
            elif self.actor() == "anonymous" or (PATCHED and self.actor() not in ("admin", "user_a" if resource == "1" else "user_b")):
                self.send(403, {"error": "forbidden"})
            else:
                self.send(200, {"id": resource, "marker": NONCE + "-order_" + ("a" if resource == "1" else "b")})
        elif url.path == "/search":
            q = parse_qs(url.query).get("q", [""])[0]
            self.send(200, "<html><body>Search: " + (html.escape(q) if PATCHED else q) + "</body></html>")
        elif url.path == "/health":
            self.send(200, {"ok": True})
        else:
            self.send(404, {"error": "missing"})

    def do_POST(self):
        body = self.rfile.read(min(int(self.headers.get("Content-Length", "0")), 8192))
        if self.path == "/login":
            fields = parse_qs(body.decode())
            actor = fields.get("username", [""])[0]
            if actor in ("user_a", "user_b", "admin") and fields.get("password") == ["fixture-only"]:
                token = secrets.token_hex(16)
                SESSIONS[token] = actor
                self.send(302, {"user": actor}, cookie=token)
            else:
                self.send(403, {"error": "login"})
        elif self.path == "/discount":
            if self.actor() == "anonymous":
                self.send(403, {"error": "login"})
                return
            try:
                percent = int(json.loads(body)["percent"])
            except (ValueError, KeyError):
                self.send(400, {"error": "input"})
                return
            if PATCHED and not 0 <= percent <= 100:
                self.send(400, {"error": "discount"})
            else:
                self.send(200, {"price": 100 - percent})
        else:
            self.send(404, {"error": "missing"})

if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("LAB_PORT", "8000"))), Handler).serve_forever()
