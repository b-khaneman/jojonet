#!/usr/bin/env python3
"""Tiny HTTP→HTTPS redirector for JojoNet Panel (binds port 80 as root via systemd)."""

from __future__ import annotations

import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


DOMAIN = _env("JOJONET_PANEL_DOMAIN").lower().rstrip(".")
PATH = _env("JOJONET_PANEL_WEB_PATH") or _env("JOJONET_PANEL_PATH") or "/jojonet-panel-entry"
if PATH and not PATH.startswith("/"):
    PATH = "/" + PATH
PATH = "/" + PATH.strip("/")
if PATH == "/":
    PATH = "/jojonet-panel-entry"
PORT = int(_env("JOJONET_PANEL_HTTP_PORT", "80") or "80")
BIND = _env("JOJONET_PANEL_HTTP_BIND", "0.0.0.0") or "0.0.0.0"


def target_url(path: str, query: str) -> str:
    # Always land on the panel entry; keep query string when present.
    loc = f"https://{DOMAIN}{PATH}/"
    if query:
        loc = f"{loc}?{query}"
    return loc


class RedirectHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _redirect(self) -> None:
        if not DOMAIN:
            self.send_error(503, "JOJONET_PANEL_DOMAIN is not set")
            return
        q = ""
        if "?" in (self.path or ""):
            q = (self.path or "").split("?", 1)[1]
        loc = target_url(self.path or "/", q)
        body = f'<a href="{loc}">Moved permanently</a>\n'.encode("ascii", "replace")
        self.send_response(301)
        self.send_header("Location", loc)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        self._redirect()

    def do_HEAD(self) -> None:  # noqa: N802
        self._redirect()

    def do_POST(self) -> None:  # noqa: N802
        self._redirect()

    def log_message(self, fmt: str, *args) -> None:  # noqa: ANN002
        return


def main() -> int:
    if not DOMAIN:
        print("JOJONET_PANEL_DOMAIN is required", file=sys.stderr)
        return 2
    server = ThreadingHTTPServer((BIND, PORT), RedirectHandler)
    print(f"jojonet-panel-http: redirecting :{PORT} → https://{DOMAIN}{PATH}/", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
