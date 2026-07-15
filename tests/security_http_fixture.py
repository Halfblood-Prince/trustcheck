from __future__ import annotations

import base64
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import parse


class SecurityHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = parse.urlsplit(self.path)
        route = parsed.path.rstrip("/") or "/"
        query = parse.parse_qs(parsed.query)

        if route == "/auth":
            expected = "Basic " + base64.b64encode(b"user:pass").decode("ascii")
            if self.headers.get("Authorization") != expected:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="trustcheck"')
                self.end_headers()
                return
            self._send_json(b'{"meta":{"api-version":"1.0"},"files":[]}')
            return

        if route == "/redirect":
            target = query.get("target", ["file:///tmp/demo.whl"])[0]
            self.send_response(302)
            self.send_header("Location", target)
            self.end_headers()
            return

        if route == "/oversized":
            self.send_response(200)
            self.send_header("Content-Length", "1048577")
            self.end_headers()
            self.wfile.write(b"x" * 1024)
            return

        if route == "/incorrect-length":
            self.send_response(200)
            self.send_header("Content-Length", "1")
            self.end_headers()
            self.wfile.write(b"short")
            return

        if route == "/chunked":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for chunk in (b"chunk", b"-body"):
                self.wfile.write(f"{len(chunk):x}\r\n".encode("ascii"))
                self.wfile.write(chunk + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
            return

        if route == "/slow":
            time.sleep(0.02)
            self._send_json(b'{"meta":{"api-version":"1.0"},"files":[]}')
            return

        if route == "/malformed-json":
            self._send_json(b"{bad")
            return

        if route == "/malformed-html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><a href='demo-1.0.whl'")
            return

        if route.endswith(".metadata"):
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            self.wfile.write(b"Metadata-Version: 2.3\nName: demo\n")
            return

        if route.endswith(".provenance"):
            self._send_json(b'{"provenance":[]}')
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        del format, args

    def _send_json(self, payload: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/vnd.pypi.simple.v1+json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@contextmanager
def security_http_server() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), SecurityHTTPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
