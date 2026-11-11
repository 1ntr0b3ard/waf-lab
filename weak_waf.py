#!/usr/bin/env python3
"""
WeakWAF — intentionally naive reverse proxy for WAF-bypass practice.

Deliberate weaknesses (each maps to a playbook technique):
  1. Case-sensitive substring matching           -> T2 (case variation)
  2. Literal keywords only (no normalization)    -> T2 (comment injection)
  3. Only the FIRST value of a parameter is checked -> T3 (HPP)
  4. Only GET/POST are inspected                 -> T5 (method obfuscation)
  5. No decoding/normalization of body           -> T1 (encoding)
  6. Checks only query/body, not headers         -> T7 (header tricks)

DO NOT use this outside an isolated lab.
"""
import http.client
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

BACKEND = os.environ.get("BACKEND", "dvwa:80")
BACKEND_HOST, _, BACKEND_PORT = BACKEND.partition(":")
BACKEND_PORT = int(BACKEND_PORT or "80")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8080"))

RULES = [
    r for r in os.environ.get(
        "WEAK_RULES",
        "UNION SELECT|<script>|' OR '1'='1|../|etc/passwd",
    ).split("|")
    if r
]

INSPECTED_METHODS = {"GET", "POST"}


def first_values(encoded: str):
    """Return only the FIRST value of each parameter (HPP weakness)."""
    parsed = parse_qs(encoded, keep_blank_values=True)
    return [values[0] for values in parsed.values()]


def is_blocked(method: str, path: str, body: bytes) -> bool:
    # Weakness 4: only GET/POST are inspected
    if method.upper() not in INSPECTED_METHODS:
        return False

    parts = urlsplit(path)
    values = first_values(parts.query)              # Weakness 3 (HPP)
    if method.upper() == "POST":
        values += first_values(body.decode("utf-8", "replace"))

    # Weakness 1/2/5: literal, case-sensitive, no normalization
    return any(rule in value for value in values for rule in RULES)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_any(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""

        if is_blocked(self.command, self.path, body):
            msg = b"WeakWAF: blocked by naive literal signature\n"
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)
            return

        headers = {
            k: v for k, v in self.headers.items()
            if k.lower() not in ("host", "content-length", "connection")
        }
        headers["Connection"] = "close"

        try:
            conn = http.client.HTTPConnection(BACKEND_HOST, BACKEND_PORT, timeout=20)
            conn.request(self.command, self.path, body=body or None, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
        except Exception as exc:                     # noqa: BLE001
            msg = f"WeakWAF backend error: {exc}\n".encode()
            self.send_response(502)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)
            return

        self.send_response(resp.status)
        skip = {"transfer-encoding", "connection", "content-length"}
        for key, value in resp.getheaders():
            if key.lower() not in skip:
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)
        conn.close()

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = do_any

    def log_message(self, fmt, *args):               # keep container logs tidy
        sys.stderr.write("weakwaf: %s - %s\n" % (self.address_string(), fmt % args))


if __name__ == "__main__":
    print(f"WeakWAF on :{LISTEN_PORT} -> {BACKEND_HOST}:{BACKEND_PORT}", flush=True)
    print(f"WeakWAF literal rules: {RULES}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler).serve_forever()
