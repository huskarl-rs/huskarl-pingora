#!/usr/bin/env python3
"""Loopback-only upstream for the browser-login tutorial; not a production server."""

from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        subject = self.headers.get("X-Authenticated-Subject")
        if path == "/health":
            self.respond(200, "ok", "text/plain")
        elif path == "/signed-out":
            self.respond(200, '<h1>You are signed out</h1><a href="/dashboard">Sign in again</a>')
        elif path == "/":
            self.respond(200, '<h1>Login demo</h1><a href="/dashboard">Sign in</a>')
        elif path == "/dashboard":
            if not subject:
                self.respond(401, "No trusted proxy identity", "text/plain")
                return
            self.respond(
                200,
                "<h1>You are signed in</h1><p>Subject: " + escape(subject) + "</p>"
                '<form method="post" action="/logout"><button>Sign out</button></form>',
            )
        else:
            self.respond(404, "Not found", "text/plain")

    def respond(self, status, content, content_type="text/html"):
        body = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Do not log arbitrary request URLs or headers in the example.
        pass


if __name__ == "__main__":
    print("Demo upstream listening on 127.0.0.1:3001", flush=True)
    ThreadingHTTPServer(("127.0.0.1", 3001), Handler).serve_forever()
