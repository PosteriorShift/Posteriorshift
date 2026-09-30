from http.server import BaseHTTPRequestHandler
import json
import os
from api._firebase import send_push

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.headers.get("x-notify-secret") != os.environ.get("NOTIFY_SECRET"):
            self.send_response(401); self.end_headers(); return

        length = int(self.headers.get("content-length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")

        title = body.get("title"); text = body.get("body")
        if not title or not text:
            self.send_response(400); self.end_headers(); return

        token = body.get("token")
        if not token:
            self.send_response(400); self.end_headers(); return

        send_push(token, title, text, body.get("priority", "high"))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')
