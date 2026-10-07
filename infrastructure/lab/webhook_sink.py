"""TEST LAB ONLY: records webhook POSTs and verifies the X-AIInfra-Signature HMAC.

POST any path  -> stored (body, headers, signature_valid)
GET  /received -> JSON list of everything received so far
Signing secret: env WEBHOOK_SECRET (default "lab-webhook-secret").
"""

import hashlib
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRET = os.environ.get("WEBHOOK_SECRET", "lab-webhook-secret").encode()
RECEIVED: list[dict] = []


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        sig = self.headers.get("X-AIInfra-Signature")
        expected = "sha256=" + hmac.new(SECRET, raw, hashlib.sha256).hexdigest()
        RECEIVED.append({"path": self.path, "event": self.headers.get("X-AIInfra-Event"),
                         "signature_valid": hmac.compare_digest(sig, expected) if sig else None,
                         "body": json.loads(raw or b"null")})
        print(f"webhook {self.path} sig_valid={RECEIVED[-1]['signature_valid']}", flush=True)
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        data = json.dumps(RECEIVED, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    print("webhook sink :9000", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 9000), H).serve_forever()
