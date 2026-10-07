"""Tiny web server for the test lab: serves /var/www/site and cloaks spam for Googlebot."""

from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

SPAM = b"""<html><head><title>Toko Batik Lab</title></head><body>
<h1>Toko Batik</h1><p>Situs slot gacor maxwin hari ini, daftar togel online terpercaya.</p>
</body></html>"""


class Handler(SimpleHTTPRequestHandler):
    server_version = "nginx/1.18.0"  # pretend, to exercise the version-disclosure check
    sys_version = ""

    def do_GET(self):
        if self.path == "/" and "Googlebot" in self.headers.get("User-Agent", ""):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(SPAM)))
            self.end_headers()
            self.wfile.write(SPAM)
            return
        super().do_GET()


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), partial(Handler, directory="/var/www/site")).serve_forever()
