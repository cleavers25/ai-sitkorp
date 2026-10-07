"""TEST LAB ONLY: a fake Wazuh 4.14 Server API (:55000) + Indexer (:9200) over plain HTTP.

Answers with the response shapes from the Wazuh documentation so the integration can be
demonstrated without a real Wazuh. Agent 001 is named "lab-target" so it auto-maps to the lab
server. Credentials: API wazuh-wui / lab-api-pass, Indexer admin / lab-idx-pass.
Never use as a real Wazuh.
"""

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = "lab-jwt-token"
API_CREDS = ("wazuh-wui", "lab-api-pass")
IDX_CREDS = ("admin", "lab-idx-pass")
POLLS = {"count": 0}


def alert(rule_id, level, desc, log, srcip=None, agent=("001", "lab-target")):
    return {"_source": {"timestamp": "2026-09-25T10:00:00.000+0000", "agent": {"id": agent[0], "name": agent[1]},
                        "rule": {"id": rule_id, "level": level, "description": desc, "groups": ["web", "attack"]},
                        "data": {"srcip": srcip} if srcip else {}, "full_log": log}}


def basic(headers) -> tuple[str, str] | None:
    h = headers.get("Authorization", "")
    if not h.startswith("Basic "):
        return None
    user, _, pw = base64.b64decode(h[6:]).decode().partition(":")
    return user, pw


def api(method: str, path: str, headers) -> tuple[int, object]:
    if path.startswith("/security/user/authenticate"):
        return (200, TOKEN) if basic(headers) == API_CREDS else (401, {"title": "Unauthorized"})
    if headers.get("Authorization") != f"Bearer {TOKEN}":
        return 401, {"title": "Unauthorized"}
    path = path.split("?")[0]
    if path == "/":
        return 200, {"data": {"title": "Wazuh API REST", "api_version": "4.14.5"}, "error": 0}
    if path == "/agents":
        items = [
            {"id": "000", "name": "wazuh-manager", "ip": "127.0.0.1", "status": "active"},
            {"id": "001", "name": "lab-target", "ip": "172.18.0.10", "status": "active",
             "os": {"name": "Debian GNU/Linux", "version": "12"}, "version": "Wazuh v4.14.5", "group": ["web"],
             "lastKeepAlive": "2026-09-25T10:00:00+00:00"},
            {"id": "002", "name": "db-kantor-01", "ip": "10.10.0.9", "status": "disconnected",
             "os": {"name": "Ubuntu", "version": "22.04"}, "version": "Wazuh v4.14.5", "group": ["default"]},
        ]
        return 200, {"data": {"affected_items": items, "total_affected_items": 3, "failed_items": []}, "error": 0}
    if path.startswith("/sca/"):
        return 200, {"data": {"affected_items": [
            {"policy_id": "cis_debian12", "name": "CIS Debian Linux 12 Benchmark", "pass": 96, "fail": 104,
             "invalid": 0, "total_checks": 200, "score": 48, "end_scan": "2026-09-25T09:00:00+00:00"}],
            "total_affected_items": 1}, "error": 0}
    return 404, {"title": "Not Found"}


def indexer(method: str, path: str, headers, body: dict) -> tuple[int, object]:
    if basic(headers) != IDX_CREDS:
        return 401, {"error": "Unauthorized"}
    if path == "/":
        return 200, {"cluster_name": "wazuh-lab", "version": {"number": "2.19.1", "distribution": "opensearch"}}
    q = json.dumps(body.get("query", {}))
    if "wazuh-states-vulnerabilities" in path:
        return 200, {"hits": {"total": {"value": 5}, "hits": [
            {"_source": {"agent": {"id": "001"}, "package": {"name": "openssl", "version": "3.0.11"},
                         "vulnerability": {"id": "CVE-2025-15467", "severity": "Critical", "score": {"base": 9.8}}}},
            {"_source": {"agent": {"id": "001"}, "package": {"name": "nginx", "version": "1.22.1"},
                         "vulnerability": {"id": "CVE-2025-23419", "severity": "High", "score": {"base": 7.5}}}}]},
            "aggregations": {"by_severity": {"buckets": [{"key": "Critical", "doc_count": 1},
                                                         {"key": "High", "doc_count": 4}]}}}
    if "multi_match" in q:
        return 200, {"hits": {"total": {"value": 2}, "hits": [
            alert("31151", 10, "Multiple web server 400 errors from same source", "GET /wp-login.php", "203.0.113.9")]},
            "aggregations": {"agents": {"buckets": [{"key": "lab-target", "doc_count": 2}]}}}
    if "syscheck" in q:
        return 200, {"hits": {"hits": [
            {"_source": {"timestamp": "2026-09-25T03:00:00Z", "syscheck": {
                "path": "/var/www/toko-batik/wp-content/uploads/2026/shell.php", "event": "added", "sha256_after": "ab" * 32}}},
            {"_source": {"timestamp": "2026-09-25T03:01:00Z", "syscheck": {"path": "/etc/hosts", "event": "modified"}}}]}}
    if "multi_terms" in json.dumps(body.get("aggs", {})):
        POLLS["count"] += 1
        buckets = [] if POLLS["count"] > 1 else [  # one burst, then quiet (no repeat notifications)
            {"key": ["001", "31106"], "doc_count": 4, "max_level": {"value": 12},
             "latest": {"hits": {"hits": [alert("31106", 12, "A web attack returned code 200 (success)",
                                                "GET /wp-content/uploads/2026/shell.php?cmd=id HTTP/1.1 200", "203.0.113.9")]}}}]
        return 200, {"aggregations": {"pairs": {"buckets": buckets}}}
    return 200, {"hits": {"total": {"value": 9}, "hits": []}, "aggregations": {"rules": {"buckets": [
        {"key": "31106", "doc_count": 4, "max_level": {"value": 12},
         "latest": {"hits": {"hits": [alert("31106", 12, "A web attack returned code 200 (success)",
                                            "GET /wp-content/uploads/2026/shell.php?cmd=id", "203.0.113.9")]}}},
        {"key": "5712", "doc_count": 5, "max_level": {"value": 10},
         "latest": {"hits": {"hits": [alert("5712", 10, "sshd: brute force trying to get access to the system",
                                            "Invalid user admin from 198.51.100.7", "198.51.100.7")]}}}]}}}


def handler(route):
    class H(BaseHTTPRequestHandler):
        def _go(self, method):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            body = json.loads(raw) if raw else {}
            code, out = route(method, self.path, self.headers, body)
            data = out.encode() if isinstance(out, str) else json.dumps(out).encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/plain" if isinstance(out, str) else "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._go("GET")

        def do_POST(self):
            self._go("POST")

    return H


if __name__ == "__main__":
    idx = ThreadingHTTPServer(("0.0.0.0", 9200), handler(indexer))
    threading.Thread(target=idx.serve_forever, daemon=True).start()
    print("fake wazuh: API :55000, indexer :9200", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 55000), handler(lambda m, p, h, b: api(m, p, h))).serve_forever()
