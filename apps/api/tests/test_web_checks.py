import asyncio
from datetime import datetime, timedelta, timezone

import httpx

from app.assessment import web_checks as wc
from app.core.enums import CheckStatus, Severity

NOW = datetime(2026, 9, 24, tzinfo=timezone.utc)
HOME = "<html><head><title>Toko Batik</title></head><body>Selamat datang</body></html>"
SPAM = "<html><body>Selamat datang <a href='x'>slot gacor maxwin</a> togel hari ini</body></html>"


def site(routes: dict, *, soft404: bool = False, cloak: bool = False, headers: dict | None = None):
    """Build a fake website. routes: path -> (status, body, extra headers)."""
    base_headers = {"content-type": "text/html", **(headers or {})}

    def handler(request: httpx.Request):
        path = request.url.path
        if request.url.scheme == "http":
            return httpx.Response(301, headers={"location": str(request.url.copy_with(scheme="https"))})
        if path == "/" and cloak and "Googlebot" in request.headers.get("user-agent", ""):
            return httpx.Response(200, text=SPAM, headers=base_headers)
        if path in routes:
            status, body, extra = routes[path]
            return httpx.Response(status, text=body, headers={**base_headers, **extra})
        if soft404:
            return httpx.Response(200, text=HOME, headers=base_headers)
        return httpx.Response(404, text="not found", headers=base_headers)

    return wc.make_client(httpx.MockTransport(handler))


async def _no_tls(host, port):
    return wc.TLSInfo(True, None, NOW + timedelta(days=90), host, "R3", [host], "TLSv1.3", "TLS_AES_128_GCM_SHA256")


def run(client, url="https://toko.example/"):
    async def go():
        async with client:
            return await wc.run_web_checks(url, client, prober=_no_tls)
    return asyncio.run(go())


def by(results, check):
    return [r for r in results if r.check == check]


SECURE = {"strict-transport-security": "max-age=31536000", "x-content-type-options": "nosniff",
          "content-security-policy": "default-src 'self'; frame-ancestors 'none'", "referrer-policy": "no-referrer"}


def test_clean_site_is_all_pass():
    results = run(site({"/": (200, HOME, {})}, headers=SECURE))
    issues = [r for r in results if r.is_issue]
    assert issues == [], [(r.check, r.title) for r in issues]
    assert by(results, "https_redirect")[0].status == CheckStatus.PASS


def test_soft_404_site_has_no_exposed_file_false_positives():
    results = run(site({"/": (200, HOME, {})}, soft404=True, headers=SECURE))
    assert not [r for r in by(results, "exposed_file") if r.is_issue]
    assert not [r for r in by(results, "directory_listing") if r.is_issue]


def test_exposed_env_git_and_listing():
    results = run(site({
        "/": (200, HOME, {}),
        "/.env": (200, "APP_NAME=Toko\nAPP_KEY=base64:abc\nDB_PASSWORD=secret123\n", {"content-type": "text/plain"}),
        "/.git/HEAD": (200, "ref: refs/heads/main\n", {"content-type": "text/plain"}),
        "/wp-content/uploads/": (200, "<html><title>Index of /wp-content/uploads</title></html>", {}),
    }, headers=SECURE))
    exposed = {r.value: r for r in by(results, "exposed_file") if r.is_issue}
    assert exposed["/.env"].severity == Severity.CRITICAL
    assert exposed["/.git/HEAD"].severity == Severity.HIGH
    [listing] = [r for r in by(results, "directory_listing") if r.is_issue]
    assert listing.target.endswith("/wp-content/uploads/")


def test_cloaked_gambling_spam_detected():
    results = run(site({"/": (200, HOME, {})}, cloak=True, headers=SECURE))
    [cloak] = by(results, "seo_cloaking")
    assert cloak.severity == Severity.CRITICAL and "slot gacor" in cloak.value
    assert not by(results, "content_injection")[0].is_issue  # normal visitors see a clean page


def test_visible_spam_and_hidden_iframe():
    page = SPAM.replace("</body>", "<iframe src='http://evil.example' width=0 height=0></iframe></body>")
    results = run(site({"/": (200, page, {})}, headers=SECURE))
    assert by(results, "content_injection")[0].severity == Severity.HIGH
    assert by(results, "suspicious_markup")[0].is_issue


def test_redirect_to_foreign_domain_and_missing_headers():
    def handler(request):
        if request.url.host == "toko.example":
            return httpx.Response(302, headers={"location": "https://slot-gacor.example/"})
        return httpx.Response(200, text=HOME, headers={"server": "nginx/1.18.0", "x-powered-by": "PHP/7.4.3"})

    results = run(wc.make_client(httpx.MockTransport(handler)))
    assert by(results, "unexpected_redirect")[0].severity == Severity.HIGH
    assert by(results, "security_headers")[0].is_issue
    assert "nginx/1.18.0" in by(results, "server_exposure")[0].value


def test_site_down():
    def handler(request):
        raise httpx.ConnectError("connection refused")

    results = run(wc.make_client(httpx.MockTransport(handler)))
    assert by(results, "http_availability")[0].severity == Severity.HIGH
    assert by(results, "content_injection")[0].status == CheckStatus.SKIPPED


def test_same_site():
    assert wc.same_site("https://example.com/", "https://www.example.com/home")
    assert wc.same_site("https://shop.example.com/", "https://example.com/")
    assert not wc.same_site("https://example.com/", "https://example.com.evil.net/")


def _tls(days, verified=True, version="TLSv1.3"):
    return wc.TLSInfo(verified, None if verified else "hostname mismatch", NOW + timedelta(days=days),
                      "x", "R3", ["x"], version, "c")


def test_tls_thresholds():
    ev = lambda info: wc.eval_tls("https://x/", info, now=NOW)[0]  # noqa: E731
    assert ev(_tls(90)).status == CheckStatus.PASS
    assert ev(_tls(20)).severity == Severity.MEDIUM
    assert ev(_tls(3)).severity == Severity.HIGH
    assert "kedaluwarsa" in ev(_tls(-2)).title and ev(_tls(-2)).severity == Severity.HIGH
    assert ev(_tls(90, verified=False)).severity == Severity.HIGH
    old = wc.eval_tls("https://x/", _tls(90, version="TLSv1.1"), now=NOW)[1]
    assert old.is_issue and old.severity == Severity.MEDIUM
