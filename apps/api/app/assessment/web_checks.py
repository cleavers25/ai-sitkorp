"""Website checks run from the management server (PRD 9.2, 10).

All web content is untrusted: it is only pattern-matched and clipped into evidence,
never interpreted.
"""

import asyncio
import re
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import httpx
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from app.assessment.server_checks import timed
from app.assessment.types import CheckResult, clip, issue, passed, skipped
from app.core.redaction import redact_text
from app.core.enums import FindingCategory as C
from app.core.enums import Severity as S

USER_AGENT = "Mozilla/5.0 (compatible; AIInfraAssistant/0.2; +internal-security-assessment)"
GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
BODY_LIMIT = 256 * 1024
PROBE_LIMIT = 64 * 1024
SLOW_SECONDS = 3.0


@dataclass
class Fetched:
    url: str
    status: int
    headers: httpx.Headers
    body: str
    elapsed: float
    history: list[str]


async def fetch(client: httpx.AsyncClient, url: str, *, follow: bool = True, limit: int = BODY_LIMIT,
                headers: dict | None = None) -> Fetched:
    """GET with a hard cap on how much body is read (a probe may hit a multi-GB dump)."""
    start = time.monotonic()
    async with client.stream("GET", url, follow_redirects=follow, headers=headers) as r:
        chunks, size = [], 0
        async for chunk in r.aiter_bytes():
            chunks.append(chunk)
            size += len(chunk)
            if size >= limit:
                break
        body = b"".join(chunks)[:limit].decode(r.encoding or "utf-8", errors="replace")
        return Fetched(str(r.url), r.status_code, r.headers, body, time.monotonic() - start,
                       [str(h.url) for h in r.history])


def _base_host(host: str) -> str:
    host = (host or "").lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def same_site(a: str, b: str) -> bool:
    ha, hb = _base_host(urlparse(a).hostname or ""), _base_host(urlparse(b).hostname or "")
    return ha == hb or ha.endswith("." + hb) or hb.endswith("." + ha)


# --- HTTP availability / redirects ----------------------------------------

async def check_http(client: httpx.AsyncClient, url: str) -> tuple[list[CheckResult], Fetched | None]:
    try:
        page = await fetch(client, url)
    except httpx.HTTPError as exc:
        return [issue("http_availability", C.WEB, "Website tidak dapat diakses", S.HIGH, target=url,
                      value=type(exc).__name__, evidence={"error": clip(str(exc), 500)},
                      recommendation="Periksa web server, DNS, dan firewall.")], None

    ev = {"status": page.status, "final_url": page.url, "redirects": page.history,
          "response_time_ms": int(page.elapsed * 1000), "server": page.headers.get("server")}
    value = f"HTTP {page.status} · {int(page.elapsed * 1000)} ms"
    results: list[CheckResult] = []
    if page.status >= 500:
        results.append(issue("http_availability", C.WEB, f"Website error (HTTP {page.status})", S.HIGH,
                             target=url, value=value, evidence=ev,
                             recommendation="Periksa log aplikasi dan web server."))
    elif page.status >= 400:
        results.append(issue("http_availability", C.WEB, f"Halaman utama mengembalikan HTTP {page.status}", S.MEDIUM,
                             target=url, value=value, evidence=ev,
                             recommendation="Pastikan URL benar dan halaman utama dapat diakses publik."))
    elif page.elapsed > SLOW_SECONDS:
        results.append(issue("http_availability", C.WEB, "Website lambat merespons", S.LOW, target=url,
                             value=value, evidence=ev, recommendation="Periksa beban server, cache, dan database."))
    else:
        results.append(passed("http_availability", C.WEB, "Website dapat diakses", target=url, value=value, evidence=ev))

    if not same_site(url, page.url):
        results.append(issue(
            "unexpected_redirect", C.MALWARE, "Website mengalihkan ke domain lain", S.HIGH, target=url,
            value=urlparse(page.url).hostname, evidence=ev, confidence=0.6,
            description="Redirect ke domain lain bisa disengaja, tetapi juga pola umum website yang disusupi "
                        "(redirect ke situs judi/spam).",
            recommendation="Pastikan redirect ini memang disengaja. Jika tidak, periksa .htaccess, konfigurasi "
                           "web server, dan file PHP yang baru berubah."))
    else:
        results.append(passed("unexpected_redirect", C.MALWARE, "Tidak ada redirect ke domain lain", target=url))
    return results, page


async def check_https_redirect(client: httpx.AsyncClient, url: str) -> list[CheckResult]:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return [issue("https_redirect", C.SSL, "Website tidak memakai HTTPS", S.MEDIUM, target=url,
                      recommendation="Pasang sertifikat TLS (mis. Let's Encrypt) dan alihkan HTTP ke HTTPS.")]
    http_url = parsed._replace(scheme="http").geturl()
    try:
        page = await fetch(client, http_url, limit=4096)
    except httpx.HTTPError:
        return [passed("https_redirect", C.SSL, "Port HTTP tidak melayani konten (hanya HTTPS)", target=http_url)]
    if page.url.startswith("https://"):
        return [passed("https_redirect", C.SSL, "HTTP dialihkan ke HTTPS", target=http_url)]
    return [issue("https_redirect", C.SSL, "HTTP tidak dialihkan ke HTTPS", S.LOW, target=http_url,
                  evidence={"final_url": page.url, "status": page.status},
                  recommendation="Tambahkan redirect 301 dari HTTP ke HTTPS.")]


# --- headers ---------------------------------------------------------------

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "x-content-type-options": "X-Content-Type-Options",
    "content-security-policy": "Content-Security-Policy",
    "referrer-policy": "Referrer-Policy",
}
VERSION_LEAK = re.compile(r"\d+\.\d+")


def eval_headers(url: str, headers: httpx.Headers) -> list[CheckResult]:
    results = []
    missing = [name for key, name in SECURITY_HEADERS.items()
               if key not in headers and not (key == "strict-transport-security" and not url.startswith("https"))]
    csp = headers.get("content-security-policy", "")
    if "x-frame-options" not in headers and "frame-ancestors" not in csp:
        missing.append("X-Frame-Options / frame-ancestors")
    if missing:
        results.append(issue("security_headers", C.CONFIGURATION, f"{len(missing)} security header tidak dipasang",
                             S.LOW, target=url, value=", ".join(missing)[:255], evidence={"missing": missing},
                             recommendation="Tambahkan header keamanan di konfigurasi web server."))
    else:
        results.append(passed("security_headers", C.CONFIGURATION, "Security header lengkap", target=url))

    leaks = {h: headers[h] for h in ("server", "x-powered-by", "x-aspnet-version")
             if h in headers and VERSION_LEAK.search(headers[h])}
    if leaks:
        results.append(issue("server_exposure", C.CONFIGURATION, "Versi software terlihat di header HTTP", S.LOW,
                             target=url, value="; ".join(f"{k}: {v}" for k, v in leaks.items())[:255],
                             evidence=leaks,
                             recommendation="Sembunyikan versi (nginx: server_tokens off; PHP: expose_php = Off)."))
    else:
        results.append(passed("server_exposure", C.CONFIGURATION, "Versi software tidak diumumkan", target=url))
    return results


# --- TLS certificate -------------------------------------------------------

@dataclass
class TLSInfo:
    verified: bool
    verify_error: str | None
    not_after: datetime
    subject_cn: str | None
    issuer: str | None
    san: list[str]
    tls_version: str | None
    cipher: str | None


def _probe_tls_sync(host: str, port: int, timeout: float) -> TLSInfo:
    verify_error = None
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der, version, cipher = tls.getpeercert(binary_form=True), tls.version(), tls.cipher()
    except ssl.SSLCertVerificationError as exc:
        verify_error = exc.verify_message or str(exc)
        insecure = ssl.create_default_context()
        insecure.check_hostname = False
        insecure.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with insecure.wrap_socket(sock, server_hostname=host) as tls:
                der, version, cipher = tls.getpeercert(binary_form=True), tls.version(), tls.cipher()

    cert = x509.load_der_x509_certificate(der)
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME) or \
        cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        names = san.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        names = []
    return TLSInfo(
        verified=verify_error is None, verify_error=verify_error,
        not_after=cert.not_valid_after_utc,
        subject_cn=str(cn[0].value) if cn else None,
        issuer=str(issuer_cn[0].value) if issuer_cn else None,
        san=list(names), tls_version=version, cipher=cipher[0] if cipher else None,
    )


async def probe_tls(host: str, port: int, timeout: float = 10) -> TLSInfo:
    return await asyncio.to_thread(_probe_tls_sync, host, port, timeout)


def eval_tls(url: str, info: TLSInfo, now: datetime | None = None) -> list[CheckResult]:
    now = now or datetime.now(timezone.utc)
    days = (info.not_after - now).days
    ev = {"subject": info.subject_cn, "issuer": info.issuer, "san": info.san[:20],
          "not_after": info.not_after.isoformat(), "days_left": days,
          "tls_version": info.tls_version, "cipher": info.cipher, "verify_error": info.verify_error}
    renew = "Perpanjang sertifikat (aktifkan auto-renew certbot/acme bila memakai Let's Encrypt)."
    results = []
    if days < 0:
        results.append(issue("ssl_certificate", C.SSL, f"Sertifikat SSL sudah kedaluwarsa ({-days} hari lalu)",
                             S.HIGH, target=url, value=f"{days} hari", evidence=ev, recommendation=renew))
    elif not info.verified:
        results.append(issue("ssl_certificate", C.SSL, "Sertifikat SSL tidak valid", S.HIGH, target=url,
                             value=clip(info.verify_error, 255), evidence=ev,
                             recommendation="Pasang sertifikat dari CA terpercaya yang mencakup hostname ini, "
                                            "lengkap dengan intermediate chain."))
    elif days < 7:
        results.append(issue("ssl_certificate", C.SSL, f"Sertifikat SSL kedaluwarsa dalam {days} hari", S.HIGH,
                             target=url, value=f"{days} hari", evidence=ev, recommendation=renew))
    elif days < 30:
        results.append(issue("ssl_certificate", C.SSL, f"Sertifikat SSL kedaluwarsa dalam {days} hari", S.MEDIUM,
                             target=url, value=f"{days} hari", evidence=ev, recommendation=renew))
    else:
        results.append(passed("ssl_certificate", C.SSL, f"Sertifikat SSL valid ({days} hari lagi)", target=url,
                              value=f"{days} hari", evidence=ev))

    if info.tls_version in ("TLSv1", "TLSv1.1", "SSLv3"):
        results.append(issue("tls_protocol", C.SSL, f"Protokol TLS usang dipakai ({info.tls_version})", S.MEDIUM,
                             target=url, value=info.tls_version, evidence=ev,
                             recommendation="Nonaktifkan TLS 1.0/1.1; gunakan TLS 1.2 dan 1.3."))
    else:
        results.append(passed("tls_protocol", C.SSL, f"Protokol TLS modern ({info.tls_version})", target=url,
                              value=info.tls_version))
    return results


async def check_tls(url: str, prober=probe_tls) -> list[CheckResult]:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return [skipped("ssl_certificate", C.SSL, "Website tidak memakai HTTPS")]
    try:
        info = await prober(parsed.hostname, parsed.port or 443)
    except (OSError, ssl.SSLError) as exc:
        return [issue("ssl_certificate", C.SSL, "Koneksi TLS gagal", S.HIGH, target=url,
                      value=type(exc).__name__, evidence={"error": clip(str(exc), 500)},
                      recommendation="Periksa konfigurasi TLS di web server.")]
    return eval_tls(url, info)


# --- exposed files / directory listing -------------------------------------

_SQL = re.compile(r"(CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump)", re.I)
_PHPCONF = re.compile(r"(DB_PASSWORD|DB_USER|\$db_pass|define\(\s*['\"]DB_)", re.I)
_PHPINFO = re.compile(r"phpinfo\(\)|<title>PHP \d", re.I)

# (path, validator, severity, title). A probe only counts when the body *looks like* the file,
# which also defeats "soft 404" sites that answer 200 for every path.
PROBES = [
    ("/.env", lambda b: re.search(r"^\s*(APP_KEY|DB_PASSWORD|DB_HOST|DATABASE_URL|SECRET_KEY|AWS_SECRET_ACCESS_KEY|MAIL_PASSWORD)\s*=", b, re.M), S.CRITICAL, "File .env (berisi credential) dapat diunduh publik"),
    ("/.git/HEAD", lambda b: b.startswith("ref: refs/"), S.HIGH, "Repository .git dapat diunduh publik"),
    ("/.git/config", lambda b: "[core]" in b, S.HIGH, "Konfigurasi .git dapat diunduh publik"),
    ("/wp-config.php.bak", lambda b: _PHPCONF.search(b), S.CRITICAL, "Backup wp-config dapat diunduh"),
    ("/wp-config.php~", lambda b: _PHPCONF.search(b), S.CRITICAL, "Backup wp-config dapat diunduh"),
    ("/wp-config.php.save", lambda b: _PHPCONF.search(b), S.CRITICAL, "Backup wp-config dapat diunduh"),
    ("/wp-config.txt", lambda b: _PHPCONF.search(b), S.CRITICAL, "Salinan wp-config dapat diunduh"),
    ("/config.php.bak", lambda b: _PHPCONF.search(b), S.CRITICAL, "Backup config.php dapat diunduh"),
    ("/backup.sql", lambda b: _SQL.search(b), S.CRITICAL, "Dump database dapat diunduh"),
    ("/dump.sql", lambda b: _SQL.search(b), S.CRITICAL, "Dump database dapat diunduh"),
    ("/database.sql", lambda b: _SQL.search(b), S.CRITICAL, "Dump database dapat diunduh"),
    ("/db.sql", lambda b: _SQL.search(b), S.CRITICAL, "Dump database dapat diunduh"),
    ("/phpinfo.php", lambda b: _PHPINFO.search(b), S.MEDIUM, "Halaman phpinfo terbuka"),
    ("/info.php", lambda b: _PHPINFO.search(b), S.MEDIUM, "Halaman phpinfo terbuka"),
    ("/server-status", lambda b: "Apache Server Status" in b, S.MEDIUM, "Apache server-status terbuka"),
    ("/.htpasswd", lambda b: re.match(r"^[\w.-]+:\S{6,}", b), S.HIGH, "File .htpasswd dapat diunduh"),
    ("/wp-content/debug.log", lambda b: re.search(r"PHP (Warning|Notice|Fatal error|Deprecated)", b), S.MEDIUM, "Log debug WordPress terbuka"),
    ("/debug.log", lambda b: re.search(r"PHP (Warning|Notice|Fatal error|Deprecated)", b), S.MEDIUM, "Log debug terbuka"),
]
LISTING_DIRS = ["/wp-content/uploads/", "/uploads/", "/images/", "/files/", "/backup/", "/assets/"]
_LISTING = re.compile(r"<title>\s*Index of /|<h1>\s*Index of /|Directory listing for /", re.I)


async def check_exposed_files(client: httpx.AsyncClient, url: str) -> list[CheckResult]:
    results: list[CheckResult] = []

    async def probe(path: str):
        try:
            return path, await fetch(client, urljoin(url, path), follow=False, limit=PROBE_LIMIT)
        except httpx.HTTPError:
            return path, None

    fetched = await asyncio.gather(*(probe(p) for p, *_ in PROBES))
    for (path, validator, severity, title), (_, page) in zip(PROBES, fetched):
        if page and page.status == 200 and validator(page.body):
            results.append(issue(
                "exposed_file", C.CONFIGURATION, title, severity, target=urljoin(url, path), value=path,
                evidence={"url": urljoin(url, path), "status": page.status,
                          "sample": clip(redact_text(page.body), 300)},
                recommendation=f"Hapus/pindahkan {path} dari document root atau blokir aksesnya di web server. "
                               "Jika berisi credential, anggap bocor dan segera rotasi."))
    if not results:
        results.append(passed("exposed_file", C.CONFIGURATION, f"Tidak ada file sensitif terekspos ({len(PROBES)} path diuji)",
                              target=url))

    listing = await asyncio.gather(*(probe(d) for d in LISTING_DIRS))
    open_dirs = [urljoin(url, d) for d, page in listing if page and page.status == 200 and _LISTING.search(page.body)]
    for d in open_dirs:
        results.append(issue("directory_listing", C.CONFIGURATION, "Directory listing aktif", S.MEDIUM, target=d,
                             value=urlparse(d).path, evidence={"url": d},
                             recommendation="Nonaktifkan autoindex (nginx) / Options -Indexes (Apache)."))
    if not open_dirs:
        results.append(passed("directory_listing", C.CONFIGURATION, "Directory listing tidak aktif", target=url))
    return results


# --- content injection / SEO spam / cloaking ---------------------------------

SPAM = re.compile(
    r"slot\s*gacor|slot\s*online|situs\s*slot|judi\s*online|situs\s*judi|togel|toto\s*macau|maxwin|"
    r"scatter\s*hitam|casino\s*online|sbobet|bandar\s*(togel|slot|bola)|rtp\s*live|pragmatic\s*play|"
    r"viagra|cialis",
    re.I,
)
HIDDEN_IFRAME = re.compile(r"<iframe[^>]+(width\s*=\s*[\"']?0|height\s*=\s*[\"']?0|display\s*:\s*none|visibility\s*:\s*hidden)", re.I)
OBFUSCATED_JS = re.compile(r"eval\s*\(\s*(unescape|atob|String\.fromCharCode)|document\.write\s*\(\s*unescape", re.I)


def _spam_terms(body: str) -> list[str]:
    return sorted({m.group(0).lower() for m in SPAM.finditer(body)})[:20]


def _snippets(body: str, pattern: re.Pattern, n: int = 3) -> list[str]:
    return [clip(body[max(0, m.start() - 80): m.end() + 80], 250) for m in list(pattern.finditer(body))[:n]]


async def check_content(client: httpx.AsyncClient, url: str, page: Fetched | None) -> list[CheckResult]:
    if page is None or page.status >= 400:
        return [skipped("content_injection", C.MALWARE, "Halaman utama tidak dapat dibaca")]
    results: list[CheckResult] = []
    normal_terms = _spam_terms(page.body)

    try:
        bot = await fetch(client, url, headers={"User-Agent": GOOGLEBOT_UA})
        bot_terms = _spam_terms(bot.body)
    except httpx.HTTPError:
        bot, bot_terms = None, []

    cloaked = sorted(set(bot_terms) - set(normal_terms))
    rec = ("Cari file yang menyisipkan konten (index.php, header.php tema, .htaccess, tabel wp_options/wp_posts), "
           "bandingkan dengan backup bersih, lalu ganti semua password admin/FTP/database.")
    if cloaked:
        results.append(issue(
            "seo_cloaking", C.MALWARE, "Konten judi/spam hanya ditampilkan ke Googlebot (cloaking)", S.CRITICAL,
            target=url, value=", ".join(cloaked)[:255], confidence=0.85,
            evidence={"terms_googlebot": bot_terms, "terms_normal": normal_terms,
                      "snippets": _snippets(bot.body, SPAM) if bot else []},
            description="Pengunjung biasa melihat halaman normal, tetapi mesin pencari melihat konten spam. "
                        "Ini pola khas website yang disusupi untuk SEO judi online.",
            recommendation=rec))
    else:
        results.append(passed("seo_cloaking", C.MALWARE, "Tidak ada perbedaan konten untuk Googlebot", target=url))

    if normal_terms:
        results.append(issue(
            "content_injection", C.MALWARE, "Halaman mengandung kata kunci judi/spam", S.HIGH, target=url,
            value=", ".join(normal_terms)[:255], confidence=0.6,
            evidence={"terms": normal_terms, "snippets": _snippets(page.body, SPAM)},
            description="Kata kunci judi/spam ditemukan di halaman utama. Periksa apakah memang konten asli.",
            recommendation=rec))
    else:
        results.append(passed("content_injection", C.MALWARE, "Tidak ada kata kunci judi/spam di halaman utama", target=url))

    js = _snippets(page.body, HIDDEN_IFRAME) + _snippets(page.body, OBFUSCATED_JS)
    if js:
        results.append(issue("suspicious_markup", C.MALWARE, "Iframe tersembunyi / JavaScript ter-obfuscate", S.MEDIUM,
                             target=url, confidence=0.5, evidence={"snippets": js},
                             recommendation="Periksa sumber script/iframe tersebut; injeksi JS sering dipakai untuk redirect."))
    else:
        results.append(passed("suspicious_markup", C.MALWARE, "Tidak ada iframe tersembunyi / JS ter-obfuscate", target=url))
    return results


# --- entry point -------------------------------------------------------------

def make_client(transport: httpx.AsyncBaseTransport | None = None) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(15.0, connect=10.0), headers={"User-Agent": USER_AGENT},
        verify=False,  # certificate validity is judged separately by check_tls
        max_redirects=5, transport=transport,
        limits=httpx.Limits(max_connections=6),
    )


async def run_web_checks(url: str, client: httpx.AsyncClient, prober=probe_tls) -> list[CheckResult]:
    results: list[CheckResult] = []
    page_holder: dict = {}

    async def http():
        res, page = await check_http(client, url)
        page_holder["page"] = page
        return res

    results += await timed("http_availability", C.WEB, http)
    page = page_holder.get("page")
    results += await timed("https_redirect", C.SSL, lambda: check_https_redirect(client, url))
    results += await timed("ssl_certificate", C.SSL, lambda: check_tls(url, prober))
    if page is not None:
        results += await timed("security_headers", C.CONFIGURATION, lambda: _async(eval_headers(url, page.headers)))
        results += await timed("exposed_file", C.CONFIGURATION, lambda: check_exposed_files(client, url))
    results += await timed("content_injection", C.MALWARE, lambda: check_content(client, url, page))
    return results


async def _async(value):
    return value
